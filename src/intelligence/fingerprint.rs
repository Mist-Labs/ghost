use crate::intelligence::history::{fetch_address_transactions, HistoricalTransaction};
use crate::intelligence::wallet_tracer::trace_wallet_origin;
use crate::tracking::cex_surveillance::load_cex_wallet_corpus_state;
use anyhow::Result;
use chrono::{Timelike, Utc};
use ethers::providers::Middleware;
use ethers::types::{Address, H256, U256};

#[derive(Debug, serde::Serialize, Clone)]
pub enum SkillTier {
    Novice,
    Intermediate,
    Professional,
}

#[derive(Debug, serde::Serialize, Clone)]
pub struct AttackerProfile {
    pub address: String,
    pub skill_tier: SkillTier,
    pub ran_test_transaction: bool,
    pub attack_hour_utc: u32,
    pub estimated_timezone: String,
    pub used_private_mempool: bool,
    pub wallet_age_days: u64,
    pub origin: crate::intelligence::wallet_tracer::WalletOrigin,
}

pub async fn build_fingerprint<M: Middleware>(
    attacker: Address,
    exploit_tx_hash: H256,
    provider: &M,
) -> Result<AttackerProfile>
where
    <M as Middleware>::Error: 'static,
{
    let tx_history = fetch_address_transactions(attacker).await?;
    let exploit_tx = provider
        .get_transaction(exploit_tx_hash)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Exploit tx not found"))?;

    let exploit_to = exploit_tx.to;
    let exploit_block = exploit_tx
        .block_number
        .map(|value| value.as_u64())
        .unwrap_or_default();
    let exploit_value = exploit_tx.value;
    let exploit_selector = method_selector(&exploit_tx.input.0);

    let ran_test = tx_history.iter().any(|tx| {
        tx.block_number < exploit_block
            && tx.to == exploit_to
            && (tx.value < exploit_value / U256::from(10_u64)
                || tx.method_id.as_deref() == exploit_selector.as_deref())
    });

    let used_private_mempool = likely_private_orderflow(&exploit_tx, &tx_history);
    let skill_tier = match (used_private_mempool, ran_test) {
        (true, true) => SkillTier::Professional,
        (true, false) | (false, true) => SkillTier::Intermediate,
        (false, false) => SkillTier::Novice,
    };

    let block = provider
        .get_block(
            exploit_tx
                .block_number
                .ok_or_else(|| anyhow::anyhow!("exploit transaction missing block number"))?,
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("exploit block not found"))?;
    let hour_utc = chrono::DateTime::from_timestamp(block.timestamp.as_u64() as i64, 0)
        .unwrap_or_default()
        .hour();
    let cex_wallets = load_cex_wallets();

    Ok(AttackerProfile {
        address: format!("{:?}", attacker),
        skill_tier,
        ran_test_transaction: ran_test,
        attack_hour_utc: hour_utc,
        estimated_timezone: hour_to_timezone(hour_utc),
        used_private_mempool,
        wallet_age_days: compute_wallet_age_days(&tx_history),
        origin: trace_wallet_origin(attacker, provider, &cex_wallets, 0).await?,
    })
}

fn likely_private_orderflow(
    exploit_tx: &ethers::types::Transaction,
    tx_history: &[HistoricalTransaction],
) -> bool {
    let Some(block_number) = exploit_tx.block_number.map(|value| value.as_u64()) else {
        return false;
    };

    let sender_history_depth = tx_history.len();
    let high_fee = exploit_tx
        .gas_price
        .map(|price| price > U256::from(5_000_000_000_u64))
        .unwrap_or(false);
    let fresh_searcher_wallet = sender_history_depth <= 3;

    high_fee && fresh_searcher_wallet && block_number > 0
}

fn hour_to_timezone(hour: u32) -> String {
    let offset = 14_i32 - hour as i32;
    let clamped = offset.clamp(-12, 14);
    if clamped >= 0 {
        format!("UTC+{clamped}")
    } else {
        format!("UTC{clamped}")
    }
}

fn compute_wallet_age_days(tx_history: &[HistoricalTransaction]) -> u64 {
    let Some(first) = tx_history.first() else {
        return 0;
    };
    let age = Utc::now().signed_duration_since(first.timestamp);
    age.num_days().max(0) as u64
}

fn load_cex_wallets() -> std::collections::HashMap<String, String> {
    let path = std::env::var("CEX_WALLETS_FILE").unwrap_or_else(|_| "cex_wallets.json".into());
    load_cex_wallet_corpus_state(std::path::Path::new(&path))
        .map(|state| state.wallets)
        .unwrap_or_default()
}

fn method_selector(input: &[u8]) -> Option<String> {
    (input.len() >= 4).then(|| format!("0x{}", hex::encode(&input[..4])))
}
