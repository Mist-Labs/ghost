use crate::protocols::{normalize_selector, ProtocolDefinition, ProtocolRegistry};
use anyhow::Result;
use ethers::providers::Middleware;
use ethers::types::Transaction;
use std::sync::Arc;

pub const FLASH_LOAN_SELECTORS: &[&str] = &[
    "ab9c4b5d", // Aave flashLoan
    "5cffe9de", // Balancer flashLoan
    "490e6cbc", // Uniswap flash
];

pub const SANCTIONED_EXIT_SELECTORS: &[&str] = &[
    "2e1a7d4d", // withdraw(uint256)
    "441a3e70", // withdraw(uint256,uint256)
    "00f714ce", // removeLiquidity
    "4515cef3", // bridge
    "a9059cbb", // standard ERC-20 transfer
];

#[derive(Debug)]
pub struct ScoreResult {
    pub score: u8,
    pub signals: Vec<String>,
    pub is_sanctioned_exit: bool,
    pub protocol: Option<Arc<ProtocolDefinition>>,
}

pub async fn score_transaction<M: Middleware>(
    tx: &Transaction,
    provider: &M,
    protocols: &ProtocolRegistry,
) -> Result<ScoreResult>
where
    <M as Middleware>::Error: 'static,
{
    let protocol = protocols.match_transaction(tx);
    if protocol.is_none() {
        return Ok(ScoreResult {
            score: 0,
            signals: Vec::new(),
            is_sanctioned_exit: false,
            protocol: None,
        });
    }

    let protocol = protocol.unwrap();
    let input_hex = hex::encode(&tx.input.0);
    let selector = normalize_selector(&input_hex[..8.min(input_hex.len())]);

    let sanctioned_exit = protocol
        .sanctioned_selectors
        .iter()
        .any(|candidate| candidate == &selector)
        || SANCTIONED_EXIT_SELECTORS.contains(&selector.as_str());
    if sanctioned_exit {
        return Ok(ScoreResult {
            score: 0,
            signals: vec![],
            is_sanctioned_exit: true,
            protocol: Some(protocol),
        });
    }

    let mut signals: Vec<String> = Vec::new();

    if FLASH_LOAN_SELECTORS.contains(&selector.as_str()) {
        signals.push("flash_loan".into());
    }
    if is_multicall(tx) && call_count(tx) >= 3 {
        signals.push("multicall_3plus".into());
    }
    if !protocol
        .known_selectors
        .iter()
        .any(|known| known == &selector)
    {
        signals.push("unknown_selector".into());
    }
    if protocol
        .suspicious_selectors
        .iter()
        .any(|known| known == &selector)
    {
        signals.push("protocol_marked_suspicious".into());
    }
    let tx_count = provider
        .get_transaction_count(tx.from, None)
        .await?
        .as_u64();
    if tx_count < 10 {
        signals.push("fresh_wallet".into());
    }
    if wallet_funded_within_hours(tx.from, 48, provider).await? {
        signals.push("recently_funded".into());
    }
    let base_fee = provider
        .get_block(ethers::types::BlockNumber::Latest)
        .await?
        .and_then(|b| b.base_fee_per_gas)
        .unwrap_or_default();
    if let Some(gas_price) = tx.gas_price {
        if gas_price > base_fee * 3u64 {
            signals.push("high_gas".into());
        }
    }

    let score = signals.len() as u8;
    Ok(ScoreResult {
        score,
        signals,
        is_sanctioned_exit: false,
        protocol: Some(protocol),
    })
}

fn is_multicall(tx: &Transaction) -> bool {
    // Check if input contains multiple function calls
    // Simple heuristic: if input length > 1000 bytes, likely multicall
    tx.input.0.len() > 1000
}

fn call_count(tx: &Transaction) -> usize {
    // Estimate call count from input size
    // Rough heuristic: each call ~200 bytes
    (tx.input.0.len() / 200).max(1)
}

async fn wallet_funded_within_hours<M: Middleware>(
    address: ethers::types::Address,
    hours: u64,
    provider: &M,
) -> Result<bool>
where
    <M as Middleware>::Error: 'static,
{
    let current_block = provider.get_block_number().await?;
    let blocks_ago = (hours * 3600) / 12; // ~12s per block
    let target_block = current_block.saturating_sub(blocks_ago.into());

    let balance = provider
        .get_balance(address, Some(target_block.into()))
        .await?;
    Ok(balance.as_u64() == 0) // If balance was 0 recently, funded since then
}
