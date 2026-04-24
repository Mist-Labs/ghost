use crate::intelligence::history::{fetch_address_transactions, HistoricalTransaction};
use anyhow::Result;
use ethers::providers::Middleware;
use ethers::types::Address;
use std::collections::HashMap;
use std::env;
use std::str::FromStr;

#[derive(Debug, serde::Serialize, Clone)]
pub enum WalletOrigin {
    CexWithdrawal { exchange: String, tx_hash: String },
    Bridge { bridge: String, tx_hash: String },
    MixerFunded { mixer: String },
    Genesis,
    MaxDepth,
}

pub async fn trace_wallet_origin<M: Middleware>(
    address: Address,
    _provider: &M,
    cex_wallets: &HashMap<String, String>,
    depth: u8,
) -> Result<WalletOrigin>
where
    <M as Middleware>::Error: 'static,
{
    if depth > 10 {
        return Ok(WalletOrigin::MaxDepth);
    }

    let Some(first_tx) = get_first_inbound_tx(address).await? else {
        return Ok(WalletOrigin::Genesis);
    };

    let from_str = format!("{:?}", first_tx.from).to_lowercase();

    if let Some(exchange) = cex_wallets.get(&from_str) {
        return Ok(WalletOrigin::CexWithdrawal {
            exchange: exchange.clone(),
            tx_hash: format!("{:?}", first_tx.hash),
        });
    }

    if let Some(bridge) = identify_bridge(first_tx.from) {
        return Ok(WalletOrigin::Bridge {
            bridge,
            tx_hash: format!("{:?}", first_tx.hash),
        });
    }

    if is_mixer_contract(first_tx.from) {
        return Ok(WalletOrigin::MixerFunded {
            mixer: "tornado_cash".into(),
        });
    }

    Box::pin(trace_wallet_origin(
        first_tx.from,
        _provider,
        cex_wallets,
        depth + 1,
    ))
    .await
}

async fn get_first_inbound_tx(address: Address) -> Result<Option<HistoricalTransaction>> {
    let history = fetch_address_transactions(address).await?;
    Ok(history.into_iter().find(|tx| tx.to == Some(address)))
}

fn identify_bridge(address: Address) -> Option<String> {
    let normalized = format!("{address:?}").to_ascii_lowercase();
    if let Some(label) = configured_bridge_registry().get(&normalized) {
        return Some(label.clone());
    }

    match normalized.as_str() {
        "0x4200000000000000000000000000000000000010" => Some("base_standard_bridge".to_string()),
        "0x4200000000000000000000000000000000000007" => {
            Some("base_l2_cross_domain_messenger".to_string())
        }
        _ => None,
    }
}

fn configured_bridge_registry() -> HashMap<String, String> {
    env::var("KNOWN_BRIDGE_ADDRESSES")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|pair| {
                    let (label, address) = pair.split_once('=')?;
                    let parsed = Address::from_str(address.trim()).ok()?;
                    Some((
                        format!("{parsed:?}").to_ascii_lowercase(),
                        label.trim().to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn is_mixer_contract(address: Address) -> bool {
    crate::tracking::mixer_detector::is_known_mixer(address)
}
