use crate::intelligence::bridge_corpus::{bridge_label_for, BridgeCorpusState};
use crate::intelligence::history::{fetch_address_transactions, HistoricalTransaction};
use crate::tracking::cex_surveillance::CexWalletMetadata;
use crate::tracking::mixer_detector::{mixer_label_for, MixerCorpusState};
use anyhow::Result;
use ethers::providers::Middleware;
use ethers::types::Address;
use std::collections::HashMap;

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
    cex_wallets: &HashMap<String, CexWalletMetadata>,
    bridge_corpus: &BridgeCorpusState,
    mixer_corpus: &MixerCorpusState,
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
            exchange: exchange.exchange.clone(),
            tx_hash: format!("{:?}", first_tx.hash),
        });
    }

    if let Some(bridge) = identify_bridge(first_tx.from, bridge_corpus) {
        return Ok(WalletOrigin::Bridge {
            bridge,
            tx_hash: format!("{:?}", first_tx.hash),
        });
    }

    if let Some(mixer) = mixer_label_for(first_tx.from, mixer_corpus) {
        return Ok(WalletOrigin::MixerFunded { mixer });
    }

    Box::pin(trace_wallet_origin(
        first_tx.from,
        _provider,
        cex_wallets,
        bridge_corpus,
        mixer_corpus,
        depth + 1,
    ))
    .await
}

async fn get_first_inbound_tx(address: Address) -> Result<Option<HistoricalTransaction>> {
    let history = fetch_address_transactions(address).await?;
    Ok(history.into_iter().find(|tx| tx.to == Some(address)))
}

fn identify_bridge(address: Address, bridge_corpus: &BridgeCorpusState) -> Option<String> {
    bridge_label_for(address, &bridge_corpus.bridges)
}
