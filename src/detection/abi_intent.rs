use crate::protocols::{normalize_selector, ProtocolDefinition};
use anyhow::Result;
use ethers::types::Transaction;
use std::sync::Arc;

const LEGITIMATE_INTENT_KEYWORDS: &[&str] = &[
    "withdraw", "redeem", "exit", "remove", "bridge", "transfer", "claim", "unstake", "migrate",
];

#[derive(Debug, PartialEq)]
pub enum ABIIntent {
    LegitimateExit,
    SuspiciousCall,
    Unknown,
}

pub async fn check_abi_intent(
    tx: &Transaction,
    protocol: Option<Arc<ProtocolDefinition>>,
) -> Result<ABIIntent> {
    let Some(protocol) = protocol else {
        return Ok(ABIIntent::Unknown);
    };

    let input_hex = hex::encode(&tx.input.0);
    let selector = normalize_selector(&input_hex[..8.min(input_hex.len())]);

    if protocol
        .sanctioned_selectors
        .iter()
        .any(|known| known == &selector)
    {
        return Ok(ABIIntent::LegitimateExit);
    }

    if protocol
        .suspicious_selectors
        .iter()
        .any(|known| known == &selector)
    {
        return Ok(ABIIntent::SuspiciousCall);
    }

    let is_legitimate = LEGITIMATE_INTENT_KEYWORDS.iter().any(|keyword| {
        protocol
            .known_selectors
            .iter()
            .any(|known| known == &selector && known.contains(keyword))
    });

    if is_legitimate {
        Ok(ABIIntent::LegitimateExit)
    } else if protocol
        .known_selectors
        .iter()
        .any(|known| known == &selector)
    {
        Ok(ABIIntent::Unknown)
    } else {
        Ok(ABIIntent::SuspiciousCall)
    }
}
