pub mod abi_intent;
pub mod anomaly_detector;
pub mod confirm_drain;
pub mod economic_check;
pub mod mempool_listener;

pub use abi_intent::{check_abi_intent, ABIIntent};
pub use anomaly_detector::score_transaction;
pub use confirm_drain::DrainResult;
pub use economic_check::EconomicCheckResult;

#[derive(Debug, PartialEq, Clone, serde::Serialize)]
pub enum ConfidenceTier {
    None,
    Low,
    Medium,
    High,
    Critical,
}

pub fn resolve_confidence_tier(
    score: u8,
    drain: &DrainResult,
    intent: &ABIIntent,
    economic: &EconomicCheckResult,
) -> ConfidenceTier {
    if matches!(intent, ABIIntent::LegitimateExit) {
        ConfidenceTier::None
    } else if economic.invariant_violated && matches!(intent, ABIIntent::Unknown) && score >= 4 {
        ConfidenceTier::Critical
    } else if economic.invariant_violated {
        ConfidenceTier::High
    } else if drain.confirmed && score >= 3 {
        ConfidenceTier::High
    } else if drain.confirmed {
        ConfidenceTier::Medium
    } else if matches!(intent, ABIIntent::SuspiciousCall) && score >= 3 {
        ConfidenceTier::High
    } else if drain.confirmed && matches!(intent, ABIIntent::SuspiciousCall) && score >= 2 {
        ConfidenceTier::Medium
    } else if matches!(intent, ABIIntent::SuspiciousCall) && score >= 2 {
        ConfidenceTier::Medium
    } else if score >= 2 && matches!(intent, ABIIntent::Unknown) {
        ConfidenceTier::Low
    } else {
        ConfidenceTier::None
    }
}
