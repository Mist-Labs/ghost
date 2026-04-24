pub mod ast_analysis;
pub mod contract_scanner;
pub mod dependency_monitor;
pub mod disclosure;
pub mod hack_feed;
pub mod invariant_monitor;
pub mod onchain;
pub mod oracle_monitor;
pub mod scheduler;
pub mod signature_extractor;
pub mod upgrade_monitor;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AttackVector {
    Reentrancy,
    FlashLoanManipulation,
    OracleManipulation,
    AccessControl,
    LogicError,
    BridgeExploit,
    GovernanceAttack,
    PriceManipulation,
    SignatureValidation,
    Unknown,
}

impl AttackVector {
    pub fn as_storage_value(&self) -> &'static str {
        match self {
            Self::Reentrancy => "reentrancy",
            Self::FlashLoanManipulation => "flash_loan_manipulation",
            Self::OracleManipulation => "oracle_manipulation",
            Self::AccessControl => "access_control",
            Self::LogicError => "logic_error",
            Self::BridgeExploit => "bridge_exploit",
            Self::GovernanceAttack => "governance_attack",
            Self::PriceManipulation => "price_manipulation",
            Self::SignatureValidation => "signature_validation",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_storage_value(value: &str) -> Self {
        match value {
            "reentrancy" => Self::Reentrancy,
            "flash_loan_manipulation" => Self::FlashLoanManipulation,
            "oracle_manipulation" => Self::OracleManipulation,
            "access_control" => Self::AccessControl,
            "logic_error" => Self::LogicError,
            "bridge_exploit" => Self::BridgeExploit,
            "governance_attack" => Self::GovernanceAttack,
            "price_manipulation" => Self::PriceManipulation,
            "signature_validation" => Self::SignatureValidation,
            _ => Self::Unknown,
        }
    }

    pub fn classify(text: &str) -> Self {
        let normalized = text.to_ascii_lowercase();
        if normalized.contains("reentr") {
            Self::Reentrancy
        } else if normalized.contains("flash loan") {
            Self::FlashLoanManipulation
        } else if normalized.contains("oracle") || normalized.contains("price feed") {
            Self::OracleManipulation
        } else if normalized.contains("access control")
            || normalized.contains("admin key")
            || normalized.contains("permission")
        {
            Self::AccessControl
        } else if normalized.contains("bridge") {
            Self::BridgeExploit
        } else if normalized.contains("governance") {
            Self::GovernanceAttack
        } else if normalized.contains("signature") || normalized.contains("permit") {
            Self::SignatureValidation
        } else if normalized.contains("price manipulation")
            || normalized.contains("sandwich")
            || normalized.contains("slippage")
        {
            Self::PriceManipulation
        } else if normalized.contains("logic")
            || normalized.contains("rounding")
            || normalized.contains("accounting")
        {
            Self::LogicError
        } else {
            Self::Unknown
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_storage_value(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    pub fn from_storage_value(value: &str) -> Self {
        match value {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            _ => Self::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SimulationMode {
    ConfiguredHealthy,
    ConfiguredDegraded,
    Generic,
}

impl SimulationMode {
    pub fn as_storage_value(&self) -> &'static str {
        match self {
            Self::ConfiguredHealthy => "configured_healthy",
            Self::ConfiguredDegraded => "configured_degraded",
            Self::Generic => "generic",
        }
    }

    pub fn from_storage_value(value: &str) -> Self {
        match value {
            "configured_healthy" => Self::ConfiguredHealthy,
            "configured_degraded" => Self::ConfiguredDegraded,
            _ => Self::Generic,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HackReport {
    pub source: String,
    pub external_id: String,
    pub protocol: String,
    pub published_at: DateTime<Utc>,
    pub loss_usd: Option<f64>,
    pub attack_vector: AttackVector,
    pub root_cause: String,
    pub chain_name: String,
    pub title: String,
    pub summary: String,
    pub source_url: String,
    pub raw_payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilitySignature {
    pub id: Uuid,
    pub derived_from_hack_id: Uuid,
    pub attack_vector: AttackVector,
    pub protocol_types: Vec<String>,
    pub bytecode_patterns: Vec<String>,
    pub abi_patterns: Vec<ABIPattern>,
    pub severity: Severity,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABIPattern {
    pub requires_functions: Vec<String>,
    pub dangerous_sequence: Vec<String>,
    pub missing_modifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanMode {
    Scheduled,
    Triggered {
        source_report_id: Uuid,
        source: String,
    },
}

impl ScanMode {
    pub fn as_storage_value(&self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Triggered { .. } => "triggered",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub protocol_id: String,
    pub protocol_name: String,
    pub chain_name: String,
    pub scan_timestamp: DateTime<Utc>,
    pub signatures_checked: u32,
    pub scan_mode: ScanMode,
    pub vulnerabilities_found: Vec<VulnerabilityMatch>,
    pub clean: bool,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityMatch {
    pub finding_type: FindingType,
    pub signature_id: Option<Uuid>,
    pub title: String,
    pub contract_address: String,
    pub confidence: f64,
    pub severity: Severity,
    pub matched_pattern: String,
    pub affected_functions: Vec<String>,
    pub simulation_confirmed: bool,
    pub remediation: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    AstRisk,
    SignatureMatch,
    UpgradeRisk,
    OracleRisk,
    DependencyRisk,
    InvariantViolation,
    GovernanceRisk,
}

impl FindingType {
    pub fn as_storage_value(&self) -> &'static str {
        match self {
            Self::AstRisk => "ast_risk",
            Self::SignatureMatch => "signature_match",
            Self::UpgradeRisk => "upgrade_risk",
            Self::OracleRisk => "oracle_risk",
            Self::DependencyRisk => "dependency_risk",
            Self::InvariantViolation => "invariant_violation",
            Self::GovernanceRisk => "governance_risk",
        }
    }
}
