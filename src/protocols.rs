use anyhow::{Context, Result};
use ethers::types::{Address, Transaction};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct ProtocolRegistry {
    protocols: Vec<Arc<ProtocolDefinition>>,
    by_address: HashMap<Address, Arc<ProtocolDefinition>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProtocolDefinition {
    pub id: String,
    pub name: String,
    pub chain_id: u64,
    #[serde(default)]
    pub protocol_type: Option<String>,
    #[serde(default)]
    pub monitoring_authorized: bool,
    #[serde(default)]
    pub monitored_addresses: Vec<Address>,
    #[serde(default)]
    pub contract_addresses: Vec<Address>,
    #[serde(default)]
    pub security_contacts: Vec<String>,
    #[serde(default)]
    pub abi: Option<serde_json::Value>,
    #[serde(default)]
    pub known_selectors: Vec<String>,
    #[serde(default)]
    pub sanctioned_selectors: Vec<String>,
    #[serde(default)]
    pub suspicious_selectors: Vec<String>,
    #[serde(default)]
    pub oracle_addresses: Vec<Address>,
    #[serde(default)]
    pub upgrade_monitor: Option<UpgradeMonitorDefinition>,
    #[serde(default)]
    pub oracle_monitor: Option<OracleMonitorDefinition>,
    #[serde(default)]
    pub dependencies: Vec<DependencyDefinition>,
    #[serde(default)]
    pub invariants: Vec<InvariantDefinition>,
    #[serde(default)]
    pub simulation: Option<SimulationProfile>,
    #[serde(default)]
    pub billing: Option<ProtocolBillingDefinition>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpgradeMonitorDefinition {
    #[serde(default)]
    pub proxy_addresses: Vec<Address>,
    #[serde(default)]
    pub timelock_addresses: Vec<Address>,
    #[serde(default = "default_timelock_lookback_blocks")]
    pub timelock_lookback_blocks: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleMonitorDefinition {
    #[serde(default)]
    pub feeds: Vec<OracleFeedDefinition>,
    #[serde(default = "default_max_cross_source_deviation_bps")]
    pub max_cross_source_deviation_bps: u64,
    #[serde(default)]
    pub require_sequencer_uptime_feed: bool,
    #[serde(default = "default_minimum_oracle_sources")]
    pub minimum_sources: usize,
    #[serde(default = "default_minimum_twap_window_secs")]
    pub minimum_twap_window_secs: u32,
    #[serde(default = "default_max_spot_vs_twap_deviation_bps")]
    pub max_spot_vs_twap_deviation_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleFeedDefinition {
    pub label: String,
    pub address: Address,
    pub kind: OracleKind,
    #[serde(default)]
    pub pair: Option<String>,
    #[serde(default)]
    pub heartbeat_secs: Option<u64>,
    #[serde(default)]
    pub window_secs: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SimulationProfile {
    #[serde(default)]
    pub token_whales: Vec<TokenWhaleDefinition>,
    #[serde(default)]
    pub routers: Vec<RouterSimulationDefinition>,
    #[serde(default)]
    pub flash_loan_providers: Vec<FlashLoanProviderDefinition>,
    #[serde(default)]
    pub market_paths: Vec<MarketPathDefinition>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenWhaleDefinition {
    pub token: Address,
    pub holder: Address,
    #[serde(default)]
    pub decimals: Option<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouterSimulationDefinition {
    pub kind: RouterKind,
    pub address: Address,
    #[serde(default)]
    pub quoter: Option<Address>,
    #[serde(default)]
    pub wrapped_native: Option<Address>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouterKind {
    UniswapV2,
    UniswapV3,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FlashLoanProviderDefinition {
    pub kind: FlashLoanProviderKind,
    pub address: Address,
    pub asset: Address,
    #[serde(default)]
    pub liquidity_holder: Option<Address>,
    #[serde(default)]
    pub max_loan_amount: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FlashLoanProviderKind {
    AaveV3,
    Balancer,
    UniswapV3,
    Erc3156,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MarketPathDefinition {
    pub label: String,
    pub router_kind: RouterKind,
    pub token_in: Address,
    pub token_out: Address,
    #[serde(default)]
    pub intermediate_tokens: Vec<Address>,
    #[serde(default)]
    pub fee_tiers: Vec<u32>,
    #[serde(default)]
    pub amount_in: Option<String>,
    #[serde(default)]
    pub slippage_bps: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OracleKind {
    Chainlink,
    SequencerUptime,
    UniswapV3Twap,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DependencyDefinition {
    pub name: String,
    pub address: Address,
    pub kind: DependencyKind,
    #[serde(default)]
    pub critical: bool,
    #[serde(default)]
    pub expected_codehash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    Bridge,
    Router,
    LendingMarket,
    Lp,
    Vault,
    ExternalHook,
    Timelock,
    Oracle,
    Other,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InvariantDefinition {
    pub name: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(flatten)]
    pub rule: InvariantRule,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InvariantRule {
    RatioMin {
        numerator: MetricSource,
        denominator: MetricSource,
        min_bps: u64,
    },
    RatioMax {
        numerator: MetricSource,
        denominator: MetricSource,
        max_bps: u64,
    },
    DeltaMaxBps {
        left: MetricSource,
        right: MetricSource,
        max_bps: u64,
    },
    ValueRange {
        metric: MetricSource,
        min: Option<String>,
        max: Option<String>,
    },
    MaxDrawdownBps {
        metric: MetricSource,
        max_bps: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetricSource {
    pub address: Address,
    pub function: String,
    #[serde(default)]
    pub arguments: Vec<serde_json::Value>,
    #[serde(default)]
    pub abi: Option<serde_json::Value>,
    #[serde(default)]
    pub output_index: usize,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProtocolBillingDefinition {
    pub tier: String,
    #[serde(default)]
    pub monthly_fee_usd: Option<i32>,
    pub billing_email: String,
    #[serde(default)]
    pub alert_webhook: Option<String>,
    #[serde(default = "default_true")]
    pub active: bool,
}

impl ProtocolRegistry {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            tracing::warn!(
                "Protocol registry file {} does not exist; mempool listener will start in passive mode",
                path.display()
            );
            return Ok(Self::default());
        }

        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read protocol registry {}", path.display()))?;
        let mut protocols: Vec<ProtocolDefinition> = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse protocol registry {}", path.display()))?;

        for protocol in &mut protocols {
            protocol.known_selectors = protocol
                .known_selectors
                .iter()
                .map(|selector| normalize_selector(selector))
                .collect();
            protocol.sanctioned_selectors = protocol
                .sanctioned_selectors
                .iter()
                .map(|selector| normalize_selector(selector))
                .collect();
            protocol.suspicious_selectors = protocol
                .suspicious_selectors
                .iter()
                .map(|selector| normalize_selector(selector))
                .collect();
        }

        let protocols: Vec<Arc<ProtocolDefinition>> = protocols.into_iter().map(Arc::new).collect();
        let mut by_address = HashMap::new();
        for protocol in &protocols {
            for address in &protocol.monitored_addresses {
                by_address.insert(*address, Arc::clone(protocol));
            }
        }

        Ok(Self {
            protocols,
            by_address,
        })
    }

    pub fn is_ready(&self) -> bool {
        !self.protocols.is_empty()
    }

    pub fn protocol_count(&self) -> usize {
        self.protocols.len()
    }

    pub fn all_protocols(&self) -> Vec<Arc<ProtocolDefinition>> {
        self.protocols.clone()
    }

    pub fn match_transaction(&self, tx: &Transaction) -> Option<Arc<ProtocolDefinition>> {
        tx.to
            .and_then(|address| self.by_address.get(&address).cloned())
    }

    pub fn monitored_protocols(&self, chain_id: u64) -> Vec<Arc<ProtocolDefinition>> {
        self.protocols
            .iter()
            .filter(|protocol| protocol.monitoring_authorized && protocol.chain_id == chain_id)
            .cloned()
            .collect()
    }

    pub fn find_by_id(&self, protocol_id: &str) -> Option<Arc<ProtocolDefinition>> {
        self.protocols
            .iter()
            .find(|protocol| protocol.id == protocol_id)
            .cloned()
    }
}

impl ProtocolDefinition {
    pub fn scan_addresses(&self) -> Vec<Address> {
        if self.contract_addresses.is_empty() {
            self.monitored_addresses.clone()
        } else {
            self.contract_addresses.clone()
        }
    }

    pub fn upgrade_proxy_addresses(&self) -> Vec<Address> {
        if let Some(monitor) = &self.upgrade_monitor {
            if !monitor.proxy_addresses.is_empty() {
                return monitor.proxy_addresses.clone();
            }
        }
        self.scan_addresses()
    }
}

pub fn normalize_selector(selector: &str) -> String {
    selector
        .trim()
        .trim_start_matches("0x")
        .to_ascii_lowercase()
}

fn default_timelock_lookback_blocks() -> u64 {
    50_000
}

fn default_max_cross_source_deviation_bps() -> u64 {
    300
}

fn default_minimum_oracle_sources() -> usize {
    2
}

fn default_minimum_twap_window_secs() -> u32 {
    1800
}

fn default_max_spot_vs_twap_deviation_bps() -> u64 {
    500
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::normalize_selector;

    #[test]
    fn normalizes_hex_selector() {
        assert_eq!(normalize_selector("0xA9059CBB"), "a9059cbb");
        assert_eq!(normalize_selector("  3593564c "), "3593564c");
    }
}
