use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ethers::types::{Address, Transaction};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, serde::Serialize, Clone, PartialEq)]
pub struct BridgeTransfer {
    pub bridge: String,
    pub bridge_tx_hash: String,
    pub exploit_tx_hash: String,
    pub amount: String,
    pub chain_hint: Option<String>,
    pub category: Option<String>,
    pub source: Option<String>,
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct BridgeCorpusState {
    pub path: PathBuf,
    pub checksum_sha256: String,
    pub loaded_at: DateTime<Utc>,
    pub source_entries: usize,
    pub duplicate_entries: usize,
    pub conflicting_entries: usize,
    pub invalid_entries: usize,
    pub bridges: HashMap<String, BridgeMetadata>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BridgeCorpusSummary {
    pub path: String,
    pub checksum_sha256: String,
    pub loaded_at: DateTime<Utc>,
    pub source_entries: usize,
    pub unique_addresses: usize,
    pub duplicate_entries: usize,
    pub conflicting_entries: usize,
    pub invalid_entries: usize,
    pub bridge_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BridgeCorpusValidationReport {
    pub path: String,
    pub checksum_sha256: String,
    pub source_entries: usize,
    pub unique_addresses: usize,
    pub duplicate_entries: usize,
    pub conflicting_entries: usize,
    pub invalid_entries: usize,
    pub warnings: Vec<String>,
    pub bridge_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct BridgeMetadata {
    pub bridge: String,
    #[serde(default)]
    pub chain_hint: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub confidence: Option<f64>,
}

pub fn detect_bridge_transfer(
    tx: &Transaction,
    to: Address,
    bridges: &HashMap<String, BridgeMetadata>,
    exploit_tx_hash: Option<&str>,
) -> Option<BridgeTransfer> {
    let to_str = normalize_address(&format!("{to:?}")).ok()?;
    let bridge = bridges.get(&to_str)?;

    Some(BridgeTransfer {
        bridge: bridge.bridge.clone(),
        bridge_tx_hash: format!("{:?}", tx.hash),
        exploit_tx_hash: exploit_tx_hash.unwrap_or_default().to_string(),
        amount: tx.value.to_string(),
        chain_hint: bridge.chain_hint.clone(),
        category: bridge.category.clone(),
        source: bridge.source.clone(),
        confidence: bridge.confidence,
    })
}

pub fn load_bridge_corpus_state(path: &Path) -> Result<BridgeCorpusState> {
    let mut entries = default_bridge_records();
    let mut invalid_entries = 0usize;

    if path.exists() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read bridge corpus {}", path.display()))?;
        let corpus: BridgeCorpus = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse bridge corpus {}", path.display()))?;
        match corpus {
            BridgeCorpus::Map(records) => {
                entries.extend(records.into_iter().map(|(address, metadata)| BridgeRecord {
                    address,
                    metadata: metadata.into_metadata(),
                }))
            }
            BridgeCorpus::List(records) => entries.extend(records),
        }
    } else {
        tracing::warn!(
            "Bridge corpus {} does not exist; using built-in bridge attribution only",
            path.display()
        );
    }

    let mut normalized: HashMap<String, BridgeMetadata> = HashMap::new();
    let mut duplicate_entries = 0usize;
    let mut conflicting_entries = 0usize;
    for entry in &entries {
        let normalized_address = match normalize_address(&entry.address) {
            Ok(address) => address,
            Err(_) => {
                invalid_entries += 1;
                tracing::warn!(
                    address = %entry.address,
                    bridge = %entry.metadata.bridge,
                    "skipping invalid bridge corpus entry"
                );
                continue;
            }
        };

        match normalized.get(&normalized_address) {
            Some(existing) if existing == &entry.metadata => duplicate_entries += 1,
            Some(existing) if existing != &entry.metadata => {
                conflicting_entries += 1;
                tracing::warn!(
                    address = %normalized_address,
                    existing_bridge = %existing.bridge,
                    conflicting_bridge = %entry.metadata.bridge,
                    "conflicting bridge labels in bridge corpus; keeping first label"
                );
            }
            None => {
                normalized.insert(normalized_address, entry.metadata.clone());
            }
            _ => {}
        }
    }

    Ok(BridgeCorpusState {
        path: path.to_path_buf(),
        checksum_sha256: checksum_for_entries(&normalized)?,
        loaded_at: Utc::now(),
        source_entries: entries.len(),
        duplicate_entries,
        conflicting_entries,
        invalid_entries,
        bridges: normalized,
    })
}

pub fn validate_bridge_corpus(path: &Path) -> Result<BridgeCorpusValidationReport> {
    let state = load_bridge_corpus_state(path)?;
    let mut warnings = Vec::new();
    if state.path.exists() {
        if state.source_entries == default_bridge_records().len() {
            warnings.push(
                "bridge corpus file contributed no additional entries beyond built-ins".to_string(),
            );
        }
    } else {
        warnings
            .push("bridge corpus file missing; using built-in bridge attribution only".to_string());
    }
    if state.duplicate_entries > 0 {
        warnings.push(format!(
            "{} duplicate bridge address entries collapsed to a single canonical record",
            state.duplicate_entries
        ));
    }
    if state.conflicting_entries > 0 {
        warnings.push(format!(
            "{} conflicting bridge labels were detected; the first label was retained",
            state.conflicting_entries
        ));
    }
    if state.invalid_entries > 0 {
        warnings.push(format!(
            "{} invalid bridge entries were skipped",
            state.invalid_entries
        ));
    }

    Ok(BridgeCorpusValidationReport {
        path: state.path.display().to_string(),
        checksum_sha256: state.checksum_sha256.clone(),
        source_entries: state.source_entries,
        unique_addresses: state.bridges.len(),
        duplicate_entries: state.duplicate_entries,
        conflicting_entries: state.conflicting_entries,
        invalid_entries: state.invalid_entries,
        warnings,
        bridge_counts: state.bridge_counts(),
    })
}

pub fn bridge_label_for(
    address: Address,
    bridges: &HashMap<String, BridgeMetadata>,
) -> Option<String> {
    let normalized = normalize_address(&format!("{address:?}")).ok()?;
    bridges
        .get(&normalized)
        .map(|metadata| metadata.bridge.clone())
}

impl BridgeCorpusState {
    pub fn summary(&self) -> BridgeCorpusSummary {
        BridgeCorpusSummary {
            path: self.path.display().to_string(),
            checksum_sha256: self.checksum_sha256.clone(),
            loaded_at: self.loaded_at,
            source_entries: self.source_entries,
            unique_addresses: self.bridges.len(),
            duplicate_entries: self.duplicate_entries,
            conflicting_entries: self.conflicting_entries,
            invalid_entries: self.invalid_entries,
            bridge_counts: self.bridge_counts(),
        }
    }

    fn bridge_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for bridge in self.bridges.values() {
            *counts.entry(bridge.bridge.clone()).or_insert(0) += 1;
        }
        counts
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum BridgeCorpus {
    Map(HashMap<String, BridgeMapValue>),
    List(Vec<BridgeRecord>),
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
enum BridgeMapValue {
    Label(String),
    Metadata(BridgeMetadata),
}

impl BridgeMapValue {
    fn into_metadata(self) -> BridgeMetadata {
        match self {
            Self::Label(bridge) => BridgeMetadata {
                bridge,
                chain_hint: None,
                category: None,
                source: None,
                confidence: None,
            },
            Self::Metadata(metadata) => metadata,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct BridgeRecord {
    address: String,
    #[serde(flatten)]
    metadata: BridgeMetadata,
}

fn default_bridge_records() -> Vec<BridgeRecord> {
    vec![
        BridgeRecord {
            address: "0x4200000000000000000000000000000000000010".into(),
            metadata: BridgeMetadata {
                bridge: "base_standard_bridge".into(),
                chain_hint: Some("base".into()),
                category: Some("canonical_bridge".into()),
                source: Some("built_in".into()),
                confidence: Some(1.0),
            },
        },
        BridgeRecord {
            address: "0x4200000000000000000000000000000000000007".into(),
            metadata: BridgeMetadata {
                bridge: "base_l2_cross_domain_messenger".into(),
                chain_hint: Some("base".into()),
                category: Some("cross_domain_messenger".into()),
                source: Some("built_in".into()),
                confidence: Some(1.0),
            },
        },
    ]
}

fn normalize_address(address: &str) -> Result<String> {
    let normalized = address.trim().to_ascii_lowercase();
    let _ = Address::from_str(&normalized)
        .with_context(|| format!("invalid EVM address in bridge corpus: {address}"))?;
    Ok(normalized)
}

fn checksum_for_entries(entries: &HashMap<String, BridgeMetadata>) -> Result<String> {
    let canonical = BTreeMap::from_iter(
        entries
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    let payload = serde_json::to_vec(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(payload);
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::{bridge_label_for, validate_bridge_corpus, BridgeMetadata};
    use ethers::types::Address;
    use std::str::FromStr;

    #[test]
    fn built_in_bridge_labels_resolve() {
        let address = Address::from_str("0x4200000000000000000000000000000000000010").unwrap();
        let report =
            validate_bridge_corpus(std::path::Path::new("non-existent-bridge-corpus.json"))
                .unwrap();
        let mut entries = std::collections::HashMap::new();
        entries.insert(
            "0x4200000000000000000000000000000000000010".to_string(),
            BridgeMetadata {
                bridge: "base_standard_bridge".to_string(),
                chain_hint: Some("base".to_string()),
                category: Some("canonical_bridge".to_string()),
                source: Some("built_in".to_string()),
                confidence: Some(1.0),
            },
        );
        assert_eq!(
            bridge_label_for(address, &entries),
            Some("base_standard_bridge".to_string())
        );
        assert!(report.unique_addresses >= 2);
    }
}
