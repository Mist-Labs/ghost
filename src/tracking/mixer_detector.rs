use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ethers::types::{Address, Transaction};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, serde::Serialize, Clone, PartialEq)]
pub struct MixerEntry {
    pub wallet: String,
    pub mixer: String,
    pub protocol_family: Option<String>,
    pub pool_denomination_eth: f64,
    pub timestamp_ms: u64,
    pub tx_hash: String,
    pub exploit_tx_hash: String,
    pub source: Option<String>,
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct MixerCorpusState {
    pub path: PathBuf,
    pub checksum_sha256: String,
    pub loaded_at: DateTime<Utc>,
    pub source_entries: usize,
    pub duplicate_entries: usize,
    pub conflicting_entries: usize,
    pub invalid_entries: usize,
    pub pools: HashMap<String, MixerPoolMetadata>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MixerCorpusSummary {
    pub path: String,
    pub checksum_sha256: String,
    pub loaded_at: DateTime<Utc>,
    pub source_entries: usize,
    pub unique_addresses: usize,
    pub duplicate_entries: usize,
    pub conflicting_entries: usize,
    pub invalid_entries: usize,
    pub mixer_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MixerCorpusValidationReport {
    pub path: String,
    pub checksum_sha256: String,
    pub source_entries: usize,
    pub unique_addresses: usize,
    pub duplicate_entries: usize,
    pub conflicting_entries: usize,
    pub invalid_entries: usize,
    pub warnings: Vec<String>,
    pub mixer_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct MixerPoolMetadata {
    pub label: String,
    pub denomination_eth: f64,
    #[serde(default)]
    pub protocol_family: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub confidence: Option<f64>,
}

pub fn detect_mixer_entry(
    tx: &Transaction,
    to: Address,
    corpus: &MixerCorpusState,
    exploit_tx_hash: Option<&str>,
) -> Option<MixerEntry> {
    let to_str = normalize_address(&format!("{to:?}")).ok()?;
    let pool = corpus.pools.get(&to_str)?;

    Some(MixerEntry {
        wallet: format!("{:?}", tx.from),
        mixer: pool.label.clone(),
        protocol_family: pool.protocol_family.clone(),
        pool_denomination_eth: pool.denomination_eth,
        timestamp_ms: Utc::now().timestamp_millis() as u64,
        tx_hash: format!("{:?}", tx.hash),
        exploit_tx_hash: exploit_tx_hash.unwrap_or_default().to_string(),
        source: pool.source.clone(),
        confidence: pool.confidence,
    })
}

pub fn mixer_label_for(address: Address, corpus: &MixerCorpusState) -> Option<String> {
    let normalized = normalize_address(&format!("{address:?}")).ok()?;
    corpus.pools.get(&normalized).map(|pool| pool.label.clone())
}

pub fn load_mixer_corpus_state(path: &Path) -> Result<MixerCorpusState> {
    let mut entries = default_mixer_records();
    let mut invalid_entries = 0usize;

    if path.exists() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read mixer corpus {}", path.display()))?;
        let corpus: MixerCorpus = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse mixer corpus {}", path.display()))?;
        match corpus {
            MixerCorpus::Map(records) => entries.extend(
                records
                    .into_iter()
                    .map(|(address, metadata)| MixerPoolRecord { address, metadata }),
            ),
            MixerCorpus::List(records) => entries.extend(records),
        }
    } else {
        tracing::warn!(
            "Mixer corpus {} does not exist; using built-in mixer attribution only",
            path.display()
        );
    }

    let mut normalized: HashMap<String, MixerPoolMetadata> = HashMap::new();
    let mut duplicate_entries = 0usize;
    let mut conflicting_entries = 0usize;
    for entry in &entries {
        let normalized_address = match normalize_address(&entry.address) {
            Ok(address) => address,
            Err(_) => {
                invalid_entries += 1;
                tracing::warn!(
                    address = %entry.address,
                    mixer = %entry.metadata.label,
                    "skipping invalid mixer corpus entry"
                );
                continue;
            }
        };

        match normalized.get(&normalized_address) {
            Some(existing) if existing == &entry.metadata => {
                duplicate_entries += 1;
            }
            Some(existing) if existing != &entry.metadata => {
                conflicting_entries += 1;
                tracing::warn!(
                    address = %normalized_address,
                    existing_mixer = %existing.label,
                    conflicting_mixer = %entry.metadata.label,
                    "conflicting mixer labels in mixer corpus; keeping first label"
                );
            }
            None => {
                normalized.insert(normalized_address, entry.metadata.clone());
            }
            _ => {}
        }
    }

    Ok(MixerCorpusState {
        path: path.to_path_buf(),
        checksum_sha256: checksum_for_entries(&normalized)?,
        loaded_at: Utc::now(),
        source_entries: entries.len(),
        duplicate_entries,
        conflicting_entries,
        invalid_entries,
        pools: normalized,
    })
}

pub fn validate_mixer_corpus(path: &Path) -> Result<MixerCorpusValidationReport> {
    let state = load_mixer_corpus_state(path)?;
    let mut warnings = Vec::new();
    if state.path.exists() {
        if state.source_entries == default_mixer_records().len() {
            warnings.push(
                "mixer corpus file contributed no additional entries beyond built-ins".to_string(),
            );
        }
    } else {
        warnings
            .push("mixer corpus file missing; using built-in mixer attribution only".to_string());
    }
    if state.duplicate_entries > 0 {
        warnings.push(format!(
            "{} duplicate mixer entries collapsed to canonical records",
            state.duplicate_entries
        ));
    }
    if state.conflicting_entries > 0 {
        warnings.push(format!(
            "{} conflicting mixer entries were detected; the first entry was retained",
            state.conflicting_entries
        ));
    }
    if state.invalid_entries > 0 {
        warnings.push(format!(
            "{} invalid mixer entries were skipped",
            state.invalid_entries
        ));
    }

    Ok(MixerCorpusValidationReport {
        path: state.path.display().to_string(),
        checksum_sha256: state.checksum_sha256.clone(),
        source_entries: state.source_entries,
        unique_addresses: state.pools.len(),
        duplicate_entries: state.duplicate_entries,
        conflicting_entries: state.conflicting_entries,
        invalid_entries: state.invalid_entries,
        warnings,
        mixer_counts: state.mixer_counts(),
    })
}

impl MixerCorpusState {
    pub fn summary(&self) -> MixerCorpusSummary {
        MixerCorpusSummary {
            path: self.path.display().to_string(),
            checksum_sha256: self.checksum_sha256.clone(),
            loaded_at: self.loaded_at,
            source_entries: self.source_entries,
            unique_addresses: self.pools.len(),
            duplicate_entries: self.duplicate_entries,
            conflicting_entries: self.conflicting_entries,
            invalid_entries: self.invalid_entries,
            mixer_counts: self.mixer_counts(),
        }
    }

    fn mixer_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for pool in self.pools.values() {
            *counts.entry(pool.label.clone()).or_insert(0) += 1;
        }
        counts
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum MixerCorpus {
    Map(HashMap<String, MixerPoolMetadata>),
    List(Vec<MixerPoolRecord>),
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct MixerPoolRecord {
    address: String,
    #[serde(flatten)]
    metadata: MixerPoolMetadata,
}

fn default_mixer_records() -> Vec<MixerPoolRecord> {
    vec![
        MixerPoolRecord {
            address: "0x12d66f87a04a9e220c9d2457c68a57bde0f7aa90".into(),
            metadata: MixerPoolMetadata {
                label: "tornado_cash".into(),
                denomination_eth: 0.1,
                protocol_family: Some("tornado".into()),
                source: Some("built_in".into()),
                confidence: Some(1.0),
            },
        },
        MixerPoolRecord {
            address: "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936".into(),
            metadata: MixerPoolMetadata {
                label: "tornado_cash".into(),
                denomination_eth: 1.0,
                protocol_family: Some("tornado".into()),
                source: Some("built_in".into()),
                confidence: Some(1.0),
            },
        },
        MixerPoolRecord {
            address: "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf".into(),
            metadata: MixerPoolMetadata {
                label: "tornado_cash".into(),
                denomination_eth: 10.0,
                protocol_family: Some("tornado".into()),
                source: Some("built_in".into()),
                confidence: Some(1.0),
            },
        },
        MixerPoolRecord {
            address: "0xa160cdab225685da1d56aa342ad8841c3b53f291".into(),
            metadata: MixerPoolMetadata {
                label: "tornado_cash".into(),
                denomination_eth: 100.0,
                protocol_family: Some("tornado".into()),
                source: Some("built_in".into()),
                confidence: Some(1.0),
            },
        },
    ]
}

fn normalize_address(address: &str) -> Result<String> {
    let normalized = address.trim().to_ascii_lowercase();
    let _ = Address::from_str(&normalized)
        .with_context(|| format!("invalid EVM address in mixer corpus: {address}"))?;
    Ok(normalized)
}

fn checksum_for_entries(entries: &HashMap<String, MixerPoolMetadata>) -> Result<String> {
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
    use super::{
        detect_mixer_entry, load_mixer_corpus_state, mixer_label_for, validate_mixer_corpus,
    };
    use ethers::types::{Address, Transaction, TxHash, U256, U64};
    use std::fs;
    use std::str::FromStr;
    use uuid::Uuid;

    #[test]
    fn detects_known_mixer_pool() {
        let path = std::env::temp_dir().join(format!("ghost-mixer-{}.json", Uuid::new_v4()));
        let state = load_mixer_corpus_state(&path).unwrap();
        let pool = Address::from_str("0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936").unwrap();
        let tx = Transaction {
            hash: TxHash::from_low_u64_be(11),
            from: Address::from_low_u64_be(1),
            to: Some(pool),
            value: U256::zero(),
            nonce: U256::zero(),
            gas: U256::zero(),
            gas_price: None,
            input: Default::default(),
            transaction_type: Some(U64::from(2_u64)),
            ..Default::default()
        };

        let entry = detect_mixer_entry(&tx, pool, &state, Some("0xexploit")).unwrap();
        assert_eq!(entry.pool_denomination_eth, 1.0);
        assert_eq!(entry.mixer, "tornado_cash");
        assert_eq!(entry.protocol_family.as_deref(), Some("tornado"));
        assert_eq!(
            mixer_label_for(pool, &state),
            Some("tornado_cash".to_string())
        );
    }

    #[test]
    fn validates_and_merges_custom_mixer_entries() {
        let path = std::env::temp_dir().join(format!("ghost-mixer-{}.json", Uuid::new_v4()));
        fs::write(
            &path,
            r#"[
                {"address":"0x00000000000000000000000000000000000000aa","label":"railgun","denomination_eth":0.0,"protocol_family":"zk_privacy"}
            ]"#,
        )
        .unwrap();

        let report = validate_mixer_corpus(&path).unwrap();
        assert!(report.unique_addresses >= 5);
        let _ = fs::remove_file(path);
    }
}
