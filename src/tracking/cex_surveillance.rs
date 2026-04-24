use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ethers::types::{Address, Transaction};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, serde::Serialize, Clone, PartialEq, Eq)]
pub struct CexDeposit {
    pub exchange: String,
    pub deposit_tx_hash: String,
    pub exploit_tx_hash: String,
    pub amount: String,
    pub legal_basis: String,
}

#[derive(Debug, Clone)]
pub struct CexCorpusState {
    pub path: PathBuf,
    pub checksum_sha256: String,
    pub loaded_at: DateTime<Utc>,
    pub source_entries: usize,
    pub duplicate_entries: usize,
    pub conflicting_entries: usize,
    pub invalid_entries: usize,
    pub wallets: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CexCorpusSummary {
    pub path: String,
    pub checksum_sha256: String,
    pub loaded_at: DateTime<Utc>,
    pub source_entries: usize,
    pub unique_addresses: usize,
    pub duplicate_entries: usize,
    pub conflicting_entries: usize,
    pub invalid_entries: usize,
    pub exchange_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CexCorpusValidationReport {
    pub path: String,
    pub checksum_sha256: String,
    pub source_entries: usize,
    pub unique_addresses: usize,
    pub duplicate_entries: usize,
    pub conflicting_entries: usize,
    pub invalid_entries: usize,
    pub warnings: Vec<String>,
    pub exchange_counts: BTreeMap<String, usize>,
}

pub fn detect_cex_deposit(
    tx: &Transaction,
    to: Address,
    cex_wallets: &HashMap<String, String>,
    exploit_tx_hash: Option<&str>,
) -> Option<CexDeposit> {
    let to_str = normalize_address(&format!("{to:?}")).ok()?;
    let exchange = cex_wallets.get(&to_str)?;

    Some(CexDeposit {
        exchange: exchange.clone(),
        deposit_tx_hash: format!("{:?}", tx.hash),
        exploit_tx_hash: exploit_tx_hash.unwrap_or_default().to_string(),
        amount: tx.value.to_string(),
        legal_basis: legal_basis_for_exchange(exchange).to_string(),
    })
}

pub fn load_cex_wallet_corpus_state(path: &Path) -> Result<CexCorpusState> {
    if !path.exists() {
        tracing::warn!(
            "CEX wallet corpus {} does not exist; fund tracking will run without exchange attribution",
            path.display()
        );
        return Ok(CexCorpusState {
            path: path.to_path_buf(),
            checksum_sha256: checksum_for_entries(&HashMap::new())?,
            loaded_at: Utc::now(),
            source_entries: 0,
            duplicate_entries: 0,
            conflicting_entries: 0,
            invalid_entries: 0,
            wallets: HashMap::new(),
        });
    }

    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read CEX wallet corpus {}", path.display()))?;
    let corpus: CexCorpus = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse CEX wallet corpus {}", path.display()))?;

    let entries = match corpus {
        CexCorpus::Map(entries) => entries
            .into_iter()
            .map(|(address, exchange)| CexWalletRecord { address, exchange })
            .collect::<Vec<_>>(),
        CexCorpus::List(entries) => entries,
    };

    let mut normalized = HashMap::new();
    let mut duplicate_entries = 0usize;
    let mut conflicting_entries = 0usize;
    let mut invalid_entries = 0usize;
    for entry in &entries {
        let normalized_address = match normalize_address(&entry.address) {
            Ok(address) => address,
            Err(_) => {
                invalid_entries += 1;
                tracing::warn!(
                    address = %entry.address,
                    exchange = %entry.exchange,
                    "skipping invalid CEX wallet corpus entry"
                );
                continue;
            }
        };

        match normalized.get(&normalized_address) {
            Some(existing) if existing == &entry.exchange => {
                duplicate_entries += 1;
            }
            Some(existing) if existing != &entry.exchange => {
                conflicting_entries += 1;
                tracing::warn!(
                    address = %normalized_address,
                    existing_exchange = %existing,
                    conflicting_exchange = %entry.exchange,
                    "conflicting exchange labels in CEX wallet corpus; keeping first label"
                );
            }
            None => {
                normalized.insert(normalized_address, entry.exchange.clone());
            }
            _ => {}
        }
    }

    Ok(CexCorpusState {
        path: path.to_path_buf(),
        checksum_sha256: checksum_for_entries(&normalized)?,
        loaded_at: Utc::now(),
        source_entries: entries.len(),
        duplicate_entries,
        conflicting_entries,
        invalid_entries,
        wallets: normalized,
    })
}

pub fn validate_cex_wallet_corpus(path: &Path) -> Result<CexCorpusValidationReport> {
    let state = load_cex_wallet_corpus_state(path)?;
    let mut warnings = Vec::new();
    if state.source_entries == 0 {
        warnings.push("corpus file was empty or missing".to_string());
    }
    if state.duplicate_entries > 0 {
        warnings.push(format!(
            "{} duplicate address entries collapsed to a single canonical record",
            state.duplicate_entries
        ));
    }
    if state.conflicting_entries > 0 {
        warnings.push(format!(
            "{} conflicting address labels were detected; the first label was retained",
            state.conflicting_entries
        ));
    }
    if state.invalid_entries > 0 {
        warnings.push(format!(
            "{} invalid address entries were skipped",
            state.invalid_entries
        ));
    }

    Ok(CexCorpusValidationReport {
        path: state.path.display().to_string(),
        checksum_sha256: state.checksum_sha256.clone(),
        source_entries: state.source_entries,
        unique_addresses: state.wallets.len(),
        duplicate_entries: state.duplicate_entries,
        conflicting_entries: state.conflicting_entries,
        invalid_entries: state.invalid_entries,
        warnings,
        exchange_counts: state.exchange_counts(),
    })
}

pub fn legal_basis_for_exchange(exchange: &str) -> &'static str {
    let normalized = exchange.trim().to_ascii_lowercase();
    if normalized.contains("coinbase")
        || normalized.contains("gemini")
        || normalized.contains("kraken us")
        || normalized.contains("kraken_us")
        || normalized.contains("binance.us")
        || normalized.ends_with(" us")
        || normalized.contains(" us ")
    {
        "FinCEN_SAR"
    } else {
        "MiCA_Article_17"
    }
}

fn normalize_address(address: &str) -> Result<String> {
    let normalized = address.trim().to_ascii_lowercase();
    let _ = Address::from_str(&normalized)
        .with_context(|| format!("invalid EVM address in CEX corpus: {address}"))?;
    Ok(normalized)
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum CexCorpus {
    Map(HashMap<String, String>),
    List(Vec<CexWalletRecord>),
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct CexWalletRecord {
    address: String,
    exchange: String,
}

impl CexCorpusState {
    pub fn summary(&self) -> CexCorpusSummary {
        CexCorpusSummary {
            path: self.path.display().to_string(),
            checksum_sha256: self.checksum_sha256.clone(),
            loaded_at: self.loaded_at,
            source_entries: self.source_entries,
            unique_addresses: self.wallets.len(),
            duplicate_entries: self.duplicate_entries,
            conflicting_entries: self.conflicting_entries,
            invalid_entries: self.invalid_entries,
            exchange_counts: self.exchange_counts(),
        }
    }

    fn exchange_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for exchange in self.wallets.values() {
            *counts.entry(exchange.clone()).or_insert(0) += 1;
        }
        counts
    }
}

fn checksum_for_entries(entries: &HashMap<String, String>) -> Result<String> {
    let canonical = BTreeMap::from_iter(
        entries
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    let payload = serde_json::to_vec(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(payload);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::{
        detect_cex_deposit, legal_basis_for_exchange, load_cex_wallet_corpus_state,
        validate_cex_wallet_corpus,
    };
    use ethers::types::{Address, Transaction, TxHash, U256, U64};
    use std::collections::HashMap;
    use std::fs;
    use std::str::FromStr;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn detects_cex_deposit_and_assigns_legal_basis() {
        let mut cex_wallets = HashMap::new();
        let address = Address::from_str("0x00000000000000000000000000000000000000aa").unwrap();
        cex_wallets.insert(
            format!("{address:?}").to_ascii_lowercase(),
            "Coinbase".to_string(),
        );

        let tx = Transaction {
            hash: TxHash::from_low_u64_be(7),
            from: Address::from_low_u64_be(1),
            to: Some(address),
            value: U256::from(42_u64),
            nonce: U256::zero(),
            gas: U256::zero(),
            gas_price: None,
            input: Default::default(),
            transaction_type: Some(U64::from(2_u64)),
            ..Default::default()
        };

        let deposit = detect_cex_deposit(&tx, address, &cex_wallets, Some("0xexploit")).unwrap();
        assert_eq!(deposit.exchange, "Coinbase");
        assert_eq!(deposit.exploit_tx_hash, "0xexploit");
        assert_eq!(deposit.legal_basis, "FinCEN_SAR");
    }

    #[test]
    fn defaults_non_us_exchange_to_mica_basis() {
        assert_eq!(legal_basis_for_exchange("Bitstamp EU"), "MiCA_Article_17");
    }

    #[test]
    fn loads_corpus_from_list_format() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ghost-cex-wallets-{nonce}.json"));
        fs::write(
            &path,
            r#"[{"address":"0x00000000000000000000000000000000000000aa","exchange":"Coinbase"}]"#,
        )
        .unwrap();

        let corpus = load_cex_wallet_corpus_state(&path).unwrap();
        assert_eq!(
            corpus
                .wallets
                .get("0x00000000000000000000000000000000000000aa"),
            Some(&"Coinbase".to_string())
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn validates_and_deduplicates_corpus() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ghost-cex-wallets-validate-{nonce}.json"));
        fs::write(
            &path,
            r#"
            [
                {"address":"0x00000000000000000000000000000000000000aa","exchange":"Coinbase"},
                {"address":"0x00000000000000000000000000000000000000aa","exchange":"Coinbase"},
                {"address":"0x00000000000000000000000000000000000000aa","exchange":"Coinbase Prime"},
                {"address":"not-an-address","exchange":"Bad"}
            ]
            "#,
        )
        .unwrap();

        let report = validate_cex_wallet_corpus(&path).unwrap();
        assert_eq!(report.unique_addresses, 1);
        assert_eq!(report.duplicate_entries, 1);
        assert_eq!(report.conflicting_entries, 1);
        assert_eq!(report.invalid_entries, 1);
        assert!(!report.checksum_sha256.is_empty());

        let _ = fs::remove_file(path);
    }
}
