use crate::intelligence::bridge_corpus::{
    detect_bridge_transfer, BridgeCorpusState, BridgeTransfer,
};
use crate::tracking::cex_surveillance::{detect_cex_deposit, CexCorpusState, CexDeposit};
use crate::tracking::mixer_detector::{detect_mixer_entry, MixerCorpusState, MixerEntry};
use anyhow::Result;
use chrono::{DateTime, Utc};
use ethers::providers::{Middleware, Provider, StreamExt, Ws};
use ethers::types::{Address, Transaction};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct TrackingContext {
    pub incident_id: Uuid,
    pub exploit_tx_hash: String,
    pub protocol_id: Option<String>,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorpusSnapshotMetadata {
    pub path: String,
    pub checksum_sha256: String,
    pub loaded_at: DateTime<Utc>,
    pub source_entries: usize,
    pub unique_entries: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IncidentCorpusProvenance {
    pub cex: CorpusSnapshotMetadata,
    pub bridge: CorpusSnapshotMetadata,
    pub mixer: CorpusSnapshotMetadata,
}

#[derive(Debug, Clone)]
pub struct IncidentCorpusSnapshot {
    pub cex: CexCorpusState,
    pub bridge: BridgeCorpusState,
    pub mixer: MixerCorpusState,
}

impl IncidentCorpusSnapshot {
    pub async fn capture(
        cex_wallets: &Arc<RwLock<CexCorpusState>>,
        bridge_corpus: &Arc<RwLock<BridgeCorpusState>>,
        mixer_corpus: &Arc<RwLock<MixerCorpusState>>,
    ) -> Self {
        Self {
            cex: cex_wallets.read().await.clone(),
            bridge: bridge_corpus.read().await.clone(),
            mixer: mixer_corpus.read().await.clone(),
        }
    }

    pub fn provenance(&self) -> IncidentCorpusProvenance {
        IncidentCorpusProvenance {
            cex: CorpusSnapshotMetadata {
                path: self.cex.path.display().to_string(),
                checksum_sha256: self.cex.checksum_sha256.clone(),
                loaded_at: self.cex.loaded_at,
                source_entries: self.cex.source_entries,
                unique_entries: self.cex.wallets.len(),
            },
            bridge: CorpusSnapshotMetadata {
                path: self.bridge.path.display().to_string(),
                checksum_sha256: self.bridge.checksum_sha256.clone(),
                loaded_at: self.bridge.loaded_at,
                source_entries: self.bridge.source_entries,
                unique_entries: self.bridge.bridges.len(),
            },
            mixer: CorpusSnapshotMetadata {
                path: self.mixer.path.display().to_string(),
                checksum_sha256: self.mixer.checksum_sha256.clone(),
                loaded_at: self.mixer.loaded_at,
                source_entries: self.mixer.source_entries,
                unique_entries: self.mixer.pools.len(),
            },
        }
    }
}

#[derive(Clone)]
pub struct FundTracker {
    pub watched_wallets: Arc<RwLock<HashSet<Address>>>,
    pub tree: Arc<RwLock<HashMap<Address, Vec<Address>>>>,
    pub cex_deposits: Arc<RwLock<Vec<CexDeposit>>>,
    pub bridge_transfers: Arc<RwLock<Vec<BridgeTransfer>>>,
    pub mixer_entries: Arc<RwLock<Vec<MixerEntry>>>,
    pub wallet_contexts: Arc<RwLock<HashMap<Address, TrackingContext>>>,
    pub incident_corpora: Arc<RwLock<HashMap<Uuid, IncidentCorpusSnapshot>>>,
    watch_loop_started: Arc<AtomicBool>,
}

impl FundTracker {
    pub fn new() -> Self {
        Self {
            watched_wallets: Arc::new(RwLock::new(HashSet::new())),
            tree: Arc::new(RwLock::new(HashMap::new())),
            cex_deposits: Arc::new(RwLock::new(Vec::new())),
            bridge_transfers: Arc::new(RwLock::new(Vec::new())),
            mixer_entries: Arc::new(RwLock::new(Vec::new())),
            wallet_contexts: Arc::new(RwLock::new(HashMap::new())),
            incident_corpora: Arc::new(RwLock::new(HashMap::new())),
            watch_loop_started: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn start_tracking(
        &self,
        origin: Address,
        provider: Arc<Provider<Ws>>,
        corpus_snapshot: IncidentCorpusSnapshot,
        context: TrackingContext,
    ) -> Result<()> {
        self.incident_corpora
            .write()
            .await
            .insert(context.incident_id, corpus_snapshot);
        self.watched_wallets.write().await.insert(origin);
        self.tree.write().await.entry(origin).or_default();
        self.wallet_contexts.write().await.insert(origin, context);

        if self
            .watch_loop_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }

        let tracker = self.clone();
        let provider_clone = provider.clone();
        let provider_for_async = provider.clone();
        let watch_loop_started = self.watch_loop_started.clone();

        tokio::spawn(async move {
            let result = async move {
                let mut stream = provider_clone.watch_blocks().await?;
                while let Some(block_hash) = stream.next().await {
                    if let Ok(Some(block)) = provider_for_async.get_block_with_txs(block_hash).await
                    {
                        for tx in block.transactions {
                            if tracker.watched_wallets.read().await.contains(&tx.from) {
                                tracker.process_outbound_tx(&tx).await;
                            }
                        }
                    }
                }
                Ok::<(), anyhow::Error>(())
            }
            .await;

            if let Err(error) = result {
                tracing::error!(error = %error, "fund tracker block watcher stopped");
            }
            watch_loop_started.store(false, Ordering::Release);
        });

        Ok(())
    }

    async fn process_outbound_tx(&self, tx: &Transaction) {
        let context = {
            let contexts = self.wallet_contexts.read().await;
            contexts.get(&tx.from).cloned()
        };

        if let Some(to) = tx.to {
            let Some(context) = context else {
                return;
            };
            let corpus_snapshot = {
                let snapshots = self.incident_corpora.read().await;
                snapshots.get(&context.incident_id).cloned()
            };
            let Some(corpus_snapshot) = corpus_snapshot else {
                tracing::warn!(
                    incident_id = %context.incident_id,
                    "missing pinned corpus snapshot for tracked incident"
                );
                return;
            };
            self.tree.write().await.entry(tx.from).or_default().push(to);
            self.watched_wallets.write().await.insert(to);
            self.wallet_contexts
                .write()
                .await
                .entry(to)
                .or_insert_with(|| context.clone());
            self.check_cex_deposit(tx, to, &corpus_snapshot.cex, &context)
                .await;
            self.check_bridge_transfer(tx, to, &corpus_snapshot.bridge, &context)
                .await;
            self.check_mixer_entry(tx, to, &corpus_snapshot.mixer, &context)
                .await;
        }
    }

    async fn check_cex_deposit(
        &self,
        tx: &Transaction,
        to: Address,
        cex_wallets: &CexCorpusState,
        context: &TrackingContext,
    ) {
        if let Some(deposit) =
            detect_cex_deposit(tx, to, &cex_wallets.wallets, Some(&context.exploit_tx_hash))
        {
            tracing::warn!(
                incident_id = %context.incident_id,
                protocol_id = ?context.protocol_id,
                "CEX deposit detected → {} | tx: {:?}",
                deposit.exchange,
                tx.hash
            );
            self.cex_deposits.write().await.push(deposit);
        }
    }

    async fn check_bridge_transfer(
        &self,
        tx: &Transaction,
        to: Address,
        bridge_corpus: &BridgeCorpusState,
        context: &TrackingContext,
    ) {
        if let Some(transfer) = detect_bridge_transfer(
            tx,
            to,
            &bridge_corpus.bridges,
            Some(&context.exploit_tx_hash),
        ) {
            tracing::warn!(
                incident_id = %context.incident_id,
                protocol_id = ?context.protocol_id,
                "Bridge transfer detected → {} | tx: {:?}",
                transfer.bridge,
                tx.hash
            );
            self.bridge_transfers.write().await.push(transfer);
        }
    }

    async fn check_mixer_entry(
        &self,
        tx: &Transaction,
        to: Address,
        mixer_corpus: &MixerCorpusState,
        context: &TrackingContext,
    ) {
        if let Some(entry) =
            detect_mixer_entry(tx, to, mixer_corpus, Some(&context.exploit_tx_hash))
        {
            tracing::warn!(
                incident_id = %context.incident_id,
                protocol_id = ?context.protocol_id,
                started_at = %context.started_at,
                mixer = %entry.mixer,
                "Mixer entry: {} ETH pool | wallet: {:?}",
                entry.pool_denomination_eth,
                tx.from
            );
            self.mixer_entries.write().await.push(entry);
        }
    }

    pub async fn incident_corpus_snapshot(
        &self,
        incident_id: Uuid,
    ) -> Option<IncidentCorpusSnapshot> {
        self.incident_corpora
            .read()
            .await
            .get(&incident_id)
            .cloned()
    }

    pub async fn incident_wallet_tree(&self, incident_id: Uuid) -> Vec<serde_json::Value> {
        let tree = self.tree.read().await;
        let contexts = self.wallet_contexts.read().await;

        tree.iter()
            .filter_map(|(from, tos)| {
                let from_context = contexts.get(from)?;
                if from_context.incident_id != incident_id {
                    return None;
                }
                let filtered_tos = tos
                    .iter()
                    .copied()
                    .filter(|address| {
                        contexts
                            .get(address)
                            .map(|context| context.incident_id == incident_id)
                            .unwrap_or(false)
                    })
                    .map(|address| format!("{address:?}"))
                    .collect::<Vec<_>>();
                Some(serde_json::json!({
                    "from": format!("{from:?}"),
                    "to": filtered_tos,
                }))
            })
            .collect()
    }

    pub async fn incident_cex_deposits(&self, exploit_tx_hash: &str) -> Vec<CexDeposit> {
        self.cex_deposits
            .read()
            .await
            .iter()
            .filter(|deposit| deposit.exploit_tx_hash == exploit_tx_hash)
            .cloned()
            .collect()
    }

    pub async fn incident_bridge_transfers(&self, exploit_tx_hash: &str) -> Vec<BridgeTransfer> {
        self.bridge_transfers
            .read()
            .await
            .iter()
            .filter(|transfer| transfer.exploit_tx_hash == exploit_tx_hash)
            .cloned()
            .collect()
    }

    pub async fn incident_mixer_entries(&self, exploit_tx_hash: &str) -> Vec<MixerEntry> {
        self.mixer_entries
            .read()
            .await
            .iter()
            .filter(|entry| entry.exploit_tx_hash == exploit_tx_hash)
            .cloned()
            .collect()
    }
}
