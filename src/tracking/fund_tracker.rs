use crate::tracking::cex_surveillance::{detect_cex_deposit, CexCorpusState, CexDeposit};
use crate::tracking::mixer_detector::{detect_mixer_entry, MixerEntry};
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

#[derive(Clone)]
pub struct FundTracker {
    pub watched_wallets: Arc<RwLock<HashSet<Address>>>,
    pub tree: Arc<RwLock<HashMap<Address, Vec<Address>>>>,
    pub cex_deposits: Arc<RwLock<Vec<CexDeposit>>>,
    pub mixer_entries: Arc<RwLock<Vec<MixerEntry>>>,
    pub wallet_contexts: Arc<RwLock<HashMap<Address, TrackingContext>>>,
    watch_loop_started: Arc<AtomicBool>,
}

impl FundTracker {
    pub fn new() -> Self {
        Self {
            watched_wallets: Arc::new(RwLock::new(HashSet::new())),
            tree: Arc::new(RwLock::new(HashMap::new())),
            cex_deposits: Arc::new(RwLock::new(Vec::new())),
            mixer_entries: Arc::new(RwLock::new(Vec::new())),
            wallet_contexts: Arc::new(RwLock::new(HashMap::new())),
            watch_loop_started: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn start_tracking(
        &self,
        origin: Address,
        provider: Arc<Provider<Ws>>,
        cex_wallets: Arc<RwLock<CexCorpusState>>,
        context: TrackingContext,
    ) -> Result<()> {
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
                                tracker.process_outbound_tx(&tx, &cex_wallets).await;
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

    async fn process_outbound_tx(
        &self,
        tx: &Transaction,
        cex_wallets: &Arc<RwLock<CexCorpusState>>,
    ) {
        let context = {
            let contexts = self.wallet_contexts.read().await;
            contexts.get(&tx.from).cloned()
        };

        if let Some(to) = tx.to {
            let Some(context) = context else {
                return;
            };
            self.tree.write().await.entry(tx.from).or_default().push(to);
            self.watched_wallets.write().await.insert(to);
            self.wallet_contexts
                .write()
                .await
                .entry(to)
                .or_insert_with(|| context.clone());
            self.check_cex_deposit(tx, to, cex_wallets, &context).await;
            self.check_mixer_entry(tx, to, &context).await;
        }
    }

    async fn check_cex_deposit(
        &self,
        tx: &Transaction,
        to: Address,
        cex_wallets: &Arc<RwLock<CexCorpusState>>,
        context: &TrackingContext,
    ) {
        let corpus = cex_wallets.read().await;
        if let Some(deposit) =
            detect_cex_deposit(tx, to, &corpus.wallets, Some(&context.exploit_tx_hash))
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

    async fn check_mixer_entry(&self, tx: &Transaction, to: Address, context: &TrackingContext) {
        if let Some(entry) = detect_mixer_entry(tx, to) {
            tracing::warn!(
                incident_id = %context.incident_id,
                protocol_id = ?context.protocol_id,
                started_at = %context.started_at,
                "Mixer entry: {} ETH pool | wallet: {:?}",
                entry.pool_denomination_eth,
                tx.from
            );
            self.mixer_entries.write().await.push(entry);
        }
    }
}
