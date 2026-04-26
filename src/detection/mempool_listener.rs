use crate::state::AppState;
use anyhow::Result;
use ethers::providers::{Middleware, Provider, StreamExt, Ws};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

const PENDING_TX_FETCH_ATTEMPTS: usize = 8;
const PENDING_TX_FETCH_INTERVAL_MS: u64 = 400;

pub async fn start_mempool_watcher(ws_url: &str, state: Arc<AppState>) -> Result<()> {
    let provider = Arc::new(Provider::<Ws>::connect(ws_url).await?);
    let mut stream = provider.watch_pending_transactions().await?;

    tracing::info!("Mempool watcher active on {}", ws_url);

    while let Some(tx_hash) = stream.next().await {
        let provider = provider.clone();
        let state = state.clone();
        tokio::spawn(async move {
            match fetch_pending_transaction(provider.clone(), tx_hash).await {
                Ok(Some(tx)) => {
                    if let Err(e) =
                        crate::orchestrator::on_suspicious_transaction(tx, state.clone()).await
                    {
                        tracing::warn!(error = %e, tx_hash = ?tx_hash, "Orchestrator failed");
                    }
                }
                Ok(None) => {
                    tracing::debug!(tx_hash = ?tx_hash, "Pending transaction details unavailable after retries");
                }
                Err(e) => {
                    tracing::warn!(error = %e, tx_hash = ?tx_hash, "Failed to fetch transaction")
                }
            }
        });
    }

    Ok(())
}

async fn fetch_pending_transaction(
    provider: Arc<Provider<Ws>>,
    tx_hash: ethers::types::H256,
) -> Result<Option<ethers::types::Transaction>> {
    for attempt in 0..PENDING_TX_FETCH_ATTEMPTS {
        if let Some(tx) = provider.get_transaction(tx_hash).await? {
            return Ok(Some(tx));
        }

        if attempt + 1 < PENDING_TX_FETCH_ATTEMPTS {
            sleep(Duration::from_millis(PENDING_TX_FETCH_INTERVAL_MS)).await;
        }
    }

    Ok(None)
}
