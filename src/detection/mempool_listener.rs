use crate::state::AppState;
use anyhow::Result;
use ethers::providers::{Middleware, Provider, StreamExt, Ws};
use std::sync::Arc;

pub async fn start_mempool_watcher(ws_url: &str, state: Arc<AppState>) -> Result<()> {
    let provider = Arc::new(Provider::<Ws>::connect(ws_url).await?);
    let mut stream = provider.watch_pending_transactions().await?;

    tracing::info!("Mempool watcher active on {}", ws_url);

    while let Some(tx_hash) = stream.next().await {
        let provider = provider.clone();
        let state = state.clone();
        tokio::spawn(async move {
            match provider.get_transaction(tx_hash).await {
                Ok(Some(tx)) => {
                    if let Err(e) =
                        crate::orchestrator::on_suspicious_transaction(tx, state.clone()).await
                    {
                        tracing::warn!(error = %e, tx_hash = ?tx_hash, "Orchestrator failed");
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, tx_hash = ?tx_hash, "Failed to fetch transaction")
                }
            }
        });
    }

    Ok(())
}
