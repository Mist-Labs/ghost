use crate::db::insert_monitor_snapshot;
use crate::intelligence::bridge_corpus::{load_bridge_corpus_state, validate_bridge_corpus};
use crate::state::AppState;
use crate::tracking::cex_surveillance::{load_cex_wallet_corpus_state, validate_cex_wallet_corpus};
use crate::tracking::mixer_detector::{load_mixer_corpus_state, validate_mixer_corpus};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;

const SYSTEM_PROTOCOL_ID: &str = "__system__";

#[derive(Debug, Clone, Serialize)]
pub struct AttributionFeedOverview {
    pub configured: Vec<ConfiguredAttributionFeed>,
    pub loaded: Vec<LoadedAttributionCorpus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfiguredAttributionFeed {
    pub kind: String,
    pub source_url: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadedAttributionCorpus {
    pub kind: String,
    pub path: String,
    pub checksum_sha256: String,
    pub loaded_at: DateTime<Utc>,
    pub unique_entries: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttributionFeedSyncResult {
    pub kind: String,
    pub source_url: String,
    pub path: String,
    pub checksum_sha256: String,
    pub synced_at: DateTime<Utc>,
    pub bytes_written: usize,
    pub unique_entries: usize,
    pub warnings: Vec<String>,
}

pub async fn feed_overview(state: &AppState) -> AttributionFeedOverview {
    let cex = state.cex_wallets.read().await.summary();
    let bridge = state.bridge_corpus.read().await.summary();
    let mixer = state.mixer_corpus.read().await.summary();

    AttributionFeedOverview {
        configured: vec![
            ConfiguredAttributionFeed {
                kind: "cex".into(),
                source_url: state.config.cex_wallets_feed_url.clone(),
                path: state.config.cex_wallets_file.display().to_string(),
            },
            ConfiguredAttributionFeed {
                kind: "bridge".into(),
                source_url: state.config.bridge_addresses_feed_url.clone(),
                path: state.config.bridge_addresses_file.display().to_string(),
            },
            ConfiguredAttributionFeed {
                kind: "mixer".into(),
                source_url: state.config.mixer_pools_feed_url.clone(),
                path: state.config.mixer_pools_file.display().to_string(),
            },
        ],
        loaded: vec![
            LoadedAttributionCorpus {
                kind: "cex".into(),
                path: state.config.cex_wallets_file.display().to_string(),
                checksum_sha256: cex.checksum_sha256,
                loaded_at: cex.loaded_at,
                unique_entries: cex.unique_addresses,
            },
            LoadedAttributionCorpus {
                kind: "bridge".into(),
                path: state.config.bridge_addresses_file.display().to_string(),
                checksum_sha256: bridge.checksum_sha256,
                loaded_at: bridge.loaded_at,
                unique_entries: bridge.unique_addresses,
            },
            LoadedAttributionCorpus {
                kind: "mixer".into(),
                path: state.config.mixer_pools_file.display().to_string(),
                checksum_sha256: mixer.checksum_sha256,
                loaded_at: mixer.loaded_at,
                unique_entries: mixer.unique_addresses,
            },
        ],
    }
}

pub fn has_configured_remote_feeds(state: &AppState) -> bool {
    state.config.cex_wallets_feed_url.is_some()
        || state.config.bridge_addresses_feed_url.is_some()
        || state.config.mixer_pools_feed_url.is_some()
}

pub async fn sync_configured_feeds(
    state: &Arc<AppState>,
) -> Result<Vec<AttributionFeedSyncResult>> {
    let mut results = Vec::new();

    if let Some(url) = state.config.cex_wallets_feed_url.as_deref() {
        let result = sync_cex_feed(&state.http_client, url, &state.config.cex_wallets_file).await?;
        *state.cex_wallets.write().await =
            load_cex_wallet_corpus_state(&state.config.cex_wallets_file)?;
        persist_feed_snapshot(state, &result).await?;
        results.push(result);
    }

    if let Some(url) = state.config.bridge_addresses_feed_url.as_deref() {
        let result =
            sync_bridge_feed(&state.http_client, url, &state.config.bridge_addresses_file).await?;
        *state.bridge_corpus.write().await =
            load_bridge_corpus_state(&state.config.bridge_addresses_file)?;
        persist_feed_snapshot(state, &result).await?;
        results.push(result);
    }

    if let Some(url) = state.config.mixer_pools_feed_url.as_deref() {
        let result =
            sync_mixer_feed(&state.http_client, url, &state.config.mixer_pools_file).await?;
        *state.mixer_corpus.write().await =
            load_mixer_corpus_state(&state.config.mixer_pools_file)?;
        persist_feed_snapshot(state, &result).await?;
        results.push(result);
    }

    Ok(results)
}

async fn persist_feed_snapshot(
    state: &Arc<AppState>,
    result: &AttributionFeedSyncResult,
) -> Result<()> {
    let mut conn = state.pool.get().await?;
    insert_monitor_snapshot(
        &mut conn,
        SYSTEM_PROTOCOL_ID,
        "attribution_feed",
        &result.kind,
        serde_json::to_value(result)?,
    )
    .await?;
    Ok(())
}

async fn sync_cex_feed(
    client: &Client,
    url: &str,
    path: &Path,
) -> Result<AttributionFeedSyncResult> {
    let (temp_path, bytes_written) = fetch_to_temp_path(client, url, path).await?;
    let report = validate_cex_wallet_corpus(&temp_path)?;
    promote_temp_path(&temp_path, path).await?;
    Ok(AttributionFeedSyncResult {
        kind: "cex".into(),
        source_url: url.to_string(),
        path: path.display().to_string(),
        checksum_sha256: report.checksum_sha256,
        synced_at: Utc::now(),
        bytes_written,
        unique_entries: report.unique_addresses,
        warnings: report.warnings,
    })
}

async fn sync_bridge_feed(
    client: &Client,
    url: &str,
    path: &Path,
) -> Result<AttributionFeedSyncResult> {
    let (temp_path, bytes_written) = fetch_to_temp_path(client, url, path).await?;
    let report = validate_bridge_corpus(&temp_path)?;
    promote_temp_path(&temp_path, path).await?;
    Ok(AttributionFeedSyncResult {
        kind: "bridge".into(),
        source_url: url.to_string(),
        path: path.display().to_string(),
        checksum_sha256: report.checksum_sha256,
        synced_at: Utc::now(),
        bytes_written,
        unique_entries: report.unique_addresses,
        warnings: report.warnings,
    })
}

async fn sync_mixer_feed(
    client: &Client,
    url: &str,
    path: &Path,
) -> Result<AttributionFeedSyncResult> {
    let (temp_path, bytes_written) = fetch_to_temp_path(client, url, path).await?;
    let report = validate_mixer_corpus(&temp_path)?;
    promote_temp_path(&temp_path, path).await?;
    Ok(AttributionFeedSyncResult {
        kind: "mixer".into(),
        source_url: url.to_string(),
        path: path.display().to_string(),
        checksum_sha256: report.checksum_sha256,
        synced_at: Utc::now(),
        bytes_written,
        unique_entries: report.unique_addresses,
        warnings: report.warnings,
    })
}

async fn fetch_to_temp_path(client: &Client, url: &str, path: &Path) -> Result<(PathBuf, usize)> {
    let payload = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to fetch attribution feed {url}"))?
        .error_for_status()
        .with_context(|| format!("attribution feed {url} returned an error status"))?
        .bytes()
        .await
        .with_context(|| format!("failed to read attribution feed body {url}"))?;

    let parent = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&parent).await?;
    let temp_path = parent.join(format!(
        ".ghost-attribution-{}-{}.tmp",
        sanitize_path_component(path),
        uuid::Uuid::new_v4()
    ));
    fs::write(&temp_path, &payload).await?;
    Ok((temp_path, payload.len()))
}

async fn promote_temp_path(temp_path: &Path, path: &Path) -> Result<()> {
    fs::rename(temp_path, path).await?;
    Ok(())
}

fn sanitize_path_component(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("feed")
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => ch,
            _ => '-',
        })
        .collect()
}
