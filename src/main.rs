mod api;
mod artifacts;
mod billing;
mod bounty;
mod config;
mod db;
mod detection;
mod intelligence;
mod legal;
mod model;
mod monitoring;
mod notifications;
mod orchestrator;
mod proactive;
mod protocols;
mod schema;
mod simulation;
mod state;
mod tracking;
mod verification;

use actix_web::{web, App, HttpServer};
use config::Config;
use ethers::providers::{Http, Provider, Ws};
use std::sync::Arc;
use tokio::sync::RwLock;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Some(exit_code) = handle_cli_commands()? {
        return if exit_code == 0 {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Ghost CLI exited with status {exit_code}"),
            ))
        };
    }

    let config = Config::from_env().map_err(to_io_error)?;
    let protocols =
        protocols::ProtocolRegistry::load(&config.protocols_file).map_err(to_io_error)?;
    db::run_pending_migrations(&config.database_url)
        .await
        .map_err(to_io_error)?;
    let pool = db::create_pool(&config.database_url)
        .await
        .map_err(to_io_error)?;
    billing::retainer::sync_protocol_configs_from_registry(&pool, &protocols)
        .await
        .map_err(to_io_error)?;

    let provider =
        Provider::<Http>::try_from(config.alchemy_http_url.as_str()).map_err(to_io_error)?;
    let ws_provider = Arc::new(
        Provider::<Ws>::connect(config.alchemy_ws_url.as_str())
            .await
            .map_err(to_io_error)?,
    );
    let cex_wallets = Arc::new(RwLock::new(
        tracking::cex_surveillance::load_cex_wallet_corpus_state(&config.cex_wallets_file)
            .map_err(to_io_error)?,
    ));
    let bridge_corpus = Arc::new(RwLock::new(
        intelligence::bridge_corpus::load_bridge_corpus_state(&config.bridge_addresses_file)
            .map_err(to_io_error)?,
    ));
    let mixer_corpus = Arc::new(RwLock::new(
        tracking::mixer_detector::load_mixer_corpus_state(&config.mixer_pools_file)
            .map_err(to_io_error)?,
    ));
    let fund_tracker = tracking::fund_tracker::FundTracker::new();

    let artifact_store =
        artifacts::ArtifactStore::new(config.artifact_dir.clone(), config.zero_g.clone());
    let notifications =
        notifications::NotificationService::new(config.smtp.clone(), config.operator_email.clone());
    let state = Arc::new(state::AppState {
        config: config.clone(),
        provider,
        ws_provider: ws_provider.clone(),
        pool: pool.clone(),
        protocols,
        artifact_store,
        notifications,
        http_client: reqwest::Client::new(),
        fund_tracker,
        cex_wallets: cex_wallets.clone(),
        bridge_corpus: bridge_corpus.clone(),
        mixer_corpus: mixer_corpus.clone(),
    });

    let listener_state = state.clone();
    let listener_url = config.alchemy_ws_url.clone();
    tokio::spawn(async move {
        if let Err(error) =
            crate::detection::mempool_listener::start_mempool_watcher(&listener_url, listener_state)
                .await
        {
            tracing::error!(error = %error, "mempool watcher stopped");
        }
    });

    if std::env::var("NATIVE_USD_FEED_ADDRESS")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .is_some()
    {
        let bounty_provider = ws_provider.clone();
        let bounty_pool = Arc::new(pool.clone());
        let stripe_key = config.stripe_api_key.clone().unwrap_or_default();
        tokio::spawn(async move {
            if let Err(error) = crate::billing::success_fee::watch_bounty_claims(
                bounty_provider,
                bounty_pool,
                stripe_key,
            )
            .await
            {
                tracing::error!(error = %error, "bounty claim watcher stopped");
            }
        });
    }

    proactive::scheduler::start(state.clone());

    let cex_summary = state.cex_wallets.read().await.summary();
    let bridge_summary = state.bridge_corpus.read().await.summary();
    let mixer_summary = state.mixer_corpus.read().await.summary();

    tracing::info!(
        bind = %config.http_bind,
        chain = %config.chain_name,
        protocols_loaded = state.protocols.protocol_count(),
        cex_wallets_loaded = cex_summary.unique_addresses,
        cex_wallets_checksum = %cex_summary.checksum_sha256,
        bridge_addresses_loaded = bridge_summary.unique_addresses,
        bridge_addresses_checksum = %bridge_summary.checksum_sha256,
        mixer_pools_loaded = mixer_summary.unique_addresses,
        mixer_pools_checksum = %mixer_summary.checksum_sha256,
        zero_g_enabled = matches!(state.artifact_store, crate::artifacts::ArtifactStore::ZeroG(_)),
        openai_enabled = state.config.openai_api_key.is_some(),
        "Ghost service starting"
    );

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(api::configure)
    })
    .bind(config.http_bind)?
    .run()
    .await
}

fn to_io_error(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, error.to_string())
}

fn handle_cli_commands() -> std::io::Result<Option<i32>> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return Ok(None);
    };

    match command.as_str() {
        "validate-cex-corpus" => {
            let path = args
                .next()
                .map(std::path::PathBuf::from)
                .or_else(|| std::env::var("CEX_WALLETS_FILE").ok().map(Into::into))
                .unwrap_or_else(|| "cex_wallets.json".into());
            let report = tracking::cex_surveillance::validate_cex_wallet_corpus(&path)
                .map_err(to_io_error)?;
            let output = serde_json::to_string_pretty(&report).map_err(to_io_error)?;
            println!("{output}");
            Ok(Some(0))
        }
        "validate-bridge-corpus" => {
            let path = args
                .next()
                .map(std::path::PathBuf::from)
                .or_else(|| std::env::var("BRIDGE_ADDRESSES_FILE").ok().map(Into::into))
                .unwrap_or_else(|| "bridge_addresses.json".into());
            let report =
                intelligence::bridge_corpus::validate_bridge_corpus(&path).map_err(to_io_error)?;
            let output = serde_json::to_string_pretty(&report).map_err(to_io_error)?;
            println!("{output}");
            Ok(Some(0))
        }
        "validate-mixer-corpus" => {
            let path = args
                .next()
                .map(std::path::PathBuf::from)
                .or_else(|| std::env::var("MIXER_POOLS_FILE").ok().map(Into::into))
                .unwrap_or_else(|| "mixer_pools.json".into());
            let report =
                tracking::mixer_detector::validate_mixer_corpus(&path).map_err(to_io_error)?;
            let output = serde_json::to_string_pretty(&report).map_err(to_io_error)?;
            println!("{output}");
            Ok(Some(0))
        }
        _ => Ok(None),
    }
}
