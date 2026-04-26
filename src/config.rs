use anyhow::{anyhow, Context, Result};
use std::env;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    pub http_bind: String,
    pub chain_name: String,
    pub chain_id: u64,
    pub database_url: String,
    pub alchemy_http_url: String,
    pub alchemy_ws_url: String,
    pub explorer_api_url: String,
    pub protocols_file: PathBuf,
    pub cex_wallets_file: PathBuf,
    pub bridge_addresses_file: PathBuf,
    pub mixer_pools_file: PathBuf,
    pub cex_wallets_feed_url: Option<String>,
    pub bridge_addresses_feed_url: Option<String>,
    pub mixer_pools_feed_url: Option<String>,
    pub artifact_dir: PathBuf,
    pub min_alert_score: u8,
    pub hack_feed_poll_interval_secs: u64,
    pub full_scan_interval_secs: u64,
    pub attribution_feed_sync_interval_secs: u64,
    pub disclosure_followup_interval_secs: u64,
    pub disclosure_first_response_sla_hours: u64,
    pub disclosure_resolution_sla_days: u64,
    pub operator_email: Option<String>,
    pub api_key: Option<String>,
    pub smtp: Option<SmtpConfig>,
    pub keeperhub_webhook_url: Option<String>,
    pub zero_g: Option<ZeroGConfig>,
    pub kimi_api_key: Option<String>,
    pub kimi_model: String,
    pub kimi_base_url: String,
    pub solc_binary: String,
    pub solc_bin_dir: Option<PathBuf>,
    pub solc_auto_install: bool,
    pub anvil_binary: String,
    pub simulation_fork_block_number: Option<u64>,
    pub simulation_startup_timeout_secs: u64,
    pub basescan_api_key: Option<String>,
    pub stripe_api_key: Option<String>,
    pub bloxroute_auth_header: Option<String>,
    pub bloxroute_tx_lookup_url_template: String,
    pub maxmind_db_path: Option<PathBuf>,
    pub mugen: Option<MugenConfig>,
    pub bounty: Option<BountyConfig>,
    pub filing_bearer_token: Option<String>,
    pub filing_timeout_secs: u64,
    pub ic3_submission_url: Option<String>,
    pub national_cybercrime_submission_url: Option<String>,
    pub ec3_coordination_submission_url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SmtpConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_email: String,
}

#[derive(Clone, Debug)]
pub struct ZeroGConfig {
    pub rpc_url: String,
    pub indexer_rpc: String,
    pub private_key: String,
    pub node_binary: String,
    pub publish_script: PathBuf,
}

#[derive(Clone, Debug)]
pub struct MugenConfig {
    pub gateway_url: String,
    pub api_key: Option<String>,
    pub model_id: String,
    pub poll_interval_secs: u64,
    pub max_polls: u32,
}

#[derive(Clone, Debug)]
pub struct BountyConfig {
    pub private_key: String,
    pub solc_binary: String,
    pub contract_path: PathBuf,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let http_bind = env::var("HTTP_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
        let chain_name = env::var("CHAIN_NAME").unwrap_or_else(|_| "base".to_string());
        let chain_id = env::var("CHAIN_ID")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("CHAIN_ID must be a valid u64")?
            .unwrap_or(8453);
        let database_url = required("DATABASE_URL")?;
        let alchemy_http_url = required("ALCHEMY_HTTP_URL")?;
        let alchemy_ws_url = required("ALCHEMY_WS_URL")?;
        let explorer_api_url = env::var("EXPLORER_API_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| normalize_explorer_api_url(&value, chain_id))
            .unwrap_or_else(|| default_explorer_api_url(chain_id));
        let protocols_file = PathBuf::from(
            env::var("PROTOCOLS_FILE").unwrap_or_else(|_| "protocols.json".to_string()),
        );
        let cex_wallets_file = PathBuf::from(
            env::var("CEX_WALLETS_FILE").unwrap_or_else(|_| "cex_wallets.json".to_string()),
        );
        let bridge_addresses_file = PathBuf::from(
            env::var("BRIDGE_ADDRESSES_FILE")
                .unwrap_or_else(|_| "bridge_addresses.json".to_string()),
        );
        let mixer_pools_file = PathBuf::from(
            env::var("MIXER_POOLS_FILE").unwrap_or_else(|_| "mixer_pools.json".to_string()),
        );
        let artifact_dir =
            PathBuf::from(env::var("ARTIFACT_DIR").unwrap_or_else(|_| "artifacts".to_string()));
        let cex_wallets_feed_url = env::var("CEX_WALLETS_FEED_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let bridge_addresses_feed_url = env::var("BRIDGE_ADDRESSES_FEED_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let mixer_pools_feed_url = env::var("MIXER_POOLS_FEED_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let min_alert_score = env::var("MIN_ALERT_SCORE")
            .ok()
            .map(|value| value.parse::<u8>())
            .transpose()
            .context("MIN_ALERT_SCORE must be a valid integer")?
            .unwrap_or(2);
        let hack_feed_poll_interval_secs = env::var("HACK_FEED_POLL_INTERVAL_SECS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("HACK_FEED_POLL_INTERVAL_SECS must be a valid u64")?
            .unwrap_or(900);
        let full_scan_interval_secs = env::var("FULL_SCAN_INTERVAL_SECS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("FULL_SCAN_INTERVAL_SECS must be a valid u64")?
            .unwrap_or(86400);
        let attribution_feed_sync_interval_secs = env::var("ATTRIBUTION_FEED_SYNC_INTERVAL_SECS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("ATTRIBUTION_FEED_SYNC_INTERVAL_SECS must be a valid u64")?
            .unwrap_or(3600);
        let disclosure_followup_interval_secs = env::var("DISCLOSURE_FOLLOWUP_INTERVAL_SECS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("DISCLOSURE_FOLLOWUP_INTERVAL_SECS must be a valid u64")?
            .unwrap_or(3600);
        let disclosure_first_response_sla_hours = env::var("DISCLOSURE_FIRST_RESPONSE_SLA_HOURS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("DISCLOSURE_FIRST_RESPONSE_SLA_HOURS must be a valid u64")?
            .unwrap_or(24);
        let disclosure_resolution_sla_days = env::var("DISCLOSURE_RESOLUTION_SLA_DAYS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("DISCLOSURE_RESOLUTION_SLA_DAYS must be a valid u64")?
            .unwrap_or(90);
        let operator_email = env::var("OPERATOR_EMAIL")
            .ok()
            .or_else(|| env::var("ALERT_EMAIL").ok())
            .filter(|value| !value.trim().is_empty());
        let api_key = env::var("GHOST_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let keeperhub_webhook_url = env::var("KEEPERHUB_WEBHOOK_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let kimi_api_key = env::var("KIMI_API_KEY")
            .ok()
            .or_else(|| env::var("OPENAI_API_KEY").ok())
            .filter(|value| !value.trim().is_empty());
        let kimi_model = env::var("KIMI_MODEL")
            .ok()
            .or_else(|| env::var("OPENAI_MODEL").ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "kimi-k2.6".to_string());
        let kimi_base_url = env::var("KIMI_BASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "https://api.moonshot.ai/v1".to_string());
        let solc_binary = env::var("SOLC_BINARY").unwrap_or_else(|_| "solc".to_string());
        let solc_bin_dir = env::var("SOLC_BIN_DIR")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        let solc_auto_install = env::var("SOLC_AUTO_INSTALL")
            .ok()
            .map(|value| parse_bool(&value))
            .transpose()
            .context("SOLC_AUTO_INSTALL must be a boolean")?
            .unwrap_or(true);
        let anvil_binary = env::var("ANVIL_BINARY").unwrap_or_else(|_| "anvil".to_string());
        let simulation_fork_block_number = env::var("SIMULATION_FORK_BLOCK_NUMBER")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("SIMULATION_FORK_BLOCK_NUMBER must be a valid u64")?;
        let simulation_startup_timeout_secs = env::var("SIMULATION_STARTUP_TIMEOUT_SECS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("SIMULATION_STARTUP_TIMEOUT_SECS must be a valid u64")?
            .unwrap_or(20);
        let basescan_api_key = env::var("ETHERSCAN_API_KEY")
            .or_else(|_| env::var("BASESCAN_API_KEY"))
            .ok()
            .filter(|value| !value.trim().is_empty());
        let stripe_api_key = env::var("STRIPE_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let bloxroute_auth_header = env::var("BLOXROUTE_AUTH")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let bloxroute_tx_lookup_url_template = env::var("BLOXROUTE_TX_LOOKUP_URL_TEMPLATE")
            .unwrap_or_else(|_| "https://api.blxrbdn.com/v1/tx/{tx_hash}".to_string());
        let maxmind_db_path = env::var("MAXMIND_DB_PATH")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);

        let smtp = smtp_from_env()?;
        let zero_g = zero_g_from_env()?;
        let mugen = mugen_from_env()?;
        let bounty = bounty_from_env()?;
        let filing_bearer_token = env::var("FILING_BEARER_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let filing_timeout_secs = env::var("FILING_TIMEOUT_SECS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("FILING_TIMEOUT_SECS must be a valid u64")?
            .unwrap_or(30);
        let ic3_submission_url = env::var("IC3_SUBMISSION_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let national_cybercrime_submission_url = env::var("NATIONAL_CYBERCRIME_SUBMISSION_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let ec3_coordination_submission_url = env::var("EC3_COORDINATION_SUBMISSION_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());

        Ok(Self {
            http_bind,
            chain_name,
            chain_id,
            database_url,
            alchemy_http_url,
            alchemy_ws_url,
            explorer_api_url,
            protocols_file,
            cex_wallets_file,
            bridge_addresses_file,
            mixer_pools_file,
            cex_wallets_feed_url,
            bridge_addresses_feed_url,
            mixer_pools_feed_url,
            artifact_dir,
            min_alert_score,
            hack_feed_poll_interval_secs,
            full_scan_interval_secs,
            attribution_feed_sync_interval_secs,
            disclosure_followup_interval_secs,
            disclosure_first_response_sla_hours,
            disclosure_resolution_sla_days,
            operator_email,
            api_key,
            smtp,
            keeperhub_webhook_url,
            zero_g,
            kimi_api_key,
            kimi_model,
            kimi_base_url,
            solc_binary,
            solc_bin_dir,
            solc_auto_install,
            anvil_binary,
            simulation_fork_block_number,
            simulation_startup_timeout_secs,
            basescan_api_key,
            stripe_api_key,
            bloxroute_auth_header,
            bloxroute_tx_lookup_url_template,
            maxmind_db_path,
            mugen,
            bounty,
            filing_bearer_token,
            filing_timeout_secs,
            ic3_submission_url,
            national_cybercrime_submission_url,
            ec3_coordination_submission_url,
        })
    }
}

fn required(key: &str) -> Result<String> {
    env::var(key).with_context(|| format!("{key} is required"))
}

fn smtp_from_env() -> Result<Option<SmtpConfig>> {
    let server = env::var("SMTP_SERVER").ok();
    let username = env::var("SMTP_USERNAME").ok();
    let password = env::var("SMTP_PASSWORD").ok();
    let from_email = env::var("FROM_EMAIL").ok();
    let port = env::var("SMTP_PORT").ok();

    let configured =
        server.is_some() || username.is_some() || password.is_some() || from_email.is_some();
    if !configured {
        return Ok(None);
    }

    let server =
        server.ok_or_else(|| anyhow!("SMTP_SERVER is required when SMTP is configured"))?;
    let username =
        username.ok_or_else(|| anyhow!("SMTP_USERNAME is required when SMTP is configured"))?;
    let password =
        password.ok_or_else(|| anyhow!("SMTP_PASSWORD is required when SMTP is configured"))?;
    let from_email =
        from_email.ok_or_else(|| anyhow!("FROM_EMAIL is required when SMTP is configured"))?;
    let port = port
        .as_deref()
        .unwrap_or("587")
        .parse::<u16>()
        .context("SMTP_PORT must be a valid u16")?;

    Ok(Some(SmtpConfig {
        server,
        port,
        username,
        password,
        from_email,
    }))
}

fn zero_g_from_env() -> Result<Option<ZeroGConfig>> {
    let rpc_url = env::var("ZG_RPC_URL").ok();
    let indexer_rpc = env::var("ZG_INDEXER_RPC").ok();
    let private_key = env::var("ZG_PRIVATE_KEY").ok();
    let node_binary = env::var("ZG_NODE_BINARY").ok();
    let publish_script = env::var("ZG_PUBLISH_SCRIPT").ok();

    let configured = rpc_url.is_some()
        || indexer_rpc.is_some()
        || private_key.is_some()
        || node_binary.is_some()
        || publish_script.is_some();
    if !configured {
        return Ok(None);
    }

    Ok(Some(ZeroGConfig {
        rpc_url: rpc_url.ok_or_else(|| anyhow!("ZG_RPC_URL is required when 0G is configured"))?,
        indexer_rpc: indexer_rpc
            .ok_or_else(|| anyhow!("ZG_INDEXER_RPC is required when 0G is configured"))?,
        private_key: private_key
            .ok_or_else(|| anyhow!("ZG_PRIVATE_KEY is required when 0G is configured"))?,
        node_binary: node_binary.unwrap_or_else(|| "node".to_string()),
        publish_script: PathBuf::from(
            publish_script.unwrap_or_else(|| "scripts/publish_to_0g.mjs".to_string()),
        ),
    }))
}

fn mugen_from_env() -> Result<Option<MugenConfig>> {
    let gateway_url = env::var("MUGEN_GATEWAY_URL").ok();
    let api_key = env::var("MUGEN_API_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let model_id = env::var("MUGEN_MODEL_ID").ok();
    let poll_interval_secs = env::var("MUGEN_POLL_INTERVAL_SECS").ok();
    let max_polls = env::var("MUGEN_MAX_POLLS").ok();

    let configured = gateway_url.is_some()
        || api_key.is_some()
        || model_id.is_some()
        || poll_interval_secs.is_some()
        || max_polls.is_some();
    if !configured {
        return Ok(None);
    }

    Ok(Some(MugenConfig {
        gateway_url: gateway_url
            .ok_or_else(|| anyhow!("MUGEN_GATEWAY_URL is required when Mugen is configured"))?,
        api_key,
        model_id: model_id.unwrap_or_else(|| "ghost_anomaly_detector_v1".to_string()),
        poll_interval_secs: poll_interval_secs
            .as_deref()
            .unwrap_or("10")
            .parse::<u64>()
            .context("MUGEN_POLL_INTERVAL_SECS must be a valid u64")?,
        max_polls: max_polls
            .as_deref()
            .unwrap_or("30")
            .parse::<u32>()
            .context("MUGEN_MAX_POLLS must be a valid u32")?,
    }))
}

fn bounty_from_env() -> Result<Option<BountyConfig>> {
    let private_key = env::var("BOUNTY_PRIVATE_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let solc_binary = env::var("BOUNTY_SOLC_BINARY").ok();
    let contract_path = env::var("BOUNTY_CONTRACT_PATH").ok();

    let configured = private_key.is_some() || solc_binary.is_some() || contract_path.is_some();
    if !configured {
        return Ok(None);
    }

    Ok(Some(BountyConfig {
        private_key: private_key.ok_or_else(|| {
            anyhow!("BOUNTY_PRIVATE_KEY is required when bounty deployment is configured")
        })?,
        solc_binary: solc_binary.unwrap_or_else(|| "solc".to_string()),
        contract_path: PathBuf::from(
            contract_path.unwrap_or_else(|| "contracts/src/GhostBounty.sol".to_string()),
        ),
    }))
}

fn default_explorer_api_url(chain_id: u64) -> String {
    format!("https://api.etherscan.io/v2/api?chainid={chain_id}")
}

fn normalize_explorer_api_url(value: &str, chain_id: u64) -> String {
    let trimmed = value.trim();
    if trimmed.contains("api.etherscan.io/v2/api") {
        return trimmed.to_string();
    }

    match trimmed {
        "https://api.basescan.org/api" | "https://api-sepolia.basescan.org/api" => {
            default_explorer_api_url(chain_id)
        }
        _ => trimmed.to_string(),
    }
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(anyhow!("invalid boolean value {value}")),
    }
}
