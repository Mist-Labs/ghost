use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use ethers::types::{Address, H256, U256};
use reqwest::Client;
use serde::Deserialize;
use std::env;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct HistoricalTransaction {
    pub hash: H256,
    pub from: Address,
    pub to: Option<Address>,
    pub value: U256,
    pub block_number: u64,
    pub timestamp: DateTime<Utc>,
    pub method_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExplorerResponse {
    status: String,
    message: String,
    result: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ExplorerTx {
    hash: String,
    from: String,
    to: String,
    value: String,
    #[serde(rename = "blockNumber")]
    block_number: String,
    #[serde(rename = "timeStamp")]
    timestamp: String,
    #[serde(rename = "methodId")]
    method_id: Option<String>,
    #[serde(rename = "isError")]
    is_error: String,
}

pub async fn fetch_address_transactions(address: Address) -> Result<Vec<HistoricalTransaction>> {
    let api_key = env::var("BASESCAN_API_KEY")
        .context("BASESCAN_API_KEY is required for historical wallet analysis")?;
    let api_url = env::var("EXPLORER_API_URL").unwrap_or_else(|_| default_explorer_api_url());

    let client = Client::new();
    let response = client
        .get(api_url)
        .query(&[
            ("module", "account"),
            ("action", "txlist"),
            ("address", &format!("{address:?}")),
            ("startblock", "0"),
            ("endblock", "99999999"),
            ("sort", "asc"),
            ("apikey", &api_key),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<ExplorerResponse>()
        .await?;

    if response.status == "0" {
        let normalized_message = response.message.to_ascii_lowercase();
        if normalized_message.contains("no transactions") {
            return Ok(Vec::new());
        }
        return Err(anyhow!(
            "explorer transaction lookup failed: {}",
            response.message
        ));
    }

    let rows: Vec<ExplorerTx> = serde_json::from_value(response.result)?;
    rows.into_iter()
        .filter(|row| row.is_error == "0")
        .map(parse_transaction)
        .collect()
}

fn parse_transaction(row: ExplorerTx) -> Result<HistoricalTransaction> {
    let timestamp = row
        .timestamp
        .parse::<i64>()
        .context("explorer timestamp was not numeric")?;
    Ok(HistoricalTransaction {
        hash: H256::from_str(&row.hash).context("invalid explorer tx hash")?,
        from: Address::from_str(&row.from).context("invalid explorer from address")?,
        to: if row.to.trim().is_empty() {
            None
        } else {
            Some(Address::from_str(&row.to).context("invalid explorer to address")?)
        },
        value: U256::from_dec_str(&row.value).context("invalid explorer tx value")?,
        block_number: row
            .block_number
            .parse::<u64>()
            .context("invalid explorer block number")?,
        timestamp: DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| anyhow!("invalid explorer timestamp value"))?,
        method_id: row.method_id,
    })
}

fn default_explorer_api_url() -> String {
    match env::var("CHAIN_ID")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(8453)
    {
        84532 => "https://api-sepolia.basescan.org/api".to_string(),
        _ => "https://api.basescan.org/api".to_string(),
    }
}
