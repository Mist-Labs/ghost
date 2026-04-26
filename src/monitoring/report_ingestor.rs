use crate::db::insert_hack_report_if_new;
use crate::model::NewHackIntelReport;
use crate::proactive::AttackVector;
use anyhow::Result;
use diesel_async::AsyncPgConnection;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct HackReport {
    id: String,
    name: String,
    date: i64,
    amount: f64,
    chain: String,
    classification: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HacksResponse {
    Wrapped { hacks: Vec<HackReport> },
    List(Vec<HackReport>),
}

pub async fn ingest_defillama_hacks(conn: &mut AsyncPgConnection) -> Result<()> {
    let client = Client::new();
    let response = client
        .get("https://api.llama.fi/hacks")
        .send()
        .await?;
    if response.status() == StatusCode::PAYMENT_REQUIRED {
        tracing::debug!("DefiLlama hacks endpoint requires payment; skipping ingestion");
        return Ok(());
    }

    let resp: HacksResponse = response.error_for_status()?.json().await?;

    let hacks = match resp {
        HacksResponse::Wrapped { hacks } => hacks,
        HacksResponse::List(hacks) => hacks,
    };

    for hack in hacks {
        let raw_payload = serde_json::to_value(&hack)?;
        let published_at = chrono::DateTime::from_timestamp(hack.date, 0)
            .ok_or_else(|| anyhow::anyhow!("invalid hack timestamp for {}", hack.id))?;
        let root_cause = hack
            .description
            .clone()
            .unwrap_or_else(|| "No public root cause yet".to_string());
        let classification = hack
            .classification
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        let _ = insert_hack_report_if_new(
            conn,
            &NewHackIntelReport {
                source: "defillama".to_string(),
                external_id: hack.id,
                protocol: hack.name.clone(),
                published_at,
                loss_usd: Some(hack.amount),
                attack_vector: AttackVector::classify(&classification),
                root_cause,
                chain_name: hack.chain.clone(),
                title: format!("DeFiLlama disclosed hack on {}", hack.name),
                summary: classification,
                source_url: "https://defillama.com/hacks".to_string(),
                raw_payload,
            },
        )
        .await?;
    }

    Ok(())
}
