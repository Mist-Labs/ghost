use super::{AttackVector, HackReport};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use rss::Channel;
use serde::Deserialize;
use std::collections::HashSet;

pub async fn poll_hack_feeds(client: &Client) -> Result<Vec<HackReport>> {
    let (rekt, defillama) = tokio::join!(poll_rekt_news(client), poll_defillama_hacks(client));

    let mut reports = Vec::new();
    reports.extend(rekt?);
    reports.extend(defillama?);

    let mut seen = HashSet::new();
    reports.retain(|report| seen.insert(format!("{}:{}", report.source, report.external_id)));
    reports.sort_by(|left, right| right.published_at.cmp(&left.published_at));

    Ok(reports)
}

async fn poll_rekt_news(client: &Client) -> Result<Vec<HackReport>> {
    let feed = client
        .get("https://rekt.news/rss")
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let channel = Channel::read_from(&feed[..]).context("failed to parse Rekt RSS feed")?;
    let mut reports = Vec::new();

    for item in channel.items() {
        let title = item.title().unwrap_or("Rekt News incident").to_string();
        let summary = item.description().unwrap_or_default().to_string();
        let url = item.link().unwrap_or_default().to_string();
        let published_at = item
            .pub_date()
            .and_then(parse_rss_date)
            .unwrap_or_else(Utc::now);
        let attack_vector = AttackVector::classify(&format!("{title}\n{summary}"));
        let protocol = title
            .split(':')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown protocol")
            .to_string();

        reports.push(HackReport {
            source: "rekt_news".into(),
            external_id: url.clone(),
            protocol,
            published_at,
            loss_usd: None,
            attack_vector: attack_vector.clone(),
            root_cause: title.clone(),
            chain_name: infer_chain_name(&format!("{title}\n{summary}")),
            title,
            summary,
            source_url: url,
            raw_payload: serde_json::json!({
                "title": item.title(),
                "description": item.description(),
                "link": item.link(),
                "pub_date": item.pub_date(),
                "attack_vector": attack_vector,
            }),
        });
    }

    Ok(reports)
}

async fn poll_defillama_hacks(client: &Client) -> Result<Vec<HackReport>> {
    let response = client
        .get("https://api.llama.fi/hacks")
        .send()
        .await?
        .error_for_status()?
        .json::<DefiLlamaResponse>()
        .await?;

    let hacks = match response {
        DefiLlamaResponse::Wrapped { hacks } => hacks,
        DefiLlamaResponse::List(hacks) => hacks,
    };

    let reports = hacks
        .into_iter()
        .map(|hack| {
            let title = format!("{} exploit", hack.name);
            let description = hack.description.clone().unwrap_or_default();
            let classification = hack.classification.clone().unwrap_or_default();
            let attack_vector = if classification.is_empty() {
                AttackVector::classify(&description)
            } else {
                AttackVector::classify(&classification)
            };

            HackReport {
                source: "defillama".into(),
                external_id: hack.id.clone(),
                protocol: hack.name.clone(),
                published_at: DateTime::from_timestamp(hack.date, 0).unwrap_or_else(Utc::now),
                loss_usd: Some(hack.amount),
                attack_vector,
                root_cause: classification.clone(),
                chain_name: hack.chain.to_ascii_lowercase(),
                title,
                summary: description.clone(),
                source_url: format!("https://defillama.com/hacks/{}", hack.id),
                raw_payload: serde_json::to_value(&hack).unwrap_or_else(|_| serde_json::json!({})),
            }
        })
        .collect();

    Ok(reports)
}

fn parse_rss_date(input: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(input)
        .map(|value| value.with_timezone(&Utc))
        .ok()
}

fn infer_chain_name(text: &str) -> String {
    let normalized = text.to_ascii_lowercase();
    if normalized.contains("base") {
        "base".into()
    } else if normalized.contains("arbitrum") {
        "arbitrum".into()
    } else if normalized.contains("optimism") {
        "optimism".into()
    } else if normalized.contains("ethereum") || normalized.contains("mainnet") {
        "ethereum".into()
    } else {
        "unknown".into()
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DefiLlamaResponse {
    Wrapped { hacks: Vec<DefiLlamaHack> },
    List(Vec<DefiLlamaHack>),
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct DefiLlamaHack {
    id: String,
    name: String,
    date: i64,
    amount: f64,
    chain: String,
    classification: Option<String>,
    description: Option<String>,
}
