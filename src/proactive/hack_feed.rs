use super::{AttackVector, HackReport};
use anyhow::Result;
use chrono::{DateTime, Utc};
use reqwest::Client;
use rss::Channel;
use std::collections::HashSet;

pub async fn poll_hack_feeds(client: &Client) -> Result<Vec<HackReport>> {
    let mut reports = Vec::new();
    match poll_rekt_news(client).await {
        Ok(items) => reports.extend(items),
        Err(error) => tracing::warn!(error = %error, "Rekt News feed polling failed"),
    }

    let mut seen = HashSet::new();
    reports.retain(|report| seen.insert(format!("{}:{}", report.source, report.external_id)));
    reports.sort_by(|left, right| right.published_at.cmp(&left.published_at));

    Ok(reports)
}

async fn poll_rekt_news(client: &Client) -> Result<Vec<HackReport>> {
    let response = client
        .get("https://newsletter.rekt.news/rss")
        .send()
        .await?;
    if !response.status().is_success() {
        tracing::debug!(status = %response.status(), "Rekt News feed unavailable; skipping poll");
        return Ok(Vec::new());
    }

    let feed = response.bytes().await?;
    let channel = match Channel::read_from(&feed[..]) {
        Ok(channel) => channel,
        Err(error) => {
            tracing::debug!(error = %error, "Rekt News feed response was not RSS; skipping poll");
            return Ok(Vec::new());
        }
    };
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
