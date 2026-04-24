use crate::billing::{
    create_stripe_subscription, hash_api_key, is_fee_active, monthly_fee_for_intel_tier,
    normalize_intel_tier,
};
use crate::db::{
    get_incident, get_recovery_case_by_incident, insert_billing_invoice, insert_intel_subscriber,
    list_intel_reports_paginated, subscriber_is_active, upsert_intel_report, PgPool,
};
use crate::model::{NewBillingInvoice, NewIntelReport, NewIntelSubscriber};
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

pub use crate::model::StoredIntelReport as IntelReport;

pub async fn publish_intel_report(pool: &PgPool, incident_id: Uuid) -> Result<IntelReport> {
    let report = build_intel_report(pool, incident_id).await?;
    let mut conn = pool.get().await?;
    let stored = upsert_intel_report(&mut conn, &report).await?;

    tracing::info!("Intel report published: {}", stored.id);
    Ok(stored)
}

pub async fn get_feed(
    pool: &PgPool,
    api_key: &str,
    page: i64,
    per_page: i64,
) -> Result<Vec<IntelReport>> {
    validate_subscriber(pool, api_key).await?;

    let page = page.max(1);
    let per_page = per_page.clamp(1, 100);
    let offset = (page - 1) * per_page;

    let mut conn = pool.get().await?;
    let reports = list_intel_reports_paginated(&mut conn, offset, per_page).await?;

    Ok(reports)
}

pub async fn validate_subscriber(pool: &PgPool, api_key: &str) -> Result<()> {
    let api_key_hash = hash_api_key(api_key);
    let mut conn = pool.get().await?;
    let active = subscriber_is_active(&mut conn, &api_key_hash).await?;

    if !active {
        anyhow::bail!("Invalid or inactive subscriber API key");
    }
    Ok(())
}

pub async fn onboard_subscriber(
    pool: &PgPool,
    stripe_key: &str,
    email: &str,
    tier: &str,
) -> Result<String> {
    let tier = normalize_intel_tier(tier)?.to_string();
    let api_key = format!(
        "ghost_intel_{}",
        Uuid::new_v4().to_string().replace('-', "")
    );
    let api_key_hash = hash_api_key(&api_key);
    let monthly_fee = monthly_fee_for_intel_tier(&tier)?;

    let stripe_subscription_id = if is_fee_active() {
        Some(create_stripe_subscription(stripe_key, email, &tier).await?)
    } else {
        tracing::info!(
            "ACTIVATE_FEE=false — Stripe subscription skipped for {} ({})",
            email,
            tier
        );
        None
    };

    let mut conn = pool.get().await?;
    insert_intel_subscriber(
        &mut conn,
        &NewIntelSubscriber {
            email: email.to_string(),
            api_key_hash,
            tier: tier.clone(),
            monthly_fee_usd: monthly_fee,
            active: true,
            metadata: serde_json::json!({
                "onboarded_at": Utc::now(),
                "stripe_subscription_id": stripe_subscription_id,
            }),
        },
    )
    .await?;

    insert_billing_invoice(
        &mut conn,
        &NewBillingInvoice {
            protocol_id: "intel_feed".into(),
            incident_id: None,
            recovery_case_id: None,
            invoice_kind: "intel_subscription".into(),
            amount_usd: monthly_fee,
            currency: "USD".into(),
            status: if is_fee_active() {
                "subscription_active".into()
            } else {
                "deferred".into()
            },
            external_invoice_id: stripe_subscription_id,
            recipient_email: email.to_string(),
            description: format!("Ghost threat intel feed — {} tier", tier),
            metadata: serde_json::json!({
                "tier": tier,
                "billing_mode": if is_fee_active() { "stripe_subscription" } else { "deferred" },
            }),
        },
    )
    .await?;

    tracing::info!("New intel subscriber onboarded: {} ({})", email, tier);
    Ok(api_key)
}

async fn build_intel_report(pool: &PgPool, incident_id: Uuid) -> Result<NewIntelReport> {
    let mut conn = pool.get().await?;
    let incident = get_incident(&mut conn, incident_id).await?;
    let recovery_case = get_recovery_case_by_incident(&mut conn, incident_id).await?;

    let detection_secs = (incident.detected_at - incident.first_seen_at)
        .num_seconds()
        .max(0) as i32;
    let chain_name = incident.chain_name.clone();
    let signal_names = incident
        .signals
        .get("signals")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();

    let attack_vector = incident
        .signals
        .get("intent")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.to_ascii_lowercase())
        .or_else(|| {
            signal_names
                .iter()
                .filter_map(|value| value.as_str())
                .next()
                .map(|value| value.to_ascii_lowercase())
        })
        .unwrap_or_else(|| "unknown".to_string());

    let attacker_skill_tier = incident
        .signals
        .get("attacker_profile")
        .and_then(|value| value.get("skill_tier"))
        .and_then(|value| value.as_str())
        .unwrap_or("unknown")
        .to_string();
    let used_private_mempool = incident
        .signals
        .get("attacker_profile")
        .and_then(|value| value.get("used_private_mempool"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let funded_via_mixer = signal_names
        .iter()
        .any(|value| value.as_str() == Some("mixer_funded"));

    let total_loss_usd = recovery_case
        .as_ref()
        .map(|case| case.total_stolen_usd)
        .unwrap_or(0);
    let recovered_usd = recovery_case
        .as_ref()
        .map(|case| case.total_recovered_usd)
        .unwrap_or(0);
    let cex_deposit_detected = recovery_case
        .as_ref()
        .and_then(|case| case.metadata.get("cex_deposit_detected"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let time_to_mixer_secs = recovery_case
        .as_ref()
        .and_then(|case| case.metadata.get("time_to_mixer_secs"))
        .and_then(|value| value.as_i64())
        .map(|value| value as i32);
    let bounty_outcome = recovery_case
        .as_ref()
        .and_then(|case| case.metadata.get("bounty_outcome"))
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
        .unwrap_or_else(|| match recovery_case.as_ref() {
            Some(case) if case.recovery_method == "bounty" && case.total_recovered_usd > 0 => {
                "claimed".to_string()
            }
            Some(case) if case.bounty_contract_address.is_some() => "pending".to_string(),
            _ => "pending".to_string(),
        });

    Ok(NewIntelReport {
        incident_id,
        published_at: Utc::now(),
        protocol_id: incident.protocol_id.clone(),
        protocol_name: incident
            .protocol_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        attack_vector,
        total_loss_usd,
        recovered_usd,
        attacker_skill_tier,
        used_private_mempool,
        funded_via_mixer,
        cex_deposit_detected,
        chains_involved: vec![chain_name],
        time_to_detection_secs: detection_secs,
        time_to_mixer_secs,
        bounty_outcome,
        metadata: serde_json::json!({
            "incident_id": incident_id,
            "incident_tx_hash": incident.tx_hash,
            "signals": signal_names,
            "summary": incident.summary,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::normalize_intel_tier;

    #[test]
    fn intel_tier_validation_rejects_unknown_values() {
        assert_eq!(normalize_intel_tier("basic").unwrap(), "basic");
        assert!(normalize_intel_tier("enterprise").is_err());
    }
}
