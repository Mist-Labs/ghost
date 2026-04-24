pub mod intel_feed;
pub mod retainer;
pub mod success_fee;

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::env;

const STRIPE_API_BASE: &str = "https://api.stripe.com/v1";
const SENTINEL_MONTHLY_FEE_USD: i32 = 2_500;
const GUARDIAN_MONTHLY_FEE_USD: i32 = 8_000;
const FORTRESS_MONTHLY_FEE_USD: i32 = 25_000;
const BASIC_INTEL_FEE_USD: i32 = 1_500;
const PRO_INTEL_FEE_USD: i32 = 5_000;

pub fn is_fee_active() -> bool {
    env::var("ACTIVATE_FEE")
        .unwrap_or_else(|_| "false".into())
        .trim()
        .eq_ignore_ascii_case("true")
}

pub fn normalize_protocol_tier(tier: &str) -> Result<&'static str> {
    match tier.trim().to_ascii_lowercase().as_str() {
        "sentinel" => Ok("sentinel"),
        "guardian" => Ok("guardian"),
        "fortress" => Ok("fortress"),
        other => Err(anyhow!("unknown protocol billing tier: {other}")),
    }
}

pub fn monthly_fee_for_protocol_tier(tier: &str) -> Result<i32> {
    Ok(match normalize_protocol_tier(tier)? {
        "sentinel" => SENTINEL_MONTHLY_FEE_USD,
        "guardian" => GUARDIAN_MONTHLY_FEE_USD,
        "fortress" => FORTRESS_MONTHLY_FEE_USD,
        _ => unreachable!(),
    })
}

pub fn normalize_intel_tier(tier: &str) -> Result<&'static str> {
    match tier.trim().to_ascii_lowercase().as_str() {
        "basic" => Ok("basic"),
        "pro" => Ok("pro"),
        other => Err(anyhow!("unknown intel subscriber tier: {other}")),
    }
}

pub fn monthly_fee_for_intel_tier(tier: &str) -> Result<i32> {
    Ok(match normalize_intel_tier(tier)? {
        "basic" => BASIC_INTEL_FEE_USD,
        "pro" => PRO_INTEL_FEE_USD,
        _ => unreachable!(),
    })
}

pub fn hash_api_key(api_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    hex::encode(hasher.finalize())
}

pub(crate) async fn create_stripe_invoice(
    stripe_key: &str,
    email: &str,
    amount_usd: i32,
    description: &str,
) -> Result<String> {
    if stripe_key.trim().is_empty() {
        return Err(anyhow!("Stripe API key is required when ACTIVATE_FEE=true"));
    }
    if amount_usd <= 0 {
        return Err(anyhow!("invoice amount must be positive"));
    }

    let client = Client::new();
    let customer_id = find_or_create_customer(&client, stripe_key, email).await?;
    let amount_cents = amount_usd
        .checked_mul(100)
        .ok_or_else(|| anyhow!("invoice amount overflow for ${amount_usd}"))?;

    stripe_form_post(
        &client,
        stripe_key,
        "invoiceitems",
        &[
            ("customer".to_string(), customer_id.clone()),
            ("amount".to_string(), amount_cents.to_string()),
            ("currency".to_string(), "usd".to_string()),
            ("description".to_string(), description.to_string()),
            ("metadata[source]".to_string(), "ghost".to_string()),
        ],
    )
    .await?;

    let invoice = stripe_form_post(
        &client,
        stripe_key,
        "invoices",
        &[
            ("customer".to_string(), customer_id),
            ("collection_method".to_string(), "send_invoice".to_string()),
            ("days_until_due".to_string(), "30".to_string()),
            ("auto_advance".to_string(), "true".to_string()),
            ("metadata[source]".to_string(), "ghost".to_string()),
        ],
    )
    .await?;
    let invoice_id = invoice
        .get("id")
        .and_then(|value| value.as_str())
        .context("Stripe invoice response missing id")?;

    let finalized = stripe_form_post(
        &client,
        stripe_key,
        &format!("invoices/{invoice_id}/finalize"),
        &[],
    )
    .await?;

    let finalized_id = finalized
        .get("id")
        .and_then(|value| value.as_str())
        .context("Stripe finalized invoice response missing id")?;

    Ok(finalized_id.to_string())
}

pub(crate) async fn create_stripe_subscription(
    stripe_key: &str,
    email: &str,
    tier: &str,
) -> Result<String> {
    if stripe_key.trim().is_empty() {
        return Err(anyhow!("Stripe API key is required when ACTIVATE_FEE=true"));
    }

    let price_id = stripe_price_id_for_tier(tier)?;
    let client = Client::new();
    let customer_id = find_or_create_customer(&client, stripe_key, email).await?;

    let subscription = stripe_form_post(
        &client,
        stripe_key,
        "subscriptions",
        &[
            ("customer".to_string(), customer_id),
            ("items[0][price]".to_string(), price_id),
            ("metadata[source]".to_string(), "ghost".to_string()),
            (
                "metadata[tier]".to_string(),
                normalize_intel_tier(tier)?.to_string(),
            ),
        ],
    )
    .await?;

    let subscription_id = subscription
        .get("id")
        .and_then(|value| value.as_str())
        .context("Stripe subscription response missing id")?;

    Ok(subscription_id.to_string())
}

async fn find_or_create_customer(client: &Client, stripe_key: &str, email: &str) -> Result<String> {
    let response = client
        .get(format!("{STRIPE_API_BASE}/customers"))
        .basic_auth(stripe_key, Some(""))
        .query(&[("email", email), ("limit", "1")])
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;

    if let Some(customer_id) = response
        .get("data")
        .and_then(|value| value.as_array())
        .and_then(|customers| customers.first())
        .and_then(|customer| customer.get("id"))
        .and_then(|value| value.as_str())
    {
        return Ok(customer_id.to_string());
    }

    let customer = stripe_form_post(
        client,
        stripe_key,
        "customers",
        &[
            ("email".to_string(), email.to_string()),
            ("metadata[source]".to_string(), "ghost".to_string()),
        ],
    )
    .await?;

    let customer_id = customer
        .get("id")
        .and_then(|value| value.as_str())
        .context("Stripe customer response missing id")?;

    Ok(customer_id.to_string())
}

async fn stripe_form_post(
    client: &Client,
    stripe_key: &str,
    path: &str,
    params: &[(String, String)],
) -> Result<serde_json::Value> {
    let response = client
        .post(format!("{STRIPE_API_BASE}/{path}"))
        .basic_auth(stripe_key, Some(""))
        .form(params)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(anyhow!(
            "Stripe request to {path} failed with {status}: {body}"
        ));
    }

    Ok(serde_json::from_str(&body).with_context(|| format!("invalid Stripe JSON for {path}"))?)
}

fn stripe_price_id_for_tier(tier: &str) -> Result<String> {
    let env_key = match normalize_intel_tier(tier)? {
        "basic" => "STRIPE_BASIC_PRICE_ID",
        "pro" => "STRIPE_PRO_PRICE_ID",
        _ => unreachable!(),
    };

    env::var(env_key).with_context(|| format!("{env_key} is required when ACTIVATE_FEE=true"))
}

#[cfg(test)]
mod tests {
    use super::{
        hash_api_key, monthly_fee_for_intel_tier, monthly_fee_for_protocol_tier,
        normalize_intel_tier, normalize_protocol_tier,
    };

    #[test]
    fn protocol_tiers_are_normalized() {
        assert_eq!(normalize_protocol_tier("Sentinel").unwrap(), "sentinel");
        assert_eq!(normalize_protocol_tier("GUARDIAN").unwrap(), "guardian");
        assert!(normalize_protocol_tier("unknown").is_err());
    }

    #[test]
    fn intel_tiers_have_expected_fees() {
        assert_eq!(normalize_intel_tier("basic").unwrap(), "basic");
        assert_eq!(monthly_fee_for_intel_tier("basic").unwrap(), 1_500);
        assert_eq!(monthly_fee_for_intel_tier("pro").unwrap(), 5_000);
        assert_eq!(monthly_fee_for_protocol_tier("fortress").unwrap(), 25_000);
    }

    #[test]
    fn api_key_hash_is_stable() {
        let left = hash_api_key("ghost_intel_demo");
        let right = hash_api_key("ghost_intel_demo");
        assert_eq!(left, right);
        assert_ne!(left, hash_api_key("ghost_intel_other"));
    }
}
