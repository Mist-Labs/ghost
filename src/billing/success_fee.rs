use crate::billing::{create_stripe_invoice, is_fee_active};
use crate::db::{
    get_incident, get_protocol_billing_account, get_recovery_case_by_bounty_contract,
    get_recovery_case_by_incident, insert_billing_invoice, mark_recovery_fee_invoiced,
    update_recovery_case_after_recovery, upsert_recovery_case, PgPool,
};
use crate::model::{NewBillingInvoice, NewRecoveryCase};
use anyhow::{anyhow, Context, Result};
use ethers::abi::{AbiParser, RawLog};
use ethers::providers::{Middleware, Provider, StreamExt, Ws};
use ethers::types::{Address, Filter, H256, I256, U256};
use std::sync::Arc;
use uuid::Uuid;

pub use crate::model::StoredRecoveryCase as RecoveryCase;

const SUCCESS_FEE_BPS: u64 = 1_000;

pub async fn open_recovery_case(
    pool: &PgPool,
    incident_id: Uuid,
    total_stolen_usd: i64,
    recovery_method: &str,
    bounty_contract_address: Option<&str>,
) -> Result<RecoveryCase> {
    let mut conn = pool.get().await?;
    let incident = get_incident(&mut conn, incident_id).await?;
    let protocol_id = incident
        .protocol_id
        .clone()
        .ok_or_else(|| anyhow!("incident {incident_id} is missing protocol_id"))?;
    let account = get_protocol_billing_account(&mut conn, &protocol_id)
        .await?
        .ok_or_else(|| anyhow!("billing account for protocol {protocol_id} was not found"))?;

    let case = upsert_recovery_case(
        &mut conn,
        &NewRecoveryCase {
            incident_id,
            protocol_id,
            total_stolen_usd,
            recovery_method: recovery_method.to_string(),
            bounty_contract_address: bounty_contract_address.map(normalize_address),
            billing_email: account.billing_email,
            metadata: serde_json::json!({
                "incident_tx_hash": incident.tx_hash,
                "opened_at": chrono::Utc::now(),
            }),
        },
    )
    .await?;

    Ok(case)
}

pub async fn record_recovery(
    pool: &PgPool,
    incident_id: Uuid,
    recovered_usd: i64,
    method: &str,
) -> Result<i64> {
    if recovered_usd <= 0 {
        return Err(anyhow!("recovered_usd must be positive"));
    }

    let mut conn = pool.get().await?;
    let case = get_recovery_case_by_incident(&mut conn, incident_id)
        .await?
        .ok_or_else(|| anyhow!("recovery case for incident {incident_id} was not opened"))?;

    let new_total = case
        .total_recovered_usd
        .checked_add(recovered_usd)
        .ok_or_else(|| anyhow!("recovered amount overflow for incident {incident_id}"))?;
    let total_fee_usd = calculate_success_fee(new_total);
    let fee_due = (total_fee_usd - case.invoiced_fee_usd).max(0);
    let mut metadata = case.metadata.clone();
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "last_recovery_at".into(),
            serde_json::json!(chrono::Utc::now()),
        );
        object.insert(
            "last_recovered_usd".into(),
            serde_json::json!(recovered_usd),
        );
        object.insert("last_method".into(), serde_json::json!(method));
        object.insert(
            "prior_recovered_usd".into(),
            serde_json::json!(case.total_recovered_usd),
        );
        object.insert("total_fee_usd".into(), serde_json::json!(total_fee_usd));
        object.insert("fee_due_usd".into(), serde_json::json!(fee_due));
    } else {
        metadata = serde_json::json!({
            "last_recovery_at": chrono::Utc::now(),
            "last_recovered_usd": recovered_usd,
            "last_method": method,
            "prior_recovered_usd": case.total_recovered_usd,
            "total_fee_usd": total_fee_usd,
            "fee_due_usd": fee_due,
        });
    }

    update_recovery_case_after_recovery(&mut conn, incident_id, new_total, method, metadata)
        .await?;

    tracing::info!(
        "Recovery recorded: ${} via {} | Total recovered: ${} | Fee now due: ${}",
        recovered_usd,
        method,
        new_total,
        fee_due
    );

    Ok(fee_due)
}

pub async fn invoice_success_fee(
    pool: &PgPool,
    stripe_key: &str,
    incident_id: Uuid,
    fee_usd: i64,
) -> Result<()> {
    if fee_usd <= 0 {
        tracing::info!(incident_id = %incident_id, "No success fee due for this recovery update");
        return Ok(());
    }

    let invoice_amount = i32::try_from(fee_usd).context("success fee exceeds i32 invoice limit")?;
    let mut conn = pool.get().await?;
    let case = get_recovery_case_by_incident(&mut conn, incident_id)
        .await?
        .ok_or_else(|| anyhow!("recovery case for incident {incident_id} was not found"))?;

    let description = format!(
        "Ghost recovery success fee — 10% of ${} recovered via {}",
        case.total_recovered_usd, case.recovery_method
    );

    if !is_fee_active() {
        tracing::info!(
            "ACTIVATE_FEE=false — success fee invoice skipped (${} deferred)",
            fee_usd
        );

        insert_billing_invoice(
            &mut conn,
            &NewBillingInvoice {
                protocol_id: case.protocol_id.clone(),
                incident_id: Some(incident_id),
                recovery_case_id: Some(case.id),
                invoice_kind: "success_fee".into(),
                amount_usd: invoice_amount,
                currency: "USD".into(),
                status: "deferred".into(),
                external_invoice_id: None,
                recipient_email: case.billing_email.clone(),
                description,
                metadata: serde_json::json!({
                    "billing_mode": "deferred",
                    "fee_due_usd": fee_usd,
                    "invoiced_fee_usd_before": case.invoiced_fee_usd,
                }),
            },
        )
        .await?;
        return Ok(());
    }

    match create_stripe_invoice(
        stripe_key,
        &case.billing_email,
        invoice_amount,
        &description,
    )
    .await
    {
        Ok(invoice_id) => {
            insert_billing_invoice(
                &mut conn,
                &NewBillingInvoice {
                    protocol_id: case.protocol_id.clone(),
                    incident_id: Some(incident_id),
                    recovery_case_id: Some(case.id),
                    invoice_kind: "success_fee".into(),
                    amount_usd: invoice_amount,
                    currency: "USD".into(),
                    status: "issued".into(),
                    external_invoice_id: Some(invoice_id),
                    recipient_email: case.billing_email.clone(),
                    description,
                    metadata: serde_json::json!({
                        "fee_due_usd": fee_usd,
                        "invoiced_fee_usd_before": case.invoiced_fee_usd,
                    }),
                },
            )
            .await?;

            mark_recovery_fee_invoiced(&mut conn, incident_id, case.invoiced_fee_usd + fee_usd)
                .await?;
            Ok(())
        }
        Err(error) => {
            insert_billing_invoice(
                &mut conn,
                &NewBillingInvoice {
                    protocol_id: case.protocol_id.clone(),
                    incident_id: Some(incident_id),
                    recovery_case_id: Some(case.id),
                    invoice_kind: "success_fee".into(),
                    amount_usd: invoice_amount,
                    currency: "USD".into(),
                    status: "failed".into(),
                    external_invoice_id: None,
                    recipient_email: case.billing_email.clone(),
                    description,
                    metadata: serde_json::json!({
                        "fee_due_usd": fee_usd,
                        "error": error.to_string(),
                    }),
                },
            )
            .await?;
            Err(error)
        }
    }
}

pub async fn watch_bounty_claims(
    provider: Arc<Provider<Ws>>,
    pool: Arc<PgPool>,
    stripe_key: String,
) -> Result<()> {
    let abi = AbiParser::default().parse(&[
        "event BountyClaimed(address indexed claimer, uint256 fundsReturnedWei, uint256 bountyWei)",
    ])?;
    let event = abi.event("BountyClaimed")?.clone();
    let topic = H256::from_slice(event.signature().as_bytes());
    let filter = Filter::new().topic0(topic);
    let mut stream = provider.subscribe_logs(&filter).await?;

    while let Some(log) = stream.next().await {
        let parsed = event.parse_log(RawLog {
            topics: log.topics.clone(),
            data: log.data.to_vec(),
        })?;

        let funds_returned_wei = parsed
            .params
            .iter()
            .find(|param| param.name == "fundsReturnedWei")
            .and_then(|param| param.value.clone().into_uint())
            .ok_or_else(|| anyhow!("BountyClaimed log missing fundsReturnedWei"))?;
        let recovered_usd = native_to_usd(provider.as_ref(), funds_returned_wei).await?;

        let mut conn = pool.get().await?;
        let normalized_address = normalize_address(format!("{:?}", log.address));
        if let Some(case) =
            get_recovery_case_by_bounty_contract(&mut conn, &normalized_address).await?
        {
            drop(conn);
            let fee = record_recovery(&pool, case.incident_id, recovered_usd, "bounty").await?;
            invoice_success_fee(&pool, &stripe_key, case.incident_id, fee).await?;
        }
    }

    Ok(())
}

fn calculate_success_fee(total_recovered_usd: i64) -> i64 {
    (total_recovered_usd.max(0) as u64 * SUCCESS_FEE_BPS / 10_000) as i64
}

async fn native_to_usd(provider: &Provider<Ws>, amount_wei: U256) -> Result<i64> {
    let feed_address: Address = std::env::var("NATIVE_USD_FEED_ADDRESS")
        .context("NATIVE_USD_FEED_ADDRESS is required to convert bounty claims into USD")?
        .parse()
        .context("NATIVE_USD_FEED_ADDRESS must be a valid address")?;

    let abi = AbiParser::default().parse(&[
        "function latestRoundData() view returns (uint80, int256, uint256, uint256, uint80)",
    ])?;
    let contract = ethers::contract::Contract::new(feed_address, abi, Arc::new(provider.clone()));
    let (_, answer, _, _, _): (U256, I256, U256, U256, U256) = contract
        .method::<_, (U256, I256, U256, U256, U256)>("latestRoundData", ())?
        .call()
        .await?;

    let answer_str = answer.to_string();
    let price_scaled = answer_str
        .parse::<f64>()
        .context("failed to parse Chainlink answer as f64")?;
    let eth_amount = amount_wei.to_string().parse::<f64>()? / 1e18f64;
    let price_usd = price_scaled / 1e8f64;

    Ok((eth_amount * price_usd).round() as i64)
}

fn normalize_address(address: impl Into<String>) -> String {
    address.into().trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::calculate_success_fee;

    #[test]
    fn success_fee_is_ten_percent() {
        assert_eq!(calculate_success_fee(5_000_000), 500_000);
        assert_eq!(calculate_success_fee(0), 0);
        assert_eq!(calculate_success_fee(-10), 0);
    }
}
