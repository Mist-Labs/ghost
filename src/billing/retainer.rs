use crate::billing::{create_stripe_invoice, is_fee_active, monthly_fee_for_protocol_tier};
use crate::db::{
    find_incident_by_tx_hash, get_protocol_billing_account, insert_billing_invoice,
    list_active_protocol_billing_accounts, upsert_protocol_billing_account, upsert_recovery_case,
    PgPool,
};
use crate::model::{NewBillingInvoice, NewProtocolBillingAccount, NewRecoveryCase};
use crate::protocols::{ProtocolBillingDefinition, ProtocolDefinition, ProtocolRegistry};
use anyhow::{anyhow, Result};

pub use crate::model::StoredProtocolBillingAccount as ProtocolConfig;

pub async fn sync_protocol_configs_from_registry(
    pool: &PgPool,
    registry: &ProtocolRegistry,
) -> Result<usize> {
    let mut conn = pool.get().await?;
    let mut synced = 0usize;

    for protocol in registry.all_protocols() {
        let Some(account) = protocol_billing_account_from_definition(&protocol)? else {
            continue;
        };
        upsert_protocol_billing_account(&mut conn, &account).await?;
        synced += 1;
    }

    tracing::info!(synced, "Protocol billing accounts synchronized");
    Ok(synced)
}

pub async fn load_monitored_protocols(pool: &PgPool) -> Result<Vec<ProtocolConfig>> {
    let mut conn = pool.get().await?;
    let protocols = list_active_protocol_billing_accounts(&mut conn).await?;

    tracing::info!(
        "Loaded {} monitored protocol billing configs",
        protocols.len()
    );
    Ok(protocols)
}

pub async fn record_incident(
    pool: &PgPool,
    protocol_id: &str,
    tx_hash: &str,
    loss_usd: i64,
) -> Result<uuid::Uuid> {
    let mut conn = pool.get().await?;
    let incident = find_incident_by_tx_hash(&mut conn, tx_hash)
        .await?
        .ok_or_else(|| anyhow!("incident with tx hash {tx_hash} was not found"))?;
    let account = get_protocol_billing_account(&mut conn, protocol_id)
        .await?
        .ok_or_else(|| anyhow!("billing account for protocol {protocol_id} was not found"))?;

    upsert_recovery_case(
        &mut conn,
        &NewRecoveryCase {
            incident_id: incident.id,
            protocol_id: protocol_id.to_string(),
            total_stolen_usd: loss_usd,
            recovery_method: "pending".to_string(),
            bounty_contract_address: None,
            billing_email: account.billing_email.clone(),
            metadata: serde_json::json!({
                "tx_hash": tx_hash,
                "protocol_name": account.protocol_name,
                "billing_tier": account.tier,
            }),
        },
    )
    .await?;

    Ok(incident.id)
}

pub async fn run_monthly_billing(pool: &PgPool, stripe_key: &str) -> Result<()> {
    let protocols = load_monitored_protocols(pool).await?;
    let mut conn = pool.get().await?;
    let mut failures = Vec::new();

    if !is_fee_active() {
        tracing::info!("ACTIVATE_FEE=false — billing cycle recorded as deferred");
    }

    for protocol in protocols {
        let description = format!(
            "Ghost monitoring — {} tier — {}",
            protocol.tier, protocol.protocol_name
        );

        let result = if is_fee_active() {
            create_stripe_invoice(
                stripe_key,
                &protocol.billing_email,
                protocol.monthly_fee_usd,
                &description,
            )
            .await
        } else {
            Ok("deferred".to_string())
        };

        match result {
            Ok(invoice_id) => {
                let status = if is_fee_active() {
                    "issued"
                } else {
                    "deferred"
                };
                insert_billing_invoice(
                    &mut conn,
                    &NewBillingInvoice {
                        protocol_id: protocol.protocol_id.clone(),
                        incident_id: None,
                        recovery_case_id: None,
                        invoice_kind: "retainer".into(),
                        amount_usd: protocol.monthly_fee_usd,
                        currency: "USD".into(),
                        status: status.into(),
                        external_invoice_id: if is_fee_active() {
                            Some(invoice_id)
                        } else {
                            None
                        },
                        recipient_email: protocol.billing_email.clone(),
                        description,
                        metadata: serde_json::json!({
                            "tier": protocol.tier,
                            "billing_mode": if is_fee_active() { "stripe_invoice" } else { "deferred" },
                        }),
                    },
                )
                .await?;
            }
            Err(error) => {
                insert_billing_invoice(
                    &mut conn,
                    &NewBillingInvoice {
                        protocol_id: protocol.protocol_id.clone(),
                        incident_id: None,
                        recovery_case_id: None,
                        invoice_kind: "retainer".into(),
                        amount_usd: protocol.monthly_fee_usd,
                        currency: "USD".into(),
                        status: "failed".into(),
                        external_invoice_id: None,
                        recipient_email: protocol.billing_email.clone(),
                        description,
                        metadata: serde_json::json!({
                            "tier": protocol.tier,
                            "error": error.to_string(),
                        }),
                    },
                )
                .await?;
                failures.push(format!("{}: {}", protocol.protocol_name, error));
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "monthly billing failures: {}",
            failures.join(" | ")
        ))
    }
}

fn protocol_billing_account_from_definition(
    protocol: &ProtocolDefinition,
) -> Result<Option<NewProtocolBillingAccount>> {
    let Some(billing) = &protocol.billing else {
        return Ok(None);
    };

    Ok(Some(NewProtocolBillingAccount {
        protocol_id: protocol.id.clone(),
        protocol_name: protocol.name.clone(),
        tier: normalize_protocol_tier_value(billing)?,
        monthly_fee_usd: billing
            .monthly_fee_usd
            .unwrap_or(monthly_fee_for_protocol_tier(&billing.tier)?),
        billing_email: billing.billing_email.clone(),
        alert_webhook: billing.alert_webhook.clone(),
        active: billing.active,
        metadata: serde_json::json!({
            "chain_id": protocol.chain_id,
            "monitored_addresses": protocol.monitored_addresses,
            "contract_addresses": protocol.contract_addresses,
        }),
    }))
}

fn normalize_protocol_tier_value(billing: &ProtocolBillingDefinition) -> Result<String> {
    Ok(crate::billing::normalize_protocol_tier(&billing.tier)?.to_string())
}

#[cfg(test)]
mod tests {
    use super::protocol_billing_account_from_definition;
    use crate::protocols::{ProtocolBillingDefinition, ProtocolDefinition};

    #[test]
    fn converts_protocol_definition_into_billing_account() {
        let definition = ProtocolDefinition {
            id: "base-vault".into(),
            name: "Base Vault".into(),
            chain_id: 8453,
            protocol_type: Some("vault".into()),
            monitoring_authorized: true,
            monitored_addresses: vec![],
            contract_addresses: vec![],
            security_contacts: vec![],
            abi: None,
            known_selectors: vec![],
            sanctioned_selectors: vec![],
            suspicious_selectors: vec![],
            oracle_addresses: vec![],
            upgrade_monitor: None,
            oracle_monitor: None,
            dependencies: vec![],
            invariants: vec![],
            simulation: None,
            billing: Some(ProtocolBillingDefinition {
                tier: "guardian".into(),
                monthly_fee_usd: None,
                billing_email: "ops@example.com".into(),
                alert_webhook: None,
                active: true,
            }),
        };

        let account = protocol_billing_account_from_definition(&definition)
            .unwrap()
            .unwrap();
        assert_eq!(account.protocol_id, "base-vault");
        assert_eq!(account.monthly_fee_usd, 8_000);
        assert_eq!(account.tier, "guardian");
    }
}
