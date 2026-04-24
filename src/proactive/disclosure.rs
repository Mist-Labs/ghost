use super::{ScanResult, Severity, SimulationMode};
use crate::db::{
    acknowledge_disclosure, get_finding, insert_disclosure, insert_findings, insert_scan_run,
    list_due_disclosures, mark_disclosure_escalated,
};
use crate::model::{StoredDisclosure, StoredScanRun};
use crate::protocols::ProtocolDefinition;
use crate::state::AppState;
use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use uuid::Uuid;

pub async fn handle_scan_result(
    state: &AppState,
    protocol: &ProtocolDefinition,
    result: &ScanResult,
    started_at: chrono::DateTime<Utc>,
) -> Result<StoredScanRun> {
    let mut conn = state.pool.get().await?;
    let scan_run = insert_scan_run(&mut conn, result, started_at).await?;
    let simulation_mode = result
        .metadata
        .get("simulation_mode")
        .and_then(|value| value.as_str())
        .map(SimulationMode::from_storage_value)
        .unwrap_or(SimulationMode::Generic);
    let findings = insert_findings(
        &mut conn,
        scan_run.id,
        &protocol.id,
        simulation_mode,
        &result.vulnerabilities_found,
    )
    .await?;

    let critical_or_high = findings
        .iter()
        .filter(|finding| {
            matches!(
                Severity::from_storage_value(&finding.severity),
                Severity::Critical | Severity::High
            ) && finding.simulation_confirmed
        })
        .collect::<Vec<_>>();

    for finding in critical_or_high {
        let evidence = state
            .artifact_store
            .persist_json(
                &format!("disclosure-{}", finding.id),
                &serde_json::json!({
                    "protocol": protocol,
                    "finding": finding,
                    "scan_run": scan_run,
                    "scan_result": result,
                    "created_at": Utc::now(),
                }),
            )
            .await?;
        let contacts = protocol.security_contacts.clone();
        let disclosure = insert_disclosure(
            &mut conn,
            finding.id,
            &protocol.id,
            &contacts,
            Utc::now() + Duration::days(state.config.disclosure_resolution_sla_days as i64),
            Some(
                Utc::now()
                    + Duration::hours(state.config.disclosure_first_response_sla_hours as i64),
            ),
            Some(&evidence.backend),
            Some(&evidence.locator),
            serde_json::json!({
                "finding": finding,
                "scan_run_id": scan_run.id,
                "evidence_checksum_sha256": evidence.checksum_sha256,
                "evidence_content_type": evidence.content_type,
                "evidence_size_bytes": evidence.size_bytes,
            }),
        )
        .await?;

        state
            .notifications
            .notify_protocol_vulnerability(protocol, finding, &disclosure)
            .await?;
    }

    Ok(scan_run)
}

pub async fn process_due_disclosures(state: &AppState) -> Result<()> {
    let mut conn = state.pool.get().await?;
    let due = list_due_disclosures(&mut conn, Utc::now(), 100).await?;

    for disclosure in due {
        let finding = get_finding(&mut conn, disclosure.finding_id).await?;
        let protocol = state
            .protocols
            .find_by_id(&disclosure.protocol_id)
            .ok_or_else(|| {
                anyhow!(
                    "protocol {} not found for disclosure",
                    disclosure.protocol_id
                )
            })?;

        let next_level = disclosure.escalation_level + 1;
        let state_label = if disclosure.acknowledged_at.is_none()
            && disclosure
                .first_response_due_at
                .map(|due| due <= Utc::now())
                .unwrap_or(false)
        {
            "escalated"
        } else {
            "overdue"
        };

        let updated =
            mark_disclosure_escalated(&mut conn, disclosure.id, next_level, state_label).await?;
        state
            .notifications
            .notify_disclosure_escalation(&protocol, &finding, &updated)
            .await?;
    }

    Ok(())
}

pub async fn acknowledge(
    state: &AppState,
    disclosure_id: Uuid,
    acknowledged_by: &str,
) -> Result<StoredDisclosure> {
    let mut conn = state.pool.get().await?;
    acknowledge_disclosure(&mut conn, disclosure_id, acknowledged_by).await
}
