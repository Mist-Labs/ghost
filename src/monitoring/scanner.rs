use crate::db::{decode_signature, list_signatures};
use crate::proactive::{
    contract_scanner, dependency_monitor, invariant_monitor, oracle_monitor, upgrade_monitor,
    ScanMode,
};
use crate::state::AppState;
use anyhow::{anyhow, Result};

#[derive(Debug, serde::Serialize, Clone)]
pub struct Vulnerability {
    pub exploit_type: String,
    pub risk_score: f64,
    pub description: String,
    pub contract_address: String,
    pub remediation: String,
    pub simulation_confirmed: bool,
}

pub async fn scan_protocol_for_vulnerabilities(
    state: &AppState,
    protocol_id: &str,
) -> Result<Vec<Vulnerability>> {
    let protocol = state
        .protocols
        .find_by_id(protocol_id)
        .ok_or_else(|| anyhow!("protocol {protocol_id} not found in registry"))?;

    let signatures = {
        let mut conn = state.pool.get().await?;
        list_signatures(&mut conn, 250)
            .await?
            .into_iter()
            .map(|row| decode_signature(&row))
            .collect::<Result<Vec<_>, _>>()?
    };

    let mut findings = Vec::new();
    findings.extend(
        contract_scanner::scan_protocol(
            &protocol,
            &signatures,
            &state.provider,
            &state.http_client,
            &state.config,
            ScanMode::Scheduled,
        )
        .await?
        .vulnerabilities_found,
    );

    if let Some(result) =
        upgrade_monitor::monitor_protocol(state, &protocol, &signatures, ScanMode::Scheduled)
            .await?
    {
        findings.extend(result.vulnerabilities_found);
    }

    if let Some(result) =
        oracle_monitor::monitor_protocol(state, &protocol, ScanMode::Scheduled).await?
    {
        findings.extend(result.vulnerabilities_found);
    }

    if let Some(result) =
        dependency_monitor::monitor_protocol(state, &protocol, ScanMode::Scheduled).await?
    {
        findings.extend(result.vulnerabilities_found);
    }

    if let Some(result) =
        invariant_monitor::monitor_protocol(state, &protocol, ScanMode::Scheduled).await?
    {
        findings.extend(result.vulnerabilities_found);
    }

    Ok(findings
        .into_iter()
        .map(|finding| Vulnerability {
            exploit_type: finding.finding_type.as_storage_value().to_string(),
            risk_score: finding.confidence,
            description: finding.title,
            contract_address: finding.contract_address,
            remediation: finding.remediation,
            simulation_confirmed: finding.simulation_confirmed,
        })
        .collect())
}
