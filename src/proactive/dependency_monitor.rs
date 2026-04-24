use super::{FindingType, ScanMode, ScanResult, Severity, VulnerabilityMatch};
use crate::db::{insert_monitor_snapshot, latest_monitor_snapshot};
use crate::state::AppState;
use anyhow::Result;
use chrono::Utc;
use ethers::providers::Middleware;
use std::collections::BTreeMap;

pub async fn monitor_protocol(
    state: &AppState,
    protocol: &crate::protocols::ProtocolDefinition,
    mode: ScanMode,
) -> Result<Option<ScanResult>> {
    if protocol.dependencies.is_empty() {
        return Ok(None);
    }

    let started_at = Utc::now();
    let mut findings = Vec::new();
    let mut exposures: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut conn = state.pool.get().await?;

    for dependency in &protocol.dependencies {
        *exposures.entry(kind_label(&dependency.kind)).or_default() += 1;

        let code = state.provider.get_code(dependency.address, None).await?;
        let codehash = format!("0x{}", hex::encode(ethers::utils::keccak256(&code.0)));
        let scope_key = format!("{:?}", dependency.address);
        let previous =
            latest_monitor_snapshot(&mut conn, &protocol.id, "dependency", &scope_key).await?;

        insert_monitor_snapshot(
            &mut conn,
            &protocol.id,
            "dependency",
            &scope_key,
            serde_json::json!({
                "name": dependency.name,
                "kind": kind_label(&dependency.kind),
                "critical": dependency.critical,
                "address": format!("{:?}", dependency.address),
                "codehash": codehash,
                "code_size": code.0.len(),
            }),
        )
        .await?;

        if code.0.is_empty() {
            findings.push(VulnerabilityMatch {
                finding_type: FindingType::DependencyRisk,
                signature_id: None,
                title: format!("Dependency {} has no deployed code", dependency.name),
                contract_address: format!("{:?}", dependency.address),
                confidence: 0.99,
                severity: if dependency.critical {
                    Severity::Critical
                } else {
                    Severity::High
                },
                matched_pattern: "missing_dependency_code".into(),
                affected_functions: Vec::new(),
                simulation_confirmed: true,
                remediation: "Validate the dependency address, pause protocol integrations that rely on it, and rotate to a verified deployment if necessary.".into(),
                details: serde_json::json!({
                    "dependency": dependency.name,
                    "kind": kind_label(&dependency.kind),
                    "critical": dependency.critical,
                }),
            });
            continue;
        }

        if let Some(expected) = &dependency.expected_codehash {
            if !expected.eq_ignore_ascii_case(&codehash) {
                findings.push(VulnerabilityMatch {
                    finding_type: FindingType::DependencyRisk,
                    signature_id: None,
                    title: format!("Dependency {} codehash diverged from expected baseline", dependency.name),
                    contract_address: format!("{:?}", dependency.address),
                    confidence: 0.98,
                    severity: if dependency.critical {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    matched_pattern: "dependency_codehash_mismatch".into(),
                    affected_functions: Vec::new(),
                    simulation_confirmed: true,
                    remediation: "Review the dependency upgrade, verify bytecode provenance, and suspend sensitive flows until the new code is approved.".into(),
                    details: serde_json::json!({
                        "dependency": dependency.name,
                        "expected_codehash": expected,
                        "observed_codehash": codehash,
                    }),
                });
            }
        }

        if let Some(previous) = previous {
            let previous_hash = previous
                .payload
                .get("codehash")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            if !previous_hash.is_empty() && !previous_hash.eq_ignore_ascii_case(&codehash) {
                findings.push(VulnerabilityMatch {
                    finding_type: FindingType::DependencyRisk,
                    signature_id: None,
                    title: format!("Dependency {} changed codehash", dependency.name),
                    contract_address: format!("{:?}", dependency.address),
                    confidence: 0.96,
                    severity: if dependency.critical {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    matched_pattern: "dependency_codehash_changed".into(),
                    affected_functions: Vec::new(),
                    simulation_confirmed: true,
                    remediation: "Diff the dependency release, re-run protocol threat modeling against the new implementation, and re-approve only after review.".into(),
                    details: serde_json::json!({
                        "dependency": dependency.name,
                        "previous_codehash": previous_hash,
                        "observed_codehash": codehash,
                    }),
                });
            }
        }
    }

    Ok(Some(ScanResult {
        protocol_id: protocol.id.clone(),
        protocol_name: protocol.name.clone(),
        chain_name: state.config.chain_name.clone(),
        scan_timestamp: Utc::now(),
        signatures_checked: 0,
        scan_mode: mode,
        vulnerabilities_found: findings.clone(),
        clean: findings.is_empty(),
        metadata: serde_json::json!({
            "monitor": "dependency_risk",
            "dependencies_checked": protocol.dependencies.len(),
            "exposure_by_kind": exposures,
            "started_at": started_at,
            "completed_at": Utc::now(),
        }),
    }))
}

fn kind_label(kind: &crate::protocols::DependencyKind) -> &'static str {
    match kind {
        crate::protocols::DependencyKind::Bridge => "bridge",
        crate::protocols::DependencyKind::Router => "router",
        crate::protocols::DependencyKind::LendingMarket => "lending_market",
        crate::protocols::DependencyKind::Lp => "lp",
        crate::protocols::DependencyKind::Vault => "vault",
        crate::protocols::DependencyKind::ExternalHook => "external_hook",
        crate::protocols::DependencyKind::Timelock => "timelock",
        crate::protocols::DependencyKind::Oracle => "oracle",
        crate::protocols::DependencyKind::Other => "other",
    }
}
