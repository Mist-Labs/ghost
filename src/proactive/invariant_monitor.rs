use super::onchain::{read_metric_source, severity_from_config};
use super::{FindingType, ScanMode, ScanResult, Severity, VulnerabilityMatch};
use crate::db::{insert_monitor_snapshot, latest_monitor_snapshot};
use crate::state::AppState;
use anyhow::Result;
use chrono::Utc;
use ethers::types::U256;

pub async fn monitor_protocol(
    state: &AppState,
    protocol: &crate::protocols::ProtocolDefinition,
    mode: ScanMode,
) -> Result<Option<ScanResult>> {
    if protocol.invariants.is_empty() {
        return Ok(None);
    }

    let started_at = Utc::now();
    let mut findings = Vec::new();
    let mut conn = state.pool.get().await?;

    for invariant in &protocol.invariants {
        let default_severity = match invariant.rule {
            crate::protocols::InvariantRule::MaxDrawdownBps { .. } => Severity::High,
            crate::protocols::InvariantRule::RatioMin { .. } => Severity::High,
            crate::protocols::InvariantRule::RatioMax { .. } => Severity::High,
            crate::protocols::InvariantRule::DeltaMaxBps { .. } => Severity::Medium,
            crate::protocols::InvariantRule::ValueRange { .. } => Severity::Medium,
        };
        let severity = severity_from_config(invariant.severity.as_deref(), default_severity);
        let scope_key = invariant.name.clone();

        let (violated, matched_pattern, remediation, details) = match &invariant.rule {
            crate::protocols::InvariantRule::RatioMin {
                numerator,
                denominator,
                min_bps,
            } => {
                let numerator_value = read_metric_source(
                    &state.provider,
                    protocol,
                    numerator,
                    &state.http_client,
                    &state.config,
                )
                .await?;
                let denominator_value = read_metric_source(
                    &state.provider,
                    protocol,
                    denominator,
                    &state.http_client,
                    &state.config,
                )
                .await?;
                let violated = denominator_value.is_zero()
                    || numerator_value.saturating_mul(U256::from(10_000u64))
                        < denominator_value.saturating_mul(U256::from(*min_bps));
                (
                    violated,
                    "ratio_min".to_string(),
                    "Restore solvency or reserve coverage above the configured floor before allowing new state-changing actions.".to_string(),
                    serde_json::json!({
                        "numerator": numerator_value.to_string(),
                        "denominator": denominator_value.to_string(),
                        "min_bps": min_bps,
                    }),
                )
            }
            crate::protocols::InvariantRule::RatioMax {
                numerator,
                denominator,
                max_bps,
            } => {
                let numerator_value = read_metric_source(
                    &state.provider,
                    protocol,
                    numerator,
                    &state.http_client,
                    &state.config,
                )
                .await?;
                let denominator_value = read_metric_source(
                    &state.provider,
                    protocol,
                    denominator,
                    &state.http_client,
                    &state.config,
                )
                .await?;
                let violated = denominator_value.is_zero()
                    || numerator_value.saturating_mul(U256::from(10_000u64))
                        > denominator_value.saturating_mul(U256::from(*max_bps));
                (
                    violated,
                    "ratio_max".to_string(),
                    "Reduce utilization or debt exposure until the monitored ratio falls back under the configured ceiling.".to_string(),
                    serde_json::json!({
                        "numerator": numerator_value.to_string(),
                        "denominator": denominator_value.to_string(),
                        "max_bps": max_bps,
                    }),
                )
            }
            crate::protocols::InvariantRule::DeltaMaxBps {
                left,
                right,
                max_bps,
            } => {
                let left_value = read_metric_source(
                    &state.provider,
                    protocol,
                    left,
                    &state.http_client,
                    &state.config,
                )
                .await?;
                let right_value = read_metric_source(
                    &state.provider,
                    protocol,
                    right,
                    &state.http_client,
                    &state.config,
                )
                .await?;
                let baseline = if left_value > right_value {
                    left_value
                } else {
                    right_value
                };
                let delta = if left_value > right_value {
                    left_value - right_value
                } else {
                    right_value - left_value
                };
                let violated = !baseline.is_zero()
                    && delta.saturating_mul(U256::from(10_000u64))
                        > baseline.saturating_mul(U256::from(*max_bps));
                (
                    violated,
                    "delta_max_bps".to_string(),
                    "Reconcile the accounting mismatch and halt flows that can amplify the balance drift.".to_string(),
                    serde_json::json!({
                        "left": left_value.to_string(),
                        "right": right_value.to_string(),
                        "delta": delta.to_string(),
                        "max_bps": max_bps,
                    }),
                )
            }
            crate::protocols::InvariantRule::ValueRange { metric, min, max } => {
                let value = read_metric_source(
                    &state.provider,
                    protocol,
                    metric,
                    &state.http_client,
                    &state.config,
                )
                .await?;
                let min = parse_optional_u256(min.as_deref())?;
                let max = parse_optional_u256(max.as_deref())?;
                let violated = min.map(|min| value < min).unwrap_or(false)
                    || max.map(|max| value > max).unwrap_or(false);
                (
                    violated,
                    "value_range".to_string(),
                    "Bring the monitored value back inside the approved operating band before processing further requests.".to_string(),
                    serde_json::json!({
                        "value": value.to_string(),
                        "min": min.map(|v| v.to_string()),
                        "max": max.map(|v| v.to_string()),
                    }),
                )
            }
            crate::protocols::InvariantRule::MaxDrawdownBps { metric, max_bps } => {
                let current = read_metric_source(
                    &state.provider,
                    protocol,
                    metric,
                    &state.http_client,
                    &state.config,
                )
                .await?;
                let previous =
                    latest_monitor_snapshot(&mut conn, &protocol.id, "invariant", &scope_key)
                        .await?;
                let previous_value = previous
                    .as_ref()
                    .and_then(|snapshot| snapshot.payload.get("value"))
                    .and_then(|value| value.as_str())
                    .and_then(|value| U256::from_dec_str(value).ok());
                let drawdown_bps = previous_value
                    .filter(|previous| !previous.is_zero() && current < *previous)
                    .map(|previous| {
                        ((previous - current).saturating_mul(U256::from(10_000u64))) / previous
                    })
                    .unwrap_or_else(U256::zero);
                let violated = drawdown_bps > U256::from(*max_bps);
                (
                    violated,
                    "max_drawdown_bps".to_string(),
                    "Investigate the value drop, reconcile reserves, and consider pausing withdrawals if the drawdown is not expected.".to_string(),
                    serde_json::json!({
                        "previous_value": previous_value.map(|v| v.to_string()),
                        "current_value": current.to_string(),
                        "drawdown_bps": drawdown_bps.to_string(),
                        "max_bps": max_bps,
                    }),
                )
            }
        };

        insert_monitor_snapshot(
            &mut conn,
            &protocol.id,
            "invariant",
            &scope_key,
            serde_json::json!({
                "name": invariant.name,
                "rule": matched_pattern.clone(),
                "value": details.get("current_value").and_then(|value| value.as_str()).unwrap_or_default(),
                "details": details.clone(),
            }),
        )
        .await?;

        if violated {
            findings.push(VulnerabilityMatch {
                finding_type: FindingType::InvariantViolation,
                signature_id: None,
                title: format!("Invariant violation: {}", invariant.name),
                contract_address: protocol
                    .scan_addresses()
                    .first()
                    .map(|address| format!("{address:?}"))
                    .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".into()),
                confidence: 0.97,
                severity,
                matched_pattern,
                affected_functions: Vec::new(),
                simulation_confirmed: true,
                remediation,
                details,
            });
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
            "monitor": "invariants",
            "invariants_checked": protocol.invariants.len(),
            "started_at": started_at,
            "completed_at": Utc::now(),
        }),
    }))
}

fn parse_optional_u256(value: Option<&str>) -> Result<Option<U256>> {
    match value {
        Some(value) => Ok(Some(U256::from_dec_str(value)?)),
        None => Ok(None),
    }
}
