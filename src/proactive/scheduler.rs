use super::contract_scanner::scan_protocol;
use super::dependency_monitor;
use super::disclosure::handle_scan_result;
use super::disclosure::process_due_disclosures;
use super::hack_feed::poll_hack_feeds;
use super::invariant_monitor;
use super::oracle_monitor;
use super::signature_extractor::extract_signature;
use super::upgrade_monitor;
use super::{ScanMode, ScanResult, SimulationMode};
use crate::db::{
    decode_signature, insert_hack_report_if_new, insert_monitor_snapshot, insert_signature,
    list_signatures,
};
use crate::model::StoredMonitorSnapshot;
use crate::model::{NewHackIntelReport, NewStoredSignature};
use crate::protocols::ProtocolDefinition;
use crate::simulation;
use crate::state::AppState;
use anyhow::Result;
use std::sync::Arc;
use tokio::time::{interval, MissedTickBehavior};

pub fn start(state: Arc<AppState>) {
    let poller_state = state.clone();
    tokio::spawn(async move {
        let mut ticker = interval(std::time::Duration::from_secs(
            poller_state.config.hack_feed_poll_interval_secs,
        ));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            if let Err(error) = poll_and_scan(poller_state.clone()).await {
                tracing::error!(error = %error, "proactive feed poll failed");
            }
        }
    });

    let scanner_state = state.clone();
    tokio::spawn(async move {
        let mut ticker = interval(std::time::Duration::from_secs(
            scanner_state.config.full_scan_interval_secs,
        ));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            if let Err(error) = run_full_scan(scanner_state.clone()).await {
                tracing::error!(error = %error, "scheduled full scan failed");
            }
        }
    });

    let disclosure_state = state.clone();
    tokio::spawn(async move {
        let mut ticker = interval(std::time::Duration::from_secs(
            disclosure_state.config.disclosure_followup_interval_secs,
        ));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            if let Err(error) = process_due_disclosures(&disclosure_state).await {
                tracing::error!(error = %error, "disclosure follow-up failed");
            }
        }
    });
}

pub async fn poll_and_scan(state: Arc<AppState>) -> Result<()> {
    let reports = poll_hack_feeds(&state.http_client).await?;
    for report in reports {
        let Some(stored_report) = ({
            let mut conn = state.pool.get().await?;
            insert_hack_report_if_new(
                &mut conn,
                &NewHackIntelReport {
                    source: report.source.clone(),
                    external_id: report.external_id.clone(),
                    protocol: report.protocol.clone(),
                    published_at: report.published_at,
                    loss_usd: report.loss_usd,
                    attack_vector: report.attack_vector.clone(),
                    root_cause: report.root_cause.clone(),
                    chain_name: report.chain_name.clone(),
                    title: report.title.clone(),
                    summary: report.summary.clone(),
                    source_url: report.source_url.clone(),
                    raw_payload: report.raw_payload.clone(),
                },
            )
            .await?
        }) else {
            continue;
        };

        tracing::info!(
            protocol = %stored_report.protocol,
            source = %stored_report.source,
            "new hack report ingested"
        );

        let Some(api_key) = state.config.openai_api_key.as_deref() else {
            tracing::warn!("OPENAI_API_KEY is not configured; skipping signature extraction");
            continue;
        };

        let signature = extract_signature(
            &state.http_client,
            api_key,
            &state.config.openai_model,
            stored_report.id,
            &report,
        )
        .await?;

        {
            let mut conn = state.pool.get().await?;
            insert_signature(
                &mut conn,
                &NewStoredSignature {
                    derived_from_report_id: stored_report.id,
                    model: state.config.openai_model.clone(),
                    signature: signature.clone(),
                },
            )
            .await?;
        }

        let protocols = state.protocols.monitored_protocols(state.config.chain_id);
        for protocol in protocols {
            let protocol_type_match = protocol
                .protocol_type
                .as_ref()
                .map(|value| {
                    signature
                        .protocol_types
                        .iter()
                        .any(|candidate| candidate.eq_ignore_ascii_case(value))
                })
                .unwrap_or(false);

            if stored_report.chain_name != state.config.chain_name && !protocol_type_match {
                continue;
            }

            let effective_protocol = validated_protocol_for_scan(&state, &protocol).await?;
            let started_at = chrono::Utc::now();
            let result = annotate_scan_result(
                scan_protocol(
                    &effective_protocol.protocol,
                    std::slice::from_ref(&signature),
                    &state.provider,
                    &state.http_client,
                    &state.config,
                    ScanMode::Triggered {
                        source_report_id: stored_report.id,
                        source: stored_report.source.clone(),
                    },
                )
                .await?,
                &effective_protocol,
            );
            handle_scan_result(&state, &protocol, &result, started_at).await?;
        }
    }

    Ok(())
}

pub async fn run_full_scan(state: Arc<AppState>) -> Result<()> {
    let signatures = {
        let mut conn = state.pool.get().await?;
        list_signatures(&mut conn, 250)
            .await?
            .into_iter()
            .map(|row| decode_signature(&row))
            .collect::<Result<Vec<_>, _>>()?
    };

    for protocol in state.protocols.monitored_protocols(state.config.chain_id) {
        let effective_protocol = validated_protocol_for_scan(&state, &protocol).await?;
        if !signatures.is_empty() {
            let started_at = chrono::Utc::now();
            let result = annotate_scan_result(
                scan_protocol(
                    &effective_protocol.protocol,
                    &signatures,
                    &state.provider,
                    &state.http_client,
                    &state.config,
                    ScanMode::Scheduled,
                )
                .await?,
                &effective_protocol,
            );
            handle_scan_result(&state, &protocol, &result, started_at).await?;
        }

        if let Some(result) =
            upgrade_monitor::monitor_protocol(
                &state,
                &protocol,
                &signatures,
                ScanMode::Scheduled,
            )
                .await?
        {
            let result = annotate_scan_result(result, &effective_protocol);
            handle_scan_result(&state, &protocol, &result, chrono::Utc::now()).await?;
        }

        if let Some(result) =
            oracle_monitor::monitor_protocol(&state, &protocol, ScanMode::Scheduled).await?
        {
            let result = annotate_scan_result(result, &effective_protocol);
            handle_scan_result(&state, &protocol, &result, chrono::Utc::now()).await?;
        }

        if let Some(result) =
            dependency_monitor::monitor_protocol(&state, &protocol, ScanMode::Scheduled).await?
        {
            let result = annotate_scan_result(result, &effective_protocol);
            handle_scan_result(&state, &protocol, &result, chrono::Utc::now()).await?;
        }

        if let Some(result) =
            invariant_monitor::monitor_protocol(&state, &protocol, ScanMode::Scheduled).await?
        {
            let result = annotate_scan_result(result, &effective_protocol);
            handle_scan_result(&state, &protocol, &result, chrono::Utc::now()).await?;
        }
    }

    crate::monitoring::run_monitoring_cycle(&state).await?;

    Ok(())
}

struct ValidatedProtocolForScan {
    protocol: ProtocolDefinition,
    simulation_mode: SimulationMode,
    snapshot: Option<StoredMonitorSnapshot>,
}

async fn validated_protocol_for_scan(
    state: &AppState,
    protocol: &ProtocolDefinition,
) -> Result<ValidatedProtocolForScan> {
    let Some(validation) =
        simulation::validate_protocol_simulation_profile(&state.provider, protocol).await?
    else {
        return Ok(ValidatedProtocolForScan {
            protocol: protocol.clone(),
            simulation_mode: SimulationMode::Generic,
            snapshot: None,
        });
    };

    let payload = serde_json::json!({
        "healthy": validation.healthy,
        "fallback_mode": if validation.healthy {
            "configured_profile"
        } else {
            "generic_simulation_only"
        },
        "validation": validation,
    });
    let mut conn = state.pool.get().await?;
    let snapshot = insert_monitor_snapshot(
        &mut conn,
        &protocol.id,
        "simulation_profile",
        "active_profile",
        payload,
    )
    .await?;

    if validation.healthy {
        return Ok(ValidatedProtocolForScan {
            protocol: protocol.clone(),
            simulation_mode: SimulationMode::ConfiguredHealthy,
            snapshot: Some(snapshot),
        });
    }

    tracing::warn!(
        protocol_id = %protocol.id,
        protocol_name = %protocol.name,
        warnings = ?validation.warnings,
        "simulation profile validation failed; falling back to generic logic"
    );

    let mut degraded = protocol.clone();
    degraded.simulation = None;
    Ok(ValidatedProtocolForScan {
        protocol: degraded,
        simulation_mode: SimulationMode::ConfiguredDegraded,
        snapshot: Some(snapshot),
    })
}

fn annotate_scan_result(
    mut result: ScanResult,
    validated_protocol: &ValidatedProtocolForScan,
) -> ScanResult {
    let simulation_metadata = serde_json::json!({
        "simulation_mode": validated_protocol.simulation_mode.as_storage_value(),
        "simulation_profile_snapshot_id": validated_protocol
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.id),
        "simulation_profile_observed_at": validated_protocol
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.observed_at),
    });

    let mut metadata = result.metadata.as_object().cloned().unwrap_or_default();
    metadata.insert(
        "simulation_mode".into(),
        serde_json::Value::String(validated_protocol.simulation_mode.as_storage_value().into()),
    );
    metadata.insert("simulation_profile".into(), simulation_metadata);
    result.metadata = serde_json::Value::Object(metadata);
    result
}
