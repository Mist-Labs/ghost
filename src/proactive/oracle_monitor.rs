use super::ast_analysis::{analyze_oracle_usage, OracleSourceEvidence};
use super::onchain::{proxy_state, read_chainlink_feed, read_uniswap_v3_twap};
use super::{FindingType, ScanMode, ScanResult, Severity, VulnerabilityMatch};
use crate::db::insert_monitor_snapshot;
use crate::state::AppState;
use anyhow::Result;
use chrono::Utc;
use std::collections::{BTreeMap, HashSet};

pub async fn monitor_protocol(
    state: &AppState,
    protocol: &crate::protocols::ProtocolDefinition,
    mode: ScanMode,
) -> Result<Option<ScanResult>> {
    let Some(config) = &protocol.oracle_monitor else {
        return Ok(None);
    };
    if config.feeds.is_empty() {
        return Ok(None);
    }

    let started_at = Utc::now();
    let mut findings = Vec::new();
    let mut feed_values: BTreeMap<String, Vec<(String, f64)>> = BTreeMap::new();
    let mut non_sequencer_sources = 0usize;
    let mut has_sequencer_feed = false;
    let now = Utc::now().timestamp() as u64;
    let mut conn = state.pool.get().await?;
    let oracle_source_evidence = collect_oracle_source_evidence(state, protocol).await?;

    for evidence in &oracle_source_evidence {
        insert_monitor_snapshot(
            &mut conn,
            &protocol.id,
            "oracle_source_evidence",
            &evidence.implementation_address,
            serde_json::to_value(evidence)?,
        )
        .await?;
    }

    for feed in &config.feeds {
        let pair_key = feed.pair.clone().unwrap_or_else(|| feed.label.clone());
        match feed.kind {
            crate::protocols::OracleKind::Chainlink => {
                let round = read_chainlink_feed(&state.provider, feed.address).await?;
                non_sequencer_sources += 1;
                feed_values
                    .entry(pair_key)
                    .or_default()
                    .push((feed.label.clone(), round.answer));

                insert_monitor_snapshot(
                    &mut conn,
                    &protocol.id,
                    "oracle_feed",
                    &feed.label,
                    serde_json::json!({
                        "kind": "chainlink",
                        "address": format!("{:?}", feed.address),
                        "answer": round.answer,
                        "raw_answer": round.raw_answer,
                        "updated_at": round.updated_at,
                        "decimals": round.decimals,
                    }),
                )
                .await?;

                if let Some(heartbeat) = feed.heartbeat_secs {
                    let age = now.saturating_sub(round.updated_at);
                    if age > heartbeat {
                        findings.push(VulnerabilityMatch {
                            finding_type: FindingType::OracleRisk,
                            signature_id: None,
                            title: format!("Oracle {} is stale", feed.label),
                            contract_address: format!("{:?}", feed.address),
                            confidence: 0.98,
                            severity: Severity::High,
                            matched_pattern: "stale_oracle_price".into(),
                            affected_functions: vec!["latestRoundData".into()],
                            simulation_confirmed: true,
                            remediation: "Pause oracle-dependent actions or fail over to an independent source until the feed resumes updating within its heartbeat.".into(),
                            details: serde_json::json!({
                                "heartbeat_secs": heartbeat,
                                "age_secs": age,
                                "pair": feed.pair,
                            }),
                        });
                    }
                }
            }
            crate::protocols::OracleKind::SequencerUptime => {
                has_sequencer_feed = true;
                let round = read_chainlink_feed(&state.provider, feed.address).await?;
                insert_monitor_snapshot(
                    &mut conn,
                    &protocol.id,
                    "oracle_feed",
                    &feed.label,
                    serde_json::json!({
                        "kind": "sequencer_uptime",
                        "address": format!("{:?}", feed.address),
                        "answer": round.answer,
                        "updated_at": round.updated_at,
                    }),
                )
                .await?;

                if round.answer >= 1.0 {
                    findings.push(VulnerabilityMatch {
                        finding_type: FindingType::OracleRisk,
                        signature_id: None,
                        title: format!("Sequencer uptime feed {} reports downtime", feed.label),
                        contract_address: format!("{:?}", feed.address),
                        confidence: 0.99,
                        severity: Severity::Critical,
                        matched_pattern: "sequencer_down".into(),
                        affected_functions: vec!["latestRoundData".into()],
                        simulation_confirmed: true,
                        remediation: "Block price-sensitive protocol actions until the Base sequencer returns and the grace period has elapsed.".into(),
                        details: serde_json::json!({
                            "raw_status": round.raw_answer,
                            "updated_at": round.updated_at,
                        }),
                    });
                }
            }
            crate::protocols::OracleKind::UniswapV3Twap => {
                if let Some(window_secs) = feed.window_secs {
                    let twap =
                        read_uniswap_v3_twap(&state.provider, feed.address, window_secs).await?;
                    non_sequencer_sources += 1;
                    let twap_price = 1.0001f64.powi(twap.twap_tick);
                    feed_values
                        .entry(pair_key)
                        .or_default()
                        .push((feed.label.clone(), twap_price));

                    insert_monitor_snapshot(
                        &mut conn,
                        &protocol.id,
                        "oracle_feed",
                        &feed.label,
                        serde_json::json!({
                            "kind": "uniswap_v3_twap",
                            "address": format!("{:?}", feed.address),
                            "window_secs": twap.window_secs,
                            "spot_tick": twap.spot_tick,
                            "twap_tick": twap.twap_tick,
                            "deviation_bps": twap.deviation_bps,
                        }),
                    )
                    .await?;

                    if window_secs < config.minimum_twap_window_secs {
                        findings.push(VulnerabilityMatch {
                            finding_type: FindingType::OracleRisk,
                            signature_id: None,
                            title: format!("TWAP window for {} is too short", feed.label),
                            contract_address: format!("{:?}", feed.address),
                            confidence: 0.95,
                            severity: Severity::High,
                            matched_pattern: "twap_window_too_short".into(),
                            affected_functions: vec!["observe".into()],
                            simulation_confirmed: true,
                            remediation: "Increase the TWAP window so transient manipulation does not materially move the oracle input.".into(),
                            details: serde_json::json!({
                                "configured_window_secs": window_secs,
                                "minimum_window_secs": config.minimum_twap_window_secs,
                            }),
                        });
                    }

                    if twap.deviation_bps > config.max_spot_vs_twap_deviation_bps {
                        findings.push(VulnerabilityMatch {
                            finding_type: FindingType::OracleRisk,
                            signature_id: None,
                            title: format!("Spot/TWAP deviation exceeded threshold for {}", feed.label),
                            contract_address: format!("{:?}", feed.address),
                            confidence: 0.9,
                            severity: Severity::High,
                            matched_pattern: "spot_twap_deviation".into(),
                            affected_functions: vec!["slot0".into(), "observe".into()],
                            simulation_confirmed: true,
                            remediation: "Switch to the TWAP value for sensitive paths and review whether the spot price has been manipulated.".into(),
                            details: serde_json::json!({
                                "deviation_bps": twap.deviation_bps,
                                "allowed_bps": config.max_spot_vs_twap_deviation_bps,
                                "window_secs": twap.window_secs,
                            }),
                        });
                    }
                }
            }
        }
    }

    if config.require_sequencer_uptime_feed && !has_sequencer_feed {
        findings.push(VulnerabilityMatch {
            finding_type: FindingType::OracleRisk,
            signature_id: None,
            title: format!("{} is missing a sequencer uptime feed", protocol.name),
            contract_address: protocol
                .scan_addresses()
                .first()
                .map(|address| format!("{address:?}"))
                .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".into()),
            confidence: 0.92,
            severity: Severity::High,
            matched_pattern: "missing_sequencer_uptime_feed".into(),
            affected_functions: Vec::new(),
            simulation_confirmed: true,
            remediation: "Integrate the Base sequencer uptime feed and gate oracle-sensitive operations until the sequencer is healthy.".into(),
            details: serde_json::json!({
                "minimum_sources": config.minimum_sources,
            }),
        });
    }

    if non_sequencer_sources < config.minimum_sources {
        findings.push(VulnerabilityMatch {
            finding_type: FindingType::OracleRisk,
            signature_id: None,
            title: format!("{} depends on too few independent oracle sources", protocol.name),
            contract_address: protocol
                .scan_addresses()
                .first()
                .map(|address| format!("{address:?}"))
                .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".into()),
            confidence: 0.88,
            severity: Severity::Medium,
            matched_pattern: "single_source_oracle_dependency".into(),
            affected_functions: Vec::new(),
            simulation_confirmed: true,
            remediation: "Add an independent corroborating source or a circuit breaker before executing price-sensitive actions.".into(),
            details: serde_json::json!({
                "observed_sources": non_sequencer_sources,
                "required_sources": config.minimum_sources,
            }),
        });
    }

    for (pair, values) in &feed_values {
        if values.len() < 2 {
            continue;
        }
        let min = values
            .iter()
            .map(|(_, value)| *value)
            .fold(f64::MAX, f64::min);
        let max = values
            .iter()
            .map(|(_, value)| *value)
            .fold(f64::MIN, f64::max);
        if min <= 0.0 {
            continue;
        }
        let deviation_bps = (((max - min) / min) * 10_000.0).round() as u64;
        if deviation_bps > config.max_cross_source_deviation_bps {
            findings.push(VulnerabilityMatch {
                finding_type: FindingType::OracleRisk,
                signature_id: None,
                title: format!("Cross-source oracle deviation exceeded threshold for {pair}"),
                contract_address: protocol
                    .scan_addresses()
                    .first()
                    .map(|address| format!("{address:?}"))
                    .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".into()),
                confidence: 0.94,
                severity: Severity::High,
                matched_pattern: "cross_source_oracle_deviation".into(),
                affected_functions: Vec::new(),
                simulation_confirmed: true,
                remediation: "Freeze price-sensitive actions and investigate which source has diverged before accepting new prices.".into(),
                details: serde_json::json!({
                    "pair": pair,
                    "deviation_bps": deviation_bps,
                    "allowed_bps": config.max_cross_source_deviation_bps,
                    "sources": values,
                }),
            });
        }
    }

    findings.extend(build_hybrid_findings(
        protocol,
        config,
        &oracle_source_evidence,
        non_sequencer_sources,
        has_sequencer_feed,
    ));

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
            "monitor": "oracle_safety",
            "feeds_checked": config.feeds.len(),
            "non_sequencer_sources": non_sequencer_sources,
            "has_sequencer_feed": has_sequencer_feed,
            "oracle_source_evidence_contracts": oracle_source_evidence.len(),
            "started_at": started_at,
            "completed_at": Utc::now(),
        }),
    }))
}

async fn collect_oracle_source_evidence(
    state: &AppState,
    protocol: &crate::protocols::ProtocolDefinition,
) -> Result<Vec<OracleSourceEvidence>> {
    let mut evidence = Vec::new();
    let mut scanned = HashSet::new();

    for address in protocol.scan_addresses() {
        let proxy = proxy_state(address, &state.provider).await?;
        if !scanned.insert(proxy.implementation) {
            continue;
        }
        match analyze_oracle_usage(
            protocol,
            proxy.implementation,
            &state.http_client,
            &state.config,
        )
        .await
        {
            Ok(Some(source)) => evidence.push(source),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    contract = ?proxy.implementation,
                    error = %error,
                    "oracle source evidence analysis skipped for contract"
                );
            }
        }
    }

    Ok(evidence)
}

fn build_hybrid_findings(
    protocol: &crate::protocols::ProtocolDefinition,
    config: &crate::protocols::OracleMonitorDefinition,
    evidence: &[OracleSourceEvidence],
    non_sequencer_sources: usize,
    has_sequencer_feed: bool,
) -> Vec<VulnerabilityMatch> {
    let mut findings = Vec::new();
    let default_contract = protocol
        .scan_addresses()
        .first()
        .map(|address| format!("{address:?}"))
        .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".into());

    for contract in evidence {
        for consumer in &contract.consumer_functions {
            let direct_spot_read = consumer.reads_uniswap_spot
                || consumer.reads_reserve_spot
                || consumer.reads_chainlink_round;
            let missing_delay_or_recency = !consumer.has_delay_guard
                && !consumer.checks_updated_at
                && !consumer.checks_answered_in_round;

            if direct_spot_read
                && !consumer.reads_uniswap_twap
                && config.minimum_twap_window_secs > 0
            {
                findings.push(VulnerabilityMatch {
                    finding_type: FindingType::OracleRisk,
                    signature_id: None,
                    title: format!(
                        "Oracle consumer {} lacks clear TWAP enforcement",
                        consumer.function_name
                    ),
                    contract_address: contract.implementation_address.clone(),
                    confidence: 0.91,
                    severity: Severity::High,
                    matched_pattern: "oracle_consumer_missing_twap_enforcement".into(),
                    affected_functions: vec![consumer.function_name.clone()],
                    simulation_confirmed: true,
                    remediation: "Use a time-weighted oracle path or explicit delayed observation window before consuming spot-sensitive prices.".into(),
                    details: serde_json::json!({
                        "source_backend": contract.source_backend,
                        "compiler_version": contract.compiler_version,
                        "source_path": consumer.source_path,
                        "line": consumer.line,
                        "column": consumer.column,
                        "reads_chainlink_round": consumer.reads_chainlink_round,
                        "reads_uniswap_spot": consumer.reads_uniswap_spot,
                        "reads_reserve_spot": consumer.reads_reserve_spot,
                        "reads_uniswap_twap": consumer.reads_uniswap_twap,
                        "minimum_twap_window_secs": config.minimum_twap_window_secs,
                    }),
                });
            }

            if consumer.reads_chainlink_round
                && missing_delay_or_recency
                && (!has_sequencer_feed || config.require_sequencer_uptime_feed)
            {
                findings.push(VulnerabilityMatch {
                    finding_type: FindingType::OracleRisk,
                    signature_id: None,
                    title: format!(
                        "Oracle consumer {} lacks recency or sequencer safety checks",
                        consumer.function_name
                    ),
                    contract_address: contract.implementation_address.clone(),
                    confidence: 0.93,
                    severity: Severity::High,
                    matched_pattern: "oracle_consumer_missing_recency_guard".into(),
                    affected_functions: vec![consumer.function_name.clone()],
                    simulation_confirmed: true,
                    remediation: "Validate updatedAt/answeredInRound freshness and gate price-sensitive paths behind Base sequencer health checks.".into(),
                    details: serde_json::json!({
                        "source_backend": contract.source_backend,
                        "compiler_version": contract.compiler_version,
                        "source_path": consumer.source_path,
                        "line": consumer.line,
                        "column": consumer.column,
                        "checks_updated_at": consumer.checks_updated_at,
                        "checks_answered_in_round": consumer.checks_answered_in_round,
                        "has_delay_guard": consumer.has_delay_guard,
                        "has_sequencer_feed": has_sequencer_feed,
                    }),
                });
            }

            if direct_spot_read
                && missing_delay_or_recency
                && (!contract.update_functions.is_empty() || non_sequencer_sources < 2)
            {
                findings.push(VulnerabilityMatch {
                    finding_type: FindingType::OracleRisk,
                    signature_id: None,
                    title: format!(
                        "Oracle consumer {} may allow same-block price consumption",
                        consumer.function_name
                    ),
                    contract_address: contract.implementation_address.clone(),
                    confidence: if contract.update_functions.is_empty() { 0.86 } else { 0.94 },
                    severity: if contract.update_functions.is_empty() {
                        Severity::High
                    } else {
                        Severity::Critical
                    },
                    matched_pattern: "same_block_oracle_consumption_window".into(),
                    affected_functions: vec![consumer.function_name.clone()],
                    simulation_confirmed: true,
                    remediation: "Introduce a delayed observation window or block-based grace period between oracle updates and oracle-dependent execution paths.".into(),
                    details: serde_json::json!({
                        "source_backend": contract.source_backend,
                        "compiler_version": contract.compiler_version,
                        "source_path": consumer.source_path,
                        "line": consumer.line,
                        "column": consumer.column,
                        "update_surfaces": contract.update_functions,
                        "non_sequencer_sources": non_sequencer_sources,
                        "reads_uniswap_twap": consumer.reads_uniswap_twap,
                        "has_delay_guard": consumer.has_delay_guard,
                    }),
                });
            }

            if non_sequencer_sources < config.minimum_sources && direct_spot_read {
                findings.push(VulnerabilityMatch {
                    finding_type: FindingType::OracleRisk,
                    signature_id: None,
                    title: format!(
                        "Oracle consumer {} relies on a direct single-source read",
                        consumer.function_name
                    ),
                    contract_address: contract.implementation_address.clone(),
                    confidence: 0.9,
                    severity: Severity::High,
                    matched_pattern: "single_source_oracle_direct_read".into(),
                    affected_functions: vec![consumer.function_name.clone()],
                    simulation_confirmed: true,
                    remediation: "Require corroboration from an independent oracle source or circuit breaker before accepting the read for price-sensitive paths.".into(),
                    details: serde_json::json!({
                        "source_backend": contract.source_backend,
                        "compiler_version": contract.compiler_version,
                        "source_path": consumer.source_path,
                        "line": consumer.line,
                        "column": consumer.column,
                        "observed_sources": non_sequencer_sources,
                        "required_sources": config.minimum_sources,
                    }),
                });
            }
        }
    }

    if findings.is_empty() && non_sequencer_sources == 0 {
        findings.push(VulnerabilityMatch {
            finding_type: FindingType::OracleRisk,
            signature_id: None,
            title: format!("{} has no usable oracle evidence configured", protocol.name),
            contract_address: default_contract,
            confidence: 0.74,
            severity: Severity::Medium,
            matched_pattern: "oracle_monitor_configuration_gap".into(),
            affected_functions: Vec::new(),
            simulation_confirmed: true,
            remediation: "Add configured oracle feeds and verify the price-consumer source paths so Ghost can enforce hybrid oracle safety checks.".into(),
            details: serde_json::json!({
                "observed_sources": non_sequencer_sources,
                "source_evidence_contracts": evidence.len(),
            }),
        });
    }

    findings
}
