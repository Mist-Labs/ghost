use super::contract_scanner::{scan_implementation_signatures, severity_for_confidence};
use super::onchain::proxy_state;
use super::{
    FindingType, ScanMode, ScanResult, Severity, VulnerabilityMatch, VulnerabilitySignature,
};
use crate::db::{insert_monitor_snapshot, latest_monitor_snapshot};
use crate::state::AppState;
use anyhow::{anyhow, Result};
use chrono::Utc;
use ethers::abi::{AbiParser, RawLog};
use ethers::providers::Middleware;
use ethers::types::{Address, BlockNumber, Filter, ValueOrArray, H256};
use std::collections::HashSet;

pub async fn monitor_protocol(
    state: &AppState,
    protocol: &crate::protocols::ProtocolDefinition,
    signatures: &[VulnerabilitySignature],
    mode: ScanMode,
) -> Result<Option<ScanResult>> {
    let Some(config) = &protocol.upgrade_monitor else {
        return Ok(None);
    };

    let started_at = Utc::now();
    let mut findings = Vec::new();
    let mut conn = state.pool.get().await?;
    let proxy_addresses = protocol.upgrade_proxy_addresses();
    let proxy_set = proxy_addresses.iter().copied().collect::<HashSet<_>>();

    for proxy_address in &proxy_addresses {
        let current = proxy_state(*proxy_address, &state.provider).await?;
        let scope_key = format!("{proxy_address:?}");
        let previous =
            latest_monitor_snapshot(&mut conn, &protocol.id, "upgrade_proxy", &scope_key).await?;

        insert_monitor_snapshot(
            &mut conn,
            &protocol.id,
            "upgrade_proxy",
            &scope_key,
            serde_json::json!({
                "proxy_address": format!("{:?}", current.proxy_address),
                "implementation": format!("{:?}", current.implementation),
                "admin": current.admin.map(|address| format!("{address:?}")),
                "beacon": current.beacon.map(|address| format!("{address:?}")),
                "codehash": current.codehash,
                "code_size": current.code_size,
            }),
        )
        .await?;

        if let Some(previous) = previous {
            compare_proxy_snapshot(&mut findings, protocol, &current, &previous.payload);
        }
    }

    findings.extend(
        queued_timelock_findings(
            state,
            protocol,
            signatures,
            &proxy_set,
            &config.timelock_addresses,
            config.timelock_lookback_blocks,
        )
        .await?,
    );

    Ok(Some(ScanResult {
        protocol_id: protocol.id.clone(),
        protocol_name: protocol.name.clone(),
        chain_name: state.config.chain_name.clone(),
        scan_timestamp: Utc::now(),
        signatures_checked: signatures.len() as u32,
        scan_mode: mode,
        vulnerabilities_found: findings.clone(),
        clean: findings.is_empty(),
        metadata: serde_json::json!({
            "monitor": "upgrade_risk",
            "proxies_checked": proxy_addresses.len(),
            "timelocks_checked": config.timelock_addresses.len(),
            "started_at": started_at,
            "completed_at": Utc::now(),
        }),
    }))
}

fn compare_proxy_snapshot(
    findings: &mut Vec<VulnerabilityMatch>,
    protocol: &crate::protocols::ProtocolDefinition,
    current: &super::onchain::ProxyState,
    previous: &serde_json::Value,
) {
    let previous_implementation = previous
        .get("implementation")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let current_implementation = format!("{:?}", current.implementation);
    if !previous_implementation.is_empty()
        && !previous_implementation.eq_ignore_ascii_case(&current_implementation)
    {
        findings.push(VulnerabilityMatch {
            finding_type: FindingType::UpgradeRisk,
            signature_id: None,
            title: format!("Proxy implementation changed for {}", protocol.name),
            contract_address: format!("{:?}", current.proxy_address),
            confidence: 0.99,
            severity: Severity::High,
            matched_pattern: "implementation_changed".into(),
            affected_functions: vec!["upgradeTo".into(), "upgradeToAndCall".into()],
            simulation_confirmed: true,
            remediation: "Review the implementation diff, rerun security scans against the new code, and pause sensitive flows until the upgrade is approved.".into(),
            details: serde_json::json!({
                "previous_implementation": previous_implementation,
                "current_implementation": current_implementation,
            }),
        });
    }

    let previous_admin = previous
        .get("admin")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let current_admin = current
        .admin
        .map(|address| format!("{address:?}"))
        .unwrap_or_default();
    if !previous_admin.is_empty() && previous_admin != current_admin {
        findings.push(VulnerabilityMatch {
            finding_type: FindingType::UpgradeRisk,
            signature_id: None,
            title: format!("Proxy admin changed for {}", protocol.name),
            contract_address: format!("{:?}", current.proxy_address),
            confidence: 0.97,
            severity: Severity::High,
            matched_pattern: "proxy_admin_changed".into(),
            affected_functions: Vec::new(),
            simulation_confirmed: true,
            remediation: "Verify the new admin address and revoke any unexpected upgrade authority before executing further changes.".into(),
            details: serde_json::json!({
                "previous_admin": previous_admin,
                "current_admin": current_admin,
            }),
        });
    }
}

async fn queued_timelock_findings(
    state: &AppState,
    protocol: &crate::protocols::ProtocolDefinition,
    signatures: &[VulnerabilitySignature],
    proxy_set: &HashSet<Address>,
    timelock_addresses: &[Address],
    lookback_blocks: u64,
) -> Result<Vec<VulnerabilityMatch>> {
    if timelock_addresses.is_empty() {
        return Ok(Vec::new());
    }

    let events = AbiParser::default().parse(&[
        "event CallScheduled(bytes32 indexed id, uint256 indexed index, address target, uint256 value, bytes data, bytes32 predecessor, uint256 delay)",
        "event CallExecuted(bytes32 indexed id, uint256 indexed index, address target, uint256 value, bytes data)",
        "event Cancelled(bytes32 indexed id)",
    ])?;
    let scheduled = events.event("CallScheduled")?.clone();
    let executed = events.event("CallExecuted")?.clone();
    let cancelled = events.event("Cancelled")?.clone();

    let current_block = state.provider.get_block_number().await?.as_u64();
    let from_block = current_block.saturating_sub(lookback_blocks);
    let addresses = timelock_addresses.to_vec();

    let scheduled_logs = state
        .provider
        .get_logs(
            &Filter::new()
                .address(ValueOrArray::Array(addresses.clone()))
                .from_block(BlockNumber::Number(from_block.into()))
                .topic0(H256::from_slice(scheduled.signature().as_bytes())),
        )
        .await?;
    let executed_logs = state
        .provider
        .get_logs(
            &Filter::new()
                .address(ValueOrArray::Array(addresses.clone()))
                .from_block(BlockNumber::Number(from_block.into()))
                .topic0(H256::from_slice(executed.signature().as_bytes())),
        )
        .await?;
    let cancelled_logs = state
        .provider
        .get_logs(
            &Filter::new()
                .address(ValueOrArray::Array(addresses))
                .from_block(BlockNumber::Number(from_block.into()))
                .topic0(H256::from_slice(cancelled.signature().as_bytes())),
        )
        .await?;

    let mut closed_ids = HashSet::new();
    for log in executed_logs {
        let parsed = executed.parse_log(RawLog {
            topics: log.topics.clone(),
            data: log.data.to_vec(),
        })?;
        if let Some(token) = parsed.params.first() {
            closed_ids.insert(token.value.clone().into_fixed_bytes().unwrap_or_default());
        }
    }
    for log in cancelled_logs {
        let parsed = cancelled.parse_log(RawLog {
            topics: log.topics.clone(),
            data: log.data.to_vec(),
        })?;
        if let Some(token) = parsed.params.first() {
            closed_ids.insert(token.value.clone().into_fixed_bytes().unwrap_or_default());
        }
    }

    let mut findings = Vec::new();
    for log in scheduled_logs {
        let parsed = scheduled.parse_log(RawLog {
            topics: log.topics.clone(),
            data: log.data.to_vec(),
        })?;

        let id = parsed
            .params
            .first()
            .and_then(|param| param.value.clone().into_fixed_bytes())
            .unwrap_or_default();
        if closed_ids.contains(&id) {
            continue;
        }

        let target = parsed
            .params
            .iter()
            .find(|param| param.name == "target")
            .and_then(|param| param.value.clone().into_address())
            .ok_or_else(|| anyhow!("timelock event missing target"))?;
        if !proxy_set.contains(&target) && !protocol.scan_addresses().contains(&target) {
            continue;
        }

        let data = parsed
            .params
            .iter()
            .find(|param| param.name == "data")
            .and_then(|param| param.value.clone().into_bytes())
            .unwrap_or_default();
        let delay = parsed
            .params
            .iter()
            .find(|param| param.name == "delay")
            .and_then(|param| param.value.clone().into_uint())
            .map(|value| value.as_u64())
            .unwrap_or_default();

        match decode_upgrade_action(&data)? {
            QueueAction::Upgrade { implementation } => {
                findings.push(VulnerabilityMatch {
                    finding_type: FindingType::GovernanceRisk,
                    signature_id: None,
                    title: format!("Queued proxy upgrade detected for {}", protocol.name),
                    contract_address: format!("{target:?}"),
                    confidence: 0.9,
                    severity: Severity::Medium,
                    matched_pattern: "queued_upgrade".into(),
                    affected_functions: vec!["upgradeTo".into()],
                    simulation_confirmed: true,
                    remediation: "Review the queued implementation before execution and block governance execution if the code has not been approved.".into(),
                    details: serde_json::json!({
                        "timelock": format!("{:?}", log.address),
                        "queued_proxy": format!("{target:?}"),
                        "queued_implementation": format!("{implementation:?}"),
                        "delay_secs": delay,
                        "scheduled_tx_hash": log.transaction_hash.map(|hash| format!("{hash:?}")),
                    }),
                });

                let signature_findings = scan_implementation_signatures(
                    protocol,
                    target,
                    implementation,
                    signatures,
                    &state.provider,
                    &state.http_client,
                    &state.config,
                )
                .await?;

                for mut finding in signature_findings {
                    finding.finding_type = FindingType::GovernanceRisk;
                    finding.title = format!(
                        "Queued implementation introduces {}",
                        finding.matched_pattern
                    );
                    finding.severity =
                        severity_for_confidence(finding.confidence, finding.severity.clone());
                    findings.push(finding);
                }
            }
            QueueAction::Pause => {
                findings.push(VulnerabilityMatch {
                    finding_type: FindingType::GovernanceRisk,
                    signature_id: None,
                    title: format!("Queued pause detected for {}", protocol.name),
                    contract_address: format!("{target:?}"),
                    confidence: 0.88,
                    severity: Severity::Medium,
                    matched_pattern: "queued_pause".into(),
                    affected_functions: vec!["pause".into()],
                    simulation_confirmed: true,
                    remediation: "Validate the pause rationale and make sure operators are prepared for the expected user impact before execution.".into(),
                    details: serde_json::json!({
                        "timelock": format!("{:?}", log.address),
                        "delay_secs": delay,
                    }),
                });
            }
            QueueAction::Unpause => {
                findings.push(VulnerabilityMatch {
                    finding_type: FindingType::GovernanceRisk,
                    signature_id: None,
                    title: format!("Queued unpause detected for {}", protocol.name),
                    contract_address: format!("{target:?}"),
                    confidence: 0.86,
                    severity: Severity::Medium,
                    matched_pattern: "queued_unpause".into(),
                    affected_functions: vec!["unpause".into()],
                    simulation_confirmed: true,
                    remediation: "Confirm the exploit or outage condition is fully remediated before allowing the queued unpause to execute.".into(),
                    details: serde_json::json!({
                        "timelock": format!("{:?}", log.address),
                        "delay_secs": delay,
                    }),
                });
            }
            QueueAction::Other { selector } => {
                if !selector.is_empty() {
                    findings.push(VulnerabilityMatch {
                        finding_type: FindingType::GovernanceRisk,
                        signature_id: None,
                        title: format!("Queued governance action observed on {}", protocol.name),
                        contract_address: format!("{target:?}"),
                        confidence: 0.6,
                        severity: Severity::Low,
                        matched_pattern: "queued_governance_action".into(),
                        affected_functions: vec![selector.clone()],
                        simulation_confirmed: true,
                        remediation: "Review the queued governance calldata and verify that it matches an expected maintenance action.".into(),
                        details: serde_json::json!({
                            "selector": selector,
                            "timelock": format!("{:?}", log.address),
                            "delay_secs": delay,
                        }),
                    });
                }
            }
        }
    }

    Ok(findings)
}

enum QueueAction {
    Upgrade { implementation: Address },
    Pause,
    Unpause,
    Other { selector: String },
}

fn decode_upgrade_action(data: &[u8]) -> Result<QueueAction> {
    if data.len() < 4 {
        return Ok(QueueAction::Other {
            selector: String::new(),
        });
    }

    let abi = AbiParser::default().parse(&[
        "function upgradeTo(address newImplementation)",
        "function upgradeToAndCall(address newImplementation, bytes data)",
        "function pause()",
        "function unpause()",
    ])?;
    let selector = hex::encode(&data[..4]);

    for function in abi.functions() {
        if function.short_signature().as_slice() != &data[..4] {
            continue;
        }
        return match function.name.as_str() {
            "upgradeTo" | "upgradeToAndCall" => {
                let args = function.decode_input(&data[4..])?;
                let implementation = args
                    .first()
                    .and_then(|token| token.clone().into_address())
                    .ok_or_else(|| anyhow!("upgrade calldata missing implementation"))?;
                Ok(QueueAction::Upgrade { implementation })
            }
            "pause" => Ok(QueueAction::Pause),
            "unpause" => Ok(QueueAction::Unpause),
            _ => Ok(QueueAction::Other {
                selector: format!("0x{selector}"),
            }),
        };
    }

    Ok(QueueAction::Other {
        selector: format!("0x{selector}"),
    })
}
