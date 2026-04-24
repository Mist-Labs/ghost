use super::ast_analysis::scan_verified_source;
use super::onchain::{load_abi, proxy_state};
use super::{
    FindingType, ScanMode, ScanResult, Severity, VulnerabilityMatch, VulnerabilitySignature,
};
use crate::config::Config;
use crate::protocols::{normalize_selector, ProtocolDefinition};
use crate::simulation;
use anyhow::Result;
use chrono::Utc;
use ethers::abi::{Abi, ParamType, Token};
use ethers::providers::Middleware;
use ethers::types::{Address, U256};
use reqwest::Client;
use std::collections::HashSet;

pub async fn scan_protocol<M: Middleware + Clone + 'static>(
    protocol: &ProtocolDefinition,
    signatures: &[VulnerabilitySignature],
    provider: &M,
    http_client: &Client,
    config: &Config,
    mode: ScanMode,
) -> Result<ScanResult>
where
    <M as Middleware>::Error: 'static,
{
    let started_at = Utc::now();
    let mut findings = Vec::new();
    let mut scanned = 0usize;

    for address in protocol.scan_addresses() {
        let state = proxy_state(address, provider).await?;
        scanned += 1;
        findings.extend(
            scan_implementation_signatures(
                protocol,
                address,
                state.implementation,
                signatures,
                provider,
                http_client,
                config,
            )
            .await?,
        );
    }

    Ok(ScanResult {
        protocol_id: protocol.id.clone(),
        protocol_name: protocol.name.clone(),
        chain_name: config.chain_name.clone(),
        scan_timestamp: Utc::now(),
        signatures_checked: signatures.len() as u32,
        scan_mode: mode,
        vulnerabilities_found: findings.clone(),
        clean: findings.is_empty(),
        metadata: serde_json::json!({
            "authorized": protocol.monitoring_authorized,
            "contracts_scanned": scanned,
            "oracle_addresses_configured": protocol.oracle_addresses.len(),
            "started_at": started_at,
            "completed_at": Utc::now(),
        }),
    })
}

pub async fn scan_implementation_signatures<M: Middleware + Clone + 'static>(
    protocol: &ProtocolDefinition,
    proxy_address: Address,
    implementation_address: Address,
    signatures: &[VulnerabilitySignature],
    provider: &M,
    http_client: &Client,
    config: &Config,
) -> Result<Vec<VulnerabilityMatch>>
where
    <M as Middleware>::Error: 'static,
{
    let code = provider.get_code(implementation_address, None).await?;
    let bytecode_hex = hex::encode(&code.0);
    let abi = load_abi(protocol, None, implementation_address, http_client, config).await?;
    let selectors = abi.as_ref().map(selectors_from_abi).unwrap_or_default();

    let mut findings = match scan_verified_source(
        protocol,
        proxy_address,
        implementation_address,
        provider,
        http_client,
        config,
    )
    .await
    {
        Ok(findings) => findings,
        Err(error) => {
            tracing::warn!(
                contract = ?implementation_address,
                error = %error,
                "verified-source AST analysis skipped for contract"
            );
            Vec::new()
        }
    };
    for signature in signatures {
        let bytecode_hits = signature
            .bytecode_patterns
            .iter()
            .filter(|pattern| !pattern.is_empty() && bytecode_hex.contains(pattern.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let (abi_hit, affected_functions) = abi
            .as_ref()
            .map(|abi| check_abi_pattern(abi, &signature.abi_patterns))
            .unwrap_or((false, Vec::new()));

        if bytecode_hits.is_empty() && !abi_hit {
            continue;
        }

        let protocol_type_bonus = protocol
            .protocol_type
            .as_ref()
            .map(|kind| {
                signature
                    .protocol_types
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(kind))
            })
            .unwrap_or(false);

        let (simulation_confirmed, simulation_attempted, simulation_reason) =
            simulate_signature_confirmation(
                protocol,
                proxy_address,
                abi.as_ref(),
                &affected_functions,
                signature,
                provider,
                config,
            )
            .await?;

        let confidence = compute_confidence(
            !bytecode_hits.is_empty(),
            abi_hit,
            protocol_type_bonus,
            simulation_confirmed,
        );

        if confidence < 0.35 {
            continue;
        }

        findings.push(VulnerabilityMatch {
            finding_type: FindingType::SignatureMatch,
            signature_id: Some(signature.id),
            title: format!(
                "{} signature match on {}",
                signature.severity.as_storage_value().to_ascii_uppercase(),
                protocol.name
            ),
            contract_address: format!("{implementation_address:?}"),
            confidence,
            severity: signature.severity.clone(),
            matched_pattern: bytecode_hits
                .first()
                .cloned()
                .unwrap_or_else(|| "abi_pattern".to_string()),
            affected_functions,
            simulation_confirmed,
            remediation: signature.remediation.clone(),
            details: serde_json::json!({
                "bytecode_hits": bytecode_hits,
                "abi_hit": abi_hit,
                "abi_selectors": selectors.clone(),
                "proxy_address": format!("{proxy_address:?}"),
                "implementation_address": format!("{implementation_address:?}"),
                "protocol_type_bonus": protocol_type_bonus,
                "simulation_attempted": simulation_attempted,
                "simulation_reason": simulation_reason,
            }),
        });
    }

    Ok(findings)
}

async fn simulate_signature_confirmation<M: Middleware>(
    protocol: &ProtocolDefinition,
    target_address: Address,
    abi: Option<&Abi>,
    affected_functions: &[String],
    signature: &VulnerabilitySignature,
    provider: &M,
    config: &Config,
) -> Result<(bool, bool, Option<String>)>
where
    <M as Middleware>::Error: 'static,
{
    let Some(abi) = abi else {
        return Ok((false, false, Some("missing_abi".into())));
    };

    let should_attempt = matches!(
        signature.attack_vector,
        crate::proactive::AttackVector::AccessControl
            | crate::proactive::AttackVector::GovernanceAttack
            | crate::proactive::AttackVector::SignatureValidation
            | crate::proactive::AttackVector::FlashLoanManipulation
            | crate::proactive::AttackVector::OracleManipulation
            | crate::proactive::AttackVector::PriceManipulation
    );
    if !should_attempt {
        return Ok((false, false, Some("attack_vector_not_simulatable".into())));
    }

    let latest_block = simulation::latest_block_number(provider).await?;
    let mut market_probe_reason: Option<String> = None;
    if matches!(
        signature.attack_vector,
        crate::proactive::AttackVector::FlashLoanManipulation
            | crate::proactive::AttackVector::OracleManipulation
            | crate::proactive::AttackVector::PriceManipulation
    ) {
        if let Some(profile) = &protocol.simulation {
            if let Some(path) = profile.market_paths.first() {
                match simulation::probe_market_liquidity(
                    config,
                    protocol,
                    latest_block,
                    path.token_in,
                    path.token_out,
                    path.amount_in
                        .as_deref()
                        .map(U256::from_dec_str)
                        .transpose()?,
                )
                .await
                {
                    Ok(Some(probe)) => {
                        let flash_required = matches!(
                            signature.attack_vector,
                            crate::proactive::AttackVector::FlashLoanManipulation
                        );
                        let confirmed = probe.route_executable
                            && (!flash_required || probe.flash_loan_available);
                        let reason = format!(
                            "market_probe:{}:{}",
                            probe.path_label.unwrap_or_else(|| "unknown_path".into()),
                            probe.reason
                        );
                        if confirmed {
                            return Ok((true, true, Some(reason)));
                        }
                        market_probe_reason = Some(reason);
                    }
                    Ok(None) => {
                        market_probe_reason = Some("market_probe:no_matching_path".into());
                    }
                    Err(error) => {
                        tracing::debug!(
                            error = %error,
                            "market simulation probe failed for proactive signature"
                        );
                        market_probe_reason = Some(format!("market_probe:error:{}", error));
                    }
                }
            }
        }
    }

    for function_name in affected_functions {
        let Ok(function) = abi.function(function_name) else {
            continue;
        };
        let args = function
            .inputs
            .iter()
            .map(|param| placeholder_token(&param.kind))
            .collect::<Result<Vec<_>>>()?;
        let calldata = ethers::types::Bytes::from(function.encode_input(&args)?);

        match simulation::call_on_fork(
            config,
            latest_block,
            target_address,
            calldata,
            Some(U256::from(6_000_000_u64)),
        )
        .await
        {
            Ok(receipt) if receipt.status == Some(1u64.into()) => {
                return Ok((
                    true,
                    true,
                    Some(format!("fork_simulation_succeeded:{function_name}")),
                ))
            }
            Ok(receipt) => {
                tracing::debug!(
                    function = %function_name,
                    status = ?receipt.status,
                    "fork simulation candidate reverted or failed"
                );
            }
            Err(error) => {
                tracing::debug!(
                    function = %function_name,
                    error = %error,
                    "fork simulation candidate errored"
                );
            }
        }
    }

    Ok((
        false,
        true,
        Some(match market_probe_reason {
            Some(reason) => format!("{reason};fork_simulation_failed_for_all_candidates"),
            None => "fork_simulation_failed_for_all_candidates".into(),
        }),
    ))
}

fn placeholder_token(kind: &ParamType) -> Result<Token> {
    Ok(match kind {
        ParamType::Address => Token::Address(Address::from_low_u64_be(0x1111)),
        ParamType::Bytes => Token::Bytes(vec![1_u8; 4]),
        ParamType::FixedBytes(size) => Token::FixedBytes(vec![1_u8; *size]),
        ParamType::Int(_) => Token::Int(1_u8.into()),
        ParamType::Uint(_) => Token::Uint(1_u8.into()),
        ParamType::Bool => Token::Bool(true),
        ParamType::String => Token::String("ghost".to_string()),
        ParamType::Array(inner) => Token::Array(vec![placeholder_token(inner)?]),
        ParamType::FixedArray(inner, size) => Token::FixedArray(
            (0..*size)
                .map(|_| placeholder_token(inner))
                .collect::<Result<Vec<_>>>()?,
        ),
        ParamType::Tuple(items) => Token::Tuple(
            items
                .iter()
                .map(placeholder_token)
                .collect::<Result<Vec<_>>>()?,
        ),
    })
}

pub fn check_abi_pattern(
    abi: &Abi,
    patterns: &[crate::proactive::ABIPattern],
) -> (bool, Vec<String>) {
    let names = abi
        .functions()
        .map(|function| function.name.clone())
        .collect::<HashSet<_>>();
    let mut affected = HashSet::new();

    for pattern in patterns {
        let requires_hit = pattern
            .requires_functions
            .iter()
            .all(|name| names.contains(name));
        let sequence_hit = pattern
            .dangerous_sequence
            .iter()
            .all(|name| names.contains(name));

        if requires_hit || sequence_hit {
            for name in &pattern.requires_functions {
                if names.contains(name) {
                    affected.insert(name.clone());
                }
            }
            for name in &pattern.dangerous_sequence {
                if names.contains(name) {
                    affected.insert(name.clone());
                }
            }
        }
    }

    let affected = affected.into_iter().collect::<Vec<_>>();
    (!affected.is_empty(), affected)
}

pub fn compute_confidence(
    bytecode_hit: bool,
    abi_hit: bool,
    protocol_type_bonus: bool,
    simulation_confirmed: bool,
) -> f64 {
    let mut confidence: f64 = 0.0;
    if bytecode_hit {
        confidence += 0.45;
    }
    if abi_hit {
        confidence += 0.35;
    }
    if protocol_type_bonus {
        confidence += 0.10;
    }
    if simulation_confirmed {
        confidence += 0.10;
    }
    confidence.min(0.99)
}

pub fn selectors_from_abi(abi: &Abi) -> Vec<String> {
    abi.functions()
        .map(|function| normalize_selector(&hex::encode(function.short_signature())))
        .collect()
}

pub fn severity_for_confidence(confidence: f64, base: Severity) -> Severity {
    if confidence >= 0.9 {
        base
    } else if confidence >= 0.75 {
        match base {
            Severity::Critical => Severity::High,
            other => other,
        }
    } else {
        Severity::Medium
    }
}

#[cfg(test)]
mod tests {
    use super::compute_confidence;
    use crate::proactive::AttackVector;

    #[test]
    fn computes_confidence_from_evidence() {
        assert!((compute_confidence(true, true, true, false) - 0.90).abs() < f64::EPSILON);
    }

    #[test]
    fn classifies_attack_vectors() {
        assert_eq!(
            AttackVector::classify("price oracle manipulation on base"),
            AttackVector::OracleManipulation
        );
        assert_eq!(
            AttackVector::classify("reentrancy attack through fallback"),
            AttackVector::Reentrancy
        );
    }
}
