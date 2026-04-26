use super::onchain::{
    load_abi, load_verified_source_bundle, VerifiedSourceBackend, VerifiedSourceBundle,
};
use super::{FindingType, Severity, VulnerabilityMatch};
use crate::config::Config;
use crate::protocols::ProtocolDefinition;
use crate::simulation;
use anyhow::{anyhow, Context, Result};
use ethers::abi::{Abi, ParamType, Token};
use ethers::providers::Middleware;
use ethers::types::{Address, Bytes, U256};
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Clone)]
struct AstRuleMatch {
    rule_id: &'static str,
    title: String,
    severity: Severity,
    remediation: String,
    function_name: Option<String>,
    source_path: String,
    line: usize,
    column: usize,
    description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OracleSourceEvidence {
    pub contract_name: String,
    pub implementation_address: String,
    pub source_backend: String,
    pub compiler_version: String,
    pub consumer_functions: Vec<OracleConsumerEvidence>,
    pub update_functions: Vec<OracleUpdateSurface>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OracleConsumerEvidence {
    pub function_name: String,
    pub source_path: String,
    pub line: usize,
    pub column: usize,
    pub reads_chainlink_round: bool,
    pub reads_uniswap_spot: bool,
    pub reads_uniswap_twap: bool,
    pub reads_reserve_spot: bool,
    pub uses_block_timestamp: bool,
    pub uses_block_number: bool,
    pub checks_updated_at: bool,
    pub checks_answered_in_round: bool,
    pub has_delay_guard: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct OracleUpdateSurface {
    pub function_name: String,
    pub source_path: String,
    pub line: usize,
    pub column: usize,
}

pub async fn scan_verified_source<M: Middleware + Clone + 'static>(
    protocol: &ProtocolDefinition,
    proxy_address: Address,
    implementation_address: Address,
    provider: &M,
    http_client: &Client,
    config: &Config,
) -> Result<Vec<VulnerabilityMatch>>
where
    <M as Middleware>::Error: 'static,
{
    let Some(bundle) =
        load_verified_source_bundle(protocol, implementation_address, http_client, config).await?
    else {
        return Ok(Vec::new());
    };

    if !bundle.language.eq_ignore_ascii_case("solidity") {
        tracing::info!(
            contract = ?implementation_address,
            language = %bundle.language,
            "skipping AST analysis for non-Solidity verified source"
        );
        return Ok(Vec::new());
    }

    let compiled_asts = compile_source_bundle(&bundle, config).await?;
    if compiled_asts.is_empty() {
        return Ok(Vec::new());
    }

    let abi = load_abi(protocol, None, implementation_address, http_client, config).await?;
    let latest_block = simulation::latest_block_number(provider, config).await?;

    let mut findings = Vec::new();
    for rule_match in collect_rule_matches(&bundle, &compiled_asts)? {
        let (simulation_confirmed, simulation_reason) = match rule_match.function_name.as_deref() {
            Some(function_name)
                if matches!(
                    rule_match.rule_id,
                    "unprotected_upgrade"
                        | "delegatecall_on_user_input"
                        | "public_selfdestruct"
                        | "unprotected_initializer"
                        | "critical_access_control_missing"
                ) =>
            {
                simulate_ast_confirmation(
                    proxy_address,
                    latest_block,
                    abi.as_ref(),
                    function_name,
                    config,
                )
                .await?
            }
            _ => (
                false,
                Some("rule_requires_human_path_or_multi-contract_context".into()),
            ),
        };

        findings.push(VulnerabilityMatch {
            finding_type: FindingType::AstRisk,
            signature_id: None,
            title: rule_match.title.clone(),
            contract_address: format!("{implementation_address:?}"),
            confidence: ast_confidence(rule_match.rule_id, simulation_confirmed),
            severity: rule_match.severity.clone(),
            matched_pattern: rule_match.rule_id.to_string(),
            affected_functions: rule_match.function_name.clone().into_iter().collect(),
            simulation_confirmed,
            remediation: rule_match.remediation.clone(),
            details: serde_json::json!({
                "rule_id": rule_match.rule_id,
                "description": rule_match.description,
                "source_backend": source_backend_label(&bundle.backend),
                "compiler_version": bundle.compiler_version,
                "contract_name": bundle.contract_name,
                "language": bundle.language,
                "optimizer_enabled": bundle.optimizer_enabled,
                "optimizer_runs": bundle.optimizer_runs,
                "source_path": rule_match.source_path,
                "line": rule_match.line,
                "column": rule_match.column,
                "proxy_address": format!("{proxy_address:?}"),
                "implementation_address": format!("{implementation_address:?}"),
                "simulation_reason": simulation_reason,
            }),
        });
    }

    Ok(findings)
}

pub async fn analyze_oracle_usage(
    protocol: &ProtocolDefinition,
    implementation_address: Address,
    http_client: &Client,
    config: &Config,
) -> Result<Option<OracleSourceEvidence>> {
    let Some(bundle) =
        load_verified_source_bundle(protocol, implementation_address, http_client, config).await?
    else {
        return Ok(None);
    };

    if !bundle.language.eq_ignore_ascii_case("solidity") {
        return Ok(None);
    }

    let compiled_asts = compile_source_bundle(&bundle, config).await?;
    if compiled_asts.is_empty() {
        return Ok(None);
    }

    let evidence = collect_oracle_source_evidence(&bundle, implementation_address, &compiled_asts)?;

    Ok(
        (!evidence.consumer_functions.is_empty() || !evidence.update_functions.is_empty())
            .then_some(evidence),
    )
}

fn source_backend_label(backend: &VerifiedSourceBackend) -> &'static str {
    match backend {
        VerifiedSourceBackend::Sourcify => "sourcify",
        VerifiedSourceBackend::BaseScan => "basescan",
    }
}

fn ast_confidence(rule_id: &str, simulation_confirmed: bool) -> f64 {
    let base = match rule_id {
        "unprotected_upgrade" => 0.58,
        "delegatecall_on_user_input" => 0.55,
        "public_selfdestruct" => 0.62,
        "tx_origin_auth" => 0.44,
        "unchecked_low_level_call" => 0.56,
        "unchecked_arithmetic_block" => 0.46,
        "unprotected_initializer" => 0.63,
        "critical_access_control_missing" => 0.57,
        "reentrancy_window" => 0.48,
        _ => 0.40,
    };
    if simulation_confirmed {
        (base + 0.27_f64).min(0.95_f64)
    } else {
        base
    }
}

fn collect_rule_matches(
    bundle: &VerifiedSourceBundle,
    compiled_asts: &BTreeMap<String, Value>,
) -> Result<Vec<AstRuleMatch>> {
    let mut findings = Vec::new();
    let mut dedupe = HashSet::new();

    for (path, ast) in compiled_asts {
        let Some(source) = bundle.source_files.get(path) else {
            continue;
        };
        let state_variables = collect_state_variable_names(ast);
        let functions = collect_nodes_by_type(ast, "FunctionDefinition");
        for function in functions {
            let visibility = function
                .get("visibility")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !matches!(visibility, "public" | "external") {
                continue;
            }

            let function_name = function
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("<fallback>")
                .to_string();
            let modifiers = function
                .get("modifiers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(extract_modifier_name)
                .map(|name| name.to_ascii_lowercase())
                .collect::<HashSet<_>>();
            let param_names = function
                .get("parameters")
                .and_then(|value| value.get("parameters"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|param| param.get("name").and_then(Value::as_str))
                .filter(|name| !name.is_empty())
                .map(ToOwned::to_owned)
                .collect::<HashSet<_>>();
            let src = function
                .get("src")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let body = function.get("body");

            if suspicious_upgrade_function(&function_name) && !has_guard_modifier(&modifiers) {
                push_rule_match(
                    &mut findings,
                    &mut dedupe,
                    path,
                    source,
                    src,
                    &function_name,
                    AstRuleMatch {
                        rule_id: "unprotected_upgrade",
                        title: format!("Unprotected upgrade surface on {}", bundle.contract_name),
                        severity: Severity::Critical,
                        remediation: "Restrict upgrade entrypoints behind explicit admin or timelock modifiers and validate implementation targets.".into(),
                        function_name: Some(function_name.clone()),
                        source_path: path.clone(),
                        line: 0,
                        column: 0,
                        description: format!(
                            "Function `{}` looks like an upgrade surface but does not carry an obvious access-control modifier.",
                            function_name
                        ),
                    },
                );
            }

            if suspicious_initializer_function(&function_name)
                && !has_initializer_modifier(&modifiers)
            {
                push_rule_match(
                    &mut findings,
                    &mut dedupe,
                    path,
                    source,
                    src,
                    &function_name,
                    AstRuleMatch {
                        rule_id: "unprotected_initializer",
                        title: format!("Unprotected initializer on {}", bundle.contract_name),
                        severity: Severity::Critical,
                        remediation: "Guard initializer entrypoints with `initializer` or equivalent one-time initialization protection and keep them operator-gated.".into(),
                        function_name: Some(function_name.clone()),
                        source_path: path.clone(),
                        line: 0,
                        column: 0,
                        description: format!(
                            "Function `{}` looks like an initializer but does not carry an initializer-style modifier.",
                            function_name
                        ),
                    },
                );
            }

            let Some(body) = body else {
                continue;
            };

            if let Some(node) = find_tx_origin(body) {
                push_rule_match(
                    &mut findings,
                    &mut dedupe,
                    path,
                    source,
                    node.get("src").and_then(Value::as_str).unwrap_or(src),
                    &function_name,
                    AstRuleMatch {
                        rule_id: "tx_origin_auth",
                        title: format!("tx.origin authorization pattern on {}", bundle.contract_name),
                        severity: Severity::High,
                        remediation: "Replace tx.origin authorization with explicit msg.sender role checks or signature validation.".into(),
                        function_name: Some(function_name.clone()),
                        source_path: path.clone(),
                        line: 0,
                        column: 0,
                        description: format!(
                            "Function `{}` references tx.origin, which is unsafe for authorization decisions.",
                            function_name
                        ),
                    },
                );
            }

            if let Some(node) = find_unchecked_low_level_call(body) {
                push_rule_match(
                    &mut findings,
                    &mut dedupe,
                    path,
                    source,
                    node.get("src").and_then(Value::as_str).unwrap_or(src),
                    &function_name,
                    AstRuleMatch {
                        rule_id: "unchecked_low_level_call",
                        title: format!(
                            "Unchecked low-level call return value on {}",
                            bundle.contract_name
                        ),
                        severity: Severity::High,
                        remediation: "Capture low-level call return values and explicitly require or handle the success flag before proceeding.".into(),
                        function_name: Some(function_name.clone()),
                        source_path: path.clone(),
                        line: 0,
                        column: 0,
                        description: format!(
                            "Function `{}` issues a low-level call and appears to ignore the returned success value.",
                            function_name
                        ),
                    },
                );
            }

            if let Some(node) = find_selfdestruct(body) {
                push_rule_match(
                    &mut findings,
                    &mut dedupe,
                    path,
                    source,
                    node.get("src").and_then(Value::as_str).unwrap_or(src),
                    &function_name,
                    AstRuleMatch {
                        rule_id: "public_selfdestruct",
                        title: format!("Reachable selfdestruct surface on {}", bundle.contract_name),
                        severity: Severity::Critical,
                        remediation: "Remove selfdestruct-capable code paths or gate them behind governance-only break-glass controls.".into(),
                        function_name: Some(function_name.clone()),
                        source_path: path.clone(),
                        line: 0,
                        column: 0,
                        description: format!(
                            "Function `{}` can reach selfdestruct from a public or external entrypoint.",
                            function_name
                        ),
                    },
                );
            }

            if let Some(node) = find_unchecked_arithmetic(body) {
                push_rule_match(
                    &mut findings,
                    &mut dedupe,
                    path,
                    source,
                    node.get("src").and_then(Value::as_str).unwrap_or(src),
                    &function_name,
                    AstRuleMatch {
                        rule_id: "unchecked_arithmetic_block",
                        title: format!(
                            "Unchecked arithmetic block on {}",
                            bundle.contract_name
                        ),
                        severity: Severity::Medium,
                        remediation: "Avoid arithmetic in `unchecked` blocks unless bounds are proven, documented, and externally constrained.".into(),
                        function_name: Some(function_name.clone()),
                        source_path: path.clone(),
                        line: 0,
                        column: 0,
                        description: format!(
                            "Function `{}` performs arithmetic inside an explicit `unchecked` block.",
                            function_name
                        ),
                    },
                );
            }

            if let Some(node) = find_user_controlled_delegatecall(body, &param_names) {
                push_rule_match(
                    &mut findings,
                    &mut dedupe,
                    path,
                    source,
                    node.get("src").and_then(Value::as_str).unwrap_or(src),
                    &function_name,
                    AstRuleMatch {
                        rule_id: "delegatecall_on_user_input",
                        title: format!(
                            "User-controlled delegatecall target on {}",
                            bundle.contract_name
                        ),
                        severity: Severity::Critical,
                        remediation: "Do not delegatecall to user-supplied targets; constrain execution to audited implementations or immutable registries.".into(),
                        function_name: Some(function_name.clone()),
                        source_path: path.clone(),
                        line: 0,
                        column: 0,
                        description: format!(
                            "Function `{}` delegatecalls through a parameter-derived target.",
                            function_name
                        ),
                    },
                );
            }

            if !has_non_reentrant_modifier(&modifiers) {
                if let Some(node) = find_reentrancy_window(body, &state_variables) {
                    push_rule_match(
                        &mut findings,
                        &mut dedupe,
                        path,
                        source,
                        node.get("src").and_then(Value::as_str).unwrap_or(src),
                        &function_name,
                        AstRuleMatch {
                            rule_id: "reentrancy_window",
                            title: format!("Reentrancy-style call/write ordering on {}", bundle.contract_name),
                            severity: Severity::Medium,
                            remediation: "Move state updates before external calls, or add a proven reentrancy guard and checks-effects-interactions ordering.".into(),
                            function_name: Some(function_name.clone()),
                            source_path: path.clone(),
                            line: 0,
                            column: 0,
                            description: format!(
                                "Function `{}` performs an external call before a later state write without an obvious reentrancy guard.",
                                function_name
                            ),
                        },
                    );
                }
            }

            if critical_state_transition_function(&function_name)
                && !has_guard_modifier(&modifiers)
                && !has_access_control_check(body)
            {
                push_rule_match(
                    &mut findings,
                    &mut dedupe,
                    path,
                    source,
                    src,
                    &function_name,
                    AstRuleMatch {
                        rule_id: "critical_access_control_missing",
                        title: format!(
                            "Critical state-transition surface lacks clear access control on {}",
                            bundle.contract_name
                        ),
                        severity: Severity::High,
                        remediation: "Protect critical state-transition entrypoints with explicit role checks, ownership checks, or timelock/governance modifiers.".into(),
                        function_name: Some(function_name.clone()),
                        source_path: path.clone(),
                        line: 0,
                        column: 0,
                        description: format!(
                            "Function `{}` matches a critical control surface but Ghost could not find an obvious modifier or msg.sender/role-based guard.",
                            function_name
                        ),
                    },
                );
            }
        }
    }

    Ok(findings)
}

fn collect_oracle_source_evidence(
    bundle: &VerifiedSourceBundle,
    implementation_address: Address,
    compiled_asts: &BTreeMap<String, Value>,
) -> Result<OracleSourceEvidence> {
    let mut consumers = Vec::new();
    let mut updates = Vec::new();

    for (path, ast) in compiled_asts {
        let Some(source) = bundle.source_files.get(path) else {
            continue;
        };
        for function in collect_nodes_by_type(ast, "FunctionDefinition") {
            let visibility = function
                .get("visibility")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !matches!(visibility, "public" | "external") {
                continue;
            }

            let function_name = function
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("<fallback>")
                .to_string();
            let src = function
                .get("src")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let (line, column) = source_location(source, src).unwrap_or((0, 0));
            let body = function.get("body");

            if suspicious_price_update_function(&function_name) {
                updates.push(OracleUpdateSurface {
                    function_name: function_name.clone(),
                    source_path: path.clone(),
                    line,
                    column,
                });
            }

            let Some(body) = body else {
                continue;
            };
            let call_names = collect_call_names(body);
            let reads_chainlink_round = call_names.contains("latestrounddata");
            let reads_uniswap_spot = call_names.contains("slot0");
            let reads_uniswap_twap =
                call_names.contains("observe") || call_names.contains("consult");
            let reads_reserve_spot = call_names.contains("getreserves");
            let uses_block_timestamp = find_block_member(body, "timestamp").is_some();
            let uses_block_number = find_block_member(body, "number").is_some();
            let checks_updated_at = references_identifier(body, "updatedAt");
            let checks_answered_in_round = references_identifier(body, "answeredInRound");
            let has_delay_guard = has_oracle_delay_guard(body);

            let looks_oracle_sensitive = reads_chainlink_round
                || reads_uniswap_spot
                || reads_uniswap_twap
                || reads_reserve_spot
                || references_identifier(body, "oracle")
                || references_identifier(body, "price");

            if looks_oracle_sensitive {
                consumers.push(OracleConsumerEvidence {
                    function_name,
                    source_path: path.clone(),
                    line,
                    column,
                    reads_chainlink_round,
                    reads_uniswap_spot,
                    reads_uniswap_twap,
                    reads_reserve_spot,
                    uses_block_timestamp,
                    uses_block_number,
                    checks_updated_at,
                    checks_answered_in_round,
                    has_delay_guard,
                });
            }
        }
    }

    Ok(OracleSourceEvidence {
        contract_name: bundle.contract_name.clone(),
        implementation_address: format!("{implementation_address:?}"),
        source_backend: source_backend_label(&bundle.backend).to_string(),
        compiler_version: bundle.compiler_version.clone(),
        consumer_functions: consumers,
        update_functions: updates,
    })
}

fn push_rule_match(
    findings: &mut Vec<AstRuleMatch>,
    dedupe: &mut HashSet<(String, String, String)>,
    path: &str,
    source: &str,
    src: &str,
    function_name: &str,
    mut finding: AstRuleMatch,
) {
    let key = (
        finding.rule_id.to_string(),
        path.to_string(),
        function_name.to_string(),
    );
    if dedupe.contains(&key) {
        return;
    }
    if let Some((line, column)) = source_location(source, src) {
        finding.line = line;
        finding.column = column;
    }
    dedupe.insert(key);
    findings.push(finding);
}

async fn simulate_ast_confirmation(
    target_address: Address,
    fork_block_number: u64,
    abi: Option<&Abi>,
    function_name: &str,
    config: &Config,
) -> Result<(bool, Option<String>)> {
    let Some(abi) = abi else {
        return Ok((false, Some("missing_abi".into())));
    };
    let Ok(function) = abi.function(function_name) else {
        return Ok((false, Some("function_missing_from_abi".into())));
    };

    let args = function
        .inputs
        .iter()
        .map(|param| ast_placeholder_token(&param.kind))
        .collect::<Result<Vec<_>>>()?;
    let calldata = Bytes::from(function.encode_input(&args)?);
    match simulation::call_on_fork(config, fork_block_number, target_address, calldata, None).await
    {
        Ok(receipt) if receipt.status == Some(1u64.into()) => {
            Ok((true, Some(format!("fork_replay_succeeded:{function_name}"))))
        }
        Ok(receipt) => Ok((
            false,
            Some(format!(
                "fork_replay_failed_status:{}",
                receipt
                    .status
                    .map(|value| value.as_u64())
                    .unwrap_or_default()
            )),
        )),
        Err(error) => Ok((false, Some(format!("fork_replay_error:{error}")))),
    }
}

fn ast_placeholder_token(kind: &ParamType) -> Result<Token> {
    Ok(match kind {
        ParamType::Address => Token::Address(Address::from_low_u64_be(0x1111)),
        ParamType::Bytes => Token::Bytes(vec![0_u8; 4]),
        ParamType::FixedBytes(size) => Token::FixedBytes(vec![1_u8; *size]),
        ParamType::Int(_) => Token::Int(U256::from(1_u8)),
        ParamType::Uint(_) => Token::Uint(U256::from(1_u8)),
        ParamType::Bool => Token::Bool(true),
        ParamType::String => Token::String("ghost".to_string()),
        ParamType::Array(inner) => Token::Array(vec![ast_placeholder_token(inner)?]),
        ParamType::FixedArray(inner, size) => Token::FixedArray(
            (0..*size)
                .map(|_| ast_placeholder_token(inner))
                .collect::<Result<Vec<_>>>()?,
        ),
        ParamType::Tuple(items) => Token::Tuple(
            items
                .iter()
                .map(ast_placeholder_token)
                .collect::<Result<Vec<_>>>()?,
        ),
    })
}

async fn compile_source_bundle(
    bundle: &VerifiedSourceBundle,
    config: &Config,
) -> Result<BTreeMap<String, Value>> {
    let solc_path = resolve_solc_path(&bundle.compiler_version, config).await?;
    let input = serde_json::to_vec(&bundle.standard_json_input)?;
    let compiler_version = bundle.compiler_version.clone();

    let output = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut child = Command::new(&solc_path)
            .arg("--standard-json")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to execute {}", solc_path.display()))?;

        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| anyhow!("failed to open solc stdin"))?;
            use std::io::Write;
            stdin.write_all(&input)?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(anyhow!(
                "solc {} failed: {}",
                compiler_version,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(output.stdout)
    })
    .await
    .context("solc compile task failed")??;

    let compiled: Value = serde_json::from_slice(&output)?;
    if let Some(errors) = compiled.get("errors").and_then(Value::as_array) {
        let fatal = errors
            .iter()
            .filter(|entry| entry.get("severity").and_then(Value::as_str) == Some("error"))
            .map(|entry| {
                entry
                    .get("formattedMessage")
                    .and_then(Value::as_str)
                    .or_else(|| entry.get("message").and_then(Value::as_str))
                    .unwrap_or("solc reported an unknown error")
                    .to_string()
            })
            .collect::<Vec<_>>();
        if !fatal.is_empty() {
            return Err(anyhow!(
                "solc {} emitted fatal errors: {}",
                bundle.compiler_version,
                fatal.join("\n")
            ));
        }
    }

    let mut asts = BTreeMap::new();
    for (path, _) in &bundle.source_files {
        if let Some(ast) = compiled
            .get("sources")
            .and_then(|value| value.get(path))
            .and_then(|value| value.get("ast"))
            .cloned()
        {
            asts.insert(path.clone(), ast);
        }
    }
    Ok(asts)
}

async fn resolve_solc_path(version: &str, config: &Config) -> Result<PathBuf> {
    let normalized = normalize_solc_version(version);
    let short = normalized
        .split('+')
        .next()
        .unwrap_or(normalized.as_str())
        .to_string();
    let cache_dir = config
        .solc_bin_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(".solc-bin"));

    if let Some(dir) = &config.solc_bin_dir {
        for candidate in solc_path_candidates(dir, &normalized, &short) {
            if candidate.exists() {
                verify_solc_version(&candidate, &normalized).await?;
                return Ok(candidate);
            }
        }
    }

    let configured = PathBuf::from(&config.solc_binary);
    match verify_solc_version(&configured, &normalized).await {
        Ok(()) => return Ok(configured),
        Err(error) if !config.solc_auto_install => return Err(error),
        Err(error) => {
            tracing::debug!(
                error = %error,
                required_version = %normalized,
                "configured solc did not match verified source compiler"
            );
        }
    }

    if config.solc_auto_install {
        let installed = install_solc_version(&normalized, &short, &cache_dir).await?;
        verify_solc_version(&installed, &normalized).await?;
        return Ok(installed);
    }

    Err(anyhow!("no solc binary found for required compiler version {normalized}"))
}

fn solc_path_candidates(dir: &Path, normalized: &str, short: &str) -> Vec<PathBuf> {
    vec![
        dir.join(format!("solc-{normalized}")),
        dir.join(format!("solc-v{normalized}")),
        dir.join(format!("solc-{short}")),
        dir.join(format!("solc-v{short}")),
        dir.join(normalized).join("solc"),
        dir.join(short).join("solc"),
    ]
}

async fn install_solc_version(normalized: &str, short: &str, dir: &Path) -> Result<PathBuf> {
    let target = dir.join(format!("solc-{normalized}"));
    if target.exists() {
        return Ok(target);
    }

    tokio::fs::create_dir_all(dir).await?;
    let platform = solc_binary_platform()?;
    let list_url = format!("https://binaries.soliditylang.org/{platform}/list.json");
    let list: Value = reqwest::get(&list_url)
        .await
        .with_context(|| format!("failed to fetch {list_url}"))?
        .error_for_status()?
        .json()
        .await?;
    let build_path = list
        .get("releases")
        .and_then(|value| value.get(short))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("solc {short} is not listed for {platform}"))?;
    let download_url = format!("https://binaries.soliditylang.org/{platform}/{build_path}");
    let bytes = reqwest::get(&download_url)
        .await
        .with_context(|| format!("failed to download {download_url}"))?
        .error_for_status()?
        .bytes()
        .await?;
    let tmp = target.with_extension("tmp");
    tokio::fs::write(&tmp, &bytes).await?;

    #[cfg(unix)]
    {
        let permissions = std::fs::Permissions::from_mode(0o755);
        tokio::fs::set_permissions(&tmp, permissions).await?;
    }

    tokio::fs::rename(&tmp, &target).await?;
    tracing::info!(
        compiler_version = %normalized,
        path = %target.display(),
        "installed solc compiler for verified-source AST analysis"
    );
    Ok(target)
}

fn solc_binary_platform() -> Result<&'static str> {
    match std::env::consts::OS {
        "macos" => Ok("macosx-amd64"),
        "linux" => Ok("linux-amd64"),
        "windows" => Ok("windows-amd64"),
        other => Err(anyhow!("automatic solc install is unsupported on {other}")),
    }
}

async fn verify_solc_version(path: &Path, version: &str) -> Result<()> {
    let path = path.to_path_buf();
    let version = version.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let output = Command::new(&path)
            .arg("--version")
            .output()
            .with_context(|| format!("failed to execute {}", path.display()))?;
        if !output.status.success() {
            return Err(anyhow!("solc version probe failed for {}", path.display()));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains(&version) {
            return Err(anyhow!(
                "solc binary {} does not match required compiler version {}",
                path.display(),
                version
            ));
        }
        Ok(())
    })
    .await
    .context("solc version probe task failed")??;
    Ok(())
}

fn normalize_solc_version(version: &str) -> String {
    version.trim().trim_start_matches('v').to_string()
}

fn collect_nodes_by_type<'a>(root: &'a Value, node_type: &str) -> Vec<&'a Value> {
    let mut nodes = Vec::new();
    visit_ast(root, &mut |node| {
        if node.get("nodeType").and_then(Value::as_str) == Some(node_type) {
            nodes.push(node);
        }
    });
    nodes
}

fn visit_ast<'a, F>(node: &'a Value, visitor: &mut F)
where
    F: FnMut(&'a Value),
{
    visitor(node);
    match node {
        Value::Array(items) => {
            for item in items {
                visit_ast(item, visitor);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                visit_ast(value, visitor);
            }
        }
        _ => {}
    }
}

fn suspicious_upgrade_function(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("upgrade")
        || name.contains("setimplementation")
        || name.contains("setbeacon")
        || name.contains("setcode")
}

fn suspicious_initializer_function(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "initialize" || name.starts_with("initialize") || name.starts_with("init")
}

fn critical_state_transition_function(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("setowner")
        || name.contains("transferownership")
        || name.contains("setadmin")
        || name.contains("changeadmin")
        || name.contains("pause")
        || name.contains("unpause")
        || name.contains("setoracle")
        || name.contains("setpricefeed")
        || name.contains("setguardian")
        || name.contains("setgovernance")
        || name.contains("settreasury")
        || name.contains("sweep")
        || name.contains("rescue")
        || name.contains("emergency")
}

fn has_guard_modifier(modifiers: &HashSet<String>) -> bool {
    modifiers.iter().any(|modifier| {
        modifier.contains("onlyowner")
            || modifier.contains("onlyadmin")
            || modifier.contains("onlyrole")
            || modifier.contains("governance")
            || modifier.contains("timelock")
            || modifier.contains("auth")
            || modifier.contains("initializer")
            || modifier.contains("owner")
    })
}

fn has_initializer_modifier(modifiers: &HashSet<String>) -> bool {
    modifiers.iter().any(|modifier| {
        modifier.contains("initializer")
            || modifier.contains("onlyinitializing")
            || modifier.contains("reinitializer")
    })
}

fn has_non_reentrant_modifier(modifiers: &HashSet<String>) -> bool {
    modifiers.iter().any(|modifier| {
        modifier.contains("nonreentrant") || modifier.contains("lock") || modifier.contains("mutex")
    })
}

fn extract_modifier_name(modifier: &Value) -> Option<String> {
    modifier
        .get("modifierName")
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn find_tx_origin(node: &Value) -> Option<&Value> {
    let mut found = None;
    visit_ast(node, &mut |candidate| {
        if found.is_some() {
            return;
        }
        let Some(member_name) = candidate.get("memberName").and_then(Value::as_str) else {
            return;
        };
        if member_name != "origin" {
            return;
        }
        let expression = candidate.get("expression");
        let is_tx = expression
            .and_then(|value| value.get("nodeType"))
            .and_then(Value::as_str)
            == Some("Identifier")
            && expression
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                == Some("tx");
        if is_tx {
            found = Some(candidate);
        }
    });
    found
}

fn find_block_member<'a>(node: &'a Value, member: &str) -> Option<&'a Value> {
    let mut found = None;
    visit_ast(node, &mut |candidate| {
        if found.is_some() {
            return;
        }
        let Some(member_name) = candidate.get("memberName").and_then(Value::as_str) else {
            return;
        };
        if member_name != member {
            return;
        }
        let expression = candidate.get("expression");
        let is_block = expression
            .and_then(|value| value.get("nodeType"))
            .and_then(Value::as_str)
            == Some("Identifier")
            && expression
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                == Some("block");
        if is_block {
            found = Some(candidate);
        }
    });
    found
}

fn find_selfdestruct(node: &Value) -> Option<&Value> {
    let mut found = None;
    visit_ast(node, &mut |candidate| {
        if found.is_some() {
            return;
        }
        if candidate.get("nodeType").and_then(Value::as_str) != Some("FunctionCall") {
            return;
        }
        let expression = candidate.get("expression");
        let is_selfdestruct = expression
            .and_then(|value| value.get("name"))
            .and_then(Value::as_str)
            == Some("selfdestruct")
            || expression
                .and_then(|value| value.get("memberName"))
                .and_then(Value::as_str)
                == Some("selfdestruct");
        if is_selfdestruct {
            found = Some(candidate);
        }
    });
    found
}

fn find_user_controlled_delegatecall<'a>(
    node: &'a Value,
    param_names: &HashSet<String>,
) -> Option<&'a Value> {
    let mut found = None;
    visit_ast(node, &mut |candidate| {
        if found.is_some() {
            return;
        }
        if candidate.get("nodeType").and_then(Value::as_str) != Some("FunctionCall") {
            return;
        }
        let Some(expression) = candidate.get("expression") else {
            return;
        };
        if expression.get("memberName").and_then(Value::as_str) != Some("delegatecall") {
            return;
        }
        let Some(target) = expression.get("expression") else {
            return;
        };
        let controlled = target
            .get("name")
            .and_then(Value::as_str)
            .map(|name| param_names.contains(name))
            .unwrap_or(false)
            || target
                .get("expression")
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                .map(|name| param_names.contains(name))
                .unwrap_or(false);
        if controlled {
            found = Some(candidate);
        }
    });
    found
}

fn find_unchecked_low_level_call(node: &Value) -> Option<&Value> {
    let mut found = None;
    visit_ast(node, &mut |candidate| {
        if found.is_some() {
            return;
        }
        if candidate.get("nodeType").and_then(Value::as_str) != Some("ExpressionStatement") {
            return;
        }
        let Some(expression) = candidate.get("expression") else {
            return;
        };
        if expression.get("nodeType").and_then(Value::as_str) != Some("FunctionCall") {
            return;
        }
        if expression
            .get("expression")
            .and_then(|value| value.get("memberName"))
            .and_then(Value::as_str)
            .is_some_and(is_unchecked_low_level_member)
        {
            found = Some(candidate);
        }
    });
    found
}

fn find_unchecked_arithmetic(node: &Value) -> Option<&Value> {
    let unchecked_blocks = collect_nodes_by_type(node, "UncheckedBlock");
    unchecked_blocks.into_iter().find(|block| {
        collect_nodes_by_type(block, "BinaryOperation")
            .iter()
            .any(|operation| {
                operation
                    .get("operator")
                    .and_then(Value::as_str)
                    .is_some_and(is_arithmetic_operator)
            })
            || collect_nodes_by_type(block, "Assignment")
                .iter()
                .any(|assignment| {
                    assignment
                        .get("operator")
                        .and_then(Value::as_str)
                        .is_some_and(|operator| matches!(operator, "+=" | "-=" | "*=" | "/="))
                })
            || collect_nodes_by_type(block, "UnaryOperation")
                .iter()
                .any(|operation| {
                    operation
                        .get("operator")
                        .and_then(Value::as_str)
                        .is_some_and(|operator| matches!(operator, "++" | "--"))
                })
    })
}

fn find_reentrancy_window<'a>(
    node: &'a Value,
    state_variables: &HashSet<String>,
) -> Option<&'a Value> {
    let mut low_level_calls = collect_nodes_by_type(node, "FunctionCall")
        .into_iter()
        .filter(|candidate| {
            candidate
                .get("expression")
                .and_then(|value| value.get("memberName"))
                .and_then(Value::as_str)
                .is_some_and(is_low_level_external_call)
        })
        .collect::<Vec<_>>();
    low_level_calls
        .sort_by_key(|candidate| src_start(candidate.get("src").and_then(Value::as_str)));

    let mut state_writes = collect_nodes_by_type(node, "Assignment")
        .into_iter()
        .filter(|assignment| assignment_touches_state(assignment, state_variables))
        .collect::<Vec<_>>();
    state_writes.sort_by_key(|candidate| src_start(candidate.get("src").and_then(Value::as_str)));

    for call in low_level_calls {
        let call_start = src_start(call.get("src").and_then(Value::as_str));
        if state_writes
            .iter()
            .any(|write| src_start(write.get("src").and_then(Value::as_str)) > call_start)
        {
            return Some(call);
        }
    }

    None
}

fn has_access_control_check(node: &Value) -> bool {
    let has_guard_call = collect_nodes_by_type(node, "FunctionCall")
        .iter()
        .any(|call| {
            let expression = call.get("expression");
            expression
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                .is_some_and(|name| {
                    let lower = name.to_ascii_lowercase();
                    lower.contains("role")
                        || lower.contains("owner")
                        || lower.contains("auth")
                        || lower.contains("guardian")
                })
                || expression
                    .and_then(|value| value.get("memberName"))
                    .and_then(Value::as_str)
                    .is_some_and(|name| {
                        let lower = name.to_ascii_lowercase();
                        lower.contains("role")
                            || lower.contains("owner")
                            || lower.contains("auth")
                            || lower.contains("guardian")
                    })
        });

    has_guard_call || find_msg_sender(node).is_some()
}

fn has_oracle_delay_guard(node: &Value) -> bool {
    let mentions_timing = find_block_member(node, "timestamp").is_some()
        || find_block_member(node, "number").is_some()
        || references_identifier(node, "updatedAt")
        || references_identifier(node, "lastUpdate")
        || references_identifier(node, "lastUpdated")
        || references_identifier(node, "gracePeriod")
        || references_identifier(node, "delay")
        || references_identifier(node, "window");

    let has_guard_call = collect_nodes_by_type(node, "FunctionCall")
        .iter()
        .any(|call| {
            let expression = call.get("expression");
            expression
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                .is_some_and(|name| matches!(name, "require" | "assert"))
        });

    mentions_timing && has_guard_call
}

fn collect_state_variable_names(root: &Value) -> HashSet<String> {
    collect_nodes_by_type(root, "VariableDeclaration")
        .into_iter()
        .filter(|declaration| {
            declaration
                .get("stateVariable")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .filter_map(|declaration| declaration.get("name").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
}

fn assignment_touches_state(node: &Value, state_variables: &HashSet<String>) -> bool {
    node.get("leftHandSide")
        .is_some_and(|lhs| expression_touches_state(lhs, state_variables))
}

fn expression_touches_state(node: &Value, state_variables: &HashSet<String>) -> bool {
    node.get("name")
        .and_then(Value::as_str)
        .is_some_and(|name| state_variables.contains(name))
        || node
            .get("expression")
            .is_some_and(|value| expression_touches_state(value, state_variables))
        || node
            .get("baseExpression")
            .is_some_and(|value| expression_touches_state(value, state_variables))
}

fn find_msg_sender(node: &Value) -> Option<&Value> {
    let mut found = None;
    visit_ast(node, &mut |candidate| {
        if found.is_some() {
            return;
        }
        let Some(member_name) = candidate.get("memberName").and_then(Value::as_str) else {
            return;
        };
        if member_name != "sender" {
            return;
        }
        let expression = candidate.get("expression");
        let is_msg = expression
            .and_then(|value| value.get("nodeType"))
            .and_then(Value::as_str)
            == Some("Identifier")
            && expression
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                == Some("msg");
        if is_msg {
            found = Some(candidate);
        }
    });
    found
}

fn references_identifier(node: &Value, name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    let mut found = false;
    visit_ast(node, &mut |candidate| {
        if found {
            return;
        }
        let matches_name = candidate
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case(&normalized))
            || candidate
                .get("memberName")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case(&normalized));
        if matches_name {
            found = true;
        }
    });
    found
}

fn collect_call_names(node: &Value) -> HashSet<String> {
    collect_nodes_by_type(node, "FunctionCall")
        .into_iter()
        .filter_map(|call| {
            call.get("expression")
                .and_then(|expression| {
                    expression
                        .get("name")
                        .and_then(Value::as_str)
                        .or_else(|| expression.get("memberName").and_then(Value::as_str))
                })
                .map(|name| name.to_ascii_lowercase())
        })
        .collect()
}

fn is_unchecked_low_level_member(member_name: &str) -> bool {
    matches!(
        member_name,
        "call" | "delegatecall" | "staticcall" | "callcode" | "send"
    )
}

fn is_low_level_external_call(member_name: &str) -> bool {
    matches!(
        member_name,
        "call" | "delegatecall" | "staticcall" | "callcode" | "send" | "transfer"
    )
}

fn is_arithmetic_operator(operator: &str) -> bool {
    matches!(operator, "+" | "-" | "*" | "/" | "%" | "**")
}

fn src_start(src: Option<&str>) -> usize {
    src.and_then(|src| src.split(':').next())
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(usize::MAX)
}

fn suspicious_price_update_function(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("setprice")
        || name.contains("updateprice")
        || name.contains("postprice")
        || name.contains("pushprice")
        || name.contains("submitprice")
        || name.contains("setoracle")
        || name.contains("updateoracle")
        || name.contains("setfeed")
}

fn source_location(source: &str, src: &str) -> Option<(usize, usize)> {
    let mut parts = src.split(':');
    let start = parts.next()?.parse::<usize>().ok()?;
    if start > source.len() {
        return None;
    }
    let prefix = &source[..start];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit('\n')
        .next()
        .map(|segment| segment.chars().count() + 1)
        .unwrap_or(1);
    Some((line, column))
}

#[cfg(test)]
mod tests {
    use super::{
        critical_state_transition_function, normalize_solc_version, source_location,
        suspicious_initializer_function, suspicious_upgrade_function,
    };

    #[test]
    fn normalizes_solc_versions() {
        assert_eq!(
            normalize_solc_version("v0.8.20+commit.a1b79de6"),
            "0.8.20+commit.a1b79de6"
        );
    }

    #[test]
    fn computes_source_locations() {
        let source = "line1\nline2\nupgradeTo(address impl)";
        assert_eq!(source_location(source, "12:9:0"), Some((3, 1)));
    }

    #[test]
    fn flags_upgrade_names() {
        assert!(suspicious_upgrade_function("upgradeToAndCall"));
        assert!(!suspicious_upgrade_function("deposit"));
    }

    #[test]
    fn flags_initializer_names() {
        assert!(suspicious_initializer_function("initialize"));
        assert!(suspicious_initializer_function("initializeV2"));
        assert!(!suspicious_initializer_function("deposit"));
    }

    #[test]
    fn flags_critical_control_surfaces() {
        assert!(critical_state_transition_function("setOracle"));
        assert!(critical_state_transition_function("pause"));
        assert!(!critical_state_transition_function("withdraw"));
    }
}
