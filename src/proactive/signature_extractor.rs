use super::{ABIPattern, AttackVector, HackReport, Severity, VulnerabilitySignature};
use anyhow::{anyhow, Result};
use reqwest::Client;
use uuid::Uuid;

pub async fn extract_signature(
    client: &Client,
    api_key: &str,
    model: &str,
    base_url: &str,
    report_id: Uuid,
    report: &HackReport,
) -> Result<VulnerabilitySignature> {
    let endpoint = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    let output_contract = serde_json::json!({
        "attack_vector": "one of: reentrancy, flash_loan_manipulation, oracle_manipulation, access_control, logic_error, bridge_exploit, governance_attack, price_manipulation, signature_validation, unknown",
        "protocol_types": ["array of protocol labels like lending, amm, vault, bridge"],
        "bytecode_patterns": ["array of lowercase hex substrings without 0x; use an empty array if none are justified"],
        "abi_patterns": [
            {
                "requires_functions": ["array of function names that should exist"],
                "dangerous_sequence": ["array of ordered function names if a call order matters"],
                "missing_modifier": "string or null"
            }
        ],
        "severity": "one of: critical, high, medium, low",
        "description": "concise conservative description",
        "remediation": "concise remediation guidance"
    });
    let response = client
        .post(endpoint)
        .bearer_auth(api_key)
        .json(&serde_json::json!({
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": format!(
                        "You are a DeFi security researcher. Extract a reusable, conservative vulnerability signature from a confirmed public incident report. Return only a valid JSON object with exactly these fields and types: {}",
                        serde_json::to_string(&output_contract)?
                    )
                },
                {
                    "role": "user",
                    "content": format!(
                        "Analyze this public DeFi exploit report and derive a structured signature for proactive scanning on Base. Be conservative: only include bytecode or ABI patterns that would generalize to the same vulnerability class. Use empty arrays instead of inventing patterns. Do not add extra keys.\n\n{}",
                        serde_json::to_string(report)?
                    )
                }
            ],
            "response_format": {
                "type": "json_object"
            }
        }))
        .send()
        .await?
        .error_for_status()?
        .json::<KimiChatCompletionResponse>()
        .await?;

    let payload = response
        .extract_text()
        .ok_or_else(|| anyhow!("Kimi response did not contain JSON output text"))?;
    let parsed: KimiSignature = serde_json::from_str(payload.trim())?;

    Ok(VulnerabilitySignature {
        id: Uuid::new_v4(),
        derived_from_hack_id: report_id,
        attack_vector: AttackVector::from_storage_value(&parsed.attack_vector),
        protocol_types: parsed.protocol_types,
        bytecode_patterns: parsed
            .bytecode_patterns
            .into_iter()
            .map(|pattern| pattern.trim().trim_start_matches("0x").to_ascii_lowercase())
            .filter(|pattern| !pattern.is_empty())
            .collect(),
        abi_patterns: parsed
            .abi_patterns
            .into_iter()
            .map(|pattern| ABIPattern {
                requires_functions: pattern.requires_functions,
                dangerous_sequence: pattern.dangerous_sequence,
                missing_modifier: pattern.missing_modifier,
            })
            .collect(),
        severity: Severity::from_storage_value(&parsed.severity),
        description: parsed.description,
        remediation: parsed.remediation,
    })
}

#[derive(Debug, serde::Deserialize)]
struct KimiSignature {
    attack_vector: String,
    protocol_types: Vec<String>,
    #[serde(default)]
    bytecode_patterns: Vec<String>,
    #[serde(default)]
    abi_patterns: Vec<KimiAbiPattern>,
    severity: String,
    description: String,
    remediation: String,
}

#[derive(Debug, serde::Deserialize)]
struct KimiAbiPattern {
    #[serde(default)]
    requires_functions: Vec<String>,
    #[serde(default)]
    dangerous_sequence: Vec<String>,
    missing_modifier: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct KimiChatCompletionResponse {
    choices: Vec<KimiChoice>,
}

impl KimiChatCompletionResponse {
    fn extract_text(&self) -> Option<String> {
        self.choices.iter().find_map(|choice| {
            choice
                .message
                .content
                .clone()
                .or_else(|| choice.message.text.clone())
        })
    }
}

#[derive(Debug, serde::Deserialize)]
struct KimiChoice {
    message: KimiMessage,
}

#[derive(Debug, serde::Deserialize)]
struct KimiMessage {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    content: Option<String>,
}
