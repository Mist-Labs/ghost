use super::{ABIPattern, AttackVector, HackReport, Severity, VulnerabilitySignature};
use anyhow::{anyhow, Result};
use reqwest::Client;
use uuid::Uuid;

pub async fn extract_signature(
    client: &Client,
    api_key: &str,
    model: &str,
    report_id: Uuid,
    report: &HackReport,
) -> Result<VulnerabilitySignature> {
    let schema = serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "attack_vector",
            "protocol_types",
            "bytecode_patterns",
            "abi_patterns",
            "severity",
            "description",
            "remediation"
        ],
        "properties": {
            "attack_vector": {
                "type": "string",
                "enum": [
                    "reentrancy",
                    "flash_loan_manipulation",
                    "oracle_manipulation",
                    "access_control",
                    "logic_error",
                    "bridge_exploit",
                    "governance_attack",
                    "price_manipulation",
                    "signature_validation",
                    "unknown"
                ]
            },
            "protocol_types": {
                "type": "array",
                "items": { "type": "string" }
            },
            "bytecode_patterns": {
                "type": "array",
                "items": { "type": "string" }
            },
            "abi_patterns": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["requires_functions", "dangerous_sequence", "missing_modifier"],
                    "properties": {
                        "requires_functions": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "dangerous_sequence": {
                            "type": "array",
                            "items": { "type": "string" }
                        },
                        "missing_modifier": {
                            "anyOf": [
                                { "type": "string" },
                                { "type": "null" }
                            ]
                        }
                    }
                }
            },
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low"]
            },
            "description": { "type": "string" },
            "remediation": { "type": "string" }
        }
    });

    let response = client
        .post("https://api.openai.com/v1/responses")
        .bearer_auth(api_key)
        .json(&serde_json::json!({
            "model": model,
            "input": [
                {
                    "role": "system",
                    "content": "You are a DeFi security researcher. Extract a reusable, conservative vulnerability signature from a confirmed public incident report. Return only structured JSON."
                },
                {
                    "role": "user",
                    "content": format!(
                        "Analyze this public DeFi exploit report and derive a structured signature for proactive scanning on Base. Be conservative: only include bytecode or ABI patterns that would generalize to the same vulnerability class.\n\n{}",
                        serde_json::to_string(report)?
                    )
                }
            ],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "vulnerability_signature",
                    "schema": schema,
                    "strict": true
                }
            }
        }))
        .send()
        .await?
        .error_for_status()?
        .json::<OpenAiResponse>()
        .await?;

    let payload = response
        .extract_text()
        .ok_or_else(|| anyhow!("OpenAI response did not contain structured text output"))?;
    let parsed: OpenAiSignature = serde_json::from_str(&payload)?;

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
struct OpenAiSignature {
    attack_vector: String,
    protocol_types: Vec<String>,
    bytecode_patterns: Vec<String>,
    abi_patterns: Vec<OpenAiAbiPattern>,
    severity: String,
    description: String,
    remediation: String,
}

#[derive(Debug, serde::Deserialize)]
struct OpenAiAbiPattern {
    requires_functions: Vec<String>,
    dangerous_sequence: Vec<String>,
    missing_modifier: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct OpenAiResponse {
    #[serde(default)]
    output_text: Option<String>,
    #[serde(default)]
    output: Vec<OpenAiOutputMessage>,
}

impl OpenAiResponse {
    fn extract_text(&self) -> Option<String> {
        if let Some(value) = &self.output_text {
            return Some(value.clone());
        }

        self.output.iter().find_map(|message| {
            message.content.iter().find_map(|content| {
                if content.kind == "output_text" {
                    content.text.clone()
                } else {
                    None
                }
            })
        })
    }
}

#[derive(Debug, serde::Deserialize)]
struct OpenAiOutputMessage {
    #[serde(default)]
    content: Vec<OpenAiOutputContent>,
}

#[derive(Debug, serde::Deserialize)]
struct OpenAiOutputContent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: Option<String>,
}
