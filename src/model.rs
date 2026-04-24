use crate::proactive::{AttackVector, VulnerabilitySignature};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewIncident {
    pub tx_hash: String,
    pub chain_name: String,
    pub status: String,
    pub confidence: String,
    pub score: i32,
    pub protocol_id: Option<String>,
    pub protocol_name: Option<String>,
    pub attacker_address: String,
    pub protocol_address: Option<String>,
    pub first_seen_at: DateTime<Utc>,
    pub detected_at: DateTime<Utc>,
    pub last_updated_at: DateTime<Utc>,
    pub signals: serde_json::Value,
    pub corpus_provenance: serde_json::Value,
    pub raw_transaction: serde_json::Value,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::incidents)]
pub struct Incident {
    pub id: Uuid,
    pub tx_hash: String,
    pub chain_name: String,
    pub status: String,
    pub confidence: String,
    pub score: i32,
    pub protocol_id: Option<String>,
    pub protocol_name: Option<String>,
    pub attacker_address: String,
    pub protocol_address: Option<String>,
    pub first_seen_at: DateTime<Utc>,
    pub detected_at: DateTime<Utc>,
    pub last_updated_at: DateTime<Utc>,
    pub signals: serde_json::Value,
    pub corpus_provenance: serde_json::Value,
    pub raw_transaction: serde_json::Value,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewArtifact {
    pub incident_id: Uuid,
    pub kind: String,
    pub storage_backend: String,
    pub locator: String,
    pub checksum_sha256: String,
    pub content_type: String,
    pub size_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::incident_artifacts)]
pub struct IncidentArtifact {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub kind: String,
    pub storage_backend: String,
    pub locator: String,
    pub checksum_sha256: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewHackIntelReport {
    pub source: String,
    pub external_id: String,
    pub protocol: String,
    pub published_at: DateTime<Utc>,
    pub loss_usd: Option<f64>,
    pub attack_vector: AttackVector,
    pub root_cause: String,
    pub chain_name: String,
    pub title: String,
    pub summary: String,
    pub source_url: String,
    pub raw_payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::hack_intel_reports)]
pub struct StoredHackIntelReport {
    pub id: Uuid,
    pub source: String,
    pub external_id: String,
    pub protocol: String,
    pub published_at: DateTime<Utc>,
    pub loss_usd: Option<f64>,
    pub attack_vector: String,
    pub root_cause: String,
    pub chain_name: String,
    pub title: String,
    pub summary: String,
    pub source_url: String,
    pub raw_payload: serde_json::Value,
    pub ingested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewStoredSignature {
    pub derived_from_report_id: Uuid,
    pub model: String,
    pub signature: VulnerabilitySignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::vulnerability_signatures)]
pub struct StoredSignature {
    pub id: Uuid,
    pub derived_from_report_id: Uuid,
    pub model: String,
    pub attack_vector: String,
    pub severity: String,
    pub protocol_types: serde_json::Value,
    pub bytecode_patterns: serde_json::Value,
    pub abi_patterns: serde_json::Value,
    pub description: String,
    pub remediation: String,
    pub raw_signature: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::protocol_scan_runs)]
pub struct StoredScanRun {
    pub id: Uuid,
    pub protocol_id: String,
    pub protocol_name: String,
    pub chain_name: String,
    pub scan_mode: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub signatures_checked: i32,
    pub findings_count: i32,
    pub clean: bool,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::protocol_findings)]
pub struct StoredFinding {
    pub id: Uuid,
    pub scan_run_id: Uuid,
    pub protocol_id: String,
    pub contract_address: String,
    pub signature_id: Option<Uuid>,
    pub finding_type: String,
    pub title: String,
    pub confidence: f64,
    pub severity: String,
    pub matched_pattern: String,
    pub affected_functions: serde_json::Value,
    pub simulation_confirmed: bool,
    pub simulation_mode: String,
    pub details: serde_json::Value,
    pub remediation: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::disclosure_events)]
pub struct StoredDisclosure {
    pub id: Uuid,
    pub finding_id: Uuid,
    pub protocol_id: String,
    pub state: String,
    pub contact_emails: serde_json::Value,
    pub due_at: DateTime<Utc>,
    pub first_response_due_at: Option<DateTime<Utc>>,
    pub last_notified_at: Option<DateTime<Utc>>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
    pub escalated_at: Option<DateTime<Utc>>,
    pub escalation_level: i32,
    pub evidence_backend: Option<String>,
    pub evidence_locator: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::monitor_snapshots)]
pub struct StoredMonitorSnapshot {
    pub id: Uuid,
    pub protocol_id: String,
    pub monitor_kind: String,
    pub scope_key: String,
    pub payload: serde_json::Value,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewProtocolBillingAccount {
    pub protocol_id: String,
    pub protocol_name: String,
    pub tier: String,
    pub monthly_fee_usd: i32,
    pub billing_email: String,
    pub alert_webhook: Option<String>,
    pub active: bool,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::protocol_billing_accounts)]
pub struct StoredProtocolBillingAccount {
    pub id: Uuid,
    pub protocol_id: String,
    pub protocol_name: String,
    pub tier: String,
    pub monthly_fee_usd: i32,
    pub billing_email: String,
    pub alert_webhook: Option<String>,
    pub active: bool,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewRecoveryCase {
    pub incident_id: Uuid,
    pub protocol_id: String,
    pub total_stolen_usd: i64,
    pub recovery_method: String,
    pub bounty_contract_address: Option<String>,
    pub billing_email: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::recovery_cases)]
pub struct StoredRecoveryCase {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub protocol_id: String,
    pub total_stolen_usd: i64,
    pub total_recovered_usd: i64,
    pub recovery_method: String,
    pub fee_invoiced: bool,
    pub invoiced_fee_usd: i64,
    pub bounty_contract_address: Option<String>,
    pub billing_email: String,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewBillingInvoice {
    pub protocol_id: String,
    pub incident_id: Option<Uuid>,
    pub recovery_case_id: Option<Uuid>,
    pub invoice_kind: String,
    pub amount_usd: i32,
    pub currency: String,
    pub status: String,
    pub external_invoice_id: Option<String>,
    pub recipient_email: String,
    pub description: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::billing_invoices)]
pub struct StoredBillingInvoice {
    pub id: Uuid,
    pub protocol_id: String,
    pub incident_id: Option<Uuid>,
    pub recovery_case_id: Option<Uuid>,
    pub invoice_kind: String,
    pub amount_usd: i32,
    pub currency: String,
    pub status: String,
    pub external_invoice_id: Option<String>,
    pub recipient_email: String,
    pub description: String,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewIntelReport {
    pub incident_id: Uuid,
    pub published_at: DateTime<Utc>,
    pub protocol_id: Option<String>,
    pub protocol_name: String,
    pub attack_vector: String,
    pub total_loss_usd: i64,
    pub recovered_usd: i64,
    pub attacker_skill_tier: String,
    pub used_private_mempool: bool,
    pub funded_via_mixer: bool,
    pub cex_deposit_detected: bool,
    pub chains_involved: Vec<String>,
    pub time_to_detection_secs: i32,
    pub time_to_mixer_secs: Option<i32>,
    pub bounty_outcome: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::intel_reports)]
pub struct StoredIntelReport {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub published_at: DateTime<Utc>,
    pub protocol_id: Option<String>,
    pub protocol_name: String,
    pub attack_vector: String,
    pub total_loss_usd: i64,
    pub recovered_usd: i64,
    pub attacker_skill_tier: String,
    pub used_private_mempool: bool,
    pub funded_via_mixer: bool,
    pub cex_deposit_detected: bool,
    pub chains_involved: serde_json::Value,
    pub time_to_detection_secs: i32,
    pub time_to_mixer_secs: Option<i32>,
    pub bounty_outcome: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewIntelSubscriber {
    pub email: String,
    pub api_key_hash: String,
    pub tier: String,
    pub monthly_fee_usd: i32,
    pub active: bool,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::intel_subscribers)]
pub struct StoredIntelSubscriber {
    pub id: Uuid,
    pub email: String,
    pub api_key_hash: String,
    pub tier: String,
    pub monthly_fee_usd: i32,
    pub active: bool,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewVerificationJob {
    pub incident_id: Uuid,
    pub provider: String,
    pub external_job_id: String,
    pub gateway_url: String,
    pub model_id: String,
    pub input_features: serde_json::Value,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::verification_jobs)]
pub struct StoredVerificationJob {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub provider: String,
    pub external_job_id: String,
    pub gateway_url: String,
    pub model_id: String,
    pub input_features: serde_json::Value,
    pub status: String,
    pub proof_hash: Option<String>,
    pub vkey: Option<String>,
    pub output_score: Option<f64>,
    pub error_message: Option<String>,
    pub submitted_at: DateTime<Utc>,
    pub settled_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSecurityReport {
    pub protocol_id: String,
    pub protocol_name: String,
    pub report_type: String,
    pub vulnerabilities: serde_json::Value,
    pub report_body: String,
    pub email_recipient: Option<String>,
    pub email_sent: bool,
    pub email_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::security_reports)]
pub struct StoredSecurityReport {
    pub id: Uuid,
    pub protocol_id: String,
    pub protocol_name: String,
    pub report_type: String,
    pub vulnerability_count: i32,
    pub vulnerabilities: serde_json::Value,
    pub report_body: String,
    pub email_recipient: Option<String>,
    pub email_sent: bool,
    pub email_error: Option<String>,
    pub generated_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewFilingSubmission {
    pub incident_id: Uuid,
    pub artifact_kind: String,
    pub filing_target: String,
    pub destination: String,
    pub status: String,
    pub request_payload: serde_json::Value,
    pub response_status_code: Option<i32>,
    pub response_body: Option<String>,
    pub error_message: Option<String>,
    pub submitted_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::filing_submissions)]
pub struct StoredFilingSubmission {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub artifact_kind: String,
    pub filing_target: String,
    pub destination: String,
    pub status: String,
    pub request_payload: serde_json::Value,
    pub response_status_code: Option<i32>,
    pub response_body: Option<String>,
    pub error_message: Option<String>,
    pub submitted_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}
