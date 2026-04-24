use crate::legal::package_generator::{EvidenceArtifact, ExploitReport, VerificationEvidence};
use crate::model::Incident;
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct LegalExportBundle {
    pub manifest: serde_json::Value,
    pub ic3_complaint_draft: serde_json::Value,
    pub ec3_coordination_referral_draft: serde_json::Value,
}

pub fn generate_legal_exports(
    incident: &Incident,
    report: &ExploitReport,
    evidence_artifacts: &[EvidenceArtifact],
    verifications: &[VerificationEvidence],
) -> Result<LegalExportBundle> {
    let generated_at = Utc::now().to_rfc3339();
    let suspected_services = serde_json::json!({
        "bridges": &report.bridge_transfers,
        "cex_deposits": &report.cex_deposits,
        "mixers": &report.mixer_entries,
    });

    let manifest = serde_json::json!({
        "schema": "ghost_legal_export_manifest_v1",
        "generated_at": &generated_at,
        "incident": {
            "id": incident.id,
            "tx_hash": &report.tx_hash,
            "chain_name": &incident.chain_name,
            "protocol_id": &incident.protocol_id,
            "protocol_name": &incident.protocol_name,
            "confidence": &incident.confidence,
            "status": &incident.status,
            "summary": &incident.summary,
            "detected_at": incident.detected_at.to_rfc3339(),
        },
        "loss_summary": {
            "total_drained_wei": report.total_drained.to_string(),
            "jurisdiction": &report.jurisdiction,
        },
        "corpus_provenance": &report.corpus_provenance,
        "artifacts": evidence_artifacts,
        "verification_jobs": verifications,
        "export_targets": [
            "ic3",
            "national_cybercrime_authority",
            "ec3_coordination_if_appropriate"
        ],
    });

    let ic3_complaint_draft = serde_json::json!({
        "schema": "ghost_ic3_complaint_draft_v1",
        "generated_at": &generated_at,
        "complaint_type": "cryptocurrency_theft_smart_contract_exploit",
        "victim_protocol": {
            "protocol_id": &incident.protocol_id,
            "protocol_name": &incident.protocol_name,
            "chain_name": &incident.chain_name,
        },
        "incident": {
            "id": incident.id,
            "summary": &incident.summary,
            "primary_transaction_hash": &report.tx_hash,
            "suspected_wallet_graph": &report.wallet_tree,
            "attacker_profile": &report.attacker_profile,
            "geo_result": &report.geo_result,
        },
        "loss_summary": {
            "estimated_loss_wei": report.total_drained.to_string(),
            "currency": "wei",
        },
        "suspected_services": &suspected_services,
        "evidence_appendix": evidence_artifacts,
        "verification_jobs": verifications,
    });

    let ec3_coordination_referral_draft = serde_json::json!({
        "schema": "ghost_ec3_coordination_referral_draft_v1",
        "generated_at": &generated_at,
        "referral_type": "national_cybercrime_filing_with_optional_ec3_coordination",
        "routing_guidance": {
            "primary_destination": "relevant_national_cybercrime_authority",
            "ec3_coordination_recommended_if": "cross_border_or_multi_member_state_links_are_present",
            "direct_public_submission_to_europol": false,
        },
        "case_overview": {
            "incident_id": incident.id,
            "transaction_hash": &report.tx_hash,
            "jurisdiction_signal": &report.jurisdiction,
            "chain_name": &incident.chain_name,
            "attacker_profile": &report.attacker_profile,
            "suspected_wallet_graph": &report.wallet_tree,
            "cross_border_indicators": &suspected_services,
        },
        "operator_routing_fields": {
            "member_state_destination": serde_json::Value::Null,
            "liaison_contact": serde_json::Value::Null,
            "ec3_coordination_requested": false,
        },
        "supporting_material": {
            "corpus_provenance": &report.corpus_provenance,
            "evidence_appendix": evidence_artifacts,
            "verification_jobs": verifications,
        },
    });

    Ok(LegalExportBundle {
        manifest,
        ic3_complaint_draft,
        ec3_coordination_referral_draft,
    })
}

#[cfg(test)]
mod tests {
    use super::generate_legal_exports;
    use crate::legal::package_generator::{EvidenceArtifact, ExploitReport, VerificationEvidence};
    use crate::model::Incident;
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn generates_expected_export_documents() {
        let incident = Incident {
            id: Uuid::new_v4(),
            tx_hash: "0xabc".into(),
            chain_name: "base".into(),
            status: "triaged".into(),
            confidence: "high".into(),
            score: 9,
            protocol_id: Some("proto".into()),
            protocol_name: Some("Proto".into()),
            attacker_address: "0xattacker".into(),
            protocol_address: Some("0xprotocol".into()),
            first_seen_at: Utc::now(),
            detected_at: Utc::now(),
            last_updated_at: Utc::now(),
            signals: json!({}),
            corpus_provenance: json!({"cex": {"checksum": "123"}}),
            raw_transaction: json!({}),
            summary: Some("example exploit".into()),
        };
        let report = ExploitReport {
            tx_hash: "0xabc".into(),
            total_drained: 123,
            attacker_profile: json!({"risk": "high"}),
            wallet_tree: vec![json!({"wallet": "0xattacker"})],
            corpus_provenance: json!({"cex": {"checksum": "123"}}),
            bridge_transfers: vec![],
            cex_deposits: vec![],
            mixer_entries: vec![],
            geo_result: Some(json!({"country": "US"})),
            jurisdiction: "base".into(),
            evidence_hashes: vec![EvidenceArtifact {
                kind: "legal_package".into(),
                storage_backend: "filesystem".into(),
                locator: "/tmp/legal.pdf".into(),
                checksum_sha256: "deadbeef".into(),
                content_type: "application/pdf".into(),
                created_at: Utc::now().to_rfc3339(),
            }],
            verifications: vec![VerificationEvidence {
                provider: "mugen".into(),
                external_job_id: "job-1".into(),
                status: "submitted".into(),
                proof_hash: None,
                vkey: None,
                output_score: Some(0.98),
                settled_at: None,
            }],
        };

        let bundle = generate_legal_exports(
            &incident,
            &report,
            &report.evidence_hashes,
            &report.verifications,
        )
        .expect("exports should build");

        assert_eq!(
            bundle.manifest["incident"]["tx_hash"],
            serde_json::Value::String("0xabc".into())
        );
        assert_eq!(
            bundle.ic3_complaint_draft["complaint_type"],
            serde_json::Value::String("cryptocurrency_theft_smart_contract_exploit".into())
        );
        assert_eq!(
            bundle.ec3_coordination_referral_draft["referral_type"],
            serde_json::Value::String(
                "national_cybercrime_filing_with_optional_ec3_coordination".into()
            )
        );
    }
}
