use crate::db::{
    insert_artifact, list_incident_artifacts, list_verification_jobs_for_incident, upsert_incident,
};
use crate::detection::*;
use crate::intelligence::fingerprint::build_fingerprint;
use crate::intelligence::geolocate::geolocate_attack_tx;
use crate::legal::export_bundle::generate_legal_exports;
use crate::legal::filing_dispatch::dispatch_legal_exports;
use crate::legal::package_generator::{
    generate_legal_package, EvidenceArtifact, ExploitReport, VerificationEvidence,
};
use crate::model::{Incident, NewArtifact, NewIncident};
use crate::state::AppState;
use crate::tracking::fund_tracker::{IncidentCorpusSnapshot, TrackingContext};
use crate::verification::mugen::submit_verification;
use anyhow::Result;
use chrono::Utc;
use ethers::types::Transaction;
use std::sync::Arc;

pub async fn on_suspicious_transaction(tx: Transaction, state: Arc<AppState>) -> Result<()> {
    let score_result = score_transaction(&tx, &state.provider, &state.protocols).await?;
    if score_result.protocol.is_none() || score_result.is_sanctioned_exit {
        return Ok(());
    }
    if score_result.score < state.config.min_alert_score {
        return Ok(());
    }

    let intent = check_abi_intent(&tx, score_result.protocol.clone()).await?;
    let (drain, economic) = if tx.block_number.is_some() {
        tokio::join!(
            confirm_drain::confirm_drain(&tx, &state.provider, &state.config),
            economic_check::check_economic_invariant(
                &tx,
                &state.provider,
                &state.config,
                score_result.protocol.as_deref(),
            ),
        )
    } else {
        (
            Ok(confirm_drain::DrainResult {
                confirmed: false,
                pct_drained: 0.0,
                absolute_loss: 0,
                reason: Some("transaction not yet mined".to_string()),
            }),
            Ok(economic_check::EconomicCheckResult {
                checked: false,
                invariant_violated: false,
                overshoot_pct: 0.0,
            }),
        )
    };
    let drain = drain.unwrap_or(confirm_drain::DrainResult {
        confirmed: false,
        pct_drained: 0.0,
        absolute_loss: 0,
        reason: Some("drain confirmation unavailable".to_string()),
    });
    let economic = economic.unwrap_or(economic_check::EconomicCheckResult {
        checked: false,
        invariant_violated: false,
        overshoot_pct: 0.0,
    });
    let tier = resolve_confidence_tier(score_result.score, &drain, &intent, &economic);

    if matches!(tier, ConfidenceTier::None | ConfidenceTier::Low) {
        return Ok(());
    }

    tracing::warn!(tx_hash = ?tx.hash, confidence = ?tier, signals = ?score_result.signals, "Suspicious transaction detected");

    let detected_at = Utc::now();
    let raw_transaction = serde_json::to_value(&tx)?;
    let signal_payload = serde_json::json!({
        "signals": score_result.signals,
        "intent": format!("{intent:?}"),
        "drain": &drain,
        "economic": {
            "checked": economic.checked,
            "invariant_violated": economic.invariant_violated,
            "overshoot_pct": economic.overshoot_pct,
        }
    });
    let corpus_snapshot = IncidentCorpusSnapshot::capture(
        &state.cex_wallets,
        &state.bridge_corpus,
        &state.mixer_corpus,
    )
    .await;
    let corpus_provenance = serde_json::to_value(corpus_snapshot.provenance())?;

    let protocol = score_result.protocol.clone().unwrap();
    let new_incident = NewIncident {
        tx_hash: format!("{:?}", tx.hash),
        chain_name: state.config.chain_name.clone(),
        status: "triaged".to_string(),
        confidence: format!("{tier:?}").to_ascii_lowercase(),
        score: score_result.score as i32,
        protocol_id: Some(protocol.id.clone()),
        protocol_name: Some(protocol.name.clone()),
        attacker_address: format!("{:?}", tx.from),
        protocol_address: tx.to.map(|value| format!("{:?}", value)),
        first_seen_at: detected_at,
        detected_at,
        last_updated_at: detected_at,
        signals: signal_payload.clone(),
        corpus_provenance: corpus_provenance.clone(),
        raw_transaction: raw_transaction.clone(),
        summary: Some(format!(
            "{} candidate exploit on {} with {} signal(s)",
            protocol.name,
            format!("{:?}", tx.hash),
            score_result.score
        )),
    };

    let incident = {
        let mut conn = state.pool.get().await?;
        upsert_incident(&mut conn, &new_incident).await?
    };

    let artifact = state
        .artifact_store
        .persist_json(
            &format!("incident-{}", incident.id),
            &serde_json::json!({
                "incident": &incident,
                "transaction": raw_transaction,
                "signals": signal_payload,
            }),
        )
        .await?;

    {
        let mut conn = state.pool.get().await?;
        insert_artifact(
            &mut conn,
            &NewArtifact {
                incident_id: incident.id,
                kind: "incident_snapshot".into(),
                storage_backend: artifact.backend.clone(),
                locator: artifact.locator.clone(),
                checksum_sha256: artifact.checksum_sha256.clone(),
                content_type: artifact.content_type.clone(),
                size_bytes: artifact.size_bytes,
            },
        )
        .await?;
    }

    if let Some(mugen) = &state.config.mugen {
        submit_verification(
            Arc::new(state.pool.clone()),
            incident.id,
            mugen.clone(),
            serde_json::json!({
                "anomaly_score": score_result.score,
                "signals": score_result.signals,
                "drain_pct": drain.pct_drained,
                "invariant_violated": economic.invariant_violated,
                "overshoot_pct": economic.overshoot_pct,
            }),
        );
    }

    state
        .fund_tracker
        .start_tracking(
            tx.from,
            state.ws_provider.clone(),
            corpus_snapshot,
            TrackingContext {
                incident_id: incident.id,
                exploit_tx_hash: format!("{:?}", tx.hash),
                protocol_id: Some(protocol.id.clone()),
                started_at: detected_at,
            },
        )
        .await?;

    state.notifications.notify_incident(&incident).await?;
    dispatch_keeperhub(&state, &incident, &artifact).await?;

    let intelligence_state = state.clone();
    let intelligence_incident = incident.clone();
    let tx_hash_hex = format!("{:?}", tx.hash);
    tokio::spawn(async move {
        if let Err(error) = build_intelligence_artifacts(
            intelligence_state,
            intelligence_incident,
            tx.from,
            tx_hash_hex,
        )
        .await
        {
            tracing::warn!(error = %error, "incident intelligence artifact generation failed");
        }
    });

    Ok(())
}

async fn dispatch_keeperhub(
    state: &AppState,
    incident: &Incident,
    artifact: &crate::artifacts::StoredArtifact,
) -> Result<()> {
    let Some(webhook_url) = &state.config.keeperhub_webhook_url else {
        return Ok(());
    };

    state
        .http_client
        .post(webhook_url)
        .json(&serde_json::json!({
            "source": "ghost",
            "incident": incident,
            "artifact": artifact,
        }))
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

async fn build_intelligence_artifacts(
    state: Arc<AppState>,
    incident: Incident,
    attacker: ethers::types::Address,
    tx_hash_hex: String,
) -> Result<()> {
    let Some(tx_hash) = tx_hash_hex.parse().ok() else {
        return Ok(());
    };
    let corpus_snapshot = match state
        .fund_tracker
        .incident_corpus_snapshot(incident.id)
        .await
    {
        Some(snapshot) => snapshot,
        None => {
            IncidentCorpusSnapshot::capture(
                &state.cex_wallets,
                &state.bridge_corpus,
                &state.mixer_corpus,
            )
            .await
        }
    };

    let profile = if state.config.basescan_api_key.is_some() {
        let cex_wallets = corpus_snapshot.cex.wallets.clone();
        let bridge_corpus = corpus_snapshot.bridge.clone();
        let mixer_corpus = corpus_snapshot.mixer.clone();
        build_fingerprint(
            attacker,
            tx_hash,
            &state.provider,
            Some(&cex_wallets),
            Some(&bridge_corpus),
            Some(&mixer_corpus),
        )
        .await
        .ok()
    } else {
        None
    };

    let geo_result = match (
        state.config.bloxroute_auth_header.as_deref(),
        state.config.maxmind_db_path.as_ref(),
    ) {
        (Some(auth), Some(path)) => geolocate_attack_tx(
            &tx_hash_hex,
            auth,
            &path.display().to_string(),
            &state.config.bloxroute_tx_lookup_url_template,
        )
        .await
        .ok()
        .flatten(),
        _ => None,
    };

    let cex_deposits = state.fund_tracker.incident_cex_deposits(&tx_hash_hex).await;
    let bridge_transfers = state
        .fund_tracker
        .incident_bridge_transfers(&tx_hash_hex)
        .await;
    let mixer_entries = state
        .fund_tracker
        .incident_mixer_entries(&tx_hash_hex)
        .await;
    let wallet_tree = state.fund_tracker.incident_wallet_tree(incident.id).await;

    let intelligence_payload = serde_json::json!({
        "incident_id": incident.id,
        "tx_hash": tx_hash_hex,
        "attacker": format!("{attacker:?}"),
        "corpus_provenance": incident.corpus_provenance.clone(),
        "profile": profile,
        "geo_result": geo_result,
        "wallet_tree": wallet_tree,
        "bridge_transfers": bridge_transfers,
        "cex_deposits": cex_deposits,
        "mixer_entries": mixer_entries,
    });

    let stored = state
        .artifact_store
        .persist_json(
            &format!("incident-intelligence-{}", incident.id),
            &intelligence_payload,
        )
        .await?;
    {
        let mut conn = state.pool.get().await?;
        insert_artifact(
            &mut conn,
            &NewArtifact {
                incident_id: incident.id,
                kind: "incident_intelligence".into(),
                storage_backend: stored.backend.clone(),
                locator: stored.locator.clone(),
                checksum_sha256: stored.checksum_sha256.clone(),
                content_type: stored.content_type.clone(),
                size_bytes: stored.size_bytes,
            },
        )
        .await?;
    }

    let attacker_profile = profile
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or_else(|| serde_json::json!({ "status": "unavailable" }));
    let geo_json = geo_result.map(serde_json::to_value).transpose()?;
    let total_drained = incident
        .signals
        .get("drain")
        .and_then(|value| value.get("absolute_loss"))
        .and_then(|value| value.as_u64().map(|value| value as u128))
        .unwrap_or(0);
    let (artifacts, verification_jobs) = {
        let mut conn = state.pool.get().await?;
        let artifacts = list_incident_artifacts(&mut conn, incident.id).await?;
        let verification_jobs = list_verification_jobs_for_incident(&mut conn, incident.id).await?;
        (artifacts, verification_jobs)
    };
    let evidence_artifacts: Vec<EvidenceArtifact> = artifacts
        .into_iter()
        .map(|artifact| EvidenceArtifact {
            kind: artifact.kind,
            storage_backend: artifact.storage_backend,
            locator: artifact.locator,
            checksum_sha256: artifact.checksum_sha256,
            content_type: artifact.content_type,
            created_at: artifact.created_at.to_rfc3339(),
        })
        .collect();
    let verification_evidence: Vec<VerificationEvidence> = verification_jobs
        .into_iter()
        .map(|job| VerificationEvidence {
            provider: job.provider,
            external_job_id: job.external_job_id,
            status: job.status,
            proof_hash: job.proof_hash,
            vkey: job.vkey,
            output_score: job.output_score,
            settled_at: job.settled_at.map(|value| value.to_rfc3339()),
        })
        .collect();
    let exploit_report = ExploitReport {
        tx_hash: tx_hash_hex,
        total_drained,
        attacker_profile,
        wallet_tree,
        corpus_provenance: incident.corpus_provenance.clone(),
        bridge_transfers: serde_json::to_value(bridge_transfers)?
            .as_array()
            .cloned()
            .unwrap_or_default(),
        cex_deposits: serde_json::to_value(cex_deposits)?
            .as_array()
            .cloned()
            .unwrap_or_default(),
        mixer_entries: serde_json::to_value(mixer_entries)?
            .as_array()
            .cloned()
            .unwrap_or_default(),
        geo_result: geo_json,
        jurisdiction: incident.chain_name.clone(),
        evidence_hashes: evidence_artifacts.clone(),
        verifications: verification_evidence.clone(),
    };
    let legal_package = generate_legal_package(&exploit_report).await?;
    let stored = state
        .artifact_store
        .persist_bytes(
            &format!("incident-legal-package-{}", incident.id),
            "application/pdf",
            &legal_package,
        )
        .await?;
    let legal_package_evidence = EvidenceArtifact {
        kind: "legal_package".into(),
        storage_backend: stored.backend.clone(),
        locator: stored.locator.clone(),
        checksum_sha256: stored.checksum_sha256.clone(),
        content_type: stored.content_type.clone(),
        created_at: Utc::now().to_rfc3339(),
    };
    let mut conn = state.pool.get().await?;
    insert_artifact(
        &mut conn,
        &NewArtifact {
            incident_id: incident.id,
            kind: "legal_package".into(),
            storage_backend: stored.backend.clone(),
            locator: stored.locator.clone(),
            checksum_sha256: stored.checksum_sha256.clone(),
            content_type: stored.content_type.clone(),
            size_bytes: stored.size_bytes,
        },
    )
    .await?;

    let mut export_inventory = evidence_artifacts;
    export_inventory.push(legal_package_evidence);
    let export_bundle = generate_legal_exports(
        &incident,
        &exploit_report,
        &export_inventory,
        &verification_evidence,
    )?;
    drop(conn);
    persist_incident_export_artifact(
        &state,
        incident.id,
        "legal_export_manifest",
        &export_bundle.manifest,
    )
    .await?;
    persist_incident_export_artifact(
        &state,
        incident.id,
        "ic3_complaint_draft",
        &export_bundle.ic3_complaint_draft,
    )
    .await?;
    persist_incident_export_artifact(
        &state,
        incident.id,
        "ec3_coordination_referral_draft",
        &export_bundle.ec3_coordination_referral_draft,
    )
    .await?;
    let _ = dispatch_legal_exports(&state, incident.id, &export_bundle).await?;

    Ok(())
}

async fn persist_incident_export_artifact(
    state: &AppState,
    incident_id: uuid::Uuid,
    kind: &str,
    payload: &serde_json::Value,
) -> Result<()> {
    let stored = state
        .artifact_store
        .persist_json(&format!("incident-{kind}-{}", incident_id), payload)
        .await?;
    let mut conn = state.pool.get().await?;
    insert_artifact(
        &mut conn,
        &NewArtifact {
            incident_id,
            kind: kind.to_string(),
            storage_backend: stored.backend,
            locator: stored.locator,
            checksum_sha256: stored.checksum_sha256,
            content_type: stored.content_type,
            size_bytes: stored.size_bytes,
        },
    )
    .await?;
    Ok(())
}
