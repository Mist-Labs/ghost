use crate::db::insert_filing_submission;
use crate::legal::export_bundle::LegalExportBundle;
use crate::model::{NewFilingSubmission, StoredFilingSubmission};
use crate::state::AppState;
use anyhow::Result;
use chrono::Utc;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

const MAX_RESPONSE_BODY_CHARS: usize = 4000;

pub async fn dispatch_legal_exports(
    state: &Arc<AppState>,
    incident_id: Uuid,
    bundle: &LegalExportBundle,
) -> Result<Vec<StoredFilingSubmission>> {
    let mut submissions = Vec::new();
    submissions.push(
        dispatch_one(
            state,
            incident_id,
            "ic3_complaint_draft",
            "ic3",
            state.config.ic3_submission_url.as_deref(),
            &bundle.ic3_complaint_draft,
        )
        .await?,
    );
    submissions.push(
        dispatch_one(
            state,
            incident_id,
            "legal_export_manifest",
            "national_cybercrime_authority",
            state.config.national_cybercrime_submission_url.as_deref(),
            &bundle.manifest,
        )
        .await?,
    );
    submissions.push(
        dispatch_one(
            state,
            incident_id,
            "ec3_coordination_referral_draft",
            "ec3_coordination",
            state.config.ec3_coordination_submission_url.as_deref(),
            &bundle.ec3_coordination_referral_draft,
        )
        .await?,
    );
    Ok(submissions)
}

async fn dispatch_one(
    state: &Arc<AppState>,
    incident_id: Uuid,
    artifact_kind: &str,
    filing_target: &str,
    destination: Option<&str>,
    payload: &Value,
) -> Result<StoredFilingSubmission> {
    let submitted_at = Utc::now();
    let mut response_status_code = None;
    let mut response_body = None;
    let mut error_message = None;
    let status = if let Some(destination) = destination {
        let mut request = state
            .http_client
            .post(destination)
            .timeout(std::time::Duration::from_secs(
                state.config.filing_timeout_secs,
            ))
            .header(CONTENT_TYPE, "application/json");
        if let Some(token) = &state.config.filing_bearer_token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }

        match request.json(payload).send().await {
            Ok(response) => {
                response_status_code = Some(response.status().as_u16() as i32);
                let body = response.text().await.unwrap_or_default();
                if !body.is_empty() {
                    response_body = Some(truncate(&body));
                }
                if response_status_code.unwrap_or_default() >= 400 {
                    error_message = Some("remote filing endpoint returned an error status".into());
                    "failed"
                } else {
                    "submitted"
                }
            }
            Err(error) => {
                error_message = Some(error.to_string());
                "failed"
            }
        }
    } else {
        error_message = Some("destination not configured".into());
        "skipped"
    };

    let mut conn = state.pool.get().await?;
    insert_filing_submission(
        &mut conn,
        &NewFilingSubmission {
            incident_id,
            artifact_kind: artifact_kind.to_string(),
            filing_target: filing_target.to_string(),
            destination: destination.unwrap_or("not_configured").to_string(),
            status: status.to_string(),
            request_payload: payload.clone(),
            response_status_code,
            response_body,
            error_message,
            submitted_at,
            completed_at: Some(Utc::now()),
        },
    )
    .await
}

fn truncate(value: &str) -> String {
    let mut trimmed = value
        .chars()
        .take(MAX_RESPONSE_BODY_CHARS)
        .collect::<String>();
    if value.chars().count() > MAX_RESPONSE_BODY_CHARS {
        trimmed.push_str("…");
    }
    trimmed
}
