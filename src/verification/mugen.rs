use crate::config::MugenConfig;
use crate::db::{
    insert_verification_job, mark_verification_job_failed, mark_verification_job_settled, PgPool,
};
use crate::model::NewVerificationJob;
use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionFeatures {
    pub anomaly_score: u8,
    pub signals: Vec<String>,
    pub drain_pct: f64,
    pub invariant_violated: bool,
    pub overshoot_pct: f64,
}

#[derive(Serialize)]
struct InferRequest {
    model_id: String,
    input: TransactionFeatures,
}

#[derive(Deserialize)]
struct InferResponse {
    job_id: String,
}

#[derive(Deserialize)]
struct JobStatus {
    status: String,
    proof_hash: Option<String>,
    vkey: Option<String>,
    output_score: Option<f64>,
    error: Option<String>,
}

pub fn submit_verification(
    pool: Arc<PgPool>,
    incident_id: Uuid,
    config: MugenConfig,
    features: serde_json::Value,
) {
    tokio::spawn(async move {
        if let Err(error) = run_verification(pool, incident_id, config, features).await {
            tracing::warn!(incident_id = %incident_id, error = %error, "Mugen verification failed");
        }
    });
}

async fn run_verification(
    pool: Arc<PgPool>,
    incident_id: Uuid,
    config: MugenConfig,
    features: serde_json::Value,
) -> Result<()> {
    let features: TransactionFeatures = serde_json::from_value(features)?;

    let client = build_client(&config.api_key)?;
    let response = client
        .post(format!(
            "{}/infer",
            config.gateway_url.trim_end_matches('/')
        ))
        .json(&InferRequest {
            model_id: config.model_id.clone(),
            input: features.clone(),
        })
        .send()
        .await?
        .error_for_status()?
        .json::<InferResponse>()
        .await?;

    {
        let mut conn = pool.get().await?;
        insert_verification_job(
            &mut conn,
            &NewVerificationJob {
                incident_id,
                provider: "mugen".to_string(),
                external_job_id: response.job_id.clone(),
                gateway_url: config.gateway_url.clone(),
                model_id: config.model_id.clone(),
                input_features: serde_json::to_value(&features)?,
                status: "pending".to_string(),
            },
        )
        .await?;
    }

    for _ in 0..config.max_polls {
        tokio::time::sleep(tokio::time::Duration::from_secs(config.poll_interval_secs)).await;
        let status = client
            .get(format!(
                "{}/jobs/{}",
                config.gateway_url.trim_end_matches('/'),
                response.job_id
            ))
            .send()
            .await?
            .error_for_status()?
            .json::<JobStatus>()
            .await?;

        match status.status.as_str() {
            "settled" | "completed" => {
                let mut conn = pool.get().await?;
                mark_verification_job_settled(
                    &mut conn,
                    &response.job_id,
                    status.proof_hash,
                    status.vkey,
                    status.output_score,
                )
                .await?;
                return Ok(());
            }
            "failed" => {
                let mut conn = pool.get().await?;
                mark_verification_job_failed(
                    &mut conn,
                    &response.job_id,
                    status.error.as_deref().unwrap_or("verification job failed"),
                )
                .await?;
                return Err(anyhow!(
                    "Mugen verification failed for job {}",
                    response.job_id
                ));
            }
            _ => {}
        }
    }

    let mut conn = pool.get().await?;
    mark_verification_job_failed(
        &mut conn,
        &response.job_id,
        "verification job timed out before settlement",
    )
    .await?;
    Err(anyhow!(
        "Mugen verification timed out for job {}",
        response.job_id
    ))
}

fn build_client(api_key: &Option<String>) -> Result<Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(api_key) = api_key {
        headers.insert(
            "Authorization",
            reqwest::header::HeaderValue::from_str(api_key)?,
        );
    }

    Ok(Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .default_headers(headers)
        .build()?)
}
