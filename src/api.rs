use crate::billing::intel_feed::{
    get_feed as get_intel_feed, onboard_subscriber, publish_intel_report,
};
use crate::billing::retainer::{record_incident as record_billable_incident, run_monthly_billing};
use crate::billing::success_fee::{invoice_success_fee, open_recovery_case, record_recovery};
use crate::bounty::deploy::{deploy_bounty_contract, BountyDeploymentRequest};
use crate::db::{
    get_finding, get_incident, get_scan_run, list_disclosures,
    list_filing_submissions_for_incident, list_findings, list_hack_reports,
    list_incident_artifacts, list_incidents, list_monitor_snapshots, list_scan_runs,
    list_security_reports, list_signatures, list_verification_jobs_for_incident, ping,
};
use crate::intelligence::attribution_feeds::{feed_overview, sync_configured_feeds};
use crate::intelligence::bridge_corpus::load_bridge_corpus_state;
use crate::proactive::disclosure::acknowledge as acknowledge_disclosure;
use crate::state::AppState;
use crate::tracking::cex_surveillance::load_cex_wallet_corpus_state;
use crate::tracking::mixer_detector::load_mixer_corpus_state;
use actix_web::{get, http::StatusCode, post, web, HttpRequest, HttpResponse, Responder};
use ethers::providers::Middleware;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(healthz)
        .service(readyz)
        .service(list_incidents_handler)
        .service(get_incident_handler)
        .service(list_incident_artifacts_handler)
        .service(list_incident_verification_jobs_handler)
        .service(list_incident_filings_handler)
        .service(get_intel_feed_handler)
        .service(onboard_intel_subscriber_handler)
        .service(publish_intel_report_handler)
        .service(run_retainer_billing_handler)
        .service(record_billable_incident_handler)
        .service(open_recovery_case_handler)
        .service(record_recovery_handler)
        .service(deploy_bounty_contract_handler)
        .service(list_hack_reports_handler)
        .service(list_signatures_handler)
        .service(list_scan_runs_handler)
        .service(get_scan_run_handler)
        .service(list_findings_handler)
        .service(get_finding_handler)
        .service(list_disclosures_handler)
        .service(acknowledge_disclosure_handler)
        .service(get_cex_corpus_handler)
        .service(reload_cex_corpus_handler)
        .service(get_bridge_corpus_handler)
        .service(reload_bridge_corpus_handler)
        .service(get_mixer_corpus_handler)
        .service(reload_mixer_corpus_handler)
        .service(get_attribution_feeds_handler)
        .service(sync_attribution_feeds_handler)
        .service(list_monitor_snapshots_handler)
        .service(list_security_reports_handler);
}

#[get("/healthz")]
async fn healthz(state: web::Data<Arc<AppState>>) -> impl Responder {
    HttpResponse::Ok().json(HealthResponse {
        status: "ok",
        protocols_loaded: state.protocols.protocol_count(),
        mempool_listener_enabled: true,
        zero_g_enabled: matches!(
            state.artifact_store,
            crate::artifacts::ArtifactStore::ZeroG(_)
        ),
        proactive_enabled: true,
    })
}

#[get("/readyz")]
async fn readyz(state: web::Data<Arc<AppState>>) -> impl Responder {
    match check_readiness(&state).await {
        Ok(report) if report.ready => HttpResponse::Ok().json(report),
        Ok(report) => HttpResponse::build(StatusCode::SERVICE_UNAVAILABLE).json(report),
        Err(error) => {
            HttpResponse::build(StatusCode::SERVICE_UNAVAILABLE).json(serde_json::json!({
                "status": "not_ready",
                "reason": error.to_string(),
            }))
        }
    }
}

#[get("/incidents")]
async fn list_incidents_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match list_incidents(&mut conn, 100).await {
        Ok(incidents) => HttpResponse::Ok().json(incidents),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/incidents/{incident_id}")]
async fn get_incident_handler(
    req: HttpRequest,
    path: web::Path<uuid::Uuid>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match get_incident(&mut conn, path.into_inner()).await {
        Ok(incident) => HttpResponse::Ok().json(incident),
        Err(error) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/incidents/{incident_id}/artifacts")]
async fn list_incident_artifacts_handler(
    req: HttpRequest,
    path: web::Path<uuid::Uuid>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match list_incident_artifacts(&mut conn, path.into_inner()).await {
        Ok(artifacts) => HttpResponse::Ok().json(artifacts),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/incidents/{incident_id}/verification-jobs")]
async fn list_incident_verification_jobs_handler(
    req: HttpRequest,
    path: web::Path<uuid::Uuid>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match list_verification_jobs_for_incident(&mut conn, path.into_inner()).await {
        Ok(rows) => HttpResponse::Ok().json(rows),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/incidents/{incident_id}/filings")]
async fn list_incident_filings_handler(
    req: HttpRequest,
    path: web::Path<uuid::Uuid>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match list_filing_submissions_for_incident(&mut conn, path.into_inner()).await {
        Ok(rows) => HttpResponse::Ok().json(rows),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/intel/feed")]
async fn get_intel_feed_handler(
    req: HttpRequest,
    query: web::Query<IntelFeedQuery>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    let Some(api_key) = req
        .headers()
        .get("x-intel-api-key")
        .and_then(|value| value.to_str().ok())
    else {
        return HttpResponse::Unauthorized().finish();
    };

    match get_intel_feed(
        &state.pool,
        api_key,
        query.page.unwrap_or(1),
        query.per_page.unwrap_or(25),
    )
    .await
    {
        Ok(reports) => HttpResponse::Ok().json(reports),
        Err(error) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[post("/intel/subscribers")]
async fn onboard_intel_subscriber_handler(
    req: HttpRequest,
    payload: web::Json<OnboardIntelSubscriberRequest>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let stripe_key = state.config.stripe_api_key.as_deref().unwrap_or("");
    match onboard_subscriber(&state.pool, stripe_key, &payload.email, &payload.tier).await {
        Ok(api_key) => HttpResponse::Ok().json(serde_json::json!({
            "api_key": api_key,
        })),
        Err(error) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[post("/intel/reports/{id}/publish")]
async fn publish_intel_report_handler(
    req: HttpRequest,
    path: web::Path<uuid::Uuid>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    match publish_intel_report(&state.pool, path.into_inner()).await {
        Ok(report) => HttpResponse::Ok().json(report),
        Err(error) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[post("/billing/retainer/run")]
async fn run_retainer_billing_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let stripe_key = state.config.stripe_api_key.as_deref().unwrap_or("");
    match run_monthly_billing(&state.pool, stripe_key).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "status": "ok",
        })),
        Err(error) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[post("/billing/incidents")]
async fn record_billable_incident_handler(
    req: HttpRequest,
    payload: web::Json<RecordBillableIncidentRequest>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    match record_billable_incident(
        &state.pool,
        &payload.protocol_id,
        &payload.tx_hash,
        payload.loss_usd,
    )
    .await
    {
        Ok(incident_id) => HttpResponse::Ok().json(serde_json::json!({
            "incident_id": incident_id,
        })),
        Err(error) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[post("/billing/recovery-cases")]
async fn open_recovery_case_handler(
    req: HttpRequest,
    payload: web::Json<OpenRecoveryCaseRequest>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let recovery_method = payload.recovery_method.as_deref().unwrap_or("pending");
    match open_recovery_case(
        &state.pool,
        payload.incident_id,
        payload.total_stolen_usd,
        recovery_method,
        payload.bounty_contract_address.as_deref(),
    )
    .await
    {
        Ok(case) => HttpResponse::Ok().json(case),
        Err(error) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[post("/billing/recovery-cases/{incident_id}/recoveries")]
async fn record_recovery_handler(
    req: HttpRequest,
    path: web::Path<uuid::Uuid>,
    payload: web::Json<RecordRecoveryRequest>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let incident_id = path.into_inner();
    match record_recovery(
        &state.pool,
        incident_id,
        payload.recovered_usd,
        &payload.method,
    )
    .await
    {
        Ok(fee_due_usd) => {
            if payload.invoice.unwrap_or(true) {
                let stripe_key = state.config.stripe_api_key.as_deref().unwrap_or("");
                if let Err(error) =
                    invoice_success_fee(&state.pool, stripe_key, incident_id, fee_due_usd).await
                {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "fee_due_usd": fee_due_usd,
                        "invoice_error": error.to_string(),
                    }));
                }
            }

            HttpResponse::Ok().json(serde_json::json!({
                "incident_id": incident_id,
                "fee_due_usd": fee_due_usd,
            }))
        }
        Err(error) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[post("/billing/recovery-cases/{incident_id}/deploy-bounty")]
async fn deploy_bounty_contract_handler(
    req: HttpRequest,
    path: web::Path<uuid::Uuid>,
    payload: web::Json<DeployBountyRequest>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let Some(config) = &state.config.bounty else {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "bounty deployment is not configured",
        }));
    };

    let incident_id = path.into_inner();
    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };
    let incident = match get_incident(&mut conn, incident_id).await {
        Ok(incident) => incident,
        Err(error) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    let attacker = match incident.attacker_address.parse() {
        Ok(address) => address,
        Err(error) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("incident attacker address is invalid: {error}"),
            }))
        }
    };
    let recovery_recipient =
        match payload
            .recovery_recipient
            .as_deref()
            .or(incident.protocol_address.as_deref())
        {
            Some(address) => match address.parse() {
                Ok(address) => address,
                Err(error) => {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "error": format!("recovery recipient address is invalid: {error}"),
                    }))
                }
            },
            None => return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "recovery recipient is required when the incident has no protocol address",
            })),
        };

    match deploy_bounty_contract(
        &BountyDeploymentRequest {
            attacker,
            recovery_recipient,
            bounty_eth: payload.bounty_eth,
            minimum_return_eth: payload.minimum_return_eth,
            exploit_tx_hash: incident.tx_hash.clone(),
            operator_email: state
                .config
                .operator_email
                .clone()
                .unwrap_or_else(|| "ghost-operator".to_string()),
        },
        config,
        state.provider.clone(),
        state.config.chain_id,
    )
    .await
    {
        Ok(receipt) => HttpResponse::Ok().json(receipt),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/proactive/reports")]
async fn list_hack_reports_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match list_hack_reports(&mut conn, 100).await {
        Ok(rows) => HttpResponse::Ok().json(rows),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/proactive/signatures")]
async fn list_signatures_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match list_signatures(&mut conn, 100).await {
        Ok(rows) => HttpResponse::Ok().json(rows),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/proactive/scans")]
async fn list_scan_runs_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match list_scan_runs(&mut conn, 100).await {
        Ok(rows) => HttpResponse::Ok().json(rows),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/proactive/scans/{id}")]
async fn get_scan_run_handler(
    req: HttpRequest,
    path: web::Path<uuid::Uuid>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match get_scan_run(&mut conn, path.into_inner()).await {
        Ok(row) => HttpResponse::Ok().json(row),
        Err(error) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/proactive/findings")]
async fn list_findings_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match list_findings(&mut conn, 200).await {
        Ok(rows) => HttpResponse::Ok().json(rows),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/proactive/findings/{id}")]
async fn get_finding_handler(
    req: HttpRequest,
    path: web::Path<uuid::Uuid>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match get_finding(&mut conn, path.into_inner()).await {
        Ok(row) => HttpResponse::Ok().json(row),
        Err(error) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/proactive/disclosures")]
async fn list_disclosures_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match list_disclosures(&mut conn, 100).await {
        Ok(rows) => HttpResponse::Ok().json(rows),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[post("/proactive/disclosures/{id}/acknowledge")]
async fn acknowledge_disclosure_handler(
    req: HttpRequest,
    path: web::Path<uuid::Uuid>,
    payload: web::Json<AcknowledgeDisclosureRequest>,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    match acknowledge_disclosure(&state, path.into_inner(), &payload.acknowledged_by).await {
        Ok(disclosure) => HttpResponse::Ok().json(disclosure),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/admin/cex-corpus")]
async fn get_cex_corpus_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let summary = state.cex_wallets.read().await.summary();
    HttpResponse::Ok().json(summary)
}

#[post("/admin/cex-corpus/reload")]
async fn reload_cex_corpus_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    match load_cex_wallet_corpus_state(&state.config.cex_wallets_file) {
        Ok(new_state) => {
            let summary = new_state.summary();
            *state.cex_wallets.write().await = new_state;
            HttpResponse::Ok().json(summary)
        }
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/admin/bridge-corpus")]
async fn get_bridge_corpus_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let summary = state.bridge_corpus.read().await.summary();
    HttpResponse::Ok().json(summary)
}

#[post("/admin/bridge-corpus/reload")]
async fn reload_bridge_corpus_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    match load_bridge_corpus_state(&state.config.bridge_addresses_file) {
        Ok(new_state) => {
            let summary = new_state.summary();
            *state.bridge_corpus.write().await = new_state;
            HttpResponse::Ok().json(summary)
        }
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/admin/mixer-corpus")]
async fn get_mixer_corpus_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let summary = state.mixer_corpus.read().await.summary();
    HttpResponse::Ok().json(summary)
}

#[post("/admin/mixer-corpus/reload")]
async fn reload_mixer_corpus_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    match load_mixer_corpus_state(&state.config.mixer_pools_file) {
        Ok(new_state) => {
            let summary = new_state.summary();
            *state.mixer_corpus.write().await = new_state;
            HttpResponse::Ok().json(summary)
        }
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/admin/attribution-feeds")]
async fn get_attribution_feeds_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    HttpResponse::Ok().json(feed_overview(state.get_ref().as_ref()).await)
}

#[post("/admin/attribution-feeds/sync")]
async fn sync_attribution_feeds_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    match sync_configured_feeds(state.get_ref()).await {
        Ok(results) => HttpResponse::Ok().json(serde_json::json!({
            "synced": results,
        })),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/monitoring/snapshots")]
async fn list_monitor_snapshots_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match list_monitor_snapshots(&mut conn, 200).await {
        Ok(rows) => HttpResponse::Ok().json(rows),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

#[get("/monitoring/security-reports")]
async fn list_security_reports_handler(
    req: HttpRequest,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    if let Err(response) = authorize(&req, state.config.api_key.as_deref()) {
        return response;
    }

    let mut conn = match state.pool.get().await {
        Ok(conn) => conn,
        Err(error) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": error.to_string(),
            }))
        }
    };

    match list_security_reports(&mut conn, 100).await {
        Ok(rows) => HttpResponse::Ok().json(rows),
        Err(error) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string(),
        })),
    }
}

fn authorize(req: &HttpRequest, api_key: Option<&str>) -> Result<(), HttpResponse> {
    let Some(api_key) = api_key else {
        return Ok(());
    };
    let Some(header) = req.headers().get("x-api-key") else {
        return Err(HttpResponse::Unauthorized().finish());
    };
    let Ok(value) = header.to_str() else {
        return Err(HttpResponse::Unauthorized().finish());
    };
    if value == api_key {
        Ok(())
    } else {
        Err(HttpResponse::Unauthorized().finish())
    }
}

async fn check_readiness(state: &Arc<AppState>) -> anyhow::Result<ReadinessReport> {
    let mut conn = state.pool.get().await?;
    ping(&mut conn).await?;

    let http_chain_id = state.provider.get_chainid().await?.as_u64();
    let ws_block_number = state.ws_provider.get_block_number().await?.as_u64();
    let protocols_loaded = state.protocols.protocol_count();
    let chain_matches = http_chain_id == state.config.chain_id;
    let has_protocols = state.protocols.is_ready();

    Ok(ReadinessReport {
        status: if chain_matches && has_protocols {
            "ready"
        } else {
            "not_ready"
        },
        ready: chain_matches && has_protocols,
        protocols_loaded,
        expected_chain_id: state.config.chain_id,
        provider_chain_id: http_chain_id,
        ws_block_number,
    })
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    protocols_loaded: usize,
    mempool_listener_enabled: bool,
    zero_g_enabled: bool,
    proactive_enabled: bool,
}

#[derive(Serialize)]
struct ReadinessReport {
    status: &'static str,
    ready: bool,
    protocols_loaded: usize,
    expected_chain_id: u64,
    provider_chain_id: u64,
    ws_block_number: u64,
}

#[derive(Deserialize)]
struct AcknowledgeDisclosureRequest {
    acknowledged_by: String,
}

#[derive(Deserialize)]
struct IntelFeedQuery {
    page: Option<i64>,
    per_page: Option<i64>,
}

#[derive(Deserialize)]
struct OnboardIntelSubscriberRequest {
    email: String,
    tier: String,
}

#[derive(Deserialize)]
struct RecordBillableIncidentRequest {
    protocol_id: String,
    tx_hash: String,
    loss_usd: i64,
}

#[derive(Deserialize)]
struct OpenRecoveryCaseRequest {
    incident_id: uuid::Uuid,
    total_stolen_usd: i64,
    recovery_method: Option<String>,
    bounty_contract_address: Option<String>,
}

#[derive(Deserialize)]
struct RecordRecoveryRequest {
    recovered_usd: i64,
    method: String,
    invoice: Option<bool>,
}

#[derive(Deserialize)]
struct DeployBountyRequest {
    bounty_eth: f64,
    minimum_return_eth: f64,
    recovery_recipient: Option<String>,
}
