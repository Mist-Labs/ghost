use crate::model::{
    Incident, IncidentArtifact, NewArtifact, NewBillingInvoice, NewFilingSubmission,
    NewHackIntelReport, NewIncident, NewIntelReport, NewIntelSubscriber, NewProtocolBillingAccount,
    NewRecoveryCase, NewSecurityReport, NewStoredSignature, NewVerificationJob,
    StoredBillingInvoice, StoredDisclosure, StoredFilingSubmission, StoredFinding,
    StoredHackIntelReport, StoredIntelReport, StoredIntelSubscriber, StoredMonitorSnapshot,
    StoredProtocolBillingAccount, StoredRecoveryCase, StoredScanRun, StoredSecurityReport,
    StoredSignature, StoredVerificationJob,
};
use crate::proactive::{
    AttackVector, Severity, SimulationMode, VulnerabilityMatch, VulnerabilitySignature,
};
use crate::schema::{
    billing_invoices, disclosure_events, filing_submissions, hack_intel_reports,
    incident_artifacts, incidents, intel_reports, intel_subscribers, monitor_snapshots,
    protocol_billing_accounts, protocol_findings, protocol_scan_runs, recovery_cases,
    security_reports, verification_jobs, vulnerability_signatures,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use diesel::connection::SimpleConnection;
use diesel::pg::PgConnection;
use diesel::prelude::{BoolExpressionMethods, ExpressionMethods, QueryDsl, SelectableHelper};
use diesel::result::DatabaseErrorKind;
use diesel::{Connection, OptionalExtension};
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::{AsyncPgConnection, RunQueryDsl as AsyncRunQueryDsl};
use uuid::Uuid;

diesel::table! {
    __diesel_schema_migrations (version) {
        version -> VarChar,
        run_on -> Timestamptz,
    }
}

pub type PgPool = Pool<AsyncPgConnection>;

struct MigrationFile {
    version: &'static str,
    name: &'static str,
    up_sql: &'static str,
}

const MIGRATIONS: &[MigrationFile] = &[
    MigrationFile {
        version: "2026-04-23-180100",
        name: "create_incidents",
        up_sql: include_str!("../migrations/2026-04-23-180100_create_incidents/up.sql"),
    },
    MigrationFile {
        version: "2026-04-23-180200",
        name: "create_incident_artifacts",
        up_sql: include_str!("../migrations/2026-04-23-180200_create_incident_artifacts/up.sql"),
    },
    MigrationFile {
        version: "2026-04-23-180300",
        name: "create_hack_intel_reports",
        up_sql: include_str!("../migrations/2026-04-23-180300_create_hack_intel_reports/up.sql"),
    },
    MigrationFile {
        version: "2026-04-23-180400",
        name: "create_vulnerability_signatures",
        up_sql: include_str!(
            "../migrations/2026-04-23-180400_create_vulnerability_signatures/up.sql"
        ),
    },
    MigrationFile {
        version: "2026-04-23-180500",
        name: "create_protocol_scan_runs",
        up_sql: include_str!("../migrations/2026-04-23-180500_create_protocol_scan_runs/up.sql"),
    },
    MigrationFile {
        version: "2026-04-23-180600",
        name: "create_protocol_findings",
        up_sql: include_str!("../migrations/2026-04-23-180600_create_protocol_findings/up.sql"),
    },
    MigrationFile {
        version: "2026-04-23-180700",
        name: "create_disclosure_events",
        up_sql: include_str!("../migrations/2026-04-23-180700_create_disclosure_events/up.sql"),
    },
    MigrationFile {
        version: "2026-04-23-180800",
        name: "create_monitor_snapshots",
        up_sql: include_str!("../migrations/2026-04-23-180800_create_monitor_snapshots/up.sql"),
    },
    MigrationFile {
        version: "2026-04-23-180900",
        name: "create_protocol_billing_accounts",
        up_sql: include_str!(
            "../migrations/2026-04-23-180900_create_protocol_billing_accounts/up.sql"
        ),
    },
    MigrationFile {
        version: "2026-04-23-181000",
        name: "create_recovery_cases",
        up_sql: include_str!("../migrations/2026-04-23-181000_create_recovery_cases/up.sql"),
    },
    MigrationFile {
        version: "2026-04-23-181100",
        name: "create_billing_invoices",
        up_sql: include_str!("../migrations/2026-04-23-181100_create_billing_invoices/up.sql"),
    },
    MigrationFile {
        version: "2026-04-23-181200",
        name: "create_intel_reports",
        up_sql: include_str!("../migrations/2026-04-23-181200_create_intel_reports/up.sql"),
    },
    MigrationFile {
        version: "2026-04-23-181300",
        name: "create_intel_subscribers",
        up_sql: include_str!("../migrations/2026-04-23-181300_create_intel_subscribers/up.sql"),
    },
    MigrationFile {
        version: "2026-04-23-181400",
        name: "create_verification_jobs",
        up_sql: include_str!("../migrations/2026-04-23-181400_create_verification_jobs/up.sql"),
    },
    MigrationFile {
        version: "2026-04-23-181500",
        name: "create_security_reports",
        up_sql: include_str!("../migrations/2026-04-23-181500_create_security_reports/up.sql"),
    },
    MigrationFile {
        version: "2026-04-24-000100",
        name: "add_simulation_mode_to_protocol_findings",
        up_sql: include_str!(
            "../migrations/2026-04-24-000100_add_simulation_mode_to_protocol_findings/up.sql"
        ),
    },
    MigrationFile {
        version: "2026-04-24-000200",
        name: "add_corpus_provenance_to_incidents",
        up_sql: include_str!(
            "../migrations/2026-04-24-000200_add_corpus_provenance_to_incidents/up.sql"
        ),
    },
    MigrationFile {
        version: "2026-04-24-000300",
        name: "create_filing_submissions",
        up_sql: include_str!("../migrations/2026-04-24-000300_create_filing_submissions/up.sql"),
    },
    MigrationFile {
        version: "2026-04-25-000100",
        name: "create_operator_accounts",
        up_sql: include_str!("../migrations/2026-04-25-000100_create_operator_accounts/up.sql"),
    },
    MigrationFile {
        version: "2026-04-25-000200",
        name: "create_operator_sessions",
        up_sql: include_str!("../migrations/2026-04-25-000200_create_operator_sessions/up.sql"),
    },
    MigrationFile {
        version: "2026-04-25-000300",
        name: "create_operator_otp_codes",
        up_sql: include_str!("../migrations/2026-04-25-000300_create_operator_otp_codes/up.sql"),
    },
    MigrationFile {
        version: "2026-04-25-000400",
        name: "create_operator_passkeys",
        up_sql: include_str!("../migrations/2026-04-25-000400_create_operator_passkeys/up.sql"),
    },
];

pub async fn create_pool(database_url: &str) -> Result<PgPool> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
    let pool = Pool::builder().build(manager).await?;
    Ok(pool)
}

pub async fn run_pending_migrations(database_url: &str) -> Result<()> {
    let database_url = database_url.to_owned();
    tokio::task::spawn_blocking(move || run_pending_migrations_blocking(&database_url)).await??;
    Ok(())
}

fn run_pending_migrations_blocking(database_url: &str) -> Result<()> {
    let mut conn = PgConnection::establish(database_url)?;
    conn.batch_execute(
        r#"
        CREATE TABLE IF NOT EXISTS __diesel_schema_migrations (
            version VARCHAR(50) PRIMARY KEY,
            run_on TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        "#,
    )?;

    let applied = diesel::RunQueryDsl::load::<String>(
        __diesel_schema_migrations::table.select(__diesel_schema_migrations::version),
        &mut conn,
    )?
    .into_iter()
    .collect::<std::collections::HashSet<_>>();

    for migration in MIGRATIONS {
        if applied.contains(migration.version) {
            continue;
        }

        tracing::info!(
            version = migration.version,
            name = migration.name,
            "running diesel migration"
        );

        conn.transaction::<_, anyhow::Error, _>(|conn| {
            conn.batch_execute(migration.up_sql)?;
            diesel::RunQueryDsl::execute(
                diesel::insert_into(__diesel_schema_migrations::table).values((
                    __diesel_schema_migrations::version.eq(migration.version),
                    __diesel_schema_migrations::run_on.eq(Utc::now()),
                )),
                conn,
            )?;
            Ok(())
        })?;
    }

    Ok(())
}

pub async fn ping(conn: &mut AsyncPgConnection) -> Result<()> {
    incidents::table
        .select(diesel::dsl::count_star())
        .get_result::<i64>(conn)
        .await?;
    Ok(())
}

pub async fn upsert_incident(
    conn: &mut AsyncPgConnection,
    incident: &NewIncident,
) -> Result<Incident> {
    if let Some(existing) = find_incident_by_tx_hash(conn, &incident.tx_hash).await? {
        return Ok(update_existing_incident(conn, &existing, incident).await?);
    }

    let inserted = diesel::insert_into(incidents::table)
        .values((
            incidents::id.eq(Uuid::new_v4()),
            incidents::tx_hash.eq(incident.tx_hash.clone()),
            incidents::chain_name.eq(incident.chain_name.clone()),
            incidents::status.eq(incident.status.clone()),
            incidents::confidence.eq(incident.confidence.clone()),
            incidents::score.eq(incident.score),
            incidents::protocol_id.eq(incident.protocol_id.clone()),
            incidents::protocol_name.eq(incident.protocol_name.clone()),
            incidents::attacker_address.eq(incident.attacker_address.clone()),
            incidents::protocol_address.eq(incident.protocol_address.clone()),
            incidents::first_seen_at.eq(incident.first_seen_at),
            incidents::detected_at.eq(incident.detected_at),
            incidents::last_updated_at.eq(incident.last_updated_at),
            incidents::signals.eq(incident.signals.clone()),
            incidents::corpus_provenance.eq(incident.corpus_provenance.clone()),
            incidents::raw_transaction.eq(incident.raw_transaction.clone()),
            incidents::summary.eq(incident.summary.clone()),
        ))
        .returning(Incident::as_returning())
        .get_result(conn)
        .await;

    match inserted {
        Ok(row) => Ok(row),
        Err(diesel::result::Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {
            let existing = find_incident_by_tx_hash(conn, &incident.tx_hash)
                .await?
                .ok_or(diesel::result::Error::NotFound)?;
            Ok(update_existing_incident(conn, &existing, incident).await?)
        }
        Err(error) => Err(error.into()),
    }
}

pub async fn insert_artifact(
    conn: &mut AsyncPgConnection,
    artifact: &NewArtifact,
) -> Result<IncidentArtifact> {
    let stored = diesel::insert_into(incident_artifacts::table)
        .values((
            incident_artifacts::id.eq(Uuid::new_v4()),
            incident_artifacts::incident_id.eq(artifact.incident_id),
            incident_artifacts::kind.eq(artifact.kind.clone()),
            incident_artifacts::storage_backend.eq(artifact.storage_backend.clone()),
            incident_artifacts::locator.eq(artifact.locator.clone()),
            incident_artifacts::checksum_sha256.eq(artifact.checksum_sha256.clone()),
            incident_artifacts::content_type.eq(artifact.content_type.clone()),
            incident_artifacts::size_bytes.eq(artifact.size_bytes),
            incident_artifacts::created_at.eq(Utc::now()),
        ))
        .returning(IncidentArtifact::as_returning())
        .get_result(conn)
        .await?;

    Ok(stored)
}

pub async fn list_incident_artifacts(
    conn: &mut AsyncPgConnection,
    incident_id_value: Uuid,
) -> Result<Vec<IncidentArtifact>> {
    let rows = incident_artifacts::table
        .filter(incident_artifacts::incident_id.eq(incident_id_value))
        .order(incident_artifacts::created_at.asc())
        .select(IncidentArtifact::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub async fn list_incidents(conn: &mut AsyncPgConnection, limit: i64) -> Result<Vec<Incident>> {
    let rows = incidents::table
        .order(incidents::detected_at.desc())
        .limit(limit)
        .select(Incident::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub async fn insert_hack_report_if_new(
    conn: &mut AsyncPgConnection,
    report: &NewHackIntelReport,
) -> Result<Option<StoredHackIntelReport>> {
    let inserted = diesel::insert_into(hack_intel_reports::table)
        .values((
            hack_intel_reports::id.eq(Uuid::new_v4()),
            hack_intel_reports::source.eq(report.source.clone()),
            hack_intel_reports::external_id.eq(report.external_id.clone()),
            hack_intel_reports::protocol.eq(report.protocol.clone()),
            hack_intel_reports::published_at.eq(report.published_at),
            hack_intel_reports::loss_usd.eq(report.loss_usd),
            hack_intel_reports::attack_vector.eq(report.attack_vector.as_storage_value()),
            hack_intel_reports::root_cause.eq(report.root_cause.clone()),
            hack_intel_reports::chain_name.eq(report.chain_name.clone()),
            hack_intel_reports::title.eq(report.title.clone()),
            hack_intel_reports::summary.eq(report.summary.clone()),
            hack_intel_reports::source_url.eq(report.source_url.clone()),
            hack_intel_reports::raw_payload.eq(report.raw_payload.clone()),
            hack_intel_reports::ingested_at.eq(Utc::now()),
        ))
        .on_conflict((hack_intel_reports::source, hack_intel_reports::external_id))
        .do_nothing()
        .returning(StoredHackIntelReport::as_returning())
        .get_result(conn)
        .await;

    match inserted {
        Ok(report) => Ok(Some(report)),
        Err(diesel::result::Error::NotFound) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub async fn insert_signature(
    conn: &mut AsyncPgConnection,
    new_signature: &NewStoredSignature,
) -> Result<StoredSignature> {
    let stored = diesel::insert_into(vulnerability_signatures::table)
        .values((
            vulnerability_signatures::id.eq(new_signature.signature.id),
            vulnerability_signatures::derived_from_report_id
                .eq(new_signature.derived_from_report_id),
            vulnerability_signatures::model.eq(new_signature.model.clone()),
            vulnerability_signatures::attack_vector
                .eq(new_signature.signature.attack_vector.as_storage_value()),
            vulnerability_signatures::severity
                .eq(new_signature.signature.severity.as_storage_value()),
            vulnerability_signatures::protocol_types.eq(serde_json::to_value(
                &new_signature.signature.protocol_types,
            )?),
            vulnerability_signatures::bytecode_patterns.eq(serde_json::to_value(
                &new_signature.signature.bytecode_patterns,
            )?),
            vulnerability_signatures::abi_patterns
                .eq(serde_json::to_value(&new_signature.signature.abi_patterns)?),
            vulnerability_signatures::description.eq(new_signature.signature.description.clone()),
            vulnerability_signatures::remediation.eq(new_signature.signature.remediation.clone()),
            vulnerability_signatures::raw_signature
                .eq(serde_json::to_value(&new_signature.signature)?),
            vulnerability_signatures::created_at.eq(Utc::now()),
        ))
        .returning(StoredSignature::as_returning())
        .get_result(conn)
        .await?;

    Ok(stored)
}

pub async fn list_signatures(
    conn: &mut AsyncPgConnection,
    limit: i64,
) -> Result<Vec<StoredSignature>> {
    let rows = vulnerability_signatures::table
        .order(vulnerability_signatures::created_at.desc())
        .limit(limit)
        .select(StoredSignature::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub async fn insert_scan_run(
    conn: &mut AsyncPgConnection,
    result: &crate::proactive::ScanResult,
    started_at: DateTime<Utc>,
) -> Result<StoredScanRun> {
    let stored = diesel::insert_into(protocol_scan_runs::table)
        .values((
            protocol_scan_runs::id.eq(Uuid::new_v4()),
            protocol_scan_runs::protocol_id.eq(result.protocol_id.clone()),
            protocol_scan_runs::protocol_name.eq(result.protocol_name.clone()),
            protocol_scan_runs::chain_name.eq(result.chain_name.clone()),
            protocol_scan_runs::scan_mode.eq(result.scan_mode.as_storage_value()),
            protocol_scan_runs::started_at.eq(started_at),
            protocol_scan_runs::completed_at.eq(result.scan_timestamp),
            protocol_scan_runs::signatures_checked.eq(result.signatures_checked as i32),
            protocol_scan_runs::findings_count.eq(result.vulnerabilities_found.len() as i32),
            protocol_scan_runs::clean.eq(result.clean),
            protocol_scan_runs::metadata.eq(result.metadata.clone()),
        ))
        .returning(StoredScanRun::as_returning())
        .get_result(conn)
        .await?;

    Ok(stored)
}

pub async fn insert_findings(
    conn: &mut AsyncPgConnection,
    scan_run_id: Uuid,
    protocol_id: &str,
    simulation_mode: SimulationMode,
    findings: &[VulnerabilityMatch],
) -> Result<Vec<StoredFinding>> {
    let mut stored = Vec::with_capacity(findings.len());

    for finding in findings {
        let row = diesel::insert_into(protocol_findings::table)
            .values((
                protocol_findings::id.eq(Uuid::new_v4()),
                protocol_findings::scan_run_id.eq(scan_run_id),
                protocol_findings::protocol_id.eq(protocol_id.to_owned()),
                protocol_findings::contract_address.eq(finding.contract_address.clone()),
                protocol_findings::signature_id.eq(finding.signature_id),
                protocol_findings::finding_type.eq(finding.finding_type.as_storage_value()),
                protocol_findings::title.eq(finding.title.clone()),
                protocol_findings::confidence.eq(finding.confidence),
                protocol_findings::severity.eq(finding.severity.as_storage_value()),
                protocol_findings::matched_pattern.eq(finding.matched_pattern.clone()),
                protocol_findings::affected_functions
                    .eq(serde_json::to_value(&finding.affected_functions)?),
                protocol_findings::simulation_confirmed.eq(finding.simulation_confirmed),
                protocol_findings::simulation_mode.eq(simulation_mode.as_storage_value()),
                protocol_findings::details.eq(finding.details.clone()),
                protocol_findings::remediation.eq(finding.remediation.clone()),
                protocol_findings::created_at.eq(Utc::now()),
            ))
            .returning(StoredFinding::as_returning())
            .get_result(conn)
            .await?;
        stored.push(row);
    }

    Ok(stored)
}

pub async fn get_finding(conn: &mut AsyncPgConnection, finding_id: Uuid) -> Result<StoredFinding> {
    let finding = protocol_findings::table
        .find(finding_id)
        .select(StoredFinding::as_select())
        .first(conn)
        .await?;

    Ok(finding)
}

pub async fn list_verification_jobs_for_incident(
    conn: &mut AsyncPgConnection,
    incident_id_value: Uuid,
) -> Result<Vec<StoredVerificationJob>> {
    let rows = verification_jobs::table
        .filter(verification_jobs::incident_id.eq(incident_id_value))
        .order(verification_jobs::submitted_at.asc())
        .select(StoredVerificationJob::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub async fn insert_disclosure(
    conn: &mut AsyncPgConnection,
    finding_id: Uuid,
    protocol_id: &str,
    contacts: &[String],
    due_at: DateTime<Utc>,
    first_response_due_at: Option<DateTime<Utc>>,
    evidence_backend: Option<&str>,
    evidence_locator: Option<&str>,
    metadata: serde_json::Value,
) -> Result<StoredDisclosure> {
    let disclosure = diesel::insert_into(disclosure_events::table)
        .values((
            disclosure_events::id.eq(Uuid::new_v4()),
            disclosure_events::finding_id.eq(finding_id),
            disclosure_events::protocol_id.eq(protocol_id.to_owned()),
            disclosure_events::state.eq("opened"),
            disclosure_events::contact_emails.eq(serde_json::to_value(contacts)?),
            disclosure_events::due_at.eq(due_at),
            disclosure_events::first_response_due_at.eq(first_response_due_at),
            disclosure_events::last_notified_at.eq(Some(Utc::now())),
            disclosure_events::acknowledged_at.eq(None::<DateTime<Utc>>),
            disclosure_events::acknowledged_by.eq(None::<String>),
            disclosure_events::escalated_at.eq(None::<DateTime<Utc>>),
            disclosure_events::escalation_level.eq(0),
            disclosure_events::evidence_backend.eq(evidence_backend.map(str::to_string)),
            disclosure_events::evidence_locator.eq(evidence_locator.map(str::to_string)),
            disclosure_events::metadata.eq(metadata),
            disclosure_events::created_at.eq(Utc::now()),
        ))
        .returning(StoredDisclosure::as_returning())
        .get_result(conn)
        .await?;

    Ok(disclosure)
}

pub async fn list_hack_reports(
    conn: &mut AsyncPgConnection,
    limit: i64,
) -> Result<Vec<StoredHackIntelReport>> {
    let rows = hack_intel_reports::table
        .order(hack_intel_reports::published_at.desc())
        .limit(limit)
        .select(StoredHackIntelReport::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub async fn list_scan_runs(
    conn: &mut AsyncPgConnection,
    limit: i64,
) -> Result<Vec<StoredScanRun>> {
    let rows = protocol_scan_runs::table
        .order(protocol_scan_runs::completed_at.desc())
        .limit(limit)
        .select(StoredScanRun::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub async fn list_disclosures(
    conn: &mut AsyncPgConnection,
    limit: i64,
) -> Result<Vec<StoredDisclosure>> {
    let rows = disclosure_events::table
        .order(disclosure_events::created_at.desc())
        .limit(limit)
        .select(StoredDisclosure::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub async fn acknowledge_disclosure(
    conn: &mut AsyncPgConnection,
    disclosure_id: Uuid,
    acknowledged_by: &str,
) -> Result<StoredDisclosure> {
    let disclosure = diesel::update(disclosure_events::table.find(disclosure_id))
        .set((
            disclosure_events::state.eq("acknowledged"),
            disclosure_events::acknowledged_at.eq(Some(Utc::now())),
            disclosure_events::acknowledged_by.eq(Some(acknowledged_by.to_owned())),
        ))
        .returning(StoredDisclosure::as_returning())
        .get_result(conn)
        .await?;

    Ok(disclosure)
}

pub async fn list_due_disclosures(
    conn: &mut AsyncPgConnection,
    now: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<StoredDisclosure>> {
    let rows = disclosure_events::table
        .filter(disclosure_events::state.eq_any(vec!["opened", "escalated"]))
        .filter(
            disclosure_events::first_response_due_at
                .is_not_null()
                .and(disclosure_events::acknowledged_at.is_null())
                .and(disclosure_events::first_response_due_at.le(now))
                .or(disclosure_events::due_at.le(now)),
        )
        .order(disclosure_events::due_at.asc())
        .limit(limit)
        .select(StoredDisclosure::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub async fn mark_disclosure_escalated(
    conn: &mut AsyncPgConnection,
    disclosure_id: Uuid,
    escalation_level: i32,
    state: &str,
) -> Result<StoredDisclosure> {
    let now = Utc::now();
    let disclosure = diesel::update(disclosure_events::table.find(disclosure_id))
        .set((
            disclosure_events::state.eq(state.to_owned()),
            disclosure_events::escalated_at.eq(Some(now)),
            disclosure_events::escalation_level.eq(escalation_level),
            disclosure_events::last_notified_at.eq(Some(now)),
        ))
        .returning(StoredDisclosure::as_returning())
        .get_result(conn)
        .await?;

    Ok(disclosure)
}

pub async fn insert_monitor_snapshot(
    conn: &mut AsyncPgConnection,
    protocol_id: &str,
    monitor_kind: &str,
    scope_key: &str,
    payload: serde_json::Value,
) -> Result<StoredMonitorSnapshot> {
    let snapshot = diesel::insert_into(monitor_snapshots::table)
        .values((
            monitor_snapshots::id.eq(Uuid::new_v4()),
            monitor_snapshots::protocol_id.eq(protocol_id.to_owned()),
            monitor_snapshots::monitor_kind.eq(monitor_kind.to_owned()),
            monitor_snapshots::scope_key.eq(scope_key.to_owned()),
            monitor_snapshots::payload.eq(payload),
            monitor_snapshots::observed_at.eq(Utc::now()),
        ))
        .returning(StoredMonitorSnapshot::as_returning())
        .get_result(conn)
        .await?;

    Ok(snapshot)
}

pub async fn latest_monitor_snapshot(
    conn: &mut AsyncPgConnection,
    protocol_id: &str,
    monitor_kind: &str,
    scope_key: &str,
) -> Result<Option<StoredMonitorSnapshot>> {
    let snapshot = monitor_snapshots::table
        .filter(monitor_snapshots::protocol_id.eq(protocol_id))
        .filter(monitor_snapshots::monitor_kind.eq(monitor_kind))
        .filter(monitor_snapshots::scope_key.eq(scope_key))
        .order(monitor_snapshots::observed_at.desc())
        .select(StoredMonitorSnapshot::as_select())
        .first(conn)
        .await
        .optional()?;

    Ok(snapshot)
}

pub async fn get_incident(conn: &mut AsyncPgConnection, incident_id: Uuid) -> Result<Incident> {
    let incident = incidents::table
        .find(incident_id)
        .select(Incident::as_select())
        .first(conn)
        .await?;

    Ok(incident)
}

pub async fn list_monitor_snapshots(
    conn: &mut AsyncPgConnection,
    limit: i64,
) -> Result<Vec<StoredMonitorSnapshot>> {
    let rows = monitor_snapshots::table
        .order(monitor_snapshots::observed_at.desc())
        .limit(limit)
        .select(StoredMonitorSnapshot::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub async fn list_security_reports(
    conn: &mut AsyncPgConnection,
    limit: i64,
) -> Result<Vec<StoredSecurityReport>> {
    let rows = security_reports::table
        .order(security_reports::generated_at.desc())
        .limit(limit)
        .select(StoredSecurityReport::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub async fn get_scan_run(
    conn: &mut AsyncPgConnection,
    scan_run_id: Uuid,
) -> Result<StoredScanRun> {
    let row = protocol_scan_runs::table
        .find(scan_run_id)
        .select(StoredScanRun::as_select())
        .first(conn)
        .await?;

    Ok(row)
}

pub async fn list_findings(conn: &mut AsyncPgConnection, limit: i64) -> Result<Vec<StoredFinding>> {
    let rows = protocol_findings::table
        .order(protocol_findings::created_at.desc())
        .limit(limit)
        .select(StoredFinding::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub async fn upsert_protocol_billing_account(
    conn: &mut AsyncPgConnection,
    account: &NewProtocolBillingAccount,
) -> Result<StoredProtocolBillingAccount> {
    let now = Utc::now();
    let row = diesel::insert_into(protocol_billing_accounts::table)
        .values((
            protocol_billing_accounts::id.eq(Uuid::new_v4()),
            protocol_billing_accounts::protocol_id.eq(account.protocol_id.clone()),
            protocol_billing_accounts::protocol_name.eq(account.protocol_name.clone()),
            protocol_billing_accounts::tier.eq(account.tier.clone()),
            protocol_billing_accounts::monthly_fee_usd.eq(account.monthly_fee_usd),
            protocol_billing_accounts::billing_email.eq(account.billing_email.clone()),
            protocol_billing_accounts::alert_webhook.eq(account.alert_webhook.clone()),
            protocol_billing_accounts::active.eq(account.active),
            protocol_billing_accounts::metadata.eq(account.metadata.clone()),
            protocol_billing_accounts::created_at.eq(now),
            protocol_billing_accounts::updated_at.eq(now),
        ))
        .on_conflict(protocol_billing_accounts::protocol_id)
        .do_update()
        .set((
            protocol_billing_accounts::protocol_name.eq(account.protocol_name.clone()),
            protocol_billing_accounts::tier.eq(account.tier.clone()),
            protocol_billing_accounts::monthly_fee_usd.eq(account.monthly_fee_usd),
            protocol_billing_accounts::billing_email.eq(account.billing_email.clone()),
            protocol_billing_accounts::alert_webhook.eq(account.alert_webhook.clone()),
            protocol_billing_accounts::active.eq(account.active),
            protocol_billing_accounts::metadata.eq(account.metadata.clone()),
            protocol_billing_accounts::updated_at.eq(now),
        ))
        .returning(StoredProtocolBillingAccount::as_returning())
        .get_result(conn)
        .await?;

    Ok(row)
}

pub async fn list_active_protocol_billing_accounts(
    conn: &mut AsyncPgConnection,
) -> Result<Vec<StoredProtocolBillingAccount>> {
    let rows = protocol_billing_accounts::table
        .filter(protocol_billing_accounts::active.eq(true))
        .order(protocol_billing_accounts::updated_at.desc())
        .select(StoredProtocolBillingAccount::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub async fn get_protocol_billing_account(
    conn: &mut AsyncPgConnection,
    protocol_id_value: &str,
) -> Result<Option<StoredProtocolBillingAccount>> {
    let row = protocol_billing_accounts::table
        .filter(protocol_billing_accounts::protocol_id.eq(protocol_id_value))
        .select(StoredProtocolBillingAccount::as_select())
        .first(conn)
        .await
        .optional()?;

    Ok(row)
}

pub async fn upsert_recovery_case(
    conn: &mut AsyncPgConnection,
    new_case: &NewRecoveryCase,
) -> Result<StoredRecoveryCase> {
    let now = Utc::now();
    let row = diesel::insert_into(recovery_cases::table)
        .values((
            recovery_cases::id.eq(Uuid::new_v4()),
            recovery_cases::incident_id.eq(new_case.incident_id),
            recovery_cases::protocol_id.eq(new_case.protocol_id.clone()),
            recovery_cases::total_stolen_usd.eq(new_case.total_stolen_usd),
            recovery_cases::total_recovered_usd.eq(0_i64),
            recovery_cases::recovery_method.eq(new_case.recovery_method.clone()),
            recovery_cases::fee_invoiced.eq(false),
            recovery_cases::invoiced_fee_usd.eq(0_i64),
            recovery_cases::bounty_contract_address.eq(new_case.bounty_contract_address.clone()),
            recovery_cases::billing_email.eq(new_case.billing_email.clone()),
            recovery_cases::metadata.eq(new_case.metadata.clone()),
            recovery_cases::created_at.eq(now),
            recovery_cases::updated_at.eq(now),
        ))
        .on_conflict(recovery_cases::incident_id)
        .do_update()
        .set((
            recovery_cases::protocol_id.eq(new_case.protocol_id.clone()),
            recovery_cases::total_stolen_usd.eq(new_case.total_stolen_usd),
            recovery_cases::recovery_method.eq(new_case.recovery_method.clone()),
            recovery_cases::bounty_contract_address.eq(new_case.bounty_contract_address.clone()),
            recovery_cases::billing_email.eq(new_case.billing_email.clone()),
            recovery_cases::metadata.eq(new_case.metadata.clone()),
            recovery_cases::updated_at.eq(now),
        ))
        .returning(StoredRecoveryCase::as_returning())
        .get_result(conn)
        .await?;

    Ok(row)
}

pub async fn get_recovery_case_by_incident(
    conn: &mut AsyncPgConnection,
    incident_id_value: Uuid,
) -> Result<Option<StoredRecoveryCase>> {
    let row = recovery_cases::table
        .filter(recovery_cases::incident_id.eq(incident_id_value))
        .select(StoredRecoveryCase::as_select())
        .first(conn)
        .await
        .optional()?;

    Ok(row)
}

pub async fn get_recovery_case_by_bounty_contract(
    conn: &mut AsyncPgConnection,
    bounty_contract_address: &str,
) -> Result<Option<StoredRecoveryCase>> {
    let row = recovery_cases::table
        .filter(
            recovery_cases::bounty_contract_address.eq(Some(bounty_contract_address.to_owned())),
        )
        .select(StoredRecoveryCase::as_select())
        .first(conn)
        .await
        .optional()?;

    Ok(row)
}

pub async fn update_recovery_case_after_recovery(
    conn: &mut AsyncPgConnection,
    incident_id_value: Uuid,
    total_recovered_usd: i64,
    recovery_method: &str,
    metadata: serde_json::Value,
) -> Result<StoredRecoveryCase> {
    let row = diesel::update(
        recovery_cases::table.filter(recovery_cases::incident_id.eq(incident_id_value)),
    )
    .set((
        recovery_cases::total_recovered_usd.eq(total_recovered_usd),
        recovery_cases::recovery_method.eq(recovery_method.to_owned()),
        recovery_cases::metadata.eq(metadata),
        recovery_cases::updated_at.eq(Utc::now()),
    ))
    .returning(StoredRecoveryCase::as_returning())
    .get_result(conn)
    .await?;

    Ok(row)
}

pub async fn mark_recovery_fee_invoiced(
    conn: &mut AsyncPgConnection,
    incident_id_value: Uuid,
    new_invoiced_fee_usd: i64,
) -> Result<StoredRecoveryCase> {
    let row = diesel::update(
        recovery_cases::table.filter(recovery_cases::incident_id.eq(incident_id_value)),
    )
    .set((
        recovery_cases::fee_invoiced.eq(true),
        recovery_cases::invoiced_fee_usd.eq(new_invoiced_fee_usd),
        recovery_cases::updated_at.eq(Utc::now()),
    ))
    .returning(StoredRecoveryCase::as_returning())
    .get_result(conn)
    .await?;

    Ok(row)
}

pub async fn insert_billing_invoice(
    conn: &mut AsyncPgConnection,
    invoice: &NewBillingInvoice,
) -> Result<StoredBillingInvoice> {
    let now = Utc::now();
    let row = diesel::insert_into(billing_invoices::table)
        .values((
            billing_invoices::id.eq(Uuid::new_v4()),
            billing_invoices::protocol_id.eq(invoice.protocol_id.clone()),
            billing_invoices::incident_id.eq(invoice.incident_id),
            billing_invoices::recovery_case_id.eq(invoice.recovery_case_id),
            billing_invoices::invoice_kind.eq(invoice.invoice_kind.clone()),
            billing_invoices::amount_usd.eq(invoice.amount_usd),
            billing_invoices::currency.eq(invoice.currency.clone()),
            billing_invoices::status.eq(invoice.status.clone()),
            billing_invoices::external_invoice_id.eq(invoice.external_invoice_id.clone()),
            billing_invoices::recipient_email.eq(invoice.recipient_email.clone()),
            billing_invoices::description.eq(invoice.description.clone()),
            billing_invoices::metadata.eq(invoice.metadata.clone()),
            billing_invoices::created_at.eq(now),
            billing_invoices::updated_at.eq(now),
        ))
        .returning(StoredBillingInvoice::as_returning())
        .get_result(conn)
        .await?;

    Ok(row)
}

pub async fn upsert_intel_report(
    conn: &mut AsyncPgConnection,
    report: &NewIntelReport,
) -> Result<StoredIntelReport> {
    let row = diesel::insert_into(intel_reports::table)
        .values((
            intel_reports::id.eq(Uuid::new_v4()),
            intel_reports::incident_id.eq(report.incident_id),
            intel_reports::published_at.eq(report.published_at),
            intel_reports::protocol_id.eq(report.protocol_id.clone()),
            intel_reports::protocol_name.eq(report.protocol_name.clone()),
            intel_reports::attack_vector.eq(report.attack_vector.clone()),
            intel_reports::total_loss_usd.eq(report.total_loss_usd),
            intel_reports::recovered_usd.eq(report.recovered_usd),
            intel_reports::attacker_skill_tier.eq(report.attacker_skill_tier.clone()),
            intel_reports::used_private_mempool.eq(report.used_private_mempool),
            intel_reports::funded_via_mixer.eq(report.funded_via_mixer),
            intel_reports::cex_deposit_detected.eq(report.cex_deposit_detected),
            intel_reports::chains_involved.eq(serde_json::to_value(&report.chains_involved)?),
            intel_reports::time_to_detection_secs.eq(report.time_to_detection_secs),
            intel_reports::time_to_mixer_secs.eq(report.time_to_mixer_secs),
            intel_reports::bounty_outcome.eq(report.bounty_outcome.clone()),
            intel_reports::metadata.eq(report.metadata.clone()),
        ))
        .on_conflict(intel_reports::incident_id)
        .do_update()
        .set((
            intel_reports::published_at.eq(report.published_at),
            intel_reports::protocol_id.eq(report.protocol_id.clone()),
            intel_reports::protocol_name.eq(report.protocol_name.clone()),
            intel_reports::attack_vector.eq(report.attack_vector.clone()),
            intel_reports::total_loss_usd.eq(report.total_loss_usd),
            intel_reports::recovered_usd.eq(report.recovered_usd),
            intel_reports::attacker_skill_tier.eq(report.attacker_skill_tier.clone()),
            intel_reports::used_private_mempool.eq(report.used_private_mempool),
            intel_reports::funded_via_mixer.eq(report.funded_via_mixer),
            intel_reports::cex_deposit_detected.eq(report.cex_deposit_detected),
            intel_reports::chains_involved.eq(serde_json::to_value(&report.chains_involved)?),
            intel_reports::time_to_detection_secs.eq(report.time_to_detection_secs),
            intel_reports::time_to_mixer_secs.eq(report.time_to_mixer_secs),
            intel_reports::bounty_outcome.eq(report.bounty_outcome.clone()),
            intel_reports::metadata.eq(report.metadata.clone()),
        ))
        .returning(StoredIntelReport::as_returning())
        .get_result(conn)
        .await?;

    Ok(row)
}

pub async fn list_intel_reports_paginated(
    conn: &mut AsyncPgConnection,
    offset: i64,
    limit: i64,
) -> Result<Vec<StoredIntelReport>> {
    let rows = intel_reports::table
        .order(intel_reports::published_at.desc())
        .offset(offset)
        .limit(limit)
        .select(StoredIntelReport::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub async fn insert_intel_subscriber(
    conn: &mut AsyncPgConnection,
    subscriber: &NewIntelSubscriber,
) -> Result<StoredIntelSubscriber> {
    let now = Utc::now();
    let row = diesel::insert_into(intel_subscribers::table)
        .values((
            intel_subscribers::id.eq(Uuid::new_v4()),
            intel_subscribers::email.eq(subscriber.email.clone()),
            intel_subscribers::api_key_hash.eq(subscriber.api_key_hash.clone()),
            intel_subscribers::tier.eq(subscriber.tier.clone()),
            intel_subscribers::monthly_fee_usd.eq(subscriber.monthly_fee_usd),
            intel_subscribers::active.eq(subscriber.active),
            intel_subscribers::metadata.eq(subscriber.metadata.clone()),
            intel_subscribers::created_at.eq(now),
            intel_subscribers::updated_at.eq(now),
        ))
        .returning(StoredIntelSubscriber::as_returning())
        .get_result(conn)
        .await?;

    Ok(row)
}

pub async fn subscriber_is_active(
    conn: &mut AsyncPgConnection,
    api_key_hash_value: &str,
) -> Result<bool> {
    let subscriber = intel_subscribers::table
        .filter(intel_subscribers::api_key_hash.eq(api_key_hash_value))
        .filter(intel_subscribers::active.eq(true))
        .select(StoredIntelSubscriber::as_select())
        .first(conn)
        .await
        .optional()?;

    Ok(subscriber.is_some())
}

pub async fn insert_verification_job(
    conn: &mut AsyncPgConnection,
    job: &NewVerificationJob,
) -> Result<StoredVerificationJob> {
    let now = Utc::now();
    let row = diesel::insert_into(verification_jobs::table)
        .values((
            verification_jobs::id.eq(Uuid::new_v4()),
            verification_jobs::incident_id.eq(job.incident_id),
            verification_jobs::provider.eq(job.provider.clone()),
            verification_jobs::external_job_id.eq(job.external_job_id.clone()),
            verification_jobs::gateway_url.eq(job.gateway_url.clone()),
            verification_jobs::model_id.eq(job.model_id.clone()),
            verification_jobs::input_features.eq(job.input_features.clone()),
            verification_jobs::status.eq(job.status.clone()),
            verification_jobs::proof_hash.eq(None::<String>),
            verification_jobs::vkey.eq(None::<String>),
            verification_jobs::output_score.eq(None::<f64>),
            verification_jobs::error_message.eq(None::<String>),
            verification_jobs::submitted_at.eq(now),
            verification_jobs::settled_at.eq(None::<DateTime<Utc>>),
            verification_jobs::updated_at.eq(now),
        ))
        .on_conflict(verification_jobs::external_job_id)
        .do_update()
        .set((
            verification_jobs::status.eq(job.status.clone()),
            verification_jobs::updated_at.eq(now),
        ))
        .returning(StoredVerificationJob::as_returning())
        .get_result(conn)
        .await?;

    Ok(row)
}

pub async fn mark_verification_job_settled(
    conn: &mut AsyncPgConnection,
    external_job_id_value: &str,
    proof_hash: Option<String>,
    vkey: Option<String>,
    output_score: Option<f64>,
) -> Result<StoredVerificationJob> {
    let now = Utc::now();
    let row = diesel::update(
        verification_jobs::table
            .filter(verification_jobs::external_job_id.eq(external_job_id_value)),
    )
    .set((
        verification_jobs::status.eq("settled"),
        verification_jobs::proof_hash.eq(proof_hash),
        verification_jobs::vkey.eq(vkey),
        verification_jobs::output_score.eq(output_score),
        verification_jobs::error_message.eq(None::<String>),
        verification_jobs::settled_at.eq(Some(now)),
        verification_jobs::updated_at.eq(now),
    ))
    .returning(StoredVerificationJob::as_returning())
    .get_result(conn)
    .await?;

    Ok(row)
}

pub async fn mark_verification_job_failed(
    conn: &mut AsyncPgConnection,
    external_job_id_value: &str,
    error_message_value: &str,
) -> Result<StoredVerificationJob> {
    let now = Utc::now();
    let row = diesel::update(
        verification_jobs::table
            .filter(verification_jobs::external_job_id.eq(external_job_id_value)),
    )
    .set((
        verification_jobs::status.eq("failed"),
        verification_jobs::error_message.eq(Some(error_message_value.to_string())),
        verification_jobs::settled_at.eq(Some(now)),
        verification_jobs::updated_at.eq(now),
    ))
    .returning(StoredVerificationJob::as_returning())
    .get_result(conn)
    .await?;

    Ok(row)
}

pub async fn insert_security_report(
    conn: &mut AsyncPgConnection,
    report: &NewSecurityReport,
) -> Result<StoredSecurityReport> {
    let delivered_at = if report.email_sent {
        Some(Utc::now())
    } else {
        None
    };
    let row = diesel::insert_into(security_reports::table)
        .values((
            security_reports::id.eq(Uuid::new_v4()),
            security_reports::protocol_id.eq(report.protocol_id.clone()),
            security_reports::protocol_name.eq(report.protocol_name.clone()),
            security_reports::report_type.eq(report.report_type.clone()),
            security_reports::vulnerability_count.eq(report
                .vulnerabilities
                .as_array()
                .map(|items| items.len() as i32)
                .unwrap_or_default()),
            security_reports::vulnerabilities.eq(report.vulnerabilities.clone()),
            security_reports::report_body.eq(report.report_body.clone()),
            security_reports::email_recipient.eq(report.email_recipient.clone()),
            security_reports::email_sent.eq(report.email_sent),
            security_reports::email_error.eq(report.email_error.clone()),
            security_reports::generated_at.eq(Utc::now()),
            security_reports::delivered_at.eq(delivered_at),
        ))
        .returning(StoredSecurityReport::as_returning())
        .get_result(conn)
        .await?;

    Ok(row)
}

pub async fn insert_filing_submission(
    conn: &mut AsyncPgConnection,
    filing: &NewFilingSubmission,
) -> Result<StoredFilingSubmission> {
    let row = diesel::insert_into(filing_submissions::table)
        .values((
            filing_submissions::id.eq(Uuid::new_v4()),
            filing_submissions::incident_id.eq(filing.incident_id),
            filing_submissions::artifact_kind.eq(filing.artifact_kind.clone()),
            filing_submissions::filing_target.eq(filing.filing_target.clone()),
            filing_submissions::destination.eq(filing.destination.clone()),
            filing_submissions::status.eq(filing.status.clone()),
            filing_submissions::request_payload.eq(filing.request_payload.clone()),
            filing_submissions::response_status_code.eq(filing.response_status_code),
            filing_submissions::response_body.eq(filing.response_body.clone()),
            filing_submissions::error_message.eq(filing.error_message.clone()),
            filing_submissions::submitted_at.eq(filing.submitted_at),
            filing_submissions::completed_at.eq(filing.completed_at),
        ))
        .returning(StoredFilingSubmission::as_returning())
        .get_result(conn)
        .await?;

    Ok(row)
}

pub async fn list_filing_submissions_for_incident(
    conn: &mut AsyncPgConnection,
    incident_id_value: Uuid,
) -> Result<Vec<StoredFilingSubmission>> {
    let rows = filing_submissions::table
        .filter(filing_submissions::incident_id.eq(incident_id_value))
        .order(filing_submissions::submitted_at.desc())
        .select(StoredFilingSubmission::as_select())
        .load(conn)
        .await?;

    Ok(rows)
}

pub fn decode_signature(row: &StoredSignature) -> Result<VulnerabilitySignature> {
    let mut signature: VulnerabilitySignature = serde_json::from_value(row.raw_signature.clone())?;
    signature.id = row.id;
    signature.derived_from_hack_id = row.derived_from_report_id;
    signature.attack_vector = AttackVector::from_storage_value(&row.attack_vector);
    signature.severity = Severity::from_storage_value(&row.severity);
    Ok(signature)
}

pub async fn find_incident_by_tx_hash(
    conn: &mut AsyncPgConnection,
    tx_hash_value: &str,
) -> Result<Option<Incident>, diesel::result::Error> {
    incidents::table
        .filter(incidents::tx_hash.eq(tx_hash_value))
        .select(Incident::as_select())
        .first(conn)
        .await
        .optional()
}

async fn update_existing_incident(
    conn: &mut AsyncPgConnection,
    existing: &Incident,
    incident: &NewIncident,
) -> Result<Incident, diesel::result::Error> {
    let merged_protocol_id = existing
        .protocol_id
        .clone()
        .or_else(|| incident.protocol_id.clone());
    let merged_protocol_name = existing
        .protocol_name
        .clone()
        .or_else(|| incident.protocol_name.clone());
    let merged_protocol_address = existing
        .protocol_address
        .clone()
        .or_else(|| incident.protocol_address.clone());
    let merged_score = existing.score.max(incident.score);
    let earliest_detected_at = existing.detected_at.min(incident.detected_at);

    diesel::update(incidents::table.find(existing.id))
        .set((
            incidents::status.eq(incident.status.clone()),
            incidents::confidence.eq(incident.confidence.clone()),
            incidents::score.eq(merged_score),
            incidents::protocol_id.eq(merged_protocol_id),
            incidents::protocol_name.eq(merged_protocol_name),
            incidents::attacker_address.eq(incident.attacker_address.clone()),
            incidents::protocol_address.eq(merged_protocol_address),
            incidents::detected_at.eq(earliest_detected_at),
            incidents::last_updated_at.eq(incident.last_updated_at),
            incidents::signals.eq(incident.signals.clone()),
            incidents::corpus_provenance.eq(incident.corpus_provenance.clone()),
            incidents::raw_transaction.eq(incident.raw_transaction.clone()),
            incidents::summary.eq(incident.summary.clone()),
        ))
        .returning(Incident::as_returning())
        .get_result(conn)
        .await
}
