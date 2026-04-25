diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    incidents (id) {
        id -> Uuid,
        tx_hash -> Text,
        chain_name -> Text,
        status -> Text,
        confidence -> Text,
        score -> Int4,
        protocol_id -> Nullable<Text>,
        protocol_name -> Nullable<Text>,
        attacker_address -> Text,
        protocol_address -> Nullable<Text>,
        first_seen_at -> Timestamptz,
        detected_at -> Timestamptz,
        last_updated_at -> Timestamptz,
        signals -> Jsonb,
        corpus_provenance -> Jsonb,
        raw_transaction -> Jsonb,
        summary -> Nullable<Text>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    incident_artifacts (id) {
        id -> Uuid,
        incident_id -> Uuid,
        kind -> Text,
        storage_backend -> Text,
        locator -> Text,
        checksum_sha256 -> Text,
        content_type -> Text,
        size_bytes -> Int8,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    hack_intel_reports (id) {
        id -> Uuid,
        source -> Text,
        external_id -> Text,
        protocol -> Text,
        published_at -> Timestamptz,
        loss_usd -> Nullable<Float8>,
        attack_vector -> Text,
        root_cause -> Text,
        chain_name -> Text,
        title -> Text,
        summary -> Text,
        source_url -> Text,
        raw_payload -> Jsonb,
        ingested_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    vulnerability_signatures (id) {
        id -> Uuid,
        derived_from_report_id -> Uuid,
        model -> Text,
        attack_vector -> Text,
        severity -> Text,
        protocol_types -> Jsonb,
        bytecode_patterns -> Jsonb,
        abi_patterns -> Jsonb,
        description -> Text,
        remediation -> Text,
        raw_signature -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    protocol_scan_runs (id) {
        id -> Uuid,
        protocol_id -> Text,
        protocol_name -> Text,
        chain_name -> Text,
        scan_mode -> Text,
        started_at -> Timestamptz,
        completed_at -> Timestamptz,
        signatures_checked -> Int4,
        findings_count -> Int4,
        clean -> Bool,
        metadata -> Jsonb,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    protocol_findings (id) {
        id -> Uuid,
        scan_run_id -> Uuid,
        protocol_id -> Text,
        contract_address -> Text,
        signature_id -> Nullable<Uuid>,
        finding_type -> Text,
        title -> Text,
        confidence -> Float8,
        severity -> Text,
        matched_pattern -> Text,
        affected_functions -> Jsonb,
        simulation_confirmed -> Bool,
        simulation_mode -> Text,
        details -> Jsonb,
        remediation -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    disclosure_events (id) {
        id -> Uuid,
        finding_id -> Uuid,
        protocol_id -> Text,
        state -> Text,
        contact_emails -> Jsonb,
        due_at -> Timestamptz,
        first_response_due_at -> Nullable<Timestamptz>,
        last_notified_at -> Nullable<Timestamptz>,
        acknowledged_at -> Nullable<Timestamptz>,
        acknowledged_by -> Nullable<Text>,
        escalated_at -> Nullable<Timestamptz>,
        escalation_level -> Int4,
        evidence_backend -> Nullable<Text>,
        evidence_locator -> Nullable<Text>,
        metadata -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    monitor_snapshots (id) {
        id -> Uuid,
        protocol_id -> Text,
        monitor_kind -> Text,
        scope_key -> Text,
        payload -> Jsonb,
        observed_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    protocol_billing_accounts (id) {
        id -> Uuid,
        protocol_id -> Text,
        protocol_name -> Text,
        tier -> Text,
        monthly_fee_usd -> Int4,
        billing_email -> Text,
        alert_webhook -> Nullable<Text>,
        active -> Bool,
        metadata -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    recovery_cases (id) {
        id -> Uuid,
        incident_id -> Uuid,
        protocol_id -> Text,
        total_stolen_usd -> Int8,
        total_recovered_usd -> Int8,
        recovery_method -> Text,
        fee_invoiced -> Bool,
        invoiced_fee_usd -> Int8,
        bounty_contract_address -> Nullable<Text>,
        billing_email -> Text,
        metadata -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    billing_invoices (id) {
        id -> Uuid,
        protocol_id -> Text,
        incident_id -> Nullable<Uuid>,
        recovery_case_id -> Nullable<Uuid>,
        invoice_kind -> Text,
        amount_usd -> Int4,
        currency -> Text,
        status -> Text,
        external_invoice_id -> Nullable<Text>,
        recipient_email -> Text,
        description -> Text,
        metadata -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    intel_reports (id) {
        id -> Uuid,
        incident_id -> Uuid,
        published_at -> Timestamptz,
        protocol_id -> Nullable<Text>,
        protocol_name -> Text,
        attack_vector -> Text,
        total_loss_usd -> Int8,
        recovered_usd -> Int8,
        attacker_skill_tier -> Text,
        used_private_mempool -> Bool,
        funded_via_mixer -> Bool,
        cex_deposit_detected -> Bool,
        chains_involved -> Jsonb,
        time_to_detection_secs -> Int4,
        time_to_mixer_secs -> Nullable<Int4>,
        bounty_outcome -> Text,
        metadata -> Jsonb,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    intel_subscribers (id) {
        id -> Uuid,
        email -> Text,
        api_key_hash -> Text,
        tier -> Text,
        monthly_fee_usd -> Int4,
        active -> Bool,
        metadata -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    verification_jobs (id) {
        id -> Uuid,
        incident_id -> Uuid,
        provider -> Text,
        external_job_id -> Text,
        gateway_url -> Text,
        model_id -> Text,
        input_features -> Jsonb,
        status -> Text,
        proof_hash -> Nullable<Text>,
        vkey -> Nullable<Text>,
        output_score -> Nullable<Float8>,
        error_message -> Nullable<Text>,
        submitted_at -> Timestamptz,
        settled_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    security_reports (id) {
        id -> Uuid,
        protocol_id -> Text,
        protocol_name -> Text,
        report_type -> Text,
        vulnerability_count -> Int4,
        vulnerabilities -> Jsonb,
        report_body -> Text,
        email_recipient -> Nullable<Text>,
        email_sent -> Bool,
        email_error -> Nullable<Text>,
        generated_at -> Timestamptz,
        delivered_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    filing_submissions (id) {
        id -> Uuid,
        incident_id -> Uuid,
        artifact_kind -> Text,
        filing_target -> Text,
        destination -> Text,
        status -> Text,
        request_payload -> Jsonb,
        response_status_code -> Nullable<Int4>,
        response_body -> Nullable<Text>,
        error_message -> Nullable<Text>,
        submitted_at -> Timestamptz,
        completed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    operator_accounts (id) {
        id -> Uuid,
        company_name -> Text,
        contact_name -> Text,
        email -> Text,
        password_hash -> Text,
        webauthn_user_id -> Text,
        otp_enabled -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        last_login_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    operator_sessions (id) {
        id -> Uuid,
        operator_account_id -> Uuid,
        token_hash -> Text,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        last_seen_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    operator_otp_codes (id) {
        id -> Uuid,
        operator_account_id -> Uuid,
        purpose -> Text,
        code_hash -> Text,
        expires_at -> Timestamptz,
        consumed_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use diesel::sql_types::Jsonb;

    operator_passkeys (id) {
        id -> Uuid,
        operator_account_id -> Uuid,
        credential_id -> Text,
        public_key -> Text,
        counter -> Int8,
        transports -> Jsonb,
        device_type -> Text,
        backed_up -> Bool,
        label -> Nullable<Text>,
        created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(incident_artifacts -> incidents (incident_id));
diesel::joinable!(vulnerability_signatures -> hack_intel_reports (derived_from_report_id));
diesel::joinable!(protocol_findings -> protocol_scan_runs (scan_run_id));
diesel::joinable!(disclosure_events -> protocol_findings (finding_id));
diesel::joinable!(recovery_cases -> incidents (incident_id));
diesel::joinable!(billing_invoices -> incidents (incident_id));
diesel::joinable!(billing_invoices -> recovery_cases (recovery_case_id));
diesel::joinable!(intel_reports -> incidents (incident_id));
diesel::joinable!(verification_jobs -> incidents (incident_id));
diesel::joinable!(filing_submissions -> incidents (incident_id));
diesel::joinable!(operator_sessions -> operator_accounts (operator_account_id));
diesel::joinable!(operator_otp_codes -> operator_accounts (operator_account_id));
diesel::joinable!(operator_passkeys -> operator_accounts (operator_account_id));

diesel::allow_tables_to_appear_in_same_query!(
    incidents,
    incident_artifacts,
    hack_intel_reports,
    vulnerability_signatures,
    protocol_scan_runs,
    protocol_findings,
    disclosure_events,
    monitor_snapshots,
    protocol_billing_accounts,
    recovery_cases,
    billing_invoices,
    intel_reports,
    intel_subscribers,
    verification_jobs,
    security_reports,
    filing_submissions,
    operator_accounts,
    operator_sessions,
    operator_otp_codes,
    operator_passkeys,
);
