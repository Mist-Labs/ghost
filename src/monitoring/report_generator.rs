use crate::db::insert_security_report;
use crate::model::NewSecurityReport;
use crate::state::AppState;
use anyhow::Result;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

pub async fn generate_and_email_report(
    state: &AppState,
    protocol_name: &str,
    vulnerabilities: Vec<crate::monitoring::scanner::Vulnerability>,
    protocol_id: &str,
) -> Result<()> {
    let report_body = render_report(protocol_name, &vulnerabilities);
    let email_recipient = state.config.operator_email.clone();

    let delivery_result = if let Some(recipient) = email_recipient.as_deref() {
        send_security_alert_email(
            &state.config,
            recipient,
            protocol_name,
            &vulnerabilities,
            &report_body,
        )
        .await
    } else {
        Ok(())
    };

    let email_sent = delivery_result.is_ok();
    let email_error = delivery_result.err().map(|error| error.to_string());

    let mut conn = state.pool.get().await?;
    insert_security_report(
        &mut conn,
        &NewSecurityReport {
            protocol_id: protocol_id.to_string(),
            protocol_name: protocol_name.to_string(),
            report_type: "monitoring_scan".to_string(),
            vulnerabilities: serde_json::to_value(&vulnerabilities)?,
            report_body,
            email_recipient,
            email_sent,
            email_error,
        },
    )
    .await?;

    Ok(())
}

pub async fn send_security_alert_email(
    config: &crate::config::Config,
    to_email: &str,
    protocol_name: &str,
    vulnerabilities: &[crate::monitoring::scanner::Vulnerability],
    report_content: &str,
) -> Result<()> {
    let Some(smtp) = &config.smtp else {
        return Ok(());
    };

    let subject = format!(
        "Ghost security report: {} findings for {}",
        vulnerabilities.len(),
        protocol_name
    );

    let html_body = format!("<html><body><pre>{}</pre></body></html>", report_content);

    let email = Message::builder()
        .from(smtp.from_email.parse()?)
        .to(to_email.parse()?)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(html_body)?;

    let creds = Credentials::new(smtp.username.clone(), smtp.password.clone());
    let mailer = SmtpTransport::starttls_relay(&smtp.server)?
        .credentials(creds)
        .port(smtp.port)
        .timeout(Some(std::time::Duration::from_secs(30)))
        .build();

    mailer.send(&email)?;
    Ok(())
}

fn render_report(
    protocol_name: &str,
    vulnerabilities: &[crate::monitoring::scanner::Vulnerability],
) -> String {
    let mut report = format!("Ghost Security Report\nProtocol: {protocol_name}\n\n");
    if vulnerabilities.is_empty() {
        report.push_str("No vulnerabilities detected.\n");
        return report;
    }

    report.push_str("Findings:\n");
    for vulnerability in vulnerabilities {
        report.push_str(&format!(
            "- [{}] {:.2} {} | contract={} | simulation_confirmed={} | remediation={}\n",
            vulnerability.exploit_type,
            vulnerability.risk_score,
            vulnerability.description,
            vulnerability.contract_address,
            vulnerability.simulation_confirmed,
            vulnerability.remediation
        ));
    }
    report
}
