use crate::config::SmtpConfig;
use crate::model::{Incident, StoredDisclosure, StoredFinding};
use crate::protocols::ProtocolDefinition;
use anyhow::{Context, Result};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

#[derive(Clone, Default)]
pub struct NotificationService {
    smtp: Option<SmtpConfig>,
    operator_email: Option<String>,
}

impl NotificationService {
    pub fn new(smtp: Option<SmtpConfig>, operator_email: Option<String>) -> Self {
        Self {
            smtp,
            operator_email,
        }
    }

    pub async fn notify_incident(&self, incident: &Incident) -> Result<()> {
        let Some(operator_email) = self.operator_email.clone() else {
            tracing::warn!(
                tx_hash = %incident.tx_hash,
                "Operator email is not configured; incident alert emitted to logs only"
            );
            return Ok(());
        };

        self.send_html_email(
            vec![operator_email],
            format!(
                "Ghost Incident Alert [{}] {}",
                incident.confidence.to_uppercase(),
                incident.tx_hash
            ),
            render_incident_html(incident),
        )
        .await
    }

    pub async fn notify_protocol_vulnerability(
        &self,
        protocol: &ProtocolDefinition,
        finding: &StoredFinding,
        disclosure: &StoredDisclosure,
    ) -> Result<()> {
        let mut recipients = protocol.security_contacts.clone();
        if let Some(operator_email) = &self.operator_email {
            recipients.push(operator_email.clone());
        }
        recipients.sort();
        recipients.dedup();

        if recipients.is_empty() {
            tracing::warn!(
                protocol_id = %protocol.id,
                finding_id = %finding.id,
                "No disclosure recipients configured for proactive finding"
            );
            return Ok(());
        }

        self.send_html_email(
            recipients,
            format!(
                "Ghost Proactive Finding [{}] {}",
                finding.severity.to_uppercase(),
                protocol.name
            ),
            render_vulnerability_html(protocol, finding, disclosure),
        )
        .await
    }

    pub async fn notify_disclosure_escalation(
        &self,
        protocol: &ProtocolDefinition,
        finding: &StoredFinding,
        disclosure: &StoredDisclosure,
    ) -> Result<()> {
        let Some(operator_email) = self.operator_email.clone() else {
            tracing::warn!(
                protocol_id = %protocol.id,
                disclosure_id = %disclosure.id,
                "Operator email is not configured; disclosure escalation emitted to logs only"
            );
            return Ok(());
        };

        self.send_html_email(
            vec![operator_email],
            format!(
                "Ghost Disclosure Escalation [{}] {}",
                disclosure.escalation_level, protocol.name
            ),
            render_escalation_html(protocol, finding, disclosure),
        )
        .await
    }

    async fn send_html_email(
        &self,
        recipients: Vec<String>,
        subject: String,
        html: String,
    ) -> Result<()> {
        let Some(smtp) = self.smtp.clone() else {
            tracing::warn!("SMTP is not configured; email alert emitted to logs only");
            return Ok(());
        };
        if recipients.is_empty() {
            return Ok(());
        }

        let mut builder = Message::builder().from(smtp.from_email.parse()?);
        for recipient in recipients {
            builder = builder.to(recipient.parse()?);
        }
        let email = builder
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html)?;

        let creds = Credentials::new(smtp.username.clone(), smtp.password.clone());
        let server = smtp.server.clone();
        let port = smtp.port;

        tokio::task::spawn_blocking(move || -> Result<()> {
            let transport = SmtpTransport::starttls_relay(&server)
                .with_context(|| format!("failed to connect to SMTP relay {server}"))?
                .credentials(creds)
                .port(port)
                .timeout(Some(std::time::Duration::from_secs(15)))
                .build();

            transport.send(&email)?;
            Ok(())
        })
        .await??;

        Ok(())
    }
}

fn render_incident_html(incident: &Incident) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
  <body style="font-family: sans-serif; padding: 16px;">
    <h2>Ghost Incident Alert</h2>
    <p><strong>Confidence:</strong> {}</p>
    <p><strong>Transaction:</strong> {}</p>
    <p><strong>Attacker:</strong> {}</p>
    <p><strong>Status:</strong> {}</p>
    <p><strong>Protocol:</strong> {}</p>
    <pre style="background: #f5f5f5; padding: 12px; border-radius: 8px;">{}</pre>
  </body>
</html>"#,
        incident.confidence,
        incident.tx_hash,
        incident.attacker_address,
        incident.status,
        incident
            .protocol_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        incident.signals
    )
}

fn render_vulnerability_html(
    protocol: &ProtocolDefinition,
    finding: &StoredFinding,
    disclosure: &StoredDisclosure,
) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
  <body style="font-family: sans-serif; padding: 16px;">
    <h2>Ghost Proactive Vulnerability Finding</h2>
    <p><strong>Protocol:</strong> {}</p>
    <p><strong>Finding:</strong> {}</p>
    <p><strong>Severity:</strong> {}</p>
    <p><strong>Contract:</strong> {}</p>
    <p><strong>Confidence:</strong> {:.2}</p>
    <p><strong>Simulation Mode:</strong> {}</p>
    <p><strong>Matched Pattern:</strong> {}</p>
    <p><strong>Remediation:</strong> {}</p>
    <p><strong>First Response Due:</strong> {:?}</p>
    <p><strong>Disclosure Due:</strong> {}</p>
    <p><strong>Evidence:</strong> {} / {}</p>
    <pre style="background: #f5f5f5; padding: 12px; border-radius: 8px;">{}</pre>
  </body>
</html>"#,
        protocol.name,
        finding.title,
        finding.severity,
        finding.contract_address,
        finding.confidence,
        finding.simulation_mode,
        finding.matched_pattern,
        finding.remediation,
        disclosure.first_response_due_at,
        disclosure.due_at,
        disclosure
            .evidence_backend
            .clone()
            .unwrap_or_else(|| "n/a".to_string()),
        disclosure
            .evidence_locator
            .clone()
            .unwrap_or_else(|| "n/a".to_string()),
        finding.details
    )
}

fn render_escalation_html(
    protocol: &ProtocolDefinition,
    finding: &StoredFinding,
    disclosure: &StoredDisclosure,
) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
  <body style="font-family: sans-serif; padding: 16px;">
    <h2>Ghost Disclosure Escalation</h2>
    <p><strong>Protocol:</strong> {}</p>
    <p><strong>Finding:</strong> {}</p>
    <p><strong>State:</strong> {}</p>
    <p><strong>Escalation Level:</strong> {}</p>
    <p><strong>Simulation Mode:</strong> {}</p>
    <p><strong>First Response Due:</strong> {:?}</p>
    <p><strong>Disclosure Due:</strong> {}</p>
    <p><strong>Acknowledged By:</strong> {}</p>
    <pre style="background: #f5f5f5; padding: 12px; border-radius: 8px;">{}</pre>
  </body>
</html>"#,
        protocol.name,
        finding.title,
        disclosure.state,
        disclosure.escalation_level,
        finding.simulation_mode,
        disclosure.first_response_due_at,
        disclosure.due_at,
        disclosure
            .acknowledged_by
            .clone()
            .unwrap_or_else(|| "unacknowledged".to_string()),
        finding.details
    )
}
