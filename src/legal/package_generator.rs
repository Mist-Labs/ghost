use anyhow::{Context, Result};
use headless_chrome::{types::PrintToPdfOptions, Browser, LaunchOptionsBuilder};

#[derive(serde::Serialize)]
pub struct ExploitReport {
    pub tx_hash: String,
    pub total_drained: u128,
    pub attacker_profile: serde_json::Value,
    pub wallet_tree: Vec<serde_json::Value>,
    pub cex_deposits: Vec<serde_json::Value>,
    pub geo_result: Option<serde_json::Value>,
    pub jurisdiction: String,
    pub evidence_hashes: Vec<EvidenceArtifact>,
    pub verifications: Vec<VerificationEvidence>,
}

#[derive(serde::Serialize, Clone)]
pub struct EvidenceArtifact {
    pub kind: String,
    pub storage_backend: String,
    pub locator: String,
    pub checksum_sha256: String,
    pub content_type: String,
    pub created_at: String,
}

#[derive(serde::Serialize, Clone)]
pub struct VerificationEvidence {
    pub provider: String,
    pub external_job_id: String,
    pub status: String,
    pub proof_hash: Option<String>,
    pub vkey: Option<String>,
    pub output_score: Option<f64>,
    pub settled_at: Option<String>,
}

pub async fn generate_legal_package(report: &ExploitReport) -> Result<Vec<u8>> {
    let html = render_legal_template(report)?;
    tokio::task::spawn_blocking(move || render_pdf_from_html(&html))
        .await
        .context("legal package render task failed")?
}

fn render_pdf_from_html(html: &str) -> Result<Vec<u8>> {
    let temp_path =
        std::env::temp_dir().join(format!("ghost-legal-package-{}.html", uuid::Uuid::new_v4()));
    std::fs::write(&temp_path, html)?;

    let browser = Browser::new(
        LaunchOptionsBuilder::default()
            .headless(true)
            .build()
            .context("failed to build headless chrome launch options")?,
    )?;
    let tab = browser.new_tab()?;
    tab.navigate_to(&format!("file://{}", temp_path.display()))?;
    tab.wait_until_navigated()?;
    let pdf_bytes = tab.print_to_pdf(Some(PrintToPdfOptions {
        display_header_footer: Some(false),
        print_background: Some(true),
        prefer_css_page_size: Some(true),
        generate_document_outline: Some(true),
        generate_tagged_pdf: Some(true),
        paper_width: Some(8.27),
        paper_height: Some(11.69),
        margin_top: Some(0.35),
        margin_bottom: Some(0.5),
        margin_left: Some(0.45),
        margin_right: Some(0.45),
        ..Default::default()
    }))?;

    let _ = std::fs::remove_file(&temp_path);
    tracing::info!("Legal package generated: {} bytes", pdf_bytes.len());
    Ok(pdf_bytes)
}

fn render_legal_template(report: &ExploitReport) -> Result<String> {
    let attacker_profile = pretty_json(&report.attacker_profile)?;
    let wallet_tree = pretty_json(&serde_json::to_value(&report.wallet_tree)?)?;
    let cex_deposits = pretty_json(&serde_json::to_value(&report.cex_deposits)?)?;
    let geo_result = pretty_json(&serde_json::to_value(&report.geo_result)?)?;
    let evidence_rows = report
        .evidence_hashes
        .iter()
        .map(|artifact| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&artifact.kind),
                escape_html(&artifact.storage_backend),
                escape_html(&artifact.content_type),
                escape_html(&artifact.checksum_sha256),
                escape_html(&artifact.locator),
                escape_html(&artifact.created_at),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let verification_rows = report
        .verifications
        .iter()
        .map(|verification| {
            format!(
                "<tr><td>{}</td><td class=\"mono\">{}</td><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
                escape_html(&verification.provider),
                escape_html(&verification.external_job_id),
                escape_html(&verification.status),
                escape_html(verification.proof_hash.as_deref().unwrap_or("pending")),
                verification
                    .output_score
                    .map(|value| format!("{value:.4}"))
                    .unwrap_or_else(|| "n/a".to_string()),
            )
        })
        .collect::<Vec<_>>()
        .join("");

    Ok(format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Ghost Legal Package</title>
  <style>
    @page {{ size: A4; margin: 16mm 12mm 18mm 12mm; }}
    body {{ font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; color: #111827; font-size: 12px; line-height: 1.45; }}
    h1, h2, h3 {{ margin: 0 0 10px; color: #0f172a; }}
    h1 {{ font-size: 26px; }}
    h2 {{ font-size: 17px; margin-top: 24px; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; }}
    h3 {{ font-size: 13px; margin-top: 16px; }}
    .hero {{ background: linear-gradient(135deg, #dbeafe, #f8fafc); padding: 18px; border-radius: 14px; border: 1px solid #bfdbfe; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 12px; }}
    .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 12px; }}
    .mono {{ font-family: Menlo, Monaco, Consolas, monospace; word-break: break-all; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th, td {{ text-align: left; vertical-align: top; padding: 8px; border-bottom: 1px solid #e5e7eb; }}
    th {{ background: #f8fafc; }}
    pre {{ background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 12px; overflow-wrap: anywhere; white-space: pre-wrap; }}
    .small {{ color: #475569; font-size: 11px; }}
    ul {{ margin: 8px 0 0 18px; }}
  </style>
</head>
<body>
  <section class="hero">
    <h1>Ghost Incident Legal Package</h1>
    <p><strong>Exploit transaction:</strong> <span class="mono">{tx_hash}</span></p>
    <div class="grid">
      <div class="card"><strong>Total drained</strong><br />{total_loss:.6} ETH-equivalent units</div>
      <div class="card"><strong>Jurisdiction</strong><br />{jurisdiction}</div>
      <div class="card"><strong>Evidence artifacts</strong><br />{artifact_count}</div>
      <div class="card"><strong>Verification jobs</strong><br />{verification_count}</div>
    </div>
    <p class="small">Generated by Ghost for responsible disclosure, law-enforcement referral support, and chain-of-custody preservation.</p>
  </section>

  <h2>Executive Summary</h2>
  <p>This package records a suspicious exploit event associated with the transaction above, captures the current attribution evidence available to Ghost, and preserves hashes and storage locators for all persisted artifacts generated during the incident response workflow.</p>

  <h2>Attacker Attribution</h2>
  <h3>Attacker Profile</h3>
  <pre>{attacker_profile}</pre>
  <h3>Wallet Graph</h3>
  <pre>{wallet_tree}</pre>
  <h3>CEX Deposits</h3>
  <pre>{cex_deposits}</pre>
  <h3>Geolocation Assessment</h3>
  <pre>{geo_result}</pre>

  <h2>Chain Of Custody</h2>
  <table>
    <thead>
      <tr>
        <th>Artifact</th>
        <th>Backend</th>
        <th>Content Type</th>
        <th>Checksum</th>
        <th>Locator</th>
        <th>Created</th>
      </tr>
    </thead>
    <tbody>{evidence_rows}</tbody>
  </table>

  <h2>Verification Appendix</h2>
  <table>
    <thead>
      <tr>
        <th>Provider</th>
        <th>Job ID</th>
        <th>Status</th>
        <th>Proof Hash</th>
        <th>Score</th>
      </tr>
    </thead>
    <tbody>{verification_rows}</tbody>
  </table>

  <h2>IC3 Complaint Draft</h2>
  <ul>
    <li>Incident type: unauthorized digital asset transfer / smart contract exploitation.</li>
    <li>Primary transaction hash: <span class="mono">{tx_hash}</span>.</li>
    <li>Estimated loss observed: {total_loss:.6} ETH-equivalent units.</li>
    <li>Available evidence includes wallet graph, exchange deposit tracing, geolocation signals, artifact checksums, and verifier job metadata.</li>
  </ul>

  <h2>Europol EC3 Referral Draft</h2>
  <ul>
    <li>Cross-border digital asset theft indicators may apply depending on exchange routing and wallet attribution shown above.</li>
    <li>Jurisdiction signal recorded by Ghost: {jurisdiction}.</li>
    <li>Artifact appendix preserves integrity data required for independent verification.</li>
  </ul>
</body>
</html>"#,
        tx_hash = escape_html(&report.tx_hash),
        total_loss = report.total_drained as f64 / 1e18,
        jurisdiction = escape_html(&report.jurisdiction),
        artifact_count = report.evidence_hashes.len(),
        verification_count = report.verifications.len(),
        attacker_profile = attacker_profile,
        wallet_tree = wallet_tree,
        cex_deposits = cex_deposits,
        geo_result = geo_result,
        evidence_rows = evidence_rows,
        verification_rows = verification_rows,
    ))
}

fn pretty_json(value: &serde_json::Value) -> Result<String> {
    Ok(escape_html(&serde_json::to_string_pretty(value)?))
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
