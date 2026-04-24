pub mod report_generator;
pub mod report_ingestor;
pub mod scanner;

pub async fn run_monitoring_cycle(state: &crate::state::AppState) -> anyhow::Result<()> {
    let protocol_ids = state
        .protocols
        .monitored_protocols(state.config.chain_id)
        .into_iter()
        .map(|protocol| (protocol.id.clone(), protocol.name.clone()))
        .collect::<Vec<_>>();

    {
        let mut conn = state.pool.get().await?;
        crate::monitoring::report_ingestor::ingest_defillama_hacks(&mut conn).await?;
    }

    for (protocol_id, protocol_name) in protocol_ids {
        let vulnerabilities =
            crate::monitoring::scanner::scan_protocol_for_vulnerabilities(state, &protocol_id)
                .await?;
        crate::monitoring::report_generator::generate_and_email_report(
            state,
            &protocol_name,
            vulnerabilities,
            &protocol_id,
        )
        .await?;
    }

    Ok(())
}
