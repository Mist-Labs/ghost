use crate::config::BountyConfig;
use anyhow::{anyhow, Context, Result};
use ethers::abi::Abi;
use ethers::contract::ContractFactory;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::{Http, LocalWallet, Provider};
use ethers::signers::Signer;
use ethers::types::{Address, Bytes};
use ethers::utils::parse_ether;
use serde::Deserialize;
use std::str::FromStr;
use std::sync::Arc;
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct BountyDeploymentRequest {
    pub attacker: Address,
    pub recovery_recipient: Address,
    pub bounty_eth: f64,
    pub minimum_return_eth: f64,
    pub exploit_tx_hash: String,
    pub operator_email: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BountyDeploymentReceipt {
    pub contract_address: Address,
    pub deployment_tx_hash: String,
    pub case_reference: String,
}

pub async fn deploy_bounty_contract(
    request: &BountyDeploymentRequest,
    config: &BountyConfig,
    provider: Provider<Http>,
    chain_id: u64,
) -> Result<BountyDeploymentReceipt> {
    let (abi, bytecode) = compile_contract(config).await?;
    let wallet = LocalWallet::from_str(&config.private_key)
        .context("invalid bounty deployment private key")?
        .with_chain_id(chain_id);
    let client = Arc::new(SignerMiddleware::new(provider, wallet));
    let case_reference = format!(
        "ghost|exploit_tx={}|contact={}",
        request.exploit_tx_hash, request.operator_email
    );

    let factory = ContractFactory::new(abi, bytecode, client);
    let mut deployer = factory.deploy((
        request.attacker,
        request.recovery_recipient,
        parse_ether(request.minimum_return_eth)?,
        case_reference.clone(),
    ))?;
    deployer.tx.set_value(parse_ether(request.bounty_eth)?);

    let (contract, receipt) = deployer.send_with_receipt().await?;

    Ok(BountyDeploymentReceipt {
        contract_address: contract.address(),
        deployment_tx_hash: format!("{:?}", receipt.transaction_hash),
        case_reference,
    })
}

async fn compile_contract(config: &BountyConfig) -> Result<(Abi, Bytes)> {
    let output = Command::new(&config.solc_binary)
        .arg("--combined-json")
        .arg("abi,bin")
        .arg(&config.contract_path)
        .output()
        .await
        .with_context(|| format!("failed to execute {}", config.solc_binary))?;
    if !output.status.success() {
        return Err(anyhow!(
            "solc compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    #[derive(Debug, Deserialize)]
    struct SolcContract {
        abi: serde_json::Value,
        bin: String,
    }

    #[derive(Debug, Deserialize)]
    struct SolcOutput {
        contracts: std::collections::HashMap<String, SolcContract>,
    }

    let compiled: SolcOutput = serde_json::from_slice(&output.stdout)?;
    let (_, contract) = compiled
        .contracts
        .into_iter()
        .find(|(name, _)| name.ends_with(":GhostBounty"))
        .ok_or_else(|| anyhow!("GhostBounty artifact not found in solc output"))?;

    let abi: Abi = match contract.abi {
        serde_json::Value::String(raw) => serde_json::from_str(&raw)?,
        other => serde_json::from_value(other)?,
    };
    let bytecode = Bytes::from(hex::decode(contract.bin)?);
    Ok((abi, bytecode))
}
