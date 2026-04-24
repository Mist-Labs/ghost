use crate::config::Config;
use crate::protocols::ProtocolDefinition;
use crate::simulation::{quote_expected_output, ForkContext};
use anyhow::{anyhow, Result};
use ethers::abi::{AbiParser, RawLog};
use ethers::providers::Middleware;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, Bytes, NameOrAddress, Transaction, TransactionRequest, H256, U256};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolType {
    Amm,
    Lending,
    Vault,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct EconomicCheckResult {
    pub checked: bool,
    pub invariant_violated: bool,
    pub overshoot_pct: f64,
}

pub async fn check_economic_invariant<M: Middleware + Clone + 'static>(
    tx: &Transaction,
    provider: &M,
    config: &Config,
    protocol_definition: Option<&ProtocolDefinition>,
) -> Result<EconomicCheckResult>
where
    <M as Middleware>::Error: 'static,
{
    let protocol = tx
        .to
        .ok_or_else(|| anyhow!("transaction is missing a protocol address"))?;

    if let Some(block_number) = tx.block_number {
        if let Ok(fork) = ForkContext::spawn(config, block_number.as_u64().saturating_sub(1)).await
        {
            if let Ok(protocol_type) = identify_protocol_type(protocol, &fork.provider).await {
                if let Ok(receipt) = fork.replay_transaction(tx).await {
                    let token_flows = extract_token_flows_from_logs(protocol, &receipt.logs)?;
                    if let Some(result) = expected_output_from_prestate(
                        protocol,
                        &fork,
                        tx.from,
                        protocol_type,
                        &token_flows,
                        protocol_definition,
                    )
                    .await?
                    {
                        let overshoot_pct = if result > 0.0 {
                            (token_flows.total_out_f64 - result) / result.max(1.0)
                        } else {
                            0.0
                        };

                        return Ok(EconomicCheckResult {
                            checked: true,
                            invariant_violated: overshoot_pct > 0.05,
                            overshoot_pct,
                        });
                    }
                }
            }
        }
    }

    let protocol_type = identify_protocol_type(protocol, provider).await?;
    let token_flows = extract_token_flows(tx, provider).await?;

    let Some(expected_output) = expected_output(
        protocol,
        provider,
        tx.from,
        protocol_type,
        &token_flows,
        None,
        protocol_definition,
    )
    .await?
    else {
        return Ok(EconomicCheckResult {
            checked: false,
            invariant_violated: false,
            overshoot_pct: 0.0,
        });
    };

    let overshoot_pct = if expected_output > 0.0 {
        (token_flows.total_out_f64 - expected_output) / expected_output.max(1.0)
    } else {
        0.0
    };

    Ok(EconomicCheckResult {
        checked: true,
        invariant_violated: overshoot_pct > 0.05,
        overshoot_pct,
    })
}

async fn identify_protocol_type<M: Middleware + Clone + 'static>(
    protocol_address: Address,
    provider: &M,
) -> Result<ProtocolType>
where
    <M as Middleware>::Error: 'static,
{
    let vault_abi =
        AbiParser::default().parse(&["function totalAssets() view returns (uint256)"])?;
    if supports_function(provider, protocol_address, &vault_abi, "totalAssets").await {
        return Ok(ProtocolType::Vault);
    }

    let amm_abi = AbiParser::default().parse(&[
        "function getReserves() view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)",
    ])?;
    if supports_function(provider, protocol_address, &amm_abi, "getReserves").await {
        return Ok(ProtocolType::Amm);
    }

    let lending_abi = AbiParser::default().parse(&[
        "function getUserAccountData(address user) view returns (uint256 totalCollateralBase, uint256 totalDebtBase, uint256 availableBorrowsBase, uint256 currentLiquidationThreshold, uint256 ltv, uint256 healthFactor)",
    ])?;
    if supports_function(
        provider,
        protocol_address,
        &lending_abi,
        "getUserAccountData",
    )
    .await
    {
        return Ok(ProtocolType::Lending);
    }

    Ok(ProtocolType::Unknown)
}

#[derive(Debug, Default)]
struct TokenFlows {
    total_in_f64: f64,
    total_out_f64: f64,
    collateral_f64: f64,
    shares_in_f64: f64,
    incoming_by_token: HashMap<Address, U256>,
    outgoing_by_token: HashMap<Address, U256>,
}

async fn extract_token_flows<M: Middleware + Clone + 'static>(
    tx: &Transaction,
    provider: &M,
) -> Result<TokenFlows>
where
    <M as Middleware>::Error: 'static,
{
    let protocol = tx
        .to
        .ok_or_else(|| anyhow!("transaction is missing a protocol address"))?;
    let receipt = provider
        .get_transaction_receipt(tx.hash)
        .await?
        .ok_or_else(|| anyhow!("transaction receipt not found"))?;
    let abi = AbiParser::default()
        .parse(&["event Transfer(address indexed from, address indexed to, uint256 value)"])?;
    let event = abi.event("Transfer")?.clone();
    let signature = H256::from_slice(event.signature().as_bytes());

    let mut flows = TokenFlows::default();
    for log in receipt.logs {
        if log.topics.first() != Some(&signature) {
            continue;
        }

        let parsed = event.parse_log(RawLog {
            topics: log.topics.clone(),
            data: log.data.to_vec(),
        })?;
        let from = parsed
            .params
            .iter()
            .find(|param| param.name == "from")
            .and_then(|param| param.value.clone().into_address());
        let to = parsed
            .params
            .iter()
            .find(|param| param.name == "to")
            .and_then(|param| param.value.clone().into_address());
        let value = parsed
            .params
            .iter()
            .find(|param| param.name == "value")
            .and_then(|param| param.value.clone().into_uint())
            .unwrap_or_default();

        if to == Some(protocol) {
            flows.total_in_f64 += u256_to_f64(value);
            flows.collateral_f64 += u256_to_f64(value);
            *flows
                .incoming_by_token
                .entry(log.address)
                .or_insert_with(U256::zero) += value;
        }
        if from == Some(protocol) {
            flows.total_out_f64 += u256_to_f64(value);
            *flows
                .outgoing_by_token
                .entry(log.address)
                .or_insert_with(U256::zero) += value;
        }
    }

    flows.shares_in_f64 = flows.total_in_f64;
    Ok(flows)
}

fn extract_token_flows_from_logs(
    protocol: Address,
    logs: &[ethers::types::Log],
) -> Result<TokenFlows> {
    let abi = AbiParser::default()
        .parse(&["event Transfer(address indexed from, address indexed to, uint256 value)"])?;
    let event = abi.event("Transfer")?.clone();
    let signature = H256::from_slice(event.signature().as_bytes());

    let mut flows = TokenFlows::default();
    for log in logs {
        if log.topics.first() != Some(&signature) {
            continue;
        }

        let parsed = event.parse_log(RawLog {
            topics: log.topics.clone(),
            data: log.data.to_vec(),
        })?;
        let from = parsed
            .params
            .iter()
            .find(|param| param.name == "from")
            .and_then(|param| param.value.clone().into_address());
        let to = parsed
            .params
            .iter()
            .find(|param| param.name == "to")
            .and_then(|param| param.value.clone().into_address());
        let value = parsed
            .params
            .iter()
            .find(|param| param.name == "value")
            .and_then(|param| param.value.clone().into_uint())
            .unwrap_or_default();

        if to == Some(protocol) {
            flows.total_in_f64 += u256_to_f64(value);
            flows.collateral_f64 += u256_to_f64(value);
            *flows
                .incoming_by_token
                .entry(log.address)
                .or_insert_with(U256::zero) += value;
        }
        if from == Some(protocol) {
            flows.total_out_f64 += u256_to_f64(value);
            *flows
                .outgoing_by_token
                .entry(log.address)
                .or_insert_with(U256::zero) += value;
        }
    }

    flows.shares_in_f64 = flows.total_in_f64;
    Ok(flows)
}

async fn expected_output<M: Middleware + Clone + 'static>(
    protocol: Address,
    provider: &M,
    user: Address,
    protocol_type: ProtocolType,
    flows: &TokenFlows,
    block_number: Option<u64>,
    protocol_definition: Option<&ProtocolDefinition>,
) -> Result<Option<f64>>
where
    <M as Middleware>::Error: 'static,
{
    match protocol_type {
        ProtocolType::Amm => {
            simulate_amm_output(protocol, provider, flows, block_number, protocol_definition).await
        }
        ProtocolType::Lending => {
            get_max_borrowable(protocol, provider, user, flows, block_number).await
        }
        ProtocolType::Vault => get_share_value(protocol, provider, flows, block_number).await,
        ProtocolType::Unknown => Ok(None),
    }
}

async fn expected_output_from_prestate(
    protocol: Address,
    fork: &ForkContext,
    user: Address,
    protocol_type: ProtocolType,
    flows: &TokenFlows,
    protocol_definition: Option<&ProtocolDefinition>,
) -> Result<Option<f64>> {
    expected_output(
        protocol,
        &fork.provider,
        user,
        protocol_type,
        flows,
        Some(fork.fork_block_number),
        protocol_definition,
    )
    .await
}

async fn simulate_amm_output<M: Middleware + Clone + 'static>(
    protocol: Address,
    provider: &M,
    flows: &TokenFlows,
    block_number: Option<u64>,
    protocol_definition: Option<&ProtocolDefinition>,
) -> Result<Option<f64>>
where
    <M as Middleware>::Error: 'static,
{
    let abi = AbiParser::default().parse(&[
        "function getReserves() view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)",
        "function token0() view returns (address)",
        "function token1() view returns (address)",
    ])?;
    if flows.incoming_by_token.len() != 1 || flows.outgoing_by_token.len() != 1 {
        return Ok(None);
    }

    let token_in = *flows
        .incoming_by_token
        .keys()
        .next()
        .ok_or_else(|| anyhow!("missing AMM input token"))?;
    let token_out = *flows
        .outgoing_by_token
        .keys()
        .next()
        .ok_or_else(|| anyhow!("missing AMM output token"))?;

    let amount_in = *flows
        .incoming_by_token
        .get(&token_in)
        .unwrap_or(&U256::zero());
    if let Some(profile) = protocol_definition.and_then(|protocol| protocol.simulation.as_ref()) {
        if let Some(expected) = quote_expected_output(
            provider,
            profile,
            token_in,
            token_out,
            amount_in,
            block_number,
        )
        .await?
        {
            return Ok(Some(u256_to_f64(expected)));
        }
    }

    let contract = ethers::contract::Contract::new(protocol, abi, Arc::new(provider.clone()));
    let mut reserves_call = contract.method::<_, (u128, u128, u32)>("getReserves", ())?;
    let mut token0_call = contract.method::<_, Address>("token0", ())?;
    let mut token1_call = contract.method::<_, Address>("token1", ())?;
    if let Some(block_number) = block_number {
        reserves_call = reserves_call.block(block_number);
        token0_call = token0_call.block(block_number);
        token1_call = token1_call.block(block_number);
    }
    let reserves = reserves_call.call().await?;
    let token0 = token0_call.call().await?;
    let token1 = token1_call.call().await?;

    let amount_in = u256_to_f64(amount_in);
    let (reserve_in, reserve_out) = if token_in == token0 && token_out == token1 {
        (reserves.0 as f64, reserves.1 as f64)
    } else if token_in == token1 && token_out == token0 {
        (reserves.1 as f64, reserves.0 as f64)
    } else {
        return Ok(None);
    };

    if reserve_in <= 0.0 || reserve_out <= 0.0 || amount_in <= 0.0 {
        return Ok(None);
    }

    let amount_in_with_fee = amount_in * 0.997;
    let expected = (amount_in_with_fee * reserve_out) / (reserve_in + amount_in_with_fee);
    Ok(Some(expected))
}

async fn get_max_borrowable<M: Middleware + Clone + 'static>(
    protocol: Address,
    provider: &M,
    user: Address,
    flows: &TokenFlows,
    block_number: Option<u64>,
) -> Result<Option<f64>>
where
    <M as Middleware>::Error: 'static,
{
    let abi = AbiParser::default().parse(&[
        "function getUserAccountData(address user) view returns (uint256 totalCollateralBase, uint256 totalDebtBase, uint256 availableBorrowsBase, uint256 currentLiquidationThreshold, uint256 ltv, uint256 healthFactor)",
    ])?;
    let contract = ethers::contract::Contract::new(protocol, abi, Arc::new(provider.clone()));
    let mut call =
        contract.method::<_, (U256, U256, U256, U256, U256, U256)>("getUserAccountData", user)?;
    if let Some(block_number) = block_number {
        call = call.block(block_number);
    }
    let result: (U256, U256, U256, U256, U256, U256) = match call.call().await {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let available = u256_to_f64(result.2);
    if available <= 0.0 {
        return Ok(None);
    }
    Ok(Some(available.min(flows.total_out_f64.max(available))))
}

async fn get_share_value<M: Middleware + Clone + 'static>(
    protocol: Address,
    provider: &M,
    flows: &TokenFlows,
    block_number: Option<u64>,
) -> Result<Option<f64>>
where
    <M as Middleware>::Error: 'static,
{
    let abi = AbiParser::default().parse(&[
        "function convertToAssets(uint256 shares) view returns (uint256)",
        "function previewRedeem(uint256 shares) view returns (uint256)",
    ])?;
    let contract =
        ethers::contract::Contract::new(protocol, abi.clone(), Arc::new(provider.clone()));
    let shares = U256::from(flows.shares_in_f64.max(0.0) as u128);

    let mut convert = contract.method::<_, U256>("convertToAssets", shares)?;
    let mut preview = contract.method::<_, U256>("previewRedeem", shares)?;
    if let Some(block_number) = block_number {
        convert = convert.block(block_number);
        preview = preview.block(block_number);
    }

    if let Ok(value) = convert.call().await {
        return Ok(Some(u256_to_f64(value)));
    }
    if let Ok(value) = preview.call().await {
        return Ok(Some(u256_to_f64(value)));
    }

    Ok(None)
}

async fn supports_function<M: Middleware + Clone + 'static>(
    provider: &M,
    address: Address,
    abi: &ethers::abi::Abi,
    function_name: &str,
) -> bool
where
    <M as Middleware>::Error: 'static,
{
    let Ok(function) = abi.function(function_name) else {
        return false;
    };
    let Ok(calldata) = function.encode_input(&[]) else {
        return false;
    };
    let tx: TypedTransaction = TransactionRequest {
        to: Some(NameOrAddress::Address(address)),
        data: Some(Bytes::from(calldata)),
        ..Default::default()
    }
    .into();
    provider.call(&tx, None).await.is_ok()
}

fn u256_to_f64(value: U256) -> f64 {
    value.to_string().parse::<f64>().unwrap_or(0.0)
}
