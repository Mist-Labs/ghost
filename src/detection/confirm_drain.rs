use crate::config::Config;
use crate::simulation::ForkContext;
use anyhow::{anyhow, Result};
use ethers::abi::AbiParser;
use ethers::providers::Middleware;
use ethers::types::{Address, BlockId, Transaction, H256, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DrainResult {
    pub confirmed: bool,
    pub pct_drained: f64,
    pub absolute_loss: u128,
    pub reason: Option<String>,
}

pub async fn confirm_drain<M: Middleware + Clone + 'static>(
    tx: &Transaction,
    provider: &M,
    config: &Config,
) -> Result<DrainResult>
where
    <M as Middleware>::Error: 'static,
{
    let protocol = tx
        .to
        .ok_or_else(|| anyhow!("transaction is missing a protocol target address"))?;
    let block_number = tx
        .block_number
        .ok_or_else(|| anyhow!("transaction is missing a mined block number"))?;
    let receipt = provider
        .get_transaction_receipt(tx.hash)
        .await?
        .ok_or_else(|| anyhow!("transaction receipt not found"))?;
    let native_balance_delta = native_balance_delta(provider, protocol, block_number.as_u64()).await?;

    if let Ok(fork) = ForkContext::spawn(config, block_number.as_u64().saturating_sub(1)).await {
        if let Ok(simulated_receipt) = fork.replay_transaction(tx).await {
            if let Ok(result) = assess_drain_from_logs(
                protocol,
                tx,
                &simulated_receipt.logs,
                |token| fork.token_balance(token, protocol, Some(fork.fork_block_number)),
                || fork.native_balance(protocol, Some(fork.fork_block_number)),
            )
            .await
            {
                return Ok(merge_native_balance_delta(DrainResult {
                    reason: result.reason.map(|reason| format!("fork_replay:{reason}")),
                    ..result
                }, native_balance_delta));
            }
        }
    }

    let result = assess_drain_from_logs(
        protocol,
        tx,
        &receipt.logs,
        |token| async move {
            token_balance_at(
                provider,
                token,
                protocol,
                block_number.as_u64().saturating_sub(1),
            )
            .await
        },
        || async move {
            Ok(provider
                .get_balance(
                    protocol,
                    Some(BlockId::Number(
                        block_number.as_u64().saturating_sub(1).into(),
                    )),
                )
                .await?)
        },
    )
    .await?;

    Ok(merge_native_balance_delta(result, native_balance_delta))
}

async fn assess_drain_from_logs<
    TokenBalanceFuture,
    NativeBalanceFuture,
    TokenBalanceFn,
    NativeBalanceFn,
>(
    protocol: Address,
    tx: &Transaction,
    logs: &[ethers::types::Log],
    mut token_balance_fn: TokenBalanceFn,
    native_balance_fn: NativeBalanceFn,
) -> Result<DrainResult>
where
    TokenBalanceFuture: std::future::Future<Output = Result<U256>>,
    NativeBalanceFuture: std::future::Future<Output = Result<U256>>,
    TokenBalanceFn: FnMut(Address) -> TokenBalanceFuture,
    NativeBalanceFn: FnOnce() -> NativeBalanceFuture,
{
    let mut highest_pct = 0.0_f64;
    let mut absolute_loss = 0_u128;
    let mut reasons = Vec::new();

    for (token, amount_out) in protocol_token_outflows(protocol, logs)? {
        let balance_before = token_balance_fn(token).await?;
        if balance_before.is_zero() {
            continue;
        }

        let pct = ratio(amount_out, balance_before);
        if pct > highest_pct {
            highest_pct = pct;
        }
        if pct > 0.0 {
            absolute_loss = absolute_loss.saturating_add(amount_out.as_u128());
            reasons.push(format!("{token:?}:{pct:.4}"));
        }
    }

    if let Some(value) = native_outflow(protocol, tx) {
        let balance_before = native_balance_fn().await?;
        if !balance_before.is_zero() {
            let pct = ratio(value, balance_before);
            if pct > highest_pct {
                highest_pct = pct;
            }
            absolute_loss = absolute_loss.saturating_add(value.as_u128());
            reasons.push(format!("native:{pct:.4}"));
        }
    }

    Ok(DrainResult {
        confirmed: highest_pct >= 0.10,
        pct_drained: highest_pct,
        absolute_loss,
        reason: (!reasons.is_empty()).then(|| reasons.join(",")),
    })
}

fn protocol_token_outflows(
    protocol: Address,
    logs: &[ethers::types::Log],
) -> Result<HashMap<Address, U256>> {
    let abi = AbiParser::default()
        .parse(&["event Transfer(address indexed from, address indexed to, uint256 value)"])?;
    let event = abi.event("Transfer")?.clone();
    let signature = H256::from_slice(event.signature().as_bytes());
    let mut flows = HashMap::new();

    for log in logs {
        if log.topics.first() != Some(&signature) {
            continue;
        }
        let parsed = event.parse_log(ethers::abi::RawLog {
            topics: log.topics.clone(),
            data: log.data.to_vec(),
        })?;
        let from = parsed
            .params
            .iter()
            .find(|param| param.name == "from")
            .and_then(|param| param.value.clone().into_address());
        let value = parsed
            .params
            .iter()
            .find(|param| param.name == "value")
            .and_then(|param| param.value.clone().into_uint())
            .unwrap_or_default();

        if from == Some(protocol) {
            let entry = flows.entry(log.address).or_insert_with(U256::zero);
            *entry += value;
        }
    }

    Ok(flows)
}

async fn token_balance_at<M: Middleware + Clone + 'static>(
    provider: &M,
    token: Address,
    account: Address,
    block_number: u64,
) -> Result<U256>
where
    <M as Middleware>::Error: 'static,
{
    let abi = AbiParser::default()
        .parse(&["function balanceOf(address account) view returns (uint256)"])?;
    let contract = ethers::contract::Contract::new(token, abi, Arc::new(provider.clone()));
    let balance = contract
        .method::<_, U256>("balanceOf", account)?
        .block(BlockId::Number(block_number.into()))
        .call()
        .await?;
    Ok(balance)
}

fn native_outflow(protocol: Address, tx: &Transaction) -> Option<U256> {
    (tx.from == protocol)
        .then_some(tx.value)
        .filter(|value| !value.is_zero())
}

async fn native_balance_delta<M: Middleware + Clone + 'static>(
    provider: &M,
    protocol: Address,
    block_number: u64,
) -> Result<Option<(f64, u128, String)>>
where
    <M as Middleware>::Error: 'static,
{
    let balance_before = provider
        .get_balance(
            protocol,
            Some(BlockId::Number(block_number.saturating_sub(1).into())),
        )
        .await?;
    if balance_before.is_zero() {
        return Ok(None);
    }

    let balance_after = provider
        .get_balance(protocol, Some(BlockId::Number(block_number.into())))
        .await?;

    if balance_after >= balance_before {
        return Ok(None);
    }

    let loss = balance_before - balance_after;
    let pct = ratio(loss, balance_before);
    Ok(Some((
        pct,
        loss.as_u128(),
        format!("native_balance_delta:{pct:.4}"),
    )))
}

fn merge_native_balance_delta(
    mut result: DrainResult,
    native_delta: Option<(f64, u128, String)>,
) -> DrainResult {
    let Some((pct, absolute_loss, reason)) = native_delta else {
        return result;
    };

    if pct > result.pct_drained {
        result.pct_drained = pct;
    }
    result.absolute_loss = result.absolute_loss.saturating_add(absolute_loss);
    result.confirmed |= pct >= 0.10;
    result.reason = match result.reason.take() {
        Some(existing) => Some(format!("{existing},{reason}")),
        None => Some(reason),
    };
    result
}

fn ratio(numerator: U256, denominator: U256) -> f64 {
    if denominator.is_zero() {
        return 0.0;
    }
    numerator.to_string().parse::<f64>().unwrap_or(0.0)
        / denominator.to_string().parse::<f64>().unwrap_or(1.0)
}
