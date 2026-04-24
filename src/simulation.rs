use crate::config::Config;
use crate::protocols::{
    FlashLoanProviderDefinition, FlashLoanProviderKind, MarketPathDefinition, ProtocolDefinition,
    RouterKind, RouterSimulationDefinition, SimulationProfile,
};
use anyhow::{anyhow, Context, Result};
use ethers::abi::AbiParser;
use ethers::contract::Contract;
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::{
    Address, BlockId, BlockNumber, Bytes, Transaction, TransactionReceipt, H256, I256, U256, U64,
};
use ethers::utils::{Anvil, AnvilInstance};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_FORK_BALANCE_WEI: &str = "1000000000000000000000000";
const DEFAULT_MARKET_PROBE_AMOUNT: &str = "1000000000000000000";

#[derive(Debug, Clone, Serialize)]
pub struct SimulationProfileValidation {
    pub healthy: bool,
    pub checked_block_number: u64,
    pub warnings: Vec<String>,
    pub routers: Vec<RouterValidationStatus>,
    pub whales: Vec<WhaleValidationStatus>,
    pub flash_loan_providers: Vec<FlashLoanValidationStatus>,
    pub market_paths: Vec<MarketPathValidationStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouterValidationStatus {
    pub kind: String,
    pub address: String,
    pub deployed: bool,
    pub quoter_address: Option<String>,
    pub quoter_deployed: Option<bool>,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WhaleValidationStatus {
    pub token: String,
    pub holder: Option<String>,
    pub required_amount: String,
    pub observed_balance: Option<String>,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlashLoanValidationStatus {
    pub kind: String,
    pub address: String,
    pub asset: String,
    pub deployed: bool,
    pub configured_max_loan_amount: Option<String>,
    pub observed_available: Option<String>,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MarketPathValidationStatus {
    pub label: String,
    pub router_kind: String,
    pub token_in: String,
    pub token_out: String,
    pub amount_in: String,
    pub quote_available: bool,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MarketSimulationProbe {
    pub path_label: Option<String>,
    pub router_kind: Option<String>,
    pub token_in: String,
    pub token_out: String,
    pub amount_in: String,
    pub quoted_output: Option<String>,
    pub executed_output: Option<String>,
    pub route_executable: bool,
    pub flash_loan_provider: Option<String>,
    pub flash_loan_available: bool,
    pub flash_loan_liquidity: Option<String>,
    pub reason: String,
}

pub struct ForkContext {
    _instance: AnvilInstance,
    pub provider: Provider<Http>,
    pub fork_block_number: u64,
}

impl ForkContext {
    pub async fn spawn(config: &Config, fork_block_number: u64) -> Result<Self> {
        let rpc_url = config.alchemy_http_url.clone();
        let chain_id = config.chain_id;
        let program = config.anvil_binary.clone();
        let timeout_ms = config.simulation_startup_timeout_secs.saturating_mul(1000);

        let instance = tokio::task::spawn_blocking(move || {
            std::panic::catch_unwind(|| {
                Anvil::at(program)
                    .fork(rpc_url)
                    .fork_block_number(fork_block_number)
                    .chain_id(chain_id)
                    .timeout(timeout_ms)
                    .arg("--steps-tracing")
                    .spawn()
            })
            .map_err(|_| anyhow!("failed to start anvil fork"))
        })
        .await
        .context("anvil spawn task failed")??;

        let provider = Provider::<Http>::try_from(instance.endpoint().as_str())
            .context("failed to connect to local anvil fork")?
            .interval(Duration::from_millis(100));

        Ok(Self {
            _instance: instance,
            provider,
            fork_block_number,
        })
    }

    pub async fn replay_transaction(&self, tx: &Transaction) -> Result<TransactionReceipt> {
        self.impersonate(tx.from).await?;
        self.set_balance(
            tx.from,
            U256::from_dec_str(DEFAULT_FORK_BALANCE_WEI).expect("constant is valid"),
        )
        .await?;
        let receipt = self.send_transaction(build_transaction_payload(tx)).await;
        let _ = self.stop_impersonating(tx.from).await;
        receipt
    }

    pub async fn send_calldata_from(
        &self,
        from: Address,
        to: Address,
        calldata: Bytes,
        gas: Option<U256>,
    ) -> Result<TransactionReceipt> {
        self.impersonate(from).await?;
        self.set_balance(
            from,
            U256::from_dec_str(DEFAULT_FORK_BALANCE_WEI).expect("constant is valid"),
        )
        .await?;
        let payload = json!({
            "from": format!("{from:?}"),
            "to": format!("{to:?}"),
            "data": format!("0x{}", hex::encode(&calldata.0)),
            "gas": gas.map(hex_quantity).unwrap_or_else(|| "0x5b8d80".to_string()),
            "value": "0x0",
        });
        let receipt = self.send_transaction(payload).await;
        let _ = self.stop_impersonating(from).await;
        receipt
    }

    pub async fn transfer_erc20_from(
        &self,
        token: Address,
        from: Address,
        to: Address,
        amount: U256,
    ) -> Result<TransactionReceipt> {
        let abi = AbiParser::default()
            .parse(&["function transfer(address to, uint256 amount) returns (bool)"])?;
        let contract = Contract::new(token, abi, Arc::new(self.provider.clone()));
        let calldata = contract
            .method::<_, bool>("transfer", (to, amount))?
            .calldata()
            .ok_or_else(|| anyhow!("failed to encode ERC20 transfer calldata"))?;
        self.send_calldata_from(from, token, calldata, Some(U256::from(300_000_u64)))
            .await
    }

    pub async fn approve_erc20_from(
        &self,
        token: Address,
        owner: Address,
        spender: Address,
        amount: U256,
    ) -> Result<TransactionReceipt> {
        let abi = AbiParser::default()
            .parse(&["function approve(address spender, uint256 amount) returns (bool)"])?;
        let contract = Contract::new(token, abi, Arc::new(self.provider.clone()));
        let calldata = contract
            .method::<_, bool>("approve", (spender, amount))?
            .calldata()
            .ok_or_else(|| anyhow!("failed to encode ERC20 approve calldata"))?;
        self.send_calldata_from(owner, token, calldata, Some(U256::from(300_000_u64)))
            .await
    }

    pub async fn token_balance(
        &self,
        token: Address,
        account: Address,
        block_number: Option<u64>,
    ) -> Result<U256> {
        let abi = AbiParser::default()
            .parse(&["function balanceOf(address account) view returns (uint256)"])?;
        let contract = Contract::new(token, abi, Arc::new(self.provider.clone()));
        let mut call = contract.method::<_, U256>("balanceOf", account)?;
        if let Some(block_number) = block_number {
            call = call.block(BlockId::Number(BlockNumber::Number(block_number.into())));
        }
        Ok(call.call().await?)
    }

    pub async fn native_balance(
        &self,
        account: Address,
        block_number: Option<u64>,
    ) -> Result<U256> {
        let block = block_number.map(|number| BlockId::Number(BlockNumber::Number(number.into())));
        Ok(self.provider.get_balance(account, block).await?)
    }

    async fn send_transaction(&self, payload: serde_json::Value) -> Result<TransactionReceipt> {
        let tx_hash = self
            .provider
            .request::<_, H256>("eth_sendTransaction", (payload,))
            .await
            .context("fork transaction submission failed")?;

        for _ in 0..80 {
            if let Some(receipt) = self.provider.get_transaction_receipt(tx_hash).await? {
                return Ok(receipt);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Err(anyhow!(
            "timed out waiting for simulated transaction receipt {tx_hash:?}"
        ))
    }

    async fn impersonate(&self, address: Address) -> Result<()> {
        self.provider
            .request::<_, bool>("anvil_impersonateAccount", (address,))
            .await
            .context("failed to impersonate account on anvil fork")?;
        Ok(())
    }

    async fn stop_impersonating(&self, address: Address) -> Result<()> {
        self.provider
            .request::<_, bool>("anvil_stopImpersonatingAccount", (address,))
            .await
            .context("failed to stop impersonating account on anvil fork")?;
        Ok(())
    }

    async fn set_balance(&self, address: Address, balance: U256) -> Result<()> {
        self.provider
            .request::<_, bool>("anvil_setBalance", (address, hex_quantity(balance)))
            .await
            .context("failed to seed impersonated account balance on anvil fork")?;
        Ok(())
    }
}

pub async fn latest_block_number<M: Middleware>(provider: &M) -> Result<u64>
where
    <M as Middleware>::Error: 'static,
{
    Ok(provider.get_block_number().await?.as_u64())
}

pub async fn probe_market_liquidity(
    config: &Config,
    protocol: &ProtocolDefinition,
    fork_block_number: u64,
    token_in: Address,
    token_out: Address,
    amount_in: Option<U256>,
) -> Result<Option<MarketSimulationProbe>> {
    let Some(profile) = protocol.simulation.as_ref() else {
        return Ok(None);
    };
    let amount_in = amount_in.unwrap_or(U256::from_dec_str(DEFAULT_MARKET_PROBE_AMOUNT)?);
    let fork = ForkContext::spawn(config, fork_block_number).await?;
    run_market_probe_on_fork(&fork, profile, token_in, token_out, amount_in).await
}

pub async fn validate_protocol_simulation_profile<M: Middleware + Clone + 'static>(
    provider: &M,
    protocol: &ProtocolDefinition,
) -> Result<Option<SimulationProfileValidation>>
where
    <M as Middleware>::Error: 'static,
{
    let Some(profile) = protocol.simulation.as_ref() else {
        return Ok(None);
    };

    let checked_block_number = latest_block_number(provider).await?;
    let block = Some(checked_block_number);
    let mut warnings = Vec::new();
    let mut routers = Vec::new();
    let mut whales = Vec::new();
    let mut flash_loan_providers = Vec::new();
    let mut market_paths = Vec::new();
    let required_whale_amounts = required_whale_amounts(profile)?;

    for router in &profile.routers {
        let deployed = address_has_code(provider, router.address, block)
            .await
            .unwrap_or(false);
        let path_count = profile
            .market_paths
            .iter()
            .filter(|path| path.router_kind == router.kind)
            .count();
        let quoter_deployed = if router.kind == RouterKind::UniswapV3 {
            match router.quoter {
                Some(address) => Some(
                    address_has_code(provider, address, block)
                        .await
                        .unwrap_or(false),
                ),
                None => None,
            }
        } else {
            None
        };

        if !deployed {
            warnings.push(format!(
                "simulation router {} at {:?} has no deployed code",
                router_kind_label(router.kind),
                router.address
            ));
        }
        if path_count > 0 && router.kind == RouterKind::UniswapV3 && router.quoter.is_none() {
            warnings.push(format!(
                "simulation router {} at {:?} is missing a quoter for configured v3 paths",
                router_kind_label(router.kind),
                router.address
            ));
        }
        if path_count > 0 && router.kind == RouterKind::Aerodrome && router.factory.is_none() {
            warnings.push(format!(
                "simulation router {} at {:?} is missing a factory for configured routes",
                router_kind_label(router.kind),
                router.address
            ));
        }
        if path_count > 0 && matches!(quoter_deployed, Some(false)) {
            warnings.push(format!(
                "simulation quoter for {} at {:?} has no deployed code",
                router_kind_label(router.kind),
                router.quoter.expect("checked above")
            ));
        }

        routers.push(RouterValidationStatus {
            kind: router_kind_label(router.kind).to_string(),
            address: format!("{:?}", router.address),
            deployed,
            quoter_address: router.quoter.map(|address| format!("{address:?}")),
            quoter_deployed,
            healthy: deployed
                && !(path_count > 0
                    && router.kind == RouterKind::UniswapV3
                    && matches!(quoter_deployed, Some(false) | None))
                && !(path_count > 0
                    && router.kind == RouterKind::Aerodrome
                    && router.factory.is_none()),
        });
    }

    for (token, required_amount) in required_whale_amounts {
        let whale = profile
            .token_whales
            .iter()
            .find(|whale| whale.token == token);
        match whale {
            Some(whale) => {
                let observed_balance = erc20_balance_of(provider, token, whale.holder, block)
                    .await
                    .ok();
                if observed_balance
                    .map(|balance| balance < required_amount)
                    .unwrap_or(true)
                {
                    warnings.push(format!(
                        "simulation whale {:?} for token {:?} is below required probe balance {}",
                        whale.holder, token, required_amount
                    ));
                }
                whales.push(WhaleValidationStatus {
                    token: format!("{token:?}"),
                    holder: Some(format!("{:?}", whale.holder)),
                    required_amount: required_amount.to_string(),
                    observed_balance: observed_balance.map(|balance| balance.to_string()),
                    healthy: observed_balance
                        .map(|balance| balance >= required_amount)
                        .unwrap_or(false),
                });
            }
            None => {
                warnings.push(format!(
                    "simulation profile has no whale configured for token {:?}",
                    token
                ));
                whales.push(WhaleValidationStatus {
                    token: format!("{token:?}"),
                    holder: None,
                    required_amount: required_amount.to_string(),
                    observed_balance: None,
                    healthy: false,
                });
            }
        }
    }

    for flash in &profile.flash_loan_providers {
        let deployed = address_has_code(provider, flash.address, block)
            .await
            .unwrap_or(false);
        let observed_available = observed_flash_loan_available(provider, flash, block)
            .await
            .ok();
        let configured_max_loan_amount = flash.max_loan_amount.clone();
        let configured_max = configured_max_loan_amount
            .as_deref()
            .map(U256::from_dec_str)
            .transpose()?;

        if !deployed {
            warnings.push(format!(
                "flash-loan provider {:?} at {:?} has no deployed code",
                flash.kind, flash.address
            ));
        }
        if let Some(configured_max) = configured_max {
            if observed_available
                .map(|observed| observed < configured_max)
                .unwrap_or(true)
            {
                warnings.push(format!(
                    "configured max_loan_amount {} for {:?} exceeds observed liquidity",
                    configured_max, flash.address
                ));
            }
        } else if observed_available
            .map(|value| value.is_zero())
            .unwrap_or(true)
        {
            warnings.push(format!(
                "flash-loan provider {:?} at {:?} has no observable liquidity",
                flash.kind, flash.address
            ));
        }

        flash_loan_providers.push(FlashLoanValidationStatus {
            kind: format!("{:?}", flash.kind),
            address: format!("{:?}", flash.address),
            asset: format!("{:?}", flash.asset),
            deployed,
            configured_max_loan_amount,
            observed_available: observed_available.map(|value| value.to_string()),
            healthy: deployed
                && observed_available
                    .map(|observed| {
                        configured_max
                            .map(|configured| observed >= configured)
                            .unwrap_or(!observed.is_zero())
                    })
                    .unwrap_or(false),
        });
    }

    for path in &profile.market_paths {
        let amount_in = parse_market_probe_amount(path.amount_in.as_deref())?;
        let router = profile
            .routers
            .iter()
            .find(|router| router.kind == path.router_kind);
        let quote_available = if let Some(router) = router {
            quote_market_path(provider, router, path, amount_in, block)
                .await?
                .is_some()
        } else {
            false
        };

        if router.is_none() {
            warnings.push(format!(
                "simulation path {} references missing {} router config",
                path.label,
                router_kind_label(path.router_kind)
            ));
        } else if !quote_available {
            warnings.push(format!(
                "simulation path {} is no longer quotable on {}",
                path.label,
                router_kind_label(path.router_kind)
            ));
        }

        market_paths.push(MarketPathValidationStatus {
            label: path.label.clone(),
            router_kind: router_kind_label(path.router_kind).to_string(),
            token_in: format!("{:?}", path.token_in),
            token_out: format!("{:?}", path.token_out),
            amount_in: amount_in.to_string(),
            quote_available,
            healthy: router.is_some() && quote_available,
        });
    }

    Ok(Some(SimulationProfileValidation {
        healthy: warnings.is_empty(),
        checked_block_number,
        warnings,
        routers,
        whales,
        flash_loan_providers,
        market_paths,
    }))
}

pub async fn quote_expected_output<M: Middleware + Clone + 'static>(
    provider: &M,
    profile: &SimulationProfile,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    block_number: Option<u64>,
) -> Result<Option<U256>>
where
    <M as Middleware>::Error: 'static,
{
    let mut best: Option<U256> = None;
    for path in matching_paths(profile, token_in, token_out) {
        let Some(router) = profile
            .routers
            .iter()
            .find(|router| router.kind == path.router_kind)
        else {
            continue;
        };

        let quote = match path.router_kind {
            RouterKind::UniswapV2 => {
                quote_uniswap_v2(provider, router.address, path, amount_in, block_number).await?
            }
            RouterKind::UniswapV3 => {
                quote_uniswap_v3(provider, router.quoter, path, amount_in, block_number).await?
            }
            RouterKind::Aerodrome => {
                quote_aerodrome(provider, router, path, amount_in, block_number).await?
            }
            RouterKind::BalancerV2 => {
                quote_balancer_v2(provider, router.address, path, amount_in, block_number).await?
            }
        };

        if let Some(quote) = quote {
            if best.map(|current| quote > current).unwrap_or(true) {
                best = Some(quote);
            }
        }
    }

    Ok(best)
}

pub fn hex_quantity(value: U256) -> String {
    format!("0x{:x}", value)
}

pub fn build_transaction_payload(tx: &Transaction) -> serde_json::Value {
    let mut payload = serde_json::Map::new();
    payload.insert("from".into(), json!(format!("{:?}", tx.from)));

    if let Some(to) = tx.to {
        payload.insert("to".into(), json!(format!("{to:?}")));
    }
    if !tx.input.0.is_empty() {
        payload.insert(
            "data".into(),
            json!(format!("0x{}", hex::encode(&tx.input.0))),
        );
    }
    payload.insert("value".into(), json!(hex_quantity(tx.value)));
    payload.insert("gas".into(), json!(hex_quantity(tx.gas)));
    payload.insert("nonce".into(), json!(hex_quantity(tx.nonce)));

    if let Some(transaction_type) = tx.transaction_type {
        payload.insert(
            "type".into(),
            json!(hex_quantity(U256::from(transaction_type.as_u64()))),
        );
    }
    if tx.transaction_type == Some(U64::from(2)) || tx.max_fee_per_gas.is_some() {
        if let Some(value) = tx.max_fee_per_gas {
            payload.insert("maxFeePerGas".into(), json!(hex_quantity(value)));
        }
        if let Some(value) = tx.max_priority_fee_per_gas {
            payload.insert("maxPriorityFeePerGas".into(), json!(hex_quantity(value)));
        }
    } else if let Some(gas_price) = tx.gas_price {
        payload.insert("gasPrice".into(), json!(hex_quantity(gas_price)));
    }
    if let Some(access_list) = &tx.access_list {
        payload.insert(
            "accessList".into(),
            serde_json::to_value(access_list).unwrap_or_else(|_| json!([])),
        );
    }

    serde_json::Value::Object(payload)
}

pub async fn call_on_fork(
    config: &Config,
    fork_block_number: u64,
    to: Address,
    calldata: Bytes,
    gas: Option<U256>,
) -> Result<TransactionReceipt> {
    let fork = ForkContext::spawn(config, fork_block_number).await?;
    fork.send_calldata_from(Address::from_low_u64_be(0xdead), to, calldata, gas)
        .await
}

async fn run_market_probe_on_fork(
    fork: &ForkContext,
    profile: &SimulationProfile,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
) -> Result<Option<MarketSimulationProbe>> {
    let caller = Address::from_low_u64_be(0xbeef);
    let flash = select_flash_loan_liquidity(
        &fork.provider,
        profile,
        token_in,
        Some(fork.fork_block_number),
    )
    .await?;

    let mut best_probe: Option<MarketSimulationProbe> = None;
    for path in matching_paths(profile, token_in, token_out) {
        let Some(router) = profile
            .routers
            .iter()
            .find(|router| router.kind == path.router_kind)
        else {
            continue;
        };

        if ensure_token_balance_on_fork(fork, profile, caller, token_in, amount_in)
            .await
            .is_err()
        {
            continue;
        }
        let _ = fork
            .approve_erc20_from(token_in, caller, router.address, amount_in)
            .await?;

        let quoted_output = match path.router_kind {
            RouterKind::UniswapV2 => {
                quote_uniswap_v2(
                    &fork.provider,
                    router.address,
                    path,
                    amount_in,
                    Some(fork.fork_block_number),
                )
                .await?
            }
            RouterKind::UniswapV3 => {
                quote_uniswap_v3(
                    &fork.provider,
                    router.quoter,
                    path,
                    amount_in,
                    Some(fork.fork_block_number),
                )
                .await?
            }
            RouterKind::Aerodrome => {
                quote_aerodrome(
                    &fork.provider,
                    router,
                    path,
                    amount_in,
                    Some(fork.fork_block_number),
                )
                .await?
            }
            RouterKind::BalancerV2 => {
                quote_balancer_v2(
                    &fork.provider,
                    router.address,
                    path,
                    amount_in,
                    Some(fork.fork_block_number),
                )
                .await?
            }
        };
        let balance_before = fork
            .token_balance(token_out, caller, Some(fork.fork_block_number))
            .await
            .unwrap_or_default();
        let execution = execute_market_path(fork, router, path, caller, amount_in).await;
        let balance_after = fork
            .token_balance(token_out, caller, None)
            .await
            .unwrap_or_default();
        let executed_output = balance_after.saturating_sub(balance_before);
        let route_executable = execution
            .as_ref()
            .map(|receipt| receipt.status == Some(1u64.into()))
            .unwrap_or(false)
            && executed_output > U256::zero();

        let probe = MarketSimulationProbe {
            path_label: Some(path.label.clone()),
            router_kind: Some(router_kind_label(path.router_kind).to_string()),
            token_in: format!("{token_in:?}"),
            token_out: format!("{token_out:?}"),
            amount_in: amount_in.to_string(),
            quoted_output: quoted_output.map(|value| value.to_string()),
            executed_output: route_executable.then(|| executed_output.to_string()),
            route_executable,
            flash_loan_provider: flash
                .as_ref()
                .and_then(|liquidity| liquidity.provider_name.clone()),
            flash_loan_available: flash
                .as_ref()
                .map(|liquidity| liquidity.available >= amount_in)
                .unwrap_or(false),
            flash_loan_liquidity: flash
                .as_ref()
                .map(|liquidity| liquidity.available.to_string()),
            reason: if route_executable {
                "configured_market_path_executed_on_fork".into()
            } else {
                "configured_market_path_not_executable".into()
            },
        };

        if probe.route_executable {
            return Ok(Some(probe));
        }
        if best_probe.is_none() {
            best_probe = Some(probe);
        }
    }

    Ok(best_probe)
}

async fn ensure_token_balance_on_fork(
    fork: &ForkContext,
    profile: &SimulationProfile,
    recipient: Address,
    token: Address,
    amount: U256,
) -> Result<()> {
    let current = fork.token_balance(token, recipient, None).await?;
    if current >= amount {
        return Ok(());
    }
    let whale = profile
        .token_whales
        .iter()
        .find(|whale| whale.token == token)
        .ok_or_else(|| anyhow!("no configured whale for token {token:?}"))?;
    let receipt = fork
        .transfer_erc20_from(token, whale.holder, recipient, amount)
        .await?;
    if receipt.status != Some(1u64.into()) {
        return Err(anyhow!("whale token funding transfer failed"));
    }
    Ok(())
}

async fn execute_market_path(
    fork: &ForkContext,
    router: &RouterSimulationDefinition,
    path: &MarketPathDefinition,
    caller: Address,
    amount_in: U256,
) -> Result<TransactionReceipt> {
    match path.router_kind {
        RouterKind::UniswapV2 => {
            execute_uniswap_v2_path(fork, router.address, path, caller, amount_in).await
        }
        RouterKind::UniswapV3 => {
            execute_uniswap_v3_path(fork, router.address, path, caller, amount_in).await
        }
        RouterKind::Aerodrome => {
            execute_aerodrome_path(fork, router, path, caller, amount_in).await
        }
        RouterKind::BalancerV2 => {
            execute_balancer_v2_path(fork, router.address, path, caller, amount_in).await
        }
    }
}

async fn execute_balancer_v2_path(
    fork: &ForkContext,
    vault: Address,
    path: &MarketPathDefinition,
    caller: Address,
    amount_in: U256,
) -> Result<TransactionReceipt> {
    let pool_ids = balancer_pool_ids(path)?;
    if pool_ids.len() != 1 {
        return Err(anyhow!(
            "Balancer v2 execution currently supports single-hop routes only"
        ));
    }

    let abi = AbiParser::default().parse(&[
        "function swap((bytes32 poolId,uint8 kind,address assetIn,address assetOut,uint256 amount,bytes userData) singleSwap,(address sender,bool fromInternalBalance,address recipient,bool toInternalBalance) funds,uint256 limit,uint256 deadline) payable returns (uint256)",
    ])?;
    let contract = Contract::new(vault, abi, Arc::new(fork.provider.clone()));
    let calldata = contract
        .method::<_, U256>(
            "swap",
            (
                (
                    pool_ids[0],
                    0_u8,
                    path.token_in,
                    path.token_out,
                    amount_in,
                    Bytes::default(),
                ),
                (caller, false, caller, false),
                amount_in,
                U256::from(chrono::Utc::now().timestamp().saturating_add(3600) as u64),
            ),
        )?
        .calldata()
        .ok_or_else(|| anyhow!("failed to encode Balancer v2 swap calldata"))?;
    fork.send_calldata_from(caller, vault, calldata, Some(U256::from(2_000_000_u64)))
        .await
}

async fn execute_aerodrome_path(
    fork: &ForkContext,
    router: &RouterSimulationDefinition,
    path: &MarketPathDefinition,
    caller: Address,
    amount_in: U256,
) -> Result<TransactionReceipt> {
    let abi = AbiParser::default().parse(&[
        "function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, (address from,address to,bool stable,address factory)[] routes, address to, uint256 deadline) returns (uint256[])",
    ])?;
    let contract = Contract::new(router.address, abi, Arc::new(fork.provider.clone()));
    let calldata = contract
        .method::<_, Vec<U256>>(
            "swapExactTokensForTokens",
            (
                amount_in,
                U256::zero(),
                aerodrome_routes(path, router)?,
                caller,
                U256::from(chrono::Utc::now().timestamp().saturating_add(3600) as u64),
            ),
        )?
        .calldata()
        .ok_or_else(|| anyhow!("failed to encode Aerodrome swap calldata"))?;
    fork.send_calldata_from(
        caller,
        router.address,
        calldata,
        Some(U256::from(2_000_000_u64)),
    )
    .await
}

async fn quote_aerodrome<M: Middleware + Clone + 'static>(
    provider: &M,
    router: &RouterSimulationDefinition,
    path: &MarketPathDefinition,
    amount_in: U256,
    block_number: Option<u64>,
) -> Result<Option<U256>>
where
    <M as Middleware>::Error: 'static,
{
    let abi = AbiParser::default().parse(&[
        "function getAmountsOut(uint256 amountIn, (address from,address to,bool stable,address factory)[] routes) view returns (uint256[])",
    ])?;
    let contract = Contract::new(router.address, abi, Arc::new(provider.clone()));
    let mut call = contract.method::<_, Vec<U256>>(
        "getAmountsOut",
        (amount_in, aerodrome_routes(path, router)?),
    )?;
    if let Some(block_number) = block_number {
        call = call.block(block_number);
    }
    match call.call().await {
        Ok(amounts) => Ok(amounts.last().copied()),
        Err(_) => Ok(None),
    }
}

async fn quote_balancer_v2<M: Middleware + Clone + 'static>(
    provider: &M,
    vault: Address,
    path: &MarketPathDefinition,
    amount_in: U256,
    block_number: Option<u64>,
) -> Result<Option<U256>>
where
    <M as Middleware>::Error: 'static,
{
    let abi = AbiParser::default().parse(&[
        "function queryBatchSwap(uint8 kind,(bytes32 poolId,uint256 assetInIndex,uint256 assetOutIndex,uint256 amount,bytes userData)[] swaps,address[] assets,(address sender,bool fromInternalBalance,address recipient,bool toInternalBalance) funds) returns (int256[])",
    ])?;
    let contract = Contract::new(vault, abi, Arc::new(provider.clone()));
    let assets = balancer_assets(path);
    let swaps = balancer_swaps(path, amount_in)?;
    let mut call = contract.method::<_, Vec<I256>>(
        "queryBatchSwap",
        (
            0_u8,
            swaps,
            assets.clone(),
            (Address::zero(), false, Address::zero(), false),
        ),
    )?;
    if let Some(block_number) = block_number {
        call = call.block(block_number);
    }

    match call.call().await {
        Ok(deltas) => Ok(deltas.last().and_then(|delta| {
            if delta.is_negative() {
                Some(delta.unsigned_abs())
            } else {
                None
            }
        })),
        Err(_) => Ok(None),
    }
}

fn aerodrome_routes(
    path: &MarketPathDefinition,
    router: &RouterSimulationDefinition,
) -> Result<Vec<(Address, Address, bool, Address)>> {
    let tokens = full_route(path);
    if tokens.len() < 2 {
        return Err(anyhow!("aerodrome path requires at least two tokens"));
    }
    let stable_hops = hop_stables(path)?;
    let factory = router.factory.unwrap_or_default();
    Ok(tokens
        .windows(2)
        .enumerate()
        .map(|(index, hop)| (hop[0], hop[1], stable_hops[index], factory))
        .collect())
}

fn hop_stables(path: &MarketPathDefinition) -> Result<Vec<bool>> {
    let hop_count = full_route(path).len().saturating_sub(1);
    if path.stable_hops.is_empty() {
        return Ok(vec![false; hop_count]);
    }
    if path.stable_hops.len() != hop_count {
        return Err(anyhow!(
            "stable_hops count must match route hop count for {}",
            path.label
        ));
    }
    Ok(path.stable_hops.clone())
}

fn full_route(path: &MarketPathDefinition) -> Vec<Address> {
    let mut route = vec![path.token_in];
    route.extend(path.intermediate_tokens.iter().copied());
    route.push(path.token_out);
    route
}

async fn execute_uniswap_v2_path(
    fork: &ForkContext,
    router: Address,
    path: &MarketPathDefinition,
    caller: Address,
    amount_in: U256,
) -> Result<TransactionReceipt> {
    let abi = AbiParser::default().parse(&[
        "function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline) returns (uint256[])",
    ])?;
    let route = v2_route(path);
    let contract = Contract::new(router, abi, Arc::new(fork.provider.clone()));
    let calldata = contract
        .method::<_, Vec<U256>>(
            "swapExactTokensForTokens",
            (
                amount_in,
                U256::zero(),
                route,
                caller,
                U256::from(chrono::Utc::now().timestamp().saturating_add(3600) as u64),
            ),
        )?
        .calldata()
        .ok_or_else(|| anyhow!("failed to encode Uniswap v2 swap calldata"))?;
    fork.send_calldata_from(caller, router, calldata, Some(U256::from(1_500_000_u64)))
        .await
}

async fn execute_uniswap_v3_path(
    fork: &ForkContext,
    router: Address,
    path: &MarketPathDefinition,
    caller: Address,
    amount_in: U256,
) -> Result<TransactionReceipt> {
    let abi = AbiParser::default().parse(&[
        "function exactInput((bytes path,address recipient,uint256 deadline,uint256 amountIn,uint256 amountOutMinimum)) payable returns (uint256)",
    ])?;
    let encoded_path = encode_uniswap_v3_path(path)?;
    let contract = Contract::new(router, abi, Arc::new(fork.provider.clone()));
    let calldata = contract
        .method::<_, U256>(
            "exactInput",
            (
                encoded_path,
                caller,
                U256::from(chrono::Utc::now().timestamp().saturating_add(3600) as u64),
                amount_in,
                U256::zero(),
            ),
        )?
        .calldata()
        .ok_or_else(|| anyhow!("failed to encode Uniswap v3 exactInput calldata"))?;
    fork.send_calldata_from(caller, router, calldata, Some(U256::from(2_000_000_u64)))
        .await
}

async fn quote_uniswap_v2<M: Middleware + Clone + 'static>(
    provider: &M,
    router: Address,
    path: &MarketPathDefinition,
    amount_in: U256,
    block_number: Option<u64>,
) -> Result<Option<U256>>
where
    <M as Middleware>::Error: 'static,
{
    let abi = AbiParser::default().parse(&[
        "function getAmountsOut(uint256 amountIn, address[] path) view returns (uint256[])",
    ])?;
    let contract = Contract::new(router, abi, Arc::new(provider.clone()));
    let mut call = contract.method::<_, Vec<U256>>("getAmountsOut", (amount_in, v2_route(path)))?;
    if let Some(block_number) = block_number {
        call = call.block(block_number);
    }
    match call.call().await {
        Ok(amounts) => Ok(amounts.last().copied()),
        Err(_) => Ok(None),
    }
}

async fn quote_uniswap_v3<M: Middleware + Clone + 'static>(
    provider: &M,
    quoter: Option<Address>,
    path: &MarketPathDefinition,
    amount_in: U256,
    block_number: Option<u64>,
) -> Result<Option<U256>>
where
    <M as Middleware>::Error: 'static,
{
    let Some(quoter) = quoter else {
        return Ok(None);
    };
    let abi = AbiParser::default().parse(&[
        "function quoteExactInput(bytes path, uint256 amountIn) returns (uint256 amountOut)",
    ])?;
    let contract = Contract::new(quoter, abi, Arc::new(provider.clone()));
    let mut call = contract.method::<_, U256>(
        "quoteExactInput",
        (encode_uniswap_v3_path(path)?, amount_in),
    )?;
    if let Some(block_number) = block_number {
        call = call.block(block_number);
    }
    match call.call().await {
        Ok(amount_out) => Ok(Some(amount_out)),
        Err(_) => Ok(None),
    }
}

async fn quote_market_path<M: Middleware + Clone + 'static>(
    provider: &M,
    router: &crate::protocols::RouterSimulationDefinition,
    path: &MarketPathDefinition,
    amount_in: U256,
    block_number: Option<u64>,
) -> Result<Option<U256>>
where
    <M as Middleware>::Error: 'static,
{
    match path.router_kind {
        RouterKind::UniswapV2 => {
            quote_uniswap_v2(provider, router.address, path, amount_in, block_number).await
        }
        RouterKind::UniswapV3 => {
            quote_uniswap_v3(provider, router.quoter, path, amount_in, block_number).await
        }
        RouterKind::Aerodrome => {
            quote_aerodrome(provider, router, path, amount_in, block_number).await
        }
        RouterKind::BalancerV2 => {
            quote_balancer_v2(provider, router.address, path, amount_in, block_number).await
        }
    }
}

fn v2_route(path: &MarketPathDefinition) -> Vec<Address> {
    full_route(path)
}

fn encode_uniswap_v3_path(path: &MarketPathDefinition) -> Result<Bytes> {
    let mut bytes = Vec::new();
    let mut route = vec![path.token_in];
    route.extend(path.intermediate_tokens.iter().copied());
    route.push(path.token_out);
    if route.len() < 2 {
        return Err(anyhow!("uniswap v3 path requires at least two tokens"));
    }
    let fees = if path.fee_tiers.is_empty() {
        vec![500_u32; route.len().saturating_sub(1)]
    } else {
        path.fee_tiers.clone()
    };
    if fees.len() != route.len().saturating_sub(1) {
        return Err(anyhow!("fee tier count must match v3 hop count"));
    }

    for (index, token) in route.iter().enumerate() {
        bytes.extend_from_slice(token.as_bytes());
        if let Some(fee) = fees.get(index) {
            let fee = fee.to_be_bytes();
            bytes.extend_from_slice(&fee[1..]);
        }
    }
    Ok(Bytes::from(bytes))
}

fn matching_paths(
    profile: &SimulationProfile,
    token_in: Address,
    token_out: Address,
) -> Vec<&MarketPathDefinition> {
    profile
        .market_paths
        .iter()
        .filter(|path| path.token_in == token_in && path.token_out == token_out)
        .collect()
}

fn balancer_assets(path: &MarketPathDefinition) -> Vec<Address> {
    full_route(path)
}

fn balancer_pool_ids(path: &MarketPathDefinition) -> Result<Vec<H256>> {
    let hop_count = full_route(path).len().saturating_sub(1);
    if path.pool_ids.len() != hop_count {
        return Err(anyhow!(
            "balancer pool_ids count must match route hop count for {}",
            path.label
        ));
    }

    path.pool_ids
        .iter()
        .map(|pool_id| {
            pool_id
                .parse::<H256>()
                .with_context(|| format!("invalid Balancer pool id {} for {}", pool_id, path.label))
        })
        .collect()
}

fn balancer_swaps(
    path: &MarketPathDefinition,
    amount_in: U256,
) -> Result<Vec<(H256, U256, U256, U256, Bytes)>> {
    let pool_ids = balancer_pool_ids(path)?;

    Ok(pool_ids
        .into_iter()
        .enumerate()
        .map(|(index, pool_id)| {
            (
                pool_id,
                U256::from(index),
                U256::from(index + 1),
                if index == 0 { amount_in } else { U256::zero() },
                Bytes::default(),
            )
        })
        .collect::<Vec<_>>())
}

#[derive(Debug, Clone)]
struct FlashLoanLiquidity {
    provider_name: Option<String>,
    available: U256,
}

async fn select_flash_loan_liquidity<M: Middleware + Clone + 'static>(
    provider: &M,
    profile: &SimulationProfile,
    asset: Address,
    block_number: Option<u64>,
) -> Result<Option<FlashLoanLiquidity>>
where
    <M as Middleware>::Error: 'static,
{
    let mut best: Option<FlashLoanLiquidity> = None;
    for flash in profile
        .flash_loan_providers
        .iter()
        .filter(|provider| provider.asset == asset)
    {
        let available = flash_loan_available(provider, flash, block_number).await?;
        if best
            .as_ref()
            .map(|current| available > current.available)
            .unwrap_or(true)
        {
            best = Some(FlashLoanLiquidity {
                provider_name: Some(format!("{:?}", flash.kind)),
                available,
            });
        }
    }
    Ok(best)
}

async fn flash_loan_available<M: Middleware + Clone + 'static>(
    provider: &M,
    flash: &FlashLoanProviderDefinition,
    block_number: Option<u64>,
) -> Result<U256>
where
    <M as Middleware>::Error: 'static,
{
    let observed = observed_flash_loan_available(provider, flash, block_number).await?;
    if let Some(max) = &flash.max_loan_amount {
        return Ok(observed.min(U256::from_dec_str(max)?));
    }
    Ok(observed)
}

async fn observed_flash_loan_available<M: Middleware + Clone + 'static>(
    provider: &M,
    flash: &FlashLoanProviderDefinition,
    block_number: Option<u64>,
) -> Result<U256>
where
    <M as Middleware>::Error: 'static,
{
    if flash.kind == FlashLoanProviderKind::Erc3156 {
        let abi = AbiParser::default()
            .parse(&["function maxFlashLoan(address token) view returns (uint256)"])?;
        let contract = Contract::new(flash.address, abi, Arc::new(provider.clone()));
        let mut call = contract.method::<_, U256>("maxFlashLoan", flash.asset)?;
        if let Some(block_number) = block_number {
            call = call.block(block_number);
        }
        if let Ok(value) = call.call().await {
            return Ok(value);
        }
    }

    let holder = flash.liquidity_holder.unwrap_or(flash.address);
    erc20_balance_of(provider, flash.asset, holder, block_number).await
}

async fn address_has_code<M: Middleware>(
    provider: &M,
    address: Address,
    block_number: Option<u64>,
) -> Result<bool>
where
    <M as Middleware>::Error: 'static,
{
    let block = block_number.map(|number| BlockId::Number(BlockNumber::Number(number.into())));
    Ok(!provider.get_code(address, block).await?.0.is_empty())
}

fn parse_market_probe_amount(amount: Option<&str>) -> Result<U256> {
    Ok(match amount {
        Some(value) => U256::from_dec_str(value)?,
        None => U256::from_dec_str(DEFAULT_MARKET_PROBE_AMOUNT)?,
    })
}

fn required_whale_amounts(profile: &SimulationProfile) -> Result<BTreeMap<Address, U256>> {
    let mut amounts = BTreeMap::new();
    for path in &profile.market_paths {
        let amount_in = parse_market_probe_amount(path.amount_in.as_deref())?;
        amounts
            .entry(path.token_in)
            .and_modify(|current| {
                if amount_in > *current {
                    *current = amount_in;
                }
            })
            .or_insert(amount_in);
    }
    Ok(amounts)
}

async fn erc20_balance_of<M: Middleware + Clone + 'static>(
    provider: &M,
    token: Address,
    holder: Address,
    block_number: Option<u64>,
) -> Result<U256>
where
    <M as Middleware>::Error: 'static,
{
    let abi = AbiParser::default()
        .parse(&["function balanceOf(address account) view returns (uint256)"])?;
    let contract = Contract::new(token, abi, Arc::new(provider.clone()));
    let mut call = contract.method::<_, U256>("balanceOf", holder)?;
    if let Some(block_number) = block_number {
        call = call.block(block_number);
    }
    Ok(call.call().await?)
}

fn router_kind_label(kind: RouterKind) -> &'static str {
    match kind {
        RouterKind::UniswapV2 => "uniswap_v2",
        RouterKind::UniswapV3 => "uniswap_v3",
        RouterKind::Aerodrome => "aerodrome",
        RouterKind::BalancerV2 => "balancer_v2",
    }
}

#[cfg(test)]
mod tests {
    use super::{hop_stables, parse_market_probe_amount, required_whale_amounts};
    use crate::protocols::{MarketPathDefinition, RouterKind, SimulationProfile};
    use ethers::types::{Address, U256};

    #[test]
    fn uses_default_probe_amount_when_path_amount_is_missing() {
        let amount = parse_market_probe_amount(None).expect("default probe amount should parse");
        assert_eq!(
            amount,
            U256::from_dec_str("1000000000000000000").expect("constant should parse")
        );
    }

    #[test]
    fn computes_max_required_whale_amount_per_input_token() {
        let token_a = Address::from_low_u64_be(0x11);
        let token_b = Address::from_low_u64_be(0x22);
        let token_c = Address::from_low_u64_be(0x33);
        let profile = SimulationProfile {
            market_paths: vec![
                MarketPathDefinition {
                    label: "small-a".into(),
                    router_kind: RouterKind::UniswapV2,
                    token_in: token_a,
                    token_out: token_b,
                    intermediate_tokens: Vec::new(),
                    fee_tiers: Vec::new(),
                    stable_hops: Vec::new(),
                    pool_ids: Vec::new(),
                    amount_in: Some("100".into()),
                    slippage_bps: None,
                },
                MarketPathDefinition {
                    label: "large-a".into(),
                    router_kind: RouterKind::UniswapV3,
                    token_in: token_a,
                    token_out: token_c,
                    intermediate_tokens: Vec::new(),
                    fee_tiers: vec![500],
                    stable_hops: Vec::new(),
                    pool_ids: Vec::new(),
                    amount_in: Some("250".into()),
                    slippage_bps: None,
                },
                MarketPathDefinition {
                    label: "default-b".into(),
                    router_kind: RouterKind::UniswapV2,
                    token_in: token_b,
                    token_out: token_c,
                    intermediate_tokens: Vec::new(),
                    fee_tiers: Vec::new(),
                    stable_hops: Vec::new(),
                    pool_ids: Vec::new(),
                    amount_in: None,
                    slippage_bps: None,
                },
            ],
            ..SimulationProfile::default()
        };

        let required = required_whale_amounts(&profile).expect("whale amounts should compute");
        assert_eq!(required.get(&token_a), Some(&U256::from(250_u64)));
        assert_eq!(
            required.get(&token_b),
            Some(&U256::from_dec_str("1000000000000000000").expect("constant should parse"))
        );
    }

    #[test]
    fn aerodrome_paths_default_to_volatile_hops() {
        let path = MarketPathDefinition {
            label: "aero".into(),
            router_kind: RouterKind::Aerodrome,
            token_in: Address::from_low_u64_be(0x11),
            token_out: Address::from_low_u64_be(0x22),
            intermediate_tokens: vec![Address::from_low_u64_be(0x33)],
            fee_tiers: Vec::new(),
            stable_hops: Vec::new(),
            pool_ids: Vec::new(),
            amount_in: None,
            slippage_bps: None,
        };

        assert_eq!(
            hop_stables(&path).expect("stable hops should default"),
            vec![false, false]
        );
    }
}
