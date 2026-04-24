use crate::config::Config;
use crate::protocols::{MetricSource, ProtocolDefinition};
use anyhow::{anyhow, Result};
use ethers::abi::{Abi, AbiParser, ParamType, Token};
use ethers::contract::Contract;
use ethers::providers::Middleware;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Address, Bytes, NameOrAddress, TransactionRequest, H256, I256, U256};
use reqwest::Client;
use serde_json::Value;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

pub const EIP1967_IMPLEMENTATION_SLOT: &str =
    "0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC";
pub const EIP1967_ADMIN_SLOT: &str =
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
pub const EIP1967_BEACON_SLOT: &str =
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

#[derive(Debug, Clone)]
pub struct ProxyState {
    pub proxy_address: Address,
    pub implementation: Address,
    pub admin: Option<Address>,
    pub beacon: Option<Address>,
    pub codehash: String,
    pub code_size: usize,
}

#[derive(Debug, Clone)]
pub struct ChainlinkFeedState {
    pub decimals: u8,
    pub answer: f64,
    pub raw_answer: String,
    pub updated_at: u64,
}

#[derive(Debug, Clone)]
pub struct UniswapTwapState {
    pub window_secs: u32,
    pub spot_tick: i32,
    pub twap_tick: i32,
    pub deviation_bps: u64,
}

#[derive(Debug, Clone)]
pub enum VerifiedSourceBackend {
    Sourcify,
    BaseScan,
}

#[derive(Debug, Clone)]
pub struct VerifiedSourceBundle {
    pub backend: VerifiedSourceBackend,
    pub compiler_version: String,
    pub contract_name: String,
    pub language: String,
    pub standard_json_input: Value,
    pub source_files: BTreeMap<String, String>,
    pub optimizer_enabled: Option<bool>,
    pub optimizer_runs: Option<u64>,
}

pub async fn load_abi(
    protocol: &ProtocolDefinition,
    explicit_abi: Option<&serde_json::Value>,
    address: Address,
    http_client: &Client,
    config: &Config,
) -> Result<Option<Abi>> {
    if let Some(abi) = explicit_abi {
        return Ok(Some(serde_json::from_value::<Abi>(abi.clone())?));
    }

    if let Some(abi) = &protocol.abi {
        return Ok(Some(serde_json::from_value::<Abi>(abi.clone())?));
    }

    if let Some(abi) = fetch_sourcify_abi(http_client, protocol.chain_id, address).await? {
        return Ok(Some(abi));
    }

    if let Some(api_key) = &config.basescan_api_key {
        if let Some(abi) =
            fetch_basescan_abi(http_client, address, api_key, &config.explorer_api_url).await?
        {
            return Ok(Some(abi));
        }
    }

    Ok(None)
}

pub async fn load_verified_source_bundle(
    protocol: &ProtocolDefinition,
    address: Address,
    http_client: &Client,
    config: &Config,
) -> Result<Option<VerifiedSourceBundle>> {
    if let Some(bundle) =
        fetch_sourcify_source_bundle(http_client, protocol.chain_id, address).await?
    {
        return Ok(Some(bundle));
    }

    if let Some(api_key) = &config.basescan_api_key {
        if let Some(bundle) =
            fetch_basescan_source_bundle(http_client, address, api_key, &config.explorer_api_url)
                .await?
        {
            return Ok(Some(bundle));
        }
    }

    Ok(None)
}

pub async fn proxy_state<M: Middleware + Clone + 'static>(
    address: Address,
    provider: &M,
) -> Result<ProxyState>
where
    <M as Middleware>::Error: 'static,
{
    let code = provider.get_code(address, None).await?;
    let implementation = read_eip1967_slot(provider, address, EIP1967_IMPLEMENTATION_SLOT).await?;
    let admin = read_eip1967_slot(provider, address, EIP1967_ADMIN_SLOT).await?;
    let beacon = read_eip1967_slot(provider, address, EIP1967_BEACON_SLOT).await?;
    let beacon_option = (beacon != Address::zero()).then_some(beacon);
    let beacon_implementation = match beacon_option {
        Some(beacon) => read_beacon_implementation(provider, beacon)
            .await
            .ok()
            .flatten(),
        None => None,
    };
    let resolved_implementation = if implementation != Address::zero() {
        implementation
    } else if let Some(beacon_implementation) = beacon_implementation {
        beacon_implementation
    } else {
        address
    };

    Ok(ProxyState {
        proxy_address: address,
        implementation: resolved_implementation,
        admin: if admin == Address::zero() {
            None
        } else {
            Some(admin)
        },
        beacon: beacon_option,
        codehash: format!("0x{}", hex::encode(ethers::utils::keccak256(&code.0))),
        code_size: code.0.len(),
    })
}

pub async fn call_function<M: Middleware>(
    provider: &M,
    address: Address,
    abi: &Abi,
    function_name: &str,
    args: &[Value],
) -> Result<Vec<Token>>
where
    <M as Middleware>::Error: 'static,
{
    let function = abi.function(function_name)?;
    let tokens = function
        .inputs
        .iter()
        .zip(args)
        .map(|(param, value)| json_to_token(&param.kind, value))
        .collect::<Result<Vec<_>>>()?;
    let calldata = function.encode_input(&tokens)?;
    let tx: TypedTransaction = TransactionRequest {
        to: Some(NameOrAddress::Address(address)),
        data: Some(Bytes::from(calldata)),
        ..Default::default()
    }
    .into();
    let output = provider.call(&tx, None).await?;
    Ok(function.decode_output(&output)?)
}

pub async fn read_metric_source<M: Middleware>(
    provider: &M,
    protocol: &ProtocolDefinition,
    source: &MetricSource,
    http_client: &Client,
    config: &Config,
) -> Result<U256>
where
    <M as Middleware>::Error: 'static,
{
    let abi = load_abi(
        protocol,
        source.abi.as_ref(),
        source.address,
        http_client,
        config,
    )
    .await?
    .ok_or_else(|| anyhow!("missing ABI for metric source {}", source.function))?;
    let outputs = call_function(
        provider,
        source.address,
        &abi,
        &source.function,
        &source.arguments,
    )
    .await?;
    let value = outputs
        .get(source.output_index)
        .ok_or_else(|| anyhow!("metric output index {} out of bounds", source.output_index))?;
    token_to_u256(value)
}

pub async fn read_chainlink_feed<M: Middleware>(
    provider: &M,
    address: Address,
) -> Result<ChainlinkFeedState>
where
    <M as Middleware>::Error: 'static,
{
    let abi = AbiParser::default().parse(&[
        "function latestRoundData() view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)",
        "function decimals() view returns (uint8)",
    ])?;
    let round = call_function(provider, address, &abi, "latestRoundData", &[]).await?;
    let decimals = call_function(provider, address, &abi, "decimals", &[]).await?;
    let decimals = decimals
        .first()
        .ok_or_else(|| anyhow!("decimals call returned no value"))?
        .clone()
        .into_uint()
        .ok_or_else(|| anyhow!("decimals call returned non-uint"))?
        .as_u32() as u8;
    let answer_token = round
        .get(1)
        .ok_or_else(|| anyhow!("latestRoundData answer missing"))?;
    let updated_at = round
        .get(3)
        .ok_or_else(|| anyhow!("latestRoundData updatedAt missing"))?
        .clone()
        .into_uint()
        .ok_or_else(|| anyhow!("updatedAt was not uint"))?
        .as_u64();
    let raw = token_to_i256(answer_token)?;
    let raw_string = raw.to_string();
    let base = raw_string.parse::<f64>().unwrap_or(0.0);
    let scaled = base / 10f64.powi(decimals as i32);

    Ok(ChainlinkFeedState {
        decimals,
        answer: scaled,
        raw_answer: raw_string,
        updated_at,
    })
}

pub async fn read_uniswap_v3_twap<M: Middleware>(
    provider: &M,
    pool_address: Address,
    window_secs: u32,
) -> Result<UniswapTwapState>
where
    <M as Middleware>::Error: 'static,
{
    let abi = AbiParser::default().parse(&[
        "function slot0() view returns (uint160 sqrtPriceX96, int24 tick, uint16 observationIndex, uint16 observationCardinality, uint16 observationCardinalityNext, uint8 feeProtocol, bool unlocked)",
        "function observe(uint32[] secondsAgos) view returns (int56[] tickCumulatives, uint160[] secondsPerLiquidityCumulativeX128s)",
    ])?;
    let slot0 = call_function(provider, pool_address, &abi, "slot0", &[]).await?;
    let observe = call_function(
        provider,
        pool_address,
        &abi,
        "observe",
        &[serde_json::json!([window_secs, 0])],
    )
    .await?;

    let spot_tick =
        token_to_i256(slot0.get(1).ok_or_else(|| anyhow!("slot0 tick missing"))?)?.as_i32();

    let tick_cumulatives = observe
        .first()
        .cloned()
        .ok_or_else(|| anyhow!("observe returned no tick cumulatives"))?
        .into_array()
        .ok_or_else(|| anyhow!("observe tick cumulatives were not an array"))?;
    if tick_cumulatives.len() < 2 {
        return Err(anyhow!("observe returned fewer than two cumulative ticks"));
    }

    let start = token_to_i256(&tick_cumulatives[0])?;
    let end = token_to_i256(&tick_cumulatives[1])?;
    let delta = end - start;
    let twap_tick = (delta / I256::from(window_secs)).as_i32();
    let deviation_bps = tick_difference_to_bps(spot_tick - twap_tick);

    Ok(UniswapTwapState {
        window_secs,
        spot_tick,
        twap_tick,
        deviation_bps,
    })
}

pub fn severity_from_config(
    value: Option<&str>,
    default: crate::proactive::Severity,
) -> crate::proactive::Severity {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "critical" => crate::proactive::Severity::Critical,
        "high" => crate::proactive::Severity::High,
        "medium" => crate::proactive::Severity::Medium,
        "low" => crate::proactive::Severity::Low,
        _ => default,
    }
}

fn tick_difference_to_bps(tick_delta: i32) -> u64 {
    let ratio = 1.0001f64.powi(tick_delta.abs());
    ((ratio - 1.0).abs() * 10_000.0).round() as u64
}

async fn read_eip1967_slot<M: Middleware>(
    provider: &M,
    address: Address,
    slot: &str,
) -> Result<Address>
where
    <M as Middleware>::Error: 'static,
{
    let slot = H256::from_str(slot)?;
    let value = provider.get_storage_at(address, slot, None).await?;
    Ok(Address::from_slice(&value.as_bytes()[12..]))
}

async fn fetch_sourcify_abi(
    client: &Client,
    chain_id: u64,
    address: Address,
) -> Result<Option<Abi>> {
    let normalized_address = format!("{address:?}").to_lowercase();
    let url = format!(
        "https://repo.sourcify.dev/contracts/full_match/{}/{}/metadata.json",
        chain_id, normalized_address
    );
    let response = client.get(url).send().await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let response = response.error_for_status()?;
    let metadata: Value = response.json().await?;
    let Some(abi_value) = metadata.get("output").and_then(|value| value.get("abi")) else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_value::<Abi>(abi_value.clone())?))
}

async fn fetch_sourcify_source_bundle(
    client: &Client,
    chain_id: u64,
    address: Address,
) -> Result<Option<VerifiedSourceBundle>> {
    let normalized_address = format!("{address:?}").to_lowercase();
    let base = format!(
        "https://repo.sourcify.dev/contracts/full_match/{}/{}/",
        chain_id, normalized_address
    );
    let metadata_url = format!("{base}metadata.json");
    let response = client.get(metadata_url).send().await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let metadata: Value = response.error_for_status()?.json().await?;
    let language = metadata
        .get("language")
        .and_then(Value::as_str)
        .unwrap_or("Solidity")
        .to_string();
    let compiler_version = metadata
        .get("compiler")
        .and_then(|value| value.get("version"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("sourcify metadata missing compiler version"))?
        .to_string();
    let contract_name = metadata
        .get("settings")
        .and_then(|value| value.get("compilationTarget"))
        .and_then(Value::as_object)
        .and_then(|targets| targets.values().next())
        .and_then(Value::as_str)
        .unwrap_or("Contract")
        .to_string();

    let mut source_files = BTreeMap::new();
    let mut source_json = serde_json::Map::new();
    let source_paths = metadata
        .get("sources")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("sourcify metadata missing sources"))?;
    for source_path in source_paths.keys() {
        let mut source_url = reqwest::Url::parse(&base)?;
        {
            let mut segments = source_url
                .path_segments_mut()
                .map_err(|_| anyhow!("invalid sourcify source path"))?;
            segments.push("sources");
            for segment in source_path.split('/') {
                segments.push(segment);
            }
        }
        let content = client
            .get(source_url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        source_json.insert(
            source_path.clone(),
            serde_json::json!({ "content": content }),
        );
        source_files.insert(source_path.clone(), content);
    }

    let settings = metadata
        .get("settings")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let optimizer_enabled = settings
        .get("optimizer")
        .and_then(|value| value.get("enabled"))
        .and_then(Value::as_bool);
    let optimizer_runs = settings
        .get("optimizer")
        .and_then(|value| value.get("runs"))
        .and_then(Value::as_u64);

    Ok(Some(VerifiedSourceBundle {
        backend: VerifiedSourceBackend::Sourcify,
        compiler_version,
        contract_name,
        language: language.clone(),
        standard_json_input: serde_json::json!({
            "language": language,
            "sources": source_json,
            "settings": settings,
        }),
        source_files,
        optimizer_enabled,
        optimizer_runs,
    }))
}

async fn fetch_basescan_abi(
    client: &Client,
    address: Address,
    api_key: &str,
    api_url: &str,
) -> Result<Option<Abi>> {
    #[derive(serde::Deserialize)]
    struct BasescanResponse {
        status: String,
        result: String,
    }

    let response = client
        .get(api_url)
        .query(&[
            ("module", "contract"),
            ("action", "getabi"),
            ("address", &format!("{address:?}")),
            ("apikey", api_key),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<BasescanResponse>()
        .await?;

    if response.status != "1" {
        return Ok(None);
    }

    Ok(Some(serde_json::from_str::<Abi>(&response.result)?))
}

async fn fetch_basescan_source_bundle(
    client: &Client,
    address: Address,
    api_key: &str,
    api_url: &str,
) -> Result<Option<VerifiedSourceBundle>> {
    #[derive(serde::Deserialize)]
    struct BasescanSourceRow {
        #[serde(rename = "SourceCode")]
        source_code: String,
        #[serde(rename = "ContractName")]
        contract_name: String,
        #[serde(rename = "CompilerVersion")]
        compiler_version: String,
        #[serde(rename = "OptimizationUsed")]
        optimization_used: String,
        #[serde(rename = "Runs")]
        runs: String,
    }

    #[derive(serde::Deserialize)]
    struct BasescanSourceResponse {
        status: String,
        result: Vec<BasescanSourceRow>,
    }

    let response = client
        .get(api_url)
        .query(&[
            ("module", "contract"),
            ("action", "getsourcecode"),
            ("address", &format!("{address:?}")),
            ("apikey", api_key),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<BasescanSourceResponse>()
        .await?;
    if response.status != "1" {
        return Ok(None);
    }
    let Some(result) = response.result.into_iter().next() else {
        return Ok(None);
    };
    if result.source_code.trim().is_empty() || result.compiler_version.trim().is_empty() {
        return Ok(None);
    }

    let compiler_version = result.compiler_version.trim().to_string();
    let optimizer_enabled = Some(result.optimization_used.trim() == "1");
    let optimizer_runs = result.runs.trim().parse::<u64>().ok();
    let (source_files, standard_json_input, language) = normalize_basescan_source(
        &result.contract_name,
        &result.source_code,
        optimizer_enabled,
        optimizer_runs,
    )?;

    Ok(Some(VerifiedSourceBundle {
        backend: VerifiedSourceBackend::BaseScan,
        compiler_version,
        contract_name: result.contract_name,
        language,
        standard_json_input,
        source_files,
        optimizer_enabled,
        optimizer_runs,
    }))
}

fn normalize_basescan_source(
    contract_name: &str,
    raw_source: &str,
    optimizer_enabled: Option<bool>,
    optimizer_runs: Option<u64>,
) -> Result<(BTreeMap<String, String>, Value, String)> {
    let raw_source = raw_source.trim();
    if let Some(value) = parse_embedded_json(raw_source) {
        let language = value
            .get("language")
            .and_then(Value::as_str)
            .unwrap_or("Solidity")
            .to_string();
        let source_object = value
            .get("sources")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("basescan source payload missing sources"))?;
        let mut source_files = BTreeMap::new();
        for (path, entry) in source_object {
            let content = entry
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("basescan source entry for {path} missing content"))?;
            source_files.insert(path.clone(), content.to_string());
        }
        return Ok((source_files, value, language));
    }

    let file_name = if contract_name.ends_with(".sol") {
        contract_name.to_string()
    } else {
        format!("{contract_name}.sol")
    };
    let mut source_files = BTreeMap::new();
    source_files.insert(file_name.clone(), raw_source.to_string());
    let standard_json_input = serde_json::json!({
        "language": "Solidity",
        "sources": {
            file_name: {
                "content": raw_source
            }
        },
        "settings": {
            "optimizer": {
                "enabled": optimizer_enabled.unwrap_or(false),
                "runs": optimizer_runs.unwrap_or(200)
            }
        }
    });
    Ok((source_files, standard_json_input, "Solidity".to_string()))
}

fn parse_embedded_json(raw: &str) -> Option<Value> {
    serde_json::from_str::<Value>(raw).ok().or_else(|| {
        if raw.starts_with("{{") && raw.ends_with("}}") {
            serde_json::from_str::<Value>(&raw[1..raw.len().saturating_sub(1)]).ok()
        } else {
            None
        }
    })
}

fn json_to_token(param_type: &ParamType, value: &Value) -> Result<Token> {
    match param_type {
        ParamType::Address => {
            let address = value
                .as_str()
                .ok_or_else(|| anyhow!("expected address string"))?
                .parse::<Address>()?;
            Ok(Token::Address(address))
        }
        ParamType::Uint(_) => {
            let value = json_to_u256(value)?;
            Ok(Token::Uint(value))
        }
        ParamType::Int(_) => {
            let value = json_to_i256(value)?;
            Ok(Token::Int(value.into_raw()))
        }
        ParamType::Bool => Ok(Token::Bool(
            value
                .as_bool()
                .ok_or_else(|| anyhow!("expected bool argument"))?,
        )),
        ParamType::String => Ok(Token::String(
            value
                .as_str()
                .ok_or_else(|| anyhow!("expected string argument"))?
                .to_string(),
        )),
        ParamType::Bytes => Ok(Token::Bytes(parse_hex_bytes(value)?)),
        ParamType::FixedBytes(len) => {
            let bytes = parse_hex_bytes(value)?;
            if bytes.len() != *len {
                return Err(anyhow!("expected {len} bytes, got {}", bytes.len()));
            }
            Ok(Token::FixedBytes(bytes))
        }
        ParamType::Array(inner) => {
            let values = value
                .as_array()
                .ok_or_else(|| anyhow!("expected array argument"))?
                .iter()
                .map(|value| json_to_token(inner, value))
                .collect::<Result<Vec<_>>>()?;
            Ok(Token::Array(values))
        }
        ParamType::Tuple(inner) => {
            let values = value
                .as_array()
                .ok_or_else(|| anyhow!("expected tuple argument"))?
                .iter()
                .zip(inner.iter())
                .map(|(value, kind)| json_to_token(kind, value))
                .collect::<Result<Vec<_>>>()?;
            Ok(Token::Tuple(values))
        }
        unsupported => Err(anyhow!("unsupported ABI argument type: {unsupported:?}")),
    }
}

fn json_to_u256(value: &Value) -> Result<U256> {
    if let Some(number) = value.as_u64() {
        return Ok(U256::from(number));
    }
    let text = value
        .as_str()
        .ok_or_else(|| anyhow!("expected decimal string or u64"))?;
    Ok(U256::from_dec_str(text)?)
}

fn json_to_i256(value: &Value) -> Result<I256> {
    if let Some(number) = value.as_i64() {
        return Ok(I256::from(number));
    }
    let text = value
        .as_str()
        .ok_or_else(|| anyhow!("expected signed decimal string or i64"))?;
    Ok(I256::from_dec_str(text)?)
}

fn parse_hex_bytes(value: &Value) -> Result<Vec<u8>> {
    let text = value
        .as_str()
        .ok_or_else(|| anyhow!("expected hex string"))?
        .trim_start_matches("0x");
    Ok(hex::decode(text)?)
}

async fn read_beacon_implementation<M: Middleware + Clone + 'static>(
    provider: &M,
    beacon: Address,
) -> Result<Option<Address>>
where
    <M as Middleware>::Error: 'static,
{
    let abi = AbiParser::default().parse(&["function implementation() view returns (address)"])?;
    let contract = Contract::new(beacon, abi, Arc::new(provider.clone()));
    let implementation = contract
        .method::<_, Address>("implementation", ())?
        .call()
        .await?;
    Ok((implementation != Address::zero()).then_some(implementation))
}

pub fn token_to_u256(token: &Token) -> Result<U256> {
    match token {
        Token::Uint(value) => Ok(*value),
        Token::Int(value) => Ok(*value),
        Token::Bool(value) => Ok(U256::from(*value as u8)),
        Token::FixedBytes(value) | Token::Bytes(value) => Ok(U256::from_big_endian(value)),
        other => Err(anyhow!("unsupported numeric output token: {other:?}")),
    }
}

pub fn token_to_i256(token: &Token) -> Result<I256> {
    match token {
        Token::Int(value) => Ok(I256::from_raw(*value)),
        Token::Uint(value) => Ok(I256::from_raw(*value)),
        Token::Bool(value) => Ok(I256::from(*value as i32)),
        other => Err(anyhow!("unsupported signed output token: {other:?}")),
    }
}
