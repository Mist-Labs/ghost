use chrono::Utc;
use ethers::types::{Address, Transaction};
use std::collections::HashMap;
use std::sync::LazyLock;

#[derive(Debug, serde::Serialize, Clone, PartialEq)]
pub struct MixerEntry {
    pub wallet: String,
    pub pool_denomination_eth: f64,
    pub timestamp_ms: u64,
    pub tx_hash: String,
}

#[derive(Clone, Copy)]
struct MixerPool {
    denomination_eth: f64,
}

static KNOWN_MIXER_POOLS: LazyLock<HashMap<&'static str, MixerPool>> = LazyLock::new(|| {
    let mut pools = HashMap::new();
    pools.insert(
        "0x12d66f87a04a9e220c9d2457c68a57bde0f7amd0",
        MixerPool {
            denomination_eth: 0.1,
        },
    );
    pools.insert(
        "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936",
        MixerPool {
            denomination_eth: 1.0,
        },
    );
    pools.insert(
        "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",
        MixerPool {
            denomination_eth: 10.0,
        },
    );
    pools.insert(
        "0xa160cdab225685da1d56aa342ad8841c3b53f291",
        MixerPool {
            denomination_eth: 100.0,
        },
    );
    pools
});

pub fn detect_mixer_entry(tx: &Transaction, to: Address) -> Option<MixerEntry> {
    if !is_known_mixer(to) {
        return None;
    }
    let to_str = normalize_address(format!("{to:?}"));
    let pool = KNOWN_MIXER_POOLS.get(to_str.as_str())?;

    Some(MixerEntry {
        wallet: format!("{:?}", tx.from),
        pool_denomination_eth: pool.denomination_eth,
        timestamp_ms: Utc::now().timestamp_millis() as u64,
        tx_hash: format!("{:?}", tx.hash),
    })
}

pub fn is_known_mixer(address: Address) -> bool {
    let address = normalize_address(format!("{address:?}"));
    KNOWN_MIXER_POOLS.contains_key(address.as_str())
}

fn normalize_address(address: String) -> String {
    address.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{detect_mixer_entry, is_known_mixer};
    use ethers::types::{Address, Transaction, TxHash, U256, U64};
    use std::str::FromStr;

    #[test]
    fn detects_known_mixer_pool() {
        let pool = Address::from_str("0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936").unwrap();
        let tx = Transaction {
            hash: TxHash::from_low_u64_be(11),
            from: Address::from_low_u64_be(1),
            to: Some(pool),
            value: U256::zero(),
            nonce: U256::zero(),
            gas: U256::zero(),
            gas_price: None,
            input: Default::default(),
            transaction_type: Some(U64::from(2_u64)),
            ..Default::default()
        };

        let entry = detect_mixer_entry(&tx, pool).unwrap();
        assert_eq!(entry.pool_denomination_eth, 1.0);
        assert!(is_known_mixer(pool));
    }
}
