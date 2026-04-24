use anyhow::Result;
use maxminddb::{geoip2, Reader};
use reqwest::Client;
use serde_json::Value;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, serde::Serialize, Clone)]
pub struct GeoResult {
    pub ip: String,
    pub city: Option<String>,
    pub country: Option<String>,
    pub isp: Option<String>,
    pub accuracy_radius: Option<u16>,
}

pub async fn geolocate_attack_tx(
    tx_hash: &str,
    bloxroute_auth: &str,
    mmdb_path: &str,
    lookup_url_template: &str,
) -> Result<Option<GeoResult>> {
    let Some(ip_str) = fetch_first_seen_node(tx_hash, bloxroute_auth, lookup_url_template).await?
    else {
        return Ok(None);
    };

    let ip: IpAddr = IpAddr::from_str(&ip_str)?;
    let reader: Reader<Vec<u8>> = Reader::open_readfile(mmdb_path)?;
    let city: geoip2::City = reader.lookup(ip)?;

    Ok(Some(GeoResult {
        ip: ip_str,
        city: city
            .city
            .and_then(|c| c.names?.get("en").map(|s| s.to_string())),
        country: city
            .country
            .and_then(|c| c.names?.get("en").map(|s| s.to_string())),
        isp: None,
        accuracy_radius: city.location.and_then(|l| l.accuracy_radius),
    }))
}

async fn fetch_first_seen_node(
    tx_hash: &str,
    bloxroute_auth: &str,
    lookup_url_template: &str,
) -> Result<Option<String>> {
    let url = lookup_url_template.replace("{tx_hash}", tx_hash);
    let client = Client::new();
    let response = client
        .get(url)
        .header("Authorization", bloxroute_auth)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;

    Ok(find_ip_in_value(&response))
}

fn find_ip_in_value(value: &Value) -> Option<String> {
    match value {
        Value::String(candidate) => candidate.parse::<IpAddr>().ok().map(|ip| ip.to_string()),
        Value::Array(items) => items.iter().find_map(find_ip_in_value),
        Value::Object(map) => {
            for (key, nested) in map {
                if key.to_ascii_lowercase().contains("ip") {
                    if let Some(found) = find_ip_in_value(nested) {
                        return Some(found);
                    }
                }
            }
            map.values().find_map(find_ip_in_value)
        }
        _ => None,
    }
}
