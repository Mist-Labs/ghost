use crate::config::ZeroGConfig;
use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::fs;
use tokio::process::Command;
use uuid::Uuid;

#[derive(Clone)]
pub enum ArtifactStore {
    Local(LocalArtifactStore),
    ZeroG(ZeroGArtifactStore),
}

#[derive(Clone)]
pub struct LocalArtifactStore {
    root: PathBuf,
}

#[derive(Clone)]
pub struct ZeroGArtifactStore {
    root: PathBuf,
    config: ZeroGConfig,
}

#[derive(Clone, Debug, Serialize)]
pub struct StoredArtifact {
    pub backend: String,
    pub locator: String,
    pub checksum_sha256: String,
    pub content_type: String,
    pub size_bytes: i64,
}

impl ArtifactStore {
    pub fn new(root: PathBuf, zero_g: Option<ZeroGConfig>) -> Self {
        match zero_g {
            Some(config) => Self::ZeroG(ZeroGArtifactStore { root, config }),
            None => Self::Local(LocalArtifactStore { root }),
        }
    }

    pub async fn persist_json<T: Serialize>(
        &self,
        key_prefix: &str,
        value: &T,
    ) -> Result<StoredArtifact> {
        let bytes = serde_json::to_vec_pretty(value)?;
        self.persist_bytes(key_prefix, "application/json", &bytes)
            .await
    }

    pub async fn persist_bytes(
        &self,
        key_prefix: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<StoredArtifact> {
        match self {
            Self::Local(store) => store.persist(key_prefix, content_type, bytes).await,
            Self::ZeroG(store) => store.persist(key_prefix, content_type, bytes).await,
        }
    }
}

impl LocalArtifactStore {
    async fn persist(
        &self,
        key_prefix: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<StoredArtifact> {
        fs::create_dir_all(&self.root).await?;
        let file_name = format!("{}-{}.json", sanitize(key_prefix), Uuid::new_v4());
        let full_path = self.root.join(file_name);
        fs::write(&full_path, bytes).await?;

        Ok(StoredArtifact {
            backend: "filesystem".into(),
            locator: full_path.to_string_lossy().to_string(),
            checksum_sha256: checksum(bytes),
            content_type: content_type.to_string(),
            size_bytes: bytes.len() as i64,
        })
    }
}

impl ZeroGArtifactStore {
    async fn persist(
        &self,
        key_prefix: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<StoredArtifact> {
        fs::create_dir_all(&self.root).await?;
        let file_name = format!("{}-{}.json", sanitize(key_prefix), Uuid::new_v4());
        let full_path = self.root.join(file_name);
        fs::write(&full_path, bytes).await?;

        let output = Command::new(&self.config.node_binary)
            .arg(&self.config.publish_script)
            .arg(full_path.as_os_str())
            .arg(content_type)
            .env("ZG_RPC_URL", &self.config.rpc_url)
            .env("ZG_INDEXER_RPC", &self.config.indexer_rpc)
            .env("ZG_PRIVATE_KEY", &self.config.private_key)
            .output()
            .await
            .with_context(|| {
                format!(
                    "failed to execute 0G publisher {}",
                    self.config.publish_script.display()
                )
            })?;

        if !output.status.success() {
            return Err(anyhow!(
                "0G artifact publisher failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let published: ZeroGPublishResult =
            serde_json::from_slice(&output.stdout).context("0G publisher returned invalid JSON")?;

        Ok(StoredArtifact {
            backend: "0g".into(),
            locator: published.root_hash,
            checksum_sha256: checksum(bytes),
            content_type: content_type.to_string(),
            size_bytes: bytes.len() as i64,
        })
    }
}

#[derive(serde::Deserialize)]
struct ZeroGPublishResult {
    root_hash: String,
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => ch,
            _ => '-',
        })
        .collect()
}

fn checksum(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::{checksum, sanitize};

    #[test]
    fn sanitizes_keys_for_filesystem_use() {
        assert_eq!(sanitize("incident:0xabc/123"), "incident-0xabc-123");
    }

    #[test]
    fn computes_sha256_checksum() {
        assert_eq!(
            checksum(b"ghost"),
            "ead6ef03d61ee60c533d6d450c50a1e559a8a37f6b796a4094cd0dac6b744428"
        );
    }
}
