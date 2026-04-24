use crate::artifacts::ArtifactStore;
use crate::config::Config;
use crate::db::PgPool;
use crate::intelligence::bridge_corpus::BridgeCorpusState;
use crate::notifications::NotificationService;
use crate::protocols::ProtocolRegistry;
use crate::tracking::cex_surveillance::CexCorpusState;
use crate::tracking::fund_tracker::FundTracker;
use crate::tracking::mixer_detector::MixerCorpusState;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub provider: ethers::providers::Provider<ethers::providers::Http>,
    pub ws_provider: Arc<ethers::providers::Provider<ethers::providers::Ws>>,
    pub pool: PgPool,
    pub protocols: ProtocolRegistry,
    pub artifact_store: ArtifactStore,
    pub notifications: NotificationService,
    pub http_client: reqwest::Client,
    pub fund_tracker: FundTracker,
    pub cex_wallets: Arc<RwLock<CexCorpusState>>,
    pub bridge_corpus: Arc<RwLock<BridgeCorpusState>>,
    pub mixer_corpus: Arc<RwLock<MixerCorpusState>>,
}
