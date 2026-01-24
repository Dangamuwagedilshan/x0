pub mod api;
pub mod auth;
pub mod config;
pub mod database;
pub mod enterprise;
pub mod models;
pub mod network_config;
pub mod services;
pub mod utils;

pub use config::Config;
pub use database::initialize_database;
pub use enterprise::License;
pub use network_config::{ApiKeyMode, NetworkConfig};

use std::sync::Arc;
use solana_sdk::signature::Keypair;
use webauthn_rs::prelude::Webauthn;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub redis: redis::aio::ConnectionManager,
    pub solana_rpc_url: String,
    pub solana_client: Arc<services::sol_client::ResilientSolanaClient>,
    pub rpc_cache: Arc<services::rpc_cache::RpcCache>,
    pub config: Config,
    pub webauthn: Arc<Webauthn>,
    pub test_network: NetworkConfig,
    pub live_network: NetworkConfig,
    pub test_fee_payer: Arc<Keypair>,
    pub live_fee_payer: Arc<Keypair>,
    pub keypair_cache: Arc<services::keypair_cache::KeypairCache>,
    pub attestation_signer: Option<Arc<services::attestation::AttestationSigner>>,
    pub license: License,
}

impl AppState {
    pub fn get_network(&self, mode: &ApiKeyMode) -> &NetworkConfig {
        match mode {
            ApiKeyMode::Test => &self.test_network,
            ApiKeyMode::Live => &self.live_network,
        }
    }

    pub fn get_fee_payer(&self, mode: &ApiKeyMode) -> &Keypair {
        match mode {
            ApiKeyMode::Test => &self.test_fee_payer,
            ApiKeyMode::Live => &self.live_fee_payer,
        }
    }
}
