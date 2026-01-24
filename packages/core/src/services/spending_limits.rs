use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use bigdecimal::ToPrimitive;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;

pub const SPENDING_LIMIT_ACTION_IPFS_CID: &str = "QmXXunoMeNhXhnr4onzBuvnMzDqH8rf1qdM94RKXayypX3";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoSessionConfig {
    pub session_id: Uuid,
    pub platform_id: Uuid,
    pub user_wallet: String,
    pub max_per_transaction: Option<f64>,
    pub max_per_day: f64,
    pub max_per_week: Option<f64>,
    pub max_per_month: Option<f64>,
    pub duration_hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoSessionResult {
    pub session_id: Uuid,
    pub session_token: String,
    pub pkp_public_key: String,
    pub pkp_eth_address: String,
    pub pkp_token_id: String,
    pub lit_action_ipfs_cid: String,
    #[serde(alias = "crypto_enforced", alias = "pkp_enabled")]
    pub mint_pkp: bool,
    pub expires_at: DateTime<Utc>,
    pub counter_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingCheckRequest {
    pub session_id: Uuid,
    pub amount_usd: f64,
    pub platform_id: Option<Uuid>,
    pub check_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingCheckResponse {
    pub allowed: bool,
    pub reason: String,
    pub current_spent: f64,
    pub limit: f64,
    pub remaining: f64,
    pub session_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPkpInfo {
    pub pkp_public_key: String,
    pub pkp_eth_address: String,
    pub pkp_token_id: String,
    pub lit_action_ipfs_cid: String,
    pub created_at: DateTime<Utc>,
}

pub async fn create_crypto_session(
    state: &AppState,
    config: CryptoSessionConfig,
) -> Result<CryptoSessionResult, CryptoSpendError> {
    use lit_rust_sdk::{
        LitNetwork, LitNodeClient, LitNodeClientConfig,
    };
    use std::time::Duration as StdDuration;
    
    tracing::info!(
        "Creating crypto-enforced session {} for platform {} (limit: ${}/day)",
        config.session_id, config.platform_id, config.max_per_day
    );
    
    let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
    let lit_network_env = std::env::var("LIT_NETWORK").unwrap_or_else(|_| "DatilDev".to_string());
    
    let network = match lit_network_env.as_str() {
        "Datil" | "mainnet" => LitNetwork::Datil,
        "DatilTest" | "testnet" => LitNetwork::DatilTest,
        _ => LitNetwork::DatilDev,
    };
    
    let lit_config = LitNodeClientConfig {
        lit_network: network,
        alert_when_unauthorized: true,
        debug: false,
        connect_timeout: StdDuration::from_secs(30),
        check_node_attestation: environment == "production",
    };
    
    let mut client = LitNodeClient::new(lit_config)
        .await
        .map_err(|e| CryptoSpendError::LitError(format!("Failed to create Lit client: {}", e)))?;
    
    client.connect()
        .await
        .map_err(|e| CryptoSpendError::LitError(format!("Failed to connect to Lit: {}", e)))?;
    
    let lit_action_cid = std::env::var("LIT_SPENDING_ACTION_CID")
        .unwrap_or_else(|_| SPENDING_LIMIT_ACTION_IPFS_CID.to_string());
    
    let pkp_info = mint_pkp_for_session(
        &client,
        &config,
        &lit_action_cid,
    ).await?;
    
    tracing::info!(
        "Minted PKP {} for session {} (bound to action {})",
        pkp_info.pkp_public_key, config.session_id, lit_action_cid
    );
    
    let session_token = generate_crypto_session_token(&config.session_id);
    
    let expires_at = Utc::now() + Duration::hours(config.duration_hours as i64);
    
    let counter_address = derive_virtual_counter_address(&config.session_id);
    
    store_crypto_session(
        state,
        &config,
        &pkp_info,
        &counter_address,
    ).await?;
    
    Ok(CryptoSessionResult {
        session_id: config.session_id,
        session_token,
        pkp_public_key: pkp_info.pkp_public_key,
        pkp_eth_address: pkp_info.pkp_eth_address,
        pkp_token_id: pkp_info.pkp_token_id,
        lit_action_ipfs_cid: lit_action_cid,
        mint_pkp: true,
        expires_at,
        counter_address,
    })
}

pub async fn check_spending_limit_internal(
    State(state): State<AppState>,
    Json(request): Json<SpendingCheckRequest>,
) -> Result<Json<SpendingCheckResponse>, (StatusCode, Json<serde_json::Value>)> {
    tracing::info!(
        "Internal spending check: session={}, amount=${}",
        request.session_id, request.amount_usd
    );
    
    let session = sqlx::query!(
        r#"
        SELECT 
            id, platform_id, is_active, expires_at,
            max_per_transaction, max_per_day, max_per_week, max_per_month,
            spent_today, spent_this_week, spent_this_month,
            crypto_enforced
        FROM ai_agent_sessions
        WHERE id = $1
        "#,
        request.session_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Database error"})),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Session not found"})),
        )
    })?;
    
    let is_active = session.is_active.unwrap_or(false);
    let is_expired = session.expires_at < Utc::now();
    
    if !is_active || is_expired {
        return Ok(Json(SpendingCheckResponse {
            allowed: false,
            reason: if is_expired { "Session expired".to_string() } else { "Session inactive".to_string() },
            current_spent: 0.0,
            limit: 0.0,
            remaining: 0.0,
            session_valid: false,
        }));
    }
    
    let spent_today = session.spent_today
        .and_then(|v| v.to_f64())
        .unwrap_or(0.0);
    
    let limit_today = session.max_per_day
        .and_then(|v| v.to_f64())
        .unwrap_or(f64::MAX);
    
    let limit_per_tx = session.max_per_transaction
        .and_then(|v| v.to_f64())
        .unwrap_or(f64::MAX);
    
    if request.amount_usd > limit_per_tx {
        return Ok(Json(SpendingCheckResponse {
            allowed: false,
            reason: format!("Amount ${:.2} exceeds per-transaction limit of ${:.2}", 
                          request.amount_usd, limit_per_tx),
            current_spent: spent_today,
            limit: limit_per_tx,
            remaining: 0.0,
            session_valid: true,
        }));
    }
    
    let remaining_today = limit_today - spent_today;
    if request.amount_usd > remaining_today {
        return Ok(Json(SpendingCheckResponse {
            allowed: false,
            reason: format!("Amount ${:.2} would exceed daily limit. Spent: ${:.2}, Limit: ${:.2}", 
                          request.amount_usd, spent_today, limit_today),
            current_spent: spent_today,
            limit: limit_today,
            remaining: remaining_today.max(0.0),
            session_valid: true,
        }));
    }
    
    if let Some(limit_week) = session.max_per_week.and_then(|v| v.to_f64()) {
        let spent_week = session.spent_this_week
            .and_then(|v| v.to_f64())
            .unwrap_or(0.0);
        
        if spent_week + request.amount_usd > limit_week {
            return Ok(Json(SpendingCheckResponse {
                allowed: false,
                reason: format!("Would exceed weekly limit. Spent: ${:.2}, Limit: ${:.2}", 
                              spent_week, limit_week),
                current_spent: spent_week,
                limit: limit_week,
                remaining: (limit_week - spent_week).max(0.0),
                session_valid: true,
            }));
        }
    }
    
    if let Some(limit_month) = session.max_per_month.and_then(|v| v.to_f64()) {
        let spent_month = session.spent_this_month
            .and_then(|v| v.to_f64())
            .unwrap_or(0.0);
        
        if spent_month + request.amount_usd > limit_month {
            return Ok(Json(SpendingCheckResponse {
                allowed: false,
                reason: format!("Would exceed monthly limit. Spent: ${:.2}, Limit: ${:.2}", 
                              spent_month, limit_month),
                current_spent: spent_month,
                limit: limit_month,
                remaining: (limit_month - spent_month).max(0.0),
                session_valid: true,
            }));
        }
    }
    
    Ok(Json(SpendingCheckResponse {
        allowed: true,
        reason: "Spending limit check passed".to_string(),
        current_spent: spent_today,
        limit: limit_today,
        remaining: remaining_today - request.amount_usd,
        session_valid: true,
    }))
}


fn generate_crypto_session_token(session_id: &Uuid) -> String {
    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..16).map(|_| rand::Rng::gen(&mut rng)).collect();
    format!("x0_crypto_{}{}", hex::encode(session_id.as_bytes()), hex::encode(random_bytes))
}

fn derive_virtual_counter_address(session_id: &Uuid) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"x0_virtual_counter_v1");
    hasher.update(session_id.as_bytes());
    let hash = hasher.finalize();
    format!("vc_{}", hex::encode(&hash[..20]))
}

async fn mint_pkp_for_session(
    _client: &lit_rust_sdk::LitNodeClient,
    config: &CryptoSessionConfig,
    lit_action_cid: &str,
) -> Result<SessionPkpInfo, CryptoSpendError> {
    use alloy::{
        network::EthereumWallet,
        primitives::U256,
        providers::ProviderBuilder,
        signers::local::PrivateKeySigner,
    };
    use lit_rust_sdk::{
        blockchain::{resolve_address, Contract, PKPNFT},
        LitNetwork,
    };
    use std::str::FromStr;
    
    tracing::info!(
        "Minting PKP for session {} bound to action {}",
        config.session_id, lit_action_cid
    );
    
    let private_key = std::env::var("LIT_MINTER_PRIVATE_KEY")
        .or_else(|_| std::env::var("ETHEREUM_PRIVATE_KEY"))
        .map_err(|_| CryptoSpendError::LitError(
            "LIT_MINTER_PRIVATE_KEY or ETHEREUM_PRIVATE_KEY not set".to_string()
        ))?;
    
    let lit_network_env = std::env::var("LIT_NETWORK").unwrap_or_else(|_| "DatilDev".to_string());
    
    let lit_network = match lit_network_env.as_str() {
        "Datil" | "mainnet" => LitNetwork::Datil,
        "DatilTest" | "testnet" => LitNetwork::DatilTest,
        _ => LitNetwork::DatilDev,
    };
    
    let use_simulation = match std::env::var("LIT_PKP_SIMULATION") {
        Ok(v) => v == "true" || v == "1",
        Err(_) => {
            match lit_network {
                LitNetwork::Datil | LitNetwork::DatilTest => false,
                LitNetwork::DatilDev => true,
            }
        }
    };
    
    if use_simulation {
        tracing::warn!(
            "PKP minting in SIMULATION mode - generating deterministic PKP info. \
             Set LIT_PKP_SIMULATION=false for real minting."
        );
        return mint_pkp_simulated(config, lit_action_cid);
    }
    
    tracing::info!(
        "Real PKP minting enabled on {:?} network",
        lit_network
    );
    
    let wallet = PrivateKeySigner::from_str(&private_key)
        .map_err(|e| CryptoSpendError::LitError(format!("Invalid private key: {}", e)))?;
    
    tracing::info!("Using minter wallet: {}", wallet.address());
    
    let pkp_nft_address = resolve_address(Contract::PKPNFT, lit_network)
        .await
        .map_err(|e| CryptoSpendError::LitError(format!("Failed to resolve PKP NFT address: {}", e)))?;
    
    tracing::info!("PKP NFT contract: {} on {:?}", pkp_nft_address, lit_network);
    
    let ethereum_wallet = EthereumWallet::from(wallet.clone());
    let provider = ProviderBuilder::new()
        .wallet(ethereum_wallet)
        .connect(lit_network.rpc_url())
        .await
        .map_err(|e| CryptoSpendError::LitError(format!("Failed to connect to Chronicle: {}", e)))?;
    
    let pkp_nft = PKPNFT::new(pkp_nft_address, provider.clone());
    
    let mint_cost = pkp_nft.mintCost().call().await
        .map_err(|e| CryptoSpendError::LitError(format!("Failed to get mint cost: {}", e)))?;
    
    tracing::info!("PKP mint cost: {} wei", mint_cost);
    
    let key_type = U256::from(2);
    
    tracing::info!("Minting PKP NFT...");
    let tx = pkp_nft.mintNext(key_type).value(mint_cost);
    
    let pending_tx = tx.send().await
        .map_err(|e| CryptoSpendError::LitError(format!("Failed to send mint tx: {}", e)))?;
    
    tracing::info!("Mint tx sent: {}", pending_tx.tx_hash());
    
    let receipt = pending_tx.get_receipt().await
        .map_err(|e| CryptoSpendError::LitError(format!("Failed to get mint receipt: {}", e)))?;
    
    tracing::info!("Mint tx confirmed in block {:?}", receipt.block_number);
    
    let token_id = receipt.logs().iter()
        .find_map(|log| {
            if log.topics().len() >= 4 {
                Some(U256::from_be_bytes(log.topics()[3].0))
            } else {
                None
            }
        })
        .ok_or_else(|| CryptoSpendError::LitError("Failed to extract token ID from mint logs".to_string()))?;
    
    tracing::info!("PKP NFT minted! Token ID: {}", token_id);
    
    let pkp_pub_key = pkp_nft.getPubkey(token_id).call().await
        .map_err(|e| CryptoSpendError::LitError(format!("Failed to get PKP pubkey: {}", e)))?;
    
    let pkp_eth_address = pkp_nft.getEthAddress(token_id).call().await
        .map_err(|e| CryptoSpendError::LitError(format!("Failed to get PKP address: {}", e)))?;
    
    tracing::info!(
        "PKP created: pubkey=0x{}..., address={}",
        hex::encode(&pkp_pub_key[..8]),
        pkp_eth_address
    );
    
    add_permitted_action_to_pkp(
        &provider,
        lit_network,
        token_id,
        lit_action_cid,
    ).await?;
    
    Ok(SessionPkpInfo {
        pkp_public_key: format!("0x{}", hex::encode(&pkp_pub_key[..])),
        pkp_eth_address: format!("{}", pkp_eth_address),
        pkp_token_id: token_id.to_string(),
        lit_action_ipfs_cid: lit_action_cid.to_string(),
        created_at: Utc::now(),
    })
}

async fn add_permitted_action_to_pkp<P>(
    _provider: &P,
    lit_network: lit_rust_sdk::LitNetwork,
    pkp_token_id: alloy::primitives::U256,
    lit_action_ipfs_cid: &str,
) -> Result<(), CryptoSpendError>
where
    P: alloy::providers::Provider + Clone,
{
    use alloy::primitives::Bytes;
    
    let pkp_permissions_address = match std::env::var("LIT_PKP_PERMISSIONS_ADDRESS") {
        Ok(addr) => {
            match addr.parse::<alloy::primitives::Address>() {
                Ok(a) if a != alloy::primitives::Address::ZERO => {
                    tracing::info!("Using PKPPermissions contract: {}", a);
                    a
                }
                _ => {
                    tracing::warn!(
                        "Invalid LIT_PKP_PERMISSIONS_ADDRESS '{}' - skipping action binding",
                        addr
                    );
                    return Ok(());
                }
            }
        }
        Err(_) => {
            match lit_network {
                lit_rust_sdk::LitNetwork::Datil => {
                    "0x213Db6E1446928E19588269bEF7dFc9187c4829A"
                        .parse::<alloy::primitives::Address>()
                        .unwrap_or_else(|e| {
                            tracing::error!("Failed to parse PKP Helper address: {:?}", e);
                            alloy::primitives::Address::ZERO
                        })
                }
                lit_rust_sdk::LitNetwork::DatilTest => {
                    tracing::warn!(
                        "PKPPermissions not configured for DatilTest - PKP {} is permissionless",
                        pkp_token_id
                    );
                    return Ok(());
                }
                lit_rust_sdk::LitNetwork::DatilDev => {
                    tracing::warn!(
                        "Skipping PKPPermissions binding on DatilDev - PKP {} is permissionless",
                        pkp_token_id
                    );
                    return Ok(());
                }
            }
        }
    };
    
    let ipfs_cid_bytes = Bytes::from(lit_action_ipfs_cid.as_bytes().to_vec());
    
    tracing::info!(
        "Binding Lit Action {} to PKP {} via PKPPermissions at {}",
        lit_action_ipfs_cid, pkp_token_id, pkp_permissions_address
    );
    
    alloy::sol! {
        #[sol(rpc)]
        interface IPKPPermissions {
            function addPermittedAction(uint256 tokenId, bytes calldata ipfsCID, uint256[] calldata scopes) external;
        }
    }
    
    let minter_key = std::env::var("LIT_MINTER_PRIVATE_KEY")
        .map_err(|_| CryptoSpendError::LitError("LIT_MINTER_PRIVATE_KEY not set".into()))?;
    
    let wallet = minter_key
        .parse::<alloy::signers::local::PrivateKeySigner>()
        .map_err(|e| CryptoSpendError::LitError(format!("Invalid minter key: {}", e)))?;
    
    let chronicle_rpc = std::env::var("LIT_CHRONICLE_RPC_URL")
        .unwrap_or_else(|_| "https://yellowstone-rpc.litprotocol.com".to_string());
    
    let rpc_url: reqwest::Url = chronicle_rpc.parse().map_err(|e| {
        CryptoSpendError::LitError(format!("Invalid Chronicle RPC URL: {}", e))
    })?;
    let provider = alloy::providers::ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(wallet))
        .connect_http(rpc_url);
    
    let pkp_permissions = IPKPPermissions::new(pkp_permissions_address, &provider);
    
    let scopes = vec![alloy::primitives::U256::from(1)];
    
    tracing::info!("Calling PKPPermissions.addPermittedAction...");
    
    let tx = pkp_permissions
        .addPermittedAction(pkp_token_id, ipfs_cid_bytes, scopes)
        .send()
        .await
        .map_err(|e| CryptoSpendError::LitError(format!("Failed to send addPermittedAction tx: {}", e)))?;
    
    tracing::info!("Permission tx sent: {:?}", tx.tx_hash());
    
    let receipt = tx
        .get_receipt()
        .await
        .map_err(|e| CryptoSpendError::LitError(format!("Failed to get permission tx receipt: {}", e)))?;
    
    tracing::info!(
        "PKP {} successfully bound to Lit Action {} (block: {:?})",
        pkp_token_id, lit_action_ipfs_cid, receipt.block_number
    );

    Ok(())
}

fn mint_pkp_simulated(
    config: &CryptoSessionConfig,
    lit_action_cid: &str,
) -> Result<SessionPkpInfo, CryptoSpendError> {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(b"simulated_pkp_v1_");
    hasher.update(config.session_id.as_bytes());
    hasher.update(lit_action_cid.as_bytes());
    let hash = hasher.finalize();
    
    let pkp_public_key = format!("0x{}", hex::encode(&hash));
    let pkp_eth_address = format!("0x{}", hex::encode(&hash[..20]));
    
    let pkp_token_id = match hash[..8].try_into() {
        Ok(bytes) => format!("{}", u64::from_be_bytes(bytes)),
        Err(e) => {
            tracing::error!("Failed to convert hash to PKP token ID: {:?}", e);
            return Err(CryptoSpendError::InvalidConfiguration("PKP generation failed".to_string()));
        }
    };
    
    tracing::info!(
        "Simulated PKP: token_id={}, address={}",
        pkp_token_id, pkp_eth_address
    );
    
    Ok(SessionPkpInfo {
        pkp_public_key,
        pkp_eth_address,
        pkp_token_id,
        lit_action_ipfs_cid: lit_action_cid.to_string(),
        created_at: Utc::now(),
    })
}

async fn store_crypto_session(
    state: &AppState,
    config: &CryptoSessionConfig,
    pkp_info: &SessionPkpInfo,
    counter_address: &str,
) -> Result<(), CryptoSpendError> {
    sqlx::query!(
        r#"
        UPDATE ai_agent_sessions
        SET 
            crypto_enforced = TRUE,
            spending_counter_address = $2,
            lit_access_conditions = $3,
            metadata = metadata || jsonb_build_object(
                'pkp_public_key', $4::text,
                'pkp_eth_address', $5::text,
                'pkp_token_id', $6::text,
                'lit_action_cid', $7::text,
                'crypto_enforcement_enabled_at', NOW()
            )
        WHERE id = $1
        "#,
        config.session_id,
        counter_address,
        serde_json::json!({
            "type": "lit_action",
            "ipfs_cid": pkp_info.lit_action_ipfs_cid,
            "pkp_bound": true
        }),
        pkp_info.pkp_public_key,
        pkp_info.pkp_eth_address,
        pkp_info.pkp_token_id,
        pkp_info.lit_action_ipfs_cid
    )
    .execute(&state.db)
    .await
    .map_err(|e| CryptoSpendError::Database(e.to_string()))?;
    
    Ok(())
}

#[derive(Debug)]
pub enum CryptoSpendError {
    SessionNotFound,
    NoPkp,
    InvalidAmount,
    InvalidConfiguration(String),
    LitError(String),
    Database(String),
}

impl std::fmt::Display for CryptoSpendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionNotFound => write!(f, "Session not found or expired"),
            Self::NoPkp => write!(f, "Session does not have a PKP"),
            Self::InvalidAmount => write!(f, "Invalid amount"),
            Self::InvalidConfiguration(e) => write!(f, "Invalid configuration: {}", e),
            Self::LitError(e) => write!(f, "Lit Protocol error: {}", e),
            Self::Database(e) => write!(f, "Database error: {}", e),
        }
    }
}

impl std::error::Error for CryptoSpendError {}

impl From<CryptoSpendError> for (StatusCode, Json<serde_json::Value>) {
    fn from(error: CryptoSpendError) -> Self {
        let (status, error_type) = match &error {
            CryptoSpendError::SessionNotFound => (StatusCode::NOT_FOUND, "session_not_found"),
            CryptoSpendError::NoPkp => (StatusCode::BAD_REQUEST, "no_pkp"),
            CryptoSpendError::InvalidAmount => (StatusCode::BAD_REQUEST, "invalid_amount"),
            CryptoSpendError::InvalidConfiguration(_) => (StatusCode::INTERNAL_SERVER_ERROR, "invalid_configuration"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        
        (status, Json(serde_json::json!({
            "error": error_type,
            "message": error.to_string()
        })))
    }
}
