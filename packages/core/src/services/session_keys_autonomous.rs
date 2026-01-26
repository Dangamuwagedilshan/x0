use axum::{
    extract::{State, Path, Extension},
    http::{StatusCode, HeaderMap},
    Json,
};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_sdk::{
    signature::Keypair,
    transaction::Transaction,
};
use chrono::{DateTime, Utc};
use bigdecimal::{BigDecimal, ToPrimitive};
use std::str::FromStr;
use sqlx::types::ipnetwork;

use crate::{
    AppState,
    auth::AuthenticatedPlatform,
    services::key_manager::SecureKeyManager,
};

#[derive(Debug, Deserialize)]
pub struct EnableAutonomyRequest {
    pub max_amount_usd: f64,
    pub duration_hours: u32,
    pub delegation_signature: String,
    pub expires_at: Option<String>,
    pub lit_encrypted_keypair: Option<String>,
    pub lit_data_hash: Option<String>,
    
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct EnableAutonomyResponse {
    pub delegate_id: Uuid,
    pub session_key_id: Uuid,
    pub max_amount_usd: f64,
    pub expires_at: DateTime<Utc>,
    pub delegate_public_key: String,
    pub autonomous_mode_enabled: bool,
    pub lit_protocol_enabled: bool,
    pub requires_lit_for_auto_sign: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeAutonomyRequest {
    pub reason: Option<String>,
}

pub async fn enable_autonomous_signing(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Path(session_key_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<EnableAutonomyRequest>,
) -> Result<Json<EnableAutonomyResponse>, (StatusCode, Json<serde_json::Value>)> {
    
    tracing::info!(
        "Enabling autonomous mode for session key {} (platform {})",
        session_key_id,
        platform.platform_id
    );
    
    if request.max_amount_usd <= 0.0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "max_amount_usd must be positive"
            }))
        ));
    }
    
    if request.duration_hours == 0 || request.duration_hours > 168 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "duration_hours must be between 1 and 168 (7 days)"
            }))
        ));
    }
    
    let session_key = sqlx::query!{
        r#"
        SELECT 
            sk.id,
            sk.platform_id,
            sk.session_keypair_id,
            sk.lit_encrypted_keypair_id,
            sk.limit_usdc,
            sk.used_amount_usdc,
            sk.expires_at,
            sk.is_active,
            ek.public_key,
            ek.encryption_mode
        FROM session_keys sk
        JOIN encrypted_keys ek ON sk.session_keypair_id = ek.id
        WHERE sk.id = $1 AND sk.platform_id = $2
        "#,
        session_key_id,
        platform.platform_id
    }
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Database error"}))
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Session key not found"}))
        )
    })?;
    
    if session_key.is_active != Some(true) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Session key is not active"
            }))
        ));
    }
    
    if session_key.expires_at < Utc::now() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Session key has expired"
            }))
        ));
    }
    
    let is_device_bound = session_key.encryption_mode.as_deref() == Some("device_bound");
    
    let mut lit_encrypted_keypair_id: Option<Uuid> = session_key.lit_encrypted_keypair_id;
    let mut lit_protocol_enabled = lit_encrypted_keypair_id.is_some();
    
    if is_device_bound {
        if let (Some(lit_ciphertext), Some(lit_hash)) = (&request.lit_encrypted_keypair, &request.lit_data_hash) {
            tracing::info!(
                "Device-bound session key {} - storing Lit Protocol encrypted copy for autonomous signing",
                session_key_id
            );
            
            let lit_keypair_id = store_lit_encrypted_keypair_for_delegate(
                &state,
                session_key_id,
                &session_key.public_key,
                lit_ciphertext,
                lit_hash,
            ).await.map_err(|e| {
                tracing::error!("Failed to store Lit-encrypted keypair: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "Failed to store Lit-encrypted keypair",
                        "details": e.to_string()
                    }))
                )
            })?;
            
            lit_encrypted_keypair_id = Some(lit_keypair_id);
            lit_protocol_enabled = true;
            
            tracing::info!(
                "Lit-encrypted keypair stored with ID {} for session key {}",
                lit_keypair_id, session_key_id
            );
        } else if lit_encrypted_keypair_id.is_some() {
            tracing::info!(
                "Device-bound session key {} already has Lit-encrypted keypair: {} (autonomous signing enabled)",
                session_key_id, lit_encrypted_keypair_id.unwrap()
            );
        } else {
            tracing::warn!(
                "Device-bound session key {} without Lit-encrypted keypair - \
                 autonomous signing will require client signature fallback",
                session_key_id
            );
        }
    } else {
        tracing::warn!(
            "Session key {} is custodial mode - autonomous delegates work best with device-bound keys",
            session_key_id
        );
    }
    
    let expires_at = if let Some(client_expiry_str) = &request.expires_at {
        DateTime::parse_from_rfc3339(client_expiry_str)
            .map_err(|e| {
                tracing::error!("Invalid expires_at format: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Invalid expires_at format"}))
                )
            })?
            .with_timezone(&Utc)
    } else {
        Utc::now() + chrono::Duration::hours(request.duration_hours as i64)
    };

    let max_expected_expiry = Utc::now() + chrono::Duration::hours(request.duration_hours as i64) + chrono::Duration::minutes(15);
    if expires_at > max_expected_expiry {
         return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "expires_at exceeds requested duration"
            }))
        ));
    }

    let expiry_string = if let Some(client_expiry_str) = &request.expires_at {
        client_expiry_str.clone()
    } else {
        expires_at.to_rfc3339()
    };

    let delegation_message = format!(
        "I authorize autonomous delegate for session {} to spend up to ${} until {}",
        session_key_id,
        request.max_amount_usd,
        expiry_string
    );
    
    let public_key = &session_key.public_key;
    verify_delegation_signature(public_key, &request.delegation_signature, &delegation_message)
        .map_err(|e| {
            tracing::error!("Delegation signature verification failed: {}", e);
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": format!("Invalid delegation signature: {}", e)}))
            )
        })?;
    
    tracing::info!("Delegation signature verified successfully");
    
    let delegate_public_key = session_key.public_key.clone();
    
    tracing::info!(
        "Creating autonomous delegate for session key {} (pubkey: {})",
        session_key_id,
        delegate_public_key
    );
    
    let delegate_id = sqlx::query_scalar!(
        r#"
        INSERT INTO autonomous_delegates (
            session_key_id,
            lit_encrypted_keypair_id,
            max_amount_usd,
            expires_at,
            delegation_signature,
            delegation_message,
            created_from_ip,
            created_from_device,
            metadata
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
        session_key_id,
        lit_encrypted_keypair_id,
        BigDecimal::from_str(&request.max_amount_usd.to_string())
            .map_err(|e| {
                tracing::error!("Failed to parse max_amount_usd: {}", e);
                (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid amount" })))
            })?,
        expires_at,
        request.delegation_signature,
        delegation_message,
        None::<ipnetwork::IpNetwork>,
        headers.get("user-agent").and_then(|h| h.to_str().ok()),
        request.metadata.unwrap_or(serde_json::json!({}))
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create delegate: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to create delegate"}))
        )
    })?;
    
    tracing::info!(
        "Created autonomous delegate {} (lit_protocol_enabled: {})",
        delegate_id, lit_protocol_enabled
    );
    
    let _ = crate::services::webhooks::send_webhook_event_for_autonomous_delegates(
        &state,
        delegate_id,
        platform.platform_id,
        crate::services::webhooks::WebhookEventType::AutonomousDelegateCreated,
    ).await;
    
    let requires_lit_for_auto_sign = if is_device_bound && !lit_protocol_enabled {
        Some(true)
    } else {
        None
    };
    
    Ok(Json(EnableAutonomyResponse {
        delegate_id,
        session_key_id,
        max_amount_usd: request.max_amount_usd,
        expires_at,
        delegate_public_key,
        autonomous_mode_enabled: true,
        lit_protocol_enabled,
        requires_lit_for_auto_sign,
    }))
}

pub async fn revoke_autonomous_mode(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Path(session_key_id): Path<Uuid>,
    Json(request): Json<RevokeAutonomyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    
    tracing::info!(
        "Revoking autonomous mode for session key {} (platform {})",
        session_key_id,
        platform.platform_id
    );
    
    let reason = request.reason.unwrap_or_else(|| "User revoked".to_string());
    let revoked_count = sqlx::query!(
        r#"
        UPDATE autonomous_delegates ad
        SET revoked_at = NOW(),
            metadata = metadata || jsonb_build_object('revocation_reason', $3::text)
        FROM session_keys sk
        WHERE ad.session_key_id = sk.id
          AND sk.id = $1
          AND sk.platform_id = $2
          AND ad.revoked_at IS NULL
          AND ad.expires_at > NOW()
        "#,
        session_key_id,
        platform.platform_id,
        reason
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Database error"}))
        )
    })?
    .rows_affected();
    
    if revoked_count == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "No active autonomous delegates found"
            }))
        ));
    }
    
    tracing::info!("Revoked {} autonomous delegate(s)", revoked_count);
    
    Ok(Json(serde_json::json!({
        "revoked": true,
        "count": revoked_count
    })))
}

pub async fn get_autonomy_status(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Path(session_key_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    
    let delegate = sqlx::query!(
        r#"
        SELECT 
            ad.id,
            ad.max_amount_usd,
            ad.used_amount_usd,
            ad.expires_at,
            ad.created_at,
            ad.revoked_at,
            ad.last_used_at
        FROM autonomous_delegates ad
        JOIN session_keys sk ON ad.session_key_id = sk.id
        WHERE sk.id = $1
          AND sk.platform_id = $2
          AND ad.revoked_at IS NULL
        ORDER BY ad.created_at DESC
        LIMIT 1
        "#,
        session_key_id,
        platform.platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Database error"}))
        )
    })?;
    
    if let Some(d) = delegate {
        let is_active = d.revoked_at.is_none() && d.expires_at > Utc::now();
        let max_amount = d.max_amount_usd.to_f64().unwrap_or(0.0);
        let used_amount = d.used_amount_usd
            .as_ref()
            .and_then(|v| v.to_f64())
            .unwrap_or(0.0);
        
        Ok(Json(serde_json::json!({
            "autonomous_mode_enabled": is_active,
            "delegate": {
                "id": d.id,
                "is_active": is_active,
                "max_amount_usd": max_amount,
                "used_amount_usd": used_amount,
                "remaining_usd": max_amount - used_amount,
                "expires_at": d.expires_at,
                "created_at": d.created_at,
                "revoked_at": d.revoked_at,
                "last_used_at": d.last_used_at,
            }
        })))
    } else {
        Ok(Json(serde_json::json!({
            "autonomous_mode_enabled": false,
            "delegate": null
        })))
    }
}

pub async fn get_active_delegate(
    state: &AppState,
    session_key_id: Uuid,
) -> Result<Option<ActiveDelegate>, Box<dyn std::error::Error + Send + Sync>> {
    
    let delegate = sqlx::query!(
        r#"
        SELECT 
            ad.id,
            ad.session_key_id,
            sk.session_keypair_id,
            ad.lit_encrypted_keypair_id,
            ad.max_amount_usd as "max_amount_usd!",
            ad.used_amount_usd as "used_amount_usd!",
            ad.expires_at,
            ek.encryption_mode
        FROM autonomous_delegates ad
        JOIN session_keys sk ON ad.session_key_id = sk.id
        JOIN encrypted_keys ek ON sk.session_keypair_id = ek.id
        WHERE ad.session_key_id = $1
          AND ad.revoked_at IS NULL
          AND ad.expires_at > NOW()
        ORDER BY ad.created_at DESC
        LIMIT 1
        "#,
        session_key_id
    )
    .fetch_optional(&state.db)
    .await?;
    
    Ok(delegate.map(|d| ActiveDelegate {
        id: d.id,
        _session_key_id: d.session_key_id,
        session_keypair_id: d.session_keypair_id,
        lit_encrypted_keypair_id: d.lit_encrypted_keypair_id,
        session_encryption_mode: d.encryption_mode,
        max_amount_usd: d.max_amount_usd,
        used_amount_usd: d.used_amount_usd,
        expires_at: d.expires_at,
    }))
}

#[derive(Debug, Clone)]
pub struct ActiveDelegate {
    pub id: Uuid,
    pub _session_key_id: Uuid,
    pub session_keypair_id: Uuid,
    pub lit_encrypted_keypair_id: Option<Uuid>,
    pub session_encryption_mode: Option<String>,
    pub max_amount_usd: BigDecimal,
    pub used_amount_usd: BigDecimal,
    pub expires_at: DateTime<Utc>,
}

impl ActiveDelegate {
    pub fn can_spend(&self, amount: f64) -> bool {
        let max = self.max_amount_usd.to_f64().unwrap_or(0.0);
        let used = self.used_amount_usd.to_f64().unwrap_or(0.0);
        let remaining = max - used;
        
        amount <= remaining && !self.is_expired()
    }
    
    pub fn remaining_usd(&self) -> f64 {
        let max = self.max_amount_usd.to_f64().unwrap_or(0.0);
        let used = self.used_amount_usd.to_f64().unwrap_or(0.0);
        max - used
    }
    
    pub fn max_usd(&self) -> f64 {
        self.max_amount_usd.to_f64().unwrap_or(0.0)
    }
    
    pub fn used_usd(&self) -> f64 {
        self.used_amount_usd.to_f64().unwrap_or(0.0)
    }
    
    pub fn session_key_id(&self) -> Uuid {
        self._session_key_id
    }
    
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }
    
    pub fn signing_keypair_id(&self) -> Option<Uuid> {
        if let Some(lit_id) = self.lit_encrypted_keypair_id {
            return Some(lit_id);
        }
        
        if self.session_encryption_mode.as_deref() != Some("device_bound") {
            return Some(self.session_keypair_id);
        }
        
        None
    }
}

pub async fn sign_with_delegate(
    state: &AppState,
    session_keypair_id: Uuid,
    transaction: &Transaction,
) -> Result<Transaction, Box<dyn std::error::Error + Send + Sync>> {
    let fee_router = crate::services::fee_router::FeeRouterClient::new();
    fee_router.validate_transaction_uses_fee_router(transaction)
        .map_err(|e| format!("Fee router validation failed: {}. All payments must route through the x0 fee router.", e))?;
    
    tracing::info!("Transaction validated: routes through x0 fee router");
    
    let key_record = sqlx::query!(
        r#"
        SELECT encryption_mode, encrypted_key_data, nonce, key_type, key_metadata
        FROM encrypted_keys
        WHERE id = $1 AND is_active = TRUE
        "#,
        session_keypair_id
    )
    .fetch_one(&state.db)
    .await?;

    let cache_key = crate::services::keypair_cache::cache_key(&session_keypair_id, &key_record.key_type);
    if let Some(cached_keypair) = state.keypair_cache.get_keypair(&cache_key) {
        let mut signed_tx = transaction.clone();
        signed_tx.sign(&[&cached_keypair], transaction.message.recent_blockhash);
        tracing::info!("Transaction signed with CACHED autonomous delegate keypair (Memory)");
        return Ok(signed_tx);
    }

    if let Ok(Some(cached_keypair)) = crate::services::keypair_cache::get_keypair_from_redis(state, &cache_key).await {
        state.keypair_cache.insert_keypair(
            cache_key.clone(), 
            cached_keypair.insecure_clone(), 
            session_keypair_id
        );
        
        let mut signed_tx = transaction.clone();
        signed_tx.sign(&[&cached_keypair], transaction.message.recent_blockhash);
        tracing::info!("Transaction signed with CACHED autonomous delegate keypair (Redis)");
        return Ok(signed_tx);
    }

    let delegate_keypair = match key_record.encryption_mode.as_deref() {
        Some("lit_protocol") => {
            tracing::info!("Decrypting delegate keypair with Lit Protocol");
            
            use lit_rust_sdk::{
                auth::load_wallet_from_env,
                types::{DecryptRequest, LitResourceAbilityRequest, LitResourceAbilityRequestResource, LitAbility, EvmContractCondition},
                LitNetwork, LitNodeClient, LitNodeClientConfig,
            };
            use std::time::Duration;
            
            let _wallet = load_wallet_from_env()
                .map_err(|e| format!("Failed to load Ethereum wallet for Lit: {}", e))?;
            
            let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
            let lit_network = std::env::var("LIT_NETWORK")
                .unwrap_or_else(|_| "DatilDev".to_string());
            
            let network = match lit_network.as_str() {
                "Datil" | "mainnet" => LitNetwork::Datil,
                "DatilTest" | "testnet" => LitNetwork::DatilTest,
                _ => LitNetwork::DatilDev,
            };
            
            tracing::info!("Connecting to Lit Network: {:?}", network);
            
            let config = LitNodeClientConfig {
                lit_network: network,
                alert_when_unauthorized: true,
                debug: false,
                connect_timeout: Duration::from_secs(30),
                check_node_attestation: environment == "production",
            };
            
            let mut client = LitNodeClient::new(config)
                .await
                .map_err(|e| format!("Failed to create Lit client: {}", e))?;
            
            client.connect()
                .await
                .map_err(|e| format!("Failed to connect to Lit Network: {}", e))?;
            
            tracing::info!("Connected to Lit Network successfully");
            
            let metadata: serde_json::Value = key_record.key_metadata
                .ok_or("Missing key metadata for Lit-encrypted key")?;
            
            let access_conditions_value = metadata.get("access_conditions")
                .ok_or("Missing access_conditions in metadata")?;

            let evm_contract_conditions: Vec<EvmContractCondition> = 
                serde_json::from_value(access_conditions_value.clone())
                    .map_err(|e| format!("Failed to parse EVM contract conditions: {}. This delegate keypair may have been encrypted with old conditions and needs re-encryption.", e))?;
            
            if let Some(first_condition) = evm_contract_conditions.first() {
                if first_condition.function_name != "balanceOf" && first_condition.function_name != "totalSupply" {
                    return Err(format!(
                        "Invalid access conditions: expected 'balanceOf' or 'totalSupply', found '{}'. This delegate keypair was encrypted with old conditions and needs re-encryption.",
                        first_condition.function_name
                    ).into());
                }
                
                if first_condition.function_name == "balanceOf" {
                    if first_condition.function_params.len() != 1 || first_condition.function_params[0] != ":userAddress" {
                        return Err(format!(
                            "Invalid access conditions: balanceOf should have 1 parameter ':userAddress', found {:?}. This delegate keypair needs re-encryption.",
                            first_condition.function_params
                        ).into());
                    }
                    tracing::info!("Validated access conditions: balanceOf(:userAddress) - compatible with capacity delegation");
                } else {
                    tracing::warn!("Access conditions use legacy totalSupply() - may not work with capacity delegation. Consider re-encrypting with balanceOf(:userAddress)");
                }
            }
            
            let ciphertext = String::from_utf8(key_record.encrypted_key_data)
                .map_err(|_| "Invalid ciphertext encoding in database")?;

            let resource_ability_requests = vec![LitResourceAbilityRequest {
                resource: LitResourceAbilityRequestResource {
                    resource: "*".to_string(),
                    resource_prefix: "lit-accesscontrolcondition".to_string(),
                },
                ability: LitAbility::AccessControlConditionDecryption.to_string(),
            }];

            let expiration = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
            
            tracing::info!("Generating local session signatures with capacity delegation...");
            
            let delegatee_address = format!("{:#x}", _wallet.address());
            tracing::info!("Creating capacity auth sigs for delegatee address: {}", delegatee_address);
            let capacity_auth_sigs = match crate::services::lit_capacity::get_capacity_auth_sigs(
                &_wallet,
                network,
                Some(&state.redis),
                &delegatee_address,
            ).await {
                Ok(sigs) => {
                    tracing::info!("Capacity delegation auth sigs obtained (count: {})", sigs.len());
                    if !sigs.is_empty() {
                        tracing::debug!("First capacity auth sig: sig={}, address={}, derived_via={}", 
                            &sigs[0].sig[..20.min(sigs[0].sig.len())],
                            sigs[0].address,
                            sigs[0].derived_via
                        );
                    }
                    sigs
                },
                Err(e) => {
                    tracing::error!("Failed to get capacity auth sigs: {}. Continuing without capacity delegation (may hit rate limits)", e);
                    vec![]
                }
            };
            
            let session_sigs = client
                .get_local_session_sigs(&_wallet, resource_ability_requests, &expiration, capacity_auth_sigs)
                .await
                .map_err(|e| format!("Failed to create session signatures: {}", e))?;

            let decrypt_params = DecryptRequest {
                ciphertext,
                data_to_encrypt_hash: String::from_utf8(key_record.nonce.clone())
                    .unwrap_or_else(|_| {
                        hex::encode(&key_record.nonce)
                    }),
                access_control_conditions: None,
                evm_contract_conditions: Some(evm_contract_conditions),
                sol_rpc_conditions: None,
                unified_access_control_conditions: None,
                chain: Some("ethereum".to_string()),
                session_sigs, 
            };
            
            tracing::info!("Decrypting delegate keypair with Lit Protocol (EVM conditions only)...");
            
            let mut last_error = String::new();
            let keypair = 'retry: loop {
                for attempt in 1..=5 {
                    match client.decrypt(decrypt_params.clone()).await {
                        Ok(response) => {
                            tracing::info!("Delegate keypair decrypted successfully with Lit Protocol (attempt {})", attempt);
                            let decrypted_bytes = response.decrypted_data;
                            
                            if decrypted_bytes.len() != 64 {
                                return Err(format!(
                                    "Invalid keypair length: expected 64 bytes, got {}",
                                    decrypted_bytes.len()
                                ).into());
                            }
                            
                            let mut keypair_bytes = [0u8; 64];
                            keypair_bytes.copy_from_slice(&decrypted_bytes);
                            
                            break 'retry Keypair::try_from(&keypair_bytes[..])
                                .map_err(|e| format!("Failed to reconstruct keypair from decrypted bytes: {}", e))?;
                        }
                        Err(e) => {
                            let error_str = e.to_string();
                            let error_debug = format!("{:?}", e);
                            last_error = error_str.clone();
                            
                            tracing::error!(
                                "Lit decrypt attempt {}/5 failed: {} | Debug: {}", 
                                attempt, 
                                error_str, 
                                error_debug
                            );
                            
                            if error_str.contains("rate_limit_exceeded") || error_str.contains("Rate limit") {
                                let delay = Duration::from_millis(1000 * attempt as u64);
                                tracing::warn!(
                                    "Lit rate limit hit (attempt {}/5), retrying after {:?}...", 
                                    attempt, 
                                    delay
                                );
                                tokio::time::sleep(delay).await;
                                continue;
                            } else {
                                if attempt < 5 {
                                    let delay = Duration::from_millis(500 * attempt as u64);
                                    tracing::warn!(
                                        "Lit decrypt failed with non-rate-limit error (attempt {}/5), retrying after {:?}...", 
                                        attempt, 
                                        delay
                                    );
                                    tokio::time::sleep(delay).await;
                                    continue;
                                }
                                return Err(format!(
                                    "Lit decryption failed after {} attempts: {}. Full error: {}", 
                                    attempt, 
                                    error_str,
                                    error_debug
                                ).into());
                            }
                        }
                    }
                }
                
                return Err(format!(
                    "Lit decryption failed after 5 attempts due to rate limiting: {}. Consider upgrading Lit Protocol capacity credits or reducing request rate.", 
                    last_error
                ).into());
            };
            
            keypair
        }
        Some("custodial") | Some("device_bound") | None => {
            tracing::info!("Decrypting delegate keypair with SecureKeyManager");
            
            let key_manager = SecureKeyManager::from_env()?;
            key_manager.retrieve_keypair_by_id(
                state,
                session_keypair_id,
            ).await?
        }
        Some(other) => {
            return Err(format!("Unsupported encryption mode: {}", other).into());
        }
    };
    
    state.keypair_cache.insert_keypair(
        cache_key.clone(),
        delegate_keypair.insecure_clone(),
        session_keypair_id
    );
    
    let _ = crate::services::keypair_cache::store_keypair_in_redis(
        state,
        &cache_key,
        &delegate_keypair,
        std::time::Duration::from_secs(900)
    ).await;
    
    let mut signed_tx = transaction.clone();
    signed_tx.sign(&[&delegate_keypair], transaction.message.recent_blockhash);
    
    tracing::info!("Transaction signed successfully with autonomous delegate");
    
    Ok(signed_tx)
}

pub struct AttestationSigningParams {
    pub delegate: ActiveDelegate,
    pub session_keypair_id: Uuid,
    pub platform_id: Uuid,
    pub payment_id: Uuid,
    pub amount_usd: f64,
}

pub struct AttestationSigningResult {
    pub signed_transaction: Transaction,
    pub attestation: Option<crate::services::attestation::SignedSpendingAttestation>,
}

pub async fn sign_with_attestation(
    state: &AppState,
    params: AttestationSigningParams,
    transaction: &Transaction,
) -> Result<AttestationSigningResult, Box<dyn std::error::Error + Send + Sync>> {
    let signed_attestation = if let Some(ref signer) = state.attestation_signer {
        let attestation_params = crate::services::attestation::AttestationParams {
            delegate_id: params.delegate.id,
            session_key_id: params.delegate.session_key_id(),
            platform_id: params.platform_id,
            spent_usd: params.delegate.used_usd(),
            limit_usd: params.delegate.max_usd(),
            requested_usd: params.amount_usd,
            payment_id: params.payment_id,
        };
        
        let attestation = match signer.create_attestation(attestation_params) {
            Ok(att) => Some(att),
            Err(e) => {
                tracing::error!(
                    "Failed to create spending attestation: {}. Continuing with payment (attestation is optional).",
                    e
                );
                None
            }
        };
        if let Some(ref attestation) = attestation {
            tracing::info!(
                "Created spending attestation for payment {} (delegate: {}, remaining after: ${})",
                params.payment_id,
                params.delegate.id,
                attestation.attestation.remaining_after_usd
            );
            
            if let Err(e) = crate::services::attestation::store_attestation(state, attestation).await {
                tracing::error!(
                    "Failed to store spending attestation: {}. Continuing with payment (attestation is optional).",
                    e
                );
            }
        }
        
        attestation
    } else {
        tracing::debug!(
            "Attestation signer not configured - using programmatic-only enforcement for payment {}",
            params.payment_id
        );
        None
    };
    
    let signed_tx = sign_with_delegate(
        state,
        params.session_keypair_id,
        transaction,
    ).await?;
    
    Ok(AttestationSigningResult {
        signed_transaction: signed_tx,
        attestation: signed_attestation,
    })
}


pub async fn record_delegate_usage(
    state: &AppState,
    delegate_id: Uuid,
    amount_usd: f64,
    payment_id: Option<Uuid>,
    transaction_signature: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    
    let amount_bd = BigDecimal::from_str(&amount_usd.to_string())?;
    
    sqlx::query!(
        r#"
        UPDATE autonomous_delegates
        SET 
            used_amount_usd = used_amount_usd + $2,
            last_used_at = NOW()
        WHERE id = $1
        "#,
        delegate_id,
        amount_bd
    )
    .execute(&state.db)
    .await?;
    
    sqlx::query!(
        r#"
        INSERT INTO autonomous_delegate_usage (
            delegate_id,
            payment_id,
            amount_usd,
            transaction_signature
        ) VALUES ($1, $2, $3, $4)
        "#,
        delegate_id,
        payment_id,
        amount_bd,
        transaction_signature
    )
    .execute(&state.db)
    .await?;
    
    Ok(())
}

fn verify_delegation_signature(
    public_key_str: &str,
    signature_base64: &str,
    message: &str,
) -> Result<(), String> {
    use solana_sdk::pubkey::Pubkey;
    use ed25519_dalek::{Verifier, Signature, VerifyingKey};
    use base64::Engine;
    let pubkey = Pubkey::from_str(public_key_str)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_base64)
        .map_err(|e| format!("Invalid base64 signature: {}", e))?;
    
    if signature_bytes.len() != 64 {
        return Err(format!("Invalid signature length: {} (expected 64)", signature_bytes.len()));
    }
    
    let signature_array: [u8; 64] = signature_bytes.try_into()
        .map_err(|_| "Invalid signature length")?;
    let signature = Signature::from_bytes(&signature_array);
    
    let verifying_key = VerifyingKey::from_bytes(&pubkey.to_bytes())
        .map_err(|e| format!("Invalid verifying key: {}", e))?;
    
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))?;
    
    Ok(())
}


async fn store_lit_encrypted_keypair_for_delegate(
    state: &AppState,
    session_key_id: Uuid,
    public_key: &str,
    lit_ciphertext: &str,
    lit_data_hash: &str,
) -> Result<Uuid, Box<dyn std::error::Error + Send + Sync>> {
    use lit_rust_sdk::types::{EvmContractCondition, ReturnValueTestV2};
    
    tracing::info!(
        "Storing client-provided Lit-encrypted keypair for session {} (pubkey: {})",
        session_key_id, public_key
    );
    
    let caller_check_abi = serde_json::json!({
        "constant": true,
        "inputs": [{"name": "account", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    });
    
    let caller_function: ethabi::Function = serde_json::from_value(caller_check_abi)
        .map_err(|e| format!("ABI error: {}", e))?;
    
    let evm_conditions = vec![EvmContractCondition {
        contract_address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
        function_name: "balanceOf".to_string(),
        function_params: vec![":userAddress".to_string()],
        function_abi: caller_function,
        chain: "ethereum".to_string(),
        return_value_test: ReturnValueTestV2 {
            key: "".to_string(),
            comparator: ">=".to_string(),
            value: "0".to_string(),
        },
    }];
    
    let key_id = Uuid::new_v4();
    
    sqlx::query!(
        r#"
        INSERT INTO encrypted_keys 
        (id, key_type, owner_id, encrypted_key_data, encryption_version, nonce, 
         public_key, key_metadata, is_active, encryption_mode, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
        "#,
        key_id,
        "autonomous_delegate_lit",
        session_key_id,
        lit_ciphertext.as_bytes(),
        1,
        lit_data_hash.as_bytes(),
        public_key,
        serde_json::json!({
            "lit_encrypted": true,
            "client_provided": true,
            "session_key_id": session_key_id,
            "access_conditions": evm_conditions
        }),
        true,
        "lit_protocol"
    )
    .execute(&state.db)
    .await?;
    
    tracing::info!(
        "Lit-encrypted keypair stored: {} (session: {})",
        key_id, session_key_id
    );
    
    Ok(key_id)
}
