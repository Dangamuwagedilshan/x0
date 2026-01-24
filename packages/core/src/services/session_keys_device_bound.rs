use axum::{
    extract::{State, Path, Extension},
    http::{StatusCode, HeaderMap},
    Json,
};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use base64::{Engine as _, engine::general_purpose};
use std::str::FromStr;
use bigdecimal::BigDecimal;
use sha2::Digest;
use crate::{
    AppState,
    auth::AuthenticatedPlatform,
    services::key_manager::SecureKeyManager,
};

#[derive(Debug, Deserialize)]
pub struct CreateDeviceBoundSessionKeyRequest {
    pub user_wallet: String,
    pub agent_id: String,
    pub agent_name: Option<String>, 
    pub limit_usdc: f64,
    pub duration_days: u32,
    pub encrypted_session_key: String,
    pub nonce: String,
    pub session_public_key: String,
    pub device_fingerprint: String,
    pub recovery_qr_data: Option<String>,
    
    pub lit_encrypted_keypair: Option<String>,
    pub lit_data_hash: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateDeviceBoundSessionKeyResponse {
    pub session_key_id: String,
    pub mode: String,
    pub is_custodial: bool,
    pub user_wallet: String,
    pub agent_id: String,
    pub agent_name: Option<String>,
    pub session_wallet: String,
    pub limit_usdc: f64,
    pub expires_at: String,
    pub requires_client_signing: bool,
    pub cross_app_compatible: bool,
    pub security_info: SecurityInfo,
}

#[derive(Debug, Serialize)]
pub struct SecurityInfo {
    pub encryption_type: String,
    pub device_bound: bool,
    pub backend_can_decrypt: bool,
    pub recovery_qr_saved: bool,
}

#[derive(Debug, Deserialize)]
pub struct GetEncryptedKeyRequest {
    pub session_key_id: String,
    pub device_fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct GetEncryptedKeyResponse {
    pub encrypted_session_key: String,
    pub nonce: String,
    pub device_fingerprint_valid: bool,
}

#[derive(Debug, Deserialize)]
pub struct RecoverSessionKeyRequest {
    pub recovery_qr_data: String,
    pub new_device_fingerprint: String,
    pub new_encrypted_session_key: String,
    pub new_nonce: String,
}

pub async fn create_device_bound_session_key(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    headers: HeaderMap,
    Json(request): Json<CreateDeviceBoundSessionKeyRequest>,
) -> Result<Json<CreateDeviceBoundSessionKeyResponse>, (StatusCode, Json<serde_json::Value>)> {
    tracing::info!(
        "Creating DEVICE-BOUND agent-scoped session key for agent '{}' ((platform {}, NON-CUSTODIAL mode)",
        request.agent_id, platform.platform_id
    );
    
    if request.agent_id.is_empty() || request.agent_id.len() > 255 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "agent_id is required and must be 1-255 characters",
                "message": "Use a consistent agent_id like 'shopping-assistant-v1' for cross-app compatibility"
            }))
        ));
    }
    
    if request.limit_usdc <= 0.0 || request.limit_usdc > 10_000.0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid limit_usdc",
                "message": "Limit must be between $0.01 and $10,000"
            }))
        ));
    }
    
    if request.duration_days == 0 || request.duration_days > 30 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid duration_days",
                "message": "Duration must be between 1 and 30 days"
            }))
        ));
    }
    
    let _user_pubkey = Pubkey::from_str(&request.user_wallet)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid user_wallet",
                "message": "Must be a valid Solana public key"
            }))
        ))?;
    
    let _session_pubkey = Pubkey::from_str(&request.session_public_key)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid session_public_key",
                "message": "Must be a valid Solana public key"
            }))
        ))?;
    
    if request.device_fingerprint.len() != 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid device_fingerprint",
                "message": "Must be 64 hex characters (SHA-256 hash)"
            }))
        ));
    }
    
    let encrypted_key_data = general_purpose::STANDARD.decode(&request.encrypted_session_key)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid encrypted_session_key encoding",
                "message": "Must be valid base64"
            }))
        ))?;
    
    let nonce = general_purpose::STANDARD.decode(&request.nonce)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid nonce encoding",
                "message": "Must be valid base64"
            }))
        ))?;
    
    if nonce.len() != 12 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid nonce size",
                "message": "Nonce must be 12 bytes"
            }))
        ));
    }
    
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .or_else(|| headers.get("x-real-ip").and_then(|h| h.to_str().ok()))
        .unwrap_or("unknown")
        .to_string();
    
    tracing::debug!(
        "Device-bound session key request validated: wallet={}, device={}, ip={}",
        request.user_wallet,
        &request.device_fingerprint[..16],
        ip_address
    );
    
    if let Ok(Some(existing_session_key_id)) = crate::services::agent_session_keys::find_existing_agent_session(
        &state.db,
        &request.user_wallet,
        &request.agent_id,
    ).await {
        tracing::info!(
            "⚡ Found existing device-bound session key {} for agent '{}' - auto-authorizing recipient {}",
            existing_session_key_id, request.agent_id, platform.platform_id
        );

        if let Err(e) = crate::services::agent_session_keys::authorize_recipient_for_session_key(
            &state.db,
            existing_session_key_id,
            platform.platform_id,
            &request.agent_id,
            None,
        ).await {
            tracing::warn!("Failed to auto-authorize recipient: {}", e);
        }

        let existing_session = sqlx::query!(
            r#"
            SELECT id, user_wallet, session_wallet_address, limit_usdc, 
                   expires_at, agent_id, agent_name, recovery_qr_generated
            FROM session_keys
            WHERE id = $1
            "#,
            existing_session_key_id
        )
        .fetch_one(&state.db)
        .await
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to fetch existing session key",
                "details": e.to_string()
            }))
        ))?;

        let agent_id_value = existing_session.agent_id.clone().unwrap_or_else(|| request.agent_id.clone());
        let agent_name_value = existing_session.agent_name.clone();
        let limit_value = existing_session.limit_usdc.to_string().parse::<f64>().unwrap_or(0.0);

        return Ok(Json(CreateDeviceBoundSessionKeyResponse {
            session_key_id: existing_session.id.to_string(),
            mode: "device_bound".to_string(),
            is_custodial: false,
            user_wallet: existing_session.user_wallet.unwrap_or(request.user_wallet),
            agent_id: agent_id_value,
            agent_name: agent_name_value,
            session_wallet: existing_session.session_wallet_address.unwrap_or_default(),
            limit_usdc: limit_value,
            expires_at: existing_session.expires_at.to_rfc3339(),
            requires_client_signing: true,
            cross_app_compatible: true,
            security_info: SecurityInfo {
                encryption_type: "Argon2id + AES-256-GCM".to_string(),
                device_bound: true,
                backend_can_decrypt: false,
                recovery_qr_saved: existing_session.recovery_qr_generated.unwrap_or(false),
            },
        }));
    }
    
    let key_manager = SecureKeyManager::from_env()
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Key manager initialization failed",
                "details": e.to_string()
            }))
        ))?;
    
    let encrypted_key_id = key_manager.store_client_encrypted_keypair(
        &state,
        encrypted_key_data,
        nonce,
        request.session_public_key.clone(),
        request.device_fingerprint.clone(),
        "ai_session_key",
        platform.platform_id,
        Some(serde_json::json!({
            "mode": "device_bound",
            "recovery_qr_provided": request.recovery_qr_data.is_some(),
            "created_from_ip": ip_address,
        })),
    )
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "Failed to store encrypted key",
            "details": e.to_string()
        }))
    ))?;
    
    tracing::info!(
        "Client-encrypted key stored: key_id={}, platform={}",
        encrypted_key_id,
        platform.platform_id
    );
    
    let session_key_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::days(request.duration_days as i64);
    let limit_decimal = BigDecimal::from_str(&request.limit_usdc.to_string())
        .unwrap_or_else(|_| BigDecimal::from(0));
    
    let recovery_qr_hash = request.recovery_qr_data.as_ref().map(|qr_data| {
        format!("{:x}", sha2::Sha256::digest(qr_data.as_bytes()))
    });
    
    let agent_name = request.agent_name.as_deref();
    
    sqlx::query!(
        r#"
        INSERT INTO session_keys (
            id, platform_id, session_keypair_id, 
            user_wallet, session_wallet_address,
            agent_id, agent_name, created_by_platform_id,
            limit_usdc, used_amount_usdc, expires_at, is_active,
            recovery_qr_generated, recovery_qr_hash, created_from_device, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $2, $8, 0, $9, TRUE, $10, $11, $12, NOW())
        "#,
        session_key_id,
        platform.platform_id,
        encrypted_key_id,
        request.user_wallet,
        request.session_public_key,
        request.agent_id,
        agent_name,
        limit_decimal,
        expires_at,
        request.recovery_qr_data.is_some(),
        recovery_qr_hash,
        request.device_fingerprint,
    )
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "Failed to create session key record",
            "details": e.to_string()
        }))
    ))?;
    
    sqlx::query!(
        r#"
        INSERT INTO session_key_security_events 
        (session_key_id, platform_id, event_type, severity, description, action_taken, ip_address)
        VALUES ($1, $2, 'device_bound_created', 'low', $3, 'none', $4)
        "#,
        session_key_id,
        platform.platform_id,
        format!("Device-bound agent-scoped session key created for agent '{}' with ${} limit for {} days", 
            request.agent_id, request.limit_usdc, request.duration_days),
        sqlx::types::ipnetwork::IpNetwork::from_str(&ip_address).ok()
    )
    .execute(&state.db)
    .await
    .ok();
    
    if let (Some(lit_ciphertext), Some(lit_hash)) = (&request.lit_encrypted_keypair, &request.lit_data_hash) {
        tracing::info!(
            "Storing Lit-encrypted keypair for session {} (enables offline autonomous signing)",
            session_key_id
        );
        
        match store_lit_encrypted_keypair_for_session(
            &state,
            session_key_id,
            &request.session_public_key,
            lit_ciphertext,
            lit_hash,
        ).await {
            Ok(lit_keypair_id) => {
                if let Err(e) = sqlx::query!(
                    "UPDATE session_keys SET lit_encrypted_keypair_id = $1 WHERE id = $2",
                    lit_keypair_id,
                    session_key_id
                )
                .execute(&state.db)
                .await {
                    tracing::warn!("Failed to link Lit keypair: {}", e);
                } else {
                    tracing::info!(
                        "Lit-encrypted keypair stored: {} (session {})",
                        lit_keypair_id, session_key_id
                    );
                }
            }
            Err(e) => {
                tracing::warn!("Failed to store Lit-encrypted keypair: {}", e);
            }
        }
    }
    
    tracing::info!(
        "Device-bound agent-scoped session key created: id={}, agent={}, wallet={}, limit=${}, device={}",
        session_key_id,
        request.agent_id,
        request.user_wallet,
        request.limit_usdc,
        &request.device_fingerprint[..16]
    );
    
    Ok(Json(CreateDeviceBoundSessionKeyResponse {
        session_key_id: session_key_id.to_string(),
        mode: "device_bound".to_string(),
        is_custodial: false,
        user_wallet: request.user_wallet,
        agent_id: request.agent_id.clone(),
        agent_name: request.agent_name.clone(),
        session_wallet: request.session_public_key,
        limit_usdc: request.limit_usdc,
        expires_at: expires_at.to_rfc3339(),
        requires_client_signing: true,
        cross_app_compatible: true,
        security_info: SecurityInfo {
            encryption_type: "Argon2id + AES-256-GCM".to_string(),
            device_bound: true,
            backend_can_decrypt: false,
            recovery_qr_saved: request.recovery_qr_data.is_some(),
        },
    }))
}

pub async fn get_encrypted_session_key(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Json(request): Json<GetEncryptedKeyRequest>,
) -> Result<Json<GetEncryptedKeyResponse>, (StatusCode, Json<serde_json::Value>)> {
    let session_key_id = Uuid::from_str(&request.session_key_id)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid session_key_id"}))
        ))?;
    
    let session = sqlx::query!(
        r#"
        SELECT session_keypair_id, is_active, expires_at
        FROM session_keys
        WHERE id = $1 AND platform_id = $2
        "#,
        session_key_id,
        platform.platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": e.to_string()}))
    ))?
    .ok_or_else(|| (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "Session key not found"}))
    ))?;
    
    if !session.is_active.unwrap_or(false) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Session key is inactive"}))
        ));
    }
    
    if session.expires_at < chrono::Utc::now() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Session key has expired"}))
        ));
    }
    
    let key_manager = SecureKeyManager::from_env()
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()}))
        ))?;
    
    let (encrypted_data, nonce, stored_fingerprint) = key_manager
        .retrieve_client_encrypted_keypair(&state, session.session_keypair_id)
        .await
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()}))
        ))?;
    
    let device_fingerprint_valid = key_manager
        .validate_device_fingerprint(
            &state,
            session.session_keypair_id,
            &request.device_fingerprint
        )
        .await
        .unwrap_or(false);
    
    if !device_fingerprint_valid {
        tracing::warn!(
            "Device fingerprint mismatch for session {}: stored={}, provided={}",
            session_key_id,
            &stored_fingerprint[..16],
            &request.device_fingerprint[..16.min(request.device_fingerprint.len())]
        );
    }
    
    Ok(Json(GetEncryptedKeyResponse {
        encrypted_session_key: general_purpose::STANDARD.encode(&encrypted_data),
        nonce: general_purpose::STANDARD.encode(&nonce),
        device_fingerprint_valid,
    }))
}

pub async fn recover_session_key_on_new_device(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Path(session_key_id): Path<String>,
    Json(request): Json<RecoverSessionKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    tracing::info!(
        "Device recovery initiated for session key {} by platform {}",
        session_key_id,
        platform.platform_id
    );
    
    let session_key_uuid = Uuid::from_str(&session_key_id)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid session_key_id"}))
        ))?;
    
    let session = sqlx::query!(
        r#"
        SELECT session_keypair_id, recovery_qr_generated
        FROM session_keys
        WHERE id = $1 AND platform_id = $2
        "#,
        session_key_uuid,
        platform.platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": e.to_string()}))
    ))?
    .ok_or_else(|| (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "Session key not found"}))
    ))?;
    
    if !session.recovery_qr_generated.unwrap_or(false) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "No recovery QR available for this session key"
            }))
        ));
    }
    
    let recovery_qr_hash = format!("{:x}", sha2::Sha256::digest(request.recovery_qr_data.as_bytes()));
    
    let stored_hash = sqlx::query_scalar!(
        r#"
        SELECT recovery_qr_hash
        FROM session_keys
        WHERE id = $1
        "#,
        session_key_uuid
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": e.to_string()}))
    ))?
    .flatten();
    
    if let Some(stored) = stored_hash {
        if stored != recovery_qr_hash {
            tracing::warn!(
                "⚠️ Recovery QR hash mismatch for session key {} - potential attack",
                session_key_id
            );
            
            sqlx::query!(
                r#"
                INSERT INTO session_key_security_events 
                (session_key_id, platform_id, event_type, severity, description, action_taken)
                VALUES ($1, $2, 'recovery_qr_mismatch', 'critical', $3, 'recovery_blocked')
                "#,
                session_key_uuid,
                platform.platform_id,
                format!("Recovery QR hash mismatch: {} != {}", &stored[..16], &recovery_qr_hash[..16])
            )
            .execute(&state.db)
            .await
            .ok();
            
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Invalid recovery QR code",
                    "message": "The provided recovery QR does not match our records"
                }))
            ));
        }
    }
    
    let new_encrypted_data = general_purpose::STANDARD.decode(&request.new_encrypted_session_key)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid encrypted key encoding"}))
        ))?;
    
    let new_nonce = general_purpose::STANDARD.decode(&request.new_nonce)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid nonce encoding"}))
        ))?;
    
    sqlx::query!(
        r#"
        UPDATE encrypted_keys
        SET encrypted_key_data = $1,
            nonce = $2
        WHERE id = $3
        "#,
        new_encrypted_data,
        new_nonce,
        session.session_keypair_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": e.to_string()}))
    ))?;
    
    let key_manager = SecureKeyManager::from_env()
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to initialize key manager",
                "details": e.to_string()
            }))
        ))?;
    
    key_manager
        .update_device_fingerprint(&state, session.session_keypair_id, request.new_device_fingerprint.clone())
        .await
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to update device fingerprint",
                "details": e.to_string()
            }))
        ))?;
    
    sqlx::query!(
        r#"
        UPDATE session_keys
        SET last_recovery_at = NOW(),
            created_from_device = $1
        WHERE id = $2
        "#,
        request.new_device_fingerprint,
        session_key_uuid
    )
    .execute(&state.db)
    .await
    .ok();
    
    tracing::info!(
        "Session key {} recovered on new device (fingerprint={})",
        session_key_id,
        &request.new_device_fingerprint[..16]
    );
    
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Session key recovered successfully on new device",
        "session_key_id": session_key_id,
        "recovered_at": chrono::Utc::now().to_rfc3339()
    })))
}

async fn store_lit_encrypted_keypair_for_session(
    state: &AppState,
    session_key_id: Uuid,
    public_key: &str,
    lit_ciphertext: &str,
    lit_data_hash: &str,
) -> Result<Uuid, Box<dyn std::error::Error + Send + Sync>> {
    use lit_rust_sdk::types::{EvmContractCondition, ReturnValueTestV2};
    
    tracing::info!(
        "Storing Lit-encrypted keypair for session {} (pubkey: {})",
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
        "session_key_lit",
        session_key_id,
        lit_ciphertext.as_bytes(),
        1,
        lit_data_hash.as_bytes(),
        public_key,
        serde_json::json!({
            "lit_encrypted": true,
            "client_provided": true,
            "session_key_id": session_key_id,
            "access_conditions": evm_conditions,
            "purpose": "autonomous_signing"
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
