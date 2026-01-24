use axum::{
    extract::{State, Extension},
    http::{StatusCode, HeaderMap},
    Json,
};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    transaction::Transaction,
    message::Message,
};
use base64::{Engine as _, engine::general_purpose};
use std::str::FromStr;
use bigdecimal::BigDecimal;
use crate::{
    AppState,
    auth::AuthenticatedPlatform,
    services::session_keys_core::SessionKeyManager,
    services::key_manager::SecureKeyManager,
};

#[derive(Debug, Deserialize)]
pub struct CreateSessionKeyRequest {
    pub user_wallet: String,
    pub agent_id: String,
    pub agent_name: Option<String>, 
    pub limit_usdc: f64,
    #[serde(default = "default_duration_days")]
    pub duration_days: u32,
    pub device_fingerprint: String,
    #[serde(skip_deserializing)]
    pub ip_address: Option<String>,
    #[serde(skip_deserializing)]
    pub user_agent: Option<String>,
}

fn default_duration_days() -> u32 {
    7
}

#[derive(Debug, Serialize)]
pub struct CreateSessionKeyResponse {
    pub session_key_id: String,
    pub user_wallet: String,
    pub agent_id: String,
    pub agent_name: Option<String>,
    pub limit_usdc: f64,
    pub expires_at: String,
    pub requires_approval: bool,
    pub approval_transaction: String,
    pub instructions: SessionKeyInstructions,
    pub cross_app_compatible: bool, 
}

#[derive(Debug, Serialize)]
pub struct SessionKeyInstructions {
    pub step_1: String,
    pub step_2: String,
    pub step_3: String,
    pub wallet_support: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SessionKeyStatusResponse {
    pub session_key_id: String,
    pub is_active: bool,
    pub is_approved: bool,
    pub limit_usdc: f64,
    pub used_amount_usdc: f64,
    pub remaining_usdc: f64,
    pub expires_at: String,
    pub days_until_expiry: i64,
    pub security_status: SecurityStatus,
}

#[derive(Debug, Serialize)]
pub struct SecurityStatus {
    pub device_fingerprint_matched: bool,
    pub recent_security_events: usize,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TopUpSessionKeyRequest {
    #[allow(dead_code)]
    pub user_wallet: String,
    pub amount_usdc: f64,
    #[allow(dead_code)]
    pub device_fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct TopUpSessionKeyResponse {
    pub session_key_id: String,
    pub previous_limit: f64,
    pub new_limit: f64,
    pub added_amount: f64,
    pub top_up_transaction: String,
    pub last_valid_block_height: u64,
    pub instructions: String,
}

pub async fn create_session_key(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    headers: HeaderMap,
    Json(mut request): Json<CreateSessionKeyRequest>,
) -> Result<Json<CreateSessionKeyResponse>, (StatusCode, Json<serde_json::Value>)> {
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .or_else(|| headers.get("x-real-ip").and_then(|h| h.to_str().ok()))
        .unwrap_or("unknown")
        .to_string();
    
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    request.ip_address = Some(ip_address.clone());
    request.user_agent = Some(user_agent.clone());

    if request.agent_id.is_empty() || request.agent_id.len() > 255 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "agent_id is required and must be 1-255 characters",
                "help": "Use a consistent agent_id like 'shopping-assistant-v1' for cross-app compatibility"
            }))
        ));
    }

    if request.limit_usdc <= 0.0 || request.limit_usdc > 10_000.0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "limit_usdc must be between $0.01 and $10,000",
                "help": "For AI agents, we recommend $50-$500 limits"
            }))
        ));
    }

    if request.duration_days == 0 || request.duration_days > 30 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "duration_days must be between 1 and 30 days",
                "help": "For AI agents, we recommend 7-14 days"
            }))
        ));
    }

    let user_pubkey = Pubkey::from_str(&request.user_wallet)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid user_wallet address",
                "provided": request.user_wallet
            }))
        ))?;

    tracing::info!(
        "Creating agent-scoped session key for agent '{}' (user {}, platform {}, limit ${}, duration {}d)",
        request.agent_id, request.user_wallet, platform.platform_id, request.limit_usdc, request.duration_days
    );

    if let Ok(Some(existing_session_key_id)) = crate::services::agent_session_keys::find_existing_agent_session(
        &state.db,
        &request.user_wallet,
        &request.agent_id,
    ).await {
        tracing::info!(
            "Found existing session key {} for agent '{}' - auto-authorizing recipient {}",
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
                   expires_at, agent_id, agent_name
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
        
        let agent_display_name = agent_name_value.clone()
            .unwrap_or_else(|| agent_id_value.clone());

        return Ok(Json(CreateSessionKeyResponse {
            session_key_id: existing_session.id.to_string(),
            user_wallet: existing_session.user_wallet.unwrap_or(request.user_wallet),
            agent_id: agent_id_value,
            agent_name: agent_name_value,
            limit_usdc: limit_value,
            expires_at: existing_session.expires_at.to_rfc3339(),
            requires_approval: false,
            approval_transaction: String::new(),
            cross_app_compatible: true,
            instructions: SessionKeyInstructions {
                step_1: format!(
                    "Session key already exists for {}",
                    agent_display_name
                ),
                step_2: format!(
                    "This app is now authorized to use the existing ${:.2} balance",
                    limit_value
                ),
                step_3: "No additional approval needed - start making payments!".to_string(),
                wallet_support: vec![],
            },
        }));
    }

    let session_keypair = Keypair::new();
    let session_pubkey = session_keypair.pubkey();

    tracing::debug!("Generated session keypair: {}", session_pubkey);

    let key_manager = SecureKeyManager::from_env()
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to initialize key manager",
                "details": e.to_string()
            }))
        ))?;

    let encrypted_key_id = key_manager.store_encrypted_keypair(
        &state,
        &session_keypair,
        "ai_session_key",
        platform.platform_id,
        None,
    )
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "Failed to store session keypair",
            "details": e.to_string()
        }))
    ))?;

    tracing::debug!("Stored encrypted session keypair with ID: {}", encrypted_key_id);

    let expires_at = chrono::Utc::now() + chrono::Duration::days(request.duration_days as i64);

    let session_key_id = Uuid::new_v4();
    let limit_decimal = BigDecimal::from_str(&request.limit_usdc.to_string())
        .unwrap_or_else(|_| BigDecimal::from(0));

    let ip_network = sqlx::types::ipnetwork::IpNetwork::from_str(&ip_address)
        .map_err(|e| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid IP address",
                "details": e.to_string()
            }))
        ))?;

    let session_wallet_pubkey = session_keypair.pubkey().to_string();
    let agent_name = request.agent_name.as_deref();
    
    sqlx::query!(
        r#"
        INSERT INTO session_keys (
            id, platform_id, session_keypair_id, limit_usdc, used_amount_usdc,
            expires_at, is_active, device_fingerprint, ip_address, user_agent,
            created_from_ip, last_security_check_at, created_at, user_wallet, session_wallet_address,
            agent_id, agent_name, created_by_platform_id
        )
        VALUES ($1, $2, $3, $4, 0, $5, TRUE, $6, $7, $8, $9, NOW(), NOW(), $10, $11, $12, $13, $2)
        "#,
        session_key_id,
        platform.platform_id,
        encrypted_key_id,
        limit_decimal,
        expires_at,
        request.device_fingerprint,
        ip_network as sqlx::types::ipnetwork::IpNetwork,
        user_agent,
        ip_network as sqlx::types::ipnetwork::IpNetwork,
        request.user_wallet,
        session_wallet_pubkey,
        request.agent_id,
        agent_name,
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

    tracing::info!("Session key {} created in database", session_key_id);

    let network_config = state.get_network(&platform.mode);
    let rpc_url = network_config.rpc_urls.first()
        .ok_or_else(|| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "No RPC URLs configured"
            }))
        ))?;

    let client = reqwest::Client::new();
    let blockhash_response = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "finalized"}]
        }))
        .send()
        .await
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to get latest blockhash",
                "details": e.to_string()
            }))
        ))?;

    let blockhash_json: serde_json::Value = blockhash_response
        .json()
        .await
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to parse blockhash response",
                "details": e.to_string()
            }))
        ))?;

    let blockhash_str = blockhash_json
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.get("blockhash"))
        .and_then(|b| b.as_str())
        .ok_or_else(|| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Invalid blockhash response format"
            }))
        ))?;

    let recent_blockhash = solana_sdk::hash::Hash::from_str(blockhash_str)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to parse blockhash",
                "details": e.to_string()
            }))
        ))?;

    let memo_text = format!(
        "x0 AI Session Key Authorization: {} - Limit: ${} - Expires: {}",
        session_key_id,
        request.limit_usdc,
        expires_at.format("%Y-%m-%d")
    );

    let memo_instruction = spl_memo::build_memo(memo_text.as_bytes(), &[&user_pubkey]);

    let mode = platform.mode;
    let network = mode.network_name();
    
    let usdc_mint = crate::services::solana::SupportedToken::Usdc
        .get_mint_address(network)
        .ok_or_else(|| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "USDC not supported on this network"
            }))
        ))?;
    
    let usdc_mint_pubkey = Pubkey::from_str(usdc_mint).map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "Invalid USDC mint address",
            "details": e.to_string()
        }))
    ))?;
    
    let token_amount = (request.limit_usdc * 1_000_000.0) as u64;
    
    use spl_associated_token_account::get_associated_token_address;
    let user_ata = get_associated_token_address(&user_pubkey, &usdc_mint_pubkey);
    let session_ata = get_associated_token_address(&session_pubkey, &usdc_mint_pubkey);
    
    tracing::info!(
        "Session key funding: {} USDC ({} tokens) from {} to {}",
        request.limit_usdc, token_amount, user_ata, session_ata
    );
    
    let fee_payer = state.get_fee_payer(&mode);
    
    let create_session_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
        &fee_payer.pubkey(),
        &session_pubkey,
        &usdc_mint_pubkey,
        &spl_token::id(),
    );
    
    use spl_token::instruction as token_instruction;
    let transfer_ix = token_instruction::transfer(
        &spl_token::id(),
        &user_ata,
        &session_ata,
        &user_pubkey,
        &[&user_pubkey],
        token_amount,
    ).map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "Failed to create transfer instruction",
            "details": e.to_string()
        }))
    ))?;

    let message = Message::new(
        &[
            memo_instruction,
            create_session_ata_ix,
            transfer_ix,
        ],
        Some(&fee_payer.pubkey()),
    );

    let mut transaction = Transaction::new_unsigned(message);
    transaction.message.recent_blockhash = recent_blockhash;
    
    transaction.partial_sign(&[fee_payer], recent_blockhash);
    
    tracing::info!(
        "Backend partially signed approval transaction (user signature still required)"
    );

    let serialized_tx = bincode::serialize(&transaction)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to serialize transaction",
                "details": e.to_string()
            }))
        ))?;

    let approval_transaction = general_purpose::STANDARD.encode(&serialized_tx);

    tracing::info!(
        "Created approval transaction for session key {} (user must sign with wallet)",
        session_key_id
    );

    Ok(Json(CreateSessionKeyResponse {
        session_key_id: session_key_id.to_string(),
        user_wallet: request.user_wallet.clone(),
        agent_id: request.agent_id.clone(),
        agent_name: request.agent_name.clone(),
        limit_usdc: request.limit_usdc,
        expires_at: expires_at.to_rfc3339(),
        requires_approval: true,
        approval_transaction,
        cross_app_compatible: true, 
        instructions: SessionKeyInstructions {
            step_1: format!(
                "Sign this transaction with your wallet ({}) to approve {} instant checkout",
                request.user_wallet,
                request.agent_name.as_deref().unwrap_or(&request.agent_id)
            ),
            step_2: format!(
                "After signing, {} can auto-process payments up to ${:.2} across ALL compatible apps",
                request.agent_name.as_deref().unwrap_or("the agent"),
                request.limit_usdc
            ),
            step_3: format!(
                "Valid for {} days - works across multiple apps using the same agent",
                request.duration_days
            ),
            wallet_support: vec![
                "Phantom".to_string(),
                "Solflare".to_string(),
                "Backpack".to_string(),
                "Any Solana wallet".to_string(),
            ],
        },
    }))
}

pub async fn submit_approval_transaction(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let signed_transaction_base64 = request.get("signed_transaction")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "signed_transaction is required"
            }))
        ))?;

    let session_key_id_str = request.get("session_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "session_key_id is required"
            }))
        ))?;

    let _transaction_bytes = base64::engine::general_purpose::STANDARD
        .decode(signed_transaction_base64)
        .map_err(|e| {
            tracing::error!("Failed to decode transaction: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid transaction encoding"
                }))
            )
        })?;

    let mode = platform.mode;
    let network_config = state.get_network(&mode);
    let rpc_url = network_config.primary_rpc_url();

    tracing::info!(
        "Submitting approval transaction for session key {} (network: {}, RPC: {})",
        session_key_id_str,
        mode,
        rpc_url
    );

    let client = reqwest::Client::new();
    let response = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendTransaction",
            "params": [
                signed_transaction_base64,
                {
                    "encoding": "base64",
                    "preflightCommitment": "confirmed",
                    "skipPreflight": false
                }
            ]
        }))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to submit transaction: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to submit transaction"
                }))
            )
        })?;

    let response_json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| {
            tracing::error!("Failed to parse RPC response: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to parse response"
                }))
            )
        })?;

    if let Some(error) = response_json.get("error") {
        tracing::error!("RPC error: {}", error);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Transaction submission failed",
                "details": error
            }))
        ));
    }

    let signature = response_json
        .get("result")
        .and_then(|r| r.as_str())
        .ok_or_else(|| {
            tracing::error!("Invalid RPC response format");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Invalid response format"
                }))
            )
        })?;

    tracing::info!(
        "Approval transaction submitted for session key {}: signature {}",
        session_key_id_str,
        signature
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "signature": signature,
        "message": "Approval transaction submitted successfully. Confirmation may take 30-60 seconds."
    })))
}

pub async fn get_session_key_status(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<SessionKeyStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    let session_key_id_str = request.get("session_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "session_key_id is required"
            }))
        ))?;

    let session_key_id = Uuid::from_str(session_key_id_str)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid session_key_id format"
            }))
        ))?;

    let session = sqlx::query!(
        r#"
        SELECT id, platform_id, limit_usdc, used_amount_usdc, expires_at, is_active,
               device_fingerprint, last_used_at
        FROM session_keys
        WHERE id = $1
        "#,
        session_key_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "Database error",
            "details": e.to_string()
        }))
    ))?
    .ok_or_else(|| (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "Session key not found"
        }))
    ))?;

    if session.platform_id != platform.platform_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Not authorized to view this session key"
            }))
        ));
    }

    let security_events_count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM session_key_security_events
        WHERE session_key_id = $1
          AND created_at > NOW() - INTERVAL '24 hours'
        "#,
        session_key_id
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let limit = session.limit_usdc.to_string().parse::<f64>().unwrap_or(0.0);
    let used = session.used_amount_usdc
        .map(|d| d.to_string().parse::<f64>().unwrap_or(0.0))
        .unwrap_or(0.0);
    let remaining = limit - used;

    let days_until_expiry = (session.expires_at - chrono::Utc::now()).num_days();

    Ok(Json(SessionKeyStatusResponse {
        session_key_id: session_key_id.to_string(),
        is_active: session.is_active.unwrap_or(false),
        is_approved: true,
        limit_usdc: limit,
        used_amount_usdc: used,
        remaining_usdc: remaining,
        expires_at: session.expires_at.to_rfc3339(),
        days_until_expiry,
        security_status: SecurityStatus {
            device_fingerprint_matched: true,
            recent_security_events: security_events_count as usize,
            last_used_at: session.last_used_at.map(|dt| dt.to_rfc3339()),
        },
    }))
}

pub async fn revoke_session_key(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let session_key_id_str = request.get("session_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "session_key_id is required"
            }))
        ))?;

    let session_key_id = Uuid::from_str(session_key_id_str)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid session_key_id format"
            }))
        ))?;

    let session = sqlx::query!(
        "SELECT platform_id FROM session_keys WHERE id = $1",
        session_key_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "Database error",
            "details": e.to_string()
        }))
    ))?
    .ok_or_else(|| (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "Session key not found"
        }))
    ))?;

    if session.platform_id != platform.platform_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                    "error": "Not authorized to revoke this session key"
            }))
        ));
    }

    let refund_signature = SessionKeyManager::revoke_session_key(&state, session_key_id, platform.platform_id)
        .await
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to revoke session key: {}", e)}))
        ))?;

    tracing::info!("Session key {} revoked by platform {}", session_key_id, platform.platform_id);

    let mut response = serde_json::json!({
        "message": "Session key revoked successfully",
        "session_key_id": session_key_id,
        "note": "This session key can no longer authorize payments. Create a new session key if needed."
    });

    if let Some(signature) = refund_signature {
        response["refund"] = serde_json::json!({
            "refunded": true,
            "transaction_signature": signature,
            "message": "Remaining balance has been refunded to your wallet"
        });
    }

    Ok(Json(response))
}

pub async fn list_session_keys(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let session_keys = SessionKeyManager::list_platform_session_keys(
        &state,
        platform.platform_id,
        true,
    )
    .await
    .map_err(|e| (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "error": "Failed to list session keys",
            "details": e.to_string()
        }))
    ))?;

    let stats = SessionKeyManager::get_session_key_stats(&state, platform.platform_id)
        .await
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to get stats",
                "details": e.to_string()
            }))
        ))?;

    Ok(Json(serde_json::json!({
        "session_keys": session_keys,
        "stats": stats,
        "platform_id": platform.platform_id.to_string()
    })))
}

#[derive(Debug, Deserialize)]
pub struct LinkSessionRequest {
    pub session_id: String,
}

pub async fn link_session(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    axum::extract::Path(session_key_id): axum::extract::Path<String>,
    Json(request): Json<LinkSessionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let session_key_uuid = Uuid::parse_str(&session_key_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid session key ID"})),
        )
    })?;

    let session_uuid = Uuid::parse_str(&request.session_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid session ID"})),
        )
    })?;

    let session_key = sqlx::query!(
        r#"SELECT id, user_wallet, is_active FROM session_keys WHERE id = $1 AND platform_id = $2"#,
        session_key_uuid,
        platform.platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error checking session key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Database error"})),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Session key not found"})),
        )
    })?;

    if !session_key.is_active.unwrap_or(false) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Session key is not active"})),
        ));
    }

    let ai_session = sqlx::query!(
        r#"SELECT id, user_wallet, is_active, expires_at FROM ai_agent_sessions WHERE id = $1 AND platform_id = $2"#,
        session_uuid,
        platform.platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error checking AI session: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Database error"})),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "AI session not found"})),
        )
    })?;

    if !ai_session.is_active.unwrap_or(false) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "AI session is not active"})),
        ));
    }

    if let Some(ref sk_wallet) = session_key.user_wallet {
        if sk_wallet != &ai_session.user_wallet {
            tracing::warn!(
                "User wallet mismatch when linking session key {} to session {}: {} vs {}",
                session_key_id, request.session_id, sk_wallet, ai_session.user_wallet
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "User wallet mismatch",
                    "message": "The session key and AI session must belong to the same user wallet"
                })),
            ));
        }
    }

    sqlx::query!(
        "UPDATE session_keys SET linked_session_id = $1 WHERE id = $2",
        session_uuid,
        session_key_uuid
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to link session key to session: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to link session"})),
        )
    })?;

    tracing::info!(
        "Session key {} linked to AI session {} for platform {}",
        session_key_id, request.session_id, platform.platform_id
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "session_key_id": session_key_id,
        "linked_session_id": request.session_id,
        "message": "Session key successfully linked to AI session. Payments will now check both session key balance and session limits."
    })))
}

pub async fn unlink_session(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    axum::extract::Path(session_key_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let session_key_uuid = Uuid::parse_str(&session_key_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid session key ID"})),
        )
    })?;

    let updated = sqlx::query!(
        r#"UPDATE session_keys 
           SET linked_session_id = NULL 
           WHERE id = $1 AND platform_id = $2
           RETURNING id"#,
        session_key_uuid,
        platform.platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error unlinking session: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Database error"})),
        )
    })?;

    if updated.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Session key not found"})),
        ));
    }

    tracing::info!(
        "Session key {} unlinked from AI session for platform {}",
        session_key_id, platform.platform_id
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "session_key_id": session_key_id,
        "message": "Session key unlinked from AI session. Payments will now only check session key balance."
    })))
}

#[derive(Debug, Deserialize)]
pub struct CheckPaymentRequest {
    pub amount: f64,
}

pub async fn check_payment(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    axum::extract::Path(session_key_id): axum::extract::Path<String>,
    Json(request): Json<CheckPaymentRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let session_key_uuid = Uuid::parse_str(&session_key_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid session key ID"})),
        )
    })?;

    if request.amount <= 0.0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Amount must be greater than 0"})),
        ));
    }

    let session_key = sqlx::query!(
        r#"
        SELECT 
            sk.id,
            sk.limit_usdc,
            sk.used_amount_usdc,
            sk.is_active,
            sk.linked_session_id,
            s.max_per_transaction,
            s.max_per_day,
            s.spent_today,
            s.is_active as session_active
        FROM session_keys sk
        LEFT JOIN ai_agent_sessions s ON sk.linked_session_id = s.id
        WHERE sk.id = $1 AND sk.platform_id = $2
        "#,
        session_key_uuid,
        platform.platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error checking payment: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Database error"})),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Session key not found"})),
        )
    })?;

    if !session_key.is_active.unwrap_or(false) {
        return Ok(Json(serde_json::json!({
            "allowed": false,
            "reason": "Session key is not active",
            "effective_limit": 0,
            "session_key_remaining": 0
        })));
    }

    let limit = session_key.limit_usdc
        .to_string().parse::<f64>().unwrap_or(0.0);
    let used = session_key.used_amount_usdc
        .map(|u| u.to_string().parse::<f64>().unwrap_or(0.0))
        .unwrap_or(0.0);
    let sk_remaining = limit - used;

    if request.amount > sk_remaining {
        return Ok(Json(serde_json::json!({
            "allowed": false,
            "reason": format!("Exceeds session key balance (${:.2} remaining)", sk_remaining),
            "effective_limit": sk_remaining,
            "session_key_remaining": sk_remaining
        })));
    }

    if session_key.linked_session_id.is_none() {
        return Ok(Json(serde_json::json!({
            "allowed": true,
            "effective_limit": sk_remaining,
            "session_key_remaining": sk_remaining
        })));
    }

    if !session_key.session_active.unwrap_or(false) {
        return Ok(Json(serde_json::json!({
            "allowed": true,
            "reason": "Linked session inactive, using session key balance only",
            "effective_limit": sk_remaining,
            "session_key_remaining": sk_remaining
        })));
    }

    if let Some(ref max_per_tx) = session_key.max_per_transaction {
        let max_per_tx_f64 = max_per_tx.to_string().parse::<f64>().unwrap_or(f64::MAX);
        if request.amount > max_per_tx_f64 {
            return Ok(Json(serde_json::json!({
                "allowed": false,
                "reason": format!("Exceeds per-transaction limit (${:.2})", max_per_tx_f64),
                "effective_limit": max_per_tx_f64,
                "session_key_remaining": sk_remaining,
                "session_remaining_today": null
            })));
        }
    }

    let spent_today = session_key.spent_today.as_ref()
        .and_then(|s| s.to_string().parse::<f64>().ok())
        .unwrap_or(0.0);
    let max_per_day = session_key.max_per_day.as_ref()
        .and_then(|m| m.to_string().parse::<f64>().ok())
        .unwrap_or(f64::MAX);
    let session_remaining_today = max_per_day - spent_today;

    if request.amount > session_remaining_today {
        return Ok(Json(serde_json::json!({
            "allowed": false,
            "reason": format!("Exceeds daily limit (${:.2} remaining today)", session_remaining_today),
            "effective_limit": session_remaining_today,
            "session_key_remaining": sk_remaining,
            "session_remaining_today": session_remaining_today
        })));
    }

    let effective_limit = sk_remaining.min(session_remaining_today);
    if let Some(ref max_per_tx) = session_key.max_per_transaction {
        let max_per_tx_f64 = max_per_tx.to_string().parse::<f64>().unwrap_or(f64::MAX);
        let effective_limit = effective_limit.min(max_per_tx_f64);
        return Ok(Json(serde_json::json!({
            "allowed": true,
            "effective_limit": effective_limit,
            "session_key_remaining": sk_remaining,
            "session_remaining_today": session_remaining_today
        })));
    }

    Ok(Json(serde_json::json!({
        "allowed": true,
        "effective_limit": effective_limit,
        "session_key_remaining": sk_remaining,
        "session_remaining_today": session_remaining_today
    })))
}
