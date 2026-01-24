use axum::{
    extract::State,
    http::StatusCode,
    Extension, Json,
};
use base64::{engine::general_purpose, Engine};
use bigdecimal::BigDecimal;
use solana_sdk::{
    message::Message,
    pubkey::Pubkey,
    signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;
use uuid::Uuid;

use crate::{
    auth::AuthenticatedPlatform,
    services::session_keys::{TopUpSessionKeyRequest, TopUpSessionKeyResponse},
    AppState,
};

pub async fn top_up_session_key(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    axum::extract::Path(session_key_id): axum::extract::Path<String>,
    Json(request): Json<TopUpSessionKeyRequest>,
) -> Result<Json<TopUpSessionKeyResponse>, (StatusCode, Json<serde_json::Value>)> {
    tracing::info!(
        "Top-up request for session key {} - amount: ${} (platform {})",
        session_key_id,
        request.amount_usdc,
        platform.platform_id
    );

    if request.amount_usdc <= 0.0 || request.amount_usdc > 100.0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid top-up amount",
                "message": "Amount must be between $0.01 and $100"
            }))
        ));
    }

    let session_key_uuid = Uuid::parse_str(&session_key_id)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid session key ID"}))
        ))?;

    let session = sqlx::query!(
        r#"
        SELECT s.id, s.platform_id, s.limit_usdc, s.is_active, s.expires_at,
               k.public_key as session_wallet_pubkey
        FROM session_keys s
        JOIN session_keypairs k ON s.session_keypair_id = k.id
        WHERE s.id = $1 AND s.platform_id = $2
        "#,
        session_key_uuid,
        platform.platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch session key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to fetch session key"}))
        )
    })?
    .ok_or_else(|| (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": "Session key not found",
            "message": "Session key not found or does not belong to this platform"
        }))
    ))?;

    if !session.is_active.unwrap_or(false) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Session key inactive",
                "message": "Cannot top up an inactive session key"
            }))
        ));
    }

    if session.expires_at < chrono::Utc::now() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Session key expired",
                "message": "Cannot top up an expired session key"
            }))
        ));
    }

    let mode = platform.mode;
    let network_config = state.get_network(&mode);
    let usdc_mint_pubkey = network_config.usdc_mint;

    let session_wallet_pubkey = Pubkey::from_str(&session.session_wallet_pubkey)
        .map_err(|_| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Invalid session wallet address"}))
        ))?;

    let user_wallet = sqlx::query_scalar!(
        "SELECT DISTINCT user_wallet FROM session_keys WHERE session_keypair_id = (SELECT session_keypair_id FROM session_keys WHERE id = $1) LIMIT 1",
        session_key_uuid
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch user wallet: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to fetch user wallet"}))
        )
    })?;

    let user_wallet_str = user_wallet.ok_or_else(|| (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "User wallet not found"}))
    ))?;
    
    let user_pubkey = Pubkey::from_str(&user_wallet_str)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid user wallet address"}))
        ))?;

    let amount_lamports = (request.amount_usdc * 1_000_000.0) as u64;

    let user_ata = spl_associated_token_account::get_associated_token_address(&user_pubkey, &usdc_mint_pubkey);
    let session_ata = spl_associated_token_account::get_associated_token_address(&session_wallet_pubkey, &usdc_mint_pubkey);

    let rpc_url = network_config.rpc_urls.first()
        .ok_or_else(|| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "No RPC URLs configured"}))
        ))?;

    let client = reqwest::Client::new();
    let blockhash_response = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "confirmed"}]
        }))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch blockhash: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to fetch blockhash"}))
            )
        })?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| {
            tracing::error!("Failed to parse blockhash response: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to parse blockhash response"}))
            )
        })?;

    let blockhash_str = blockhash_response["result"]["value"]["blockhash"]
        .as_str()
        .ok_or_else(|| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to extract blockhash"}))
        ))?;
    
    let last_valid_block_height = blockhash_response["result"]["value"]["lastValidBlockHeight"]
        .as_u64()
        .ok_or_else(|| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to extract lastValidBlockHeight"}))
        ))?;

    let blockhash = solana_sdk::hash::Hash::from_str(blockhash_str)
        .map_err(|_| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Invalid blockhash"}))
        ))?;

    let mut instructions = vec![];
    
    let fee_payer = state.get_fee_payer(&mode);
    
    let create_user_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
        &fee_payer.pubkey(),
        &user_pubkey,
        &usdc_mint_pubkey,
        &spl_token::id(),
    );
    instructions.push(create_user_ata_ix);
    
    tracing::debug!(
        "Added create ATA instruction for user wallet {} (platform pays, idempotent if exists)",
        user_pubkey
    );
    
    let create_session_ata_ix = spl_associated_token_account::instruction::create_associated_token_account(
        &fee_payer.pubkey(),
        &session_wallet_pubkey,
        &usdc_mint_pubkey,
        &spl_token::id(),
    );
    instructions.push(create_session_ata_ix);
    
    tracing::debug!(
        "Added create ATA instruction for session wallet {} (platform pays, idempotent if exists)",
        session_wallet_pubkey
    );

    let transfer_ix = spl_token::instruction::transfer(
        &spl_token::id(),
        &user_ata,
        &session_ata,
        &user_pubkey,
        &[],
        amount_lamports,
    )
    .map_err(|e| {
        tracing::error!("Failed to create transfer instruction: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to create transfer instruction"}))
        )
    })?;
    
    instructions.push(transfer_ix);

    let message = Message::new(&instructions, Some(&fee_payer.pubkey()));
    let mut transaction = Transaction::new_unsigned(message);
    transaction.message.recent_blockhash = blockhash;
    
    transaction.partial_sign(&[&fee_payer], blockhash);
    
    tracing::info!(
        "Platform partially signed top-up transaction with {} instructions",
        instructions.len()
    );
    tracing::info!(
        "Transaction details: fee_payer={}, user={}, session_wallet={}, amount=${}, blockhash={}",
        fee_payer.pubkey(),
        user_pubkey,
        session_wallet_pubkey,
        request.amount_usdc,
        blockhash
    );
    tracing::warn!(
        "Blockhash validity: ~60-90 seconds from NOW. User must sign within this window!"
    );

    let serialized_tx = bincode::serialize(&transaction)
        .map_err(|e| {
            tracing::error!("Failed to serialize transaction: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to serialize transaction"}))
            )
        })?;

    let top_up_transaction_b64 = general_purpose::STANDARD.encode(&serialized_tx);

    let previous_limit = session.limit_usdc.to_string().parse::<f64>().unwrap_or(0.0);
    let new_limit = previous_limit + request.amount_usdc;

    tracing::info!(
        "Created top-up transaction for session {} - previous: ${}, new: ${} (includes create ATA + transfer instructions)",
        session_key_id,
        previous_limit,
        new_limit
    );

    Ok(Json(TopUpSessionKeyResponse {
        session_key_id: session_key_id.clone(),
        previous_limit,
        new_limit,
        added_amount: request.amount_usdc,
        top_up_transaction: top_up_transaction_b64,
        last_valid_block_height,
        instructions: "Sign this transaction in your wallet to add funds to your session key.".to_string(),
    }))
}

pub async fn submit_top_up_transaction(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    axum::extract::Path(session_key_id): axum::extract::Path<String>,
    Json(request): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    tracing::info!("Submitting top-up transaction for session {}", session_key_id);

    let session_key_uuid = Uuid::parse_str(&session_key_id)
        .map_err(|_| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid session key ID"}))
        ))?;

    let signed_tx_b64 = request["signed_transaction"]
        .as_str()
        .ok_or_else(|| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Missing signed_transaction field"}))
        ))?;

    let top_up_amount = request["amount_usdc"]
        .as_f64()
        .ok_or_else(|| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Missing amount_usdc field"}))
        ))?;

    let tx_bytes = general_purpose::STANDARD.decode(signed_tx_b64)
        .map_err(|e| {
            tracing::error!("Failed to decode transaction: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid transaction encoding"}))
            )
        })?;

    let transaction: Transaction = bincode::deserialize(&tx_bytes)
        .map_err(|e| {
            tracing::error!("Failed to deserialize transaction: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid transaction format"}))
            )
        })?;

    let mode = platform.mode;
    let network_config = state.get_network(&mode);
    let rpc_url = network_config.rpc_urls.first()
        .ok_or_else(|| (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "No RPC URLs configured"}))
        ))?;

    let client = reqwest::Client::new();
    let tx_b64 = general_purpose::STANDARD.encode(
        bincode::serialize(&transaction)
            .map_err(|e| {
                tracing::error!("Failed to serialize transaction: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                    "error": "Failed to prepare transaction"
                })))
            })?
    );
    
    let send_response = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendTransaction",
            "params": [
                tx_b64,
                {"encoding": "base64", "skipPreflight": false, "preflightCommitment": "confirmed"}
            ]
        }))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to send transaction: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to send transaction"}))
            )
        })?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| {
            tracing::error!("Failed to parse send response: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to parse send response"}))
            )
        })?;

    let signature = send_response["result"]
        .as_str()
        .ok_or_else(|| {
            let error_msg = send_response["error"]["message"].as_str().unwrap_or("Unknown error");
            tracing::error!("Transaction failed: {}", error_msg);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Transaction failed",
                    "details": error_msg
                }))
            )
        })?;

    tracing::info!("Top-up transaction submitted: {}", signature);

    let previous_limit_f64 = sqlx::query_scalar!(
        "SELECT limit_usdc FROM session_keys WHERE id = $1 AND platform_id = $2",
        session_key_uuid,
        platform.platform_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch current limit: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to fetch current limit"}))
        )
    })?
    .to_string()
    .parse::<f64>()
    .unwrap_or(0.0);

    let new_limit = previous_limit_f64 + top_up_amount;
    let new_limit_bd = BigDecimal::from_str(&new_limit.to_string())
        .map_err(|e| {
            tracing::error!("Failed to convert new limit to BigDecimal: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": "Failed to update spending limit"
            })))
        })?;

    sqlx::query!(
        "UPDATE session_keys SET limit_usdc = $1 WHERE id = $2 AND platform_id = $3",
        new_limit_bd,
        session_key_uuid,
        platform.platform_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to update session limit: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to update limit"}))
        )
    })?;

    tracing::info!(
        "Session {} limit updated: ${} → ${} (added ${})",
        session_key_id,
        previous_limit_f64,
        new_limit,
        top_up_amount
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "signature": signature,
        "session_key_id": session_key_id,
        "previous_limit": previous_limit_f64,
        "new_limit": new_limit,
        "added_amount": top_up_amount,
        "message": format!("Successfully topped up session key with ${:.2}. New limit: ${:.2}", top_up_amount, new_limit)
    })))
}
