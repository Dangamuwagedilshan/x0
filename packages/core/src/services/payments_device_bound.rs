use axum::{
    extract::{State, Path},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_sdk::transaction::Transaction;
use uuid::Uuid;
use base64::Engine;

use crate::{
    auth::AuthenticatedPlatform,
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct SubmitSignedTransactionRequest {
    pub signed_transaction: String,
}

#[derive(Debug, Serialize)]
pub struct SignedTransactionResponse {
    pub payment_id: Uuid,
    pub status: String,
    pub signature: String,
    pub confirmed_in_ms: Option<i64>,
    pub message: String,
}

pub async fn submit_signed_transaction(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Path(payment_id): Path<Uuid>,
    Json(request): Json<SubmitSignedTransactionRequest>,
) -> Result<Json<SignedTransactionResponse>, (StatusCode, Json<serde_json::Value>)> {
    
    let start_time = std::time::Instant::now();
    
    tracing::info!(
        " Receiving signed transaction for payment {} from platform {}",
        payment_id,
        platform.platform_id
    );

    #[derive(Debug)]
    struct PaymentRecord {
        id: Uuid,
        platform_id: Uuid,
        status: String,
        amount_usd: Option<bigdecimal::BigDecimal>,
        metadata: Option<serde_json::Value>,
    }

    let payment = sqlx::query_as!(
        PaymentRecord,
        r#"
        SELECT id, platform_id, status::text as "status!", amount_usd, metadata
        FROM payments
        WHERE id = $1
        "#,
        payment_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error fetching payment: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to fetch payment"})),
        )
    })?
    .ok_or_else(|| {
        tracing::warn!("Payment {} not found", payment_id);
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Payment not found"})),
        )
    })?;

    tracing::info!(
        "Processing signed transaction for payment {}: amount=${:?}, status={}",
        payment.id,
        payment.amount_usd,
        payment.status
    );

    let is_device_bound = payment.metadata
        .as_ref()
        .and_then(|m| m.get("device_bound"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !is_device_bound {
        tracing::warn!(
            "Payment {} is not marked as device-bound in metadata - may be custodial payment",
            payment.id
        );
    }

    if payment.platform_id != platform.platform_id {
        tracing::warn!(
            "Merchant {} attempted to submit signature for payment {} owned by platform {}",
            platform.platform_id,
            payment_id,
            payment.platform_id
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Payment belongs to different platform"})),
        ));
    }

    if payment.status != "awaiting_signature" {
        tracing::warn!(
            "Payment {} has invalid status for signature submission: {}",
            payment_id,
            payment.status
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Invalid payment status",
                "message": format!("Payment status is '{}', expected 'awaiting_signature'", payment.status)
            })),
        ));
    }

    let tx_bytes = base64::engine::general_purpose::STANDARD
        .decode(&request.signed_transaction)
        .map_err(|e| {
            tracing::error!("Failed to decode signed transaction: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid base64 encoding"})),
            )
        })?;

    let transaction: Transaction = bincode::deserialize(&tx_bytes)
        .map_err(|e| {
            tracing::error!("Failed to deserialize transaction: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid transaction format"})),
            )
        })?;

    if transaction.signatures.is_empty() || transaction.signatures[0] == solana_sdk::signature::Signature::default() {
        tracing::error!("Transaction is not signed");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Transaction is not signed"})),
        ));
    }

    tracing::info!(
        "Transaction validation passed for payment {} - submitting to blockchain",
        payment_id
    );

    let mode = platform.mode;

    let network_config = state.get_network(&mode);
    let rpc_url = network_config.rpc_urls.first()
        .ok_or_else(|| {
            tracing::error!("No RPC URLs configured for network mode: {:?}", mode);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "No RPC URLs configured"})),
            )
        })?;

    let client = reqwest::Client::new();
    let response = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendTransaction",
            "params": [
                request.signed_transaction,
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
            tracing::error!("Failed to send transaction to RPC: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to submit transaction to blockchain"})),
            )
        })?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| {
            tracing::error!("Failed to parse RPC response: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to parse blockchain response"})),
            )
        })?;

    if let Some(error) = response.get("error") {
        tracing::error!(
            "Transaction submission failed for payment {}: {}",
            payment_id,
            error
        );
        
        sqlx::query!(
            r#"
            UPDATE payments
            SET status = 'failed',
                metadata = jsonb_set(
                    COALESCE(metadata, '{}'::jsonb),
                    '{rpc_error}',
                    $1::jsonb
                )
            WHERE id = $2
            "#,
            error,
            payment_id
        )
        .execute(&state.db)
        .await
        .ok();

        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Transaction rejected by blockchain",
                "details": error
            })),
        ));
    }

    let signature = response
        .get("result")
        .and_then(|r| r.as_str())
        .ok_or_else(|| {
            tracing::error!("No signature in RPC response: {:?}", response);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "No signature in blockchain response"})),
            )
        })?
        .to_string();

    tracing::info!(
        "Transaction submitted successfully for payment {}: signature={}",
        payment_id,
        signature
    );

    let confirmed_in_ms = start_time.elapsed().as_millis() as i64;
    
    sqlx::query!(
        r#"
        UPDATE payments
        SET status = 'confirmed',
            transaction_signature = $1,
            confirmed_at = NOW(),
            metadata = jsonb_set(
                COALESCE(metadata, '{}'::jsonb),
                '{confirmed_in_ms}',
                $2::text::jsonb
            )
        WHERE id = $3
        "#,
        signature,
        confirmed_in_ms.to_string(),
        payment_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to update payment status: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to update payment status"})),
        )
    })?;

    let webhook_payload = json!({
        "event": "payment_confirmed",
        "payment_id": payment_id,
        "status": "confirmed",
        "signature": signature,
        "amount_usd": payment.amount_usd,
        "confirmed_in_ms": confirmed_in_ms,
        "device_bound": true,
    });

    if let Ok(Some(webhook_url)) = sqlx::query_scalar!(
        "SELECT webhook_url FROM platforms WHERE id = $1",
        platform.platform_id
    )
    .fetch_optional(&state.db)
    .await
    { 
        let _ = sqlx::query!(
            r#"
            INSERT INTO webhook_events (
                id, payment_id, platform_id, event_type, payload, 
                webhook_url, status, attempts, created_at
            ) VALUES (
                gen_random_uuid(), $1, $2, 'payment_confirmed', $3, $4, 'pending', 0, NOW()
            )
            "#,
            payment_id,
            platform.platform_id,
            webhook_payload,
            webhook_url
        )
        .execute(&state.db)
        .await;
    }

    Ok(Json(SignedTransactionResponse {
        payment_id,
        status: "confirmed".to_string(),
        signature,
        confirmed_in_ms: Some(confirmed_in_ms),
        message: "Payment confirmed successfully".to_string(),
    }))
}

pub async fn is_device_bound_session_key(
    state: &AppState,
    session_key_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        SELECT ek.encryption_mode
        FROM session_keys sk
        JOIN encrypted_keys ek ON sk.session_keypair_id = ek.id
        WHERE sk.id = $1
        "#,
        session_key_id
    )
    .fetch_optional(&state.db)
    .await?;

    Ok(result
        .and_then(|r| r.encryption_mode)
        .map(|mode| mode == "device_bound")
        .unwrap_or(false))
}
