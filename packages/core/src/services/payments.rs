use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Extension, Json,
};
use base64::Engine;
use bigdecimal::BigDecimal;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signer::Signer,
    transaction::Transaction,
};
use spl_associated_token_account::get_associated_token_address;
use std::str::FromStr;
use uuid::Uuid;

use crate::{
    auth::AuthenticatedPlatform,
    network_config::ApiKeyMode,
    services::{
        agent_session_keys,
        session_keys_core::{SessionKeyManager, SessionKeyRequestContext},
        solana::SupportedToken,
        webhooks::{create_webhook_event, WebhookEventType},
    },
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct SmartPaymentRequest {
    pub agent_id: String,
    pub user_wallet: String,
    pub amount_usd: f64,
    pub token: Option<String>,
    pub session_token: Option<String>,
    pub session_key_id: Option<String>,
    #[serde(default)]
    pub auto_detect_gasless: Option<bool>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct SmartPaymentResponse {
    pub payment_id: Uuid,
    pub status: String,
    pub amount_usd: f64,
    pub gasless_used: bool,
    pub unsigned_transaction: Option<String>,
    pub requires_signature: bool,
    pub transaction_signature: Option<String>,
    pub confirmed_in_ms: Option<i64>,
    pub next_steps: String,
    pub submit_url: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
pub struct SessionCheckResult {
    pub allowed: bool,
    pub reason: String,
    pub requires_approval: Option<bool>,
}

pub async fn smart_payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Json(request): Json<SmartPaymentRequest>,
) -> Result<Json<SmartPaymentResponse>, (StatusCode, Json<serde_json::Value>)> {
    let start_time = std::time::Instant::now();

    tracing::info!(
        "Processing smart payment for agent {} amount ${} platform {}",
        request.agent_id,
        request.amount_usd,
        platform.platform_id
    );

    if request.amount_usd <= 0.0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Invalid amount",
                "message": "Amount must be greater than 0"
            })),
        ));
    }

    if let Some(ref token) = request.session_token {
        let session_check =
            validate_session_and_check_limits(&state, token, &platform.platform_id, request.amount_usd)
                .await?;

        if !session_check.allowed {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "Spending limit exceeded",
                    "message": session_check.reason,
                    "requires_approval": session_check.requires_approval.unwrap_or(false)
                })),
            ));
        }
    }

    let amount_bd: BigDecimal = request
        .amount_usd
        .to_string()
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid amount format"}))))?;

    let mode = platform.mode;

    let has_session_key =
        headers.get("x-session-key-id").is_some() || request.session_key_id.is_some();

    let should_use_gasless = if has_session_key {
        tracing::info!("Session key detected - forcing gasless mode");
        true
    } else if request.auto_detect_gasless.unwrap_or(false) {
        check_if_gasless_needed(&state, &request.user_wallet, mode)
            .await
            .unwrap_or(false)
    } else {
        false
    };

    let mut payment_metadata = request.metadata.clone().unwrap_or_else(|| json!({}));
    payment_metadata["agent_id"] = json!(request.agent_id);
    payment_metadata["smart_payment"] = json!(true);
    payment_metadata["auto_gasless"] = json!(should_use_gasless);

    let payment_id = Uuid::new_v4();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);

    sqlx::query!(
        r#"
        INSERT INTO payments (
            id, platform_id, amount_usd, customer_wallet, status,
            payment_type, metadata, created_at, expires_at
        ) VALUES (
            $1, $2, $3, $4, 'pending', 'one_time', $5, NOW(), $6
        )
        "#,
        payment_id,
        platform.platform_id,
        amount_bd,
        request.user_wallet,
        payment_metadata,
        expires_at
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create payment: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create payment"})),
        )
    })?;

    if let Some(ref token) = request.session_token {
        if let Err(e) = record_session_spending(&state, token, request.amount_usd).await {
            tracing::warn!("Spending limit check failed: {}", e);

            if e.to_string().contains("limit") || e.to_string().contains("exceeded") {
                return Err((
                    StatusCode::PAYMENT_REQUIRED,
                    Json(json!({
                        "error": e.to_string(),
                        "code": "SPENDING_LIMIT_EXCEEDED"
                    })),
                ));
            }
        }
    }

    let customer_pubkey = Pubkey::from_str(&request.user_wallet).map_err(|e| {
        tracing::error!("Invalid customer wallet: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid user wallet address"})),
        )
    })?;

    let platform_wallet = sqlx::query_scalar!(
        "SELECT wallet_address FROM platforms WHERE id = $1",
        platform.platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch platform wallet: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to fetch platform wallet"})),
        )
    })?
    .ok_or_else(|| {
        tracing::error!("Platform {} has no wallet configured", platform.platform_id);
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Platform wallet not configured"})),
        )
    })?;

    let recipient_pubkey = Pubkey::from_str(&platform_wallet).map_err(|e| {
        tracing::error!("Invalid platform wallet: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Invalid platform wallet address"})),
        )
    })?;

    let _network_config = state.get_network(&mode);
    let token = request.token.as_deref().unwrap_or("USDC");

    let session_key_id = headers
        .get("x-session-key-id")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| Uuid::from_str(s).ok())
        .or_else(|| {
            request
                .session_key_id
                .as_ref()
                .and_then(|s| Uuid::from_str(s).ok())
        })
        .or_else(|| {
            tracing::debug!(
                "No x-session-key-id header - attempting lookup by agent_id={}",
                request.agent_id
            );
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    agent_session_keys::get_agent_session_key(
                        &state.db,
                        &request.user_wallet,
                        &request.agent_id,
                        platform.platform_id
                    ).await.ok()
                })
            })
        });

    let session_key_details = if let Some(session_key_id_value) = session_key_id {
        match agent_session_keys::get_session_key_for_payment(
            &state.db,
            session_key_id_value,
            platform.platform_id,
        )
        .await
        {
            Ok(details) => {
                tracing::info!(
                    "Session key {} validated for platform {}",
                    details.id,
                    platform.platform_id
                );
                Some(details)
            }
            Err(e) => {
                tracing::error!("Session key validation failed: {}", e);
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "Session key not authorized for this platform",
                        "code": "SESSION_KEY_UNAUTHORIZED"
                    })),
                ));
            }
        }
    } else {
        None
    };

    let session_wallet_pubkey = session_key_details
        .as_ref()
        .and_then(|d| d.session_wallet_address.as_ref())
        .and_then(|addr| Pubkey::from_str(addr).ok());

    tracing::info!(
        "Building {} transaction for payment {}: {} {} (mode: {})",
        if should_use_gasless { "GASLESS" } else { "STANDARD" },
        payment_id,
        request.amount_usd,
        token,
        mode
    );

    let transaction = build_payment_transaction(
        &state,
        &customer_pubkey,
        &recipient_pubkey,
        request.amount_usd,
        token,
        &payment_id,
        mode,
        should_use_gasless,
        session_wallet_pubkey.as_ref(),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to build transaction: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to build transaction", "details": e.to_string()})),
        )
    })?;

    let serialized = bincode::serialize(&transaction).map_err(|e| {
        tracing::error!("Failed to serialize transaction: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to serialize transaction"})),
        )
    })?;

    let unsigned_transaction = base64::engine::general_purpose::STANDARD.encode(&serialized);

    let (auto_signed, transaction_signature) = if let Some(session_key_id_value) = session_key_id {
        try_auto_sign_with_session_key(
            &state,
            &headers,
            session_key_id_value,
            &platform,
            &request,
            &payment_id,
            &transaction,
            mode,
            should_use_gasless,
            &customer_pubkey,
            &recipient_pubkey,
            token,
            &session_key_details,
        )
        .await
    } else {
        (false, None)
    };

    let _ = create_webhook_event(
        &state,
        platform.platform_id,
        if auto_signed {
            WebhookEventType::PaymentConfirmed
        } else {
            WebhookEventType::PaymentCreated
        },
        json!({
            "payment_id": payment_id,
            "amount_usd": request.amount_usd,
            "agent_id": request.agent_id,
            "user_wallet": request.user_wallet,
        }),
        Some(payment_id),
    )
    .await;

    let confirmed_in_ms = start_time.elapsed().as_millis() as i64;

    let next_steps = if auto_signed {
        "Payment auto-signed and confirmed instantly!"
    } else if should_use_gasless {
        "Transaction ready (gasless). User must sign, backend will submit."
    } else {
        "Transaction ready. User must sign and submit to Solana."
    };

    let response = SmartPaymentResponse {
        payment_id,
        status: if auto_signed {
            "confirmed".to_string()
        } else {
            "pending".to_string()
        },
        amount_usd: request.amount_usd,
        gasless_used: should_use_gasless,
        unsigned_transaction: if auto_signed {
            None
        } else {
            Some(unsigned_transaction)
        },
        requires_signature: !auto_signed,
        transaction_signature,
        confirmed_in_ms: Some(confirmed_in_ms),
        next_steps: next_steps.to_string(),
        submit_url: if auto_signed {
            None
        } else {
            Some(format!("/api/v1/payments/{}/submit", payment_id))
        },
        created_at: Utc::now(),
    };

    Ok(Json(response))
}

async fn build_payment_transaction(
    state: &AppState,
    customer: &Pubkey,
    recipient: &Pubkey,
    amount: f64,
    token: &str,
    payment_id: &Uuid,
    mode: ApiKeyMode,
    gasless: bool,
    session_key_pubkey: Option<&Pubkey>,
) -> Result<Transaction, Box<dyn std::error::Error + Send + Sync>> {
    let payer = if gasless {
        session_key_pubkey.unwrap_or(customer)
    } else {
        customer
    };

    let mut instructions: Vec<Instruction> = Vec::new();
    let network = mode.network_name();
    let network_config = state.get_network(&mode);
    let rpc_url = network_config.primary_rpc_url();

    tracing::info!(
        "Building {} transaction for payment {} (network: {})",
        if gasless { "gasless" } else { "standard" },
        payment_id,
        network
    );

    match token.to_uppercase().as_str() {
        "SOL" => {
            let sol_price = crate::services::solana::fetch_sol_price()
                .await
                .unwrap_or(100.0);
            let sol_amount = amount / sol_price;
            let lamports = (sol_amount * 1_000_000_000.0) as u64;

            tracing::info!(
                "SOL transfer: ${} @ ${}/SOL = {} lamports",
                amount,
                sol_price,
                lamports
            );

            instructions.push(solana_sdk::system_instruction::transfer(
                payer, recipient, lamports,
            ));
        }
        "USDC" | "USDT" => {
            let token_enum = if token == "USDC" {
                SupportedToken::Usdc
            } else {
                SupportedToken::Usdt
            };

            let mint_address = token_enum
                .get_mint_address(network)
                .ok_or("Token not supported on this network")?;
            let mint_pubkey = Pubkey::from_str(mint_address)?;

            let token_owner = session_key_pubkey.unwrap_or(customer);
            let owner_ata = get_associated_token_address(token_owner, &mint_pubkey);
            let recipient_ata = get_associated_token_address(recipient, &mint_pubkey);

            let decimals = token_enum.decimals();
            let token_amount = (amount * 10f64.powi(decimals as i32)) as u64;

            tracing::info!(
                "{} transfer: ${} = {} atomic units",
                token,
                amount,
                token_amount
            );

            instructions.push(
                spl_token::instruction::transfer_checked(
                    &spl_token::id(),
                    &owner_ata,
                    &mint_pubkey,
                    &recipient_ata,
                    token_owner,
                    &[],
                    token_amount,
                    decimals,
                )?,
            );
        }
        _ => {
            return Err(format!("Unsupported token: {}", token).into());
        }
    }

    let client = reqwest::Client::new();
    let blockhash_response: serde_json::Value = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "confirmed"}]
        }))
        .send()
        .await?
        .json()
        .await?;

    let blockhash_str = blockhash_response["result"]["value"]["blockhash"]
        .as_str()
        .ok_or("Failed to get blockhash")?;

    let blockhash = solana_sdk::hash::Hash::from_str(blockhash_str)?;

    let message = solana_sdk::message::Message::new_with_blockhash(&instructions, Some(payer), &blockhash);

    Ok(Transaction::new_unsigned(message))
}

#[allow(clippy::too_many_arguments)]
async fn try_autonomous_delegate_signing(
    state: &AppState,
    session_key_id: Uuid,
    platform: &AuthenticatedPlatform,
    request: &SmartPaymentRequest,
    payment_id: &Uuid,
    transaction: &Transaction,
    mode: ApiKeyMode,
    _should_use_gasless: bool,
    session_key_details: &Option<agent_session_keys::SessionKeyDetails>,
) -> Option<(bool, Option<String>)> {
    use crate::services::session_keys_autonomous::{
        get_active_delegate, sign_with_attestation, record_delegate_usage,
        AttestationSigningParams,
    };

    let delegate = match get_active_delegate(state, session_key_id).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            tracing::info!("No active autonomous delegate for session key {}", session_key_id);
            return None;
        }
        Err(e) => {
            tracing::error!("Failed to check autonomous delegate: {}", e);
            return None;
        }
    };

    if !delegate.can_spend(request.amount_usd) {
        tracing::info!(
            "Autonomous delegate {} cannot spend ${} (remaining: ${})",
            delegate.id,
            request.amount_usd,
            delegate.remaining_usd()
        );
        return None;
    }

    let signing_keypair_id = match delegate.signing_keypair_id() {
        Some(id) => id,
        None => {
            tracing::warn!(
                "Autonomous delegate {} has no signing keypair - requires client signature",
                delegate.id
            );
            return None;
        }
    };

    tracing::info!(
        "Autonomous delegate {} active - signing payment {} (${} remaining, keypair: {})",
        delegate.id,
        payment_id,
        delegate.remaining_usd(),
        signing_keypair_id
    );

    let attestation_params = AttestationSigningParams {
        delegate: delegate.clone(),
        session_keypair_id: signing_keypair_id,
        platform_id: platform.platform_id,
        payment_id: *payment_id,
        amount_usd: request.amount_usd,
    };

    let result = match sign_with_attestation(state, attestation_params, transaction).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Autonomous delegate signing failed: {}", e);
            return None;
        }
    };

    let signed_tx = result.signed_transaction;

    if let Some(ref attestation) = result.attestation {
        tracing::info!(
            "Payment {} signed with cryptographic attestation (remaining: ${})",
            payment_id,
            attestation.attestation.remaining_after_usd
        );
    } else {
        tracing::info!("Transaction signed with autonomous delegate (programmatic enforcement only)");
    }

    let serialized = match bincode::serialize(&signed_tx) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to serialize signed transaction: {}", e);
            return Some((false, None));
        }
    };

    let network_config = state.get_network(&mode);
    let rpc_url = match network_config.rpc_urls.first() {
        Some(url) => url,
        None => {
            tracing::error!("No RPC URLs configured");
            return Some((false, None));
        }
    };

    let client = reqwest::Client::new();
    let response = match client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendTransaction",
            "params": [
                base64::engine::general_purpose::STANDARD.encode(&serialized),
                {
                    "encoding": "base64",
                    "preflightCommitment": "confirmed",
                    "skipPreflight": false
                }
            ]
        }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to send autonomous transaction: {}", e);
            return Some((false, None));
        }
    };

    let response_json: serde_json::Value = match response.json().await {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("Failed to parse RPC response: {}", e);
            return Some((false, None));
        }
    };

    if let Some(error) = response_json.get("error") {
        tracing::error!("RPC error submitting autonomous transaction: {}", error);
        let _ = sqlx::query!(
            "UPDATE payments SET status = 'failed' WHERE id = $1",
            payment_id
        )
        .execute(&state.db)
        .await;
        return Some((false, None));
    }

    let sig_str = match response_json.get("result").and_then(|r| r.as_str()) {
        Some(s) => s.to_string(),
        None => {
            tracing::error!("Invalid RPC response format");
            return Some((false, None));
        }
    };

    tracing::info!(
        "AUTONOMOUS PAYMENT CONFIRMED! Payment {} - Signature: {}",
        payment_id,
        sig_str
    );

    let _ = sqlx::query!(
        r#"
        UPDATE payments
        SET status = 'confirmed',
            transaction_signature = $1,
            metadata = jsonb_set(
                COALESCE(metadata, '{}'::jsonb),
                '{autonomous_signed}',
                'true'::jsonb
            )
        WHERE id = $2
        "#,
        sig_str,
        payment_id
    )
    .execute(&state.db)
    .await;

    let _ = record_delegate_usage(
        state,
        delegate.id,
        request.amount_usd,
        Some(*payment_id),
        Some(sig_str.clone()),
    ).await;

    if let Some(ref details) = session_key_details {
        if let Some(ref agent_id) = details.agent_id {
            let _ = agent_session_keys::log_agent_session_usage(
                &state.db,
                details.id,
                platform.platform_id,
                agent_id,
                request.amount_usd,
                Some(*payment_id),
                Some(sig_str.clone()),
            ).await;
        }
    }

    let _ = crate::services::webhooks::create_webhook_event(
        state,
        platform.platform_id,
        crate::services::webhooks::WebhookEventType::PaymentConfirmed,
        json!({
            "payment_id": payment_id,
            "amount_usd": request.amount_usd,
            "transaction_signature": sig_str,
            "autonomous_signed": true,
            "delegate_id": delegate.id,
        }),
        Some(*payment_id),
    ).await;

    Some((true, Some(sig_str)))
}

#[allow(clippy::too_many_arguments)]
async fn try_auto_sign_with_session_key(
    state: &AppState,
    headers: &HeaderMap,
    session_key_id: Uuid,
    platform: &AuthenticatedPlatform,
    request: &SmartPaymentRequest,
    payment_id: &Uuid,
    transaction: &Transaction,
    mode: ApiKeyMode,
    should_use_gasless: bool,
    customer_pubkey: &Pubkey,
    recipient_pubkey: &Pubkey,
    token: &str,
    session_key_details: &Option<agent_session_keys::SessionKeyDetails>,
) -> (bool, Option<String>) {
    tracing::info!(
        "Attempting auto-sign with session key {} for payment {}",
        session_key_id,
        payment_id
    );

    let is_device_bound = crate::services::payments_device_bound::is_device_bound_session_key(
        state,
        session_key_id,
    ).await.unwrap_or(false);

    if is_device_bound {
        tracing::info!(
            "Device-bound session key {} - checking for autonomous delegate",
            session_key_id
        );

        if let Some((signed, sig)) = try_autonomous_delegate_signing(
            state,
            session_key_id,
            platform,
            request,
            payment_id,
            transaction,
            mode,
            should_use_gasless,
            session_key_details,
        ).await {
            return (signed, sig);
        }
        
        tracing::info!(
            "No active autonomous delegate for device-bound session key {} - requires client signature",
            session_key_id
        );
        return (false, None);
    }

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

    let device_fingerprint = headers
        .get("x-device-fingerprint")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let request_context = SessionKeyRequestContext {
        device_fingerprint,
        ip_address,
        user_agent,
    };

    match SessionKeyManager::get_active_session_key(state, platform.platform_id, request.amount_usd, request_context)
        .await
    {
        Ok(session_keypair) => {
            tracing::info!("Session key validated - auto-signing payment {}", payment_id);

            let session_pubkey = session_keypair.pubkey();

            let rebuilt_transaction = match build_payment_transaction(
                state,
                customer_pubkey,
                recipient_pubkey,
                request.amount_usd,
                token,
                payment_id,
                mode,
                should_use_gasless,
                Some(&session_pubkey),
            )
            .await
            {
                Ok(tx) => tx,
                Err(e) => {
                    tracing::error!("Failed to rebuild transaction: {}", e);
                    return (false, None);
                }
            };

            let mut tx = rebuilt_transaction;
            tx.sign(&[&session_keypair], tx.message.recent_blockhash);

            let serialized = match bincode::serialize(&tx) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to serialize signed transaction: {}", e);
                    return (false, None);
                }
            };

            let network_config = state.get_network(&mode);
            let rpc_url = match network_config.rpc_urls.first() {
                Some(url) => url,
                None => {
                    tracing::error!("No RPC URLs configured");
                    return (false, None);
                }
            };

            let client = reqwest::Client::new();
            let response = match client
                .post(rpc_url)
                .json(&json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "sendTransaction",
                    "params": [
                        base64::engine::general_purpose::STANDARD.encode(&serialized),
                        {
                            "encoding": "base64",
                            "preflightCommitment": "confirmed",
                            "skipPreflight": false
                        }
                    ]
                }))
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("Failed to send transaction: {}", e);
                    return (false, None);
                }
            };

            let response_json: serde_json::Value = match response.json().await {
                Ok(j) => j,
                Err(e) => {
                    tracing::error!("Failed to parse RPC response: {}", e);
                    return (false, None);
                }
            };

            if let Some(error) = response_json.get("error") {
                tracing::error!("RPC error: {}", error);
                let _ = sqlx::query!(
                    "UPDATE payments SET status = 'failed' WHERE id = $1",
                    payment_id
                )
                .execute(&state.db)
                .await;
                return (false, None);
            }

            let sig_str = match response_json.get("result").and_then(|r| r.as_str()) {
                Some(s) => s.to_string(),
                None => {
                    tracing::error!("Invalid RPC response format");
                    return (false, None);
                }
            };

            tracing::info!("Payment {} confirmed - Signature: {}", payment_id, sig_str);

            let _ = sqlx::query!(
                r#"
                UPDATE payments
                SET status = 'confirmed', transaction_signature = $1
                WHERE id = $2
                "#,
                sig_str,
                payment_id
            )
            .execute(&state.db)
            .await;

            if let Some(ref details) = session_key_details {
                if let Some(ref agent_id) = details.agent_id {
                    let _ = agent_session_keys::log_agent_session_usage(
                        &state.db,
                        details.id,
                        platform.platform_id,
                        agent_id,
                        request.amount_usd,
                        Some(*payment_id),
                        Some(sig_str.clone()),
                    )
                    .await;
                }
            }

            (true, Some(sig_str))
        }
        Err(e) => {
            tracing::warn!("Session key validation failed: {}", e);
            (false, None)
        }
    }
}

pub async fn validate_session_and_check_limits(
    state: &AppState,
    token: &str,
    platform_id: &Uuid,
    amount: f64,
) -> Result<SessionCheckResult, (StatusCode, Json<serde_json::Value>)> {
    let session = sqlx::query!(
        r#"
        SELECT id, crypto_enforced
        FROM ai_agent_sessions
        WHERE session_token = $1
          AND platform_id = $2
          AND is_active = true
          AND expires_at > NOW()
        "#,
        token,
        platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Session lookup error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Session validation failed"})),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid or expired session",
                "message": "Session token is invalid, expired, or has been revoked"
            })),
        )
    })?;

    let amount_bd: BigDecimal = amount.to_string().parse().map_err(|e| {
        tracing::error!("Failed to parse amount: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Invalid amount"})),
        )
    })?;

    let check_result = sqlx::query_scalar!(
        "SELECT check_ai_session_spending_limit($1, $2)",
        session.id,
        amount_bd
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Limit check error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Limit check failed"})),
        )
    })?
    .unwrap_or_else(|| json!({"allowed": false, "reason": "Unknown error"}));

    let allowed = check_result
        .get("allowed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let reason = check_result
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown reason")
        .to_string();

    let requires_approval = check_result.get("requires_approval").and_then(|v| v.as_bool());

    Ok(SessionCheckResult {
        allowed,
        reason,
        requires_approval,
    })
}

async fn record_session_spending(
    state: &AppState,
    token: &str,
    amount: f64,
) -> Result<(), Box<dyn std::error::Error>> {
    let session = sqlx::query!(
        "SELECT id, crypto_enforced FROM ai_agent_sessions WHERE session_token = $1",
        token
    )
    .fetch_optional(&state.db)
    .await?;

    if let Some(session_record) = session {
        let use_atomic = session_record.crypto_enforced.unwrap_or(false);
        
        if use_atomic {
            super::spending_limits_atomic::check_and_record_spend_atomic(
                state,
                session_record.id,
                amount,
            ).await.map_err(|e| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string()
                )) as Box<dyn std::error::Error>
            })?;
        } else {
            let amount_bd: BigDecimal = amount.to_string().parse()?;
            sqlx::query_scalar!(
                "SELECT record_ai_session_spending($1, $2)",
                session_record.id,
                amount_bd
            )
            .fetch_one(&state.db)
            .await?;
        }
    }

    Ok(())
}

async fn check_if_gasless_needed(
    state: &AppState,
    wallet: &str,
    mode: ApiKeyMode,
) -> Result<bool, Box<dyn std::error::Error>> {
    let pubkey = Pubkey::from_str(wallet).map_err(|e| format!("Invalid wallet address: {}", e))?;

    let network_config = state.get_network(&mode);
    let rpc_url = network_config.primary_rpc_url();

    let client = reqwest::Client::new();
    let response: serde_json::Value = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [pubkey.to_string()]
        }))
        .send()
        .await?
        .json()
        .await?;

    let balance = response["result"]["value"].as_u64().unwrap_or(0);
    let min_balance_lamports = 10_000_000;
    let needs_gasless = balance < min_balance_lamports;

    tracing::info!(
        "Wallet {} balance: {} lamports - needs_gasless: {}",
        wallet,
        balance,
        needs_gasless
    );

    Ok(needs_gasless)
}
