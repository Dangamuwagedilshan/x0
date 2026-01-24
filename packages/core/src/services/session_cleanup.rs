use crate::AppState;
use crate::network_config::ApiKeyMode;
use solana_sdk::{
    pubkey::Pubkey,
    transaction::Transaction,
    message::Message,
    hash::Hash,
};
use spl_token::instruction::transfer;
use std::str::FromStr;
use tokio::time::{interval, Duration};
use base64::{Engine as _, engine::general_purpose};

pub async fn expired_session_cleanup_worker(state: AppState) {
    tracing::info!("Starting expired session cleanup worker (runs hourly)");
    let mut interval_timer = interval(Duration::from_secs(3600));
    
    loop {
        interval_timer.tick().await;
        
        match cleanup_expired_sessions(&state).await {
            Ok(cleaned) => {
                if cleaned > 0 {
                    tracing::info!("Cleaned up {} expired sessions", cleaned);
                }
            }
            Err(e) => {
                tracing::error!("❌ Expired session cleanup failed: {}", e);
            }
        }
    }
}

async fn cleanup_expired_sessions(state: &AppState) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let expired_sessions = sqlx::query!(
        r#"
        SELECT 
            id, 
            platform_id, 
            session_keypair_id, 
            session_wallet_address,
            user_wallet,
            limit_usdc, 
            used_amount_usdc,
            (limit_usdc - used_amount_usdc) as "remaining_usdc!"
        FROM session_keys
        WHERE expires_at < NOW()
          AND is_active = TRUE
          AND (limit_usdc - used_amount_usdc) > 0.01
          AND user_wallet IS NOT NULL
          AND session_wallet_address IS NOT NULL
        ORDER BY expires_at ASC
        LIMIT 100
        "#
    )
    .fetch_all(&state.db)
    .await?;
    
    let count = expired_sessions.len();
    
    if count == 0 {
        return Ok(0);
    }
    
    tracing::info!(
        "🧹 Found {} expired sessions with remaining balance to cleanup",
        count
    );
    
    for session in expired_sessions {
    let remaining_usdc_clone = session.remaining_usdc.clone();
    let user_wallet_clone = session.user_wallet.clone();
    let session_id = session.id;
    
    let session_record = SessionRecord {
        id: session.id,
        platform_id: session.platform_id,
        session_keypair_id: session.session_keypair_id,
        session_wallet_address: session.session_wallet_address,
        user_wallet: session.user_wallet,
    };
    
    match refund_session_key(state, &session_record).await {
        Ok(signature) => {
            tracing::info!(
                "Refunded ${:.2} from session {} to user {} (tx: {})",
                remaining_usdc_clone.to_string().parse::<f64>().unwrap_or(0.0),
                session_id,
                match user_wallet_clone.as_ref() {
                    Some(wallet) => wallet,
                    None => {
                        tracing::error!("Missing user wallet for session {}", session_id);
                        continue;
                    }
                },
                signature
            );
                sqlx::query!(
                    "UPDATE session_keys SET is_active = FALSE WHERE id = $1",
                    session.id
                )
                .execute(&state.db)
                .await?;
                
                sqlx::query!(
                    r#"
                    INSERT INTO session_key_security_events 
                    (session_key_id, platform_id, event_type, severity, description, action_taken)
                    VALUES ($1, $2, 'auto_cleanup', 'low', $3, 'refunded_and_deactivated')
                    "#,
                    session_id,
                    session_record.platform_id,
                    format!(
                        "Expired session auto-cleaned: refunded ${:.2} to user",
                        remaining_usdc_clone.to_string().parse::<f64>().unwrap_or(0.0)
                    )
                )
                .execute(&state.db)
                .await?;
            }
            Err(e) => {
                tracing::error!(
                    "❌ Failed to refund session {}: {} - marking as inactive anyway",
                    session_id,
                    e
                );
                
                sqlx::query!(
                    "UPDATE session_keys SET is_active = FALSE WHERE id = $1",
                    session_id
                )
                .execute(&state.db)
                .await?;
                
                sqlx::query!(
                    r#"
                    INSERT INTO session_key_security_events 
                    (session_key_id, platform_id, event_type, severity, description, action_taken)
                    VALUES ($1, $2, 'cleanup_failed', 'medium', $3, 'deactivated')
                    "#,
                    session.id,
                    session.platform_id,
                    format!("Failed to refund expired session: {}", e)
                )
                .execute(&state.db)
                .await?;
            }
        }
    }
    
    Ok(count)
}

pub async fn refund_session_key(
    state: &AppState,
    session: &SessionRecord,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let user_wallet = session.user_wallet.as_ref()
        .ok_or("Missing user_wallet")?;
    let session_wallet_address = session.session_wallet_address.as_ref()
        .ok_or("Missing session_wallet_address")?;
    
    sqlx::query!(
        "UPDATE session_keys SET refund_status = 'processing', refund_attempted_at = NOW() WHERE id = $1",
        session.id
    )
    .execute(&state.db)
    .await?;
    
    let platform = sqlx::query!(
        "SELECT default_mode as mode FROM platforms WHERE id = $1",
        session.platform_id
    )
    .fetch_one(&state.db)
    .await?;
    
    let mode = match platform.mode.as_str() {
        "test" => ApiKeyMode::Test,
        "live" => ApiKeyMode::Live,
        _ => ApiKeyMode::Test,
    };
    let network = mode.network_name();
    
    let usdc_mint_str = crate::services::solana::SupportedToken::Usdc
        .get_mint_address(network)
        .ok_or("USDC not supported on network")?;
    
    let usdc_mint = Pubkey::from_str(usdc_mint_str)?;
    let session_pubkey = Pubkey::from_str(session_wallet_address)?;
    let user_pubkey = Pubkey::from_str(user_wallet)?;
    
    let session_ata = spl_associated_token_account::get_associated_token_address(&session_pubkey, &usdc_mint);
    let user_ata = spl_associated_token_account::get_associated_token_address(&user_pubkey, &usdc_mint);
    
    let network_config = state.get_network(&mode);
    let rpc_url = network_config.primary_rpc_url();
    let client = reqwest::Client::new();
    
    let balance_response: serde_json::Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenAccountBalance",
            "params": [session_ata.to_string()]
        }))
        .send()
        .await?
        .json()
        .await?;
    
    if balance_response.get("error").is_some() {
        sqlx::query!(
            "UPDATE session_keys SET refund_status = 'not_needed', refund_completed_at = NOW() WHERE id = $1",
            session.id
        )
        .execute(&state.db)
        .await?;
        return Ok("no_balance".to_string());
    }
    
    let balance_lamports = balance_response
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.get("amount"))
        .and_then(|a| a.as_str())
        .ok_or("Invalid balance response")?
        .parse::<u64>()?;
    
    if balance_lamports == 0 {
        sqlx::query!(
            "UPDATE session_keys SET refund_status = 'not_needed', refund_completed_at = NOW() WHERE id = $1",
            session.id
        )
        .execute(&state.db)
        .await?;
        return Ok("zero_balance".to_string());
    }
    
    let encrypted_key = sqlx::query!(
        r#"
        SELECT encrypted_key_data, nonce 
        FROM encrypted_keys 
        WHERE id = $1
        "#,
        session.session_keypair_id
    )
    .fetch_one(&state.db)
    .await?;
    
    let key_manager = crate::services::key_manager::SecureKeyManager::from_env()?;
    let session_keypair = key_manager.decrypt_keypair(
        &encrypted_key.encrypted_key_data,
        &encrypted_key.nonce,
    )?;
    
    let transfer_ix = transfer(
        &spl_token::id(),
        &session_ata,
        &user_ata,
        &session_pubkey,
        &[],
        balance_lamports,
    )?;
    
    let blockhash_response: serde_json::Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "finalized"}]
        }))
        .send()
        .await?
        .json()
        .await?;
    
    let blockhash_str = blockhash_response
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.get("blockhash"))
        .and_then(|b| b.as_str())
        .ok_or("Invalid blockhash response")?;
    
    let recent_blockhash = Hash::from_str(blockhash_str)?;
    
    let message = Message::new(&[transfer_ix], Some(&session_pubkey));
    let mut transaction = Transaction::new_unsigned(message);
    transaction.message.recent_blockhash = recent_blockhash;
    transaction.sign(&[&session_keypair], recent_blockhash);
    
    let tx_bytes = bincode::serialize(&transaction)?;
    let tx_b64 = general_purpose::STANDARD.encode(&tx_bytes);
    
    let submit_response: serde_json::Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendTransaction",
            "params": [
                tx_b64,
                {
                    "encoding": "base64",
                    "skipPreflight": false,
                    "preflightCommitment": "confirmed"
                }
            ]
        }))
        .send()
        .await?
        .json()
        .await?;
    
    if let Some(error) = submit_response.get("error") {
        sqlx::query!(
            "UPDATE session_keys SET refund_status = 'failed' WHERE id = $1",
            session.id
        )
        .execute(&state.db)
        .await?;
        return Err(format!("RPC error: {:?}", error).into());
    }
    
    let signature = submit_response
        .get("result")
        .and_then(|r| r.as_str())
        .ok_or("No signature in response")?
        .to_string();
    
    sqlx::query!(
        "UPDATE session_keys SET refund_status = 'completed', refund_signature = $1, refund_completed_at = NOW() WHERE id = $2",
        signature,
        session.id
    )
    .execute(&state.db)
    .await?;
    
    Ok(signature)
}

pub struct SessionRecord {
    pub id: uuid::Uuid,
    pub platform_id: uuid::Uuid,
    pub session_keypair_id: uuid::Uuid,
    pub session_wallet_address: Option<String>,
    pub user_wallet: Option<String>,
}

