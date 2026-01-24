use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::auth::AuthenticatedPlatform;
use crate::AppState;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct WebhookEvent {
    pub id: Uuid,
    pub payment_id: Option<Uuid>,
    pub platform_id: Uuid,
    pub event_type: WebhookEventType,
    pub payload: serde_json::Value,
    pub webhook_url: String,
    pub status: WebhookStatus,
    pub attempts: i32,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub response_code: Option<i32>,
    pub response_body: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, sqlx::Type, Clone, PartialEq)]
#[sqlx(type_name = "webhook_event_type", rename_all = "snake_case")]
pub enum WebhookEventType {
    PaymentCreated,
    PaymentConfirmed,
    PaymentFailed,
    PaymentExpired,

    SessionCreated,
    SessionRevoked,
    SessionExpired,
    SessionLimitExceeded,

    WithdrawalInitiated,
    WithdrawalCompleted,
    WithdrawalFailed,
    
    AutonomousDelegateCreated,
}

#[derive(Debug, Serialize, Deserialize, sqlx::Type, Clone)]
#[sqlx(type_name = "webhook_status", rename_all = "lowercase")]
pub enum WebhookStatus {
    Pending,
    Delivered,
    Failed,
    Exhausted,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event: WebhookEventType,
    pub data: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    pub signature: String,
}

pub fn generate_webhook_signature(payload: &str, secret: &str, timestamp: i64) -> String {
    let signed_payload = format!("{}:{}", timestamp, payload);
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(signed_payload.as_bytes());

    let result = mac.finalize();
    format!("t={},v1={}", timestamp, hex::encode(result.into_bytes()))
}

#[allow(dead_code)] // SDK utility: platforms use this to verify received webhooks
pub fn verify_webhook_signature(payload: &str, signature: &str, secret: &str) -> bool {
    let parts: Vec<&str> = signature.split(',').collect();
    if parts.len() != 2 {
        return false;
    }

    let timestamp_str = match parts[0].strip_prefix("t=") {
        Some(ts) => ts,
        None => return false,
    };

    let timestamp: i64 = match timestamp_str.parse() {
        Ok(ts) => ts,
        Err(_) => return false,
    };

    let provided_sig = match parts[1].strip_prefix("v1=") {
        Some(sig) => sig,
        None => return false,
    };

    let now = Utc::now().timestamp();
    let age = now - timestamp;

    if age > 300 || age < -60 {
        return false;
    }

    let expected_signature = generate_webhook_signature(payload, secret, timestamp);
    let expected_sig = match expected_signature.strip_prefix(&format!("t={},v1=", timestamp)) {
        Some(sig) => sig,
        None => return false,
    };

    provided_sig.as_bytes().ct_eq(expected_sig.as_bytes()).into()
}

async fn get_platform_webhook_secret(
    state: &AppState,
    platform_id: Uuid,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(existing) = sqlx::query!(
        "SELECT webhook_secret FROM platforms WHERE id = $1 AND webhook_secret IS NOT NULL",
        platform_id
    )
    .fetch_one(&state.db)
    .await
    {
        if let Some(secret) = existing.webhook_secret {
            return Ok(secret);
        }
    }

    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let webhook_secret = format!("whsec_{}", hex::encode(secret_bytes));

    sqlx::query!(
        "UPDATE platforms SET webhook_secret = $1 WHERE id = $2",
        webhook_secret,
        platform_id
    )
    .execute(&state.db)
    .await?;

    tracing::info!("Generated new webhook secret for platform {}", platform_id);
    Ok(webhook_secret)
}

pub async fn create_webhook_event(
    state: &AppState,
    platform_id: Uuid,
    event_type: WebhookEventType,
    data: serde_json::Value,
    reference_id: Option<Uuid>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let idempotency_key = format!(
        "{:?}_{}_{}",
        event_type,
        reference_id.unwrap_or(platform_id),
        Utc::now().timestamp()
    );

    let webhook_url = match sqlx::query!(
        "SELECT webhook_url FROM platforms WHERE id = $1",
        platform_id
    )
    .fetch_one(&state.db)
    .await?
    .webhook_url
    {
        Some(url) if !url.is_empty() => url,
        _ => {
            tracing::debug!("No webhook URL configured for platform {}", platform_id);
            return Ok(());
        }
    };

    let webhook_secret = get_platform_webhook_secret(state, platform_id).await?;

    let now = Utc::now();
    let timestamp = now.timestamp();

    let mut payload = WebhookPayload {
        event: event_type.clone(),
        data,
        timestamp: now,
        signature: String::new(),
    };

    let payload_json = serde_json::to_string(&payload)?;
    let signature = generate_webhook_signature(&payload_json, &webhook_secret, timestamp);
    payload.signature = signature;

    let webhook_id = Uuid::new_v4();
    sqlx::query!(
        r#"
        INSERT INTO webhook_events 
        (id, payment_id, platform_id, event_type, payload, webhook_url, status, attempts, idempotency_key, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
        webhook_id,
        reference_id,
        platform_id,
        event_type as WebhookEventType,
        serde_json::to_value(&payload)?,
        webhook_url,
        WebhookStatus::Pending as WebhookStatus,
        0,
        idempotency_key,
        now
    )
    .execute(&state.db)
    .await?;

    tokio::spawn(deliver_webhook(state.clone(), webhook_id));

    Ok(())
}

async fn get_webhook_event(state: &AppState, webhook_id: Uuid) -> Result<WebhookEvent, sqlx::Error> {
    sqlx::query_as!(
        WebhookEvent,
        r#"
        SELECT id, payment_id, platform_id, event_type as "event_type: WebhookEventType", 
               payload, webhook_url, status as "status: WebhookStatus", attempts,
               last_attempt_at, next_retry_at, response_code, response_body, created_at
        FROM webhook_events WHERE id = $1
        "#,
        webhook_id
    )
    .fetch_one(&state.db)
    .await
}

pub async fn deliver_webhook(state: AppState, webhook_id: Uuid) {
    const MAX_RETRIES: i32 = 5;
    const RETRY_DELAYS: [i64; 5] = [60, 300, 900, 3600, 86400];

    let webhook = match get_webhook_event(&state, webhook_id).await {
        Ok(webhook) => webhook,
        Err(e) => {
            tracing::error!("Failed to get webhook {}: {}", webhook_id, e);
            return;
        }
    };

    if matches!(
        webhook.status,
        WebhookStatus::Delivered | WebhookStatus::Exhausted
    ) {
        return;
    }

    let attempt_count = webhook.attempts + 1;

    if attempt_count > MAX_RETRIES {
        let _ = sqlx::query!(
            "UPDATE webhook_events SET status = 'exhausted' WHERE id = $1",
            webhook_id
        )
        .execute(&state.db)
        .await;
        tracing::error!(
            "Webhook {} exhausted after {} attempts",
            webhook_id,
            MAX_RETRIES
        );
        return;
    }

    let platform_secret = match get_platform_webhook_secret(&state, webhook.platform_id).await {
        Ok(secret) => secret,
        Err(e) => {
            tracing::error!(
                "Failed to get webhook secret for platform {}: {}",
                webhook.platform_id,
                e
            );
            return;
        }
    };

    let timestamp = Utc::now().timestamp();
    let payload_json = serde_json::to_string(&webhook.payload).unwrap_or_default();
    let signature = generate_webhook_signature(&payload_json, &platform_secret, timestamp);

    let mut payload: WebhookPayload = match serde_json::from_value(webhook.payload) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to deserialize webhook payload: {}", e);
            return;
        }
    };
    payload.signature = signature.clone();
    payload.timestamp = Utc::now();

    let signed_payload = match serde_json::to_string(&payload) {
        Ok(json) => json,
        Err(e) => {
            tracing::error!("Failed to serialize signed payload: {}", e);
            return;
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to build HTTP client: {}", e);
            return;
        }
    };

    let mut headers = reqwest::header::HeaderMap::new();
    if let Ok(val) = "application/json".parse() {
        headers.insert("Content-Type", val);
    }
    if let Ok(val) = signature.parse() {
        headers.insert("X-X0-Signature", val);
    }
    if let Ok(val) = format!("{:?}", payload.event).parse() {
        headers.insert("X-X0-Event", val);
    }
    if let Ok(val) = webhook_id.to_string().parse() {
        headers.insert("X-X0-Delivery", val);
    }
    if let Ok(val) = attempt_count.to_string().parse() {
        headers.insert("X-X0-Attempt", val);
    }

    let response = client
        .post(&webhook.webhook_url)
        .headers(headers)
        .body(signed_payload)
        .send()
        .await;

    let now = Utc::now();

    match response {
        Ok(resp) => {
            let status_code = resp.status().as_u16() as i32;
            let response_body = resp.text().await.unwrap_or_default();

            if (200..300).contains(&status_code) {
                let _ = sqlx::query!(
                    r#"
                    UPDATE webhook_events 
                    SET status = 'delivered', attempts = $1, last_attempt_at = $2,
                        response_code = $3, response_body = $4
                    WHERE id = $5
                    "#,
                    attempt_count,
                    now,
                    status_code,
                    response_body.chars().take(1000).collect::<String>(),
                    webhook_id
                )
                .execute(&state.db)
                .await;

                tracing::info!("Webhook {} delivered successfully", webhook_id);
            } else {
                update_webhook_failed(
                    &state,
                    webhook_id,
                    attempt_count,
                    status_code,
                    response_body,
                    &RETRY_DELAYS,
                )
                .await;
            }
        }
        Err(e) => {
            update_webhook_failed(&state, webhook_id, attempt_count, 0, e.to_string(), &RETRY_DELAYS)
                .await;
        }
    }
}

async fn update_webhook_failed(
    state: &AppState,
    webhook_id: Uuid,
    attempt_count: i32,
    response_code: i32,
    response_body: String,
    retry_delays: &[i64; 5],
) {
    let delay_seconds = if attempt_count <= retry_delays.len() as i32 {
        retry_delays[(attempt_count - 1) as usize]
    } else {
        86400
    };

    let next_retry = Utc::now() + chrono::Duration::seconds(delay_seconds);

    let _ = sqlx::query!(
        r#"
        UPDATE webhook_events 
        SET status = 'failed', attempts = $1, last_attempt_at = $2, 
            next_retry_at = $3, response_code = $4, response_body = $5
        WHERE id = $6
        "#,
        attempt_count,
        Utc::now(),
        next_retry,
        if response_code > 0 {
            Some(response_code)
        } else {
            None
        },
        response_body.chars().take(1000).collect::<String>(),
        webhook_id
    )
    .execute(&state.db)
    .await;

    tracing::warn!(
        "Webhook {} failed (attempt {}/5), retry in {}s",
        webhook_id,
        attempt_count,
        delay_seconds
    );
}

pub async fn webhook_retry_worker(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        interval.tick().await;

        let webhooks = sqlx::query!(
            r#"
            SELECT id FROM webhook_events 
            WHERE status = 'failed' AND next_retry_at <= NOW()
            LIMIT 10
            "#
        )
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        for webhook in webhooks {
            let state_clone = state.clone();
            tokio::spawn(deliver_webhook(state_clone, webhook.id));
        }
    }
}

pub async fn list_webhook_events(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
) -> Result<Json<Vec<WebhookEvent>>, (StatusCode, Json<serde_json::Value>)> {
    let webhooks = sqlx::query_as!(
        WebhookEvent,
        r#"
        SELECT id, payment_id, platform_id, event_type as "event_type: WebhookEventType",
               payload, webhook_url, status as "status: WebhookStatus", attempts,
               last_attempt_at, next_retry_at, response_code, response_body, created_at
        FROM webhook_events 
        WHERE platform_id = $1 
        ORDER BY created_at DESC 
        LIMIT 50
        "#,
        platform.platform_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to list webhook events: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to fetch webhook events"})),
        )
    })?;

    Ok(Json(webhooks))
}

pub async fn retry_webhook(
    State(state): State<AppState>,
    Path(webhook_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let result = sqlx::query!(
        r#"
        UPDATE webhook_events 
        SET status = 'pending', next_retry_at = NOW(), attempts = 0
        WHERE id = $1 AND status IN ('failed', 'exhausted')
        RETURNING id
        "#,
        webhook_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to retry webhook: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to update webhook status"})),
        )
    })?;

    if result.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Webhook not found or not in failed state"})),
        ));
    }

    tokio::spawn(deliver_webhook(state, webhook_id));

    Ok(Json(serde_json::json!({
        "success": true,
        "webhook_id": webhook_id
    })))
}

#[allow(dead_code)]
pub async fn create_withdrawal_webhook_event(
    state: &AppState,
    withdrawal_id: Uuid,
    platform_id: Uuid,
    event_type: WebhookEventType,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let platform = sqlx::query!(
        "SELECT webhook_url, webhook_secret FROM platforms WHERE id = $1",
        platform_id
    )
    .fetch_optional(&state.db)
    .await?;

    let Some(platform) = platform else {
        return Err("Platform not found".into());
    };

    let Some(webhook_url) = platform.webhook_url else {
        return Ok(());
    };

    let payload = serde_json::json!({
        "withdrawal_id": withdrawal_id,
        "event_type": format!("{:?}", event_type),
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    sqlx::query!(
        r#"
        INSERT INTO webhook_events (id, platform_id, event_type, payload, webhook_url, status, created_at)
        VALUES ($1, $2, $3, $4, $5, 'pending', NOW())
        "#,
        Uuid::new_v4(),
        platform_id,
        event_type as WebhookEventType,
        payload,
        webhook_url
    )
    .execute(&state.db)
    .await?;

    Ok(())
}

pub async fn send_webhook_event_for_autonomous_delegates(
    state: &AppState,
    delegate_id: Uuid,
    platform_id: Uuid,
    event_type: WebhookEventType,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let platform = sqlx::query!(
        "SELECT webhook_url, webhook_secret FROM platforms WHERE id = $1",
        platform_id
    )
    .fetch_optional(&state.db)
    .await?;

    let Some(platform) = platform else {
        return Err("Platform not found".into());
    };

    let Some(webhook_url) = platform.webhook_url else {
        return Ok(());
    };

    let payload = serde_json::json!({
        "delegate_id": delegate_id,
        "event_type": format!("{:?}", event_type),
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    sqlx::query!(
        r#"
        INSERT INTO webhook_events (id, platform_id, event_type, payload, webhook_url, status, created_at)
        VALUES ($1, $2, $3, $4, $5, 'pending', NOW())
        "#,
        Uuid::new_v4(),
        platform_id,
        event_type as WebhookEventType,
        payload,
        webhook_url
    )
    .execute(&state.db)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_signature() {
        let payload = r#"{"event":"PaymentConfirmed","data":{"id":"123"}}"#;
        let secret = "test_secret";
        let timestamp = Utc::now().timestamp();

        let signature = generate_webhook_signature(payload, secret, timestamp);
        assert!(signature.starts_with(&format!("t={},v1=", timestamp)));

        let is_valid = verify_webhook_signature(payload, &signature, secret);
        assert!(is_valid);
    }

    #[test]
    fn test_webhook_signature_replay_protection() {
        let payload = r#"{"event":"PaymentConfirmed","data":{"id":"123"}}"#;
        let secret = "test_secret";

        let old_timestamp = Utc::now().timestamp() - 600;
        let old_signature = generate_webhook_signature(payload, secret, old_timestamp);

        let is_valid = verify_webhook_signature(payload, &old_signature, secret);
        assert!(!is_valid);
    }

    #[test]
    fn test_webhook_signature_tampering() {
        let payload = r#"{"event":"PaymentConfirmed","data":{"id":"123"}}"#;
        let tampered = r#"{"event":"PaymentConfirmed","data":{"id":"999"}}"#;
        let secret = "test_secret";
        let timestamp = Utc::now().timestamp();

        let signature = generate_webhook_signature(payload, secret, timestamp);

        assert!(!verify_webhook_signature(tampered, &signature, secret));
        assert!(!verify_webhook_signature(payload, &signature, "wrong_secret"));
    }
}

