use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use bigdecimal::{BigDecimal, ToPrimitive};
use chrono::{Utc, Duration as ChronoDuration};
use rand::Rng;
use serde_json::json;
use std::str::FromStr;

use crate::{
    models::*,
    auth::AuthenticatedPlatform,
    services::spending_limits::{self, CryptoSessionConfig},
    AppState,
};

fn generate_session_token() -> String {
    let mut rng = rand::thread_rng();
    let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    format!("x0_session_{}", hex::encode(random_bytes))
}

pub async fn create_agent_session(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Json(request): Json<CreateAgentSessionRequest>,
) -> Result<Json<AgentSessionResponse>, (StatusCode, Json<serde_json::Value>)> {
    let should_mint_pkp = request.mint_pkp.unwrap_or(false);
    
    tracing::info!(
        "Creating AI agent session for platform {} with agent {} (mint_pkp: {})",
        platform.platform_id,
        request.agent_id,
        should_mint_pkp
    );

    if request.user_wallet.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "Invalid user wallet",
                "message": "user_wallet cannot be empty"
            })),
        ));
    }

    let session_token = generate_session_token();
    
    let duration_hours = request.duration_hours.unwrap_or(24);
    let expires_at = Utc::now() + ChronoDuration::hours(duration_hours);

    let limits = if let Some(explicit_limits) = request.limits.clone() {
        explicit_limits
    } else if let Some(spending_limit) = request.spending_limit_usd {
        SessionLimits {
            max_per_transaction: Some(spending_limit),
            max_per_day: Some(spending_limit * 50.0),
            max_per_week: Some(spending_limit * 200.0),
            max_per_month: Some(spending_limit * 500.0),
            require_approval_above: Some(spending_limit * 0.5),
        }
    } else {
        SessionLimits {
            max_per_transaction: Some(1000.0),
            max_per_day: Some(5000.0),
            max_per_week: Some(20000.0),
            max_per_month: Some(50000.0),
            require_approval_above: Some(500.0),
        }
    };

    let max_per_transaction = limits.max_per_transaction
        .map(|v| BigDecimal::from_str(&v.to_string()).ok())
        .flatten();
    let max_per_day = limits.max_per_day
        .map(|v| BigDecimal::from_str(&v.to_string()).ok())
        .flatten();
    let max_per_week = limits.max_per_week
        .map(|v| BigDecimal::from_str(&v.to_string()).ok())
        .flatten();
    let max_per_month = limits.max_per_month
        .map(|v| BigDecimal::from_str(&v.to_string()).ok())
        .flatten();
    let require_approval_above = limits.require_approval_above
        .map(|v| BigDecimal::from_str(&v.to_string()).ok())
        .flatten();

    let allowed_recipients_vec: Vec<String> = request.allowed_recipients
        .map(|v| v.into_iter().map(|u| u.to_string()).collect())
        .unwrap_or_default();
    let allowed_recipients: &[String] = &allowed_recipients_vec;

    let metadata = request.metadata.unwrap_or_else(|| json!({}));

    let session = sqlx::query_as!(
        AgentSession,
        r#"
        INSERT INTO ai_agent_sessions (
            platform_id, session_token, agent_id, agent_name, user_wallet,
            max_per_transaction, max_per_day, max_per_week, max_per_month,
            require_approval_above, allowed_recipients, metadata, expires_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
        )
        RETURNING *
        "#,
        platform.platform_id,
        session_token,
        request.agent_id,
        request.agent_name,
        request.user_wallet,
        max_per_transaction,
        max_per_day,
        max_per_week,
        max_per_month,
        require_approval_above,
        allowed_recipients,
        metadata,
        expires_at
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create AI session: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create session"})),
        )
    })?;

    tracing::info!("Created AI session {} for agent {}", session.id, session.agent_id);

    let (has_pkp, pkp_address) = if should_mint_pkp {
        let max_per_day_usd = limits.max_per_day.unwrap_or(5000.0);
        
        let pkp_config = CryptoSessionConfig {
            session_id: session.id,
            platform_id: platform.platform_id,
            user_wallet: request.user_wallet.clone(),
            max_per_transaction: limits.max_per_transaction,
            max_per_day: max_per_day_usd,
            max_per_week: limits.max_per_week,
            max_per_month: limits.max_per_month,
            duration_hours: duration_hours as u32,
        };
        
        match spending_limits::create_crypto_session(&state, pkp_config).await {
            Ok(pkp_result) => {
                tracing::info!(
                    "Session {} now has on-chain PKP identity (address: {})",
                    session.id, pkp_result.pkp_eth_address
                );
                (true, Some(pkp_result.pkp_eth_address))
            }
            Err(e) => {
                tracing::error!(
                    "Failed to mint PKP for session {}: {}. Session will work without on-chain identity.",
                    session.id, e
                );
                (false, None)
            }
        }
    } else {
        (false, None)
    };

    let zero = BigDecimal::from(0);
    let spent_today = session.spent_today.as_ref().unwrap_or(&zero);
    let spent_this_week = session.spent_this_week.as_ref().unwrap_or(&zero);
    let spent_this_month = session.spent_this_month.as_ref().unwrap_or(&zero);
    
    let remaining_today = session.max_per_day
        .as_ref()
        .and_then(|v| (v - spent_today).to_f64())
        .unwrap_or(f64::MAX);
    let remaining_this_week = session.max_per_week
        .as_ref()
        .and_then(|v| (v - spent_this_week).to_f64())
        .unwrap_or(f64::MAX);
    let remaining_this_month = session.max_per_month
        .as_ref()
        .and_then(|v| (v - spent_this_month).to_f64())
        .unwrap_or(f64::MAX);

    Ok(Json(AgentSessionResponse {
        id: session.id,
        session_token: session.session_token,
        agent_id: session.agent_id,
        agent_name: session.agent_name,
        user_wallet: session.user_wallet,
        limits: SessionLimits {
            max_per_transaction: session.max_per_transaction.and_then(|v| v.to_f64()),
            max_per_day: session.max_per_day.and_then(|v| v.to_f64()),
            max_per_week: session.max_per_week.and_then(|v| v.to_f64()),
            max_per_month: session.max_per_month.and_then(|v| v.to_f64()),
            require_approval_above: session.require_approval_above.and_then(|v| v.to_f64()),
        },
        is_active: session.is_active.unwrap_or(true),
        created_at: session.created_at,
        expires_at: session.expires_at,
        remaining_today,
        remaining_this_week,
        remaining_this_month,
        mint_pkp: has_pkp,
        pkp_address,
    }))
}

pub async fn get_agent_session(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Path(session_id): Path<String>,
) -> Result<Json<AgentSessionResponse>, (StatusCode, Json<serde_json::Value>)> {
    let session_uuid = uuid::Uuid::parse_str(&session_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid session ID"})),
        )
    })?;

    let session = sqlx::query_as!(
        AgentSession,
        r#"SELECT * FROM ai_agent_sessions WHERE id = $1 AND platform_id = $2"#,
        session_uuid,
        platform.platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database error"})),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Session not found"})),
        )
    })?;

    let zero = BigDecimal::from(0);
    let spent_today = session.spent_today.as_ref().unwrap_or(&zero);
    let spent_this_week = session.spent_this_week.as_ref().unwrap_or(&zero);
    let spent_this_month = session.spent_this_month.as_ref().unwrap_or(&zero);
    
    let remaining_today = session.max_per_day
        .as_ref()
        .and_then(|v| (v - spent_today).to_f64())
        .unwrap_or(f64::MAX);
    let remaining_this_week = session.max_per_week
        .as_ref()
        .and_then(|v| (v - spent_this_week).to_f64())
        .unwrap_or(f64::MAX);
    let remaining_this_month = session.max_per_month
        .as_ref()
        .and_then(|v| (v - spent_this_month).to_f64())
        .unwrap_or(f64::MAX);

    Ok(Json(AgentSessionResponse {
        id: session.id,
        session_token: session.session_token,
        agent_id: session.agent_id,
        agent_name: session.agent_name,
        user_wallet: session.user_wallet,
        limits: SessionLimits {
            max_per_transaction: session.max_per_transaction.and_then(|v| v.to_f64()),
            max_per_day: session.max_per_day.and_then(|v| v.to_f64()),
            max_per_week: session.max_per_week.and_then(|v| v.to_f64()),
            max_per_month: session.max_per_month.and_then(|v| v.to_f64()),
            require_approval_above: session.require_approval_above.and_then(|v| v.to_f64()),
        },
        is_active: session.is_active.unwrap_or(true),
        created_at: session.created_at,
        expires_at: session.expires_at,
        remaining_today,
        remaining_this_week,
        remaining_this_month,
        mint_pkp: session.crypto_enforced.unwrap_or(false),
        pkp_address: session.metadata.get("pkp_eth_address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    }))
}

pub async fn revoke_agent_session(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let session_uuid = uuid::Uuid::parse_str(&session_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid session ID"})),
        )
    })?;

    let result = sqlx::query!(
        r#"
        UPDATE ai_agent_sessions
        SET is_active = false, revoked_at = NOW()
        WHERE id = $1 AND platform_id = $2
        RETURNING id
        "#,
        session_uuid,
        platform.platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database error"})),
        )
    })?;

    if result.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Session not found"})),
        ));
    }

    tracing::info!("Revoked AI session {}", session_uuid);

    Ok(Json(json!({
        "success": true,
        "message": "Session revoked successfully"
    })))
}

pub async fn list_agent_sessions(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
) -> Result<Json<Vec<AgentSessionResponse>>, (StatusCode, Json<serde_json::Value>)> {
    let sessions = sqlx::query_as!(
        AgentSession,
        r#"
        SELECT * FROM ai_agent_sessions
        WHERE platform_id = $1
        ORDER BY created_at DESC
        "#,
        platform.platform_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Database error"})),
        )
    })?;

    let responses: Vec<AgentSessionResponse> = sessions
        .into_iter()
        .map(|session| {
            let zero = BigDecimal::from(0);
            let spent_today = session.spent_today.as_ref().unwrap_or(&zero);
            let spent_this_week = session.spent_this_week.as_ref().unwrap_or(&zero);
            let spent_this_month = session.spent_this_month.as_ref().unwrap_or(&zero);
            
            let remaining_today = session.max_per_day
                .as_ref()
                .and_then(|v| (v - spent_today).to_f64())
                .unwrap_or(f64::MAX);
            let remaining_this_week = session.max_per_week
                .as_ref()
                .and_then(|v| (v - spent_this_week).to_f64())
                .unwrap_or(f64::MAX);
            let remaining_this_month = session.max_per_month
                .as_ref()
                .and_then(|v| (v - spent_this_month).to_f64())
                .unwrap_or(f64::MAX);

            AgentSessionResponse {
                id: session.id,
                session_token: session.session_token,
                agent_id: session.agent_id,
                agent_name: session.agent_name,
                user_wallet: session.user_wallet,
                limits: SessionLimits {
                    max_per_transaction: session.max_per_transaction.and_then(|v| v.to_f64()),
                    max_per_day: session.max_per_day.and_then(|v| v.to_f64()),
                    max_per_week: session.max_per_week.and_then(|v| v.to_f64()),
                    max_per_month: session.max_per_month.and_then(|v| v.to_f64()),
                    require_approval_above: session.require_approval_above.and_then(|v| v.to_f64()),
                },
                is_active: session.is_active.unwrap_or(true),
                created_at: session.created_at,
                expires_at: session.expires_at,
                remaining_today,
                remaining_this_week,
                remaining_this_month,
                mint_pkp: session.crypto_enforced.unwrap_or(false),
                pkp_address: session.metadata.get("pkp_eth_address")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            }
        })
        .collect();

    Ok(Json(responses))
}