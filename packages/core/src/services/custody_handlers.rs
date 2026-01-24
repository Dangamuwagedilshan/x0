use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    auth::AuthenticatedPlatform,
    services::agent_wallet_custody::{
        AgentCustodyManager, CustodyError, CustodySpendingRules, GrantCustodyRequest,
    },
    AppState,
};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SpendingRulesApiRequest {
    pub max_transaction_amount_sol: Option<f64>,
    pub max_transaction_amount_usdc: Option<f64>,
    pub daily_limit_sol: Option<f64>,
    pub daily_limit_usdc: Option<f64>,
    #[serde(default)]
    pub allowed_recipients: Vec<String>,
    #[serde(default)]
    pub allowed_programs: Vec<String>,
    pub require_approval_above_sol: Option<f64>,
    pub require_approval_above_usdc: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct GrantCustodyApiRequest {
    pub agent_id: String,
    pub user_wallet: String,
    pub encrypted_keypair_base64: String,
    pub client_nonce_base64: String,
    pub expires_in_days: Option<u32>,
    pub spending_rules: Option<SpendingRulesApiRequest>,
}

#[derive(Debug, Serialize)]
pub struct GrantCustodyApiResponse {
    pub custody_id: Uuid,
    pub access_secret: String,
    pub user_wallet: String,
    pub expires_at: Option<String>,
    pub warning: String,
}

pub async fn grant_custody(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Json(request): Json<GrantCustodyApiRequest>,
) -> Result<Json<GrantCustodyApiResponse>, (StatusCode, Json<serde_json::Value>)> {
    use base64::Engine;

    let encrypted_keypair = base64::engine::general_purpose::STANDARD
        .decode(&request.encrypted_keypair_base64)
        .map_err(|e| {
            (StatusCode::BAD_REQUEST, Json(json!({
                "error": "Invalid encrypted_keypair_base64",
                "message": e.to_string()
            })))
        })?;

    let client_nonce = base64::engine::general_purpose::STANDARD
        .decode(&request.client_nonce_base64)
        .map_err(|e| {
            (StatusCode::BAD_REQUEST, Json(json!({
                "error": "Invalid client_nonce_base64",
                "message": e.to_string()
            })))
        })?;

    let manager = AgentCustodyManager::new();

    let spending_rules = request.spending_rules.map(|api_rules| CustodySpendingRules {
        max_transaction_amount_sol: api_rules.max_transaction_amount_sol,
        max_transaction_amount_usdc: api_rules.max_transaction_amount_usdc,
        daily_limit_sol: api_rules.daily_limit_sol,
        daily_limit_usdc: api_rules.daily_limit_usdc,
        allowed_recipients: api_rules.allowed_recipients,
        allowed_programs: api_rules.allowed_programs,
        require_approval_above_sol: api_rules.require_approval_above_sol,
        require_approval_above_usdc: api_rules.require_approval_above_usdc,
    });

    let result = manager.grant_custody(
        &state,
        platform.platform_id,
        GrantCustodyRequest {
            agent_id: request.agent_id,
            user_wallet: request.user_wallet,
            encrypted_keypair,
            client_nonce,
            expires_in_days: request.expires_in_days,
            spending_rules,
        },
    ).await.map_err(custody_error_to_response)?;

    Ok(Json(GrantCustodyApiResponse {
        custody_id: result.custody_id,
        access_secret: result.access_secret,
        user_wallet: result.user_wallet,
        expires_at: result.expires_at.map(|t| t.to_rfc3339()),
        warning: result.warning,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SignWithCustodyRequest {
    pub access_secret: String,
    pub transaction_message_base64: String,
}

#[derive(Debug, Serialize)]
pub struct SignWithCustodyResponse {
    pub signature_base64: String,
    pub public_key: String,
}

pub async fn sign_with_custody(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Path(custody_id): Path<Uuid>,
    Json(request): Json<SignWithCustodyRequest>,
) -> Result<Json<SignWithCustodyResponse>, (StatusCode, Json<serde_json::Value>)> {
    use base64::Engine;
    use crate::services::agent_wallet_custody::AgentSignRequest;

    let transaction_message = base64::engine::general_purpose::STANDARD
        .decode(&request.transaction_message_base64)
        .map_err(|e| {
            (StatusCode::BAD_REQUEST, Json(json!({
                "error": "Invalid transaction_message_base64",
                "message": e.to_string()
            })))
        })?;

    let custody_check = sqlx::query!(
        "SELECT platform_id FROM agent_wallet_custody WHERE id = $1",
        custody_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Database error",
            "message": e.to_string()
        })))
    })?;

    match custody_check {
        Some(c) if c.platform_id == platform.platform_id => {}
        _ => {
            return Err((StatusCode::NOT_FOUND, Json(json!({
                "error": "Custody not found",
                "message": "Custody record not found or does not belong to this platform"
            }))));
        }
    }

    let manager = AgentCustodyManager::new();

    let result = manager.sign_with_custody(
        &state,
        AgentSignRequest {
            custody_id,
            access_secret: request.access_secret,
            transaction_message,
        },
    ).await.map_err(custody_error_to_response)?;

    Ok(Json(SignWithCustodyResponse {
        signature_base64: base64::engine::general_purpose::STANDARD.encode(&result.signature),
        public_key: result.public_key,
    }))
}

pub async fn revoke_custody(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Path(custody_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let manager = AgentCustodyManager::new();

    manager.revoke_custody(&state, custody_id, platform.platform_id)
        .await
        .map_err(custody_error_to_response)?;

    Ok(Json(json!({
        "success": true,
        "custody_id": custody_id,
        "message": "Custody revoked successfully"
    })))
}

pub async fn list_custody(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let records = sqlx::query!(
        r#"
        SELECT id, agent_id, user_wallet, expires_at, created_at
        FROM agent_wallet_custody
        WHERE platform_id = $1 AND is_active = TRUE
        ORDER BY created_at DESC
        LIMIT 100
        "#,
        platform.platform_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "error": "Database error",
            "message": e.to_string()
        })))
    })?;

    let custody_list: Vec<serde_json::Value> = records.iter().map(|r| {
        json!({
            "custody_id": r.id,
            "agent_id": r.agent_id,
            "user_wallet": r.user_wallet,
            "expires_at": r.expires_at.map(|t| t.to_rfc3339()),
            "created_at": r.created_at.to_rfc3339()
        })
    }).collect();

    Ok(Json(json!({
        "custody_records": custody_list,
        "total": custody_list.len()
    })))
}

fn custody_error_to_response(err: CustodyError) -> (StatusCode, Json<serde_json::Value>) {
    let (status, code) = match &err {
        CustodyError::InvalidAccessSecret => (StatusCode::UNAUTHORIZED, "INVALID_ACCESS_SECRET"),
        CustodyError::CustodyNotFound => (StatusCode::NOT_FOUND, "CUSTODY_NOT_FOUND"),
        CustodyError::CustodyRevoked => (StatusCode::GONE, "CUSTODY_REVOKED"),
        CustodyError::LitProtocolError(_) => (StatusCode::SERVICE_UNAVAILABLE, "LIT_ERROR"),
        CustodyError::DecryptionFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DECRYPTION_FAILED"),
        CustodyError::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR"),
        CustodyError::InvalidKeypair(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INVALID_KEYPAIR"),
        CustodyError::InvalidTransaction(_) => (StatusCode::BAD_REQUEST, "INVALID_TRANSACTION"),
        CustodyError::SpendingLimitExceeded(_) => (StatusCode::FORBIDDEN, "SPENDING_LIMIT_EXCEEDED"),
        CustodyError::DailyLimitExceeded(_) => (StatusCode::FORBIDDEN, "DAILY_LIMIT_EXCEEDED"),
        CustodyError::RecipientNotAllowed(_) => (StatusCode::FORBIDDEN, "RECIPIENT_NOT_ALLOWED"),
        CustodyError::ProgramNotAllowed(_) => (StatusCode::FORBIDDEN, "PROGRAM_NOT_ALLOWED"),
        CustodyError::ApprovalRequired(_) => (StatusCode::FORBIDDEN, "APPROVAL_REQUIRED"),
    };

    (status, Json(json!({
        "error": err.to_string(),
        "code": code
    })))
}
