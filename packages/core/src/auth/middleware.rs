use axum::{
    extract::{Request, State, ConnectInfo},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{Response, IntoResponse},
    Json,
};
use uuid::Uuid;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use sha2::{Sha256, Digest};
use crate::AppState;
use crate::network_config::ApiKeyMode;
use rand::RngCore;
use std::net::SocketAddr;
use serde_json::json;

#[derive(Debug, Clone)]
pub struct AuthenticatedPlatform {
    pub platform_id: Uuid,
    #[allow(dead_code)] // Available for audit logging
    pub api_key_id: Uuid,
    pub mode: ApiKeyMode,
}

struct ApiKeyRecord {
    id: Uuid,
    platform_id: Uuid,
    argon2_hash: Option<String>,
}

pub async fn authenticate_platform(
    State(state): State<AppState>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    mut request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    let ip_address = connect_info.map(|ci| ci.0.ip().to_string());
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let endpoint = request.uri().path().to_string();
    let http_method = request.method().to_string();
    
    let auth_header = headers
        .get("Authorization")
        .and_then(|header| header.to_str().ok());
    
    let auth_header = match auth_header {
        Some(header) => header,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Missing authentication",
                    "message": "Authorization header is required",
                    "code": "MISSING_AUTH_HEADER"
                }))
            ));
        }
    };

    if !auth_header.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid authentication format",
                "message": "Authorization header must use Bearer token format",
                "code": "INVALID_AUTH_FORMAT"
            }))
        ));
    }

    let api_key = &auth_header[7..];
    
    let _mode = ApiKeyMode::from_api_key(api_key).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid API key format",
                "message": "API key must start with 'x0_test_', 'x0_live_', or 'x0_agent_'",
                "code": "INVALID_KEY_FORMAT"
            }))
        )
    })?;

    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    let is_agent_key = ApiKeyMode::is_agent_key(api_key);
    
    let (api_key_record, actual_mode) = if is_agent_key {
        let agent_record = sqlx::query_as::<_, (Uuid, Uuid, Option<String>, bool, String)>(
            r#"
            SELECT 
                ak.id, 
                ak.platform_id, 
                ak.argon2_hash, 
                ak.is_active,
                m.default_mode as platform_mode
            FROM api_keys ak
            JOIN platforms m ON m.id = ak.platform_id
            WHERE ak.sha256_hash = $1 AND ak.is_active = true AND ak.is_agent_key = true
            "#
        )
        .bind(&key_hash)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Database error during agent key authentication: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Authentication failed",
                    "message": "An internal error occurred during authentication",
                    "code": "DATABASE_ERROR"
                }))
            )
        })?;
        
        match agent_record {
            Some((id, platform_id, argon2_hash, _is_active, mode_str)) => {
                let mode = if mode_str == "test" {
                    ApiKeyMode::Test
                } else {
                    ApiKeyMode::Live
                };
                let record = ApiKeyRecord {
                    id,
                    platform_id,
                    argon2_hash,
                };
                (Some(record), mode)
            },
            None => (None, ApiKeyMode::Test)
        }
    } else {
        let platform_record = sqlx::query!(
            r#"
            SELECT id, platform_id, argon2_hash, is_active
            FROM api_keys 
            WHERE sha256_hash = $1 AND is_active = true AND (is_agent_key = false OR is_agent_key IS NULL)
            "#,
            key_hash
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Database error during authentication: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Authentication failed",
                    "message": "An internal error occurred during authentication",
                    "code": "DATABASE_ERROR"
                }))
            )
        })?;
        
        match platform_record {
            Some(rec) => {
                let record = ApiKeyRecord {
                    id: rec.id,
                    platform_id: rec.platform_id,
                    argon2_hash: rec.argon2_hash,
                };
                (Some(record), _mode)
            },
            None => (None, ApiKeyMode::Test)
        }
    };

    let record = api_key_record.ok_or_else(|| {
        tracing::warn!("Invalid API key attempted: {}", if is_agent_key { "agent key" } else { "platform key" });
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid API key",
                "message": "The provided API key is invalid or has been revoked",
                "code": "INVALID_API_KEY"
            }))
        )
    })?;

    let hash_str = record.argon2_hash
        .as_ref()
        .ok_or_else(|| {
            tracing::error!("Missing Argon2 hash in database for key {}", record.id);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Authentication configuration error",
                    "message": "API key configuration is incomplete",
                    "code": "MISSING_HASH"
                }))
            )
        })?;

    let parsed_hash = PasswordHash::new(hash_str)
        .map_err(|_| {
            tracing::error!("Invalid Argon2 hash format in database for key {}", record.id);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Authentication configuration error",
                    "message": "API key configuration is invalid",
                    "code": "INVALID_HASH_FORMAT"
                }))
            )
        })?;

    let argon2 = Argon2::default();
    if argon2.verify_password(api_key.as_bytes(), &parsed_hash).is_err() {
        tracing::warn!("API key failed Argon2 verification");
        
        let db_clone = state.db.clone();
        let key_id = record.id;
        let platform_id = record.platform_id;
        let ip_clone = ip_address.clone();
        let ua_clone = user_agent.clone();
        let endpoint_clone = endpoint.clone();
        let method_clone = http_method.clone();
        
        tokio::spawn(async move {
            let _ = crate::services::audit::log_api_key_usage(
                &db_clone,
                key_id,
                platform_id,
                &endpoint_clone,
                Some(&method_clone),
                ip_clone.as_deref(),
                ua_clone.as_deref(),
                None,
                "unauthorized",
                Some(401),
                Some("API key failed Argon2 verification"),
                None,
                None,
            )
            .await;
        });
        
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Invalid API key",
                "message": "The provided API key is invalid",
                "code": "INVALID_API_KEY"
            }))
        ));
    }

    let db_clone = state.db.clone();
    let key_id = record.id;
    let platform_id = record.platform_id;
    let ip_clone = ip_address.clone();
    let ua_clone = user_agent.clone();
    let endpoint_clone = endpoint.clone();
    let method_clone = http_method.clone();
    
    tokio::spawn(async move {
        let _ = crate::services::audit::log_api_key_usage(
            &db_clone,
            key_id,
            platform_id,
            &endpoint_clone,
            Some(&method_clone),
            ip_clone.as_deref(),
            ua_clone.as_deref(),
            None,
            "success",
            Some(200),
            None,
            None,
            None,
        )
        .await;
    });

    let authenticated_platform = AuthenticatedPlatform {
        platform_id: record.platform_id,
        api_key_id: record.id,
        mode: actual_mode,
    };
    
    request.extensions_mut().insert(authenticated_platform);
    request.extensions_mut().insert(actual_mode);
    
    Ok(next.run(request).await)
}

pub async fn generate_api_key_string(
    state: &AppState, 
    platform_id: Uuid,
    mode: ApiKeyMode,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let api_key = format!("{}{}", mode.prefix(), hex::encode(key_bytes));

    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    let sha256_hash = hex::encode(hasher.finalize());

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let argon2_hash = argon2.hash_password(api_key.as_bytes(), &salt)
        .map_err(|e| format!("Argon2 hashing failed: {}", e))?; 

    let mode_str = mode.to_string();
    
    sqlx::query!(
        r#"
        INSERT INTO api_keys (id, platform_id, sha256_hash, argon2_hash, is_active, created_at, mode)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
        Uuid::new_v4(),
        platform_id,
        sha256_hash,
        argon2_hash.to_string(),
        true,
        chrono::Utc::now(),
        mode_str
    )
    .execute(&state.db)
    .await?;
    
    tracing::info!("Generated secure {} mode API key for platform {}", mode, platform_id);
    Ok(api_key)
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateApiKeyRequest {
    pub platform_id: Uuid,
    pub mode: String,
}

#[derive(Debug, serde::Serialize)]
pub struct CreateApiKeyResponse {
    pub api_key: String,
    pub platform_id: Uuid,
    pub mode: String,
    pub message: String,
}

pub async fn create_platform_api_key_handler(
    State(state): axum::extract::State<AppState>,
    axum::Json(req): axum::Json<CreateApiKeyRequest>,
) -> Result<axum::Json<CreateApiKeyResponse>, (StatusCode, axum::Json<serde_json::Value>)> {
    let mode = ApiKeyMode::from_str(&req.mode);
    
    let platform = sqlx::query!("SELECT id FROM platforms WHERE id = $1", req.platform_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Database error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({"error": "Database error"})))
        })?
        .ok_or_else(|| {
            (StatusCode::NOT_FOUND, axum::Json(json!({"error": "Platform not found"})))
        })?;
    
    let api_key = generate_api_key_string(&state, platform.id, mode)
        .await
        .map_err(|e| {
            tracing::error!("Failed to generate API key: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({"error": "Failed to generate API key"})))
        })?;
    
    Ok(axum::Json(CreateApiKeyResponse {
        api_key,
        platform_id: platform.id,
        mode: mode.to_string(),
        message: "API key created successfully. Store this key securely - it cannot be retrieved again.".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_api_key_format() {
        let key_bytes: [u8; 32] = [1; 32];
        let api_key = format!("x0_live_{}", hex::encode(key_bytes));
        assert!(api_key.starts_with("x0_live_"));
        assert_eq!(api_key.len(), 72);

        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        let hash = hex::encode(hasher.finalize());
        assert_eq!(hash.len(), 64);
    }
}