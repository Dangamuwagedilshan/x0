use axum::{extract::State, http::StatusCode, Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::AuthenticatedPlatform;
use crate::models::ApiKeyScope;
use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAgentApiKeyRequest {
    pub name: String,
    pub agent_id: String,
    pub scopes: Vec<String>,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_hour: i32,
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub mode: Option<String>,
}

fn default_rate_limit() -> i32 {
    1000
}

#[derive(Debug, Serialize)]
pub struct AgentApiKeyResponse {
    pub id: Uuid,
    pub key_prefix: String,
    pub full_key: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub rate_limit_per_hour: i32,
    pub agent_metadata: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

fn generate_api_key() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    format!("x0_{}", hex::encode(bytes))
}

fn validate_scopes(scopes: &[String]) -> Result<(), String> {
    for scope in scopes {
        if ApiKeyScope::from_str(scope).is_none() {
            return Err(format!(
                "Invalid scope '{}'. Valid scopes: full, read_only, create_payments, manage_sessions, read_analytics",
                scope
            ));
        }
    }
    Ok(())
}

pub async fn create_agent_api_key(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Json(request): Json<CreateAgentApiKeyRequest>,
) -> Result<Json<AgentApiKeyResponse>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = validate_scopes(&request.scopes) {
        return Err((StatusCode::BAD_REQUEST, Json(json!({"error": e}))));
    }

    let api_key = generate_api_key();
    let key_id = Uuid::new_v4();
    let key_prefix = format!("{}...{}", &api_key[..10], &api_key[api_key.len() - 4..]);

    let sha256_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        hex::encode(hasher.finalize())
    };

    let argon2_hash = {
        use argon2::{
            password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
            Argon2,
        };
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(api_key.as_bytes(), &salt)
            .map_err(|e| {
                tracing::error!("Failed to hash API key: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to create API key"})),
                )
            })?
            .to_string()
    };

    let scopes_vec: Vec<String> = if request.scopes.is_empty() {
        vec!["read_only".to_string()]
    } else {
        request.scopes.clone()
    };
    let scopes_arr: &[String] = &scopes_vec;
    let rate_limit = request.rate_limit_per_hour;

    let agent_metadata = json!({
        "agent_id": request.agent_id,
        "agent_name": request.name,
        "custom": request.metadata
    });

    let mode_str = request.mode.as_deref().unwrap_or("live");

    sqlx::query!(
        r#"
        INSERT INTO api_keys (id, platform_id, key_hash, key_hash_argon2, scopes, 
                              rate_limit_per_hour, agent_metadata, mode, is_agent_key, is_active)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, true)
        "#,
        key_id,
        platform.platform_id,
        sha256_hash,
        argon2_hash,
        scopes_arr,
        rate_limit,
        agent_metadata,
        mode_str
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create agent API key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create API key"})),
        )
    })?;

    tracing::info!(
        "Created agent API key {} for platform {} (agent: {}, mode: {})",
        key_id,
        platform.platform_id,
        request.agent_id,
        mode_str
    );

    let created_at = sqlx::query_scalar!("SELECT created_at FROM api_keys WHERE id = $1", key_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or_else(|_| chrono::Utc::now());

    Ok(Json(AgentApiKeyResponse {
        id: key_id,
        key_prefix,
        full_key: api_key,
        name: request.name,
        scopes: request.scopes,
        rate_limit_per_hour: rate_limit,
        agent_metadata,
        created_at,
    }))
}

pub async fn list_agent_api_keys(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let keys = sqlx::query!(
        r#"
        SELECT id, scopes, rate_limit_per_hour, agent_metadata,
               is_active, last_used_at, created_at
        FROM api_keys
        WHERE platform_id = $1 AND is_agent_key = true
        ORDER BY created_at DESC
        "#,
        platform.platform_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to list agent API keys: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to list API keys"})),
        )
    })?;

    let keys_json: Vec<serde_json::Value> = keys
        .into_iter()
        .map(|k| {
            let scopes: Vec<String> = k.scopes;

            let agent_name = k
                .agent_metadata
                .as_ref()
                .and_then(|m| m.get("agent_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown Agent");

            json!({
                "id": k.id,
                "agent_name": agent_name,
                "scopes": scopes,
                "rate_limit_per_hour": k.rate_limit_per_hour,
                "agent_metadata": k.agent_metadata,
                "is_active": k.is_active,
                "last_used_at": k.last_used_at,
                "created_at": k.created_at
            })
        })
        .collect();

    Ok(Json(json!({
        "keys": keys_json,
        "count": keys_json.len()
    })))
}

pub async fn revoke_agent_api_key(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    axum::extract::Path(key_id): axum::extract::Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let result = sqlx::query!(
        r#"
        UPDATE api_keys 
        SET is_active = false 
        WHERE id = $1 AND platform_id = $2 AND is_agent_key = true
        "#,
        key_id,
        platform.platform_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to revoke API key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to revoke API key"})),
        )
    })?;

    if result.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "API key not found"})),
        ));
    }

    tracing::info!(
        "Revoked agent API key {} for platform {}",
        key_id,
        platform.platform_id
    );

    Ok(Json(json!({
        "success": true,
        "message": "API key revoked"
    })))
}
