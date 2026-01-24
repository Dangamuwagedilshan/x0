use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;
use crate::AppState;
use redis::AsyncCommands;

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyResponse {
    pub credential_id: String,
    pub public_key: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub client_data_json: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ChallengeState<T> {
    state: T,
    platform_id: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn store_registration_challenge(
    redis: &mut redis::aio::ConnectionManager,
    challenge_id: Uuid,
    state: PasskeyRegistration,
    platform_id: Uuid,
) -> Result<(), WebAuthnError> {
    let challenge_state = ChallengeState {
        state,
        platform_id,
        created_at: chrono::Utc::now(),
    };
    
    let key = format!("webauthn:reg:{}", challenge_id);
    let value = serde_json::to_vec(&challenge_state)
        .map_err(|e| WebAuthnError::DatabaseError(format!("Serialization failed: {}", e)))?;
    
    let _: () = redis
        .set_ex(key, value, 600)
        .await
        .map_err(|e| WebAuthnError::DatabaseError(format!("Redis error: {}", e)))?;
    
    Ok(())
}

async fn get_registration_challenge(
    redis: &mut redis::aio::ConnectionManager,
    challenge_id: Uuid,
) -> Result<(PasskeyRegistration, Uuid), WebAuthnError> {
    let key = format!("webauthn:reg:{}", challenge_id);
    
    let value: Option<Vec<u8>> = redis
        .get_del(&key)
        .await
        .map_err(|e| WebAuthnError::DatabaseError(format!("Redis error: {}", e)))?;
    
    let value = value.ok_or(WebAuthnError::ChallengeNotFound)?;
    
    let challenge_state: ChallengeState<PasskeyRegistration> = serde_json::from_slice(&value)
        .map_err(|e| WebAuthnError::DatabaseError(format!("Deserialization failed: {}", e)))?;
    
    let age = chrono::Utc::now() - challenge_state.created_at;
    if age.num_minutes() > 5 {
        return Err(WebAuthnError::ChallengeExpired);
    }
    
    Ok((challenge_state.state, challenge_state.platform_id))
}

async fn store_authentication_challenge(
    redis: &mut redis::aio::ConnectionManager,
    challenge_id: Uuid,
    state: PasskeyAuthentication,
    platform_id: Uuid,
) -> Result<(), WebAuthnError> {
    let challenge_state = ChallengeState {
        state,
        platform_id,
        created_at: chrono::Utc::now(),
    };
    
    let key = format!("webauthn:auth:{}", challenge_id);
    let value = serde_json::to_vec(&challenge_state)
        .map_err(|e| WebAuthnError::DatabaseError(format!("Serialization failed: {}", e)))?;
    
    let _: () = redis
        .set_ex(key, value, 600)
        .await
        .map_err(|e| WebAuthnError::DatabaseError(format!("Redis error: {}", e)))?;
    
    Ok(())
}

async fn get_authentication_challenge(
    redis: &mut redis::aio::ConnectionManager,
    challenge_id: Uuid,
) -> Result<(PasskeyAuthentication, Uuid), WebAuthnError> {
    let key = format!("webauthn:auth:{}", challenge_id);
    
    let value: Option<Vec<u8>> = redis
        .get_del(&key)
        .await
        .map_err(|e| WebAuthnError::DatabaseError(format!("Redis error: {}", e)))?;
    
    let value = value.ok_or(WebAuthnError::ChallengeNotFound)?;
    
    let challenge_state: ChallengeState<PasskeyAuthentication> = serde_json::from_slice(&value)
        .map_err(|e| WebAuthnError::DatabaseError(format!("Deserialization failed: {}", e)))?;
    
    let age = chrono::Utc::now() - challenge_state.created_at;
    if age.num_minutes() > 5 {
        return Err(WebAuthnError::ChallengeExpired);
    }
    
    Ok((challenge_state.state, challenge_state.platform_id))
}

pub async fn store_passkey_in_db(
    db: &sqlx::PgPool,
    platform_id: Uuid,
    passkey: &Passkey,
) -> Result<String, WebAuthnError> {
    tracing::info!("Storing passkey in database for platform {}", platform_id);
    
    let cred_id = passkey.cred_id();
    let credential_id = serde_json::to_string(cred_id)
        .map_err(|e| WebAuthnError::DatabaseError(format!("Failed to serialize credential ID: {}", e)))?;
    
    let public_key_cose = serde_json::to_vec(&passkey)
        .map_err(|e| WebAuthnError::DatabaseError(format!("Serialization failed: {}", e)))?;
    
    let counter: i64 = 0;
    
    let user_handle = platform_id.to_string();
    
    sqlx::query!(
        r#"
        INSERT INTO webauthn_credentials 
        (platform_id, credential_id, public_key_cose, counter, user_handle, is_active, created_at)
        VALUES ($1, $2, $3, $4, $5, TRUE, NOW())
        ON CONFLICT (credential_id) 
        DO UPDATE SET 
            counter = EXCLUDED.counter,
            last_used_at = NOW()
        "#,
        platform_id,
        credential_id,
        public_key_cose,
        counter,
        user_handle,
    )
    .execute(db)
    .await
    .map_err(|e| WebAuthnError::DatabaseError(format!("Database insert failed: {}", e)))?;
    
    tracing::info!("Passkey stored in database: {}", credential_id);
    
    Ok(credential_id)
}

pub async fn retrieve_passkeys_from_db(
    db: &sqlx::PgPool,
    platform_id: Uuid,
) -> Result<Vec<Passkey>, WebAuthnError> {
    tracing::debug!("Retrieving passkeys from database for platform {}", platform_id);
    
    let records = sqlx::query!(
        r#"
        SELECT public_key_cose, counter 
        FROM webauthn_credentials 
        WHERE platform_id = $1 AND is_active = TRUE
        ORDER BY created_at DESC
        "#,
        platform_id
    )
    .fetch_all(db)
    .await
    .map_err(|e| WebAuthnError::DatabaseError(format!("Database query failed: {}", e)))?;
    
    if records.is_empty() {
        return Err(WebAuthnError::NoCredentialsFound);
    }
    
    let passkeys: Vec<Passkey> = records
        .into_iter()
        .filter_map(|r| {
            let cose_bytes = &r.public_key_cose;
            match serde_json::from_slice::<Passkey>(cose_bytes) {
                Ok(passkey) => Some(passkey),
                Err(e) => {
                    tracing::warn!("Failed to deserialize passkey: {}", e);
                    None
                }
            }
        })
        .collect();
    
    if passkeys.is_empty() {
        return Err(WebAuthnError::NoCredentialsFound);
    }
    
    tracing::debug!("Retrieved {} passkey(s) from database", passkeys.len());
    
    Ok(passkeys)
}

pub async fn update_passkey_counter(
    db: &sqlx::PgPool,
    credential_id: &str,
    new_counter: u32,
) -> Result<(), WebAuthnError> {
    sqlx::query!(
        r#"
        UPDATE webauthn_credentials
        SET counter = $1,
            last_used_at = NOW()
        WHERE credential_id = $2
        "#,
        new_counter as i64,
        credential_id,
    )
    .execute(db)
    .await
    .map_err(|e| WebAuthnError::DatabaseError(format!("Counter update failed: {}", e)))?;
    
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartRegistrationRequest {
    pub platform_id: Uuid,
    pub email: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartRegistrationResponse {
    pub challenge_id: Uuid,
    pub options: CreationChallengeResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinishRegistrationRequest {
    pub challenge_id: Uuid,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinishRegistrationResponse {
    pub credential_id: String,
    pub success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartAuthenticationRequest {
    pub platform_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartAuthenticationResponse {
    pub challenge_id: Uuid,
    pub options: RequestChallengeResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinishAuthenticationRequest {
    pub challenge_id: Uuid,
    pub credential: PublicKeyCredential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinishAuthenticationResponse {
    pub platform_id: Uuid,
    pub success: bool,
}

#[derive(Debug)]
pub enum WebAuthnError {
    WebAuthnError(String),
    DatabaseError(String),
    ChallengeNotFound,
    ChallengeExpired,
    NoCredentialsFound,
}

impl IntoResponse for WebAuthnError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            WebAuthnError::WebAuthnError(msg) => (StatusCode::BAD_REQUEST, msg),
            WebAuthnError::DatabaseError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", msg)),
            WebAuthnError::ChallengeNotFound => (StatusCode::NOT_FOUND, "Challenge not found".to_string()),
            WebAuthnError::ChallengeExpired => (StatusCode::BAD_REQUEST, "Challenge expired".to_string()),
            WebAuthnError::NoCredentialsFound => (StatusCode::NOT_FOUND, "No credentials found for platform".to_string()),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

pub async fn start_registration(
    State(state): State<AppState>,
    Json(req): Json<StartRegistrationRequest>,
) -> Result<Json<StartRegistrationResponse>, WebAuthnError> {
    tracing::info!("Starting passkey registration for platform {}", req.platform_id);

    let webauthn = &state.webauthn;

    sqlx::query!(
        "SELECT id FROM platforms WHERE id = $1",
        req.platform_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| WebAuthnError::DatabaseError(e.to_string()))?
    .ok_or_else(|| WebAuthnError::DatabaseError("Merchant not found".to_string()))?;

    let user_unique_id = Uuid::new_v4();

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(
            user_unique_id,
            &req.email,
            &req.display_name,
            None,
        )
        .map_err(|e| WebAuthnError::WebAuthnError(format!("Failed to start registration: {:?}", e)))?;

    let challenge_id = Uuid::new_v4();
    let mut redis = state.redis.clone();
    
    store_registration_challenge(&mut redis, challenge_id, reg_state, req.platform_id).await?;

    tracing::info!("Registration challenge created: {}", challenge_id);

    Ok(Json(StartRegistrationResponse {
        challenge_id,
        options: ccr,
    }))
}

pub async fn finish_registration(
    State(state): State<AppState>,
    Json(req): Json<FinishRegistrationRequest>,
) -> Result<Json<FinishRegistrationResponse>, WebAuthnError> {
    tracing::info!("Finishing passkey registration for challenge {}", req.challenge_id);

    let webauthn = &state.webauthn;

    let mut redis = state.redis.clone();
    let (reg_state, platform_id) = match get_registration_challenge(&mut redis, req.challenge_id).await {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to get registration challenge {}: {:?}", req.challenge_id, e);
            return Err(e);
        }
    };

    tracing::info!("Got registration challenge for platform {}", platform_id);

    let passkey = match webauthn.finish_passkey_registration(&req.credential, &reg_state) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::error!("WebAuthn verification failed for challenge {}: {:?}", req.challenge_id, e);
            return Err(WebAuthnError::WebAuthnError(format!("Registration verification failed: {:?}", e)));
        }
    };

    let credential_id = store_passkey_in_db(&state.db, platform_id, &passkey).await?;

    tracing::info!("Passkey registered successfully: {}", credential_id);


    Ok(Json(FinishRegistrationResponse {
        credential_id,
        success: true,
    }))
}

pub async fn start_authentication(
    State(state): State<AppState>,
    Json(req): Json<StartAuthenticationRequest>,
) -> Result<Json<StartAuthenticationResponse>, WebAuthnError> {
    tracing::info!("Starting passkey authentication for platform {}", req.platform_id);

    let webauthn = &state.webauthn;

    let passkeys = retrieve_passkeys_from_db(&state.db, req.platform_id).await?;

    tracing::info!("Found {} passkey(s) for platform {}", passkeys.len(), req.platform_id);

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| WebAuthnError::WebAuthnError(format!("Failed to start authentication: {:?}", e)))?;

    let challenge_id = Uuid::new_v4();
    let mut redis = state.redis.clone();
    
    store_authentication_challenge(&mut redis, challenge_id, auth_state, req.platform_id).await?;

    tracing::info!("Authentication challenge created: {}", challenge_id);

    Ok(Json(StartAuthenticationResponse {
        challenge_id,
        options: rcr,
    }))
}

pub async fn finish_authentication(
    State(_state): State<AppState>,
    Json(req): Json<FinishAuthenticationRequest>,
) -> Result<Json<FinishAuthenticationResponse>, WebAuthnError> {
    tracing::info!("Finishing passkey authentication for challenge {}", req.challenge_id);

    let webauthn = &_state.webauthn;

    let mut redis = _state.redis.clone();
    let (auth_state, platform_id) = get_authentication_challenge(&mut redis, req.challenge_id).await?;

    let auth_result = webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| WebAuthnError::WebAuthnError(format!("Authentication verification failed: {:?}", e)))?;

    let cred_id = auth_result.cred_id();
    let credential_id = serde_json::to_string(cred_id)
        .map_err(|e| WebAuthnError::DatabaseError(format!("Failed to serialize credential ID: {}", e)))?;
    let new_counter = auth_result.counter();

    update_passkey_counter(&_state.db, &credential_id, new_counter).await?;

    tracing::info!("Authentication successful for platform {} (credential: {}, counter: {})", 
                   platform_id, credential_id, new_counter);

    Ok(Json(FinishAuthenticationResponse {
        platform_id,
        success: true,
    }))
}
