use axum::{
    extract::{State, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Extension,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use argon2::{
    Argon2,
    PasswordHash, PasswordVerifier, PasswordHasher,
    password_hash::{rand_core::OsRng, SaltString}
};
use sqlx::PgPool;

#[derive(Debug)]
pub enum SecurityError {
    MissingJWTSecret,
    WeakJWTSecret,
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityError::MissingJWTSecret => write!(f, "ADMIN_JWT_SECRET environment variable is not set"),
            SecurityError::WeakJWTSecret => write!(f, "ADMIN_JWT_SECRET must be at least 32 characters long"),
        }
    }
}

impl std::error::Error for SecurityError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminRole {
    SuperAdmin,  
    Admin,      
    Support, 
}

impl AdminRole {
    pub fn can_manage_users(&self) -> bool {
        matches!(self, AdminRole::SuperAdmin)
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "super_admin" => Some(AdminRole::SuperAdmin),
            "admin" => Some(AdminRole::Admin),
            "support" => Some(AdminRole::Support),
            _ => None,
        }
    }
    
    pub fn to_str(&self) -> &str {
        match self {
            AdminRole::SuperAdmin => "super_admin",
            AdminRole::Admin => "admin",
            AdminRole::Support => "support",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminClaims {
    pub sub: String,    
    pub email: String,
    pub role: String,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedAdmin {
    pub admin_id: Uuid,
    pub email: String,
    pub role: AdminRole,
}

#[derive(Debug, Deserialize)]
pub struct AdminLoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AdminLoginResponse {
    pub token: String,
    pub expires_at: String,
    pub admin: AdminInfo,
}

#[derive(Debug, Serialize)]
pub struct AdminInfo {
    pub id: Uuid,
    pub email: String,
    pub full_name: String,
    pub role: String,
}

fn get_jwt_secret() -> Result<String, SecurityError> {
    let secret = std::env::var("ADMIN_JWT_SECRET")
        .map_err(|_| SecurityError::MissingJWTSecret)?;
    
    if secret.len() < 32 {
        return Err(SecurityError::WeakJWTSecret);
    }
    
    Ok(secret)
}

pub fn validate_jwt_secret_on_startup() -> Result<(), SecurityError> {
    get_jwt_secret()?;
    tracing::info!("ADMIN_JWT_SECRET validated successfully");
    Ok(())
}

pub fn generate_admin_token(admin_id: Uuid, email: &str, role: &AdminRole) -> Result<String, jsonwebtoken::errors::Error> {
    let _secret = get_jwt_secret()
        .expect("ADMIN_JWT_SECRET must be configured - call validate_jwt_secret_on_startup() during app initialization");
    
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();
    
    let claims = AdminClaims {
        sub: admin_id.to_string(),
        email: email.to_string(),
        role: role.to_str().to_string(),
        exp: expiration,
        iat: Utc::now().timestamp(),
    };
    
    let secret = get_jwt_secret()
        .expect("ADMIN_JWT_SECRET must be configured - call validate_jwt_secret_on_startup() during app initialization");
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes())
    )
}

pub fn verify_admin_token(token: &str) -> Result<AdminClaims, jsonwebtoken::errors::Error> {
    let secret = get_jwt_secret()
        .expect("ADMIN_JWT_SECRET must be configured - call validate_jwt_secret_on_startup() during app initialization");
    let validation = Validation::new(Algorithm::HS256);
    
    let token_data = decode::<AdminClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation
    )?;
    
    Ok(token_data.claims)
}

pub async fn admin_login(
    State(state): State<crate::AppState>,
    headers: HeaderMap,
    Json(req): Json<AdminLoginRequest>,
) -> Result<Json<AdminLoginResponse>, (StatusCode, Json<serde_json::Value>)> {
    let pool = &state.db;
    if !req.email.contains('@') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid email",
                "message": "Email must be valid"
            }))
        ));
    }
    
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    
    let admin = sqlx::query!(
        r#"
        SELECT id, email, full_name, password_hash, role, is_active
        FROM admin_users
        WHERE email = $1
        "#,
        req.email.to_lowercase()
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!("Database error during admin login: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Database error",
                "message": "Failed to query admin user"
            }))
        )
    })?;
    
    let admin = admin.ok_or_else(|| {
        tracing::warn!("Failed login attempt for non-existent admin: {}", req.email);
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Unauthorized",
                "message": "Invalid email or password"
            }))
        )
    })?;
    
    if !admin.is_active {
        tracing::warn!("Login attempt for inactive admin: {}", req.email);
        
        let _ = log_admin_action(
            pool,
            admin.id,
            "admin.login",
            None,
            None,
            serde_json::json!({"reason": "account_inactive"}),
            ip_address.as_deref(),
            user_agent.as_deref(),
            "failure",
            Some("Account is inactive"),
        ).await;
        
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Account inactive",
                "message": "Your admin account has been deactivated"
            }))
        ));
    }
    
    let parsed_hash = PasswordHash::new(&admin.password_hash)
        .map_err(|e| {
            tracing::error!("Invalid password hash format: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Authentication error",
                    "message": "Failed to verify password"
                }))
            )
        })?;
    
    let argon2 = Argon2::default();
    if argon2.verify_password(req.password.as_bytes(), &parsed_hash).is_err() {
        tracing::warn!("Failed login attempt for admin: {} (invalid password)", req.email);
        
        let _ = log_admin_action(
            pool,
            admin.id,
            "admin.login",
            None,
            None,
            serde_json::json!({"reason": "invalid_password"}),
            ip_address.as_deref(),
            user_agent.as_deref(),
            "failure",
            Some("Invalid password"),
        ).await;
        
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Unauthorized",
                "message": "Invalid email or password"
            }))
        ));
    }
    
    let role = AdminRole::from_str(&admin.role)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Invalid role",
                    "message": "Admin has invalid role configuration"
                }))
            )
        })?;
    
    let token = generate_admin_token(admin.id, &admin.email, &role)
        .map_err(|e| {
            tracing::error!("Failed to generate JWT token: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Token generation error",
                    "message": "Failed to generate authentication token"
                }))
            )
        })?;
    
    let expires_at = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp");
    
    let _ = sqlx::query!(
        "UPDATE admin_users SET last_login_at = NOW(), last_login_ip = $1 WHERE id = $2",
        ip_address,
        admin.id
    )
    .execute(pool)
    .await;
    
    let _ = log_admin_action(
        pool,
        admin.id,
        "admin.login",
        None,
        None,
        serde_json::json!({}),
        ip_address.as_deref(),
        user_agent.as_deref(),
        "success",
        None,
    ).await;
    
    tracing::info!("Admin {} logged in successfully", admin.email);
    
    Ok(Json(AdminLoginResponse {
        token,
        expires_at: expires_at.to_rfc3339(),
        admin: AdminInfo {
            id: admin.id,
            email: admin.email,
            full_name: admin.full_name,
            role: admin.role,
        },
    }))
}

pub async fn admin_auth_middleware(
    State(state): State<crate::AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let pool = &state.db;
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    let token = &auth_header[7..];
    
    let claims = verify_admin_token(token)
        .map_err(|e| {
            tracing::warn!("Invalid admin token: {}", e);
            StatusCode::UNAUTHORIZED
        })?;
    
    let admin_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    let role = AdminRole::from_str(&claims.role)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    let admin_active = sqlx::query!(
        "SELECT is_active FROM admin_users WHERE id = $1",
        admin_id
    )
    .fetch_optional(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    match admin_active {
        Some(admin) if admin.is_active => {
            let authenticated_admin = AuthenticatedAdmin {
                admin_id,
                email: claims.email,
                role,
            };
            
            request.extensions_mut().insert(authenticated_admin);
            Ok(next.run(request).await)
        }
        _ => {
            tracing::warn!("Token valid but admin {} is inactive or doesn't exist", admin_id);
            Err(StatusCode::FORBIDDEN)
        }
    }
}

pub async fn log_admin_action(
    pool: &PgPool,
    admin_id: Uuid,
    action: &str,
    resource_type: Option<&str>,
    resource_id: Option<Uuid>,
    details: serde_json::Value,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    status: &str,
    error_message: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO admin_audit_log 
        (admin_id, action, resource_type, resource_id, details, ip_address, user_agent, status, error_message)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
        admin_id,
        action,
        resource_type,
        resource_id,
        details,
        ip_address,
        user_agent,
        status,
        error_message
    )
    .execute(pool)
    .await?;
    
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

#[derive(Debug, Deserialize)]
pub struct CreateAdminRequest {
    pub email: String,
    pub full_name: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct AdminUserResponse {
    pub id: Uuid,
    pub email: String,
    pub full_name: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: String,
}

pub async fn create_admin_user(
    State(state): State<crate::AppState>,
    headers: HeaderMap,
    Extension(admin): Extension<AuthenticatedAdmin>,
    Json(req): Json<CreateAdminRequest>,
) -> Result<Json<AdminUserResponse>, (StatusCode, Json<serde_json::Value>)> {
    let pool = &state.db;
    if !admin.role.can_manage_users() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Forbidden",
                "message": "Insufficient permissions to create admin users"
            }))
        ));
    }
    
    if req.password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Bad Request",
                "message": "Password must be at least 8 characters"
            }))
        ));
    }
    
    let new_role = AdminRole::from_str(&req.role)
        .ok_or_else(|| (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Bad Request",
                "message": "Invalid role. Supported: super_admin, admin, support"
            }))
        ))?;
    
    let password_hash = hash_password(&req.password)
        .map_err(|e| {
            tracing::error!("Failed to hash password: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Internal Server Error",
                    "message": "Failed to process password"
                }))
            )
        })?;
    
    let user = sqlx::query!(
        r#"
        INSERT INTO admin_users (email, full_name, password_hash, role, created_by)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, email, full_name, role, is_active, created_at
        "#,
        req.email.to_lowercase(),
        req.full_name,
        password_hash,
        new_role.to_str(),
        admin.admin_id
    )
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create admin user: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Database error",
                "message": "Failed to create admin user"
            }))
        )
    })?;
    
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok());
    
    let _ = log_admin_action(
        &pool,
        admin.admin_id,
        "admin.user.create",
        Some("admin_user"),
        Some(user.id),
        serde_json::json!({
            "email": user.email,
            "role": user.role,
            "created_by": admin.email
        }),
        ip_address,
        user_agent,
        "success",
        None,
    ).await;
    
    tracing::info!(
        "Admin {} created new admin user {} with role {}",
        admin.email,
        user.email,
        user.role
    );
    
    Ok(Json(AdminUserResponse {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role,
        is_active: user.is_active,
        created_at: user.created_at.to_rfc3339(),
    }))
}

pub async fn list_admin_users(
    State(state): State<crate::AppState>,
    Extension(admin): Extension<AuthenticatedAdmin>,
) -> Result<Json<Vec<AdminUserResponse>>, (StatusCode, Json<serde_json::Value>)> {
    let pool = &state.db;
    if !admin.role.can_manage_users() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Forbidden",
                "message": "You don't have permission to manage users"
            }))
        ));
    }
    let users = sqlx::query!(
        r#"
        SELECT id, email, full_name, role, is_active, created_at
        FROM admin_users
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to list admin users: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Database error",
                "message": "Failed to fetch admin users"
            }))
        )
    })?;
    
    let response: Vec<AdminUserResponse> = users
        .into_iter()
        .map(|u| AdminUserResponse {
            id: u.id,
            email: u.email,
            full_name: u.full_name,
            role: u.role,
            is_active: u.is_active,
            created_at: u.created_at.to_rfc3339(),
        })
        .collect();
    
    Ok(Json(response))
}

