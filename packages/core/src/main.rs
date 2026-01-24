use axum::{
    routing::{get, post},
    Router,
    middleware::{self, Next},
    http::{header, StatusCode, Method},
    response::Response,
    extract::Request,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;
use tracing::Instrument;
use axum::extract::DefaultBodyLimit;
use axum::response::IntoResponse;
use std::net::SocketAddr;
use std::sync::Arc;

mod api;
mod auth;
mod config;
mod database;
mod enterprise;
mod models;
mod network_config;
mod services;
mod utils;

use config::Config;
use network_config::{ApiKeyMode, NetworkConfig};
use enterprise::License;
use webauthn_rs::prelude::*;
use solana_sdk::signature::Signer;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub redis: redis::aio::ConnectionManager,
    pub solana_rpc_url: String,
    pub solana_client: Arc<services::sol_client::ResilientSolanaClient>,
    pub rpc_cache: Arc<services::rpc_cache::RpcCache>,
    pub config: Config,
    pub webauthn: Arc<Webauthn>,
    pub test_network: NetworkConfig,
    pub live_network: NetworkConfig,
    pub test_fee_payer: Arc<solana_sdk::signature::Keypair>,
    pub live_fee_payer: Arc<solana_sdk::signature::Keypair>,
    pub keypair_cache: Arc<services::keypair_cache::KeypairCache>,
    pub attestation_signer: Option<Arc<services::attestation::AttestationSigner>>,
    pub license: License,
}

impl AppState {
    pub fn get_network(&self, mode: &ApiKeyMode) -> &NetworkConfig {
        match mode {
            ApiKeyMode::Test => &self.test_network,
            ApiKeyMode::Live => &self.live_network,
        }
    }

    pub fn get_fee_payer(&self, mode: &ApiKeyMode) -> &solana_sdk::signature::Keypair {
        match mode {
            ApiKeyMode::Test => &self.test_fee_payer,
            ApiKeyMode::Live => &self.live_fee_payer,
        }
    }
}

async fn correlation_id_middleware(mut request: Request, next: Next) -> Result<Response, StatusCode> {
    let correlation_id = Uuid::new_v4().to_string();
    if let Ok(val) = correlation_id.parse() {
        request.headers_mut().insert("x-correlation-id", val);
    }

    let span = tracing::info_span!(
        "request",
        correlation_id = &correlation_id,
        method = %request.method(),
        path = %request.uri().path()
    );

    let response = next.run(request).instrument(span).await;
    Ok(response)
}

async fn error_handler_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let uri = request.uri().clone();

    let result = next.run(request).await;

    if result.status().is_client_error() || result.status().is_server_error() {
        tracing::error!(
            "Request failed with status {}: {} {}",
            result.status(),
            method,
            uri
        );
    }

    Ok(result)
}

fn load_keypair_from_env(var_name: &str) -> Result<solana_sdk::signature::Keypair, String> {
    let key_str = std::env::var(var_name)
        .map_err(|_| format!("{} not set in environment", var_name))?;

    if let Ok(bytes) = serde_json::from_str::<Vec<u8>>(&key_str) {
        return solana_sdk::signature::Keypair::try_from(&bytes[..])
            .map_err(|e| format!("Invalid keypair bytes in {}: {}", var_name, e));
    }

    let bytes = bs58::decode(&key_str).into_vec()
        .map_err(|e| format!("Invalid base58 in {}: {}", var_name, e))?;

    solana_sdk::signature::Keypair::try_from(&bytes[..])
        .map_err(|e| format!("Invalid keypair in {}: {}", var_name, e))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = dotenvy::dotenv() {
        if !e.to_string().contains("not found") {
            eprintln!("Warning: Failed to load .env file: {}", e);
        }
    }

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "x0=info,sqlx=warn,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting x0 - Payment Infrastructure for AI Agents");

    let build_time = option_env!("BUILD_TIMESTAMP")
        .map(String::from)
        .unwrap_or_else(|| "unknown".to_string());

    let git_hash = option_env!("GIT_HASH")
        .map(String::from)
        .unwrap_or_else(|| "unknown".to_string());

    tracing::info!(
        "Version: v{} | Build: {} | Commit: {}",
        env!("CARGO_PKG_VERSION"),
        build_time,
        git_hash
    );

    let license = License::from_env();
    tracing::info!(
        "License: {:?} (customer: {})",
        license.tier,
        license.customer_id
    );

    if let Err(e) = auth::admin::validate_jwt_secret_on_startup() {
        tracing::error!("Security Error: {}", e);
        tracing::error!("Please set ADMIN_JWT_SECRET environment variable (minimum 32 characters)");
        std::process::exit(1);
    }

    if let Err(e) = services::agent_wallet_custody::AgentCustodyManager::validate_production_config() {
        tracing::error!("Agent Custody Security Error: {}", e);
        std::process::exit(1);
    }

    let config = match Config::from_env() {
        Ok(config) => {
            tracing::info!("Configuration loaded successfully");
            config
        },
        Err(e) => {
            tracing::error!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    let db = database::initialize_database(&config.database_url).await
        .map_err(|e| {
            tracing::error!("Database initialization failed: {}", e);
            e
        })?;

    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let redis = database::create_redis_connection(&redis_url).await
        .map_err(|e| {
            tracing::error!("Failed to connect to Redis: {}", e);
            e
        })?;

    let solana_client = Arc::new(services::sol_client::ResilientSolanaClient::new(
        config.solana_rpc_urls.clone()
    ));

    let rpc_cache = Arc::new(services::rpc_cache::RpcCache::new());

    let cache_cleanup = rpc_cache.clone();
    tokio::spawn(services::rpc_cache::start_cache_cleanup(cache_cleanup));

    let monitor_client = solana_client.clone();
    tokio::spawn(services::sol_client::start_endpoint_monitor(monitor_client));

    let webauthn = {
        let rp_id = std::env::var("WEBAUTHN_RP_ID")
            .unwrap_or_else(|_| "localhost".to_string());

        let rp_origin_str = std::env::var("WEBAUTHN_RP_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());

        let rp_origin = Url::parse(&rp_origin_str)
            .expect("Invalid WEBAUTHN_RP_ORIGIN URL");

        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)
            .expect("Failed to create WebAuthn builder");

        Arc::new(builder.build().expect("Failed to build WebAuthn"))
    };

    let test_network = NetworkConfig::from_mode(ApiKeyMode::Test)
        .expect("Failed to initialize test network configuration");
    let live_network = NetworkConfig::from_mode(ApiKeyMode::Live)
        .expect("Failed to initialize live network configuration");

    tracing::info!("Network configs initialized:");
    tracing::info!("  Test mode: {} ({})", test_network.network_name, test_network.primary_rpc_url());
    tracing::info!("  Live mode: {} ({})", live_network.network_name, live_network.primary_rpc_url());

    let test_fee_payer = match load_keypair_from_env("DEVNET_FEE_PAYER_KEYPAIR") {
        Ok(kp) => {
            tracing::info!("Test fee payer loaded: {}", kp.pubkey());
            Arc::new(kp)
        }
        Err(e) => {
            tracing::warn!("Devnet fee payer not configured: {} - gasless payments disabled for test mode", e);
            match load_keypair_from_env("DEVNET_ESCROW_KEYPAIR") {
                Ok(kp) => Arc::new(kp),
                Err(_) => std::process::exit(1),
            }
        }
    };

    let live_fee_payer = match load_keypair_from_env("MAINNET_FEE_PAYER_KEYPAIR") {
        Ok(kp) => {
            tracing::info!("Live fee payer loaded: {}", kp.pubkey());
            Arc::new(kp)
        }
        Err(e) => {
            tracing::warn!("Mainnet fee payer not configured: {} - gasless payments disabled for live mode", e);
            match load_keypair_from_env("MAINNET_ESCROW_KEYPAIR") {
                Ok(kp) => Arc::new(kp),
                Err(_) => std::process::exit(1),
            }
        }
    };

    let attestation_signer = match services::attestation::AttestationSigner::from_env() {
        Ok(signer) => {
            tracing::info!("Attestation signer loaded: {}", signer.public_key());
            Some(Arc::new(signer))
        }
        Err(e) => {
            tracing::warn!("Attestation signer not configured: {}", e);
            None
        }
    };

    let state = AppState {
        db,
        redis,
        solana_rpc_url: config.solana_rpc_urls.first()
            .unwrap_or(&"https://api.devnet.solana.com".to_string())
            .clone(),
        solana_client: solana_client.clone(),
        rpc_cache,
        config: config.clone(),
        webauthn,
        test_network,
        live_network,
        test_fee_payer,
        live_fee_payer,
        keypair_cache: Arc::new(services::keypair_cache::KeypairCache::new(
            services::keypair_cache::KeypairCacheConfig::from_env()
        )),
        attestation_signer,
        license,
    };

    let webhook_state = state.clone();
    tokio::spawn(services::webhooks::webhook_retry_worker(webhook_state));

    let reset_job_state = state.clone();
    tokio::spawn(services::limit_reset::start_spending_limit_reset_job(reset_job_state));
    tracing::info!("Spending limit reset job started");

    let session_cleanup_state = state.clone();
    tokio::spawn(services::session_cleanup::expired_session_cleanup_worker(session_cleanup_state));
    tracing::info!("Session cleanup worker started");
    
    let scopes_cleanup_state = state.clone();
    tokio::spawn(auth::scopes::cleanup_api_key_usage_worker(scopes_cleanup_state));
    tracing::info!("API key usage cleanup worker started");
    
    let session_key_maintenance_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Err(e) = services::session_keys_core::run_session_key_maintenance(&session_key_maintenance_state).await {
                tracing::error!("Session key maintenance error: {:?}", e);
            }
        }
    });
    tracing::info!("Session key maintenance worker started");

    let public_routes = Router::new()
        .route("/health", get(api::health::health_check))
        .route("/health/detailed", get(api::health::system_health))
        .route("/", get(root_handler))
        .with_state(state.clone());

    let protected_routes = Router::new()
        .route("/api/v1/sessions", post(services::sessions::create_agent_session))
        .route("/api/v1/sessions", get(services::sessions::list_agent_sessions))
        .route("/api/v1/sessions/:id", get(services::sessions::get_agent_session))
        .route("/api/v1/sessions/:id/revoke", post(services::sessions::revoke_agent_session))

        .route("/api/v1/session-keys/create", post(services::session_keys::create_session_key)
            .layer(DefaultBodyLimit::max(10 * 1024)))
        .route("/api/v1/session-keys/submit-approval", post(services::session_keys::submit_approval_transaction)
            .layer(DefaultBodyLimit::max(50 * 1024)))
        .route("/api/v1/session-keys/status", post(services::session_keys::get_session_key_status))
        .route("/api/v1/session-keys/revoke", post(services::session_keys::revoke_session_key))
        .route("/api/v1/session-keys/list", get(services::session_keys::list_session_keys))
        
        .route("/api/v1/session-keys/:id/top-up", post(services::session_keys_topup::top_up_session_key)
            .layer(DefaultBodyLimit::max(10 * 1024)))
        .route("/api/v1/session-keys/:id/submit-top-up", post(services::session_keys_topup::submit_top_up_transaction)
            .layer(DefaultBodyLimit::max(50 * 1024)))
        
        .route("/api/v1/session-keys/:id/link-session", post(services::session_keys::link_session)
            .layer(DefaultBodyLimit::max(5 * 1024)))
        .route("/api/v1/session-keys/:id/unlink-session", post(services::session_keys::unlink_session)
            .layer(DefaultBodyLimit::max(1 * 1024)))
        .route("/api/v1/session-keys/:id/check-payment", post(services::session_keys::check_payment)
            .layer(DefaultBodyLimit::max(5 * 1024)))
        
        .route("/api/v1/session-keys/device-bound/create", post(services::session_keys_device_bound::create_device_bound_session_key)
            .layer(DefaultBodyLimit::max(50 * 1024)))
        .route("/api/v1/session-keys/device-bound/get-encrypted", post(services::session_keys_device_bound::get_encrypted_session_key)
            .layer(DefaultBodyLimit::max(5 * 1024)))
        .route("/api/v1/session-keys/device-bound/:id/recover", post(services::session_keys_device_bound::recover_session_key_on_new_device)
            .layer(DefaultBodyLimit::max(50 * 1024)))

        .route("/api/v1/payments", post(services::payments::smart_payment)
            .layer(DefaultBodyLimit::max(15 * 1024)))
        
        .route("/api/v1/payments/:payment_id/submit-signed", post(services::payments_device_bound::submit_signed_transaction)
            .layer(DefaultBodyLimit::max(50 * 1024)))

        .route("/api/v1/pricing/suggest", post(services::pricing::get_pricing_suggestion))
        .route("/api/v1/pricing/ppp-factor", post(services::pricing::get_ppp_factor))
        .route("/api/v1/pricing/ppp-factors", get(services::pricing::list_ppp_factors))

        .route("/api/v1/session-keys/:id/enable-autonomy",
            post(services::session_keys_autonomous::enable_autonomous_signing))
        .route("/api/v1/session-keys/:id/revoke-autonomy",
            post(services::session_keys_autonomous::revoke_autonomous_mode))
        .route("/api/v1/session-keys/:id/autonomy-status",
            get(services::session_keys_autonomous::get_autonomy_status))
        
        .route("/api/v1/delegates/:id/attestations",
            get(services::attestation::get_delegate_attestations_handler))

        .route("/api/v1/agent-keys", post(services::agent_keys::create_agent_api_key))
        .route("/api/v1/agent-keys", get(services::agent_keys::list_agent_api_keys))
        .route("/api/v1/agent-keys/:id/revoke", post(services::agent_keys::revoke_agent_api_key))

        .route("/api/v1/analytics/agents", get(services::analytics::get_agent_analytics))

        .route("/api/v1/spending/check",
            post(services::spending_limits::check_spending_limit_internal))

        .route("/api/v1/webhooks", get(services::webhooks::list_webhook_events))
        .route("/api/v1/webhooks/:id/retry", post(services::webhooks::retry_webhook))

        .route("/api/v1/custody", get(services::custody_handlers::list_custody))
        .route("/api/v1/custody/grant", post(services::custody_handlers::grant_custody)
            .layer(DefaultBodyLimit::max(50 * 1024)))
        .route("/api/v1/custody/:custody_id/sign", post(services::custody_handlers::sign_with_custody)
            .layer(DefaultBodyLimit::max(50 * 1024)))
        .route("/api/v1/custody/:custody_id/revoke", post(services::custody_handlers::revoke_custody))

        .with_state(state.clone())
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::middleware::authenticate_platform));

    let admin_routes = Router::new()
        .route("/admin/login", post(auth::admin::admin_login))
        .with_state(state.clone());
    
    let admin_protected_routes = Router::new()
        .route("/admin/users", post(auth::admin::create_admin_user))
        .route("/admin/users", get(auth::admin::list_admin_users))
        .route("/admin/api-keys", post(auth::middleware::create_platform_api_key_handler))
        .route("/admin/platforms/:platform_id/usage", get(services::audit::get_platform_usage_stats_handler))
        .route("/admin/platforms/:platform_id/security-events", get(services::audit::get_platform_security_events_handler))
        .route("/admin/platforms/:platform_id/timeline", get(services::audit::get_platform_usage_timeline_handler))
        .route("/admin/gas/analytics", get(services::gas_tracking::get_gas_analytics_handler))
        .route("/admin/gas/profitability", get(services::gas_tracking::get_gas_profitability_handler))
        .with_state(state.clone())
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::admin::admin_auth_middleware));
    
    let webauthn_routes = Router::new()
        .route("/api/v1/webauthn/register/start", post(auth::webauthn::start_registration))
        .route("/api/v1/webauthn/register/finish", post(auth::webauthn::finish_registration))
        .route("/api/v1/webauthn/auth/start", post(auth::webauthn::start_authentication))
        .route("/api/v1/webauthn/auth/finish", post(auth::webauthn::finish_authentication))
        .with_state(state.clone());
    
    let passkey_routes = Router::new()
        .route("/platforms/:platform_id/setup-passkey", get(auth::passkey::get_passkey_setup_page))
        .route("/api/platforms/:platform_id/passkey-status", get(auth::passkey::get_passkey_status))
        .with_state(state.clone());

    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(admin_routes)
        .merge(admin_protected_routes)
        .merge(webauthn_routes)
        .merge(passkey_routes)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn(error_handler_middleware))
        .layer(middleware::from_fn(correlation_id_middleware))
        .layer(middleware::from_fn(cors_layer));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.port))
        .await?;

    tracing::info!("x0 API running on http://0.0.0.0:{}", config.port);
    tracing::info!("Health endpoint: http://0.0.0.0:{}/health", config.port);

    let shutdown = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        tracing::info!("Received shutdown signal, gracefully shutting down...");
    };

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>()
    )
    .with_graceful_shutdown(shutdown)
    .await?;

    Ok(())
}

async fn root_handler() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "name": "x0",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Payment infrastructure for AI agents",
        "docs": "https://docs.x0.dev",
        "health": "/health"
    }))
}

async fn cors_layer(request: Request, next: Next) -> Result<Response, StatusCode> {
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if request.method() == Method::OPTIONS {
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(axum::body::Body::empty())
            .unwrap();

        add_cors_headers(response.headers_mut(), &origin);
        return Ok(response);
    }

    let mut response = next.run(request).await;
    add_cors_headers(response.headers_mut(), &origin);
    Ok(response)
}

fn add_cors_headers(headers: &mut axum::http::HeaderMap, origin: &str) {
    if !origin.is_empty() {
        if let Ok(val) = origin.parse() {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, val);
        }
    } else {
        if let Ok(val) = "*".parse() {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, val);
        }
    }

    if let Ok(val) = "GET, POST, PUT, DELETE, OPTIONS".parse() {
        headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, val);
    }
    if let Ok(val) = "Content-Type, Authorization, X-Requested-With, Idempotency-Key".parse() {
        headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, val);
    }
    if let Ok(val) = "true".parse() {
        headers.insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, val);
    }
    if let Ok(val) = "86400".parse() {
        headers.insert(header::ACCESS_CONTROL_MAX_AGE, val);
    }
}
