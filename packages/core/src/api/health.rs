use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use crate::AppState;

pub async fn health_check() -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(serde_json::json!({
        "status": "healthy",
        "service": "x0",
        "version": env!("CARGO_PKG_VERSION")
    })))
}

pub async fn system_health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let db_healthy = check_database_health(&state.db).await;
    let redis_healthy = check_redis_health(&state.redis).await;
    
    let solana_status = match state.solana_client.get_health().await {
        Ok(_) => "healthy",
        Err(_) => "degraded",
    };

    let overall_status = if db_healthy && redis_healthy {
        "healthy"
    } else if db_healthy {
        "degraded"
    } else {
        "unhealthy"
    };

    Json(serde_json::json!({
        "status": overall_status,
        "service": "x0",
        "version": env!("CARGO_PKG_VERSION"),
        "components": {
            "database": if db_healthy { "healthy" } else { "unhealthy" },
            "redis": if redis_healthy { "healthy" } else { "unhealthy" },
            "solana_rpc": solana_status
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn check_database_health(db: &sqlx::PgPool) -> bool {
    sqlx::query("SELECT 1")
        .fetch_one(db)
        .await
        .is_ok()
}

async fn check_redis_health(redis: &redis::aio::ConnectionManager) -> bool {
    let mut conn = redis.clone();
    redis::cmd("PING")
        .query_async::<_, String>(&mut conn)
        .await
        .is_ok()
}
