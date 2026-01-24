use sqlx::PgPool;
use sqlx::types::ipnetwork::IpNetwork;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use crate::AppState;

pub async fn log_api_key_usage(
    db: &PgPool,
    api_key_id: Uuid,
    platform_id: Uuid,
    endpoint: &str,
    http_method: Option<&str>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    request_id: Option<&str>,
    status: &str,
    response_code: Option<i32>,
    error_message: Option<&str>,
    request_duration_ms: Option<i32>,
    metadata: Option<serde_json::Value>,
) -> Result<(), sqlx::Error> {
    let ip_addr: Option<IpNetwork> = ip_address.and_then(|ip| {
        ip.parse::<std::net::IpAddr>().ok().map(IpNetwork::from)
    });
    
    let request_id_uuid: Option<Uuid> = request_id.and_then(|id| Uuid::parse_str(id).ok());
    
    sqlx::query!(
        r#"
        INSERT INTO api_key_audit_log 
        (api_key_id, platform_id, endpoint, http_method, ip_address, user_agent, 
         request_id, status, response_code, error_message, request_duration_ms, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
        api_key_id,
        platform_id,
        endpoint,
        http_method,
        ip_addr as Option<IpNetwork>,
        user_agent,
        request_id_uuid,
        status,
        response_code,
        error_message,
        request_duration_ms,
        metadata.unwrap_or_else(|| serde_json::json!({}))
    )
    .execute(db)
    .await?;
    
    Ok(())
}


pub async fn get_api_key_usage_stats(
    db: &PgPool,
    platform_id: Uuid,
    days: i32,
) -> Result<ApiKeyUsageStats, sqlx::Error> {
    let stats = sqlx::query_as!(
        ApiKeyUsageStats,
        r#"
        SELECT 
            COUNT(*) as "total_requests!",
            COUNT(*) FILTER (WHERE status = 'success') as "successful_requests!",
            COUNT(*) FILTER (WHERE status = 'failed') as "failed_requests!",
            COUNT(*) FILTER (WHERE status = 'unauthorized') as "unauthorized_requests!",
            COUNT(*) FILTER (WHERE status = 'rate_limited') as "rate_limited_requests!",
            COUNT(DISTINCT endpoint) as "unique_endpoints!",
            COUNT(DISTINCT ip_address) as "unique_ips!",
            AVG(request_duration_ms)::integer as avg_duration_ms,
            MAX(created_at) as last_request_at
        FROM api_key_audit_log
        WHERE platform_id = $1 
        AND created_at > NOW() - ($2 || ' days')::INTERVAL
        "#,
        platform_id,
        days.to_string()
    )
    .fetch_one(db)
    .await?;
    
    Ok(stats)
}

pub async fn get_security_events(
    db: &PgPool,
    platform_id: Uuid,
    limit: i32,
) -> Result<Vec<SecurityEvent>, sqlx::Error> {
    let events = sqlx::query_as!(
        SecurityEvent,
        r#"
        SELECT 
            id,
            api_key_id,
            endpoint,
            http_method,
            ip_address,
            status,
            error_message,
            created_at
        FROM api_key_audit_log
        WHERE platform_id = $1 
        AND status IN ('failed', 'unauthorized', 'rate_limited')
        ORDER BY created_at DESC
        LIMIT $2
        "#,
        platform_id,
        limit as i64
    )
    .fetch_all(db)
    .await?;
    
    Ok(events)
}

pub async fn get_usage_timeline(
    db: &PgPool,
    platform_id: Uuid,
    hours: i32,
) -> Result<Vec<UsageTimelineEntry>, sqlx::Error> {
    let timeline = sqlx::query_as!(
        UsageTimelineEntry,
        r#"
        SELECT 
            date_trunc('hour', created_at) as "hour!",
            COUNT(*) as "total_requests!",
            COUNT(*) FILTER (WHERE status = 'success') as "successful_requests!",
            COUNT(*) FILTER (WHERE status = 'failed') as "failed_requests!"
        FROM api_key_audit_log
        WHERE platform_id = $1 
        AND created_at > NOW() - ($2 || ' hours')::INTERVAL
        GROUP BY date_trunc('hour', created_at)
        ORDER BY date_trunc('hour', created_at) DESC
        "#,
        platform_id,
        hours.to_string()
    )
    .fetch_all(db)
    .await?;
    
    Ok(timeline)
}

#[derive(Debug, serde::Serialize)]
pub struct ApiKeyUsageStats {
    pub total_requests: i64,
    pub successful_requests: i64,
    pub failed_requests: i64,
    pub unauthorized_requests: i64,
    pub rate_limited_requests: i64,
    pub unique_endpoints: i64,
    pub unique_ips: i64,
    pub avg_duration_ms: Option<i32>,
    pub last_request_at: Option<DateTime<Utc>>,
}

#[derive(Debug, serde::Serialize)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub api_key_id: Option<Uuid>,
    pub endpoint: Option<String>,
    pub http_method: Option<String>,
    pub ip_address: Option<String>,
    pub status: Option<String>,
    pub error_message: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, serde::Serialize)]
pub struct UsageTimelineEntry {
    pub hour: DateTime<Utc>,
    pub total_requests: i64,
    pub successful_requests: i64,
    pub failed_requests: i64,
}

#[derive(Debug, Deserialize)]
pub struct UsageStatsQuery {
    pub days: Option<i32>,
}

pub async fn get_platform_usage_stats_handler(
    State(state): State<AppState>,
    Path(platform_id): Path<Uuid>,
    Query(query): Query<UsageStatsQuery>,
) -> Result<Json<ApiKeyUsageStats>, (StatusCode, Json<serde_json::Value>)> {
    let days = query.days.unwrap_or(30);
    
    get_api_key_usage_stats(&state.db, platform_id, days)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("Failed to get usage stats for platform {}: {}", platform_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to fetch usage statistics"
                }))
            )
        })
}

#[derive(Debug, Deserialize)]
pub struct SecurityEventsQuery {
    pub limit: Option<i32>,
}

pub async fn get_platform_security_events_handler(
    State(state): State<AppState>,
    Path(platform_id): Path<Uuid>,
    Query(query): Query<SecurityEventsQuery>,
) -> Result<Json<Vec<SecurityEvent>>, (StatusCode, Json<serde_json::Value>)> {
    let limit = query.limit.unwrap_or(100);
    
    get_security_events(&state.db, platform_id, limit)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("Failed to get security events for platform {}: {}", platform_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to fetch security events"
                }))
            )
        })
}

#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    pub hours: Option<i32>,
}

pub async fn get_platform_usage_timeline_handler(
    State(state): State<AppState>,
    Path(platform_id): Path<Uuid>,
    Query(query): Query<TimelineQuery>,
) -> Result<Json<Vec<UsageTimelineEntry>>, (StatusCode, Json<serde_json::Value>)> {
    let hours = query.hours.unwrap_or(24);
    
    get_usage_timeline(&state.db, platform_id, hours)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("Failed to get usage timeline for platform {}: {}", platform_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to fetch usage timeline"
                }))
            )
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ip_parsing() {
        let valid_ipv4 = "192.168.1.1";
        let valid_ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let invalid = "not-an-ip";
        
        assert!(valid_ipv4.parse::<std::net::IpAddr>().is_ok());
        assert!(valid_ipv6.parse::<std::net::IpAddr>().is_ok());
        assert!(invalid.parse::<std::net::IpAddr>().is_err());
    }
}
