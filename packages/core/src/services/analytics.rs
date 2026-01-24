use axum::{
    extract::{Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    auth::AuthenticatedPlatform,
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    pub period_days: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct AgentStats {
    pub agent_id: String,
    pub agent_name: Option<String>,
    pub total_payments: i64,
    pub total_volume_usd: f64,
    pub avg_payment_size: f64,
    pub success_rate: f64,
}

#[derive(Debug, Serialize)]
pub struct AgentAnalyticsResponse {
    pub period_days: i32,
    pub total_ai_payments: i64,
    pub total_ai_volume_usd: f64,
    pub avg_payment_size: f64,
    pub by_agent: Vec<AgentStats>,
    pub payment_intents_created: i64,
    pub payment_intents_confirmed: i64,
    pub conversion_rate: f64,
}

pub async fn get_agent_analytics(
    State(state): State<AppState>,
    Extension(platform): Extension<AuthenticatedPlatform>,
    Query(query): Query<AnalyticsQuery>,
) -> Result<Json<AgentAnalyticsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let period_days = query.period_days.unwrap_or(30);
    
    let intent_stats = sqlx::query!(
        r#"
        SELECT 
            COUNT(*) as total_created,
            COUNT(CASE WHEN status = 'succeeded' THEN 1 END) as total_confirmed
        FROM payment_intents
        WHERE platform_id = $1
          AND created_at >= NOW() - INTERVAL '1 day' * $2
        "#,
        platform.platform_id,
        period_days as f64
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch intent stats: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to fetch analytics"}))
        )
    })?;
    
    let total_created = intent_stats.total_created.unwrap_or(0);
    let total_confirmed = intent_stats.total_confirmed.unwrap_or(0);
    let conversion_rate = if total_created > 0 {
        (total_confirmed as f64 / total_created as f64) * 100.0
    } else {
        0.0
    };
    
    let ai_payment_stats = sqlx::query!(
        r#"
        SELECT 
            COUNT(p.id) as total_payments,
            COALESCE(SUM(p.amount_usd), 0) as total_volume
        FROM payments p
        INNER JOIN payment_intents pi ON p.id = pi.payment_id
        WHERE pi.platform_id = $1
          AND pi.created_at >= NOW() - INTERVAL '1 day' * $2
          AND p.status = 'confirmed'
        "#,
        platform.platform_id,
        period_days as f64
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch AI payment stats: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to fetch analytics"}))
        )
    })?;
    
    let total_ai_payments = ai_payment_stats.total_payments.unwrap_or(0);
    let total_volume = ai_payment_stats.total_volume
        .and_then(|v| v.to_string().parse::<f64>().ok())
        .unwrap_or(0.0);
    
    let avg_payment_size = if total_ai_payments > 0 {
        total_volume / total_ai_payments as f64
    } else {
        0.0
    };
    
    let agent_breakdown = sqlx::query!(
        r#"
        SELECT 
            pi.agent_id,
            pi.agent_name,
            COUNT(p.id) as payment_count,
            COALESCE(SUM(p.amount_usd), 0) as total_volume,
            COUNT(CASE WHEN p.status = 'confirmed' THEN 1 END) as successful_payments
        FROM payment_intents pi
        LEFT JOIN payments p ON p.id = pi.payment_id
        WHERE pi.platform_id = $1
          AND pi.created_at >= NOW() - INTERVAL '1 day' * $2
          AND pi.agent_id IS NOT NULL
        GROUP BY pi.agent_id, pi.agent_name
        ORDER BY total_volume DESC
        "#,
        platform.platform_id,
        period_days as f64
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch agent breakdown: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to fetch analytics"}))
        )
    })?;
    
    let by_agent: Vec<AgentStats> = agent_breakdown
        .into_iter()
        .map(|row| {
            let payment_count = row.payment_count.unwrap_or(0);
            let volume = row.total_volume
                .and_then(|v| v.to_string().parse::<f64>().ok())
                .unwrap_or(0.0);
            let successful = row.successful_payments.unwrap_or(0);
            
            AgentStats {
                agent_id: row.agent_id.unwrap_or_else(|| "unknown".to_string()),
                agent_name: row.agent_name,
                total_payments: payment_count,
                total_volume_usd: volume,
                avg_payment_size: if payment_count > 0 { volume / payment_count as f64 } else { 0.0 },
                success_rate: if payment_count > 0 {
                    (successful as f64 / payment_count as f64) * 100.0
                } else {
                    0.0
                },
            }
        })
        .collect();
    
    Ok(Json(AgentAnalyticsResponse {
        period_days,
        total_ai_payments,
        total_ai_volume_usd: total_volume,
        avg_payment_size,
        by_agent,
        payment_intents_created: total_created,
        payment_intents_confirmed: total_confirmed,
        conversion_rate,
    }))
}
