use uuid::Uuid;
use sqlx::PgPool;
use bigdecimal::{BigDecimal, FromPrimitive};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use crate::AppState;

/// Record gas cost for a transaction. This is an optional analytics function
/// that platform operators can call after transactions to track gas spending.
#[allow(dead_code)]
pub async fn record_gas_cost(
    db: &PgPool,
    payment_id: Option<Uuid>,
    transaction_signature: &str,
    transaction_type: &str,
    gas_cost_lamports: u64,
    sol_price_usd: f64,
    network: &str,
    compute_units_used: Option<i32>,
    priority_fee_lamports: Option<i64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let gas_cost_sol = gas_cost_lamports as f64 / 1_000_000_000.0;
    let gas_cost_usd = gas_cost_sol * sol_price_usd;
    
    let priority_fee = priority_fee_lamports.unwrap_or(0);
    
    sqlx::query!(
        r#"
        INSERT INTO gas_fee_costs (
            payment_id, transaction_signature, transaction_type,
            gas_cost_lamports, gas_cost_sol, gas_cost_usd, sol_price_at_time,
            fee_payer, network, compute_units_used, priority_fee_lamports, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
        "#,
        payment_id,
        transaction_signature,
        transaction_type,
        gas_cost_lamports as i64,
        BigDecimal::from_f64(gas_cost_sol)
            .ok_or("Failed to convert gas_cost_sol to BigDecimal")?,
        BigDecimal::from_f64(gas_cost_usd)
            .ok_or("Failed to convert gas_cost_usd to BigDecimal")?,
        BigDecimal::from_f64(sol_price_usd)
            .ok_or("Failed to convert sol_price_usd to BigDecimal")?,
        "platform",
        network,
        compute_units_used,
        priority_fee,
    )
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to record gas cost for tx {}: {}", transaction_signature, e);
        format!("Database error recording gas cost: {}", e)
    })?;
    
    tracing::debug!(
        "Recorded gas cost: {} lamports (${:.6} USD) for {} transaction {}",
        gas_cost_lamports,
        gas_cost_usd,
        transaction_type,
        transaction_signature
    );
    
    Ok(())
}

pub async fn get_gas_cost_analytics(
    db: &PgPool,
    network: &str,
    days: i32,
) -> Result<Vec<GasCostAnalytics>, Box<dyn std::error::Error + Send + Sync>> {
    let analytics = sqlx::query_as!(
        GasCostAnalytics,
        r#"
        SELECT 
            date,
            network,
            transaction_type,
            transaction_count::bigint as "transaction_count!",
            avg_gas_usd::numeric as "avg_gas_usd!",
            min_gas_usd::numeric as "min_gas_usd!",
            max_gas_usd::numeric as "max_gas_usd!",
            total_gas_usd::numeric as "total_gas_usd!",
            avg_compute_units::numeric as "avg_compute_units",
            avg_priority_fee::numeric as "avg_priority_fee"
        FROM gas_cost_analytics
        WHERE network = $1
        AND date >= CURRENT_DATE - $2::integer
        ORDER BY date DESC, transaction_type
        "#,
        network,
        days
    )
    .fetch_all(db)
    .await?;
    
    Ok(analytics)
}

pub async fn check_gas_profitability(
    db: &PgPool,
    network: &str,
    days: i32,
) -> Result<Vec<GasProfitabilityCheck>, Box<dyn std::error::Error + Send + Sync>> {
    let profitability = sqlx::query_as!(
        GasProfitabilityCheck,
        r#"
        SELECT 
            date,
            network,
            transaction_count::bigint as "transaction_count!",
            avg_gas_cost::numeric as "avg_gas_cost!",
            avg_fee_margin::numeric as "avg_fee_margin!",
            profitable_percentage::numeric as "profitable_percentage!",
            total_gas_spent::numeric as "total_gas_spent!",
            total_fee_margin::numeric as "total_fee_margin!",
            net_margin::numeric as "net_margin!"
        FROM gas_profitability_check
        WHERE network = $1
        AND date >= CURRENT_DATE - $2::integer
        ORDER BY date DESC
        "#,
        network,
        days
    )
    .fetch_all(db)
    .await?;
    
    Ok(profitability)
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct GasCostAnalytics {
    pub date: Option<chrono::NaiveDate>,
    pub network: Option<String>,
    pub transaction_type: Option<String>,
    pub transaction_count: i64,
    pub avg_gas_usd: BigDecimal,
    pub min_gas_usd: BigDecimal,
    pub max_gas_usd: BigDecimal,
    pub total_gas_usd: BigDecimal,
    pub avg_compute_units: Option<BigDecimal>,
    pub avg_priority_fee: Option<BigDecimal>,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
pub struct GasProfitabilityCheck {
    pub date: Option<chrono::NaiveDate>,
    pub network: Option<String>,
    pub transaction_count: i64,
    pub avg_gas_cost: BigDecimal,
    pub avg_fee_margin: BigDecimal,
    pub profitable_percentage: BigDecimal,
    pub total_gas_spent: BigDecimal,
    pub total_fee_margin: BigDecimal,
    pub net_margin: BigDecimal,
}

#[derive(Debug, Deserialize)]
pub struct GasAnalyticsQuery {
    pub network: Option<String>,
    pub days: Option<i32>,
}

pub async fn get_gas_analytics_handler(
    State(state): State<AppState>,
    Query(query): Query<GasAnalyticsQuery>,
) -> Result<Json<Vec<GasCostAnalytics>>, (StatusCode, Json<serde_json::Value>)> {
    let network = query.network.as_deref().unwrap_or("devnet");
    let days = query.days.unwrap_or(7);
    
    get_gas_cost_analytics(&state.db, network, days)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("Failed to get gas analytics: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to fetch gas analytics"
                }))
            )
        })
}

pub async fn get_gas_profitability_handler(
    State(state): State<AppState>,
    Query(query): Query<GasAnalyticsQuery>,
) -> Result<Json<Vec<GasProfitabilityCheck>>, (StatusCode, Json<serde_json::Value>)> {
    let network = query.network.as_deref().unwrap_or("devnet");
    let days = query.days.unwrap_or(7);
    
    check_gas_profitability(&state.db, network, days)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("Failed to get gas profitability: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to fetch gas profitability"
                }))
            )
        })
}
