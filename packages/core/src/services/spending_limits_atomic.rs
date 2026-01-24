use crate::AppState;
use axum::http::StatusCode;
use axum::Json;
use bigdecimal::{BigDecimal, FromPrimitive, ToPrimitive};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug)]
pub enum SpendingError {
    SessionNotFound,
    SessionInactive,
    SessionExpired,
    PerTransactionLimitExceeded { limit: f64, requested: f64 },
    DailyLimitExceeded { spent: f64, limit: f64, requested: f64 },
    WeeklyLimitExceeded { spent: f64, limit: f64, requested: f64 },
    MonthlyLimitExceeded { spent: f64, limit: f64, requested: f64 },
    DatabaseError(String),
}

impl std::fmt::Display for SpendingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionNotFound => write!(f, "Session not found"),
            Self::SessionInactive => write!(f, "Session is inactive"),
            Self::SessionExpired => write!(f, "Session has expired"),
            Self::PerTransactionLimitExceeded { limit, requested } => {
                write!(f, "Transaction amount ${:.2} exceeds per-transaction limit of ${:.2}", requested, limit)
            }
            Self::DailyLimitExceeded { spent, limit, requested } => {
                write!(f, "Would exceed daily limit: ${:.2} spent + ${:.2} requested > ${:.2} limit", spent, requested, limit)
            }
            Self::WeeklyLimitExceeded { spent, limit, requested } => {
                write!(f, "Would exceed weekly limit: ${:.2} spent + ${:.2} requested > ${:.2} limit", spent, requested, limit)
            }
            Self::MonthlyLimitExceeded { spent, limit, requested } => {
                write!(f, "Would exceed monthly limit: ${:.2} spent + ${:.2} requested > ${:.2} limit", spent, requested, limit)
            }
            Self::DatabaseError(e) => write!(f, "Database error: {}", e),
        }
    }
}

impl std::error::Error for SpendingError {}

pub async fn check_and_record_spend_atomic(
    state: &AppState,
    session_id: Uuid,
    amount_usd: f64,
) -> Result<(), SpendingError> {
    let mut tx = state.db.begin()
        .await
        .map_err(|e| SpendingError::DatabaseError(e.to_string()))?;
    
    tracing::debug!(
        "🔒 Acquiring row lock for session {} to check ${:.2} spend",
        session_id,
        amount_usd
    );
    
    let session = sqlx::query!(
        r#"
        SELECT 
            id,
            is_active,
            expires_at,
            max_per_transaction,
            max_per_day,
            max_per_week,
            max_per_month,
            spent_today,
            spent_this_week,
            spent_this_month
        FROM ai_agent_sessions
        WHERE id = $1
        FOR UPDATE  -- 🔐 CRITICAL: Locks row until transaction commits
        "#,
        session_id
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| SpendingError::DatabaseError(e.to_string()))?
    .ok_or(SpendingError::SessionNotFound)?;
    
    if !session.is_active.unwrap_or(false) {
        tx.rollback().await.ok();
        return Err(SpendingError::SessionInactive);
    }
    
    if session.expires_at < chrono::Utc::now() {
        tx.rollback().await.ok();
        return Err(SpendingError::SessionExpired);
    }
    
    let limit_per_tx = session.max_per_transaction
        .and_then(|v| v.to_f64())
        .unwrap_or(f64::MAX);
    
    let limit_daily = session.max_per_day
        .and_then(|v| v.to_f64())
        .unwrap_or(f64::MAX);
    
    let limit_weekly = session.max_per_week
        .and_then(|v| v.to_f64());
    
    let limit_monthly = session.max_per_month
        .and_then(|v| v.to_f64());
    
    let spent_today = session.spent_today
        .and_then(|v| v.to_f64())
        .unwrap_or(0.0);
    
    let spent_this_week = session.spent_this_week
        .and_then(|v| v.to_f64())
        .unwrap_or(0.0);
    
    let spent_this_month = session.spent_this_month
        .and_then(|v| v.to_f64())
        .unwrap_or(0.0);
    
    if amount_usd > limit_per_tx {
        tx.rollback().await.ok();
        tracing::warn!(
            "❌ Per-transaction limit exceeded: ${:.2} > ${:.2}",
            amount_usd,
            limit_per_tx
        );
        return Err(SpendingError::PerTransactionLimitExceeded {
            limit: limit_per_tx,
            requested: amount_usd,
        });
    }
    
    if spent_today + amount_usd > limit_daily {
        tx.rollback().await.ok();
        tracing::warn!(
            "❌ Daily limit exceeded: ${:.2} spent + ${:.2} requested > ${:.2} limit",
            spent_today,
            amount_usd,
            limit_daily
        );
        return Err(SpendingError::DailyLimitExceeded {
            spent: spent_today,
            limit: limit_daily,
            requested: amount_usd,
        });
    }
    
    if let Some(limit_week) = limit_weekly {
        if spent_this_week + amount_usd > limit_week {
            tx.rollback().await.ok();
            tracing::warn!(
                "❌ Weekly limit exceeded: ${:.2} spent + ${:.2} requested > ${:.2} limit",
                spent_this_week,
                amount_usd,
                limit_week
            );
            return Err(SpendingError::WeeklyLimitExceeded {
                spent: spent_this_week,
                limit: limit_week,
                requested: amount_usd,
            });
        }
    }
    
    if let Some(limit_month) = limit_monthly {
        if spent_this_month + amount_usd > limit_month {
            tx.rollback().await.ok();
            tracing::warn!(
                "❌ Monthly limit exceeded: ${:.2} spent + ${:.2} requested > ${:.2} limit",
                spent_this_month,
                amount_usd,
                limit_month
            );
            return Err(SpendingError::MonthlyLimitExceeded {
                spent: spent_this_month,
                limit: limit_month,
                requested: amount_usd,
            });
        }
    }
    
    let amount_bd = BigDecimal::from_f64(amount_usd)
        .ok_or_else(|| SpendingError::DatabaseError("Invalid amount".to_string()))?;
    
    sqlx::query!(
        r#"
        UPDATE ai_agent_sessions
        SET 
            spent_today = COALESCE(spent_today, 0) + $2,
            spent_this_week = COALESCE(spent_this_week, 0) + $2,
            spent_this_month = COALESCE(spent_this_month, 0) + $2,
            last_used_at = NOW()
        WHERE id = $1
        "#,
        session_id,
        amount_bd
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| SpendingError::DatabaseError(e.to_string()))?;
    
    tx.commit()
        .await
        .map_err(|e| SpendingError::DatabaseError(e.to_string()))?;
    
    tracing::debug!(
        "Spend recorded atomically: session {} charged ${:.2} (new daily total: ${:.2})",
        session_id,
        amount_usd,
        spent_today + amount_usd
    );
    
    Ok(())
}

#[allow(dead_code)] // SDK utility for error handling
pub fn spending_error_to_response(
    error: SpendingError,
) -> (StatusCode, Json<serde_json::Value>) {
    let (status, message) = match error {
        SpendingError::SessionNotFound => (
            StatusCode::NOT_FOUND,
            "Session not found".to_string(),
        ),
        SpendingError::SessionInactive | SpendingError::SessionExpired => (
            StatusCode::FORBIDDEN,
            error.to_string(),
        ),
        SpendingError::PerTransactionLimitExceeded { .. }
        | SpendingError::DailyLimitExceeded { .. }
        | SpendingError::WeeklyLimitExceeded { .. }
        | SpendingError::MonthlyLimitExceeded { .. } => (
            StatusCode::PAYMENT_REQUIRED,
            error.to_string(),
        ),
        SpendingError::DatabaseError(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error".to_string(),
        ),
    };
    
    (
        status,
        Json(json!({
            "error": message,
            "code": "SPENDING_LIMIT_EXCEEDED"
        })),
    )
}