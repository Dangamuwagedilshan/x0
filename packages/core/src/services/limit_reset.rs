use crate::AppState;
use tokio::time::{interval, Duration};
use chrono::{Utc, Datelike};

pub async fn start_spending_limit_reset_job(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(5 * 60));
        
        let mut last_daily_reset = Utc::now().date_naive();
        let mut last_weekly_reset = Utc::now().iso_week();
        let mut last_monthly_reset = (Utc::now().year(), Utc::now().month());
        
        tracing::info!(
            "🕐 Spending limit reset job started (checks every 5 minutes)"
        );
        
        loop {
            ticker.tick().await;
            
            let now = Utc::now();
            let current_date = now.date_naive();
            let current_week = now.iso_week();
            let current_month = (now.year(), now.month());
            
            if current_date != last_daily_reset {
                tracing::info!(
                    "🔄 Running daily spending limit reset (date changed: {} -> {})",
                    last_daily_reset,
                    current_date
                );
                
                match sqlx::query!("SELECT reset_ai_session_daily_limits()")
                    .execute(&state.db)
                    .await
                {
                    Ok(result) => {
                        tracing::info!(
                            "Daily spending limits reset successfully ({} sessions affected)",
                            result.rows_affected()
                        );
                        last_daily_reset = current_date;
                        
                        if let Err(e) = log_reset_event(&state, "daily").await {
                            tracing::warn!("Failed to log reset event: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("❌ Daily spending reset failed: {}", e);
                    }
                }
            }
            
            if current_week != last_weekly_reset {
                tracing::info!(
                    "🔄 Running weekly spending limit reset (week changed: {:?} -> {:?})",
                    last_weekly_reset,
                    current_week
                );
                
                match sqlx::query!("SELECT reset_ai_session_weekly_limits()")
                    .execute(&state.db)
                    .await
                {
                    Ok(result) => {
                        tracing::info!(
                            "Weekly spending limits reset successfully ({} sessions affected)",
                            result.rows_affected()
                        );
                        last_weekly_reset = current_week;
                        
                        if let Err(e) = log_reset_event(&state, "weekly").await {
                            tracing::warn!("Failed to log reset event: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("❌ Weekly spending reset failed: {}", e);
                    }
                }
            }
            
            if current_month != last_monthly_reset {
                tracing::info!(
                    "🔄 Running monthly spending limit reset (month changed: {:?} -> {:?})",
                    last_monthly_reset,
                    current_month
                );
                
                match sqlx::query!("SELECT reset_ai_session_monthly_limits()")
                    .execute(&state.db)
                    .await
                {
                    Ok(result) => {
                        tracing::info!(
                            "Monthly spending limits reset successfully ({} sessions affected)",
                            result.rows_affected()
                        );
                        last_monthly_reset = current_month;
                        
                        if let Err(e) = log_reset_event(&state, "monthly").await {
                            tracing::warn!("Failed to log reset event: {}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!("❌ Monthly spending reset failed: {}", e);
                    }
                }
            }
        }
    });
}

async fn log_reset_event(
    state: &AppState,
    reset_type: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO system_events (event_type, event_data, created_at)
        VALUES ($1, $2, NOW())
        "#,
        format!("spending_limit_reset_{}", reset_type),
        serde_json::json!({
            "reset_type": reset_type,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        })
    )
    .execute(&state.db)
    .await?;
    
    Ok(())
}
