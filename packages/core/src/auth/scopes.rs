use crate::AppState;

pub async fn cleanup_api_key_usage_worker(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
    
    loop {
        interval.tick().await;
        
        match sqlx::query!("SELECT cleanup_old_api_key_usage()")
            .execute(&state.db)
            .await
        {
            Ok(_) => {
                tracing::info!("Cleaned up old API key usage records");
            }
            Err(e) => {
                tracing::error!("❌ Failed to cleanup API key usage: {}", e);
            }
        }
        
    }
}
