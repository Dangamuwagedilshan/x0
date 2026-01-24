use sqlx::PgPool;
use redis::aio::ConnectionManager;

pub async fn initialize_database(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(50)  
        .min_connections(5)  
        .acquire_timeout(std::time::Duration::from_secs(30))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(3600))
        .connect(database_url)
        .await?;

    sqlx::query("SELECT 1").execute(&pool).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    
    tracing::info!("Database initialized successfully with {} max connections", 50);
    Ok(pool)
}

pub async fn create_redis_connection(redis_url: &str) -> Result<ConnectionManager, redis::RedisError> {
    let client = redis::Client::open(redis_url)?;
    let manager = ConnectionManager::new(client).await?;
    tracing::info!("Redis connection established");
    Ok(manager)
}

