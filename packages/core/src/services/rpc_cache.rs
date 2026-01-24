use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct CachedValue {
    pub data: Value,
    pub cached_at: Instant,
    pub ttl: Duration,
}

impl CachedValue {
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }
}

#[derive(Clone)]
pub struct RpcCache {
    cache: Arc<RwLock<HashMap<String, CachedValue>>>,
}

impl RpcCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get(&self, key: &str) -> Option<Value> {
        let cache = self.cache.read().await;
        if let Some(cached) = cache.get(key) {
            if !cached.is_expired() {
                tracing::debug!("Cache HIT for key: {}", key);
                return Some(cached.data.clone());
            } else {
                tracing::debug!("Cache EXPIRED for key: {}", key);
            }
        } else {
            tracing::debug!("Cache MISS for key: {}", key);
        }
        None
    }

    pub async fn set(&self, key: String, value: Value, ttl: Duration) {
        let mut cache = self.cache.write().await;
        cache.insert(
            key,
            CachedValue {
                data: value,
                cached_at: Instant::now(),
                ttl,
            },
        );
    }

    pub async fn invalidate(&self, key: &str) {
        let mut cache = self.cache.write().await;
        cache.remove(key);
        tracing::debug!("Cache INVALIDATE for key: {}", key);
    }

    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        tracing::info!("Cache cleared");
    }

    pub async fn cleanup_expired(&self) {
        let mut cache = self.cache.write().await;
        let before_count = cache.len();
        cache.retain(|_, v| !v.is_expired());
        let after_count = cache.len();
        if before_count > after_count {
            tracing::debug!("Cleaned up {} expired cache entries", before_count - after_count);
        }
    }
}

pub async fn start_cache_cleanup(cache: Arc<RpcCache>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    
    loop {
        interval.tick().await;
        cache.cleanup_expired().await;
    }
}
