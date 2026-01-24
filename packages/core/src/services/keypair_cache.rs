use crate::AppState;
use dashmap::DashMap;
use redis::AsyncCommands;
use solana_sdk::signature::Keypair;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Clone)]
pub struct KeypairCacheConfig {
    pub memory_ttl: Duration,
    pub redis_ttl: Duration,
    pub max_size: usize,
    pub enabled: bool,
}

impl Default for KeypairCacheConfig {
    fn default() -> Self {
        Self {
            memory_ttl: Duration::from_secs(5 * 60),
            redis_ttl: Duration::from_secs(15 * 60), 
            max_size: 1000,
            enabled: true,
        }
    }
}

impl KeypairCacheConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("KEYPAIR_CACHE_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        let memory_ttl_secs = std::env::var("KEYPAIR_CACHE_MEMORY_TTL")
            .unwrap_or_else(|_| "300".to_string())
            .parse()
            .unwrap_or(300);

        let redis_ttl_secs = std::env::var("KEYPAIR_CACHE_REDIS_TTL")
            .unwrap_or_else(|_| "900".to_string())
            .parse()
            .unwrap_or(900);

        let max_size = std::env::var("KEYPAIR_CACHE_MAX_SIZE")
            .unwrap_or_else(|_| "1000".to_string())
            .parse()
            .unwrap_or(1000);

        Self {
            memory_ttl: Duration::from_secs(memory_ttl_secs),
            redis_ttl: Duration::from_secs(redis_ttl_secs),
            max_size,
            enabled,
        }
    }
}

#[derive(Clone)]
struct CachedItem {
    data: Vec<u8>,
    cached_at: Instant,
    expires_at: Instant,
}

impl CachedItem {
    fn new(data: Vec<u8>, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            data,
            cached_at: now,
            expires_at: now + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

pub struct KeypairCache {
    cache: Arc<DashMap<String, CachedItem>>,
    config: KeypairCacheConfig,
    metrics: Arc<CacheMetrics>,
}

impl KeypairCache {
    pub fn new(config: KeypairCacheConfig) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            config,
            metrics: Arc::new(CacheMetrics::default()),
        }
    }

    pub fn get_keypair(&self, key: &str) -> Option<Keypair> {
        if !self.config.enabled {
            return None;
        }

        if let Some(entry) = self.cache.get(key) {
            if !entry.is_expired() {
                self.metrics.memory_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::debug!("Cache HIT (memory): {}", key);
                
                if entry.data.len() == 64 {
                    let mut bytes = [0u8; 64];
                    bytes.copy_from_slice(&entry.data);
                    return Keypair::try_from(&bytes[..]).ok();
                }
            } else {
                drop(entry);
                self.cache.remove(key);
                tracing::debug!("Cache EXPIRED (memory): {}", key);
            }
        }

        None
    }

    pub fn get_bytes(&self, key: &str) -> Option<Vec<u8>> {
        if !self.config.enabled {
            return None;
        }

        if let Some(entry) = self.cache.get(key) {
            if !entry.is_expired() {
                self.metrics.memory_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::debug!("Cache HIT (memory): {}", key);
                return Some(entry.data.clone());
            } else {
                drop(entry);
                self.cache.remove(key);
                tracing::debug!("Cache EXPIRED (memory): {}", key);
            }
        }

        None
    }

    pub fn insert_keypair(&self, key: String, keypair: Keypair, key_id: Uuid) {
        if !self.config.enabled {
            return;
        }
        self.insert_bytes(key, keypair.to_bytes().to_vec(), key_id);
    }

    pub fn insert_bytes(&self, key: String, data: Vec<u8>, _key_id: Uuid) {
        if !self.config.enabled {
            return;
        }

        if self.cache.len() >= self.config.max_size {
            self.evict_oldest();
        }

        let cached = CachedItem::new(data, self.config.memory_ttl);
        self.cache.insert(key.clone(), cached);
        tracing::debug!("Cached in memory: {}", key);
    }

    pub fn remove(&self, key: &str) {
        self.cache.remove(key);
        tracing::debug!("Removed from memory cache: {}", key);
    }

    fn evict_oldest(&self) {
        let mut oldest_key: Option<String> = None;
        let mut oldest_time = Instant::now();

        for entry in self.cache.iter() {
            if entry.value().cached_at < oldest_time {
                oldest_time = entry.value().cached_at;
                oldest_key = Some(entry.key().clone());
            }
        }

        if let Some(key) = oldest_key {
            self.cache.remove(&key);
            tracing::debug!("Evicted oldest entry: {}", key);
        }
    }

    pub fn metrics(&self) -> &CacheMetrics {
        &self.metrics
    }

    pub fn clear(&self) {
        self.cache.clear();
    }
}

#[derive(Default)]
pub struct CacheMetrics {
    pub memory_hits: std::sync::atomic::AtomicU64,
    pub redis_hits: std::sync::atomic::AtomicU64,
    pub lit_calls: std::sync::atomic::AtomicU64,
    pub total_requests: std::sync::atomic::AtomicU64,
}

impl CacheMetrics {
    pub fn hit_rate(&self) -> f64 {
        let total = self.total_requests.load(std::sync::atomic::Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }

        let hits = self.memory_hits.load(std::sync::atomic::Ordering::Relaxed)
            + self.redis_hits.load(std::sync::atomic::Ordering::Relaxed);
        (hits as f64 / total as f64) * 100.0
    }

    pub fn log_stats(&self) {
        let memory = self.memory_hits.load(std::sync::atomic::Ordering::Relaxed);
        let redis = self.redis_hits.load(std::sync::atomic::Ordering::Relaxed);
        let lit = self.lit_calls.load(std::sync::atomic::Ordering::Relaxed);
        let total = self.total_requests.load(std::sync::atomic::Ordering::Relaxed);

        tracing::info!(
            "📊 Keypair Cache Stats: {:.1}% hit rate ({} memory, {} redis, {} lit, {} total)",
            self.hit_rate(),
            memory,
            redis,
            lit,
            total,
        );
    }
}

pub fn cache_key(key_id: &Uuid, key_type: &str) -> String {
    format!("lit_keypair:{}:{}", key_type, key_id)
}

fn encrypt_bytes_for_redis(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let key_manager = crate::services::key_manager::SecureKeyManager::from_env()?;
    let (encrypted, nonce) = key_manager.encrypt_bytes(data)?;

    Ok(bincode::serialize(&(encrypted, nonce))?)
}

fn decrypt_bytes_from_redis(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let (encrypted, nonce): (Vec<u8>, Vec<u8>) = bincode::deserialize(data)?;
    let key_manager = crate::services::key_manager::SecureKeyManager::from_env()?;
    Ok(key_manager.decrypt_bytes(&encrypted, &nonce)?)
}

pub async fn get_keypair_from_redis(
    state: &AppState,
    key: &str,
) -> Result<Option<Keypair>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(bytes) = get_bytes_from_redis(state, key).await? {
        if bytes.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&bytes);
            return Ok(Some(Keypair::try_from(&arr[..])?));
        }
    }
    Ok(None)
}

pub async fn get_bytes_from_redis(
    state: &AppState,
    key: &str,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = state.redis.clone();
    
    let data: Option<Vec<u8>> = conn.get(key).await?;
    
    if let Some(data) = data {
        let decrypted = decrypt_bytes_from_redis(&data)?;
        tracing::debug!("Cache HIT (redis): {}", key);
        return Ok(Some(decrypted));
    }

    Ok(None)
}

pub async fn store_keypair_in_redis(
    state: &AppState,
    key: &str,
    keypair: &Keypair,
    ttl: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    store_bytes_in_redis(state, key, &keypair.to_bytes(), ttl).await
}

pub async fn store_bytes_in_redis(
    state: &AppState,
    key: &str,
    data: &[u8],
    ttl: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let encrypted = encrypt_bytes_for_redis(data)?;
    let mut conn = state.redis.clone();
    
    conn.set_ex::<_, _, ()>(key, encrypted, ttl.as_secs() as u64).await?;
    tracing::debug!("Cached in Redis: {} (TTL: {}s)", key, ttl.as_secs());
    
    Ok(())
}

pub async fn invalidate_keypair_cache(
    state: &AppState,
    key_id: Uuid,
    key_type: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let key = cache_key(&key_id, key_type);

    state.keypair_cache.remove(&key);

    let mut conn = state.redis.clone();
    let _: () = conn.del(&key).await?;

    tracing::info!("🗑️ Invalidated cache for {}", key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_format() {
        let key_id = Uuid::new_v4();
        let key = cache_key(&key_id, "autonomous_delegate");
        assert!(key.starts_with("lit_keypair:autonomous_delegate:"));
    }

    #[test]
    fn test_cached_keypair_expiry() {
        let keypair = Keypair::new();
        let key_id = Uuid::new_v4();
        let cached = CachedKeypair::new(keypair, key_id, Duration::from_millis(100));
        
        assert!(!cached.is_expired());
        std::thread::sleep(Duration::from_millis(150));
        assert!(cached.is_expired());
    }

    #[test]
    fn test_memory_cache_insert_get() {
        let config = KeypairCacheConfig::default();
        let cache = KeypairCache::new(config);
        
        let keypair = Keypair::new();
        let pubkey = keypair.pubkey();
        let key_id = Uuid::new_v4();
        
        cache.insert("test_key".to_string(), keypair, key_id);
        
        let cached = cache.get("test_key").expect("Cached keypair should be found");
        assert_eq!(cached.pubkey(), pubkey);
    }

    #[test]
    fn test_encrypt_decrypt_redis() {
        let keypair = Keypair::new();
        let pubkey = keypair.pubkey();
        
        let encrypted = encrypt_for_redis(&keypair).expect("Encryption should succeed");
        let decrypted = decrypt_from_redis(&encrypted).expect("Decryption should succeed");
        
        assert_eq!(decrypted.pubkey(), pubkey);
    }
}
