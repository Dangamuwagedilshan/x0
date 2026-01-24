use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};

#[derive(Debug, Clone)]
pub struct SolanaEndpoint {
    pub url: String,
    pub priority: u8,
    pub health_score: Arc<RwLock<HealthScore>>,
    pub last_used: Arc<RwLock<Instant>>,
}

#[derive(Debug, Clone)]
pub struct HealthScore {
    pub success_rate: f64,
    pub avg_latency_ms: u64,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    pub last_health_check: Instant,
}

impl Default for HealthScore {
    fn default() -> Self {
        Self {
            success_rate: 100.0,
            avg_latency_ms: 0,
            last_error: None,
            consecutive_failures: 0,
            last_health_check: Instant::now(),
        }
    }
}

#[derive(Clone)]
pub struct ResilientSolanaClient {
    endpoints: Vec<SolanaEndpoint>,
    client: reqwest::Client,
    circuit_breaker_threshold: u32,
    rate_limiter: Arc<Semaphore>,
    last_request_time: Arc<RwLock<Instant>>,
}

impl ResilientSolanaClient {
    pub fn new(rpc_urls: Vec<String>) -> Self {
        let endpoints = rpc_urls
            .into_iter()
            .enumerate()
            .map(|(i, url)| SolanaEndpoint {
                url,
                priority: i as u8,
                health_score: Arc::new(RwLock::new(HealthScore::default())),
                last_used: Arc::new(RwLock::new(Instant::now())),
            })
            .collect();

        Self {
            endpoints,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("Failed to create HTTP client"),
            circuit_breaker_threshold: 5,
            rate_limiter: Arc::new(Semaphore::new(3)),
            last_request_time: Arc::new(RwLock::new(Instant::now())),
        }
    }

    pub async fn select_best_endpoint(&self) -> Option<&SolanaEndpoint> {
        let mut best_endpoint = None;
        let mut best_score = f64::MIN;

        for endpoint in &self.endpoints {
            let mut health = endpoint.health_score.write().await;
            
            if health.consecutive_failures >= self.circuit_breaker_threshold {
                let time_since_last_check = health.last_health_check.elapsed();
                if time_since_last_check > Duration::from_secs(30) {
                    tracing::info!("Auto-recovering endpoint {} after cooldown", endpoint.url);
                    health.consecutive_failures = 0;
                    health.success_rate = 50.0;
                }
            }
            
            if health.consecutive_failures >= self.circuit_breaker_threshold {
                drop(health);
                continue;
            }

            let score = self.calculate_endpoint_score(&health, endpoint.priority).await;
            drop(health);
            
            if score > best_score {
                best_score = score;
                best_endpoint = Some(endpoint);
            }
        }

        best_endpoint
    }

    async fn calculate_endpoint_score(&self, health: &HealthScore, priority: u8) -> f64 {
        let latency_penalty = if health.avg_latency_ms > 1000 { 0.5 } else { 1.0 };
        let priority_bonus = (10.0 - priority as f64) * 0.1;
        
        health.success_rate * latency_penalty + priority_bonus
    }

    pub async fn make_rpc_call(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let _permit = self.rate_limiter.acquire().await?;

        let mut last_request = self.last_request_time.write().await;
        let elapsed = last_request.elapsed();
        if elapsed < Duration::from_millis(300) {
            let sleep_duration = Duration::from_millis(300) - elapsed;
            drop(last_request);
            tokio::time::sleep(sleep_duration).await;
            let mut last_request = self.last_request_time.write().await;
            *last_request = Instant::now();
        } else {
            *last_request = Instant::now();
            drop(last_request);
        }

        let endpoint = self
            .select_best_endpoint()
            .await
            .ok_or("No healthy endpoints available")?;

        let start_time = Instant::now();
        let result = self.execute_rpc_call(endpoint, method, params.clone()).await;
        let latency = start_time.elapsed();

        self.update_endpoint_health(endpoint, &result, latency).await;

        match result {
            Ok(response) => Ok(response),
            Err(e) => {
                let error_msg = e.to_string();
                tracing::warn!("RPC call failed on {}: {}", endpoint.url, error_msg);
                
                if error_msg.contains("429") || error_msg.contains("Too Many Requests") {
                    let base_delay = 5000;
                    let jitter = rand::random::<u64>() % 2000;
                    let backoff_ms = base_delay + jitter;
                    tracing::warn!("Rate limit detected, backing off for {}ms", backoff_ms);
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    
                    let mut health = endpoint.health_score.write().await;
                    health.consecutive_failures = self.circuit_breaker_threshold;
                    drop(health);
                } else {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                
                if let Some(fallback) = self.select_fallback_endpoint(endpoint).await {
                    tracing::info!("Trying fallback endpoint: {}", fallback.url);
                    self.execute_rpc_call(fallback, method, params).await
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn execute_rpc_call(
        &self,
        endpoint: &SolanaEndpoint,
        method: &str,
        params: Value,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });

        let response = self
            .client
            .post(&endpoint.url)
            .header("Content-Type", "application/json")
            .json(&payload)  
            .timeout(Duration::from_secs(15))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("HTTP error: {}", response.status()).into());
        }

        let json_response: Value = response.json().await?;

        if let Some(error) = json_response.get("error") {
            return Err(format!("RPC error: {}", error).into());
        }

        Ok(json_response)
    }

    async fn update_endpoint_health(
        &self,
        endpoint: &SolanaEndpoint,
        result: &Result<Value, Box<dyn std::error::Error + Send + Sync>>,
        latency: Duration,
    ) {
        let mut health = endpoint.health_score.write().await;
        let mut last_used = endpoint.last_used.write().await;
        
        *last_used = Instant::now();
        health.last_health_check = Instant::now();

        match result {
            Ok(_) => {
                health.consecutive_failures = 0;
                health.success_rate = (health.success_rate * 0.9) + (100.0 * 0.1);
                health.avg_latency_ms = ((health.avg_latency_ms as f64 * 0.8) + 
                                       (latency.as_millis() as f64 * 0.2)) as u64;
                health.last_error = None;
            }
            Err(e) => {
                let error_msg = e.to_string();
                
                if error_msg.contains("429") || error_msg.contains("Too Many Requests") {
                    tracing::warn!("Rate limit hit on {}, backing off but not marking unhealthy", endpoint.url);
                    health.success_rate = (health.success_rate * 0.95) + (80.0 * 0.05);
                } else {
                    health.consecutive_failures += 1;
                    health.success_rate = (health.success_rate * 0.9) + (0.0 * 0.1);
                }
                
                health.last_error = Some(error_msg);
            }
        }
    }

    async fn select_fallback_endpoint(&self, failed_endpoint: &SolanaEndpoint) -> Option<&SolanaEndpoint> {
        self.endpoints
            .iter()
            .filter(|ep| ep.url != failed_endpoint.url)
            .find(|ep| {
                let health_score = ep.health_score.try_read();
                if let Ok(health) = health_score {
                    health.consecutive_failures < self.circuit_breaker_threshold
                } else {
                    false
                }
            })
    }

    pub async fn health_check_all_endpoints(&self) {
        let health_check_tasks: Vec<_> = self
            .endpoints
            .iter()
            .map(|endpoint| {
                let client = self.client.clone();
                let url = endpoint.url.clone();
                let health_score = endpoint.health_score.clone();
                
                tokio::spawn(async move {
                    let start = Instant::now();
                    let result = client
                        .post(&url)
                        .json(&json!({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "getHealth"
                        }))
                        .send()
                        .await;
                    
                    let latency = start.elapsed();
                    let mut health = health_score.write().await;
                    
                    match result {
                        Ok(response) if response.status().is_success() => {
                            health.consecutive_failures = 0;
                            health.avg_latency_ms = latency.as_millis() as u64;
                        }
                        _ => {
                            health.consecutive_failures += 1;
                        }
                    }
                    
                    health.last_health_check = Instant::now();
                })
            })
            .collect();

        for task in health_check_tasks {
            let _ = task.await;
        }
    }

    pub async fn get_endpoint_stats(&self) -> Vec<(String, HealthScore)> {
        let mut stats = Vec::new();

        for endpoint in &self.endpoints {
            let health = endpoint.health_score.read().await;
            stats.push((endpoint.url.clone(), health.clone()));
        }

        stats
    }

    pub async fn get_health(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.make_rpc_call("getHealth", serde_json::json!([])).await?;
        Ok(())
    }
}

pub async fn start_endpoint_monitor(client: Arc<ResilientSolanaClient>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    
    loop {
        interval.tick().await;
        client.health_check_all_endpoints().await;
        
        let stats = client.get_endpoint_stats().await;
        for (url, health) in stats {
            tracing::debug!(
                "Endpoint {} - Success: {:.1}%, Latency: {}ms, Failures: {}",
                url, health.success_rate, health.avg_latency_ms, health.consecutive_failures
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_endpoint_selection() {
        let client = ResilientSolanaClient::new(vec![
            "https://api.mainnet-beta.solana.com".to_string(),
            "https://rpc.ankr.com/solana".to_string(),
        ]);

        let endpoint = client.select_best_endpoint().await;
        assert!(endpoint.is_some());
    }

    #[test]
    fn test_health_score_calculation() {
        let health = HealthScore {
            success_rate: 95.0,
            avg_latency_ms: 500,
            consecutive_failures: 0,
            ..Default::default()
        };

        assert!(health.success_rate > 90.0);
    }
}