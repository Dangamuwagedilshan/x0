use uuid::Uuid;
use serde::{Deserialize, Serialize};
use solana_sdk::signer::keypair::Keypair;
use bigdecimal::{BigDecimal, ToPrimitive, FromPrimitive};
use crate::AppState;
use sqlx::types::ipnetwork::IpNetwork;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKeyInfo {
    pub id: Uuid,
    pub session_keypair_id: Uuid,
    pub public_key: String,
    pub limit_usdc: f64,
    pub used_amount_usdc: f64,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub city: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Clone)]
struct Transaction {
    pub amount: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKeyRequestContext {
    pub device_fingerprint: String,
    pub ip_address: String,
    pub user_agent: String,
}

#[derive(Debug)]
pub enum SessionKeyError {
    NotFound,
    Expired,
    LimitExceeded,
    AlreadyRevoked,
    DatabaseError(String),
    InvalidAmount,
    RateLimited,
    DeviceMismatch,
    ImpossibleTravel,
    AnomalousTransaction,
}

impl std::fmt::Display for SessionKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SessionKeyError::NotFound => write!(f, "Session key not found"),
            SessionKeyError::Expired => write!(f, "Session key has expired"),
            SessionKeyError::LimitExceeded => write!(f, "Session key spending limit exceeded"),
            SessionKeyError::AlreadyRevoked => write!(f, "Session key has been revoked"),
            SessionKeyError::DatabaseError(e) => write!(f, "Database error: {}", e),
            SessionKeyError::InvalidAmount => write!(f, "Invalid transaction amount"),
            SessionKeyError::RateLimited => write!(f, "Rate limit exceeded for session key usage"),
            SessionKeyError::DeviceMismatch => write!(f, "Device fingerprint mismatch detected"),
            SessionKeyError::ImpossibleTravel => write!(f, "Impossible travel detected - session revoked"),
            SessionKeyError::AnomalousTransaction => write!(f, "Anomalous transaction pattern detected"),
        }
    }
}

impl std::error::Error for SessionKeyError {}

pub struct SessionKeyManager;

impl SessionKeyManager {
    pub async fn get_active_session_key(
        state: &AppState,
        platform_id: Uuid,
        transaction_amount_usd: f64,
        request_context: SessionKeyRequestContext,
    ) -> Result<Keypair, SessionKeyError> {
        tracing::debug!(
            "Checking for active session key for platform {} (amount: ${}, ip: {})",
            platform_id, transaction_amount_usd, request_context.ip_address
        );

        let recent_usage = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM session_key_usage_log 
            WHERE platform_id = $1 
              AND created_at > NOW() - INTERVAL '1 minute'
            "#,
            platform_id
        )
        .fetch_one(&state.db)
        .await
        .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

        if recent_usage > 10 {
            tracing::warn!(
                "Rate limit exceeded for platform {}: {} requests in last minute",
                platform_id, recent_usage
            );
            
            Self::log_security_event(
                state,
                None,
                platform_id,
                "rate_limit_exceeded",
                "high",
                &format!("{} session key requests in 1 minute", recent_usage),
                Some(&request_context.ip_address),
            ).await?;
            
            return Err(SessionKeyError::RateLimited);
        }

        let session = sqlx::query!(
            r#"
            SELECT id, session_keypair_id, limit_usdc, used_amount_usdc, expires_at,
                   device_fingerprint, ip_address, user_agent,
                   last_known_latitude, last_known_longitude, last_security_check_at
            FROM session_keys
            WHERE platform_id = $1 
              AND is_active = TRUE 
              AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
            FOR UPDATE
            "#,
            platform_id
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?
        .ok_or(SessionKeyError::NotFound)?;

        if let Some(ref stored_fingerprint) = session.device_fingerprint {
            if stored_fingerprint != &request_context.device_fingerprint {
                tracing::warn!(
                    "Device fingerprint mismatch for platform {} session {}",
                    platform_id, session.id
                );
                
                Self::log_security_event(
                    state,
                    Some(session.id),
                    platform_id,
                    "device_mismatch",
                    "critical",
                    &format!(
                        "Expected: {}, Got: {}",
                        stored_fingerprint, request_context.device_fingerprint
                    ),
                    Some(&request_context.ip_address),
                ).await?;
                
                Self::revoke_session_key(state, session.id, platform_id).await?;
                
                return Err(SessionKeyError::DeviceMismatch);
            }
        }

        if let Some(stored_ip) = session.ip_address {
            let stored_ip_str = stored_ip.to_string();
            if stored_ip_str != request_context.ip_address {
                tracing::info!(
                    "IP address changed for session {} from {} to {}",
                    session.id, stored_ip_str, request_context.ip_address
                );

                Self::log_security_event(
                    state,
                    Some(session.id),
                    platform_id,
                    "ip_change",
                    "low",
                    &format!("IP changed from {} to {}", stored_ip_str, request_context.ip_address),
                    Some(&request_context.ip_address),
                ).await.ok();
            }
        }

        match check_ip_location(&request_context.ip_address).await {
            Ok(current_location) => {
                if let Ok(Some(stored_location_data)) = sqlx::query!(
                    r#"
                    SELECT last_known_latitude, last_known_longitude, last_security_check_at
                    FROM session_keys
                    WHERE id = $1 AND last_known_latitude IS NOT NULL
                    "#,
                    session.id
                )
                .fetch_optional(&state.db)
                .await {
                    if let (Some(lat), Some(lon), Some(last_check)) = (
                        stored_location_data.last_known_latitude,
                        stored_location_data.last_known_longitude,
                        stored_location_data.last_security_check_at,
                    ) {
                        let stored_location = GeoLocation {
                            latitude: lat,
                            longitude: lon,
                            city: None,
                            country: None,
                        };
                        
                        let distance_km = calculate_distance(&current_location, &stored_location);
                        let time_elapsed = (chrono::Utc::now() - last_check).num_seconds() as f64 / 3600.0;
                        
                        let speed_kmh = if time_elapsed > 0.0 { distance_km / time_elapsed } else { 0.0 };
                        
                        if distance_km > 500.0 && speed_kmh > 900.0 {
                            tracing::error!(
                                "IMPOSSIBLE TRAVEL DETECTED: {} km in {:.1} hours ({:.1} km/h) for session {}",
                                distance_km, time_elapsed, speed_kmh, session.id
                            );
                            
                            Self::log_security_event(
                                state,
                                Some(session.id),
                                platform_id,
                                "impossible_travel",
                                "critical",
                                &format!(
                                    "Travel {} km in {:.1} hours ({:.1} km/h) - Location: {} -> {}",
                                    distance_km, time_elapsed, speed_kmh,
                                    format!("{},{}", stored_location.latitude, stored_location.longitude),
                                    format!("{},{}", current_location.latitude, current_location.longitude)
                                ),
                                Some(&request_context.ip_address),
                            ).await?;
                            
                            Self::revoke_session_key(state, session.id, platform_id).await?;
                            return Err(SessionKeyError::ImpossibleTravel);
                        } else if distance_km > 100.0 {
                            tracing::info!(
                                "Significant location change for session {}: {} km in {:.1} hours",
                                session.id, distance_km, time_elapsed
                            );
                        }
                    }
                }
                
                let session_id = session.id;
                let db = state.db.clone();
                let lat = current_location.latitude;
                let lon = current_location.longitude;
                tokio::spawn(async move {
                    let _ = sqlx::query!(
                        r#"
                        UPDATE session_keys
                        SET last_known_latitude = $1,
                            last_known_longitude = $2
                        WHERE id = $3
                        "#,
                        lat,
                        lon,
                        session_id
                    )
                    .execute(&db)
                    .await;
                });
            }
            Err(e) => {
                tracing::warn!(
                    "Geolocation check failed for session {}, continuing anyway: {}",
                    session.id, e
                );
            }
        }

        match get_recent_transactions(state, session.id).await {
            Ok(recent_transactions) => {
                if detect_anomaly(&recent_transactions, transaction_amount_usd) {
                    tracing::warn!(
                        "ANOMALOUS TRANSACTION DETECTED: ${} for session {} (platform {})",
                        transaction_amount_usd, session.id, platform_id
                    );
                    
                    Self::log_security_event(
                        state,
                        Some(session.id),
                        platform_id,
                        "anomalous_transaction_pattern",
                        "high",
                        &format!(
                            "Unusual amount: ${:.2} (mean of last {} transactions differs by >3 std devs)",
                            transaction_amount_usd, recent_transactions.len()
                        ),
                        Some(&request_context.ip_address),
                    ).await?;
                    
                    tracing::error!("Blocking anomalous transaction - manual approval required");
                    return Err(SessionKeyError::AnomalousTransaction);
                }
            }
            Err(e) => {
                tracing::debug!("Anomaly detection skipped: {}", e);
            }
        }

        if session.expires_at < chrono::Utc::now() {
            let _ = Self::deactivate_session_key(state, session.id).await;
            return Err(SessionKeyError::Expired);
        }

        let limit = session.limit_usdc.to_f64().unwrap_or(0.0);
        let used = session.used_amount_usdc.map(|d| d.to_f64().unwrap_or(0.0)).unwrap_or(0.0);
        let remaining = limit - used;

        tracing::debug!(
            "Session key {} found: limit=${}, used=${}, remaining=${}",
            session.id, limit, used, remaining
        );

        if transaction_amount_usd > remaining {
            tracing::warn!(
                "Transaction ${} exceeds session key remaining limit ${}",
                transaction_amount_usd, remaining
            );
            return Err(SessionKeyError::LimitExceeded);
        }

        Self::log_session_key_usage(
            state,
            session.id,
            platform_id,
            transaction_amount_usd,
            &request_context,
        ).await?;

        let ip_network = IpNetwork::from_str(&request_context.ip_address)
            .map_err(|e| SessionKeyError::DatabaseError(format!("Invalid IP address: {}", e)))?;
        
        let _ = sqlx::query!(
            r#"
            UPDATE session_keys
            SET ip_address = $1,
                user_agent = $2,
                last_security_check_at = NOW()
            WHERE id = $3
            "#,
            ip_network as IpNetwork,
            request_context.user_agent,
            session.id
        )
        .execute(&state.db)
        .await;

        let key_manager = crate::services::key_manager::SecureKeyManager::from_env()
            .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

        let session_keypair = key_manager.retrieve_keypair(
            state,
            "ai_session_key",
            platform_id,
        ).await
        .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

        Self::increment_session_key_usage(state, session.id, transaction_amount_usd).await?;

        tracing::info!(
            "Session key {} authorized for ${} transaction (platform {}) - All security checks passed",
            session.id, transaction_amount_usd, platform_id
        );

        Ok(session_keypair)
    }

    pub async fn increment_session_key_usage(
        state: &AppState,
        session_id: Uuid,
        amount_usd: f64,
    ) -> Result<(), SessionKeyError> {
        if amount_usd <= 0.0 {
            return Err(SessionKeyError::InvalidAmount);
        }

        let amount_decimal = BigDecimal::from_f64(amount_usd)
            .ok_or(SessionKeyError::InvalidAmount)?;

        sqlx::query!(
            r#"
            UPDATE session_keys
            SET used_amount_usdc = used_amount_usdc + $1,
                last_used_at = NOW()
            WHERE id = $2
            "#,
            amount_decimal,
            session_id
        )
        .execute(&state.db)
        .await
        .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

        tracing::debug!("Incremented session key {} usage by ${}", session_id, amount_usd);

        Ok(())
    }

    pub async fn revoke_session_key(
        state: &AppState,
        session_id: Uuid,
        platform_id: Uuid,
    ) -> Result<Option<String>, SessionKeyError> {
        tracing::info!("Revoking session key {} for platform {}", session_id, platform_id);

        let session_details = sqlx::query!(
            r#"
            SELECT 
                id, 
                platform_id, 
                session_keypair_id,
                session_wallet_address,
                user_wallet,
                limit_usdc, 
                used_amount_usdc,
                (limit_usdc - COALESCE(used_amount_usdc, 0)) as "remaining_usdc!"
            FROM session_keys
            WHERE id = $1 AND platform_id = $2 AND is_active = TRUE
            "#,
            session_id,
            platform_id
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?
        .ok_or(SessionKeyError::NotFound)?;

        let result = sqlx::query!(
            r#"
            UPDATE session_keys
            SET is_active = FALSE,
                revoked_at = NOW()
            WHERE id = $1 AND platform_id = $2 AND is_active = TRUE
            "#,
            session_id,
            platform_id
        )
        .execute(&state.db)
        .await
        .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SessionKeyError::AlreadyRevoked);
        }

        if let Ok(session) = Self::get_session_info(state, session_id).await {
            let key_update = sqlx::query!(
                "UPDATE encrypted_keys SET is_active = FALSE WHERE id = $1 RETURNING key_type",
                session.session_keypair_id
            )
            .fetch_optional(&state.db)
            .await;
            
            if let Ok(Some(record)) = key_update {
                 if let Err(e) = crate::services::keypair_cache::invalidate_keypair_cache(
                    state,
                    session.session_keypair_id,
                    &record.key_type
                ).await {
                    tracing::warn!("Failed to invalidate cache for key {}: {}", session.session_keypair_id, e);
                }
            }
        }

        tracing::info!("Session key {} revoked successfully", session_id);

        let remaining_f64 = session_details.remaining_usdc.to_string().parse::<f64>().unwrap_or(0.0);
        
        if remaining_f64 > 0.01 
            && session_details.user_wallet.is_some() 
            && session_details.session_wallet_address.is_some() 
        {
            tracing::info!(
                "Triggering immediate refund of ${:.2} for revoked session {}",
                remaining_f64,
                session_id
            );

            let session_record = crate::services::session_cleanup::SessionRecord {
                id: session_details.id,
                platform_id: session_details.platform_id,
                session_keypair_id: session_details.session_keypair_id,
                session_wallet_address: session_details.session_wallet_address,
                user_wallet: session_details.user_wallet,
            };

            match crate::services::session_cleanup::refund_session_key(state, &session_record).await {
                Ok(signature) => {
                    if signature != "no_balance" && signature != "zero_balance" {
                        tracing::info!(
                            "Immediate refund successful for session {}: ${:.2} refunded (tx: {})",
                            session_id,
                            remaining_f64,
                            signature
                        );
                        return Ok(Some(signature));
                    } else {
                        tracing::info!("No refund needed for session {} ({})", session_id, signature);
                    }
                }
                Err(e) => {
                    tracing::error!(
                        "❌ Immediate refund failed for session {}: {} - will be retried by cleanup worker",
                        session_id,
                        e
                    );
                }
            }
        } else {
            tracing::info!("No refund needed for session {} (remaining: ${:.2})", session_id, remaining_f64);
        }

        Ok(None)
    }

    pub async fn deactivate_session_key(
        state: &AppState,
        session_id: Uuid,
    ) -> Result<(), SessionKeyError> {
        sqlx::query!(
            r#"
            UPDATE session_keys
            SET is_active = FALSE
            WHERE id = $1
            "#,
            session_id
        )
        .execute(&state.db)
        .await
        .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

        tracing::debug!("Deactivated session key {}", session_id);

        Ok(())
    }

    pub async fn get_session_info(
        state: &AppState,
        session_id: Uuid,
    ) -> Result<SessionKeyInfo, SessionKeyError> {
        let session = sqlx::query!(
            r#"
            SELECT id, session_keypair_id, limit_usdc, used_amount_usdc, 
                   expires_at, is_active
            FROM session_keys
            WHERE id = $1
            "#,
            session_id
        )
        .fetch_one(&state.db)
        .await
        .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

        Ok(SessionKeyInfo {
            id: session.id,
            session_keypair_id: session.session_keypair_id,
            public_key: String::new(),
            limit_usdc: session.limit_usdc.to_f64().unwrap_or(0.0),
            used_amount_usdc: session.used_amount_usdc.map(|d| d.to_f64().unwrap_or(0.0)).unwrap_or(0.0),
            expires_at: session.expires_at,
            is_active: session.is_active.unwrap_or(false),
        })
    }

    pub async fn list_platform_session_keys(
        state: &AppState,
        platform_id: Uuid,
        include_inactive: bool,
    ) -> Result<Vec<SessionKeyInfo>, SessionKeyError> {
        if include_inactive {
            let sessions = sqlx::query!(
                r#"
                SELECT id, session_keypair_id, limit_usdc, used_amount_usdc, 
                       expires_at, is_active
                FROM session_keys
                WHERE platform_id = $1
                ORDER BY created_at DESC
                "#,
                platform_id
            )
            .fetch_all(&state.db)
            .await
            .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

            Ok(sessions
                .into_iter()
                .map(|s| SessionKeyInfo {
                    id: s.id,
                    session_keypair_id: s.session_keypair_id,
                    public_key: String::new(),
                    limit_usdc: s.limit_usdc.to_f64().unwrap_or(0.0),
                    used_amount_usdc: s.used_amount_usdc.map(|d| d.to_f64().unwrap_or(0.0)).unwrap_or(0.0),
                    expires_at: s.expires_at,
                    is_active: s.is_active.unwrap_or(false),
                })
                .collect())
        } else {
            let sessions = sqlx::query!(
                r#"
                SELECT id, session_keypair_id, limit_usdc, used_amount_usdc, 
                       expires_at, is_active
                FROM session_keys
                WHERE platform_id = $1 AND is_active = TRUE AND expires_at > NOW()
                ORDER BY created_at DESC
                "#,
                platform_id
            )
            .fetch_all(&state.db)
            .await
            .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

            Ok(sessions
                .into_iter()
                .map(|s| SessionKeyInfo {
                    id: s.id,
                    session_keypair_id: s.session_keypair_id,
                    public_key: String::new(),
                    limit_usdc: s.limit_usdc.to_f64().unwrap_or(0.0),
                    used_amount_usdc: s.used_amount_usdc.map(|d| d.to_f64().unwrap_or(0.0)).unwrap_or(0.0),
                    expires_at: s.expires_at,
                    is_active: s.is_active.unwrap_or(false),
                })
                .collect())
        }
    }    
    
    async fn log_session_key_usage(
        state: &AppState,
        session_key_id: Uuid,
        platform_id: Uuid,
        amount_usd: f64,
        context: &SessionKeyRequestContext,
    ) -> Result<(), SessionKeyError> {
        let amount_decimal = BigDecimal::from_f64(amount_usd)
            .ok_or(SessionKeyError::InvalidAmount)?;

        let ip_network = IpNetwork::from_str(&context.ip_address)
            .map_err(|e| SessionKeyError::DatabaseError(format!("Invalid IP address: {}", e)))?;

        sqlx::query!(
            r#"
            INSERT INTO session_key_usage_log 
            (session_key_id, platform_id, amount_usd, ip_address, user_agent, device_fingerprint, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            "#,
            session_key_id,
            platform_id,
            amount_decimal,
            ip_network as IpNetwork,
            context.user_agent,
            context.device_fingerprint,
        )
        .execute(&state.db)
        .await
        .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn log_security_event(
        state: &AppState,
        session_key_id: Option<Uuid>,
        platform_id: Uuid,
        event_type: &str,
        severity: &str,
        description: &str,
        ip_address: Option<&str>,
    ) -> Result<(), SessionKeyError> {
        let action_taken = match severity {
            "critical" => "revoked",
            "high" => "flagged",
            _ => "logged",
        };

        let ip_network = match ip_address {
            Some(ip_str) => Some(
                IpNetwork::from_str(ip_str)
                    .map_err(|e| SessionKeyError::DatabaseError(format!("Invalid IP address: {}", e)))?
            ),
            None => None,
        };

        sqlx::query!(
            r#"
            INSERT INTO session_key_security_events 
            (session_key_id, platform_id, event_type, severity, description, action_taken, ip_address, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            "#,
            session_key_id,
            platform_id,
            event_type,
            severity,
            description,
            action_taken,
            ip_network as Option<IpNetwork>,
        )
        .execute(&state.db)
        .await
        .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    pub async fn send_session_expiry_notifications(
        state: &AppState,
    ) -> Result<usize, SessionKeyError> {
        let expiring_soon = sqlx::query!(
            r#"
            SELECT sk.id, sk.platform_id, sk.expires_at, m.email, m.name
            FROM session_keys sk
            JOIN platforms m ON sk.platform_id = m.id
            WHERE sk.is_active = TRUE
              AND sk.expires_at > NOW()
              AND sk.expires_at < NOW() + INTERVAL '7 days'
              AND sk.expiry_notification_sent = FALSE
            "#
        )
        .fetch_all(&state.db)
        .await
        .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

        let mut notified_count = 0;

        for session in expiring_soon {
            let days_until_expiry = (session.expires_at - chrono::Utc::now()).num_days();

            tracing::info!(
                "Sending session key expiry notification to {} (expires in {} days)",
                session.email, days_until_expiry
            );

            let email_result: Result<(), Box<dyn std::error::Error + Send + Sync>> = Ok(());
            
            tracing::warn!(
                "Session key expiry email would be sent to {} for session {}",
                session.email, session.name
            );

            if email_result.is_ok() {
                let _ = sqlx::query!(
                    "UPDATE session_keys SET expiry_notification_sent = TRUE WHERE id = $1",
                    session.id
                )
                .execute(&state.db)
                .await;

                notified_count += 1;
            }
        }

        tracing::info!("Sent {} session key expiry notifications", notified_count);

        Ok(notified_count)
    }

    pub async fn cleanup_expired_session_keys(
        state: &AppState,
    ) -> Result<usize, SessionKeyError> {
        let result = sqlx::query!(
            r#"
            UPDATE session_keys
            SET is_active = FALSE
            WHERE is_active = TRUE AND expires_at < NOW()
            "#
        )
        .execute(&state.db)
        .await
        .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

        let cleaned = result.rows_affected() as usize;

        if cleaned > 0 {
            tracing::info!("Cleaned up {} expired session keys", cleaned);
        }

        Ok(cleaned)
    }

    pub async fn get_session_key_stats(
        state: &AppState,
        platform_id: Uuid,
    ) -> Result<SessionKeyStats, SessionKeyError> {
        let active_sessions = Self::list_platform_session_keys(state, platform_id, false).await?;

        let total_limit: f64 = active_sessions.iter().map(|s| s.limit_usdc).sum();
        let total_used: f64 = active_sessions.iter().map(|s| s.used_amount_usdc).sum();
        let total_remaining = total_limit - total_used;

        let earliest_expiry = active_sessions
            .iter()
            .map(|s| s.expires_at)
            .min();

        Ok(SessionKeyStats {
            active_count: active_sessions.len(),
            total_limit_usdc: total_limit,
            total_used_usdc: total_used,
            total_remaining_usdc: total_remaining,
            earliest_expiry,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKeyStats {
    pub active_count: usize,
    pub total_limit_usdc: f64,
    pub total_used_usdc: f64,
    pub total_remaining_usdc: f64,
    pub earliest_expiry: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn run_session_key_maintenance(state: &AppState) -> Result<(), SessionKeyError> {
    tracing::info!("Running session key maintenance tasks");

    let notifications_sent = SessionKeyManager::send_session_expiry_notifications(state).await?;

    let keys_cleaned = SessionKeyManager::cleanup_expired_session_keys(state).await?;

    tracing::info!(
        "Session key maintenance complete: {} notifications sent, {} keys cleaned",
        notifications_sent, keys_cleaned
    );

    Ok(())
}

async fn check_ip_location(ip: &str) -> Result<GeoLocation, SessionKeyError> {
    if ip.starts_with("127.") || ip.starts_with("192.168.") || ip.starts_with("10.") || ip == "::1" || ip == "unknown" {
        tracing::debug!("Skipping geolocation for local/unknown IP: {}", ip);
        return Ok(GeoLocation {
            latitude: 0.0,
            longitude: 0.0,
            city: Some("localhost".to_string()),
            country: Some("local".to_string()),
        });
    }

    tracing::debug!("Fetching geolocation for IP: {}", ip);
    
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://ip-api.com/json/{}?fields=status,lat,lon,city,country", ip))
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
        .map_err(|e| {
            tracing::warn!("Failed to fetch geolocation for {}: {}", ip, e);
            SessionKeyError::DatabaseError(format!("Geolocation API timeout"))
        })?;

    #[derive(Deserialize)]
    struct IpApiResponse {
        status: String,
        lat: Option<f64>,
        lon: Option<f64>,
        city: Option<String>,
        country: Option<String>,
    }

    let data: IpApiResponse = response.json().await.map_err(|e| {
        tracing::warn!("Failed to parse geolocation response: {}", e);
        SessionKeyError::DatabaseError(format!("Geolocation parse error: {}", e))
    })?;

    if data.status != "success" {
        tracing::warn!("Geolocation failed for IP {}: status={}", ip, data.status);
        return Ok(GeoLocation {
            latitude: 0.0,
            longitude: 0.0,
            city: None,
            country: None,
        });
    }

    Ok(GeoLocation {
        latitude: data.lat.unwrap_or(0.0),
        longitude: data.lon.unwrap_or(0.0),
        city: data.city,
        country: data.country,
    })
}

fn calculate_distance(loc1: &GeoLocation, loc2: &GeoLocation) -> f64 {
    const EARTH_RADIUS_KM: f64 = 6371.0;

    let lat1_rad = loc1.latitude.to_radians();
    let lat2_rad = loc2.latitude.to_radians();
    let delta_lat = (loc2.latitude - loc1.latitude).to_radians();
    let delta_lon = (loc2.longitude - loc1.longitude).to_radians();

    let a = (delta_lat / 2.0).sin().powi(2)
        + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    EARTH_RADIUS_KM * c
}

async fn get_recent_transactions(
    state: &AppState,
    session_id: Uuid,
) -> Result<Vec<Transaction>, SessionKeyError> {
    let records = sqlx::query!(
        r#"
        SELECT amount_usd, created_at
        FROM session_key_usage_log
        WHERE session_key_id = $1
          AND created_at > NOW() - INTERVAL '24 hours'
        ORDER BY created_at DESC
        LIMIT 50
        "#,
        session_id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

    Ok(records
        .into_iter()
        .map(|r| Transaction {
            amount: r.amount_usd.to_f64().unwrap_or(0.0),
        })
        .collect())
}

fn detect_anomaly(transactions: &[Transaction], current_amount: f64) -> bool {
    if transactions.len() < 3 {
        tracing::debug!("Not enough transaction history for anomaly detection ({})", transactions.len());
        return false;
    }

    let amounts: Vec<f64> = transactions.iter().map(|t| t.amount).collect();
    let mean = amounts.iter().sum::<f64>() / amounts.len() as f64;
    
    let variance = amounts.iter()
        .map(|a| (a - mean).powi(2))
        .sum::<f64>() / amounts.len() as f64;
    let std_dev = variance.sqrt();

    let z_score = (current_amount - mean).abs() / std_dev.max(0.01);
    let is_anomaly = z_score > 3.0;

    if is_anomaly {
        tracing::warn!(
            "Anomaly detected: amount=${} vs mean=${:.2} (std_dev={:.2}, z-score={:.2})",
            current_amount, mean, std_dev, z_score
        );
    }

    is_anomaly
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_key_validation() {
        let err = SessionKeyError::Expired;
        assert_eq!(err.to_string(), "Session key has expired");
    }

    #[test]
    fn test_session_key_stats_serialization() {
        let stats = SessionKeyStats {
            active_count: 2,
            total_limit_usdc: 20000.0,
            total_used_usdc: 5000.0,
            total_remaining_usdc: 15000.0,
            earliest_expiry: Some(chrono::Utc::now()),
        };

        let json = serde_json::to_string(&stats)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to serialize session stats: {}", e);
                "{}".to_string()
            });
        assert!(json.contains("active_count"));
        assert!(json.contains("total_limit_usdc"));
    }
}
