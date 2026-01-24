use uuid::Uuid;
use sqlx::PgPool;
use std::str::FromStr;
use crate::services::session_keys_core::SessionKeyError;

pub async fn get_agent_session_key(
    db: &PgPool,
    user_wallet: &str,
    agent_id: &str,
    platform_id: Uuid,
) -> Result<Uuid, SessionKeyError> {
    tracing::debug!(
        "Looking for agent-scoped session key: user={}, agent={}, platform={}",
        user_wallet, agent_id, platform_id
    );

    let session_key = sqlx::query!(
        r#"
        SELECT id, agent_id, authorized_recipients, created_by_platform_id
        FROM session_keys
        WHERE user_wallet = $1
          AND agent_id = $2
          AND is_active = TRUE
          AND expires_at > NOW()
        ORDER BY created_at DESC
        LIMIT 1
        "#,
        user_wallet,
        agent_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

    let session_key = match session_key {
        Some(sk) => sk,
        None => {
            tracing::info!(
                "No active session key found for user={} agent={} - user needs to authorize",
                user_wallet, agent_id
            );
            return Err(SessionKeyError::NotFound);
        }
    };

    let authorized_recipients = session_key.authorized_recipients
        .unwrap_or_default();

    if !authorized_recipients.is_empty() {
        let platform_id_str = platform_id.to_string();
        if !authorized_recipients.contains(&platform_id_str) {
            tracing::warn!(
                "Recipient {} not authorized for session key {} (user={}, agent={})",
                platform_id, session_key.id, user_wallet, agent_id
            );
            
            let is_authorized = sqlx::query_scalar!(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM session_key_authorizations
                    WHERE session_key_id = $1
                      AND platform_id = $2
                      AND revoked_at IS NULL
                ) as "exists!"
                "#,
                session_key.id,
                platform_id
            )
            .fetch_one(db)
            .await
            .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

            if !is_authorized {
                return Err(SessionKeyError::NotFound);
            }
        }
    }

    tracing::info!(
        "Found agent-scoped session key {} for user={} agent={} platform={}",
        session_key.id, user_wallet, agent_id, platform_id
    );

    Ok(session_key.id)
}

pub async fn log_agent_session_usage(
    db: &PgPool,
    session_key_id: Uuid,
    platform_id: Uuid,
    agent_id: &str,
    amount_usd: f64,
    payment_id: Option<Uuid>,
    transaction_signature: Option<String>,
) -> Result<(), SessionKeyError> {
    let amount_decimal = bigdecimal::BigDecimal::from_str(&amount_usd.to_string())
        .map_err(|_| SessionKeyError::InvalidAmount)?;

    sqlx::query!(
        r#"
        INSERT INTO session_key_recipient_usage (
            session_key_id, platform_id, agent_id, amount_usd, 
            payment_id, transaction_signature
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        session_key_id,
        platform_id,
        agent_id,
        amount_decimal,
        payment_id,
        transaction_signature
    )
    .execute(db)
    .await
    .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

    tracing::debug!(
        "Logged cross-app usage: session={}, recipient={}, agent={}, amount=${}",
        session_key_id, platform_id, agent_id, amount_usd
    );

    Ok(())
}

pub async fn authorize_recipient_for_session_key(
    db: &PgPool,
    session_key_id: Uuid,
    platform_id: Uuid,
    agent_id: &str,
    authorization_signature: Option<String>,
) -> Result<(), SessionKeyError> {
    sqlx::query!(
        r#"
        INSERT INTO session_key_authorizations (
            session_key_id, platform_id, agent_id, authorization_signature
        )
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (session_key_id, platform_id) DO NOTHING
        "#,
        session_key_id,
        platform_id,
        agent_id,
        authorization_signature
    )
    .execute(db)
    .await
    .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

    tracing::info!(
        "Authorized recipient {} for session key {} (agent={})",
        platform_id, session_key_id, agent_id
    );

    Ok(())
}

pub async fn find_existing_agent_session(
    db: &PgPool,
    user_wallet: &str,
    agent_id: &str,
) -> Result<Option<Uuid>, SessionKeyError> {
    let result = sqlx::query_scalar!(
        r#"
        SELECT id FROM session_keys
        WHERE user_wallet = $1
          AND agent_id = $2
          AND is_active = TRUE
          AND expires_at > NOW()
        LIMIT 1
        "#,
        user_wallet,
        agent_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

    Ok(result)
}

pub async fn get_session_key_for_payment(
    db: &PgPool,
    session_key_id: Uuid,
    platform_id: Uuid,
) -> Result<SessionKeyDetails, SessionKeyError> {
    let session_key = sqlx::query!(
        r#"
        SELECT 
            sk.id,
            sk.user_wallet,
            sk.session_wallet_address,
            sk.agent_id,
            sk.agent_name,
            sk.session_keypair_id,
            sk.limit_usdc,
            sk.used_amount_usdc,
            sk.is_active,
            sk.expires_at,
            sk.device_fingerprint,
            sk.authorized_recipients,
            sk.created_by_platform_id
        FROM session_keys sk
        WHERE sk.id = $1
          AND sk.is_active = TRUE
          AND sk.expires_at > NOW()
        "#,
        session_key_id
    )
    .fetch_optional(db)
    .await
    .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?
    .ok_or(SessionKeyError::NotFound)?;

    if let Some(ref agent_id) = session_key.agent_id {
        let authorized_recipients = session_key.authorized_recipients
            .clone()
            .unwrap_or_default();

        if !authorized_recipients.is_empty() {
            let platform_id_str = platform_id.to_string();
            if !authorized_recipients.contains(&platform_id_str) {
                let is_authorized = sqlx::query_scalar!(
                    r#"
                    SELECT EXISTS(
                        SELECT 1 FROM session_key_authorizations
                        WHERE session_key_id = $1
                          AND platform_id = $2
                          AND revoked_at IS NULL
                    ) as "exists!"
                    "#,
                    session_key_id,
                    platform_id
                )
                .fetch_one(db)
                .await
                .map_err(|e| SessionKeyError::DatabaseError(e.to_string()))?;

                if !is_authorized {
                    tracing::warn!(
                        "Recipient {} not authorized for agent-scoped session key {} (agent={})",
                        platform_id, session_key_id, agent_id
                    );
                    return Err(SessionKeyError::NotFound);
                }
            }
        }

        tracing::debug!(
            "Recipient {} authorized for agent-scoped session key {} (agent={})",
            platform_id, session_key_id, agent_id
        );
    }

    Ok(SessionKeyDetails {
        id: session_key.id,
        session_wallet_address: session_key.session_wallet_address,
        agent_id: session_key.agent_id,
    })
}

#[derive(Debug, Clone)]
pub struct SessionKeyDetails {
    pub id: Uuid,
    pub session_wallet_address: Option<String>,
    pub agent_id: Option<String>,
}
