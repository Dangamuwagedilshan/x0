use axum::{
    extract::{Path, State},
    Extension,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use solana_sdk::signature::{Keypair, Signer};
use uuid::Uuid;
use base64::Engine;
use std::sync::Arc;

use crate::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingAttestation {
    pub delegate_id: Uuid,
    pub session_key_id: Uuid,
    pub platform_id: Uuid,
    pub spent_usd: f64,
    pub limit_usd: f64,
    pub requested_usd: f64,
    pub remaining_after_usd: f64,
    pub timestamp_ms: i64,
    pub nonce: String,
    pub payment_id: Uuid,
    pub version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSpendingAttestation {
    pub attestation: SpendingAttestation,
    pub signature: String,
    pub signer_public_key: String,
}

pub struct AttestationParams {
    pub delegate_id: Uuid,
    pub session_key_id: Uuid,
    pub platform_id: Uuid,
    pub spent_usd: f64,
    pub limit_usd: f64,
    pub requested_usd: f64,
    pub payment_id: Uuid,
}

#[derive(Clone)]
pub struct AttestationSigner {
    keypair: Arc<Keypair>,
}

impl AttestationSigner {
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair: Arc::new(keypair),
        }
    }
    
    pub fn from_env() -> Result<Self, String> {
        let key_str = std::env::var("X0_ATTESTATION_PRIVATE_KEY")
            .map_err(|_| "X0_ATTESTATION_PRIVATE_KEY environment variable not set")?;
        
        if let Ok(bytes) = bs58::decode(&key_str).into_vec() {
            if bytes.len() == 64 {
                let keypair = Keypair::try_from(bytes.as_slice())
                    .map_err(|e| format!("Invalid keypair bytes: {}", e))?;
                return Ok(Self::new(keypair));
            }
        }
        
        if let Ok(bytes) = serde_json::from_str::<Vec<u8>>(&key_str) {
            if bytes.len() == 64 {
                let keypair = Keypair::try_from(bytes.as_slice())
                    .map_err(|e| format!("Invalid keypair bytes: {}", e))?;
                return Ok(Self::new(keypair));
            }
        }
        
        Err("X0_ATTESTATION_PRIVATE_KEY must be base58 or JSON array of 64 bytes".to_string())
    }
    
    pub fn generate() -> Self {
        Self::new(Keypair::new())
    }
    
    pub fn public_key(&self) -> String {
        self.keypair.pubkey().to_string()
    }
    
    pub fn keypair_json(&self) -> String {
        serde_json::to_string(&self.keypair.to_bytes().to_vec())
            .unwrap_or_else(|_| "[REDACTED]".to_string())
    }
    
    pub fn create_attestation(&self, params: AttestationParams) -> Result<SignedSpendingAttestation, String> {
        let remaining_after = params.limit_usd - params.spent_usd - params.requested_usd;
        
        let attestation = SpendingAttestation {
            delegate_id: params.delegate_id,
            session_key_id: params.session_key_id,
            platform_id: params.platform_id,
            spent_usd: params.spent_usd,
            limit_usd: params.limit_usd,
            requested_usd: params.requested_usd,
            remaining_after_usd: remaining_after,
            timestamp_ms: Utc::now().timestamp_millis(),
            nonce: Uuid::new_v4().to_string(),
            payment_id: params.payment_id,
            version: 1,
        };
        
        let message = serde_json::to_string(&attestation)
            .map_err(|e| {
                tracing::error!("Failed to serialize attestation: {}", e);
                format!("Failed to create attestation: {}", e)
            })?;
        
        let signature = self.keypair.sign_message(message.as_bytes());
        
        Ok(SignedSpendingAttestation {
            attestation,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
            signer_public_key: self.keypair.pubkey().to_string(),
        })
    }
    
    pub fn verify_attestation(&self, signed: &SignedSpendingAttestation) -> Result<(), String> {
        use solana_sdk::signature::Signature;
        use solana_sdk::pubkey::Pubkey;
        use std::str::FromStr;
        
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&signed.signature)
            .map_err(|e| format!("Invalid base64 signature: {}", e))?;
        
        let signature = Signature::try_from(sig_bytes.as_slice())
            .map_err(|e| format!("Invalid signature bytes: {}", e))?;
        
        let pubkey = Pubkey::from_str(&signed.signer_public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;
        
        let message = serde_json::to_string(&signed.attestation)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        if signature.verify(pubkey.as_ref(), message.as_bytes()) {
            Ok(())
        } else {
            Err("Signature verification failed".to_string())
        }
    }
}

pub async fn store_attestation(
    state: &AppState,
    signed: &SignedSpendingAttestation,
) -> Result<Uuid, sqlx::Error> {
    use bigdecimal::BigDecimal;
    use std::str::FromStr;
    
    let attestation = &signed.attestation;
    let attestation_json = serde_json::to_string(&attestation)
        .expect("Attestation serialization should never fail");
    
    let id = sqlx::query_scalar!(
        r#"
        INSERT INTO spending_attestations (
            delegate_id,
            payment_id,
            platform_id,
            spent_usd,
            limit_usd,
            requested_usd,
            remaining_after_usd,
            attestation_json,
            signature,
            signer_public_key,
            attestation_timestamp,
            nonce,
            version
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING id
        "#,
        attestation.delegate_id,
        attestation.payment_id,
        attestation.platform_id,
        BigDecimal::from_str(&attestation.spent_usd.to_string())
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
        BigDecimal::from_str(&attestation.limit_usd.to_string())
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
        BigDecimal::from_str(&attestation.requested_usd.to_string())
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
        BigDecimal::from_str(&attestation.remaining_after_usd.to_string())
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
        attestation_json,
        signed.signature,
        signed.signer_public_key,
        DateTime::from_timestamp_millis(attestation.timestamp_ms).unwrap_or(Utc::now()),
        attestation.nonce,
        attestation.version as i16,
    )
    .fetch_one(&state.db)
    .await?;
    
    tracing::info!(
        "Stored spending attestation {} for payment {} (delegate: {}, requested: ${})",
        id, attestation.payment_id, attestation.delegate_id, attestation.requested_usd
    );
    
    Ok(id)
}

pub async fn get_attestations_for_delegate(
    state: &AppState,
    delegate_id: Uuid,
) -> Result<Vec<SignedSpendingAttestation>, sqlx::Error> {
    let records = sqlx::query!(
        r#"
        SELECT 
            attestation_json,
            signature,
            signer_public_key
        FROM spending_attestations
        WHERE delegate_id = $1
        ORDER BY created_at DESC
        "#,
        delegate_id
    )
    .fetch_all(&state.db)
    .await?;
    
    let attestations = records
        .into_iter()
        .filter_map(|r| {
            let attestation: SpendingAttestation = serde_json::from_str(&r.attestation_json).ok()?;
            Some(SignedSpendingAttestation {
                attestation,
                signature: r.signature.clone(),
                signer_public_key: r.signer_public_key.clone(),
            })
        })
        .collect();
    
    Ok(attestations)
}

#[derive(Debug, Serialize)]
pub struct AttestationAuditResponse {
    pub delegate_id: Uuid,
    pub attestation_count: usize,
    pub attestations: Vec<SignedSpendingAttestation>,
    pub x0_attestation_public_key: Option<String>,
}

pub async fn get_delegate_attestations_handler(
    State(state): State<AppState>,
    Extension(platform): Extension<crate::auth::AuthenticatedPlatform>,
    Path(delegate_id): Path<Uuid>,
) -> Result<axum::Json<AttestationAuditResponse>, (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    use axum::http::StatusCode;
    use serde_json::json;
    
    let delegate_check = sqlx::query!(
        r#"
        SELECT ad.id, sk.platform_id
        FROM autonomous_delegates ad
        JOIN session_keys sk ON sk.id = ad.session_key_id
        WHERE ad.id = $1
        "#,
        delegate_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error checking delegate ownership: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({"error": "Database error"})),
        )
    })?;
    
    let delegate_record = delegate_check.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "Delegate not found"})),
        )
    })?;
    
    if delegate_record.platform_id != platform.platform_id {
        return Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "Delegate does not belong to this platform"})),
        ));
    }
    
    let attestations = get_attestations_for_delegate(&state, delegate_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch attestations: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "Failed to fetch attestations"})),
            )
        })?;
    
    let public_key = state.attestation_signer.as_ref().map(|s| s.public_key());
    
    Ok(axum::Json(AttestationAuditResponse {
        delegate_id,
        attestation_count: attestations.len(),
        attestations,
        x0_attestation_public_key: public_key,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_attestation_creation_and_verification() {
        let signer = AttestationSigner::generate();
        
        let params = AttestationParams {
            delegate_id: Uuid::new_v4(),
            session_key_id: Uuid::new_v4(),
            platform_id: Uuid::new_v4(),
            spent_usd: 50.0,
            limit_usd: 100.0,
            requested_usd: 25.0,
            payment_id: Uuid::new_v4(),
        };
        
        let signed = signer.create_attestation(params).expect("Failed to create attestation");
        
        assert_eq!(signed.attestation.remaining_after_usd, 25.0);
        assert_eq!(signed.attestation.version, 1);
        
        assert!(signer.verify_attestation(&signed).is_ok());
    }
    
    #[test]
    fn test_attestation_tampering_detected() {
        let signer = AttestationSigner::generate();
        
        let params = AttestationParams {
            delegate_id: Uuid::new_v4(),
            session_key_id: Uuid::new_v4(),
            platform_id: Uuid::new_v4(),
            spent_usd: 50.0,
            limit_usd: 100.0,
            requested_usd: 25.0,
            payment_id: Uuid::new_v4(),
        };
        
        let mut signed = signer.create_attestation(params).expect("Failed to create attestation");
        
        signed.attestation.remaining_after_usd = 1000.0;
        
        assert!(signer.verify_attestation(&signed).is_err());
    }
    
    #[test]
    fn test_keypair_serialization() {
        let signer = AttestationSigner::generate();
        let json = signer.keypair_json();
        let pubkey = signer.public_key();
        
        let bytes: Vec<u8> = serde_json::from_str(&json).expect("Test keypair JSON should be valid");
        assert_eq!(bytes.len(), 64);
        
        assert!(pubkey.len() > 30);
    }
}
