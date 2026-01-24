use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::signature::Signer;
use uuid::Uuid;
use zeroize::Zeroize;
use crate::AppState;

const NONCE_SIZE: usize = 12;

#[derive(Debug)]
pub enum KeyManagerError {
    EncryptionFailed(String),
    DecryptionFailed(String),
    MissingMasterKey,
    InvalidMasterKey,
    DatabaseError(String),
    KeyNotFound,
    InvalidKeyData,
}

impl std::fmt::Display for KeyManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            KeyManagerError::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            KeyManagerError::DecryptionFailed(e) => write!(f, "Decryption failed: {}", e),
            KeyManagerError::MissingMasterKey => write!(f, "MASTER_ENCRYPTION_KEY environment variable not set"),
            KeyManagerError::InvalidMasterKey => write!(f, "Master key must be 64 hex characters (32 bytes)"),
            KeyManagerError::DatabaseError(e) => write!(f, "Database error: {}", e),
            KeyManagerError::KeyNotFound => write!(f, "Encryption key not found"),
            KeyManagerError::InvalidKeyData => write!(f, "Invalid key data format"),
        }
    }
}

impl std::error::Error for KeyManagerError {}

pub struct SecureKeyManager {
    pub(crate) master_key: [u8; 32],
}

impl SecureKeyManager {
    pub fn from_env() -> Result<Self, KeyManagerError> {
        let master_key_hex = std::env::var("MASTER_ENCRYPTION_KEY")
            .map_err(|_| KeyManagerError::MissingMasterKey)?;

        if master_key_hex.len() != 64 {
            return Err(KeyManagerError::InvalidMasterKey);
        }

        let master_key_bytes = hex::decode(&master_key_hex)
            .map_err(|_| KeyManagerError::InvalidMasterKey)?;

        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&master_key_bytes);

        Ok(Self { master_key })
    }

    pub fn encrypt_bytes(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), KeyManagerError> {
        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| KeyManagerError::EncryptionFailed(e.to_string()))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| KeyManagerError::EncryptionFailed(format!("Nonce generation failed: {}", e)))?;
        
        let nonce = Nonce::from(nonce_bytes);

        let encrypted_data = cipher
            .encrypt(&nonce, data)
            .map_err(|e| KeyManagerError::EncryptionFailed(e.to_string()))?;

        Ok((encrypted_data, nonce_bytes.to_vec()))
    }

    pub fn decrypt_bytes(&self, encrypted_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, KeyManagerError> {
        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| KeyManagerError::DecryptionFailed(e.to_string()))?;

        if nonce.len() != NONCE_SIZE {
            return Err(KeyManagerError::InvalidKeyData);
        }

        let nonce_array: [u8; NONCE_SIZE] = nonce.try_into()
            .map_err(|_| KeyManagerError::InvalidKeyData)?;
        let nonce = Nonce::from(nonce_array);

        cipher
            .decrypt(&nonce, encrypted_data)
            .map_err(|e| KeyManagerError::DecryptionFailed(e.to_string()))
    }

    pub fn encrypt_keypair(&self, keypair: &Keypair) -> Result<(Vec<u8>, Vec<u8>), KeyManagerError> {
        self.encrypt_bytes(keypair.to_bytes().as_ref())
    }

    pub fn decrypt_keypair(&self, encrypted_data: &[u8], nonce: &[u8]) -> Result<Keypair, KeyManagerError> {
        let decrypted = self.decrypt_bytes(encrypted_data, nonce)?;

        if decrypted.len() != 64 {
            return Err(KeyManagerError::InvalidKeyData);
        }

        Keypair::try_from(&decrypted[..])
            .map_err(|_| KeyManagerError::InvalidKeyData)
    }



    pub async fn store_encrypted_keypair(
        &self,
        state: &AppState,
        keypair: &Keypair,
        key_type: &str,
        owner_id: Uuid,
        metadata: Option<serde_json::Value>,
    ) -> Result<Uuid, KeyManagerError> {
        let (encrypted_data, nonce) = self.encrypt_keypair(keypair)?;
        let public_key = keypair.pubkey().to_string();

        let key_id = Uuid::new_v4();

        sqlx::query!(
            r#"
            INSERT INTO encrypted_keys 
            (id, key_type, owner_id, encrypted_key_data, encryption_version, nonce, public_key, key_metadata, is_active, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
            "#,
            key_id,
            key_type,
            owner_id,
            encrypted_data,
            1,
            nonce,
            public_key,
            metadata.unwrap_or(serde_json::json!({})),
            true
        )
        .execute(&state.db)
        .await
        .map_err(|e| KeyManagerError::DatabaseError(e.to_string()))?;

        self.log_key_operation(state, key_id, "created", true, None).await;

        tracing::info!("Stored encrypted {} key for owner {}", key_type, owner_id);
        Ok(key_id)
    }

    pub async fn retrieve_keypair(
        &self,
        state: &AppState,
        key_type: &str,
        owner_id: Uuid,
    ) -> Result<Keypair, KeyManagerError> {
        let record = sqlx::query!(
            r#"
            SELECT id, encrypted_key_data, nonce
            FROM encrypted_keys
            WHERE key_type = $1 AND owner_id = $2 AND is_active = TRUE
            ORDER BY created_at DESC
            LIMIT 1
            "#,
            key_type,
            owner_id
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| KeyManagerError::DatabaseError(e.to_string()))?
        .ok_or(KeyManagerError::KeyNotFound)?;

        let keypair = self.decrypt_keypair(&record.encrypted_key_data, &record.nonce)?;

        let key_id = record.id;
        let db_clone = state.db.clone();
        tokio::spawn(async move {
            let _ = sqlx::query!(
                "UPDATE encrypted_keys SET last_used_at = NOW() WHERE id = $1",
                key_id
            )
            .execute(&db_clone)
            .await;
        });

        self.log_key_operation(state, record.id, "accessed", true, None).await;

        Ok(keypair)
    }

    async fn log_key_operation(
        &self,
        state: &AppState,
        key_id: Uuid,
        operation: &str,
        success: bool,
        error_message: Option<String>,
    ) {
        let _ = sqlx::query!(
            r#"
            INSERT INTO key_operation_logs (id, key_id, operation, operator, success, error_message, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            "#,
            Uuid::new_v4(),
            key_id,
            operation,
            "system",
            success,
            error_message
        )
        .execute(&state.db)
        .await;
    }
}


impl Drop for SecureKeyManager {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_master_key() {
        let key1 = SecureKeyManager::generate_master_key();
        let key2 = SecureKeyManager::generate_master_key();
        
        assert_eq!(key1.len(), 64);
        assert_ne!(key1, key2); 
    }

    #[test]
    fn test_encrypt_decrypt_keypair() {
        let master_key = SecureKeyManager::generate_master_key();
        std::env::set_var("MASTER_ENCRYPTION_KEY", &master_key);

        let manager = SecureKeyManager::from_env().expect("Key manager creation should succeed");
        let original_keypair = Keypair::new();
        
        let (encrypted, nonce) = manager.encrypt_keypair(&original_keypair).expect("Encryption should succeed");
        let decrypted_keypair = manager.decrypt_keypair(&encrypted, &nonce).expect("Decryption should succeed");

        assert_eq!(
            original_keypair.pubkey().to_string(),
            decrypted_keypair.pubkey().to_string()
        );
    }
}

impl SecureKeyManager {
    pub async fn store_client_encrypted_keypair(
        &self,
        state: &AppState,
        encrypted_data: Vec<u8>,
        nonce: Vec<u8>,
        public_key: String,
        device_fingerprint: String,
        key_type: &str,
        owner_id: Uuid,
        metadata: Option<serde_json::Value>,
    ) -> Result<Uuid, KeyManagerError> {
        if encrypted_data.is_empty() {
            return Err(KeyManagerError::InvalidKeyData);
        }
        
        if nonce.len() != NONCE_SIZE {
            return Err(KeyManagerError::InvalidKeyData);
        }
        
        if device_fingerprint.is_empty() {
            return Err(KeyManagerError::EncryptionFailed(
                "Device fingerprint required for client-encrypted keys".to_string()
            ));
        }
        
        if public_key.len() < 32 || public_key.len() > 44 {
            return Err(KeyManagerError::InvalidKeyData);
        }

        let key_id = Uuid::new_v4();

        sqlx::query!(
            r#"
            INSERT INTO encrypted_keys 
            (id, key_type, owner_id, encrypted_key_data, encryption_version, 
             nonce, public_key, key_metadata, is_active, encryption_mode, 
             client_encrypted, device_fingerprint, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
            "#,
            key_id,
            key_type,
            owner_id,
            encrypted_data,
            1,
            nonce,
            public_key,
            metadata.unwrap_or(serde_json::json!({})),
            true,
            "device_bound",
            true,
            device_fingerprint,
        )
        .execute(&state.db)
        .await
        .map_err(|e| KeyManagerError::DatabaseError(e.to_string()))?;

        self.log_key_operation(
            state, 
            key_id, 
            "created_client_encrypted", 
            true, 
            Some("Device-bound mode".to_string())
        ).await;

        tracing::info!(
            "Stored CLIENT-ENCRYPTED {} key for owner {} (device-bound mode, non-custodial)",
            key_type, owner_id
        );
        
        Ok(key_id)
    }
    
    pub async fn retrieve_client_encrypted_keypair(
        &self,
        state: &AppState,
        key_id: Uuid,
    ) -> Result<(Vec<u8>, Vec<u8>, String), KeyManagerError> {
        let record = sqlx::query!(
            r#"
            SELECT encrypted_key_data, nonce, device_fingerprint, encryption_mode
            FROM encrypted_keys
            WHERE id = $1 AND is_active = TRUE
            "#,
            key_id
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| KeyManagerError::DatabaseError(e.to_string()))?
        .ok_or(KeyManagerError::KeyNotFound)?;
        
        if record.encryption_mode.as_deref() != Some("device_bound") {
            return Err(KeyManagerError::InvalidKeyData);
        }
        
        self.log_key_operation(
            state,
            key_id,
            "retrieved_for_client_decrypt",
            true,
            Some("Returning encrypted data to client".to_string())
        ).await;
        
        Ok((
            record.encrypted_key_data,
            record.nonce,
            record.device_fingerprint.unwrap_or_default(),
        ))
    }
    
    pub async fn validate_device_fingerprint(
        &self,
        state: &AppState,
        key_id: Uuid,
        provided_fingerprint: &str,
    ) -> Result<bool, KeyManagerError> {
        let record = sqlx::query!(
            r#"
            SELECT device_fingerprint
            FROM encrypted_keys
            WHERE id = $1 AND encryption_mode = 'device_bound'
            "#,
            key_id
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| KeyManagerError::DatabaseError(e.to_string()))?
        .ok_or(KeyManagerError::KeyNotFound)?;
        
        let stored_fingerprint = record.device_fingerprint.unwrap_or_default();
        let matches = stored_fingerprint == provided_fingerprint;
        
        if !matches {
            tracing::warn!(
                "Device fingerprint mismatch for key {}: expected {}, got {}",
                key_id,
                &stored_fingerprint[..8],
                &provided_fingerprint[..8.min(provided_fingerprint.len())]
            );
            
            self.log_key_operation(
                state,
                key_id,
                "device_mismatch",
                false,
                Some(format!("Fingerprint mismatch: {} != {}", 
                    &stored_fingerprint[..8], 
                    &provided_fingerprint[..8.min(provided_fingerprint.len())]
                ))
            ).await;
        }
        
        Ok(matches)
    }
    
    pub async fn update_device_fingerprint(
        &self,
        state: &AppState,
        key_id: Uuid,
        new_fingerprint: String,
    ) -> Result<(), KeyManagerError> {
        sqlx::query!(
            r#"
            UPDATE encrypted_keys
            SET device_fingerprint = $1
            WHERE id = $2 AND encryption_mode = 'device_bound'
            "#,
            new_fingerprint,
            key_id
        )
        .execute(&state.db)
        .await
        .map_err(|e| KeyManagerError::DatabaseError(e.to_string()))?;
        
        self.log_key_operation(
            state,
            key_id,
            "device_migrated",
            true,
            Some("Device fingerprint updated after recovery".to_string())
        ).await;
        
        tracing::info!(
            "Updated device fingerprint for key {} (device migration)",
            key_id
        );
        
        Ok(())
    }
    
    pub async fn retrieve_keypair_by_id(
        &self,
        state: &AppState,
        key_id: Uuid,
    ) -> Result<Keypair, KeyManagerError> {
        let record = sqlx::query!(
            r#"
            SELECT encrypted_key_data, nonce
            FROM encrypted_keys
            WHERE id = $1 AND is_active = TRUE
            "#,
            key_id
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| KeyManagerError::DatabaseError(e.to_string()))?
        .ok_or(KeyManagerError::KeyNotFound)?;
        
        let keypair = self.decrypt_keypair(&record.encrypted_key_data, &record.nonce)?;
        
        let db_clone = state.db.clone();
        tokio::spawn(async move {
            let _ = sqlx::query!(
                "UPDATE encrypted_keys SET last_used_at = NOW() WHERE id = $1",
                key_id
            )
            .execute(&db_clone)
            .await;
        });
        
        self.log_key_operation(state, key_id, "accessed", true, None).await;
        
        Ok(keypair)
    }
}
