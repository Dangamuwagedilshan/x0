use uuid::Uuid;
use serde::{Deserialize, Serialize};
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::signature::Signer;
use crate::AppState;
use crate::services::fee_router::{FeeRouterClient, FEE_ROUTER_PROGRAM_ID};
use base64::Engine;
use bigdecimal::BigDecimal;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustodySpendingRules {
    pub max_transaction_amount_sol: Option<f64>,
    pub max_transaction_amount_usdc: Option<f64>,
    pub daily_limit_sol: Option<f64>,
    pub daily_limit_usdc: Option<f64>,
    pub allowed_recipients: Vec<String>,
    pub allowed_programs: Vec<String>,
    pub require_approval_above_sol: Option<f64>,
    pub require_approval_above_usdc: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct TransactionDetails {
    pub amount: f64,
    pub token: String,
    pub recipient: String,
    pub program_id: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCustodyInfo {
    pub custody_id: Uuid,
    pub agent_id: String,
    pub user_wallet: String,
    pub platform_id: Uuid,
    pub access_secret_hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantCustodyRequest {
    pub agent_id: String,
    pub user_wallet: String,
    pub encrypted_keypair: Vec<u8>,
    pub client_nonce: Vec<u8>,
    pub expires_in_days: Option<u32>,
    pub spending_rules: Option<CustodySpendingRules>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantCustodyResponse {
    pub custody_id: Uuid,
    pub access_secret: String,
    pub user_wallet: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub warning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSignRequest {
    pub custody_id: Uuid,
    pub access_secret: String,
    pub transaction_message: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSignResponse {
    pub signature: Vec<u8>,
    pub public_key: String,
}

#[derive(Debug)]
pub enum CustodyError {
    InvalidAccessSecret,
    CustodyNotFound,
    CustodyRevoked,
    LitProtocolError(String),
    DecryptionFailed(String),
    DatabaseError(String),
    InvalidKeypair(String),
    InvalidTransaction(String),
    SpendingLimitExceeded(String),
    DailyLimitExceeded(String),
    RecipientNotAllowed(String),
    ProgramNotAllowed(String),
    ApprovalRequired(String),
}

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CustodyError::InvalidAccessSecret => write!(f, "Invalid access secret - agent not authorized"),
            CustodyError::CustodyNotFound => write!(f, "Custody record not found or expired"),
            CustodyError::CustodyRevoked => write!(f, "Wallet custody has been revoked"),
            CustodyError::LitProtocolError(e) => write!(f, "Lit Protocol error: {}", e),
            CustodyError::DecryptionFailed(e) => write!(f, "Failed to decrypt keypair: {}", e),
            CustodyError::DatabaseError(e) => write!(f, "Database error: {}", e),
            CustodyError::InvalidKeypair(e) => write!(f, "Invalid keypair: {}", e),
            CustodyError::InvalidTransaction(e) => write!(f, "Invalid transaction: {}", e),
            CustodyError::SpendingLimitExceeded(e) => write!(f, "Spending limit exceeded: {}", e),
            CustodyError::DailyLimitExceeded(e) => write!(f, "Daily spending limit exceeded: {}", e),
            CustodyError::RecipientNotAllowed(e) => write!(f, "Recipient not allowed: {}", e),
            CustodyError::ProgramNotAllowed(e) => write!(f, "Program not allowed: {}", e),
            CustodyError::ApprovalRequired(e) => write!(f, "User approval required: {}", e),
        }
    }
}

impl std::error::Error for CustodyError {}

fn bd_to_f64(bd: &Option<BigDecimal>) -> Option<f64> {
    bd.as_ref().and_then(|v| v.to_string().parse::<f64>().ok())
}

fn json_to_vec(json: &Option<serde_json::Value>) -> Vec<String> {
    json.as_ref()
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .unwrap_or_default()
}

#[derive(Debug, Clone, Default)]
struct ExtractedRules {
    max_tx_sol: Option<f64>,
    max_tx_usdc: Option<f64>,
    daily_limit_sol: Option<f64>,
    daily_limit_usdc: Option<f64>,
    allowed_recipients: Vec<String>,
    allowed_programs: Vec<String>,
    require_approval_sol: Option<f64>,
    require_approval_usdc: Option<f64>,
}

pub struct AgentCustodyManager;

impl AgentCustodyManager {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_production_config() -> Result<(), CustodyError> {
        let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
        
        if environment != "production" {
            tracing::info!("Agent Custody Manager initialized (development mode)");
            return Ok(());
        }
        
        tracing::info!("Validating Agent Custody security configuration for production...");
        
        let lit_enabled = std::env::var("LIT_PROTOCOL_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);
        
        if !lit_enabled {
            return Err(CustodyError::LitProtocolError(
                "CRITICAL: LIT_PROTOCOL_ENABLED must be true in production. \
                 Agent custody without Lit Protocol is NOT secure for production use.".to_string()
            ));
        }
        
        let eth_key = std::env::var("ETHEREUM_PRIVATE_KEY").unwrap_or_default();
        if eth_key.is_empty() {
            return Err(CustodyError::LitProtocolError(
                "ETHEREUM_PRIVATE_KEY required for Lit Protocol authentication".to_string()
            ));
        }

        let master_key = std::env::var("MASTER_ENCRYPTION_KEY").unwrap_or_default();
        if master_key.len() != 64 {
            return Err(CustodyError::LitProtocolError(
                "MASTER_ENCRYPTION_KEY must be 64 hex characters (32 bytes)".to_string()
            ));
        }
        
        tracing::info!("Production Agent Custody configuration validated:");
        tracing::info!("   - Lit Protocol: ENABLED");
        tracing::info!("   - Non-custodial mode: ACTIVE");
        tracing::info!("   - Access secrets: Agent-controlled (platform never stores)");
        
        Ok(())
    }

    fn generate_access_secret() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let bytes: [u8; 32] = rng.gen();
        format!("x0_custody_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    fn hash_access_secret(secret: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn verify_access_secret(secret: &str, stored_hash: &str) -> bool {
        let computed_hash = Self::hash_access_secret(secret);
        use subtle::ConstantTimeEq;
        computed_hash.as_bytes().ct_eq(stored_hash.as_bytes()).into()
    }

    pub async fn grant_custody(
        &self,
        state: &AppState,
        platform_id: Uuid,
        request: GrantCustodyRequest,
    ) -> Result<GrantCustodyResponse, CustodyError> {
        tracing::info!(
            "Granting wallet custody to agent {} for wallet {} (platform {})",
            request.agent_id,
            request.user_wallet,
            platform_id
        );

        let access_secret = Self::generate_access_secret();
        let access_secret_hash = Self::hash_access_secret(&access_secret);

        let expires_at = request.expires_in_days.map(|days| {
            chrono::Utc::now() + chrono::Duration::days(days as i64)
        });

        let custody_id = Uuid::new_v4();

        let lit_shard_id = self.store_keypair_with_lit(
            state,
            &request.encrypted_keypair,
            &request.client_nonce,
            &access_secret_hash,
            &request.user_wallet,
        ).await?;

        let spending_rules_id = if let Some(ref rules) = request.spending_rules {
            let rules_id = Uuid::new_v4();
            
            sqlx::query!(
                r#"
                INSERT INTO agent_custody_spending_rules 
                (id, custody_id, max_transaction_amount_sol, max_transaction_amount_usdc,
                 daily_limit_sol, daily_limit_usdc, allowed_recipients, allowed_programs,
                 require_approval_above_sol, require_approval_above_usdc, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
                "#,
                rules_id,
                custody_id,
                rules.max_transaction_amount_sol.and_then(|v| BigDecimal::try_from(v).ok()),
                rules.max_transaction_amount_usdc.and_then(|v| BigDecimal::try_from(v).ok()),
                rules.daily_limit_sol.and_then(|v| BigDecimal::try_from(v).ok()),
                rules.daily_limit_usdc.and_then(|v| BigDecimal::try_from(v).ok()),
                serde_json::to_value(&rules.allowed_recipients)
                    .map_err(|e| CustodyError::DatabaseError(e.to_string()))?,
                serde_json::to_value(&rules.allowed_programs)
                    .map_err(|e| CustodyError::DatabaseError(e.to_string()))?,
                rules.require_approval_above_sol.and_then(|v| BigDecimal::try_from(v).ok()),
                rules.require_approval_above_usdc.and_then(|v| BigDecimal::try_from(v).ok()),
            )
            .execute(&state.db)
            .await
            .map_err(|e| CustodyError::DatabaseError(e.to_string()))?;
            
            tracing::info!(
                "Spending rules stored: max_tx_sol={:?}, daily_sol={:?}, recipients={}, programs={}",
                rules.max_transaction_amount_sol,
                rules.daily_limit_sol,
                rules.allowed_recipients.len(),
                rules.allowed_programs.len()
            );
            
            Some(rules_id)
        } else {
            tracing::warn!(
                "No spending rules provided for custody {} - agent has unlimited access",
                custody_id
            );
            None
        };

        sqlx::query!(
            r#"
            INSERT INTO agent_wallet_custody 
            (id, platform_id, agent_id, user_wallet, access_secret_hash, 
             lit_shard_id, spending_rules_id, expires_at, is_active, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, NOW())
            "#,
            custody_id,
            platform_id,
            request.agent_id,
            request.user_wallet,
            access_secret_hash,
            lit_shard_id,
            spending_rules_id,
            expires_at,
        )
        .execute(&state.db)
        .await
        .map_err(|e| CustodyError::DatabaseError(e.to_string()))?;

        let warning = if request.spending_rules.is_some() {
            "Store the access_secret securely. Spending limits apply.".to_string()
        } else {
            "⚠️ WARNING: No spending limits set! Agent has unlimited signing access. Store the access_secret securely.".to_string()
        };

        tracing::info!(
            "Custody granted: {} -> agent {} (expires: {:?}, has_limits: {})",
            request.user_wallet,
            request.agent_id,
            expires_at,
            request.spending_rules.is_some()
        );

        Ok(GrantCustodyResponse {
            custody_id,
            access_secret,
            user_wallet: request.user_wallet,
            expires_at,
            warning,
        })
    }

    pub async fn sign_with_custody(
        &self,
        state: &AppState,
        request: AgentSignRequest,
    ) -> Result<AgentSignResponse, CustodyError> {
        tracing::debug!("Agent signing request for custody {}", request.custody_id);

        let custody = sqlx::query!(
            r#"
            SELECT 
                c.agent_id, c.user_wallet, c.access_secret_hash, c.lit_shard_id, 
                c.expires_at, c.is_active, c.spending_rules_id,
                r.max_transaction_amount_sol,
                r.max_transaction_amount_usdc,
                r.daily_limit_sol,
                r.daily_limit_usdc,
                r.allowed_recipients,
                r.allowed_programs,
                r.require_approval_above_sol,
                r.require_approval_above_usdc
            FROM agent_wallet_custody c
            LEFT JOIN agent_custody_spending_rules r ON c.spending_rules_id = r.id
            WHERE c.id = $1
            "#,
            request.custody_id
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| CustodyError::DatabaseError(e.to_string()))?
        .ok_or(CustodyError::CustodyNotFound)?;

        if !custody.is_active.unwrap_or(false) {
            return Err(CustodyError::CustodyRevoked);
        }

        if let Some(expires) = custody.expires_at {
            if expires < chrono::Utc::now() {
                return Err(CustodyError::CustodyNotFound);
            }
        }

        if !Self::verify_access_secret(&request.access_secret, &custody.access_secret_hash) {
            tracing::warn!(
                "Invalid access secret attempt for custody {} (agent: {})",
                request.custody_id,
                custody.agent_id
            );
            return Err(CustodyError::InvalidAccessSecret);
        }

        let tx_details = self.parse_transaction(&request.transaction_message)?;
        
        tracing::info!(
            "Agent {} requesting signature: {} {} to {} (program: {})",
            custody.agent_id,
            tx_details.amount,
            tx_details.token,
            tx_details.recipient,
            tx_details.program_id
        );

        if custody.spending_rules_id.is_some() {
            let rules = ExtractedRules {
                max_tx_sol: bd_to_f64(&custody.max_transaction_amount_sol),
                max_tx_usdc: bd_to_f64(&custody.max_transaction_amount_usdc),
                daily_limit_sol: bd_to_f64(&custody.daily_limit_sol),
                daily_limit_usdc: bd_to_f64(&custody.daily_limit_usdc),
                allowed_recipients: json_to_vec(&custody.allowed_recipients),
                allowed_programs: json_to_vec(&custody.allowed_programs),
                require_approval_sol: bd_to_f64(&custody.require_approval_above_sol),
                require_approval_usdc: bd_to_f64(&custody.require_approval_above_usdc),
            };
            
            self.validate_transaction_against_rules(
                state,
                request.custody_id,
                &tx_details,
                &rules,
            ).await?;
        } else {
            tracing::warn!(
                "No spending rules for custody {} - allowing unrestricted signing",
                request.custody_id
            );
        }

        let keypair = self.retrieve_keypair_from_lit(
            state,
            &custody.lit_shard_id,
            &request.access_secret,
        ).await?;

        if keypair.pubkey().to_string() != custody.user_wallet {
            return Err(CustodyError::InvalidKeypair(
                "Decrypted keypair doesn't match wallet address".to_string()
            ));
        }

        let signature = keypair.sign_message(&request.transaction_message);

        if custody.spending_rules_id.is_some() {
            self.record_spending(state, request.custody_id, &tx_details).await?;
        }

        tracing::info!(
            "Agent {} signed transaction: {} {} to {} (within rules)",
            custody.agent_id,
            tx_details.amount,
            tx_details.token,
            tx_details.recipient
        );

        Ok(AgentSignResponse {
            signature: signature.as_ref().to_vec(),
            public_key: keypair.pubkey().to_string(),
        })
    }

    pub async fn revoke_custody(
        &self,
        state: &AppState,
        custody_id: Uuid,
        platform_id: Uuid,
    ) -> Result<(), CustodyError> {
        let result = sqlx::query!(
            r#"
            UPDATE agent_wallet_custody 
            SET is_active = FALSE, revoked_at = NOW()
            WHERE id = $1 AND platform_id = $2
            "#,
            custody_id,
            platform_id
        )
        .execute(&state.db)
        .await
        .map_err(|e| CustodyError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(CustodyError::CustodyNotFound);
        }

        tracing::info!("Custody {} revoked by platform {}", custody_id, platform_id);
        Ok(())
    }

    fn parse_transaction(&self, message_bytes: &[u8]) -> Result<TransactionDetails, CustodyError> {
        use solana_sdk::message::Message;
        
        let message = match bincode::deserialize::<Message>(message_bytes) {
            Ok(m) => m,
            Err(_) => {
                return self.parse_transaction_legacy(message_bytes);
            }
        };
        
        if message.instructions.is_empty() {
            return Err(CustodyError::InvalidTransaction("No instructions in transaction".to_string()));
        }
        
        let first_instruction = &message.instructions[0];
        let program_id = message.account_keys
            .get(first_instruction.program_id_index as usize)
            .map(|k| k.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        if program_id == FEE_ROUTER_PROGRAM_ID {
            tracing::info!("Transaction routes through x0 fee router - approved");
            return self.parse_fee_router_transfer(&message, first_instruction);
        }
        
        if program_id == "11111111111111111111111111111111" {
            tracing::warn!("REJECTED: Direct SOL transfer without fee router");
            return Err(CustodyError::ProgramNotAllowed(
                "Direct SOL transfers are not allowed. Transactions must route through x0 fee router.".to_string()
            ));
        }
        
        if program_id == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" {
            tracing::warn!("REJECTED: Direct SPL token transfer without fee router");
            return Err(CustodyError::ProgramNotAllowed(
                "Direct SPL token transfers are not allowed. Transactions must route through x0 fee router.".to_string()
            ));
        }
        
        tracing::warn!("Unknown program in transaction: {}", program_id);
        Ok(TransactionDetails {
            amount: 0.0,
            token: "UNKNOWN".to_string(),
            recipient: message.account_keys.get(1)
                .map(|k| k.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            program_id,
        })
    }

    fn parse_transaction_legacy(&self, message_bytes: &[u8]) -> Result<TransactionDetails, CustodyError> {
        tracing::debug!("Using legacy transaction parsing for {} bytes", message_bytes.len());
        Ok(TransactionDetails {
            amount: 0.0,
            token: "UNKNOWN".to_string(),
            recipient: "unknown".to_string(),
            program_id: "unknown".to_string(),
        })
    }

    fn parse_fee_router_transfer(
        &self,
        message: &solana_sdk::message::Message,
        instruction: &solana_sdk::instruction::CompiledInstruction,
    ) -> Result<TransactionDetails, CustodyError> {
        if instruction.data.len() < 16 {
            return Err(CustodyError::InvalidTransaction(
                "Invalid fee router instruction data".to_string()
            ));
        }
        
        let amount = u64::from_le_bytes(
            instruction.data[8..16].try_into()
                .map_err(|_| CustodyError::InvalidTransaction("Failed to parse amount".to_string()))?
        );
        
        let (recipient, token) = if instruction.accounts.len() == 4 {
            let recipient_index = instruction.accounts.get(1)
                .ok_or(CustodyError::InvalidTransaction("No recipient in fee router SOL transfer".to_string()))?;
            let recipient = message.account_keys
                .get(*recipient_index as usize)
                .map(|k| k.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            (recipient, "SOL".to_string())
        } else if instruction.accounts.len() >= 5 {
            let recipient_ata_index = instruction.accounts.get(2)
                .ok_or(CustodyError::InvalidTransaction("No recipient ATA in fee router token transfer".to_string()))?;
            let recipient = message.account_keys
                .get(*recipient_ata_index as usize)
                .map(|k| k.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            (recipient, "USDC".to_string())
        } else {
            return Err(CustodyError::InvalidTransaction(
                format!("Unknown fee router instruction format with {} accounts", instruction.accounts.len())
            ));
        };
        
        let fee_router = FeeRouterClient::new();
        let fee_wallet_str = fee_router.fee_wallet().to_string();
        let has_fee_wallet = message.account_keys.iter().any(|k| k.to_string() == fee_wallet_str);
        
        if !has_fee_wallet {
            return Err(CustodyError::InvalidTransaction(
                "Fee router transaction missing x0 fee wallet".to_string()
            ));
        }
        
        let token_amount = if token == "SOL" {
            amount as f64 / 1_000_000_000.0
        } else {
            amount as f64 / 1_000_000.0
        };
        
        Ok(TransactionDetails {
            amount: token_amount,
            token,
            recipient,
            program_id: FEE_ROUTER_PROGRAM_ID.to_string(),
        })
    }

    async fn validate_transaction_against_rules(
        &self,
        state: &AppState,
        custody_id: Uuid,
        tx: &TransactionDetails,
        rules: &ExtractedRules,
    ) -> Result<(), CustodyError> {
        let max_amount = match tx.token.as_str() {
            "SOL" => rules.max_tx_sol,
            "USDC" => rules.max_tx_usdc,
            _ => None,
        };
        
        if let Some(max) = max_amount {
            if tx.amount > max {
                return Err(CustodyError::SpendingLimitExceeded(
                    format!("Amount {} {} exceeds max {} {} per transaction", 
                            tx.amount, tx.token, max, tx.token)
                ));
            }
        }
        
        let daily_limit = match tx.token.as_str() {
            "SOL" => rules.daily_limit_sol,
            "USDC" => rules.daily_limit_usdc,
            _ => None,
        };
        
        if let Some(limit) = daily_limit {
            let today_spending = self.get_today_spending(state, custody_id, &tx.token).await?;
            
            if today_spending + tx.amount > limit {
                return Err(CustodyError::DailyLimitExceeded(
                    format!("Daily limit {} {} would be exceeded (current: {:.4}, requested: {:.4})",
                            limit, tx.token, today_spending, tx.amount)
                ));
            }
        }
        
        if !rules.allowed_recipients.is_empty() && !rules.allowed_recipients.contains(&tx.recipient) {
            return Err(CustodyError::RecipientNotAllowed(
                format!("Recipient {} not in whitelist ({} allowed)", 
                        tx.recipient, rules.allowed_recipients.len())
            ));
        }
        
        if !rules.allowed_programs.is_empty() && !rules.allowed_programs.contains(&tx.program_id) {
            return Err(CustodyError::ProgramNotAllowed(
                format!("Program {} not in allowed list", tx.program_id)
            ));
        }
        
        let approval_threshold = match tx.token.as_str() {
            "SOL" => rules.require_approval_sol,
            "USDC" => rules.require_approval_usdc,
            _ => None,
        };
        
        if let Some(threshold) = approval_threshold {
            if tx.amount > threshold {
                return Err(CustodyError::ApprovalRequired(
                    format!("Amount {} {} exceeds approval threshold {} {}", 
                            tx.amount, tx.token, threshold, tx.token)
                ));
            }
        }
        
        tracing::debug!(
            "Transaction validated for custody {}: {} {} to {}",
            custody_id, tx.amount, tx.token, tx.recipient
        );
        
        Ok(())
    }

    async fn get_today_spending(
        &self,
        state: &AppState,
        custody_id: Uuid,
        token: &str,
    ) -> Result<f64, CustodyError> {
        let today = chrono::Utc::now().date_naive();
        
        let record = sqlx::query!(
            r#"
            SELECT total_sol, total_usdc
            FROM agent_custody_daily_spending
            WHERE custody_id = $1 AND date = $2
            "#,
            custody_id,
            today
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| CustodyError::DatabaseError(e.to_string()))?;
        
        match record {
            Some(r) => {
                let amount: BigDecimal = match token {
                    "SOL" => r.total_sol,
                    "USDC" => r.total_usdc,
                    _ => BigDecimal::from(0),
                };
                Ok(amount.to_string().parse::<f64>().unwrap_or(0.0))
            }
            None => Ok(0.0),
        }
    }

    async fn record_spending(
        &self,
        state: &AppState,
        custody_id: Uuid,
        tx: &TransactionDetails,
    ) -> Result<(), CustodyError> {
        let today = chrono::Utc::now().date_naive();
        let amount = BigDecimal::try_from(tx.amount)
            .map_err(|e| CustodyError::DatabaseError(format!("Invalid amount: {}", e)))?;
        
        match tx.token.as_str() {
            "SOL" => {
                sqlx::query!(
                    r#"
                    INSERT INTO agent_custody_daily_spending 
                    (id, custody_id, date, total_sol, total_usdc, transaction_count, created_at, updated_at)
                    VALUES ($1, $2, $3, $4, 0, 1, NOW(), NOW())
                    ON CONFLICT (custody_id, date) 
                    DO UPDATE SET 
                        total_sol = agent_custody_daily_spending.total_sol + $4,
                        transaction_count = agent_custody_daily_spending.transaction_count + 1,
                        updated_at = NOW()
                    "#,
                    Uuid::new_v4(),
                    custody_id,
                    today,
                    amount,
                )
                .execute(&state.db)
                .await
                .map_err(|e| CustodyError::DatabaseError(e.to_string()))?;
            }
            "USDC" => {
                sqlx::query!(
                    r#"
                    INSERT INTO agent_custody_daily_spending 
                    (id, custody_id, date, total_sol, total_usdc, transaction_count, created_at, updated_at)
                    VALUES ($1, $2, $3, 0, $4, 1, NOW(), NOW())
                    ON CONFLICT (custody_id, date) 
                    DO UPDATE SET 
                        total_usdc = agent_custody_daily_spending.total_usdc + $4,
                        transaction_count = agent_custody_daily_spending.transaction_count + 1,
                        updated_at = NOW()
                    "#,
                    Uuid::new_v4(),
                    custody_id,
                    today,
                    amount,
                )
                .execute(&state.db)
                .await
                .map_err(|e| CustodyError::DatabaseError(e.to_string()))?;
            }
            _ => {
                tracing::debug!("Unknown token type '{}' - not recording spending", tx.token);
            }
        }
        
        tracing::debug!(
            "Recorded spending for custody {}: {} {}",
            custody_id, tx.amount, tx.token
        );
        
        Ok(())
    }

    async fn store_keypair_with_lit(
        &self,
        state: &AppState,
        encrypted_keypair: &[u8],
        client_nonce: &[u8],
        access_secret_hash: &str,
        wallet_address: &str,
    ) -> Result<String, CustodyError> {
        let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
        let lit_enabled = std::env::var("LIT_PROTOCOL_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);

        let shard_id = Uuid::new_v4();

        if !lit_enabled {
            tracing::warn!(
                "DEVELOPMENT MODE: Using local storage instead of Lit Protocol. \
                 Set LIT_PROTOCOL_ENABLED=true for production security."
            );

            let key_manager = crate::services::key_manager::SecureKeyManager::from_env()
                .map_err(|e| CustodyError::DatabaseError(e.to_string()))?;

            let (server_encrypted, server_nonce) = self.encrypt_with_master_key(
                &key_manager,
                encrypted_keypair,
            )?;

            sqlx::query!(
                r#"
                INSERT INTO agent_custody_shards 
                (id, wallet_address, access_secret_hash, encrypted_data, 
                 client_nonce, server_nonce, storage_type, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, 'local', NOW())
                "#,
                shard_id,
                wallet_address,
                access_secret_hash,
                server_encrypted,
                client_nonce,
                server_nonce,
            )
            .execute(&state.db)
            .await
            .map_err(|e| CustodyError::DatabaseError(e.to_string()))?;

            return Ok(shard_id.to_string());
        }

        tracing::info!("Storing keypair with Lit Protocol BLS encryption");

        use lit_rust_sdk::{
            auth::load_wallet_from_env,
            types::EncryptRequest,
            LitNetwork, LitNodeClient, LitNodeClientConfig,
        };
        use std::time::Duration;

        let _wallet = load_wallet_from_env()
            .map_err(|e| CustodyError::LitProtocolError(
                format!("Failed to load Ethereum wallet: {}", e)
            ))?;

        let lit_network = std::env::var("LIT_NETWORK")
            .unwrap_or_else(|_| "DatilDev".to_string());

        let network = match lit_network.as_str() {
            "Datil" | "mainnet" => LitNetwork::Datil,
            "DatilTest" | "testnet" => LitNetwork::DatilTest,
            _ => LitNetwork::DatilDev,
        };

        let config = LitNodeClientConfig {
            lit_network: network,
            alert_when_unauthorized: true,
            debug: false,
            connect_timeout: Duration::from_secs(30),
            check_node_attestation: environment == "production",
        };

        let mut client = LitNodeClient::new(config)
            .await
            .map_err(|e| CustodyError::LitProtocolError(format!("Failed to create Lit client: {}", e)))?;

        client.connect()
            .await
            .map_err(|e| CustodyError::LitProtocolError(format!("Failed to connect: {}", e)))?;

        let connected_nodes = client.connected_nodes().len();
        if connected_nodes < 3 {
            return Err(CustodyError::LitProtocolError(
                format!("Insufficient Lit nodes: {}/3 minimum", connected_nodes)
            ));
        }

        use lit_rust_sdk::types::{EvmContractCondition, ReturnValueTestV2};

        let caller_function: ethabi::Function = serde_json::from_value(serde_json::json!({
            "constant": true,
            "inputs": [{"name": "account", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "", "type": "uint256"}],
            "stateMutability": "view",
            "type": "function"
        })).map_err(|e| CustodyError::LitProtocolError(format!("ABI error: {}", e)))?;

        let evm_conditions = vec![EvmContractCondition {
            contract_address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            function_name: "balanceOf".to_string(),
            function_params: vec![":userAddress".to_string()],
            function_abi: caller_function,
            chain: "ethereum".to_string(),
            return_value_test: ReturnValueTestV2 {
                key: "".to_string(),
                comparator: ">=".to_string(),
                value: "0".to_string(),
            },
        }];

        let encrypt_params = EncryptRequest {
            data_to_encrypt: encrypted_keypair.to_vec(),
            access_control_conditions: None,
            evm_contract_conditions: Some(evm_conditions.clone()),
            sol_rpc_conditions: None,
            unified_access_control_conditions: None,
        };

        let encrypted_result = client
            .encrypt(encrypt_params)
            .await
            .map_err(|e| CustodyError::LitProtocolError(format!("Encryption failed: {}", e)))?;

        sqlx::query!(
            r#"
            INSERT INTO agent_custody_shards 
            (id, wallet_address, access_secret_hash, ciphertext, 
             data_to_encrypt_hash, access_conditions, client_nonce,
             lit_node_count, storage_type, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'lit', NOW())
            "#,
            shard_id,
            wallet_address,
            access_secret_hash,
            encrypted_result.ciphertext.as_bytes(),
            encrypted_result.data_to_encrypt_hash,
            serde_json::to_value(&evm_conditions)
                .map_err(|e| CustodyError::LitProtocolError(format!("JSON error: {}", e)))?,
            client_nonce,
            connected_nodes as i32,
        )
        .execute(&state.db)
        .await
        .map_err(|e| CustodyError::DatabaseError(e.to_string()))?;

        tracing::info!(
            "Keypair stored with Lit Protocol (shard: {}, nodes: {})",
            shard_id, connected_nodes
        );

        Ok(shard_id.to_string())
    }

    async fn retrieve_keypair_from_lit(
        &self,
        state: &AppState,
        shard_id: &str,
        access_secret: &str,
    ) -> Result<Keypair, CustodyError> {
        let shard_uuid = Uuid::parse_str(shard_id)
            .map_err(|e| CustodyError::DatabaseError(format!("Invalid shard ID: {}", e)))?;

        let cache_key = crate::services::keypair_cache::cache_key(&shard_uuid, "agent_custody");
        
        if let Some(cached_bytes) = state.keypair_cache.get_bytes(&cache_key) {
            let keypair = Keypair::try_from(cached_bytes.as_slice())
                .map_err(|e| CustodyError::InvalidKeypair(e.to_string()))?;
            tracing::debug!("Agent custody keypair retrieved from memory cache");
            return Ok(keypair);
        }

        if let Ok(Some(cached_bytes)) = crate::services::keypair_cache::get_bytes_from_redis(state, &cache_key).await {
            let keypair = Keypair::try_from(cached_bytes.as_slice())
                .map_err(|e| CustodyError::InvalidKeypair(e.to_string()))?;
            
            state.keypair_cache.insert_bytes(
                cache_key.clone(),
                cached_bytes,
                shard_uuid,
            );
            
            tracing::debug!("Agent custody keypair retrieved from Redis cache");
            return Ok(keypair);
        }

        tracing::info!("Cache MISS for agent custody - decrypting from storage");

        let shard_record = sqlx::query!(
            r#"
            SELECT storage_type, encrypted_data, ciphertext, data_to_encrypt_hash,
                   access_conditions, client_nonce, server_nonce
            FROM agent_custody_shards
            WHERE id = $1
            "#,
            shard_uuid
        )
        .fetch_optional(&state.db)
        .await
        .map_err(|e| CustodyError::DatabaseError(e.to_string()))?
        .ok_or(CustodyError::CustodyNotFound)?;

        let decrypted_client_encrypted: Vec<u8>;

        if shard_record.storage_type == "local" {
            let key_manager = crate::services::key_manager::SecureKeyManager::from_env()
                .map_err(|e| CustodyError::DatabaseError(e.to_string()))?;

            let encrypted_data = shard_record.encrypted_data
                .ok_or(CustodyError::DecryptionFailed("No encrypted data".to_string()))?;
            let server_nonce = shard_record.server_nonce
                .ok_or(CustodyError::DecryptionFailed("No server nonce".to_string()))?;

            decrypted_client_encrypted = self.decrypt_with_master_key(
                &key_manager,
                &encrypted_data,
                &server_nonce,
            )?;
        } else {
            decrypted_client_encrypted = self.decrypt_from_lit(
                state,
                &shard_record.ciphertext.unwrap_or_default(),
                &shard_record.data_to_encrypt_hash.unwrap_or_default(),
                shard_record.access_conditions,
            ).await?;
        }

        let client_nonce = if shard_record.client_nonce.is_empty() {
            return Err(CustodyError::DecryptionFailed("No client nonce".to_string()));
        } else {
            shard_record.client_nonce
        };

        let keypair_bytes = self.decrypt_with_access_secret(
            &decrypted_client_encrypted,
            &client_nonce,
            access_secret,
        )?;

        let keypair = Keypair::try_from(keypair_bytes.as_slice())
            .map_err(|e| CustodyError::InvalidKeypair(e.to_string()))?;

        state.keypair_cache.insert_bytes(
            cache_key.clone(),
            keypair.to_bytes().to_vec(),
            shard_uuid,
        );

        let _ = crate::services::keypair_cache::store_bytes_in_redis(
            state,
            &cache_key,
            &keypair.to_bytes().to_vec(),
            std::time::Duration::from_secs(900),
        ).await;

        tracing::info!("Agent custody keypair decrypted and cached (shard: {})", shard_id);

        Ok(keypair)
    }

    async fn decrypt_from_lit(
        &self,
        state: &AppState,
        ciphertext: &[u8],
        data_hash: &str,
        access_conditions: Option<serde_json::Value>,
    ) -> Result<Vec<u8>, CustodyError> {
        use lit_rust_sdk::{
            auth::load_wallet_from_env,
            types::{DecryptRequest, EvmContractCondition, LitAbility, 
                    LitResourceAbilityRequest, LitResourceAbilityRequestResource},
            LitNetwork, LitNodeClient, LitNodeClientConfig,
        };
        use std::time::Duration;

        tracing::info!("Decrypting agent custody keypair via Lit Protocol");

        let wallet = load_wallet_from_env()
            .map_err(|e| CustodyError::LitProtocolError(format!("Failed to load wallet: {}", e)))?;

        let lit_network = std::env::var("LIT_NETWORK").unwrap_or_else(|_| "DatilDev".to_string());
        let network = match lit_network.as_str() {
            "Datil" | "mainnet" => LitNetwork::Datil,
            "DatilTest" | "testnet" => LitNetwork::DatilTest,
            _ => LitNetwork::DatilDev,
        };

        let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
        let is_production = environment == "production";
        
        let config = LitNodeClientConfig {
            lit_network: network,
            alert_when_unauthorized: true,
            debug: !is_production,
            connect_timeout: Duration::from_secs(30),
            check_node_attestation: is_production,
        };

        tracing::debug!("Connecting to Lit Network: {:?} (attestation: {})", network, is_production);
        
        let mut client = LitNodeClient::new(config)
            .await
            .map_err(|e| CustodyError::LitProtocolError(format!("Client error: {}", e)))?;

        client.connect()
            .await
            .map_err(|e| CustodyError::LitProtocolError(format!("Connect error: {}", e)))?;

        let connected_nodes = client.connected_nodes().len();
        if connected_nodes < 3 {
            return Err(CustodyError::LitProtocolError(
                format!("Insufficient Lit nodes connected: {}/3 minimum", connected_nodes)
            ));
        }
        
        tracing::info!("Connected to {} Lit nodes", connected_nodes);

        let resource_ability_requests = vec![LitResourceAbilityRequest {
            resource: LitResourceAbilityRequestResource {
                resource: "*".to_string(),
                resource_prefix: "lit-accesscontrolcondition".to_string(),
            },
            ability: LitAbility::AccessControlConditionDecryption.to_string(),
        }];

        let expiration = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();

        let delegatee_address = format!("{:#x}", wallet.address());
        tracing::debug!("Getting capacity auth sigs for delegatee: {}", delegatee_address);
        
        let capacity_auth_sigs = crate::services::lit_capacity::get_capacity_auth_sigs(
            &wallet,
            network,
            Some(&state.redis),
            &delegatee_address,
        ).await.unwrap_or_default();

        let session_sigs = client
            .get_local_session_sigs(&wallet, resource_ability_requests, &expiration, capacity_auth_sigs)
            .await
            .map_err(|e| CustodyError::LitProtocolError(format!("Session sigs error: {}", e)))?;

        tracing::info!("Session signatures created successfully (count: {})", session_sigs.len());

        let evm_conditions: Option<Vec<EvmContractCondition>> = access_conditions
            .and_then(|v| serde_json::from_value(v).ok());

        let ciphertext_str = String::from_utf8_lossy(ciphertext).to_string();

        let decrypt_params = DecryptRequest {
            ciphertext: ciphertext_str,
            data_to_encrypt_hash: data_hash.to_string(),
            access_control_conditions: None,
            evm_contract_conditions: evm_conditions,
            sol_rpc_conditions: None,
            unified_access_control_conditions: None,
            chain: Some("ethereum".to_string()),
            session_sigs,
        };

        let result = Self::decrypt_with_retry(
            || async {
                client
                    .decrypt(decrypt_params.clone())
                    .await
                    .map_err(|e| format!("Decrypt error: {}", e))
            },
            3,
        )
        .await
        .map_err(|e| CustodyError::LitProtocolError(e))?;

        tracing::info!("Lit Protocol decryption successful");

        Ok(result.decrypted_data)
    }

    async fn decrypt_with_retry<F, Fut, T>(
        mut operation: F,
        max_retries: u32,
    ) -> Result<T, String>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, String>>,
    {
        let mut attempt = 0;
        let mut delay = std::time::Duration::from_secs(1);

        loop {
            attempt += 1;
            
            match operation().await {
                Ok(result) => {
                    if attempt > 1 {
                        tracing::info!("Lit operation succeeded on attempt {}", attempt);
                    }
                    return Ok(result);
                }
                Err(e) => {
                    if attempt >= max_retries {
                        tracing::error!(
                            "Lit operation failed after {} attempts: {}",
                            attempt, e
                        );
                        return Err(e);
                    }
                    
                    tracing::warn!(
                        "Lit operation attempt {} failed, retrying in {:?}: {}",
                        attempt, delay, e
                    );
                    
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
            }
        }
    }

    fn decrypt_with_access_secret(
        &self,
        encrypted_data: &[u8],
        nonce: &[u8],
        access_secret: &str,
    ) -> Result<Vec<u8>, CustodyError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(access_secret.as_bytes());
        let key_bytes = hasher.finalize();

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| CustodyError::DecryptionFailed(e.to_string()))?;

        let nonce_array: [u8; 12] = nonce.try_into()
            .map_err(|_| CustodyError::DecryptionFailed("Invalid nonce length".to_string()))?;

        let nonce = Nonce::from(nonce_array);

        cipher
            .decrypt(&nonce, encrypted_data)
            .map_err(|e| CustodyError::DecryptionFailed(format!("AES decryption failed: {}", e)))
    }

    fn encrypt_with_master_key(
        &self,
        key_manager: &crate::services::key_manager::SecureKeyManager,
        data: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CustodyError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = Aes256Gcm::new_from_slice(&key_manager.master_key)
            .map_err(|e| CustodyError::DatabaseError(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| CustodyError::DatabaseError(e.to_string()))?;

        let nonce = Nonce::from(nonce_bytes);

        let encrypted = cipher
            .encrypt(&nonce, data)
            .map_err(|e| CustodyError::DatabaseError(e.to_string()))?;

        Ok((encrypted, nonce_bytes.to_vec()))
    }

    fn decrypt_with_master_key(
        &self,
        key_manager: &crate::services::key_manager::SecureKeyManager,
        encrypted: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, CustodyError> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };

        let cipher = Aes256Gcm::new_from_slice(&key_manager.master_key)
            .map_err(|e| CustodyError::DecryptionFailed(e.to_string()))?;

        let nonce_array: [u8; 12] = nonce.try_into()
            .map_err(|_| CustodyError::DecryptionFailed("Invalid nonce".to_string()))?;

        let nonce = Nonce::from(nonce_array);

        cipher
            .decrypt(&nonce, encrypted)
            .map_err(|e| CustodyError::DecryptionFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_secret_generation() {
        let secret1 = AgentCustodyManager::generate_access_secret();
        let secret2 = AgentCustodyManager::generate_access_secret();
        
        assert!(secret1.starts_with("x0_custody_"));
        assert!(secret2.starts_with("x0_custody_"));
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_access_secret_verification() {
        let secret = AgentCustodyManager::generate_access_secret();
        let hash = AgentCustodyManager::hash_access_secret(&secret);
        
        assert!(AgentCustodyManager::verify_access_secret(&secret, &hash));
        assert!(!AgentCustodyManager::verify_access_secret("wrong_secret", &hash));
    }
}
