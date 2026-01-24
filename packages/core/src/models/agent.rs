use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use bigdecimal::BigDecimal;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyScope {
    Full,
    ReadOnly,
    CreatePayments,
    ManageSessions,
    ReadAnalytics,
}

impl ApiKeyScope {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "full" => Some(Self::Full),
            "read_only" => Some(Self::ReadOnly),
            "create_payments" => Some(Self::CreatePayments),
            "manage_sessions" => Some(Self::ManageSessions),
            "read_analytics" => Some(Self::ReadAnalytics),
            _ => None,
        }
    }

    #[allow(dead_code)] // Future: scope-based authorization
    pub fn allows(&self, operation: &str) -> bool {
        if matches!(self, Self::Full) {
            return true;
        }
        
        match operation {
            "read" => true,
            "create_payment" => matches!(self, Self::CreatePayments),
            "manage_session" => matches!(self, Self::ManageSessions),
            "read_analytics" => matches!(self, Self::ReadAnalytics),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionLimits {
    pub max_per_transaction: Option<f64>,
    pub max_per_day: Option<f64>,
    pub max_per_week: Option<f64>,
    pub max_per_month: Option<f64>,
    pub require_approval_above: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAgentSessionRequest {
    pub agent_id: String,
    pub agent_name: Option<String>,
    pub user_wallet: String,
    pub limits: Option<SessionLimits>,
    pub allowed_recipients: Option<Vec<Uuid>>,
    pub duration_hours: Option<i64>,
    pub metadata: Option<serde_json::Value>,
    #[serde(default, alias = "pkp_enabled", alias = "crypto_enforced")]
    pub mint_pkp: Option<bool>,
    pub spending_limit_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AgentSession {
    pub id: Uuid,
    pub platform_id: Uuid,
    pub session_token: String,
    pub agent_id: String,
    pub agent_name: Option<String>,
    pub user_wallet: String,
    
    pub max_per_transaction: Option<BigDecimal>,
    pub max_per_day: Option<BigDecimal>,
    pub max_per_week: Option<BigDecimal>,
    pub max_per_month: Option<BigDecimal>,
    pub require_approval_above: Option<BigDecimal>,
    
    pub spent_today: Option<BigDecimal>,
    pub spent_this_week: Option<BigDecimal>,
    pub spent_this_month: Option<BigDecimal>,
    pub last_reset_daily: Option<DateTime<Utc>>,
    pub last_reset_weekly: Option<DateTime<Utc>>,
    pub last_reset_monthly: Option<DateTime<Utc>>,
    
    pub allowed_recipients: serde_json::Value,
    pub is_active: Option<bool>,
    pub metadata: serde_json::Value,
    
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    
    pub allowed_platforms: Option<serde_json::Value>,
    
    pub attestation_public_key: Option<String>,
    pub attestation_signature: Option<String>,
    pub attestation_nonce: Option<i64>,
    
    pub lit_encrypted_keypair_id: Option<Uuid>,
    pub spending_counter_address: Option<String>,
    pub spending_counter_nonce: Option<i64>,
    #[serde(rename = "mint_pkp", alias = "crypto_enforced", alias = "pkp_enabled")]
    pub crypto_enforced: Option<bool>,
    pub lit_access_conditions: Option<serde_json::Value>,
    
    pub pkp_public_key: Option<String>,
    pub lit_action_ipfs_cid: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentSessionResponse {
    pub id: Uuid,
    pub session_token: String,
    pub agent_id: String,
    pub agent_name: Option<String>,
    pub user_wallet: String,
    pub limits: SessionLimits,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub remaining_today: f64,
    pub remaining_this_week: f64,
    pub remaining_this_month: f64,
    #[serde(default, alias = "pkp_enabled", alias = "crypto_enforced")]
    pub mint_pkp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkp_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfile {
    pub location_country: Option<String>,
    pub wallet_history: Option<serde_json::Value>,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PppConfig {
    #[serde(default = "default_ppp_enabled")]
    pub enabled: bool,
    pub min_factor: Option<f64>,
    pub max_factor: Option<f64>,
    pub floor_price: Option<f64>,
    pub ceiling_price: Option<f64>,
    pub max_discount_percent: Option<f64>,
    pub extra_discount_percent: Option<f64>,
    pub custom_reasoning: Option<String>,
}

impl Default for PppConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_factor: None,
            max_factor: None,
            floor_price: None,
            ceiling_price: None,
            max_discount_percent: None,
            extra_discount_percent: None,
            custom_reasoning: None,
        }
    }
}

fn default_ppp_enabled() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PricingSuggestionRequest {
    pub agent_id: String,
    pub product_id: Option<String>,
    pub base_price: f64,
    pub currency: Option<String>,
    pub user_profile: Option<UserProfile>,
    pub ppp_config: Option<PppConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PricingSuggestionResponse {
    pub suggested_amount: f64,
    pub min_amount: f64,
    pub max_amount: f64,
    pub currency: String,
    pub reasoning: String,
    pub ppp_adjusted: bool,
    pub adjustment_factor: Option<f64>,
}


