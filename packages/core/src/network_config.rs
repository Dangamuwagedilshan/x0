use serde::{Deserialize, Serialize};
use std::str::FromStr;
use solana_sdk::pubkey::Pubkey;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyMode {
    Test,
    Live,
}

impl ApiKeyMode {
    pub fn from_api_key(api_key: &str) -> Option<Self> {
        if api_key.starts_with("x0_test_") {
            Some(ApiKeyMode::Test)
        } else if api_key.starts_with("x0_live_") {
            Some(ApiKeyMode::Live)
        } else if api_key.starts_with("x0_agent_") {
            Some(ApiKeyMode::Test)
        } else {
            None
        }
    }
    
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "test" => ApiKeyMode::Test,
            _ => ApiKeyMode::Live,
        }
    }
    
    pub fn is_agent_key(api_key: &str) -> bool {
        api_key.starts_with("x0_agent_")
    }

    pub fn prefix(&self) -> &'static str {
        match self {
            ApiKeyMode::Test => "x0_test_",
            ApiKeyMode::Live => "x0_live_",
        }
    }

    pub fn network_name(&self) -> &'static str {
        match self {
            ApiKeyMode::Test => "devnet",
            ApiKeyMode::Live => "mainnet-beta",
        }
    }
}

impl std::fmt::Display for ApiKeyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiKeyMode::Test => write!(f, "test"),
            ApiKeyMode::Live => write!(f, "live"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub mode: ApiKeyMode,
    pub rpc_urls: Vec<String>,
    pub usdc_mint: Pubkey,
    pub usdt_mint: Pubkey,
    pub network_name: String,
}

impl NetworkConfig {
    pub fn from_mode(mode: ApiKeyMode) -> Result<Self, NetworkConfigError> {
        match mode {
            ApiKeyMode::Test => Self::devnet(),
            ApiKeyMode::Live => Self::mainnet(),
        }
    }

    fn devnet() -> Result<Self, NetworkConfigError> {
        let rpc_urls = Self::parse_rpc_urls("DEVNET_RPC_URLS", "DEVNET_RPC_URL")?
            .unwrap_or_else(|| vec!["https://api.devnet.solana.com".to_string()]);

        let usdc_mint = Self::parse_pubkey(
            "DEVNET_USDC_MINT",
            "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        )?;

        let usdt_mint = Self::parse_pubkey(
            "DEVNET_USDT_MINT",
            "EgEHQxJ8aPe7bsrR88zG3w3Y9N5CZg3w8d1K1CZg3w8d",
        )?;

        Ok(NetworkConfig {
            mode: ApiKeyMode::Test,
            rpc_urls,
            usdc_mint,
            usdt_mint,
            network_name: "devnet".to_string(),
        })
    }

    fn mainnet() -> Result<Self, NetworkConfigError> {
        let rpc_urls = Self::parse_rpc_urls("MAINNET_RPC_URLS", "MAINNET_RPC_URL")?
            .unwrap_or_else(|| vec![
                "https://mainnet.helius-rpc.com/?api-key=272cf617-7bc7-4400-bbbc-24813f492a6c".to_string(),
                "https://api.mainnet-beta.solana.com".to_string()
            ]);

        let usdc_mint = Self::parse_pubkey(
            "MAINNET_USDC_MINT",
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        )?;

        let usdt_mint = Self::parse_pubkey(
            "MAINNET_USDT_MINT",
            "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
        )?;

        Ok(NetworkConfig {
            mode: ApiKeyMode::Live,
            rpc_urls,
            usdc_mint,
            usdt_mint,
            network_name: "mainnet-beta".to_string(),
        })
    }

    fn parse_rpc_urls(
        multi_key: &str,
        single_key: &str,
    ) -> Result<Option<Vec<String>>, NetworkConfigError> {
        if let Ok(urls) = std::env::var(multi_key) {
            let parsed: Vec<String> = urls
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            
            if parsed.is_empty() {
                return Ok(None);
            }
            return Ok(Some(parsed));
        }

        if let Ok(url) = std::env::var(single_key) {
            return Ok(Some(vec![url]));
        }

        Ok(None)
    }

    fn parse_pubkey(key: &str, default: &str) -> Result<Pubkey, NetworkConfigError> {
        let address = std::env::var(key).unwrap_or_else(|_| default.to_string());
        Pubkey::from_str(&address).map_err(|e| NetworkConfigError::InvalidPubkey {
            key: key.to_string(),
            value: address,
            error: e.to_string(),
        })
    }

    pub fn primary_rpc_url(&self) -> &str {
        &self.rpc_urls[0]
    }

    pub fn get_token_mint(&self, token: &str) -> Option<Pubkey> {
        match token.to_lowercase().as_str() {
            "usdc" => Some(self.usdc_mint),
            "usdt" => Some(self.usdt_mint),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum NetworkConfigError {
    MissingEnvVar(String),
    InvalidPubkey {
        key: String,
        value: String,
        error: String,
    },
}

impl std::fmt::Display for NetworkConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkConfigError::MissingEnvVar(var) => {
                write!(f, "Missing required environment variable: {}", var)
            }
            NetworkConfigError::InvalidPubkey { key, value, error } => {
                write!(f, "Invalid Pubkey for {}: {} - {}", key, value, error)
            }
        }
    }
}

impl std::error::Error for NetworkConfigError {}
