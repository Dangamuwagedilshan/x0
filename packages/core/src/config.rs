use std::str::FromStr;
use solana_sdk::pubkey::Pubkey;

#[derive(Debug)]
pub enum ConfigError {
    MissingSeed,
    InvalidSeedLength,
    InvalidRecipientWallet,
    MissingRequiredEnvVar(String),
    InvalidUrl(String),
    InvalidConfiguration(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ConfigError::MissingSeed => write!(f, "X0_MASTER_SEED is required"),
            ConfigError::InvalidSeedLength => write!(f, "X0_MASTER_SEED must be at least 32 characters"),
            ConfigError::InvalidRecipientWallet => write!(f, "RECIPIENT_WALLET is not a valid Solana address"),
            ConfigError::MissingRequiredEnvVar(var) => write!(f, "Required environment variable {} is missing", var),
            ConfigError::InvalidUrl(url) => write!(f, "Invalid URL: {}", url),
            ConfigError::InvalidConfiguration(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub solana_rpc_urls: Vec<String>, 
    pub recipient_wallet: String,
    pub wallet_keypair_path: Option<String>, 
    pub frontend_url: String,
    pub dashboard_url: String,
    pub base_url: String,
    pub port: u16,
    pub usdc_mint: String,  
    pub solana_network: String,
    pub platform_wallet_dir: String,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        dotenvy::dotenv().ok();

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| ConfigError::MissingRequiredEnvVar("DATABASE_URL".to_string()))?;
        
        let recipient_wallet = std::env::var("RECIPIENT_WALLET")
            .map_err(|_| ConfigError::MissingRequiredEnvVar("RECIPIENT_WALLET".to_string()))?;

        Pubkey::from_str(&recipient_wallet)
            .map_err(|_| ConfigError::InvalidRecipientWallet)?;
        
        let solana_network = std::env::var("SOLANA_NETWORK")
            .unwrap_or_else(|_| "devnet".to_string());
        
        let mut solana_rpc_urls = if let Ok(urls) = std::env::var("SOLANA_RPC_URLS") {
            urls.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else if let Ok(single_url) = std::env::var("SOLANA_RPC_URL") {
            vec![single_url]
        } else {
            vec![]
        };
        
        if solana_network == "mainnet" || solana_network == "mainnet-beta" {
            let fallback_endpoints = vec![
                "https://api.mainnet-beta.solana.com".to_string(),
            ];
            
            for fallback in fallback_endpoints {
                if !solana_rpc_urls.iter().any(|url| url.contains(&fallback)) {
                    solana_rpc_urls.push(fallback);
                }
            }
        } else {
            if solana_rpc_urls.is_empty() {
                solana_rpc_urls.push("https://api.devnet.solana.com".to_string());
            }
        }
            
        let usdc_mint = std::env::var("USDC_MINT")
            .unwrap_or_else(|_| {
                if solana_network == "mainnet" || solana_network == "mainnet-beta" {
                    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string()
                } else {
                    "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU".to_string()
                }
            });
        
        let frontend_url = std::env::var("FRONTEND_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());
        
        let config = Self {
            database_url,
            solana_rpc_urls,
            recipient_wallet,
            wallet_keypair_path: std::env::var("WALLET_KEYPAIR_PATH").ok(),
            dashboard_url: std::env::var("DASHBOARD_URL")
                .unwrap_or_else(|_| frontend_url.clone()),
            frontend_url,
            base_url: std::env::var("BASE_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .map_err(|_| ConfigError::MissingRequiredEnvVar("PORT must be valid number".to_string()))?,
            usdc_mint,    
            solana_network, 
            platform_wallet_dir: std::env::var("PLATFORM_WALLET_DIR")
                .unwrap_or_else(|_| "./secure/platform_wallets".to_string()),
        };

        config.validate()?;
        
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        for url in &self.solana_rpc_urls {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(ConfigError::InvalidUrl(url.clone()));
            }
        }

        if self.recipient_wallet == "11111111111111111111111111111112" {
            return Err(ConfigError::InvalidRecipientWallet);
        }

        let is_mainnet = self.solana_network.to_lowercase().contains("mainnet");
        let mainnet_usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let devnet_usdc = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";

        if is_mainnet && self.usdc_mint == devnet_usdc {
            tracing::error!(
                "CRITICAL CONFIGURATION ERROR: Running on MAINNET but USDC_MINT is set to DEVNET address!"
            );
            tracing::error!(
                "   Current USDC_MINT: {} (DEVNET)",
                self.usdc_mint
            );
            tracing::error!(
                "   Expected for MAINNET: {}",
                mainnet_usdc
            );
            tracing::error!("   ALL PAYMENTS WILL FAIL until this is fixed!");
            tracing::error!("   Update your .env file and restart the server.");
            return Err(ConfigError::InvalidConfiguration(
                format!(
                    "USDC_MINT mismatch: Using devnet USDC ({}) on mainnet. Expected: {}",
                    devnet_usdc, mainnet_usdc
                )
            ));
        }

        if !is_mainnet && self.usdc_mint == mainnet_usdc {
            tracing::warn!(
                "  Network is {} but USDC_MINT is set to MAINNET address. This will cause payment failures.",
                self.solana_network
            );
            tracing::warn!(
                "   Current USDC_MINT: {} (MAINNET)",
                self.usdc_mint
            );
            tracing::warn!(
                "   Expected for DEVNET: {}",
                devnet_usdc
            );
        }

        if let Ok(master_seed) = std::env::var("X0_MASTER_SEED") {
            if master_seed.len() < 32 {
                return Err(ConfigError::InvalidSeedLength);
            }
        } else {
            tracing::warn!("X0_MASTER_SEED not set - platform wallet generation will fail");
        }
        
        Ok(())
    }
}