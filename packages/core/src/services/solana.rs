//! Solana utility functions for SDK and internal use
#![allow(dead_code)] // SDK utilities - available for platform integrations

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

use crate::{
    network_config::ApiKeyMode,
    AppState,
};

pub const DEVNET_USDC_MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
pub const MAINNET_USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub const DEVNET_USDT_MINT: &str = "EgEHQxJ8aPe7bsrR88zG3w3Y9N5CZg3w8d1K1CZg3w8d";
pub const MAINNET_USDT_MINT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SupportedToken {
    Usdc,
    Usdt,
    Sol,
}

impl SupportedToken {
    pub fn get_mint_address(&self, network: &str) -> Option<&'static str> {
        match (self, network.to_lowercase().as_str()) {
            (SupportedToken::Usdc, "mainnet" | "mainnet-beta") => Some(MAINNET_USDC_MINT),
            (SupportedToken::Usdc, _) => Some(DEVNET_USDC_MINT),
            (SupportedToken::Usdt, "mainnet" | "mainnet-beta") => Some(MAINNET_USDT_MINT),
            (SupportedToken::Usdt, _) => Some(DEVNET_USDT_MINT),
            (SupportedToken::Sol, _) => None,
        }
    }

    pub fn decimals(&self) -> u8 {
        match self {
            SupportedToken::Usdc | SupportedToken::Usdt => 6,
            SupportedToken::Sol => 9,
        }
    }

    pub fn symbol(&self) -> &str {
        match self {
            SupportedToken::Sol => "SOL",
            SupportedToken::Usdc => "USDC",
            SupportedToken::Usdt => "USDT",
        }
    }
}

pub fn get_usdc_mint_for_network(network: &str) -> &'static str {
    match network.to_lowercase().as_str() {
        "mainnet" | "mainnet-beta" => MAINNET_USDC_MINT,
        _ => DEVNET_USDC_MINT,
    }
}

pub async fn fetch_sol_price() -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let response = reqwest::get(
        "https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd",
    )
    .await?
    .json::<serde_json::Value>()
    .await?;

    if let Some(price) = response["solana"]["usd"].as_f64() {
        tracing::debug!("Fetched SOL price: ${}", price);
        return Ok(price);
    }

    Err("Failed to fetch SOL price".into())
}

pub fn validate_solana_address(address: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if address.len() < 32 || address.len() > 44 {
        return Err("Invalid address length".into());
    }

    let _ = solana_sdk::pubkey::Pubkey::from_str(address)
        .map_err(|_| "Invalid Solana address format")?;

    Ok(())
}

pub async fn get_wallet_balance(
    state: &AppState,
    wallet: &str,
    mode: ApiKeyMode,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    validate_solana_address(wallet)?;

    let network_config = state.get_network(&mode);
    let rpc_url = network_config.primary_rpc_url();

    let client = reqwest::Client::new();
    let response: Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [wallet]
        }))
        .send()
        .await?
        .json()
        .await?;

    let balance = response["result"]["value"]
        .as_u64()
        .ok_or("Failed to parse balance")?;

    Ok(balance)
}

pub async fn get_token_balance(
    state: &AppState,
    wallet: &str,
    token: SupportedToken,
    mode: ApiKeyMode,
) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    validate_solana_address(wallet)?;

    let network_config = state.get_network(&mode);
    let network = mode.network_name();
    let rpc_url = network_config.primary_rpc_url();

    let mint_address = token
        .get_mint_address(network)
        .ok_or("Token not supported on this network")?;

    let wallet_pubkey = solana_sdk::pubkey::Pubkey::from_str(wallet)?;
    let mint_pubkey = solana_sdk::pubkey::Pubkey::from_str(mint_address)?;
    let ata = spl_associated_token_account::get_associated_token_address(&wallet_pubkey, &mint_pubkey);

    let client = reqwest::Client::new();
    let response: Value = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenAccountBalance",
            "params": [ata.to_string()]
        }))
        .send()
        .await?
        .json()
        .await?;

    if response.get("error").is_some() {
        return Ok(0.0);
    }

    let balance = response["result"]["value"]["uiAmount"]
        .as_f64()
        .unwrap_or(0.0);

    Ok(balance)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_token_mint_addresses() {
        assert_eq!(
            SupportedToken::Usdc.get_mint_address("mainnet"),
            Some(MAINNET_USDC_MINT)
        );
        assert_eq!(
            SupportedToken::Usdc.get_mint_address("devnet"),
            Some(DEVNET_USDC_MINT)
        );
        assert_eq!(SupportedToken::Sol.get_mint_address("mainnet"), None);
    }

    #[test]
    fn test_validate_solana_address() {
        assert!(validate_solana_address("So11111111111111111111111111111111111111112").is_ok());
        assert!(validate_solana_address("invalid").is_err());
        assert!(validate_solana_address("").is_err());
    }

    #[test]
    fn test_token_decimals() {
        assert_eq!(SupportedToken::Usdc.decimals(), 6);
        assert_eq!(SupportedToken::Usdt.decimals(), 6);
        assert_eq!(SupportedToken::Sol.decimals(), 9);
    }
}
