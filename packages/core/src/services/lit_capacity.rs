use alloy::{
    network::EthereumWallet,
    primitives::U256,
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use chrono::{Datelike, TimeZone};
use lit_rust_sdk::{
    auth::{load_wallet_from_env, EthWalletProvider},
    blockchain::{resolve_address, Contract, RateLimitNFT},
    types::AuthSig,
    LitNetwork,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRateLimitNft {
    pub token_id: String,
    pub expires_at: i64,
    pub network: String,
}

pub async fn get_or_mint_rate_limit_nft(
    network: LitNetwork,
    redis_conn: Option<&redis::aio::ConnectionManager>,
    duration_days: u64,
) -> Result<String, String> {
    let env_key = format!("LIT_CAPACITY_TOKEN_ID_{:?}", network).to_uppercase();
    if let Ok(token_id) = std::env::var(&env_key) {
        if !token_id.is_empty() {
            tracing::info!(
                "Using pre-configured Capacity Credit token ID from {}: {}",
                env_key,
                token_id
            );
            return Ok(token_id);
        }
    }
    
    let cache_key = format!("lit:rate_limit_nft:{:?}", network);
    
    if let Some(redis_conn) = redis_conn {
        let mut conn = redis_conn.clone();
        if let Ok(Some(cached_json)) = redis::cmd("GET")
            .arg(&cache_key)
            .query_async::<_, Option<String>>(&mut conn)
            .await
        {
            if let Ok(cached) = serde_json::from_str::<CachedRateLimitNft>(&cached_json) {
                let now = chrono::Utc::now().timestamp();
                
                if cached.expires_at > now {
                    let days_remaining = (cached.expires_at - now) / 86400;
                    tracing::info!(
                        "Using cached Rate Limit NFT: {} (expires in {} days)",
                        cached.token_id,
                        days_remaining
                    );
                    return Ok(cached.token_id);
                } else {
                    tracing::warn!("Cached Rate Limit NFT expired, will mint new one");
                }
            }
        }
    }
    
    tracing::info!("No cached or pre-configured Rate Limit NFT found, minting new one...");
    
    let token_id = mint_rate_limit_nft(network, duration_days).await?;
    
    if let Some(redis_conn) = redis_conn {
        let mut conn = redis_conn.clone();
        let future_date = chrono::Utc::now() + chrono::Duration::days(duration_days as i64);
        let midnight = chrono::Utc
            .with_ymd_and_hms(
                future_date.year(),
                future_date.month(),
                future_date.day(),
                0,
                0,
                0,
            )
            .single()
            .unwrap();
        
        let cached = CachedRateLimitNft {
            token_id: token_id.clone(),
            expires_at: midnight.timestamp(),
            network: format!("{:?}", network),
        };
        
        let cached_json = serde_json::to_string(&cached)
            .map_err(|e| format!("Failed to serialize cached NFT: {}", e))?;
        
        let ttl_seconds = (duration_days * 86400) + 3600;
        
        let _: Result<(), _> = redis::cmd("SETEX")
            .arg(&cache_key)
            .arg(ttl_seconds)
            .arg(&cached_json)
            .query_async(&mut conn)
            .await;
        
        tracing::info!("Cached Rate Limit NFT: {} (expires in {} days)", token_id, duration_days);
    }
    
    Ok(token_id)
}

async fn mint_rate_limit_nft(
    network: LitNetwork,
    duration_days: u64,
) -> Result<String, String> {
    tracing::info!("Minting Rate Limit NFT for {} days on {:?}...", duration_days, network);
    
    let wallet = load_wallet_from_env()
        .map_err(|e| format!("Failed to load Ethereum wallet (set ETHEREUM_PRIVATE_KEY): {}", e))?;
    
    tracing::info!("Minting with wallet address: {}", wallet.address());
    
    let rate_limit_nft_address = resolve_address(Contract::RateLimitNFT, network)
        .await
        .map_err(|e| format!("Failed to resolve Rate Limit NFT address: {}", e))?;
    
    tracing::info!("Rate Limit NFT contract: {}", rate_limit_nft_address);
    
    let ethereum_wallet = EthereumWallet::from(wallet.clone());
    let provider = ProviderBuilder::new()
        .wallet(ethereum_wallet)
        .connect(network.rpc_url())
        .await
        .map_err(|e| format!("Failed to connect to Ethereum provider: {}", e))?;
    
    let rate_limit_nft = RateLimitNFT::new(rate_limit_nft_address, provider);
    
    let future_date = chrono::Utc::now() + chrono::Duration::days(duration_days as i64);
    let midnight = chrono::Utc
        .with_ymd_and_hms(
            future_date.year(),
            future_date.month(),
            future_date.day(),
            0,
            0,
            0,
        )
        .single()
        .ok_or("Failed to calculate midnight timestamp")?;
    
    let expires_at = U256::from(midnight.timestamp() as u64);
    let requests_per_kilosecond = U256::from(1000);
    
    let cost = rate_limit_nft
        .calculateCost(requests_per_kilosecond, expires_at)
        .call()
        .await
        .map_err(|e| format!("Failed to calculate Rate Limit NFT cost: {}", e))?;
    
    let cost_eth = cost.to_string().parse::<f64>().unwrap_or(0.0) / 1e18;
    tracing::info!("Rate Limit NFT cost: {} wei (~{} ETH)", cost, cost_eth);
    
    tracing::info!("Sending mint transaction...");
    let receipt = rate_limit_nft
        .mint(expires_at)
        .value(cost)
        .send()
        .await
        .map_err(|e| format!("Failed to send mint transaction: {}", e))?
        .get_receipt()
        .await
        .map_err(|e| format!("Failed to get mint transaction receipt: {}", e))?;
    
    if receipt.logs().is_empty() {
        return Err("No logs in mint receipt - failed to extract token ID".to_string());
    }
    
    let token_id = U256::from_be_bytes(receipt.logs()[0].topics()[3].0);
    let token_id_str = token_id.to_string();
    
    let cost_eth = cost.to_string().parse::<f64>().unwrap_or(0.0) / 1e18;
    
    tracing::info!("Rate Limit NFT minted successfully!");
    tracing::info!("   Token ID: {}", token_id_str);
    tracing::info!("   Expires: {}", midnight.to_rfc3339());
    tracing::info!("   TX Hash: {:?}", receipt.transaction_hash);
    tracing::info!("   Cost: {} wei (~{} ETH)", cost, cost_eth);
    
    Ok(token_id_str)
}

pub async fn create_capacity_delegation_auth_sig_with_wallet(
    wallet: &PrivateKeySigner,
    token_id: &str,
    delegatee_addresses: &[String],
    uses: &str,
) -> Result<AuthSig, String> {
    tracing::info!(
        "Creating capacity delegation auth sig for token {} (delegating to {} addresses)",
        token_id,
        delegatee_addresses.len()
    );
    
    let auth_sig = EthWalletProvider::create_capacity_delegation_auth_sig(
        wallet,
        token_id,
        delegatee_addresses,
        uses,
    )
    .await
    .map_err(|e| format!("Failed to create capacity delegation auth sig: {}", e))?;
    
    tracing::info!("Capacity delegation auth sig created");
    
    Ok(auth_sig)
}

pub async fn get_capacity_auth_sigs(
    wallet: &PrivateKeySigner,
    network: LitNetwork,
    redis_conn: Option<&redis::aio::ConnectionManager>,
    delegatee_address: &str,
) -> Result<Vec<AuthSig>, String> {
    let token_id = get_or_mint_rate_limit_nft(network, redis_conn, 30).await?;
    
    let auth_sig = create_capacity_delegation_auth_sig_with_wallet(
        wallet,
        &token_id,
        &[delegatee_address.to_string()],
        "100",
    ).await?;
    
    Ok(vec![auth_sig])
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_mint_rate_limit_nft() {
        if std::env::var("ETHEREUM_PRIVATE_KEY").is_err() {
            println!("Skipping test - ETHEREUM_PRIVATE_KEY not set");
            return;
        }
        
        let token_id = mint_rate_limit_nft(LitNetwork::DatilDev, 30).await;
        assert!(token_id.is_ok(), "Failed to mint NFT: {:?}", token_id.err());
        
        println!("Minted NFT with token ID: {}", token_id.unwrap());
    }
}
