use solana_sdk::signature::{Keypair, Signer};

fn main() {
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║       x0 Attestation Keypair Generator                     ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();
    
    let keypair = Keypair::new();
    
    let public_key = keypair.pubkey().to_string();
    
    let private_key_bytes = keypair.to_bytes();
    let private_key_json = serde_json::to_string(&private_key_bytes.to_vec())
        .expect("Failed to serialize private key to JSON");
    
    let private_key_base58 = bs58::encode(&private_key_bytes).into_string();
    
    println!("✅ New attestation keypair generated!\n");
    
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ PUBLIC KEY (share this for verification)                        │");
    println!("├─────────────────────────────────────────────────────────────────┤");
    println!("│ {}", public_key);
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();
    
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ PRIVATE KEY - JSON format (recommended for env var)             │");
    println!("├─────────────────────────────────────────────────────────────────┤");
    println!("│ Set this in your environment:                                   │");
    println!("│                                                                 │");
    println!("│ export X0_ATTESTATION_PRIVATE_KEY='{}'", private_key_json);
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();
    
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ PRIVATE KEY - Base58 format (alternative)                       │");
    println!("├─────────────────────────────────────────────────────────────────┤");
    println!("│ {}", private_key_base58);
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();
    
    println!("IMPORTANT SECURITY NOTES:");
    println!("   1. Store the private key securely (e.g., secrets manager)");
    println!("   2. Never commit the private key to version control");
    println!("   3. The public key should be published for verification");
    println!("   4. Back up the private key - losing it breaks audit verification");
    println!();
    
    println!("Quick setup for Railway/Heroku/etc:");
    println!("   X0_ATTESTATION_PRIVATE_KEY='{}'", private_key_json);
}
