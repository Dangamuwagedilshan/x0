use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    transaction::Transaction,
};
use spl_token;
use std::str::FromStr;

/// x0 Fee Router Program ID
/// This is the deployed Anchor program that enforces 0.8% fees
pub const FEE_ROUTER_PROGRAM_ID: &str = "BebdiSCiXfA5n9sWFJTKvekrxebWFTuqdrQ2bcBgAk7v";

pub const X0_FEE_WALLET: &str = "FM7tTDb8CSERXF6WjuTQGvba46L2r3YfCQp345RjxW52";

pub const FEE_BASIS_POINTS: u64 = 80;
pub const BASIS_POINTS_DIVISOR: u64 = 10000;

pub const MIN_FEE_LAMPORTS: u64 = 5000;

pub const MIN_FEE_TOKEN_UNITS: u64 = 10000;

mod discriminators {
    pub const TRANSFER_SOL_WITH_FEE: [u8; 8] = [0x9f, 0x1a, 0x3b, 0x2c, 0x4d, 0x5e, 0x6f, 0x70];
    
    pub const TRANSFER_TOKEN_WITH_FEE: [u8; 8] = [0xa1, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81];
}

#[derive(Clone)]
pub struct FeeRouterClient {
    program_id: Pubkey,
    fee_wallet: Pubkey,
}

impl Default for FeeRouterClient {
    fn default() -> Self {
        Self::new()
    }
}

impl FeeRouterClient {
    pub fn new() -> Self {
        let program_id = Pubkey::from_str(FEE_ROUTER_PROGRAM_ID)
            .expect("Invalid fee router program ID");
        let fee_wallet = Pubkey::from_str(X0_FEE_WALLET)
            .expect("Invalid fee wallet address");
        
        Self {
            program_id,
            fee_wallet,
        }
    }

    #[allow(dead_code)]
    pub fn with_program_id(program_id: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let program_id = Pubkey::from_str(program_id)?;
        let fee_wallet = Pubkey::from_str(X0_FEE_WALLET)?;
        
        Ok(Self {
            program_id,
            fee_wallet,
        })
    }

    #[allow(dead_code)]
    pub fn program_id(&self) -> &Pubkey {
        &self.program_id
    }

    pub fn fee_wallet(&self) -> &Pubkey {
        &self.fee_wallet
    }

    pub fn calculate_fee_lamports(&self, amount_lamports: u64) -> u64 {
        let calculated = amount_lamports
            .saturating_mul(FEE_BASIS_POINTS)
            .saturating_div(BASIS_POINTS_DIVISOR);
        
        std::cmp::max(calculated, MIN_FEE_LAMPORTS)
    }

    pub fn calculate_fee_tokens(&self, amount: u64) -> u64 {
        let calculated = amount
            .saturating_mul(FEE_BASIS_POINTS)
            .saturating_div(BASIS_POINTS_DIVISOR);
        
        std::cmp::max(calculated, MIN_FEE_TOKEN_UNITS)
    }

    pub fn calculate_recipient_amount_lamports(&self, total_amount: u64) -> u64 {
        let fee = self.calculate_fee_lamports(total_amount);
        total_amount.saturating_sub(fee)
    }

    pub fn calculate_recipient_amount_tokens(&self, total_amount: u64) -> u64 {
        let fee = self.calculate_fee_tokens(total_amount);
        total_amount.saturating_sub(fee)
    }

    pub fn transfer_sol_with_fee_instruction(
        &self,
        payer: &Pubkey,
        recipient: &Pubkey,
        amount_lamports: u64,
    ) -> Instruction {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&discriminators::TRANSFER_SOL_WITH_FEE);
        data.extend_from_slice(&amount_lamports.to_le_bytes());

        Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(*payer, true),
                AccountMeta::new(*recipient, false),
                AccountMeta::new(self.fee_wallet, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            ],
            data,
        }
    }

    pub fn transfer_token_with_fee_instruction(
        &self,
        payer: &Pubkey,
        payer_token_account: &Pubkey,
        recipient_token_account: &Pubkey,
        fee_token_account: &Pubkey,
        amount: u64,
    ) -> Instruction {
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&discriminators::TRANSFER_TOKEN_WITH_FEE);
        data.extend_from_slice(&amount.to_le_bytes());

        Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(*payer, true),
                AccountMeta::new(*payer_token_account, false),
                AccountMeta::new(*recipient_token_account, false),
                AccountMeta::new(*fee_token_account, false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data,
        }
    }

    pub fn validate_transaction_uses_fee_router(&self, transaction: &Transaction) -> Result<(), FeeRouterValidationError> {
        let instructions = &transaction.message.instructions;
        
        if instructions.is_empty() {
            return Err(FeeRouterValidationError::NoInstructions);
        }

        let account_keys = &transaction.message.account_keys;
        let has_fee_router = instructions.iter().any(|ix| {
            let program_id_index = ix.program_id_index as usize;
            program_id_index < account_keys.len() && account_keys[program_id_index] == self.program_id
        });

        if !has_fee_router {
            return Err(FeeRouterValidationError::FeeRouterNotCalled);
        }

        let has_fee_wallet = account_keys.iter().any(|key| *key == self.fee_wallet);
        
        if !has_fee_wallet {
            return Err(FeeRouterValidationError::FeeWalletMissing);
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum FeeRouterValidationError {
    NoInstructions,
    FeeRouterNotCalled,
    FeeWalletMissing,
}

impl std::fmt::Display for FeeRouterValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoInstructions => write!(f, "Transaction has no instructions"),
            Self::FeeRouterNotCalled => write!(f, "Transaction does not route through fee router program"),
            Self::FeeWalletMissing => write!(f, "x0 fee wallet is missing from transaction"),
        }
    }
}

impl std::error::Error for FeeRouterValidationError {}

pub fn get_fee_token_account(mint: &Pubkey) -> Pubkey {
    let fee_wallet = Pubkey::from_str(X0_FEE_WALLET).expect("Invalid fee wallet");
    spl_associated_token_account::get_associated_token_address(&fee_wallet, mint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_calculation_sol() {
        let client = FeeRouterClient::new();
        
        let amount = 1_000_000_000u64;
        let fee = client.calculate_fee_lamports(amount);
        
        assert_eq!(fee, 8_000_000);
        
        let recipient = client.calculate_recipient_amount_lamports(amount);
        assert_eq!(recipient, 992_000_000);
    }

    #[test]
    fn test_fee_calculation_minimum() {
        let client = FeeRouterClient::new();
        
        let amount = 10_000u64;
        let fee = client.calculate_fee_lamports(amount);
        
        assert_eq!(fee, MIN_FEE_LAMPORTS);
    }

    #[test]
    fn test_fee_calculation_tokens() {
        let client = FeeRouterClient::new();
        
        let amount = 100_000_000u64;
        let fee = client.calculate_fee_tokens(amount);
        
        assert_eq!(fee, 800_000);
    }

    #[test]
    fn test_program_id() {
        let client = FeeRouterClient::new();
        assert_eq!(client.program_id().to_string(), FEE_ROUTER_PROGRAM_ID);
    }

    #[test]
    fn test_fee_wallet() {
        let client = FeeRouterClient::new();
        assert_eq!(client.fee_wallet().to_string(), X0_FEE_WALLET);
    }
}
