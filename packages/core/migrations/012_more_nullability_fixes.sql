-- Make more columns NOT NULL for proper SQLx type inference

-- payment_intents.currency should be NOT NULL with default
UPDATE payment_intents SET currency = 'USDC' WHERE currency IS NULL;
ALTER TABLE payment_intents ALTER COLUMN currency SET NOT NULL;

-- Fix webauthn_credentials.public_key_cose - if it exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'webauthn_credentials' 
               AND column_name = 'public_key_cose') THEN
        UPDATE webauthn_credentials SET public_key_cose = '\x' WHERE public_key_cose IS NULL;
        ALTER TABLE webauthn_credentials ALTER COLUMN public_key_cose SET NOT NULL;
    END IF;
END $$;

-- Fix mpc_wallets.passkey_credential_id to NOT NULL if has values
-- Actually, this might legitimately be NULL for some wallets, so leave it
-- The code should handle Option<String>

-- Fix spending_attestations nullable columns
UPDATE spending_attestations SET signature = '' WHERE signature IS NULL;
ALTER TABLE spending_attestations ALTER COLUMN signature SET NOT NULL;

UPDATE spending_attestations SET signer_public_key = '' WHERE signer_public_key IS NULL;
ALTER TABLE spending_attestations ALTER COLUMN signer_public_key SET NOT NULL;

-- Fix idempotency_keys ip_address column type if needed
-- It should be VARCHAR/TEXT, not IpNetwork
-- Check if the column type needs changing
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'idempotency_keys' 
               AND column_name = 'ip_address'
               AND data_type = 'inet') THEN
        -- Convert from inet to text
        ALTER TABLE idempotency_keys ALTER COLUMN ip_address TYPE TEXT USING ip_address::TEXT;
    END IF;
END $$;

-- Same for api_key_audit_log
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'api_key_audit_log' 
               AND column_name = 'ip_address'
               AND data_type = 'inet') THEN
        ALTER TABLE api_key_audit_log ALTER COLUMN ip_address TYPE TEXT USING ip_address::TEXT;
    END IF;
END $$;

-- Fix security_events nullable columns for SecurityEvent struct
ALTER TABLE security_events ALTER COLUMN id SET NOT NULL;
ALTER TABLE security_events ALTER COLUMN event_type SET NOT NULL;

-- Make mpc_shards.platform_shard_id and recovery_shard_id be UUIDs not strings
-- This is tricky - need to check what type they actually are
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'mpc_wallets' 
               AND column_name = 'platform_shard_id'
               AND data_type = 'character varying') THEN
        -- First add new UUID columns
        ALTER TABLE mpc_wallets ADD COLUMN IF NOT EXISTS platform_shard_uuid UUID;
        ALTER TABLE mpc_wallets ADD COLUMN IF NOT EXISTS recovery_shard_uuid UUID;
        -- Note: Can't easily convert string to UUID without knowing the format
    END IF;
END $$;
