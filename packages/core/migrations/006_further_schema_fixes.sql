-- Migration 006: Final schema fixes (from cargo build errors)
-- Adds remaining missing columns and enum values

-- pricing_suggestions: add user_country_code column
ALTER TABLE pricing_suggestions 
    ADD COLUMN IF NOT EXISTS user_country_code VARCHAR(2);

-- spending_attestations: add platform_id and signer_public_key columns
ALTER TABLE spending_attestations 
    ADD COLUMN IF NOT EXISTS platform_id UUID REFERENCES platforms(id),
    ADD COLUMN IF NOT EXISTS signer_public_key TEXT;

-- payment_intents: add agent_metadata column
ALTER TABLE payment_intents 
    ADD COLUMN IF NOT EXISTS agent_metadata JSONB;

-- payment_intent_status enum: add 'canceled' value if missing
DO $$ 
BEGIN
    -- Check if 'canceled' exists in the enum
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum 
        WHERE enumlabel = 'canceled' 
        AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'payment_intent_status')
    ) THEN
        ALTER TYPE payment_intent_status ADD VALUE IF NOT EXISTS 'canceled';
    END IF;
END $$;

-- idempotency_keys: add created_resource_type column
ALTER TABLE idempotency_keys 
    ADD COLUMN IF NOT EXISTS created_resource_type VARCHAR(100);

-- Create indexes for new columns
CREATE INDEX IF NOT EXISTS idx_pricing_suggestions_country ON pricing_suggestions(user_country_code);
CREATE INDEX IF NOT EXISTS idx_spending_attestations_platform ON spending_attestations(platform_id);

-- Add comments
COMMENT ON COLUMN pricing_suggestions.user_country_code IS 'ISO 2-letter country code for PPP adjustments';
COMMENT ON COLUMN spending_attestations.platform_id IS 'Reference to the platform';
COMMENT ON COLUMN spending_attestations.signer_public_key IS 'Public key that signed the attestation';
COMMENT ON COLUMN payment_intents.agent_metadata IS 'Agent-specific metadata for the payment intent';
COMMENT ON COLUMN idempotency_keys.created_resource_type IS 'Type of resource created (payment, session, etc.)';
