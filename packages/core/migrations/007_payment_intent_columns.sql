-- Migration 007: Final remaining schema fixes
-- Adds columns and fixes for remaining sqlx compile errors

-- pricing_suggestions: add ppp_factor column
ALTER TABLE pricing_suggestions 
    ADD COLUMN IF NOT EXISTS ppp_factor NUMERIC(10,4);

-- spending_attestations: add spent_usd column
ALTER TABLE spending_attestations 
    ADD COLUMN IF NOT EXISTS spent_usd NUMERIC(20,8);

-- payment_intents: add confirmed_at column  
ALTER TABLE payment_intents 
    ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMPTZ;

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_payment_intents_confirmed_at ON payment_intents(confirmed_at);

-- Add comments
COMMENT ON COLUMN pricing_suggestions.ppp_factor IS 'Purchase Power Parity factor for price adjustments';
COMMENT ON COLUMN spending_attestations.spent_usd IS 'Amount spent in USD for this attestation';
COMMENT ON COLUMN payment_intents.confirmed_at IS 'When the payment intent was confirmed';
