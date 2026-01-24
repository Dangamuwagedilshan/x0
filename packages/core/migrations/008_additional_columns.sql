-- Migration 007: Additional schema fixes
-- Adds remaining missing columns found in cargo build errors

-- pricing_suggestions: add reasoning column
ALTER TABLE pricing_suggestions 
    ADD COLUMN IF NOT EXISTS reasoning TEXT;

-- spending_attestations: add limit_usd column
ALTER TABLE spending_attestations 
    ADD COLUMN IF NOT EXISTS limit_usd DECIMAL(20, 8);

-- payment_intents: add canceled_at column
ALTER TABLE payment_intents 
    ADD COLUMN IF NOT EXISTS canceled_at TIMESTAMPTZ;

-- Add comments
COMMENT ON COLUMN pricing_suggestions.reasoning IS 'Explanation of why the price was suggested';
COMMENT ON COLUMN spending_attestations.limit_usd IS 'The spending limit in USD that was attested';
COMMENT ON COLUMN payment_intents.canceled_at IS 'When the payment intent was canceled';
