-- Migration 005: Remaining schema fixes (from cargo build errors)
-- Adds missing columns identified from compile-time sqlx query verification

-- autonomous_delegate_usage: add payment_id column
ALTER TABLE autonomous_delegate_usage 
    ADD COLUMN IF NOT EXISTS payment_id UUID REFERENCES payments(id);

-- session_key_recipient_usage: add payment_id column
ALTER TABLE session_key_recipient_usage 
    ADD COLUMN IF NOT EXISTS payment_id UUID REFERENCES payments(id);

-- pricing_suggestions: add user_wallet column
ALTER TABLE pricing_suggestions 
    ADD COLUMN IF NOT EXISTS user_wallet VARCHAR(255);

-- ai_agent_sessions: add spending_counter fields
ALTER TABLE ai_agent_sessions 
    ADD COLUMN IF NOT EXISTS spending_counter_address VARCHAR(255),
    ADD COLUMN IF NOT EXISTS spending_counter_nonce BIGINT,
    ADD COLUMN IF NOT EXISTS lit_access_conditions JSONB,
    ADD COLUMN IF NOT EXISTS lit_encrypted_keypair_id UUID;

-- spending_attestations: add payment_id and signature columns
ALTER TABLE spending_attestations 
    ADD COLUMN IF NOT EXISTS payment_id UUID REFERENCES payments(id),
    ADD COLUMN IF NOT EXISTS signature TEXT;

-- payment_intents: add missing columns
ALTER TABLE payment_intents 
    ADD COLUMN IF NOT EXISTS payment_intent_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS agent_id UUID,
    ADD COLUMN IF NOT EXISTS agent_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS capture_method VARCHAR(50) DEFAULT 'automatic';

-- payment_intent_events: add previous_status column
ALTER TABLE payment_intent_events 
    ADD COLUMN IF NOT EXISTS previous_status VARCHAR(50);

-- api_key_audit_log: add missing columns
ALTER TABLE api_key_audit_log 
    ADD COLUMN IF NOT EXISTS response_code INTEGER,
    ADD COLUMN IF NOT EXISTS request_duration_ms INTEGER,
    ADD COLUMN IF NOT EXISTS error_message TEXT;

-- idempotency_keys: add user_agent column
ALTER TABLE idempotency_keys 
    ADD COLUMN IF NOT EXISTS user_agent TEXT;

-- lit_network_shards: add lit_node_count and is_active columns
ALTER TABLE lit_network_shards 
    ADD COLUMN IF NOT EXISTS lit_node_count INTEGER,
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;

-- webauthn_credentials: ensure public_key_cose is not optional (BYTEA)
-- First check if column exists and update nulls
UPDATE webauthn_credentials SET public_key_cose = '' WHERE public_key_cose IS NULL;

-- Create indexes for new columns
CREATE INDEX IF NOT EXISTS idx_autonomous_delegate_usage_payment_id ON autonomous_delegate_usage(payment_id);
CREATE INDEX IF NOT EXISTS idx_session_key_recipient_usage_payment_id ON session_key_recipient_usage(payment_id);
CREATE INDEX IF NOT EXISTS idx_spending_attestations_payment_id ON spending_attestations(payment_id);
CREATE INDEX IF NOT EXISTS idx_payment_intents_agent_id ON payment_intents(agent_id);
CREATE INDEX IF NOT EXISTS idx_lit_network_shards_is_active ON lit_network_shards(is_active);

-- Add comments
COMMENT ON COLUMN autonomous_delegate_usage.payment_id IS 'Reference to the payment this usage is for';
COMMENT ON COLUMN session_key_recipient_usage.payment_id IS 'Reference to the payment this usage is for';
COMMENT ON COLUMN ai_agent_sessions.spending_counter_address IS 'On-chain spending counter PDA address';
COMMENT ON COLUMN ai_agent_sessions.spending_counter_nonce IS 'Current nonce for spending counter';
COMMENT ON COLUMN ai_agent_sessions.lit_access_conditions IS 'Lit Protocol access control conditions';
COMMENT ON COLUMN ai_agent_sessions.lit_encrypted_keypair_id IS 'Reference to encrypted keypair in Lit';
COMMENT ON COLUMN payment_intents.capture_method IS 'Payment capture method: automatic or manual';
COMMENT ON COLUMN lit_network_shards.lit_node_count IS 'Number of Lit nodes in the network shard';
COMMENT ON COLUMN lit_network_shards.is_active IS 'Whether this shard is currently active';
