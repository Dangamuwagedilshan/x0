-- Add missing columns to spending_attestations table

ALTER TABLE spending_attestations 
    ADD COLUMN IF NOT EXISTS requested_usd NUMERIC(20, 8),
    ADD COLUMN IF NOT EXISTS remaining_after_usd NUMERIC(20, 8),
    ADD COLUMN IF NOT EXISTS attestation_timestamp TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS nonce TEXT;

-- Make attestation_json stored as TEXT instead of JSONB if that's what the code expects
-- (checking the code, it appears to be using serde_json::to_string)
ALTER TABLE spending_attestations 
    ALTER COLUMN attestation_json TYPE TEXT USING attestation_json::TEXT;

-- Also add security_events table if missing (used by audit.rs)
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    details JSONB DEFAULT '{}',
    ip_address TEXT,
    user_agent TEXT,
    request_id UUID,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create indexes for security_events
CREATE INDEX IF NOT EXISTS idx_security_events_platform_id ON security_events(platform_id);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at DESC);
