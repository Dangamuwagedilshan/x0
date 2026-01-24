-- Migration: 003_ai_agent_sessions_extended.sql
-- Add extended fields to ai_agent_sessions for attestation and PKP support

-- Add allowed_platforms for multi-platform agent authorization
ALTER TABLE ai_agent_sessions ADD COLUMN IF NOT EXISTS allowed_platforms JSONB DEFAULT '[]'::jsonb;

-- Add attestation fields for cryptographic verification
ALTER TABLE ai_agent_sessions ADD COLUMN IF NOT EXISTS attestation_public_key TEXT;
ALTER TABLE ai_agent_sessions ADD COLUMN IF NOT EXISTS attestation_signature TEXT;
ALTER TABLE ai_agent_sessions ADD COLUMN IF NOT EXISTS attestation_nonce TEXT;

-- Add PKP (Programmable Key Pair) fields for Lit Protocol integration
ALTER TABLE ai_agent_sessions ADD COLUMN IF NOT EXISTS pkp_public_key TEXT;
ALTER TABLE ai_agent_sessions ADD COLUMN IF NOT EXISTS lit_action_ipfs_cid TEXT;

-- Add crypto_enforced flag for enhanced security mode
ALTER TABLE ai_agent_sessions ADD COLUMN IF NOT EXISTS crypto_enforced BOOLEAN DEFAULT false;

-- Create index for PKP lookups
CREATE INDEX IF NOT EXISTS idx_ai_agent_sessions_pkp_public_key ON ai_agent_sessions(pkp_public_key) WHERE pkp_public_key IS NOT NULL;

-- Create index for attestation lookups
CREATE INDEX IF NOT EXISTS idx_ai_agent_sessions_attestation ON ai_agent_sessions(attestation_public_key) WHERE attestation_public_key IS NOT NULL;

COMMENT ON COLUMN ai_agent_sessions.allowed_platforms IS 'JSON array of platform IDs this agent session can interact with';
COMMENT ON COLUMN ai_agent_sessions.attestation_public_key IS 'Public key used for session attestation verification';
COMMENT ON COLUMN ai_agent_sessions.attestation_signature IS 'Signature proving session authenticity';
COMMENT ON COLUMN ai_agent_sessions.attestation_nonce IS 'Nonce used in attestation to prevent replay attacks';
COMMENT ON COLUMN ai_agent_sessions.pkp_public_key IS 'Lit Protocol PKP public key for distributed key management';
COMMENT ON COLUMN ai_agent_sessions.lit_action_ipfs_cid IS 'IPFS CID of the Lit Action controlling this PKP';
COMMENT ON COLUMN ai_agent_sessions.crypto_enforced IS 'Whether cryptographic verification is required for all operations';
