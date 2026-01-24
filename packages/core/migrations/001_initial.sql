-- x0 Initial Schema
-- Payment Infrastructure for AI Agents

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Custom Types
CREATE TYPE payment_status AS ENUM ('pending', 'confirmed', 'failed', 'expired');
CREATE TYPE webhook_status AS ENUM ('pending', 'delivered', 'failed', 'exhausted');
CREATE TYPE webhook_event_type AS ENUM (
    'session.created',
    'session.revoked',
    'session_key.created',
    'session_key.revoked',
    'payment.created',
    'payment.confirmed',
    'payment.failed'
);

-- Updated timestamp function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- PLATFORMS (API consumers / platforms integrating x0)
-- =============================================================================

CREATE TABLE platforms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    wallet_address VARCHAR(44) NOT NULL,
    webhook_url VARCHAR(512),
    webhook_secret VARCHAR(255),
    
    -- Feature flags
    ai_sessions_enabled BOOLEAN DEFAULT TRUE,
    mpc_wallet_enabled BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_platforms_updated_at
    BEFORE UPDATE ON platforms
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_platforms_email ON platforms(email);

-- =============================================================================
-- API KEYS
-- =============================================================================

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Key identification
    key_hash VARCHAR(256) NOT NULL UNIQUE,
    key_prefix VARCHAR(16) NOT NULL,
    name VARCHAR(255),
    
    -- Mode and permissions
    mode VARCHAR(10) NOT NULL DEFAULT 'test' CHECK (mode IN ('test', 'live')),
    scopes TEXT[] DEFAULT ARRAY['payments:read', 'payments:write', 'sessions:read', 'sessions:write'],
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMPTZ,
    
    -- Usage tracking
    last_used_at TIMESTAMPTZ,
    request_count BIGINT DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_merchant ON api_keys(platform_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

-- =============================================================================
-- ENCRYPTED KEYS (session keys, MPC shards, autonomous delegates)
-- =============================================================================

CREATE TABLE encrypted_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL,
    
    -- Key type for access control
    key_type VARCHAR(50) NOT NULL CHECK (key_type IN (
        'session_key',
        'ai_session_key',
        'mpc_platform_shard',
        'mpc_recovery_shard',
        'autonomous_delegate',
        'autonomous_delegate_lit'
    )),
    
    -- Encryption
    encrypted_key_data BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    encryption_version INTEGER DEFAULT 1,
    encryption_mode VARCHAR(20) DEFAULT 'aes_gcm' CHECK (encryption_mode IN ('aes_gcm', 'lit_protocol')),
    
    -- Public key (unencrypted for lookups)
    public_key VARCHAR(255) NOT NULL,
    
    -- Metadata
    key_metadata JSONB DEFAULT '{}',
    
    -- Client-side encrypted flag (for device-bound keys)
    client_encrypted BOOLEAN DEFAULT FALSE,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ
);

CREATE INDEX idx_encrypted_keys_owner ON encrypted_keys(owner_id, key_type);
CREATE INDEX idx_encrypted_keys_public ON encrypted_keys(public_key);
CREATE INDEX idx_encrypted_keys_active ON encrypted_keys(is_active) WHERE is_active = TRUE;

-- =============================================================================
-- AI AGENT SESSIONS
-- =============================================================================

CREATE TABLE ai_agent_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Session identification
    session_token VARCHAR(255) NOT NULL UNIQUE,
    agent_id VARCHAR(255) NOT NULL,
    agent_name VARCHAR(255),
    
    -- User wallet being authorized
    user_wallet VARCHAR(255) NOT NULL,
    
    -- Spending limits
    max_per_transaction DECIMAL(20, 8),
    max_per_day DECIMAL(20, 8),
    max_per_week DECIMAL(20, 8),
    max_per_month DECIMAL(20, 8),
    require_approval_above DECIMAL(20, 8),
    
    -- Current usage tracking
    spent_today DECIMAL(20, 8) DEFAULT 0,
    spent_this_week DECIMAL(20, 8) DEFAULT 0,
    spent_this_month DECIMAL(20, 8) DEFAULT 0,
    last_reset_daily TIMESTAMPTZ DEFAULT NOW(),
    last_reset_weekly TIMESTAMPTZ DEFAULT NOW(),
    last_reset_monthly TIMESTAMPTZ DEFAULT NOW(),
    
    -- Optional merchant restrictions
    allowed_platforms JSONB DEFAULT '[]'::jsonb,
    
    -- Cryptographic spending attestation
    attestation_public_key VARCHAR(255),
    attestation_signature TEXT,
    attestation_nonce BIGINT DEFAULT 0,
    
    -- Session status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_ai_sessions_token ON ai_agent_sessions(session_token) WHERE is_active = TRUE;
CREATE INDEX idx_ai_sessions_merchant ON ai_agent_sessions(platform_id);
CREATE INDEX idx_ai_sessions_wallet ON ai_agent_sessions(user_wallet);
CREATE INDEX idx_ai_sessions_expires ON ai_agent_sessions(expires_at) WHERE is_active = TRUE;
CREATE INDEX idx_ai_sessions_agent ON ai_agent_sessions(agent_id);

-- =============================================================================
-- SESSION KEYS (Device-bound keys for auto-signing)
-- =============================================================================

CREATE TABLE session_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Reference to encrypted keypair
    session_keypair_id UUID NOT NULL REFERENCES encrypted_keys(id),
    
    -- Optional link to agent session
    linked_session_id UUID REFERENCES ai_agent_sessions(id) ON DELETE SET NULL,
    
    -- User and wallet info
    user_wallet VARCHAR(255),
    session_wallet_address VARCHAR(255),
    
    -- Agent info
    agent_id VARCHAR(255),
    agent_name VARCHAR(255),
    created_by_platform_id UUID REFERENCES platforms(id),
    
    -- Spending limits
    limit_usdc DECIMAL(20, 2) NOT NULL,
    used_amount_usdc DECIMAL(20, 2) DEFAULT 0,
    
    -- Period-based limits
    daily_limit_usdc DECIMAL(20, 2),
    weekly_limit_usdc DECIMAL(20, 2),
    monthly_limit_usdc DECIMAL(20, 2),
    spent_today DECIMAL(20, 2) DEFAULT 0,
    spent_this_week DECIMAL(20, 2) DEFAULT 0,
    spent_this_month DECIMAL(20, 2) DEFAULT 0,
    
    -- Time limits
    expires_at TIMESTAMPTZ NOT NULL,
    expiry_notification_sent BOOLEAN DEFAULT FALSE,
    
    -- Security metadata
    device_fingerprint TEXT,
    ip_address INET,
    user_agent TEXT,
    created_from_ip INET,
    created_from_device TEXT,
    last_security_check_at TIMESTAMPTZ,
    
    -- Geolocation
    last_known_latitude DOUBLE PRECISION,
    last_known_longitude DOUBLE PRECISION,
    
    -- Encryption mode
    encryption_mode VARCHAR(20) DEFAULT 'aes_gcm',
    
    -- Lit Protocol autonomous signing
    lit_encrypted_keypair_id UUID REFERENCES encrypted_keys(id),
    
    -- Recovery
    recovery_qr_generated BOOLEAN DEFAULT FALSE,
    last_recovery_at TIMESTAMPTZ,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT positive_limit CHECK (limit_usdc > 0),
    CONSTRAINT positive_used CHECK (used_amount_usdc >= 0),
    CONSTRAINT used_not_exceed_limit CHECK (used_amount_usdc <= limit_usdc)
);

CREATE INDEX idx_session_keys_merchant ON session_keys(platform_id);
CREATE INDEX idx_session_keys_active ON session_keys(platform_id, is_active, expires_at) WHERE is_active = TRUE;
CREATE INDEX idx_session_keys_expiry ON session_keys(expires_at) WHERE is_active = TRUE;
CREATE INDEX idx_session_keys_linked_session ON session_keys(linked_session_id) WHERE linked_session_id IS NOT NULL;

-- =============================================================================
-- AUTONOMOUS DELEGATES (Lit Protocol encrypted keys for server-side signing)
-- =============================================================================

CREATE TABLE autonomous_delegates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Parent session key
    session_key_id UUID NOT NULL REFERENCES session_keys(id) ON DELETE CASCADE,
    
    -- Encrypted delegate key (Lit Protocol encrypted)
    delegate_keypair_id UUID NOT NULL REFERENCES encrypted_keys(id) ON DELETE CASCADE,
    
    -- Spending policy
    max_amount_usd DECIMAL(20, 8) NOT NULL,
    used_amount_usd DECIMAL(20, 8) DEFAULT 0,
    
    -- Time limits
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    
    -- User consent proof
    delegation_signature TEXT NOT NULL,
    delegation_message TEXT NOT NULL,
    
    -- Security tracking
    created_from_ip INET,
    created_from_device TEXT,
    
    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT positive_max_amount CHECK (max_amount_usd > 0),
    CONSTRAINT positive_used_amount CHECK (used_amount_usd >= 0),
    CONSTRAINT used_not_exceed_max CHECK (used_amount_usd <= max_amount_usd)
);

CREATE INDEX idx_autonomous_delegates_active ON autonomous_delegates(session_key_id, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_autonomous_delegates_expired ON autonomous_delegates(expires_at) WHERE revoked_at IS NULL;

-- =============================================================================
-- PAYMENTS
-- =============================================================================

CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Payment details
    amount_usd DECIMAL(20, 8) NOT NULL,
    currency VARCHAR(10) DEFAULT 'USDC',
    payment_type VARCHAR(50) DEFAULT 'direct',
    
    -- Status
    status payment_status NOT NULL DEFAULT 'pending',
    
    -- Blockchain
    transaction_signature VARCHAR(88),
    from_wallet VARCHAR(44),
    to_wallet VARCHAR(44),
    
    -- Agent context
    session_id UUID REFERENCES ai_agent_sessions(id) ON DELETE SET NULL,
    session_key_id UUID REFERENCES session_keys(id) ON DELETE SET NULL,
    agent_id VARCHAR(255),
    
    -- Idempotency
    idempotency_key VARCHAR(255),
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TRIGGER update_payments_updated_at
    BEFORE UPDATE ON payments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_payments_merchant ON payments(platform_id);
CREATE INDEX idx_payments_status ON payments(status);
CREATE INDEX idx_payments_signature ON payments(transaction_signature) WHERE transaction_signature IS NOT NULL;
CREATE INDEX idx_payments_session ON payments(session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_payments_session_key ON payments(session_key_id) WHERE session_key_id IS NOT NULL;
CREATE INDEX idx_payments_idempotency ON payments(platform_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_payments_expires ON payments(expires_at, status) WHERE status = 'pending';

-- =============================================================================
-- AI SESSION ACTIVITIES (audit log)
-- =============================================================================

CREATE TABLE ai_session_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES ai_agent_sessions(id) ON DELETE CASCADE,
    
    -- Activity details
    activity_type VARCHAR(50) NOT NULL,
    payment_id UUID REFERENCES payments(id) ON DELETE SET NULL,
    amount DECIMAL(20, 8),
    
    -- Result
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    
    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    
    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_session_activities_session ON ai_session_activities(session_id);
CREATE INDEX idx_session_activities_created ON ai_session_activities(created_at DESC);

-- =============================================================================
-- SESSION KEY USAGE LOG (for rate limiting and anomaly detection)
-- =============================================================================

CREATE TABLE session_key_usage_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_key_id UUID NOT NULL REFERENCES session_keys(id) ON DELETE CASCADE,
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Usage details
    amount_usd DECIMAL(20, 2) NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT,
    device_fingerprint TEXT,
    transaction_hash TEXT,
    
    -- Security flags
    suspicious_activity_detected BOOLEAN DEFAULT FALSE,
    security_flags TEXT[],
    
    -- Timestamp
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    CONSTRAINT positive_amount CHECK (amount_usd > 0)
);

CREATE INDEX idx_session_key_usage_session ON session_key_usage_log(session_key_id);
CREATE INDEX idx_session_key_usage_merchant ON session_key_usage_log(platform_id, created_at DESC);
CREATE INDEX idx_session_key_usage_suspicious ON session_key_usage_log(platform_id, suspicious_activity_detected) WHERE suspicious_activity_detected = TRUE;

-- =============================================================================
-- SESSION KEY SECURITY EVENTS
-- =============================================================================

CREATE TABLE session_key_security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_key_id UUID REFERENCES session_keys(id) ON DELETE SET NULL,
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Event details
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    description TEXT NOT NULL,
    
    -- Context
    metadata JSONB,
    action_taken TEXT,
    ip_address INET,
    
    -- Timestamp
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_security_events_merchant ON session_key_security_events(platform_id, created_at DESC);
CREATE INDEX idx_security_events_type ON session_key_security_events(event_type, severity);

-- =============================================================================
-- WEBHOOKS
-- =============================================================================

CREATE TABLE webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Event details
    event_type webhook_event_type NOT NULL,
    payload JSONB NOT NULL,
    webhook_url VARCHAR(512) NOT NULL,
    
    -- Status
    status webhook_status NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER DEFAULT 5,
    
    -- Response tracking
    last_attempt_at TIMESTAMPTZ,
    next_retry_at TIMESTAMPTZ,
    response_code INTEGER,
    response_body TEXT,
    
    -- Idempotency
    idempotency_key VARCHAR(255),
    
    -- Reference
    payment_id UUID REFERENCES payments(id) ON DELETE SET NULL,
    session_id UUID REFERENCES ai_agent_sessions(id) ON DELETE SET NULL,
    
    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_events_status ON webhook_events(status);
CREATE INDEX idx_webhook_events_retry ON webhook_events(next_retry_at) WHERE status = 'failed';
CREATE INDEX idx_webhook_events_merchant ON webhook_events(platform_id);

-- =============================================================================
-- IDEMPOTENCY KEYS
-- =============================================================================

CREATE TABLE idempotency_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Key and state
    idempotency_key VARCHAR(255) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    response_code INTEGER,
    response_body JSONB,
    
    -- Status
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed')),
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    
    CONSTRAINT unique_idempotency UNIQUE (platform_id, idempotency_key)
);

CREATE INDEX idx_idempotency_key ON idempotency_keys(platform_id, idempotency_key);
CREATE INDEX idx_idempotency_expires ON idempotency_keys(expires_at);

-- =============================================================================
-- MPC WALLETS (for advanced non-custodial setup)
-- =============================================================================

CREATE TABLE mpc_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Wallet address
    wallet_address VARCHAR(44) NOT NULL,
    
    -- Shard references
    platform_shard_id UUID NOT NULL REFERENCES encrypted_keys(id),
    lit_network_shard_id VARCHAR(255) NOT NULL,
    recovery_shard_id UUID REFERENCES encrypted_keys(id),
    
    -- WebAuthn credential
    passkey_credential_id VARCHAR(255),
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TRIGGER update_mpc_wallets_updated_at
    BEFORE UPDATE ON mpc_wallets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE INDEX idx_mpc_wallets_merchant ON mpc_wallets(platform_id);
CREATE INDEX idx_mpc_wallets_address ON mpc_wallets(wallet_address);

-- =============================================================================
-- WEBAUTHN CREDENTIALS
-- =============================================================================

CREATE TABLE webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Credential data
    credential_id TEXT NOT NULL UNIQUE,
    credential_public_key BYTEA NOT NULL,
    credential_name VARCHAR(255),
    
    -- Counter for replay protection
    sign_count BIGINT DEFAULT 0,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_webauthn_merchant ON webauthn_credentials(platform_id);
CREATE INDEX idx_webauthn_credential ON webauthn_credentials(credential_id);

-- =============================================================================
-- ADMIN USERS (for self-hosted dashboard)
-- =============================================================================

CREATE TABLE admin_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    
    -- Role
    role VARCHAR(50) DEFAULT 'admin' CHECK (role IN ('admin', 'operator', 'viewer')),
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- 2FA
    totp_secret VARCHAR(255),
    totp_enabled BOOLEAN DEFAULT FALSE,
    
    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

CREATE INDEX idx_admin_email ON admin_users(email);

-- =============================================================================
-- RATE LIMITING
-- =============================================================================

CREATE TABLE rate_limit_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(255) NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    request_count INTEGER DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_rate_limit_key UNIQUE (key, window_start)
);

CREATE INDEX idx_rate_limit_key ON rate_limit_entries(key, window_start);
CREATE INDEX idx_rate_limit_cleanup ON rate_limit_entries(window_start);

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Check spending limit
CREATE OR REPLACE FUNCTION check_ai_session_spending_limit(
    p_session_id UUID,
    p_amount DECIMAL(20, 8)
) RETURNS JSONB AS $$
DECLARE
    v_session RECORD;
BEGIN
    SELECT * INTO v_session
    FROM ai_agent_sessions
    WHERE id = p_session_id
      AND is_active = TRUE
      AND expires_at > NOW();
    
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'allowed', FALSE,
            'reason', 'Session not found or expired'
        );
    END IF;
    
    IF v_session.max_per_transaction IS NOT NULL 
       AND p_amount > v_session.max_per_transaction THEN
        RETURN jsonb_build_object(
            'allowed', FALSE,
            'reason', 'Exceeds per-transaction limit',
            'limit', v_session.max_per_transaction,
            'requested', p_amount
        );
    END IF;
    
    IF v_session.max_per_day IS NOT NULL 
       AND (v_session.spent_today + p_amount) > v_session.max_per_day THEN
        RETURN jsonb_build_object(
            'allowed', FALSE,
            'reason', 'Exceeds daily spending limit',
            'limit', v_session.max_per_day,
            'spent', v_session.spent_today,
            'requested', p_amount
        );
    END IF;
    
    IF v_session.require_approval_above IS NOT NULL 
       AND p_amount > v_session.require_approval_above THEN
        RETURN jsonb_build_object(
            'allowed', FALSE,
            'reason', 'Amount requires user approval',
            'requires_approval', TRUE,
            'threshold', v_session.require_approval_above,
            'requested', p_amount
        );
    END IF;
    
    RETURN jsonb_build_object(
        'allowed', TRUE,
        'session_id', v_session.id
    );
END;
$$ LANGUAGE plpgsql;

-- Record spending
CREATE OR REPLACE FUNCTION record_ai_session_spending(
    p_session_id UUID,
    p_amount DECIMAL(20, 8)
) RETURNS BOOLEAN AS $$
BEGIN
    UPDATE ai_agent_sessions
    SET 
        spent_today = spent_today + p_amount,
        spent_this_week = spent_this_week + p_amount,
        spent_this_month = spent_this_month + p_amount,
        last_used_at = NOW()
    WHERE id = p_session_id;
    
    RETURN FOUND;
END;
$$ LANGUAGE plpgsql;

-- Reset daily limits
CREATE OR REPLACE FUNCTION reset_ai_session_daily_limits()
RETURNS void AS $$
BEGIN
    UPDATE ai_agent_sessions
    SET 
        spent_today = 0,
        last_reset_daily = NOW()
    WHERE last_reset_daily < DATE_TRUNC('day', NOW());
    
    UPDATE session_keys
    SET spent_today = 0
    WHERE DATE_TRUNC('day', created_at) < DATE_TRUNC('day', NOW());
END;
$$ LANGUAGE plpgsql;

-- Reset weekly limits
CREATE OR REPLACE FUNCTION reset_ai_session_weekly_limits()
RETURNS void AS $$
BEGIN
    UPDATE ai_agent_sessions
    SET 
        spent_this_week = 0,
        last_reset_weekly = NOW()
    WHERE last_reset_weekly < DATE_TRUNC('week', NOW());
    
    UPDATE session_keys
    SET spent_this_week = 0
    WHERE DATE_TRUNC('week', created_at) < DATE_TRUNC('week', NOW());
END;
$$ LANGUAGE plpgsql;

-- Reset monthly limits  
CREATE OR REPLACE FUNCTION reset_ai_session_monthly_limits()
RETURNS void AS $$
BEGIN
    UPDATE ai_agent_sessions
    SET 
        spent_this_month = 0,
        last_reset_monthly = NOW()
    WHERE last_reset_monthly < DATE_TRUNC('month', NOW());
    
    UPDATE session_keys
    SET spent_this_month = 0
    WHERE DATE_TRUNC('month', created_at) < DATE_TRUNC('month', NOW());
END;
$$ LANGUAGE plpgsql;

-- Check autonomous delegate limit
CREATE OR REPLACE FUNCTION check_autonomous_delegate_limit(
    p_delegate_id UUID,
    p_amount DECIMAL(20, 8)
) RETURNS JSONB AS $$
DECLARE
    v_delegate RECORD;
BEGIN
    SELECT * INTO v_delegate
    FROM autonomous_delegates
    WHERE id = p_delegate_id
      AND revoked_at IS NULL
      AND expires_at > NOW();
    
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'allowed', FALSE,
            'reason', 'Delegate not found or expired'
        );
    END IF;
    
    IF (v_delegate.used_amount_usd + p_amount) > v_delegate.max_amount_usd THEN
        RETURN jsonb_build_object(
            'allowed', FALSE,
            'reason', 'Exceeds delegate spending limit',
            'limit', v_delegate.max_amount_usd,
            'used', v_delegate.used_amount_usd,
            'requested', p_amount
        );
    END IF;
    
    RETURN jsonb_build_object(
        'allowed', TRUE,
        'delegate_id', v_delegate.id,
        'remaining', v_delegate.max_amount_usd - v_delegate.used_amount_usd
    );
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE platforms IS 'Platforms and applications integrating x0 for AI agent payments';
COMMENT ON TABLE api_keys IS 'API keys for authenticating merchant requests';
COMMENT ON TABLE encrypted_keys IS 'Encrypted keypairs for session keys, MPC shards, and autonomous delegates';
COMMENT ON TABLE ai_agent_sessions IS 'Authorization sessions allowing AI agents to make payments';
COMMENT ON TABLE session_keys IS 'Device-bound keys for automatic transaction signing within limits';
COMMENT ON TABLE autonomous_delegates IS 'Lit Protocol encrypted keys for server-side autonomous signing';
COMMENT ON TABLE payments IS 'Payment transactions initiated by AI agents';
COMMENT ON TABLE webhook_events IS 'Webhook delivery queue for event notifications';
COMMENT ON TABLE mpc_wallets IS 'Multi-party computation wallets for non-custodial security';
COMMENT ON TABLE webauthn_credentials IS 'Passkey credentials for WebAuthn authentication';
