-- x0 Surgical Schema Additions
-- Based on actual query requirements from the codebase

-- =============================================================================
-- ADD MISSING COLUMNS TO EXISTING TABLES
-- =============================================================================

-- Platforms: Add missing columns
ALTER TABLE platforms ADD COLUMN IF NOT EXISTS wallet_type VARCHAR(20) DEFAULT 'external';
ALTER TABLE platforms ADD COLUMN IF NOT EXISTS wallet_generated BOOLEAN DEFAULT FALSE;
ALTER TABLE platforms ADD COLUMN IF NOT EXISTS default_mode VARCHAR(10) DEFAULT 'test';

-- API Keys: Add missing columns for rate limiting and agent keys
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS sha256_hash VARCHAR(256);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS argon2_hash VARCHAR(255);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS rate_limit_per_hour INTEGER DEFAULT 1000;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS is_agent_key BOOLEAN DEFAULT FALSE;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_hash_argon2 VARCHAR(255);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS agent_metadata JSONB;

-- AI Agent Sessions: Add missing columns
ALTER TABLE ai_agent_sessions ADD COLUMN IF NOT EXISTS allowed_recipients TEXT[];
ALTER TABLE ai_agent_sessions ADD COLUMN IF NOT EXISTS crypto_enforced BOOLEAN DEFAULT FALSE;
ALTER TABLE ai_agent_sessions ADD COLUMN IF NOT EXISTS pkp_public_key TEXT;
ALTER TABLE ai_agent_sessions ADD COLUMN IF NOT EXISTS lit_action_ipfs_cid TEXT;

-- Admin Users: Add missing columns
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255);
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS last_login_ip INET;
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES admin_users(id);

-- WebAuthn Credentials: Add missing columns
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS public_key_cose BYTEA;
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS counter BIGINT DEFAULT 0;
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS user_handle VARCHAR(255);

-- Session Keys: Add missing columns
ALTER TABLE session_keys ADD COLUMN IF NOT EXISTS recovery_qr_hash VARCHAR(255);
ALTER TABLE session_keys ADD COLUMN IF NOT EXISTS authorized_recipients TEXT[];
ALTER TABLE session_keys ADD COLUMN IF NOT EXISTS refund_status VARCHAR(20) DEFAULT 'not_applicable';
ALTER TABLE session_keys ADD COLUMN IF NOT EXISTS refund_signature VARCHAR(128);
ALTER TABLE session_keys ADD COLUMN IF NOT EXISTS refund_attempted_at TIMESTAMPTZ;
ALTER TABLE session_keys ADD COLUMN IF NOT EXISTS refund_completed_at TIMESTAMPTZ;

-- Autonomous Delegates: Add missing column
ALTER TABLE autonomous_delegates ADD COLUMN IF NOT EXISTS lit_encrypted_keypair_id UUID REFERENCES encrypted_keys(id);

-- Payments: Add missing columns
ALTER TABLE payments ADD COLUMN IF NOT EXISTS customer_wallet VARCHAR(255);
ALTER TABLE payments ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMPTZ;
ALTER TABLE payments ADD COLUMN IF NOT EXISTS mode VARCHAR(10) DEFAULT 'test';

-- Idempotency Keys: Add missing columns
ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS response_status_code INTEGER;
ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS last_accessed_at TIMESTAMPTZ;
ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS endpoint VARCHAR(255);
ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS request_method VARCHAR(10);
ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS request_fingerprint VARCHAR(255);
ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS created_resource_id UUID;

-- Encrypted Keys: Add missing column
ALTER TABLE encrypted_keys ADD COLUMN IF NOT EXISTS device_fingerprint TEXT;

-- =============================================================================
-- ADD MISSING WEBHOOK EVENT TYPES
-- =============================================================================

-- Extend the webhook_event_type enum with additional values
ALTER TYPE webhook_event_type ADD VALUE IF NOT EXISTS 'payment_confirmed';
ALTER TYPE webhook_event_type ADD VALUE IF NOT EXISTS 'autonomous_delegate.created';
ALTER TYPE webhook_event_type ADD VALUE IF NOT EXISTS 'withdrawal.initiated';
ALTER TYPE webhook_event_type ADD VALUE IF NOT EXISTS 'withdrawal.completed';
ALTER TYPE webhook_event_type ADD VALUE IF NOT EXISTS 'withdrawal.failed';

-- =============================================================================
-- CREATE MISSING TABLES
-- =============================================================================

-- Payment Intent Status enum
DO $$ BEGIN
    CREATE TYPE payment_intent_status AS ENUM (
        'requires_payment',
        'processing', 
        'succeeded',
        'failed',
        'cancelled',
        'expired'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Payment Intents (Stripe-like payment flow)
CREATE TABLE IF NOT EXISTS payment_intents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Amount info
    amount DECIMAL(20, 8) NOT NULL,
    currency VARCHAR(10) DEFAULT 'USDC',
    
    -- Status
    status payment_intent_status NOT NULL DEFAULT 'requires_payment',
    
    -- Description and metadata
    description TEXT,
    metadata JSONB DEFAULT '{}',
    
    -- Agent context
    agent_id VARCHAR(255),
    customer_wallet VARCHAR(255),
    
    -- Client-side secret for completing payment
    client_secret VARCHAR(255) NOT NULL,
    
    -- Related payment
    payment_id UUID REFERENCES payments(id) ON DELETE SET NULL,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours'
);

CREATE INDEX IF NOT EXISTS idx_payment_intents_platform ON payment_intents(platform_id);
CREATE INDEX IF NOT EXISTS idx_payment_intents_status ON payment_intents(status);

-- Payment Intent Events (audit trail)
CREATE TABLE IF NOT EXISTS payment_intent_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payment_intent_id UUID NOT NULL REFERENCES payment_intents(id) ON DELETE CASCADE,
    
    -- Event info
    event_type VARCHAR(50) NOT NULL,
    old_status payment_intent_status,
    new_status payment_intent_status,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payment_intent_events_intent ON payment_intent_events(payment_intent_id);

-- System Wallets (platform treasury wallets)
CREATE TABLE IF NOT EXISTS system_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_type VARCHAR(50) NOT NULL,
    public_key VARCHAR(255) NOT NULL,
    
    -- Optional encrypted key reference
    encrypted_key_id UUID REFERENCES encrypted_keys(id),
    
    -- Description
    description TEXT,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Admin who created
    created_by UUID REFERENCES admin_users(id),
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_system_wallets_type ON system_wallets(wallet_type);

-- System Wallet Audit Log
CREATE TABLE IF NOT EXISTS system_wallet_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    system_wallet_id UUID NOT NULL REFERENCES system_wallets(id) ON DELETE CASCADE,
    
    -- Action details
    action VARCHAR(100) NOT NULL,
    performed_by UUID REFERENCES admin_users(id),
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_system_wallet_audit ON system_wallet_audit_log(system_wallet_id);

-- Withdrawals
CREATE TABLE IF NOT EXISTS withdrawals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Withdrawal details
    to_address VARCHAR(255) NOT NULL,
    amount DECIMAL(20, 8) NOT NULL,
    token VARCHAR(20) DEFAULT 'USDC',
    
    -- Status
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    
    -- Transaction
    transaction_signature VARCHAR(128),
    
    -- Error handling
    error_message TEXT,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_withdrawals_platform ON withdrawals(platform_id);
CREATE INDEX IF NOT EXISTS idx_withdrawals_status ON withdrawals(status);

-- API Key Audit Log
CREATE TABLE IF NOT EXISTS api_key_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Request details
    endpoint VARCHAR(255),
    http_method VARCHAR(10),
    ip_address INET,
    user_agent TEXT,
    
    -- Response
    response_status INTEGER,
    response_time_ms INTEGER,
    
    -- Security flags
    suspicious BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_key_audit_platform ON api_key_audit_log(platform_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_key_audit_key ON api_key_audit_log(api_key_id);

-- Autonomous Delegate Usage
CREATE TABLE IF NOT EXISTS autonomous_delegate_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delegate_id UUID NOT NULL REFERENCES autonomous_delegates(id) ON DELETE CASCADE,
    
    -- Transaction details
    amount_usd DECIMAL(20, 8) NOT NULL,
    recipient_wallet VARCHAR(255),
    transaction_signature VARCHAR(128),
    
    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_autonomous_delegate_usage_delegate ON autonomous_delegate_usage(delegate_id);

-- Session Keypairs (encrypted session wallet keypairs)
CREATE TABLE IF NOT EXISTS session_keypairs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_key_id UUID NOT NULL REFERENCES session_keys(id) ON DELETE CASCADE,
    
    -- Key reference
    encrypted_key_id UUID NOT NULL REFERENCES encrypted_keys(id),
    
    -- Public key for lookups
    public_key VARCHAR(255) NOT NULL,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_session_keypairs_session ON session_keypairs(session_key_id);
CREATE INDEX IF NOT EXISTS idx_session_keypairs_public ON session_keypairs(public_key);

-- Session Key Authorizations (dynamic recipient authorization)
CREATE TABLE IF NOT EXISTS session_key_authorizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_key_id UUID NOT NULL REFERENCES session_keys(id) ON DELETE CASCADE,
    
    -- Authorized platform/agent
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    agent_id VARCHAR(255),
    
    -- Signature proof
    authorization_signature TEXT NOT NULL,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_session_key_auth_session ON session_key_authorizations(session_key_id);
CREATE INDEX IF NOT EXISTS idx_session_key_auth_platform ON session_key_authorizations(platform_id);

-- Session Key Recipient Usage
CREATE TABLE IF NOT EXISTS session_key_recipient_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_key_id UUID NOT NULL REFERENCES session_keys(id) ON DELETE CASCADE,
    
    -- Recipient details
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    agent_id VARCHAR(255),
    
    -- Usage
    amount_usd DECIMAL(20, 8) NOT NULL,
    transaction_signature VARCHAR(128),
    
    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_session_key_recipient_usage_session ON session_key_recipient_usage(session_key_id);

-- Lit Network Shards (for MPC wallet encrypted key shards)
CREATE TABLE IF NOT EXISTS lit_network_shards (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(255) NOT NULL,
    passkey_credential_id VARCHAR(255) NOT NULL,
    
    -- Encrypted shard data
    ciphertext TEXT NOT NULL,
    data_to_encrypt_hash TEXT NOT NULL,
    
    -- Access conditions (Lit Protocol)
    access_conditions JSONB NOT NULL,
    
    -- Node info
    connected_nodes INTEGER DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lit_shards_wallet ON lit_network_shards(wallet_address);
CREATE INDEX IF NOT EXISTS idx_lit_shards_credential ON lit_network_shards(passkey_credential_id);

-- Spending Attestations (cryptographic proof of autonomous spending)
CREATE TABLE IF NOT EXISTS spending_attestations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delegate_id UUID NOT NULL REFERENCES autonomous_delegates(id) ON DELETE CASCADE,
    
    -- Attestation data
    attestation_json JSONB NOT NULL,
    attestation_signature TEXT NOT NULL,
    attestation_hash VARCHAR(128) NOT NULL,
    
    -- Transaction reference
    transaction_signature VARCHAR(128),
    
    -- Spending details
    amount_usd DECIMAL(20, 8) NOT NULL,
    recipient_wallet VARCHAR(255),
    
    -- Version
    version SMALLINT DEFAULT 1,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_spending_attestations_delegate ON spending_attestations(delegate_id);

-- System Events (for system-level audit logging)
CREATE TABLE IF NOT EXISTS system_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Event details
    event_type VARCHAR(100) NOT NULL,
    event_data JSONB NOT NULL,
    
    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_system_events_type ON system_events(event_type, created_at DESC);

-- Pricing Suggestions (AI pricing recommendations)
CREATE TABLE IF NOT EXISTS pricing_suggestions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    
    -- Context
    agent_id VARCHAR(255),
    product_id VARCHAR(255),
    
    -- Pricing
    base_price DECIMAL(20, 8) NOT NULL,
    suggested_price DECIMAL(20, 8),
    currency VARCHAR(10) DEFAULT 'USD',
    
    -- Adjustment type
    adjustment_type VARCHAR(20),
    adjustment_factor DECIMAL(10, 4),
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pricing_suggestions_platform ON pricing_suggestions(platform_id);

-- PPP Adjustments (Purchasing Power Parity data)
CREATE TABLE IF NOT EXISTS ppp_adjustments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Country info
    country_code VARCHAR(3) NOT NULL UNIQUE,
    country_name VARCHAR(100) NOT NULL,
    
    -- PPP factor (relative to USD)
    ppp_factor DECIMAL(10, 4) NOT NULL,
    
    -- Currency
    currency_code VARCHAR(10),
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ppp_country ON ppp_adjustments(country_code);

-- Key Operation Logs (key management audit)
CREATE TABLE IF NOT EXISTS key_operation_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id UUID NOT NULL,
    
    -- Operation details
    operation VARCHAR(50) NOT NULL,
    operator VARCHAR(255),
    
    -- Result
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    
    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_key_operation_logs_key ON key_operation_logs(key_id);

-- Admin Audit Log
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID REFERENCES admin_users(id) ON DELETE SET NULL,
    
    -- Action details
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    
    -- Details
    details JSONB DEFAULT '{}',
    
    -- Security context
    ip_address INET,
    user_agent TEXT,
    
    -- Result
    status VARCHAR(20) DEFAULT 'success',
    error_message TEXT,
    
    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_admin ON admin_audit_log(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_action ON admin_audit_log(action, created_at DESC);

-- Audit Logs (general platform audit)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID REFERENCES platforms(id) ON DELETE SET NULL,
    
    -- Action
    action VARCHAR(100) NOT NULL,
    details JSONB DEFAULT '{}',
    
    -- Context
    ip_address VARCHAR(45),
    user_agent TEXT,
    
    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_platform ON audit_logs(platform_id, created_at DESC);

-- Gas Fee Costs (track Solana transaction costs)
CREATE TABLE IF NOT EXISTS gas_fee_costs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payment_id UUID REFERENCES payments(id) ON DELETE SET NULL,
    
    -- Transaction
    transaction_signature VARCHAR(128),
    transaction_type VARCHAR(50),
    
    -- Costs
    compute_units_consumed BIGINT,
    fee_lamports BIGINT,
    priority_fee_lamports BIGINT,
    
    -- Profitability analysis
    payment_amount_usd DECIMAL(20, 8),
    fee_amount_usd DECIMAL(20, 8),
    
    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gas_fee_payment ON gas_fee_costs(payment_id);

-- =============================================================================
-- MISSING FUNCTIONS
-- =============================================================================

-- Generate payment intent client secret
CREATE OR REPLACE FUNCTION generate_payment_intent_client_secret(intent_id UUID)
RETURNS TEXT AS $$
BEGIN
    RETURN 'pi_' || REPLACE(intent_id::text, '-', '') || '_secret_' || encode(gen_random_bytes(16), 'hex');
END;
$$ LANGUAGE plpgsql;

-- Check API key rate limit
CREATE OR REPLACE FUNCTION check_api_key_rate_limit(
    p_api_key_id UUID,
    p_endpoint TEXT,
    p_rate_limit_per_hour INTEGER
) RETURNS BOOLEAN AS $$
DECLARE
    v_request_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_request_count
    FROM api_key_audit_log
    WHERE api_key_id = p_api_key_id
      AND created_at > NOW() - INTERVAL '1 hour';
    
    RETURN v_request_count < p_rate_limit_per_hour;
END;
$$ LANGUAGE plpgsql;

-- Record API key usage
CREATE OR REPLACE FUNCTION record_api_key_usage(
    p_api_key_id UUID,
    p_endpoint TEXT
) RETURNS void AS $$
BEGIN
    UPDATE api_keys 
    SET last_used_at = NOW(), 
        request_count = request_count + 1
    WHERE id = p_api_key_id;
END;
$$ LANGUAGE plpgsql;

-- Cleanup old API key usage records
CREATE OR REPLACE FUNCTION cleanup_old_api_key_usage()
RETURNS void AS $$
BEGIN
    DELETE FROM api_key_audit_log
    WHERE created_at < NOW() - INTERVAL '30 days';
    
    DELETE FROM rate_limit_entries
    WHERE window_start < NOW() - INTERVAL '2 hours';
END;
$$ LANGUAGE plpgsql;

-- Cleanup expired idempotency keys
CREATE OR REPLACE FUNCTION cleanup_expired_idempotency_keys()
RETURNS void AS $$
BEGIN
    DELETE FROM idempotency_keys
    WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Get PPP adjusted price
CREATE OR REPLACE FUNCTION get_ppp_adjusted_price(
    p_base_price DECIMAL(20, 8),
    p_country_code TEXT
) RETURNS DECIMAL(20, 8) AS $$
DECLARE
    v_ppp_factor DECIMAL(10, 4);
BEGIN
    SELECT ppp_factor INTO v_ppp_factor
    FROM ppp_adjustments
    WHERE country_code = p_country_code;
    
    IF v_ppp_factor IS NULL THEN
        RETURN p_base_price;
    END IF;
    
    RETURN p_base_price * v_ppp_factor;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- VIEWS FOR ANALYTICS (optional, used by gas tracking)
-- =============================================================================

CREATE OR REPLACE VIEW gas_cost_analytics AS
SELECT 
    DATE_TRUNC('day', created_at) as period,
    COUNT(*) as transaction_count,
    AVG(fee_lamports) as avg_fee_lamports,
    SUM(fee_lamports) as total_fee_lamports,
    AVG(fee_amount_usd) as avg_fee_usd,
    SUM(fee_amount_usd) as total_fee_usd,
    AVG(compute_units_consumed) as avg_compute_units
FROM gas_fee_costs
WHERE created_at > NOW() - INTERVAL '30 days'
GROUP BY DATE_TRUNC('day', created_at)
ORDER BY period DESC;

CREATE OR REPLACE VIEW gas_profitability_check AS
SELECT 
    DATE_TRUNC('day', gfc.created_at) as period,
    COUNT(*) as transaction_count,
    SUM(gfc.payment_amount_usd) as total_payment_volume,
    SUM(gfc.fee_amount_usd) as total_fees,
    CASE 
        WHEN SUM(gfc.payment_amount_usd) > 0 
        THEN SUM(gfc.fee_amount_usd) / SUM(gfc.payment_amount_usd) * 100 
        ELSE 0 
    END as fee_percentage,
    SUM(gfc.payment_amount_usd) - SUM(gfc.fee_amount_usd) as net_revenue
FROM gas_fee_costs gfc
WHERE gfc.created_at > NOW() - INTERVAL '30 days'
GROUP BY DATE_TRUNC('day', gfc.created_at)
ORDER BY period DESC;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE payment_intents IS 'Stripe-like payment intent flow for AI agent payments';
COMMENT ON TABLE system_wallets IS 'Platform-owned treasury wallets';
COMMENT ON TABLE withdrawals IS 'Withdrawal requests from platform wallets';
COMMENT ON TABLE lit_network_shards IS 'Lit Protocol encrypted key shards for MPC wallets';
COMMENT ON TABLE spending_attestations IS 'Cryptographic proofs of autonomous delegate spending';
COMMENT ON TABLE ppp_adjustments IS 'Purchasing Power Parity adjustment factors by country';
