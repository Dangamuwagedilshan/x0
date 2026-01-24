-- Agent Wallet Custody Tables
-- For secure agent-controlled wallet access via Lit Protocol

-- Main custody records - tracks which agents have custody of which wallets
CREATE TABLE IF NOT EXISTS agent_wallet_custody (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_id UUID NOT NULL REFERENCES platforms(id),
    agent_id VARCHAR(255) NOT NULL,
    user_wallet VARCHAR(64) NOT NULL,
    -- Hash of the access_secret (NEVER store the actual secret)
    access_secret_hash VARCHAR(64) NOT NULL,
    -- Reference to the encrypted shard
    lit_shard_id VARCHAR(255) NOT NULL,
    -- Optional expiry
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Indexes for common queries
    CONSTRAINT unique_agent_wallet_custody UNIQUE (platform_id, agent_id, user_wallet)
);

CREATE INDEX idx_agent_wallet_custody_platform ON agent_wallet_custody(platform_id);
CREATE INDEX idx_agent_wallet_custody_agent ON agent_wallet_custody(agent_id);
CREATE INDEX idx_agent_wallet_custody_wallet ON agent_wallet_custody(user_wallet);
CREATE INDEX idx_agent_wallet_custody_active ON agent_wallet_custody(is_active) WHERE is_active = TRUE;

-- Encrypted shard storage - stores the Lit Protocol encrypted keypairs
CREATE TABLE IF NOT EXISTS agent_custody_shards (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_address VARCHAR(64) NOT NULL,
    -- Hash of access_secret for this shard
    access_secret_hash VARCHAR(64) NOT NULL,
    
    -- For local storage (development mode)
    encrypted_data BYTEA,
    server_nonce BYTEA,
    
    -- For Lit Protocol storage (production)
    ciphertext BYTEA,
    data_to_encrypt_hash VARCHAR(255),
    access_conditions JSONB,
    lit_node_count INTEGER,
    
    -- Client-side encryption nonce (used in both modes)
    client_nonce BYTEA NOT NULL,
    
    -- Storage type: 'local' or 'lit'
    storage_type VARCHAR(20) NOT NULL DEFAULT 'local',
    
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_custody_shards_wallet ON agent_custody_shards(wallet_address);
CREATE INDEX idx_agent_custody_shards_hash ON agent_custody_shards(access_secret_hash);

-- Audit log for custody operations
CREATE TABLE IF NOT EXISTS agent_custody_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    custody_id UUID REFERENCES agent_wallet_custody(id),
    platform_id UUID NOT NULL,
    agent_id VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL, -- 'grant', 'sign', 'revoke'
    wallet_address VARCHAR(64),
    success BOOLEAN NOT NULL,
    error_message TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_custody_audit_custody ON agent_custody_audit(custody_id);
CREATE INDEX idx_agent_custody_audit_platform ON agent_custody_audit(platform_id);
CREATE INDEX idx_agent_custody_audit_created ON agent_custody_audit(created_at);

COMMENT ON TABLE agent_wallet_custody IS 'Tracks agent custody of user wallets - agents can sign transactions on behalf of users';
COMMENT ON COLUMN agent_wallet_custody.access_secret_hash IS 'SHA256 hash of the access_secret - the actual secret is NEVER stored';
COMMENT ON TABLE agent_custody_shards IS 'Encrypted keypair storage - either local (dev) or Lit Protocol (prod)';
