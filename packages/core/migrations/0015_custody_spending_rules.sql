-- Migration: OAuth-style spending rules for agent wallet custody
-- Enables per-custody spending limits, recipient whitelists, and daily caps

-- Spending rules for each custody grant
CREATE TABLE IF NOT EXISTS agent_custody_spending_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    custody_id UUID NOT NULL REFERENCES agent_wallet_custody(id) ON DELETE CASCADE,
    
    -- Per-transaction limits
    max_transaction_amount_sol NUMERIC(20, 9),
    max_transaction_amount_usdc NUMERIC(20, 9),
    
    -- Daily aggregate limits
    daily_limit_sol NUMERIC(20, 9),
    daily_limit_usdc NUMERIC(20, 9),
    
    -- Whitelists (empty = allow all)
    allowed_recipients JSONB DEFAULT '[]'::jsonb,
    allowed_programs JSONB DEFAULT '[]'::jsonb,
    
    -- High-value transaction handling (future: require user approval)
    require_approval_above_sol NUMERIC(20, 9),
    require_approval_above_usdc NUMERIC(20, 9),
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(custody_id)
);

-- Track daily spending per custody for limit enforcement
CREATE TABLE IF NOT EXISTS agent_custody_daily_spending (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    custody_id UUID NOT NULL REFERENCES agent_wallet_custody(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    
    -- Aggregate spending by token type
    total_sol NUMERIC(20, 9) NOT NULL DEFAULT 0,
    total_usdc NUMERIC(20, 9) NOT NULL DEFAULT 0,
    transaction_count INTEGER NOT NULL DEFAULT 0,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ,
    
    UNIQUE(custody_id, date)
);

-- Add spending_rules_id reference to custody table
ALTER TABLE agent_wallet_custody 
ADD COLUMN IF NOT EXISTS spending_rules_id UUID REFERENCES agent_custody_spending_rules(id);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_custody_spending_rules_custody 
ON agent_custody_spending_rules(custody_id);

CREATE INDEX IF NOT EXISTS idx_custody_daily_spending_lookup 
ON agent_custody_daily_spending(custody_id, date);

-- Comments
COMMENT ON TABLE agent_custody_spending_rules IS 'OAuth-style spending limits for agent wallet custody grants';
COMMENT ON TABLE agent_custody_daily_spending IS 'Daily spending aggregates for limit enforcement';
COMMENT ON COLUMN agent_custody_spending_rules.allowed_recipients IS 'JSON array of allowed recipient wallet addresses (empty = any)';
COMMENT ON COLUMN agent_custody_spending_rules.allowed_programs IS 'JSON array of allowed Solana program IDs (empty = any)';
