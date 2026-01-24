-- Migration: 004_schema_refinements.sql
-- Fix remaining schema issues identified from compile errors

-- Fix gas_fee_costs table - add missing columns
ALTER TABLE gas_fee_costs ADD COLUMN IF NOT EXISTS network VARCHAR(50) DEFAULT 'solana-mainnet';
ALTER TABLE gas_fee_costs ADD COLUMN IF NOT EXISTS gas_cost_lamports BIGINT;
ALTER TABLE gas_fee_costs ADD COLUMN IF NOT EXISTS gas_cost_sol DECIMAL(20,10);
ALTER TABLE gas_fee_costs ADD COLUMN IF NOT EXISTS gas_cost_usd DECIMAL(20,8);
ALTER TABLE gas_fee_costs ADD COLUMN IF NOT EXISTS sol_price_at_time DECIMAL(20,8);
ALTER TABLE gas_fee_costs ADD COLUMN IF NOT EXISTS fee_payer VARCHAR(100);
ALTER TABLE gas_fee_costs ADD COLUMN IF NOT EXISTS compute_units_used INTEGER;

-- Drop and recreate views (can't just replace if column names change)
DROP VIEW IF EXISTS gas_cost_analytics CASCADE;
DROP VIEW IF EXISTS gas_profitability_check CASCADE;

-- Recreate gas_cost_analytics view with correct columns expected by Rust code
CREATE VIEW gas_cost_analytics AS
SELECT 
    DATE(created_at) as date,
    COALESCE(network, 'solana-mainnet') as network,
    transaction_type,
    COUNT(*)::bigint as transaction_count,
    AVG(COALESCE(gas_cost_usd, fee_amount_usd)) as avg_gas_usd,
    MIN(COALESCE(gas_cost_usd, fee_amount_usd)) as min_gas_usd,
    MAX(COALESCE(gas_cost_usd, fee_amount_usd)) as max_gas_usd,
    SUM(COALESCE(gas_cost_usd, fee_amount_usd)) as total_gas_usd,
    AVG(COALESCE(compute_units_used, compute_units_consumed))::numeric as avg_compute_units,
    AVG(priority_fee_lamports)::numeric as avg_priority_fee
FROM gas_fee_costs
WHERE created_at > NOW() - INTERVAL '30 days'
GROUP BY DATE(created_at), COALESCE(network, 'solana-mainnet'), transaction_type;

-- Recreate gas_profitability_check view with correct columns expected by Rust code
CREATE VIEW gas_profitability_check AS
SELECT 
    DATE(gfc.created_at) as date,
    COALESCE(gfc.network, 'solana-mainnet') as network,
    COUNT(*)::bigint as transaction_count,
    AVG(COALESCE(gfc.gas_cost_usd, gfc.fee_amount_usd)) as avg_gas_cost,
    AVG(COALESCE(gfc.fee_amount_usd, 0) - COALESCE(gfc.gas_cost_usd, gfc.fee_amount_usd, 0)) as avg_fee_margin,
    (COUNT(*) FILTER (WHERE COALESCE(gfc.fee_amount_usd, 0) > COALESCE(gfc.gas_cost_usd, gfc.fee_amount_usd, 0)) * 100.0 / NULLIF(COUNT(*), 0)) as profitable_percentage,
    SUM(COALESCE(gfc.gas_cost_usd, gfc.fee_amount_usd, 0)) as total_gas_spent,
    SUM(COALESCE(gfc.fee_amount_usd, 0) - COALESCE(gfc.gas_cost_usd, gfc.fee_amount_usd, 0)) as total_fee_margin,
    SUM(COALESCE(gfc.payment_amount_usd, 0)) - SUM(COALESCE(gfc.gas_cost_usd, gfc.fee_amount_usd, 0)) as net_margin
FROM gas_fee_costs gfc
WHERE gfc.created_at > NOW() - INTERVAL '30 days'
GROUP BY DATE(gfc.created_at), COALESCE(gfc.network, 'solana-mainnet');

-- Fix api_key_audit_log table - add missing columns
ALTER TABLE api_key_audit_log ADD COLUMN IF NOT EXISTS request_id UUID;
ALTER TABLE api_key_audit_log ADD COLUMN IF NOT EXISTS status VARCHAR(50);

-- Fix idempotency_keys table - add missing columns
ALTER TABLE idempotency_keys ADD COLUMN IF NOT EXISTS ip_address INET;

-- Fix system_wallets table - add unique constraint for ON CONFLICT
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes 
                   WHERE indexname = 'system_wallets_wallet_type_key') THEN
        ALTER TABLE system_wallets ADD CONSTRAINT system_wallets_wallet_type_key UNIQUE (wallet_type);
    END IF;
EXCEPTION WHEN duplicate_object THEN
    NULL;
END $$;

-- Add missing columns to admin_users if they don't exist with proper NOT NULL defaults
DO $$
BEGIN
    -- Check if columns exist and add defaults if not
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'admin_users' AND column_name = 'full_name' AND is_nullable = 'YES') THEN
        UPDATE admin_users SET full_name = email WHERE full_name IS NULL;
        ALTER TABLE admin_users ALTER COLUMN full_name SET NOT NULL;
        ALTER TABLE admin_users ALTER COLUMN full_name SET DEFAULT '';
    END IF;
    
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'admin_users' AND column_name = 'role' AND is_nullable = 'YES') THEN
        UPDATE admin_users SET role = 'admin' WHERE role IS NULL;
        ALTER TABLE admin_users ALTER COLUMN role SET NOT NULL;
        ALTER TABLE admin_users ALTER COLUMN role SET DEFAULT 'admin';
    END IF;
    
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'admin_users' AND column_name = 'is_active' AND is_nullable = 'YES') THEN
        UPDATE admin_users SET is_active = true WHERE is_active IS NULL;
        ALTER TABLE admin_users ALTER COLUMN is_active SET NOT NULL;
        ALTER TABLE admin_users ALTER COLUMN is_active SET DEFAULT true;
    END IF;
    
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'admin_users' AND column_name = 'created_at' AND is_nullable = 'YES') THEN
        UPDATE admin_users SET created_at = NOW() WHERE created_at IS NULL;
        ALTER TABLE admin_users ALTER COLUMN created_at SET NOT NULL;
        ALTER TABLE admin_users ALTER COLUMN created_at SET DEFAULT NOW();
    END IF;
END $$;

-- Add ip_address to admin_audit_log if missing
ALTER TABLE admin_audit_log ADD COLUMN IF NOT EXISTS ip_address INET;

-- Add platform mode default
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'platforms' AND column_name = 'mode' AND is_nullable = 'YES') THEN
        UPDATE platforms SET mode = 'test' WHERE mode IS NULL;
        ALTER TABLE platforms ALTER COLUMN mode SET DEFAULT 'test';
    END IF;
END $$;

-- Add payment mode default  
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'payments' AND column_name = 'mode' AND is_nullable = 'YES') THEN
        UPDATE payments SET mode = 'test' WHERE mode IS NULL;
        ALTER TABLE payments ALTER COLUMN mode SET DEFAULT 'test';
    END IF;
END $$;

-- Add session_keys created_at default
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'session_keys' AND column_name = 'created_at' AND is_nullable = 'YES') THEN
        UPDATE session_keys SET created_at = NOW() WHERE created_at IS NULL;
        ALTER TABLE session_keys ALTER COLUMN created_at SET DEFAULT NOW();
    END IF;
END $$;

-- Add api_keys is_active default
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'api_keys' AND column_name = 'is_active' AND is_nullable = 'YES') THEN
        UPDATE api_keys SET is_active = true WHERE is_active IS NULL;
        ALTER TABLE api_keys ALTER COLUMN is_active SET DEFAULT true;
    END IF;
END $$;

COMMENT ON COLUMN gas_fee_costs.gas_cost_lamports IS 'Gas cost in lamports (native Solana units)';
COMMENT ON COLUMN gas_fee_costs.gas_cost_usd IS 'Gas cost converted to USD';
COMMENT ON COLUMN gas_fee_costs.priority_fee_lamports IS 'Priority fee in lamports for faster processing';
