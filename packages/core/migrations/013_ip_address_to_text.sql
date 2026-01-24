-- Change inet columns to text for simpler handling

-- admin_users.last_login_ip
ALTER TABLE admin_users ALTER COLUMN last_login_ip TYPE TEXT USING last_login_ip::TEXT;

-- api_key_audit_log.ip_address  
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'api_key_audit_log' 
               AND column_name = 'ip_address'
               AND data_type = 'inet') THEN
        ALTER TABLE api_key_audit_log ALTER COLUMN ip_address TYPE TEXT USING ip_address::TEXT;
    END IF;
END $$;

-- admin_audit_log.ip_address
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name = 'admin_audit_log' 
               AND column_name = 'ip_address'
               AND data_type = 'inet') THEN
        ALTER TABLE admin_audit_log ALTER COLUMN ip_address TYPE TEXT USING ip_address::TEXT;
    END IF;
END $$;
