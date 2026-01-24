-- Fix payment_intents column nullability for SQLx type inference

-- Make capture_method NOT NULL with default
UPDATE payment_intents SET capture_method = 'automatic' WHERE capture_method IS NULL;
ALTER TABLE payment_intents ALTER COLUMN capture_method SET NOT NULL;
ALTER TABLE payment_intents ALTER COLUMN capture_method SET DEFAULT 'automatic';

-- Make agent_metadata NOT NULL with default
UPDATE payment_intents SET agent_metadata = '{}' WHERE agent_metadata IS NULL;
ALTER TABLE payment_intents ALTER COLUMN agent_metadata SET NOT NULL;
ALTER TABLE payment_intents ALTER COLUMN agent_metadata SET DEFAULT '{}';

-- Fix platforms.default_mode to NOT NULL with default (column is named default_mode, not mode)
UPDATE platforms SET default_mode = 'test' WHERE default_mode IS NULL;
ALTER TABLE platforms ALTER COLUMN default_mode SET NOT NULL;
ALTER TABLE platforms ALTER COLUMN default_mode SET DEFAULT 'test';

-- Fix api_keys.mode to NOT NULL with default  
UPDATE api_keys SET mode = 'test' WHERE mode IS NULL;
ALTER TABLE api_keys ALTER COLUMN mode SET NOT NULL;
ALTER TABLE api_keys ALTER COLUMN mode SET DEFAULT 'test';

-- Fix api_keys.scopes to NOT NULL with default (it's a text[] array)
UPDATE api_keys SET scopes = ARRAY['full'] WHERE scopes IS NULL;
ALTER TABLE api_keys ALTER COLUMN scopes SET NOT NULL;
ALTER TABLE api_keys ALTER COLUMN scopes SET DEFAULT ARRAY['full'];

-- Fix session_keys.created_at to NOT NULL
UPDATE session_keys SET created_at = now() WHERE created_at IS NULL;
ALTER TABLE session_keys ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE session_keys ALTER COLUMN created_at SET DEFAULT now();

-- NOTE: admins table doesn't exist in this schema, skipping

-- Fix payments.mode to NOT NULL with default
UPDATE payments SET mode = 'test' WHERE mode IS NULL;
ALTER TABLE payments ALTER COLUMN mode SET NOT NULL;
ALTER TABLE payments ALTER COLUMN mode SET DEFAULT 'test';

-- Fix idempotency_keys.request_fingerprint - make sure it's nullable (as expected by code)
-- This one should stay nullable based on the code logic
