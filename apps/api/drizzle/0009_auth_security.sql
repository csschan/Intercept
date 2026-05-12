-- Auth security fixes: hashing + missing columns

-- API key prefix for display
ALTER TABLE owners ADD COLUMN IF NOT EXISTS api_key_prefix TEXT;

-- x402 max per call for sessions
ALTER TABLE spending_sessions ADD COLUMN IF NOT EXISTS x402_max_per_call NUMERIC(18,6);
