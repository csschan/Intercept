-- Migration: Address-based merchant binding
-- Names are spoofable; addresses are not. This migration introduces real
-- on-chain address binding for known merchants and session allowlists.

-- 1. Known merchants now bind to a real recipient address
ALTER TABLE known_merchants
  ADD COLUMN IF NOT EXISTS address text,
  ADD COLUMN IF NOT EXISTS chain text,
  ADD COLUMN IF NOT EXISTS category text;

CREATE INDEX IF NOT EXISTS idx_known_merchants_agent_address
  ON known_merchants (agent_id, address)
  WHERE address IS NOT NULL;

-- 2. Spending sessions can lock down recipient addresses (the unforgeable field)
ALTER TABLE spending_sessions
  ADD COLUMN IF NOT EXISTS allowed_recipients text[] DEFAULT '{}'::text[];
