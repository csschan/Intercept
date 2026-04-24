-- Migration: Add on-chain execution columns to auth_requests
-- Stores real devnet tx signature + Explorer URL after authorized execution

ALTER TABLE auth_requests
  ADD COLUMN IF NOT EXISTS tx_signature text,
  ADD COLUMN IF NOT EXISTS tx_explorer_url text;
