-- Migration: Add security_context column to auth_requests
-- Run this after the initial migration (0000_init.sql)

ALTER TABLE auth_requests
  ADD COLUMN IF NOT EXISTS security_context jsonb;

-- Index for querying high-risk transactions
CREATE INDEX IF NOT EXISTS idx_auth_requests_security_risk
  ON auth_requests ((security_context->>'overallRiskLevel'))
  WHERE security_context IS NOT NULL;
