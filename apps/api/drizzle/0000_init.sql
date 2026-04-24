-- Agent Guard — Initial Schema Migration
-- Generated: 2026-03-27

-- Enums
DO $$ BEGIN
  CREATE TYPE "decision" AS ENUM('allow', 'deny', 'ask_user', 'pending');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE "resolved_by" AS ENUM('auto', 'human', 'timeout');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE "chain" AS ENUM('solana', 'solana-devnet', 'ethereum', 'base', 'polygon', 'arbitrum');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE "tx_type" AS ENUM('transfer', 'swap', 'contract_call', 'approve', 'other');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE "agent_status" AS ENUM('active', 'paused', 'deleted');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE "timeout_action" AS ENUM('allow', 'deny');
EXCEPTION WHEN duplicate_object THEN null; END $$;

-- Owners (users)
CREATE TABLE IF NOT EXISTS "owners" (
  "id"                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "email"             TEXT UNIQUE,
  "telegram_chat_id"  TEXT,
  "slack_webhook_url" TEXT,
  "api_key"           TEXT NOT NULL UNIQUE,
  "created_at"        TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Policies
CREATE TABLE IF NOT EXISTS "policies" (
  "id"                                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "owner_id"                            UUID NOT NULL REFERENCES "owners"("id"),
  "auto_approve_below_usdc"             NUMERIC(18,6),
  "require_approval_above_usdc"         NUMERIC(18,6),
  "daily_limit_usdc"                    NUMERIC(18,6),
  "monthly_limit_usdc"                  NUMERIC(18,6),
  "allow_recurring"                     BOOLEAN NOT NULL DEFAULT true,
  "allow_auto_purchase"                 BOOLEAN NOT NULL DEFAULT false,
  "require_confirmation_new_merchant"   BOOLEAN NOT NULL DEFAULT false,
  "allowed_categories"                  TEXT[] DEFAULT '{}',
  "blocked_categories"                  TEXT[] DEFAULT '{}',
  "merchant_allowlist"                  TEXT[] DEFAULT '{}',
  "merchant_blocklist"                  TEXT[] DEFAULT '{}',
  "token_allowlist"                     TEXT[] DEFAULT '{}',
  "timeout_seconds"                     INTEGER NOT NULL DEFAULT 300,
  "timeout_action"                      "timeout_action" NOT NULL DEFAULT 'deny',
  "raw_text"                            TEXT,
  "on_chain_hash"                       TEXT,
  "created_at"                          TIMESTAMP NOT NULL DEFAULT NOW(),
  "updated_at"                          TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Agents
CREATE TABLE IF NOT EXISTS "agents" (
  "id"                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "owner_id"             UUID NOT NULL REFERENCES "owners"("id"),
  "policy_id"            UUID REFERENCES "policies"("id"),
  "name"                 TEXT NOT NULL,
  "description"          TEXT,
  "wallet_address"       TEXT,
  "webhook_url"          TEXT,
  "status"               "agent_status" NOT NULL DEFAULT 'active',
  "daily_spent_usdc"     NUMERIC(18,6) NOT NULL DEFAULT 0,
  "monthly_spent_usdc"   NUMERIC(18,6) NOT NULL DEFAULT 0,
  "daily_reset_at"       TIMESTAMP NOT NULL DEFAULT NOW(),
  "monthly_reset_at"     TIMESTAMP NOT NULL DEFAULT NOW(),
  "created_at"           TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Authorization Requests
CREATE TABLE IF NOT EXISTS "auth_requests" (
  "id"                TEXT PRIMARY KEY,
  "agent_id"          UUID NOT NULL REFERENCES "agents"("id"),
  "owner_id"          UUID NOT NULL REFERENCES "owners"("id"),
  "chain"             "chain" NOT NULL,
  "tx_type"           "tx_type" NOT NULL DEFAULT 'transfer',
  "from_address"      TEXT,
  "to_address"        TEXT NOT NULL,
  "amount_raw"        TEXT NOT NULL,
  "amount_usdc"       NUMERIC(18,6),
  "token"             TEXT NOT NULL,
  "token_address"     TEXT,
  "tx_metadata"       JSONB,
  "raw_tx_data"       JSONB,
  "decision"          "decision" NOT NULL DEFAULT 'pending',
  "reason"            TEXT,
  "rule_triggered"    TEXT,
  "resolved_by"       "resolved_by",
  "resolved_at"       TIMESTAMP,
  "expires_at"        TIMESTAMP,
  "webhook_delivered" BOOLEAN NOT NULL DEFAULT false,
  "created_at"        TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Audit Log (append-only)
CREATE TABLE IF NOT EXISTS "audit_logs" (
  "id"          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "request_id"  TEXT REFERENCES "auth_requests"("id"),
  "agent_id"    UUID REFERENCES "agents"("id"),
  "owner_id"    UUID REFERENCES "owners"("id"),
  "event"       TEXT NOT NULL,
  "data"        JSONB,
  "created_at"  TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Known Merchants
CREATE TABLE IF NOT EXISTS "known_merchants" (
  "id"              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "agent_id"        UUID NOT NULL REFERENCES "agents"("id"),
  "identifier"      TEXT NOT NULL,
  "first_seen_at"   TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE("agent_id", "identifier")
);

-- Indexes
CREATE INDEX IF NOT EXISTS "auth_requests_agent_id_idx"  ON "auth_requests"("agent_id");
CREATE INDEX IF NOT EXISTS "auth_requests_owner_id_idx"  ON "auth_requests"("owner_id");
CREATE INDEX IF NOT EXISTS "auth_requests_decision_idx"  ON "auth_requests"("decision");
CREATE INDEX IF NOT EXISTS "auth_requests_created_at_idx" ON "auth_requests"("created_at" DESC);
CREATE INDEX IF NOT EXISTS "audit_logs_request_id_idx"   ON "audit_logs"("request_id");
CREATE INDEX IF NOT EXISTS "known_merchants_agent_id_idx" ON "known_merchants"("agent_id");
