-- Complete schema: add all missing tables and columns

-- Session key column
ALTER TABLE spending_sessions ADD COLUMN IF NOT EXISTS session_key TEXT;

-- Agent endpoints
CREATE TABLE IF NOT EXISTS agent_endpoints (
  id          SERIAL PRIMARY KEY,
  agent_id    TEXT NOT NULL,
  chain       TEXT NOT NULL,
  endpoint_type TEXT NOT NULL,
  url         TEXT NOT NULL,
  status      TEXT DEFAULT 'unknown',
  tools_count INTEGER DEFAULT 0,
  tools_list  JSONB,
  pricing     TEXT,
  last_checked TIMESTAMP,
  created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_endpoints_agent ON agent_endpoints(chain, agent_id);

-- Agent whitelist
CREATE TABLE IF NOT EXISTS agent_whitelist (
  id          SERIAL PRIMARY KEY,
  owner_id    UUID REFERENCES owners(id),
  agent_id    TEXT NOT NULL,
  chain       TEXT NOT NULL,
  level       TEXT DEFAULT 'trusted',
  reason      TEXT,
  added_at    TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_whitelist_agent ON agent_whitelist(chain, agent_id);

-- Verification reports
CREATE TABLE IF NOT EXISTS verification_reports (
  id              SERIAL PRIMARY KEY,
  agent_id        TEXT NOT NULL,
  chain           TEXT NOT NULL,
  verdict         TEXT NOT NULL,
  verdict_reason  TEXT,
  report_hash     TEXT,
  signature       TEXT,
  dimensions      JSONB,
  on_chain_status TEXT DEFAULT 'pending',
  created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_verification_reports_agent ON verification_reports(chain, agent_id);

-- Add name column to erc8004_agents if missing
ALTER TABLE erc8004_agents ADD COLUMN IF NOT EXISTS name TEXT;
