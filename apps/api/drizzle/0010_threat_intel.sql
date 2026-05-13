-- Shared Threat Intelligence table

CREATE TABLE IF NOT EXISTS threat_intel (
  id               SERIAL PRIMARY KEY,
  threat_type      TEXT NOT NULL,
  threat_value     TEXT NOT NULL,
  chain            TEXT,
  reason           TEXT NOT NULL,
  rule_triggered   TEXT,
  severity         TEXT NOT NULL DEFAULT 'high',
  source_agent_id  TEXT,
  source_request_id TEXT,
  report_count     INTEGER NOT NULL DEFAULT 1,
  last_reported_at TIMESTAMP NOT NULL DEFAULT NOW(),
  first_seen_at    TIMESTAMP NOT NULL DEFAULT NOW(),
  status           TEXT NOT NULL DEFAULT 'active'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_intel_unique ON threat_intel(threat_type, threat_value, chain) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_threat_intel_value ON threat_intel(threat_value);
CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intel(threat_type, status);
