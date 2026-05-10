-- Missing tables required by monitor routes

CREATE TABLE IF NOT EXISTS erc8004_alerts (
  id          SERIAL PRIMARY KEY,
  agent_id    TEXT NOT NULL,
  chain       TEXT NOT NULL,
  alert_type  TEXT NOT NULL,
  severity    TEXT NOT NULL DEFAULT 'warning',
  title       TEXT NOT NULL,
  detail      TEXT,
  created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_erc8004_alerts_agent ON erc8004_alerts(chain, agent_id);

CREATE TABLE IF NOT EXISTS agent_capabilities (
  id          SERIAL PRIMARY KEY,
  agent_id    TEXT NOT NULL,
  chain       TEXT NOT NULL,
  capability  TEXT NOT NULL,
  category    TEXT,
  confidence  NUMERIC DEFAULT 1.0,
  source      TEXT DEFAULT 'uri',
  created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE(chain, agent_id, capability)
);

CREATE INDEX IF NOT EXISTS idx_agent_capabilities_agent ON agent_capabilities(chain, agent_id);
