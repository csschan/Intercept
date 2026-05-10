-- Add scoring columns to erc8004_agents

ALTER TABLE erc8004_agents
  ADD COLUMN IF NOT EXISTS security_score  NUMERIC,
  ADD COLUMN IF NOT EXISTS tx_count        INTEGER,
  ADD COLUMN IF NOT EXISTS top_flag        TEXT,
  ADD COLUMN IF NOT EXISTS scored_at       TIMESTAMP;

CREATE TABLE IF NOT EXISTS erc8004_dimensions (
  id                   SERIAL PRIMARY KEY,
  agent_id             TEXT NOT NULL,
  chain                TEXT NOT NULL,
  fund_safety          NUMERIC,
  logic_transparency   NUMERIC,
  compliance           NUMERIC,
  tech_stability       NUMERIC,
  behavior_consistency NUMERIC,
  rug_pull_index       NUMERIC,
  gas_anomaly_score    NUMERIC,
  scored_at            TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE(chain, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_erc8004_dimensions_chain ON erc8004_dimensions(chain, agent_id);
