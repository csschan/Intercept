-- ERC-8004 Agent Monitor: persisted scan results

CREATE TABLE IF NOT EXISTS erc8004_agents (
  id              SERIAL PRIMARY KEY,
  agent_id        TEXT NOT NULL,
  owner           TEXT NOT NULL,
  chain           TEXT NOT NULL,
  chain_label     TEXT NOT NULL,
  block_number    TEXT NOT NULL,
  tx_hash         TEXT NOT NULL,
  wallet          TEXT,
  uri             TEXT,
  first_seen_at   TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE(chain, agent_id)
);

CREATE TABLE IF NOT EXISTS erc8004_scan_cursors (
  chain           TEXT PRIMARY KEY,
  last_block      TEXT NOT NULL,
  agent_count     INTEGER NOT NULL DEFAULT 0,
  updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_erc8004_agents_chain ON erc8004_agents(chain);
CREATE INDEX IF NOT EXISTS idx_erc8004_agents_owner ON erc8004_agents(owner);
