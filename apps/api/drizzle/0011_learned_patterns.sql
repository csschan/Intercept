-- Auto-learned injection patterns from LLM analysis

CREATE TABLE IF NOT EXISTS learned_patterns (
  id              SERIAL PRIMARY KEY,
  pattern         TEXT NOT NULL,
  label           TEXT NOT NULL,
  weight          INTEGER NOT NULL DEFAULT 25,
  source          TEXT NOT NULL DEFAULT 'llm',
  example_text    TEXT,
  confidence      NUMERIC DEFAULT 0.8,
  hit_count       INTEGER NOT NULL DEFAULT 0,
  last_hit_at     TIMESTAMP,
  created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
  status          TEXT NOT NULL DEFAULT 'active'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_learned_patterns_pattern ON learned_patterns(pattern) WHERE status = 'active';
