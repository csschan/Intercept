import {
  pgTable,
  text,
  timestamp,
  jsonb,
  boolean,
  numeric,
  uuid,
  pgEnum,
  integer,
} from 'drizzle-orm/pg-core'

// ── Enums ────────────────────────────────────────────────────────────────────

export const decisionEnum = pgEnum('decision', ['allow', 'deny', 'ask_user', 'pending'])
export const resolvedByEnum = pgEnum('resolved_by', ['auto', 'human', 'timeout'])
export const chainEnum = pgEnum('chain', [
  'solana',
  'solana-devnet',
  'ethereum',
  'base',
  'polygon',
  'arbitrum',
  'arc-testnet',
])
export const txTypeEnum = pgEnum('tx_type', ['transfer', 'swap', 'contract_call', 'approve', 'other'])
export const agentStatusEnum = pgEnum('agent_status', ['active', 'paused', 'deleted'])
export const sessionStatusEnum = pgEnum('session_status', ['active', 'exhausted', 'expired', 'revoked'])
export const timeoutActionEnum = pgEnum('timeout_action', ['allow', 'deny'])

// ── Owners (Users) ────────────────────────────────────────────────────────────

export const owners = pgTable('owners', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: text('email').unique(),
  telegramChatId: text('telegram_chat_id'),
  slackWebhookUrl: text('slack_webhook_url'),
  apiKey: text('api_key').notNull().unique(),       // stored as SHA-256 hash
  apiKeyPrefix: text('api_key_prefix'),              // first 8 chars for display (ag_xxxx...)
  createdAt: timestamp('created_at').notNull().defaultNow(),
})

// ── Policies ──────────────────────────────────────────────────────────────────

export const policies = pgTable('policies', {
  id: uuid('id').primaryKey().defaultRandom(),
  ownerId: uuid('owner_id').notNull().references(() => owners.id),
  // Core spending rules
  autoApproveBelowUsdc: numeric('auto_approve_below_usdc', { precision: 18, scale: 6 }),
  requireApprovalAboveUsdc: numeric('require_approval_above_usdc', { precision: 18, scale: 6 }),
  dailyLimitUsdc: numeric('daily_limit_usdc', { precision: 18, scale: 6 }),
  monthlyLimitUsdc: numeric('monthly_limit_usdc', { precision: 18, scale: 6 }),
  // Behavior flags
  allowRecurring: boolean('allow_recurring').notNull().default(true),
  allowAutoPurchase: boolean('allow_auto_purchase').notNull().default(true),
  requireConfirmationNewMerchant: boolean('require_confirmation_new_merchant').notNull().default(false),
  // Lists
  allowedCategories: text('allowed_categories').array().default([]),
  blockedCategories: text('blocked_categories').array().default([]),
  merchantAllowlist: text('merchant_allowlist').array().default([]),
  merchantBlocklist: text('merchant_blocklist').array().default([]),
  tokenAllowlist: text('token_allowlist').array().default([]),
  // Human-in-loop config
  timeoutSeconds: integer('timeout_seconds').notNull().default(300),
  timeoutAction: timeoutActionEnum('timeout_action').notNull().default('deny'),
  // Meta
  rawText: text('raw_text'),
  onChainHash: text('on_chain_hash'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
})

// ── Agents ────────────────────────────────────────────────────────────────────

export const agents = pgTable('agents', {
  id: uuid('id').primaryKey().defaultRandom(),
  ownerId: uuid('owner_id').notNull().references(() => owners.id),
  policyId: uuid('policy_id').references(() => policies.id),
  name: text('name').notNull(),
  description: text('description'),
  walletAddress: text('wallet_address'),
  webhookUrl: text('webhook_url'),
  status: agentStatusEnum('status').notNull().default('active'),
  // Budget tracking (rolling)
  dailySpentUsdc: numeric('daily_spent_usdc', { precision: 18, scale: 6 }).notNull().default('0'),
  monthlySpentUsdc: numeric('monthly_spent_usdc', { precision: 18, scale: 6 }).notNull().default('0'),
  dailyResetAt: timestamp('daily_reset_at').notNull().defaultNow(),
  monthlyResetAt: timestamp('monthly_reset_at').notNull().defaultNow(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
})

// ── Authorization Requests ────────────────────────────────────────────────────

export const authRequests = pgTable('auth_requests', {
  id: text('id').primaryKey(), // req_nanoid format
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  ownerId: uuid('owner_id').notNull().references(() => owners.id),
  // Chain info
  chain: chainEnum('chain').notNull(),
  txType: txTypeEnum('tx_type').notNull().default('transfer'),
  // Transaction data (normalized)
  fromAddress: text('from_address'),
  toAddress: text('to_address').notNull(),
  amountRaw: text('amount_raw').notNull(),       // raw units (lamports / wei)
  amountUsdc: numeric('amount_usdc', { precision: 18, scale: 6 }), // normalized to USDC equiv
  token: text('token').notNull(),
  tokenAddress: text('token_address'),
  // Metadata
  txMetadata: jsonb('tx_metadata'),              // { purpose, merchant, category, is_recurring, is_new_merchant }
  rawTxData: jsonb('raw_tx_data'),               // original transaction object from agent
  // Decision
  decision: decisionEnum('decision').notNull().default('pending'),
  reason: text('reason'),
  ruleTriggered: text('rule_triggered'),
  // Resolution
  resolvedBy: resolvedByEnum('resolved_by'),
  resolvedAt: timestamp('resolved_at'),
  expiresAt: timestamp('expires_at'),
  // Webhook
  webhookDelivered: boolean('webhook_delivered').notNull().default(false),
  // Security analysis results (prompt injection, address blacklist, anomaly, session)
  securityContext: jsonb('security_context'),
  // On-chain execution (real devnet tx after allow)
  txSignature: text('tx_signature'),
  txExplorerUrl: text('tx_explorer_url'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
})

// ── Audit Log (append-only) ───────────────────────────────────────────────────

export const auditLogs = pgTable('audit_logs', {
  id: uuid('id').primaryKey().defaultRandom(),
  requestId: text('request_id').references(() => authRequests.id),
  agentId: uuid('agent_id').references(() => agents.id),
  ownerId: uuid('owner_id').references(() => owners.id),
  event: text('event').notNull(), // 'decision_made' | 'human_approved' | 'human_denied' | 'timeout' | 'webhook_sent'
  data: jsonb('data'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
})

// ── Spending Sessions ────────────────────────────────────────────────────────

export const spendingSessions = pgTable('spending_sessions', {
  id: text('id').primaryKey(),                          // sess_nanoid
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  ownerId: uuid('owner_id').notNull().references(() => owners.id),
  sessionKey: text('session_key'),                     // stored as SHA-256 hash
  maxAmountUsdc: numeric('max_amount_usdc', { precision: 18, scale: 6 }).notNull(),
  x402MaxPerCall: numeric('x402_max_per_call', { precision: 18, scale: 6 }),
  spentSoFar: numeric('spent_so_far', { precision: 18, scale: 6 }).notNull().default('0'),
  expiresAt: timestamp('expires_at').notNull(),
  allowedMerchants: text('allowed_merchants').array().default([]),
  allowedRecipients: text('allowed_recipients').array().default([]),
  allowedCategories: text('allowed_categories').array().default([]),
  purpose: text('purpose'),
  policySnapshotId: uuid('policy_snapshot_id').references(() => policies.id),
  policyHash: text('policy_hash'),
  status: sessionStatusEnum('status').notNull().default('active'),
  revokedAt: timestamp('revoked_at'),
  revokedReason: text('revoked_reason'),
  onChainPda: text('on_chain_pda'),
  onChainSignature: text('on_chain_signature'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
})

export const sessionSpends = pgTable('session_spends', {
  id: uuid('id').primaryKey().defaultRandom(),
  sessionId: text('session_id').notNull().references(() => spendingSessions.id),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  toAddress: text('to_address').notNull(),
  amountUsdc: numeric('amount_usdc', { precision: 18, scale: 6 }).notNull(),
  token: text('token').notNull().default('USDC'),
  merchant: text('merchant'),
  category: text('category'),
  purpose: text('purpose'),
  onChainSignature: text('on_chain_signature'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
})

// ── ERC-8004 Agent Monitor ───────────────────────────────────────────────────

export const erc8004Agents = pgTable('erc8004_agents', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  agentId: text('agent_id').notNull(),
  owner: text('owner').notNull(),
  chain: text('chain').notNull(),
  chainLabel: text('chain_label').notNull(),
  blockNumber: text('block_number').notNull(),
  txHash: text('tx_hash').notNull(),
  wallet: text('wallet'),
  uri: text('uri'),
  name: text('name'),
  securityScore: numeric('security_score'),
  txCount: integer('tx_count'),
  topFlag: text('top_flag'),
  scoredAt: timestamp('scored_at'),
  firstSeenAt: timestamp('first_seen_at').notNull().defaultNow(),
})

export const erc8004Alerts = pgTable('erc8004_alerts', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  agentId: text('agent_id').notNull(),
  chain: text('chain').notNull(),
  alertType: text('alert_type').notNull(),
  severity: text('severity').notNull().default('warning'),
  title: text('title').notNull(),
  detail: text('detail'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
})

export const erc8004Dimensions = pgTable('erc8004_dimensions', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  agentId: text('agent_id').notNull(),
  chain: text('chain').notNull(),
  fundSafety: numeric('fund_safety'),
  logicTransparency: numeric('logic_transparency'),
  compliance: numeric('compliance'),
  techStability: numeric('tech_stability'),
  behaviorConsistency: numeric('behavior_consistency'),
  rugPullIndex: numeric('rug_pull_index'),
  gasAnomalyScore: numeric('gas_anomaly_score'),
  scoredAt: timestamp('scored_at').notNull().defaultNow(),
})

export const erc8004ScanCursors = pgTable('erc8004_scan_cursors', {
  chain: text('chain').primaryKey(),
  lastBlock: text('last_block').notNull(),
  agentCount: integer('agent_count').notNull().default(0),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
})

// ── Agent Capabilities & Endpoints ──────────────────────────────────────────

export const agentCapabilities = pgTable('agent_capabilities', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  agentId: text('agent_id').notNull(),
  chain: text('chain').notNull(),
  capability: text('capability').notNull(),
  category: text('category'),
  confidence: numeric('confidence').default('1.0'),
  source: text('source').default('uri'),
  lastChecked: timestamp('last_checked'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
})

export const agentEndpoints = pgTable('agent_endpoints', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  agentId: text('agent_id').notNull(),
  chain: text('chain').notNull(),
  endpointType: text('endpoint_type').notNull(),
  url: text('url').notNull(),
  status: text('status').default('unknown'),
  toolsCount: integer('tools_count').default(0),
  toolsList: jsonb('tools_list'),
  pricing: text('pricing'),
  lastChecked: timestamp('last_checked'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
})

export const agentWhitelist = pgTable('agent_whitelist', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  ownerId: uuid('owner_id').references(() => owners.id),
  agentId: text('agent_id').notNull(),
  chain: text('chain').notNull(),
  level: text('level').default('trusted'),
  reason: text('reason'),
  addedAt: timestamp('added_at').notNull().defaultNow(),
})

// ── Verification Reports ────────────────────────────────────────────────────

export const verificationReports = pgTable('verification_reports', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  agentId: text('agent_id').notNull(),
  chain: text('chain').notNull(),
  verdict: text('verdict').notNull(),
  verdictReason: text('verdict_reason'),
  reportHash: text('report_hash'),
  signature: text('signature'),
  dimensions: jsonb('dimensions'),
  onChainStatus: text('on_chain_status').default('pending'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
})

// ── Known Merchants (for new merchant detection) ──────────────────────────────

export const knownMerchants = pgTable('known_merchants', {
  id: uuid('id').primaryKey().defaultRandom(),
  agentId: uuid('agent_id').notNull().references(() => agents.id),
  identifier: text('identifier').notNull(),       // display name (e.g. "OpenAI")
  address: text('address'),                        // on-chain recipient address (the actual binding)
  chain: text('chain'),                            // 'solana-devnet', 'ethereum', etc.
  category: text('category'),                      // 'api_credits', 'cloud_compute', etc.
  firstSeenAt: timestamp('first_seen_at').notNull().defaultNow(),
})

// ── Shared Threat Intelligence ──────────────────────────────────────────────
// Every deny feeds this table. All agents benefit from collective data.

export const threatIntel = pgTable('threat_intel', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  threatType: text('threat_type').notNull(),         // 'address' | 'url' | 'injection_pattern' | 'token'
  threatValue: text('threat_value').notNull(),        // the address, URL, token mint, or pattern hash
  chain: text('chain'),                               // null = cross-chain
  reason: text('reason').notNull(),
  ruleTriggered: text('rule_triggered'),
  severity: text('severity').notNull().default('high'),
  sourceAgentId: text('source_agent_id'),
  sourceRequestId: text('source_request_id'),
  reportCount: integer('report_count').notNull().default(1),
  lastReportedAt: timestamp('last_reported_at').notNull().defaultNow(),
  firstSeenAt: timestamp('first_seen_at').notNull().defaultNow(),
  status: text('status').notNull().default('active'),
})

// ── Learned Injection Patterns ──────────────────────────────────────────────
// Auto-generated by LLM analysis of deny history. Supplements hardcoded L1 rules.

export const learnedPatterns = pgTable('learned_patterns', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  pattern: text('pattern').notNull(),                // regex string
  label: text('label').notNull(),                     // human-readable name
  weight: integer('weight').notNull().default(25),    // injection score weight
  source: text('source').notNull().default('llm'),    // 'llm' | 'manual'
  exampleText: text('example_text'),                  // the deny text that inspired this
  confidence: numeric('confidence').default('0.8'),   // LLM's confidence in this pattern
  hitCount: integer('hit_count').notNull().default(0),
  lastHitAt: timestamp('last_hit_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  status: text('status').notNull().default('active'), // 'active' | 'disabled' | 'expired'
})
