#!/usr/bin/env node
/**
 * Intercept MCP Server
 *
 * Exposes spending authorization as native MCP tools that any AI agent can discover and use.
 * Supports stdio transport (local) and SSE transport (remote).
 *
 * Tools:
 *   - authorize_payment:      Check if a payment is allowed before executing
 *   - get_spending_budget:    Query remaining daily/monthly budget
 *   - list_pending_approvals: View transactions awaiting human approval
 *   - create_spending_session: Request a time-limited spending session
 *   - resolve_request:        Approve or deny a pending request (human-in-the-loop)
 *
 * Usage:
 *   AGENT_GUARD_API_KEY=xxx AGENT_GUARD_AGENT_ID=xxx npx @intercept/mcp
 *
 * MCP config (claude_desktop_config.json):
 *   {
 *     "mcpServers": {
 *       "intercept": {
 *         "command": "npx",
 *         "args": ["@intercept/mcp"],
 *         "env": {
 *           "AGENT_GUARD_API_KEY": "your-key",
 *           "AGENT_GUARD_AGENT_ID": "your-agent-id",
 *           "AGENT_GUARD_BASE_URL": "http://localhost:8080"
 *         }
 *       }
 *     }
 *   }
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { readFile } from 'fs/promises'
import { fileURLToPath } from 'url'
import { dirname, resolve as resolvePath } from 'path'

// ── Config ───────────────────────────────────────────────────────────────────

const API_KEY = process.env.AGENT_GUARD_API_KEY ?? ''
const AGENT_ID = process.env.AGENT_GUARD_AGENT_ID ?? ''
const BASE_URL = process.env.AGENT_GUARD_BASE_URL ?? 'http://localhost:8080'

// ── API Client ───────────────────────────────────────────────────────────────

async function apiRequest(method: string, path: string, body?: unknown): Promise<unknown> {
  const response = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY,
    },
    body: body ? JSON.stringify(body) : undefined,
  })

  const data = await response.json().catch(() => ({ error: response.statusText }))

  if (!response.ok) {
    throw new Error(`API ${response.status}: ${JSON.stringify(data)}`)
  }

  return data
}

// ── MCP Server ───────────────────────────────────────────────────────────────

const server = new McpServer({
  name: 'intercept',
  version: '0.1.0',
})

// ── Tool: authorize_payment ──────────────────────────────────────────────────

server.tool(
  'authorize_payment',
  'Check if a payment transaction is allowed by the spending policy before executing it. ' +
  'Returns allow (safe to proceed), deny (blocked, do not execute), or ask_user (paused, waiting for human approval). ' +
  'You MUST call this tool before any payment or token transfer.',
  {
    chain: z.enum(['solana', 'solana-devnet', 'ethereum', 'base', 'polygon', 'arbitrum', 'arc-testnet'])
      .describe('Blockchain network for the transaction'),
    to: z.string().describe('Recipient wallet address'),
    amount: z.string().describe('Amount in smallest unit (lamports for SOL, wei for ETH, or base units for tokens)'),
    token: z.string().default('USDC').describe('Token symbol (e.g., USDC, SOL, ETH)'),
    merchant: z.string().optional().describe('Merchant or service name (e.g., "OpenAI", "AWS")'),
    category: z.string().optional().describe('Spending category (e.g., "api_credits", "cloud_compute", "saas")'),
    purpose: z.string().optional().describe('Why this payment is being made'),
    is_recurring: z.boolean().optional().describe('Whether this is a recurring/subscription payment'),
  },
  async (params) => {
    try {
      // Pre-check: counterparty address risk via GoPlus
      let counterpartyWarning = ''
      try {
        const chainIds: Record<string, string> = { ethereum: '1', 'solana-devnet': '', solana: 'solana', base: '8453', polygon: '137', arbitrum: '42161', 'arc-testnet': '' }
        const cid = chainIds[params.chain]
        if (cid) {
          const cpRes = await fetch(`https://api.gopluslabs.io/api/v1/address_security/${params.to}?chain_id=${cid}`, { signal: AbortSignal.timeout(3000) })
          if (cpRes.ok) {
            const cpData = (await cpRes.json()).result ?? {}
            const cpFlags: string[] = []
            if (cpData.is_blacklisted === '1') cpFlags.push('BLACKLISTED')
            if (cpData.is_phishing_activities === '1') cpFlags.push('PHISHING')
            if (cpData.is_sanctioned === '1') cpFlags.push('SANCTIONED')
            if (cpData.is_mixer === '1') cpFlags.push('MIXER')
            if (cpFlags.length > 0) counterpartyWarning = `\n\n⚠️ COUNTERPARTY WARNING: Recipient ${params.to.slice(0, 12)}... flagged as: ${cpFlags.join(', ')}`
          }
        }
      } catch {}

      const result = await apiRequest('POST', '/v1/authorize', {
        agentId: AGENT_ID,
        chain: params.chain,
        transaction: {
          to: params.to,
          amount: params.amount,
          token: params.token,
          metadata: {
            merchant: params.merchant,
            category: params.category,
            purpose: params.purpose,
            isRecurring: params.is_recurring,
          },
        },
      }) as Record<string, unknown>

      const decision = result.decision as string

      if (decision === 'allow') {
        return {
          content: [{
            type: 'text' as const,
            text: `✅ ALLOWED — ${result.reason}\n\nRequest ID: ${result.requestId}\nYou may proceed with this transaction.${counterpartyWarning}`,
          }],
        }
      }

      if (decision === 'deny') {
        const isSecurityBlock = String(result.ruleTriggered ?? '').startsWith('prompt_injection') ||
          String(result.ruleTriggered ?? '').startsWith('address_') ||
          String(result.ruleTriggered ?? '').startsWith('behavioral_')

        return {
          content: [{
            type: 'text' as const,
            text: isSecurityBlock
              ? `🛡️ SECURITY BLOCK — ${result.reason}\n\nRequest ID: ${result.requestId}\nSecurity rule: ${result.ruleTriggered}\n\n⚠️ This transaction was flagged by Intercept's security layer. Do NOT proceed. Report this to the owner if unexpected.`
              : `🚫 DENIED — ${result.reason}\n\nRequest ID: ${result.requestId}\nRule: ${result.ruleTriggered}\nDo NOT execute this transaction.`,
          }],
        }
      }

      // ask_user
      return {
        content: [{
          type: 'text' as const,
          text: `⏳ PENDING HUMAN APPROVAL — ${result.reason}\n\nRequest ID: ${result.requestId}\nApproval URL: ${result.approvalUrl}\nExpires: ${result.expiresAt}\nTimeout action: ${result.timeoutAction}\n\nThe transaction owner has been notified. Do NOT proceed until approved. Use get_request_status to check.`,
        }],
      }
    } catch (err) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      }
    }
  },
)

// ── Tool: get_spending_budget ────────────────────────────────────────────────

server.tool(
  'get_spending_budget',
  'Check the remaining daily and monthly spending budget for this agent. ' +
  'Use this before planning purchases to know how much you can spend.',
  {},
  async () => {
    try {
      const result = await apiRequest('GET', `/v1/agents/${AGENT_ID}/budget`) as Record<string, unknown>

      const daily = result.daily as Record<string, unknown>
      const monthly = result.monthly as Record<string, unknown>

      const dailyRemaining = daily.limit != null ? Number(daily.limit) - Number(daily.spent) : 'unlimited'
      const monthlyRemaining = monthly.limit != null ? Number(monthly.limit) - Number(monthly.spent) : 'unlimited'

      return {
        content: [{
          type: 'text' as const,
          text: [
            `📊 Budget Status`,
            ``,
            `Daily:   $${daily.spent} spent` + (daily.limit != null ? ` / $${daily.limit} limit ($${dailyRemaining} remaining)` : ' (no limit)'),
            `Monthly: $${monthly.spent} spent` + (monthly.limit != null ? ` / $${monthly.limit} limit ($${monthlyRemaining} remaining)` : ' (no limit)'),
            ``,
            `Daily resets:   ${daily.resetAt}`,
            `Monthly resets: ${monthly.resetAt}`,
          ].join('\n'),
        }],
      }
    } catch (err) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      }
    }
  },
)

// ── Tool: get_request_status ─────────────────────────────────────────────────

server.tool(
  'get_request_status',
  'Check the current status of a pending authorization request. ' +
  'Use this after authorize_payment returns ask_user to poll for human approval.',
  {
    request_id: z.string().describe('The request ID returned by authorize_payment (e.g., req_xxxx)'),
  },
  async (params) => {
    try {
      const result = await apiRequest('GET', `/v1/requests/${params.request_id}`) as Record<string, unknown>

      const decision = result.decision as string
      const statusEmoji = decision === 'allow' ? '✅' : decision === 'deny' ? '🚫' : '⏳'

      return {
        content: [{
          type: 'text' as const,
          text: [
            `${statusEmoji} Request ${params.request_id}: ${decision.toUpperCase()}`,
            decision !== 'ask_user' ? `Resolved by: ${result.resolvedBy}` : `Expires: ${result.expiresAt}`,
            `Reason: ${result.reason}`,
          ].join('\n'),
        }],
      }
    } catch (err) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      }
    }
  },
)

// ── Tool: list_pending_approvals ─────────────────────────────────────────────

server.tool(
  'list_pending_approvals',
  'List all transactions currently waiting for human approval. ' +
  'Useful for understanding what is blocked and needs attention.',
  {
    owner_id: z.string().describe('Owner ID to check pending approvals for'),
  },
  async (params) => {
    try {
      const result = await apiRequest('GET', `/v1/requests/pending?ownerId=${params.owner_id}`) as Array<Record<string, unknown>>

      if (!result.length) {
        return {
          content: [{ type: 'text' as const, text: '✅ No pending approvals — all clear.' }],
        }
      }

      const lines = result.map((r, i) => [
        `${i + 1}. ${r.id}`,
        `   Amount: $${r.amountUsdc} ${r.token} → ${r.toAddress}`,
        `   Reason: ${r.reason}`,
        `   Expires: ${r.expiresAt}`,
      ].join('\n'))

      return {
        content: [{
          type: 'text' as const,
          text: `⏳ ${result.length} pending approval(s):\n\n${lines.join('\n\n')}`,
        }],
      }
    } catch (err) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      }
    }
  },
)

// ── Tool: create_spending_session ────────────────────────────────────────────

server.tool(
  'create_spending_session',
  'Create a time-limited spending session with a fixed budget. ' +
  'Useful for scoped tasks like "spend up to $20 on API credits in the next hour". ' +
  'Transactions within a session are auto-approved up to the session budget.',
  {
    max_amount_usdc: z.number().positive().describe('Maximum budget for this session in USDC'),
    duration_minutes: z.number().positive().describe('How long the session is valid (in minutes)'),
    allowed_merchants: z.array(z.string()).optional().describe('Restrict spending to these merchants only'),
    allowed_categories: z.array(z.string()).optional().describe('Restrict spending to these categories only'),
    purpose: z.string().optional().describe('What this session is for (e.g., "batch API calls to OpenAI")'),
  },
  async (params) => {
    try {
      const result = await apiRequest('POST', '/v1/sessions', {
        agentId: AGENT_ID,
        maxAmountUsdc: params.max_amount_usdc,
        durationMinutes: params.duration_minutes,
        allowedMerchants: params.allowed_merchants,
        allowedCategories: params.allowed_categories,
        purpose: params.purpose,
      }) as Record<string, unknown>

      return {
        content: [{
          type: 'text' as const,
          text: [
            `✅ Spending session created`,
            ``,
            `Session ID: ${result.id}`,
            `Budget: $${result.maxAmountUsdc}`,
            `Expires: ${result.expiresAt}`,
            params.purpose ? `Purpose: ${params.purpose}` : '',
            ``,
            `Use session ID with session_spend to execute payments within this session.`,
          ].filter(Boolean).join('\n'),
        }],
      }
    } catch (err) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      }
    }
  },
)

// ── Tool: session_spend ──────────────────────────────────────────────────────

server.tool(
  'session_spend',
  'Execute a spend within an active spending session. ' +
  'Automatically approved if within session budget and constraints.',
  {
    session_id: z.string().describe('The spending session ID'),
    to: z.string().describe('Recipient wallet address'),
    amount_usdc: z.number().positive().describe('Amount to spend in USDC'),
    token: z.string().default('USDC').describe('Token to use'),
    merchant: z.string().optional().describe('Merchant name'),
    category: z.string().optional().describe('Spending category'),
    purpose: z.string().optional().describe('Purpose of this specific spend'),
  },
  async (params) => {
    try {
      const result = await apiRequest('POST', `/v1/sessions/${params.session_id}/spend`, {
        to: params.to,
        amountUsdc: params.amount_usdc,
        token: params.token,
        merchant: params.merchant,
        category: params.category,
        purpose: params.purpose,
      }) as Record<string, unknown>

      return {
        content: [{
          type: 'text' as const,
          text: [
            `✅ Spend approved`,
            ``,
            `Amount: $${params.amount_usdc}`,
            `Remaining: $${result.remaining}`,
            `Session status: ${result.sessionStatus}`,
            `Session expires: ${result.expiresAt}`,
          ].join('\n'),
        }],
      }
    } catch (err) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      }
    }
  },
)

// ── Tool: suggest_spending ────────────────────────────────────────────────────

server.tool(
  'suggest_spending',
  'Ask Intercept what you CAN spend before attempting a transaction. ' +
  'Returns budget limits, merchant/category status, and whether a planned transaction would auto-approve. ' +
  'Use this to plan purchases intelligently within policy constraints.',
  {
    desired_amount_usdc: z.number().optional().describe('How much you want to spend (in USDC)'),
    merchant: z.string().optional().describe('Target merchant to check against allow/blocklist'),
    category: z.string().optional().describe('Spending category to check'),
    intent: z.string().optional().describe('What you plan to do (e.g., "buy 1000 OpenAI API tokens")'),
  },
  async (params) => {
    try {
      const result = await apiRequest('POST', '/v1/suggest', {
        agentId: AGENT_ID,
        desiredAmountUsdc: params.desired_amount_usdc,
        merchant: params.merchant,
        category: params.category,
        intent: params.intent,
      }) as Record<string, unknown>

      const budget = result.budget as Record<string, unknown>
      const lines: string[] = ['📋 Spending Guidance', '']

      // Budget info
      if (budget.effectiveMaxUsdc != null) {
        lines.push(`Available budget: $${budget.effectiveMaxUsdc}`)
      }
      if (budget.autoApproveBelowUsdc != null) {
        lines.push(`Auto-approve threshold: ≤ $${budget.autoApproveBelowUsdc}`)
      }

      // Merchant check
      const merchant = result.merchant as Record<string, unknown> | undefined
      if (merchant) {
        const statusMap: Record<string, string> = {
          known: '✅ Known merchant — will auto-approve',
          new: '⚠️ New merchant — first transaction needs human approval',
          blocked: '🚫 Blocked merchant — choose another provider',
          not_in_allowlist: '⚠️ Not on approved list — needs human approval',
        }
        lines.push(`Merchant "${merchant.name}": ${statusMap[merchant.status as string] ?? merchant.status}`)
      }

      // Category check
      const category = result.category as Record<string, unknown> | undefined
      if (category) {
        lines.push(`Category "${category.name}": ${category.status}`)
      }

      // Would it auto-approve?
      lines.push('')
      lines.push(result.wouldAutoApprove
        ? '✅ This transaction would be AUTO-APPROVED'
        : '⚠️ This transaction would need HUMAN APPROVAL or may be DENIED')

      // Blockers / suggestions
      const blockers = result.blockers as string[]
      if (blockers?.length) {
        lines.push('', '🚫 Blockers:', ...blockers.map(b => `  - ${b}`))
      }
      const suggestions = result.suggestions as string[]
      if (suggestions?.length) {
        lines.push('', '💡 Suggestions:', ...suggestions.map(s => `  - ${s}`))
      }

      return {
        content: [{ type: 'text' as const, text: lines.join('\n') }],
      }
    } catch (err) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      }
    }
  },
)

// ── Tool: check_security_profile ─────────────────────────────────────────────

server.tool(
  'check_security_profile',
  'View the security threat summary for this agent — recent injection attempts, behavioral anomalies, ' +
  'suspicious address detections, and overall risk level. ' +
  'Use this to audit your own activity and detect if you may have been compromised.',
  {},
  async () => {
    try {
      const result = await apiRequest('GET', `/v1/agents/${AGENT_ID}/security`) as Record<string, unknown>
      const summary = result.summary as Record<string, number>

      const riskEmoji = result.overallRisk === 'high' ? '🔴' : result.overallRisk === 'medium' ? '🟡' : '🟢'

      const lines = [
        `${riskEmoji} Security Profile — ${result.agentName} (last ${result.period})`,
        '',
        `Overall Risk: ${String(result.overallRisk).toUpperCase()}`,
        '',
        `Security Events:`,
        `  Requests scanned:       ${summary?.totalRequests ?? 0}`,
        `  Security overrides:     ${summary?.overridesApplied ?? 0}`,
        `  Injection attempts:     ${summary?.injectionAttempts ?? 0}`,
        `  Anomaly detections:     ${summary?.anomalyDetections ?? 0}`,
        `  Suspicious addresses:   ${summary?.suspiciousAddresses ?? 0}`,
      ]

      const events = result.recentSecurityEvents as Array<Record<string, unknown>>
      if (events?.length) {
        lines.push('', 'Recent alerts:')
        events.slice(0, 5).forEach(e => {
          lines.push(`  [${new Date(e.timestamp as string).toLocaleTimeString()}] ${e.ruleTriggered} — ${e.originalDecision} → ${e.newDecision}`)
        })
      }

      return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
    } catch (err) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      }
    }
  },
)

// ── Tool: get_transaction_history ─────────────────────────────────────────────

server.tool(
  'get_transaction_history',
  'View recent transaction history and authorization decisions for this agent. ' +
  'Helps understand past spending patterns and decisions.',
  {
    limit: z.number().min(1).max(50).default(10).describe('Number of recent transactions to return'),
  },
  async (params) => {
    try {
      const result = await apiRequest('GET', `/v1/agents/${AGENT_ID}/history?limit=${params.limit}`) as Array<Record<string, unknown>>

      if (!result.length) {
        return {
          content: [{ type: 'text' as const, text: 'No transaction history yet.' }],
        }
      }

      const lines = result.map((r, i) => {
        const emoji = r.decision === 'allow' ? '✅' : r.decision === 'deny' ? '🚫' : '⏳'
        return `${emoji} $${r.amountUsdc} ${r.token} → ${r.toAddress} — ${r.decision} (${r.ruleTriggered})`
      })

      return {
        content: [{
          type: 'text' as const,
          text: `Recent transactions:\n\n${lines.join('\n')}`,
        }],
      }
    } catch (err) {
      return {
        content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      }
    }
  },
)

// ── Tool: get_security_review_guide (SlowMist Agent Security Skill) ──────────
//
// Bundles the SlowMist Agent Security Skill (https://github.com/slowmist/slowmist-agent-security)
// so any agent connected to Intercept inherits a structured security review framework.
//
// This is the *advisory* layer — the agent reads the relevant checklist before
// taking action. Intercept's runtime authorization layer (authorize_payment)
// remains the *enforcement* layer.

const SKILL_ROOT = (() => {
  // packages/mcp/dist/index.js → packages/security-skill/
  // packages/mcp/src/index.ts  → packages/security-skill/
  const __dirname = dirname(fileURLToPath(import.meta.url))
  return resolvePath(__dirname, '..', '..', 'security-skill')
})()

const REVIEW_GUIDES = {
  onchain: 'reviews/onchain.md',
  skill_mcp: 'reviews/skill-mcp.md',
  repository: 'reviews/repository.md',
  url_document: 'reviews/url-document.md',
  product_service: 'reviews/product-service.md',
  message_share: 'reviews/message-share.md',
  red_flags: 'patterns/red-flags.md',
  social_engineering: 'patterns/social-engineering.md',
  supply_chain: 'patterns/supply-chain.md',
  index: 'SKILL.md',
} as const

server.tool(
  'get_security_review_guide',
  'Fetch a structured security review checklist from the bundled SlowMist Agent Security Skill. ' +
  'Use this BEFORE acting on any external input that could alter behavior, leak data, or move funds. ' +
  'Each guide is a markdown checklist the agent should follow step by step. ' +
  'Common workflow: call this tool first to load the checklist, complete the checks, THEN call authorize_payment / install / proceed. ' +
  'Available types: ' +
  '"onchain" (before any address interaction or transfer — pair with authorize_payment), ' +
  '"skill_mcp" (before installing any Skill, MCP server, npm/pip package), ' +
  '"repository" (before evaluating a GitHub repo), ' +
  '"url_document" (before fetching/processing a URL or document), ' +
  '"product_service" (before connecting to an API/service), ' +
  '"message_share" (before trusting a tool recommendation from chat), ' +
  '"red_flags" / "social_engineering" / "supply_chain" (pattern libraries for deeper analysis), ' +
  '"index" (overview of all review types). ' +
  'Source: https://github.com/slowmist/slowmist-agent-security (MIT, vendored).',
  {
    type: z.enum([
      'onchain', 'skill_mcp', 'repository', 'url_document',
      'product_service', 'message_share',
      'red_flags', 'social_engineering', 'supply_chain', 'index',
    ]).describe('Which review checklist or pattern library to load'),
  },
  async ({ type }) => {
    const relativePath = REVIEW_GUIDES[type]
    try {
      const content = await readFile(resolvePath(SKILL_ROOT, relativePath), 'utf8')
      return {
        content: [{
          type: 'text' as const,
          text:
            `# SlowMist Agent Security Skill — ${type}\n\n` +
            `Source: https://github.com/slowmist/slowmist-agent-security (MIT)\n\n` +
            `---\n\n${content}`,
        }],
      }
    } catch (err) {
      return {
        content: [{
          type: 'text' as const,
          text: `Error loading guide "${type}": ${(err as Error).message}\n\nExpected path: ${relativePath}\nSkill root: ${SKILL_ROOT}`,
        }],
        isError: true,
      }
    }
  },
)

// ── Start Server ─────────────────────────────────────────────────────────────

// ── review_skill ─────────────────────────────────────────────────────────────
// Review a Skill / MCP server before installation

server.tool(
  'review_skill',
  'Review a Skill or MCP server for security risks BEFORE installation. ' +
  'Checks source trust, author identity, file types, permissions, and red flag patterns. ' +
  'Use this whenever an agent is asked to install any external package.',
  {
    name: z.string().describe('Package or skill name'),
    source: z.enum(['npm', 'github', 'clawhub', 'pip', 'unknown']).describe('Where the package is published'),
    author: z.string().optional().describe('Author name or org'),
    hasExecutableCode: z.boolean().optional().describe('Does it contain .js/.py/.sh files?'),
    fileTypes: z.array(z.string()).optional().describe('File extensions in the package'),
    permissions: z.array(z.string()).optional().describe('Requested permissions'),
  },
  async (params) => {
    const res = await fetch(`${BASE_URL}/v1/review/skill`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    })
    const data = await res.json()
    const lines = [
      `═══ SKILL REVIEW: ${data.summary} ═══`,
      ...data.checks.map((c: any) => `${c.status === 'pass' ? '✅' : c.status === 'warn' ? '⚠️' : '❌'} ${c.name}: ${c.detail}`),
    ]
    return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
  },
)

// ── review_repository ────────────────────────────────────────────────────────

server.tool(
  'review_repository',
  'Review a GitHub repository for security risks. Checks popularity, maintenance, license, team, and code patterns.',
  {
    url: z.string().describe('GitHub repository URL'),
    stars: z.number().optional(),
    forks: z.number().optional(),
    contributors: z.number().optional(),
    createdAt: z.string().optional(),
    lastCommit: z.string().optional(),
    hasLicense: z.boolean().optional(),
    isVerifiedOrg: z.boolean().optional(),
  },
  async (params) => {
    const res = await fetch(`${BASE_URL}/v1/review/repository`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    })
    const data = await res.json()
    const lines = [
      `═══ REPO REVIEW: ${data.summary} ═══`,
      ...data.checks.map((c: any) => `${c.status === 'pass' ? '✅' : c.status === 'warn' ? '⚠️' : '❌'} ${c.name}: ${c.detail}`),
    ]
    return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
  },
)

// ── review_url ───────────────────────────────────────────────────────────────

server.tool(
  'review_url',
  'Review a URL or document for security risks before fetching or processing it.',
  {
    url: z.string().describe('URL to review'),
    hasCodeBlocks: z.boolean().optional(),
    hasExternalLinks: z.boolean().optional(),
  },
  async (params) => {
    const res = await fetch(`${BASE_URL}/v1/review/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    })
    const data = await res.json()
    const lines = [
      `═══ URL REVIEW: ${data.summary} ═══`,
      ...data.checks.map((c: any) => `${c.status === 'pass' ? '✅' : c.status === 'warn' ? '⚠️' : '❌'} ${c.name}: ${c.detail}`),
    ]
    return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
  },
)

// ── review_product ───────────────────────────────────────────────────────────

server.tool(
  'review_product',
  'Review a product, service, API, or SDK before integration.',
  {
    name: z.string().describe('Product name'),
    type: z.enum(['api', 'sdk', 'service', 'platform']),
    hasAudit: z.boolean().optional(),
    auditBy: z.string().optional(),
    teamKnown: z.boolean().optional(),
    incidentHistory: z.boolean().optional(),
    permissionsRequired: z.array(z.string()).optional(),
  },
  async (params) => {
    const res = await fetch(`${BASE_URL}/v1/review/product`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    })
    const data = await res.json()
    const lines = [
      `═══ PRODUCT REVIEW: ${data.summary} ═══`,
      ...data.checks.map((c: any) => `${c.status === 'pass' ? '✅' : c.status === 'warn' ? '⚠️' : '❌'} ${c.name}: ${c.detail}`),
    ]
    return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
  },
)

// ── review_message ───────────────────────────────────────────────────────────

server.tool(
  'review_message',
  'Review a social media message or recommendation for social engineering risks before acting on it.',
  {
    content: z.string().describe('Message text'),
    source: z.enum(['twitter', 'discord', 'telegram', 'other']),
    recommends: z.string().optional(),
    hasUrl: z.boolean().optional(),
    hasCode: z.boolean().optional(),
    urgencyLanguage: z.boolean().optional(),
  },
  async (params) => {
    const res = await fetch(`${BASE_URL}/v1/review/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    })
    const data = await res.json()
    const lines = [
      `═══ MESSAGE REVIEW: ${data.summary} ═══`,
      ...data.checks.map((c: any) => `${c.status === 'pass' ? '✅' : c.status === 'warn' ? '⚠️' : '❌'} ${c.name}: ${c.detail}`),
    ]
    return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
  },
)

// ── assess_agent_before_call ──────────────────────────────────────────────────
// Pre-call assessment: check if an agent is safe to call

server.tool(
  'assess_agent_before_call',
  'Assess whether it is safe to call another AI agent before making the call. ' +
  'Checks: security score, declared capabilities, endpoint status, whitelist, and pricing. ' +
  'Use this BEFORE delegating to, paying, or interacting with any external agent. ' +
  'Returns: proceed / caution / reject recommendation with reasons.',
  {
    targetAgentId: z.string().describe('Agent ID to assess'),
    targetChain: z.enum(['ethereum', 'bsc', 'polygon', 'arbitrum', 'base', 'optimism', 'solana']).describe('Chain'),
    intendedAction: z.string().describe('What you want the agent to do (e.g. "audit smart contract", "swap tokens")'),
    maxBudget: z.number().optional().default(0).describe('Maximum USD you are willing to pay'),
  },
  async ({ targetAgentId, targetChain, intendedAction, maxBudget }) => {
    const res = await fetch(`${BASE_URL}/v1/assess`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetAgentId, targetChain, intendedAction, maxBudget }),
    })
    if (!res.ok) return { content: [{ type: 'text' as const, text: 'Assessment failed' }] }
    const d = await res.json()

    const icon = d.recommendation === 'proceed' ? '✅' : d.recommendation === 'caution' ? '⚠️' : d.recommendation === 'reject' ? '❌' : '❓'

    const lines = [
      `${icon} PRE-CALL ASSESSMENT: ${d.recommendation.toUpperCase()}`,
      ``,
      `Agent: #${d.agentId} on ${d.chain}`,
      `Security Score: ${d.securityScore ?? 'Not analyzed'}/100 ${d.grade ? `(Grade ${d.grade})` : ''}`,
      `Whitelisted: ${d.isWhitelisted ? `Yes — ${d.whitelistReason}` : 'No'}`,
      ``,
      `Wallet: ${d.wallet ?? 'No wallet bound — cannot pay this agent'}`,
      `Can do "${intendedAction}"? ${d.canDoAction ? `Yes (matched: ${d.matchedCapabilities.join(', ') || 'general'})` : 'No matching capabilities found'}`,
      ``,
      `Capabilities (${d.capabilities.length}):`,
      ...d.capabilities.slice(0, 8).map((c: any) => `  [${c.category}] ${c.capability} (${c.source}, ${Math.round(c.confidence * 100)}%)`),
      ``,
      `Endpoints (${d.endpoints.length}):`,
      ...d.endpoints.map((e: any) => `  ${e.type}: ${e.url} [${e.status}] ${e.toolsCount ? `${e.toolsCount} tools` : ''}`),
      ``,
      `Pricing: ${d.pricing}`,
      ``,
      `Reasons:`,
      ...d.reasons.map((r: string) => `  • ${r}`),
      ``,
      d.wallet && d.recommendation !== 'reject'
        ? `To pay this agent, call: authorize_payment({ chain: "${targetChain}", to: "${d.wallet}", ... })`
        : d.wallet ? `Payment address available but agent is rejected — do not pay.`
        : `No payment address — this agent has not bound a wallet via ERC-8004.`,
    ]

    return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
  },
)

// ── search_agents ────────────────────────────────────────────────────────────

server.tool(
  'search_agents',
  'Search for AI agents by capability. Find agents that can do a specific task. ' +
  'Use this when you need to discover agents for delegation or collaboration.',
  {
    query: z.string().describe('What capability to search for (e.g. "security audit", "swap", "price feed")'),
    chain: z.enum(['ethereum', 'bsc', 'polygon', 'arbitrum', 'base', 'optimism', 'solana']).optional().describe('Filter by chain'),
  },
  async ({ query, chain }) => {
    const params = new URLSearchParams({ q: query })
    if (chain) params.set('chain', chain)
    const res = await fetch(`${BASE_URL}/v1/capabilities/search?${params}`)
    if (!res.ok) return { content: [{ type: 'text' as const, text: 'Search failed' }] }
    const d = await res.json()

    if (d.results.length === 0) {
      return { content: [{ type: 'text' as const, text: `No agents found with capability "${query}"` }] }
    }

    const lines = [
      `Found ${d.results.length} agent(s) with "${query}" capability:`,
      ``,
      ...d.results.map((r: any) =>
        `  #${r.agentId} (${r.chain}) — ${r.capability} [${r.category}] — Score: ${r.securityScore ?? '?'}/100`
      ),
    ]
    return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
  },
)

// ── analyze_agent ────────────────────────────────────────────────────────────
// Full deep analysis of an on-chain agent — 26 dimensions

server.tool(
  'analyze_agent',
  'Run a comprehensive security analysis on an on-chain AI agent. ' +
  'Covers: address risk, contract security, token safety, approval patterns, address poisoning, ' +
  'funding source, behavioral analysis, cross-chain correlation, relationship graph, ' +
  'behavior-claim consistency, amount distribution, probe patterns, and more. ' +
  'Use this to get a complete security profile before trusting any agent.',
  {
    chain: z.enum(['ethereum', 'bsc', 'polygon', 'arbitrum', 'base', 'optimism', 'solana']).describe('Chain'),
    agentId: z.string().describe('Agent ID (numeric for EVM, asset pubkey for Solana)'),
  },
  async ({ chain, agentId }) => {
    const res = await fetch(`${BASE_URL}/v1/monitor/agents/${chain}/${agentId}`)
    if (!res.ok) {
      return { content: [{ type: 'text' as const, text: `Analysis failed: agent not found` }] }
    }
    const d = await res.json()
    const sa = d.securityAnalysis ?? {}
    const p = d.profile ?? {}
    const sm = d.slowmistReport ?? {}
    const da = d.deepAnalysis ?? {}
    const oa = d.ownerAnalysis ?? {}

    const lines = [
      `═══ AGENT SECURITY ANALYSIS ═══`,
      `Agent: #${d.agentId} on ${d.chainLabel}`,
      `Wallet: ${d.wallet ?? 'none'}`,
      `Score: ${sa.score ?? '—'}/100 | Grade: ${p.overallGrade ?? '—'}`,
      ``,
      `── Security Dimensions ──`,
      ...(p.dimensions ? Object.entries(p.dimensions).map(([k, v]) => `  ${k}: ${v}/100`) : ['  No data']),
      ``,
      `── Risk Indicators ──`,
      `  Rug-Pull Index: ${p.rugPullIndex?.score ?? 0}/100 ${p.rugPullIndex?.factors?.length ? `(${p.rugPullIndex.factors.join(', ')})` : ''}`,
      `  Gas Anomaly: ${p.gasAnomaly?.detected ? 'YES — ' + p.gasAnomaly.detail : 'No'}`,
      `  Logic Drift: ${p.logicDrift?.score ?? 0}% ${p.logicDrift?.detected ? '— ' + p.logicDrift.detail : ''}`,
      ``,
      `── On-Chain Checklist (${sm.checklist?.length ?? 0} steps) ──`,
      ...(sm.checklist ?? []).map((c: any) => `  ${c.status === 'pass' ? '✅' : c.status === 'warn' ? '⚠️' : c.status === 'fail' ? '❌' : '⏭'} ${c.name}: ${c.findings?.[0] ?? ''}`),
      ``,
      `── Deep Analysis ──`,
      ...(da.penalties ?? []).map((p: any) => `  -${p.points}: ${p.reason}`),
      da.claimConsistency ? `  Claim consistency: ${da.claimConsistency.score}/100` : '',
      da.graph ? `  Graph: ${da.graph.nodes} nodes, ${da.graph.edges} edges, ${da.graph.rings} rings` : '',
      da.probePattern?.detected ? `  ⚠ Probe-then-drain pattern detected` : '',
      da.frequencyTrend ? `  Frequency: ${da.frequencyTrend.trend}` : '',
      ``,
      `── Owner ──`,
      `  Address: ${oa.address ?? '—'}`,
      `  Agents owned: ${oa.totalAgents ?? '—'}`,
      `  Risk: ${oa.riskLevel ?? '—'}`,
      ``,
      `Transactions: ${sa.totalTransactions ?? 0} | Safe: ${sa.safe ?? 0} | Suspicious: ${sa.suspicious ?? 0} | Dangerous: ${sa.dangerous ?? 0}`,
    ].filter(Boolean)

    return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
  },
)

// ── verify_agent ─────────────────────────────────────────────────────────────

server.tool(
  'verify_agent',
  'Quick verification of an on-chain AI agent. Returns score, grade, and key findings. ' +
  'For deep analysis use analyze_agent instead.',
  {
    chain: z.enum(['ethereum', 'bsc', 'polygon', 'arbitrum', 'base', 'optimism', 'solana']).describe('Chain'),
    agentId: z.string().describe('Agent ID'),
  },
  async ({ chain, agentId }) => {
    const res = await fetch(`${BASE_URL}/v1/monitor/agents/${chain}/${agentId}`)
    if (!res.ok) return { content: [{ type: 'text' as const, text: 'Agent not found' }] }
    const d = await res.json()
    const sa = d.securityAnalysis ?? {}
    const verdict = sa.findings?.[0] ?? {}

    const lines = [
      `Agent #${d.agentId} on ${d.chainLabel}: Score ${sa.score ?? '—'}/100`,
      verdict.title ?? '',
      verdict.detail ?? '',
      `Txs: ${sa.totalTransactions ?? 0} | Safe: ${sa.safe ?? 0} | Suspicious: ${sa.suspicious ?? 0}`,
    ]
    return { content: [{ type: 'text' as const, text: lines.join('\n') }] }
  },
)

async function main() {
  if (!API_KEY) {
    console.error('Error: AGENT_GUARD_API_KEY environment variable is required')
    process.exit(1)
  }
  if (!AGENT_ID) {
    console.error('Error: AGENT_GUARD_AGENT_ID environment variable is required')
    process.exit(1)
  }

  const transport = new StdioServerTransport()
  await server.connect(transport)
  console.error(`Intercept MCP Server running (agent: ${AGENT_ID}, api: ${BASE_URL})`)
}

main().catch((err) => {
  console.error('Fatal:', err)
  process.exit(1)
})
