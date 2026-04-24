/**
 * @agent-guard/solana-plugin
 *
 * Agent Guard plugin for Solana Agent Kit.
 * Registers spending authorization as native agent actions so any Solana AI agent
 * automatically checks policies before executing transactions.
 *
 * Usage with Solana Agent Kit:
 *   import { SolanaAgentKit } from 'solana-agent-kit'
 *   import { agentGuardPlugin } from '@agent-guard/solana-plugin'
 *
 *   const agent = new SolanaAgentKit(wallet, rpcUrl, { plugins: [agentGuardPlugin(options)] })
 *
 * Usage standalone (LangChain / Vercel AI SDK / any framework):
 *   import { createAgentGuardTools } from '@agent-guard/solana-plugin'
 *   const tools = createAgentGuardTools(options)
 */

import { AgentGuard, type AuthorizeParams, type AuthorizeResult, type Chain } from '@agent-guard/sdk'

// ── Types ────────────────────────────────────────────────────────────────────

export interface AgentGuardPluginOptions {
  agentId: string
  apiKey: string
  baseUrl?: string
  /** Default chain for transactions (default: 'solana') */
  defaultChain?: Chain
  /** Auto-wait for human approval on ask_user (default: false) */
  autoWaitForApproval?: boolean
  /** Timeout for waiting approval in ms (default: 5min) */
  approvalTimeoutMs?: number
}

export interface ToolDefinition {
  name: string
  description: string
  parameters: Record<string, unknown>
  execute: (params: Record<string, unknown>) => Promise<string>
}

// ── Plugin Factory ───────────────────────────────────────────────────────────

/**
 * Create the Agent Guard plugin for Solana Agent Kit.
 *
 * Returns an object compatible with Solana Agent Kit's plugin interface:
 * { name, actions: [...] }
 */
export function agentGuardPlugin(options: AgentGuardPluginOptions) {
  const tools = createAgentGuardTools(options)

  return {
    name: 'agent-guard',
    methods: Object.fromEntries(
      tools.map((tool) => [
        tool.name,
        {
          description: tool.description,
          schema: tool.parameters,
          handler: tool.execute,
        },
      ]),
    ),
  }
}

// ── Tool Definitions ─────────────────────────────────────────────────────────

/**
 * Create standalone tool definitions usable with any agent framework.
 * Each tool has { name, description, parameters, execute }.
 */
export function createAgentGuardTools(options: AgentGuardPluginOptions): ToolDefinition[] {
  const guard = new AgentGuard({
    agentId: options.agentId,
    apiKey: options.apiKey,
    baseUrl: options.baseUrl,
    pollTimeout: options.approvalTimeoutMs,
  })
  const defaultChain = options.defaultChain ?? 'solana'

  return [
    // ── authorize_payment ────────────────────────────────────────────────
    {
      name: 'agent_guard_authorize',
      description:
        'Check if a payment is authorized before executing. ' +
        'Returns "allow" (proceed), "deny" (blocked), or "ask_user" (pending human approval). ' +
        'MUST be called before any transfer, swap, or payment.',
      parameters: {
        type: 'object',
        properties: {
          to: { type: 'string', description: 'Recipient wallet address' },
          amount: { type: 'string', description: 'Amount in base units (lamports/wei)' },
          token: { type: 'string', description: 'Token symbol', default: 'USDC' },
          chain: { type: 'string', description: 'Chain (default: solana)', enum: ['solana', 'solana-devnet', 'ethereum', 'base', 'polygon', 'arbitrum'] },
          merchant: { type: 'string', description: 'Merchant or service name' },
          category: { type: 'string', description: 'Spending category' },
          purpose: { type: 'string', description: 'Reason for this payment' },
        },
        required: ['to', 'amount'],
      },
      execute: async (params) => {
        const authParams: AuthorizeParams = {
          chain: (params.chain as Chain) ?? defaultChain,
          to: params.to as string,
          amount: params.amount as string,
          token: (params.token as string) ?? 'USDC',
          metadata: {
            merchant: params.merchant as string | undefined,
            category: params.category as string | undefined,
            purpose: params.purpose as string | undefined,
          },
        }

        const result = await guard.authorize(authParams)

        if (result.decision === 'allow') {
          return JSON.stringify({
            status: 'allowed',
            message: result.reason,
            requestId: result.requestId,
            action: 'You may proceed with this transaction.',
          })
        }

        if (result.decision === 'deny') {
          return JSON.stringify({
            status: 'denied',
            message: result.reason,
            rule: result.ruleTriggered,
            requestId: result.requestId,
            action: 'Do NOT execute this transaction.',
          })
        }

        // ask_user
        if (options.autoWaitForApproval) {
          const finalDecision = await guard.waitForApproval(result.requestId)
          return JSON.stringify({
            status: finalDecision,
            message: `Human ${finalDecision === 'allow' ? 'approved' : 'denied'} the transaction.`,
            requestId: result.requestId,
            action: finalDecision === 'allow' ? 'Proceed with transaction.' : 'Do NOT execute.',
          })
        }

        return JSON.stringify({
          status: 'pending_approval',
          message: result.reason,
          requestId: result.requestId,
          approvalUrl: result.approvalUrl,
          expiresAt: result.expiresAt,
          action: 'Transaction is paused. The owner has been notified. Wait for approval before proceeding.',
        })
      },
    },

    // ── get_budget ───────────────────────────────────────────────────────
    {
      name: 'agent_guard_budget',
      description:
        'Check remaining spending budget (daily and monthly limits). ' +
        'Call this before planning any purchases to understand budget constraints.',
      parameters: {
        type: 'object',
        properties: {},
        required: [],
      },
      execute: async () => {
        const baseUrl = options.baseUrl ?? 'https://api.agentguard.io'
        const response = await fetch(`${baseUrl}/v1/agents/${options.agentId}/budget`, {
          headers: { 'X-API-Key': options.apiKey },
        })
        const data = await response.json() as Record<string, unknown>

        const daily = data.daily as Record<string, unknown>
        const monthly = data.monthly as Record<string, unknown>

        return JSON.stringify({
          daily: {
            spent: daily.spent,
            limit: daily.limit,
            remaining: daily.limit != null ? Number(daily.limit) - Number(daily.spent) : null,
            resetAt: daily.resetAt,
          },
          monthly: {
            spent: monthly.spent,
            limit: monthly.limit,
            remaining: monthly.limit != null ? Number(monthly.limit) - Number(monthly.spent) : null,
            resetAt: monthly.resetAt,
          },
        })
      },
    },

    // ── check_approval_status ────────────────────────────────────────────
    {
      name: 'agent_guard_check_approval',
      description:
        'Check if a pending authorization request has been approved or denied by the human owner. ' +
        'Use after agent_guard_authorize returns pending_approval.',
      parameters: {
        type: 'object',
        properties: {
          request_id: { type: 'string', description: 'Request ID from agent_guard_authorize' },
        },
        required: ['request_id'],
      },
      execute: async (params) => {
        const baseUrl = options.baseUrl ?? 'https://api.agentguard.io'
        const response = await fetch(`${baseUrl}/v1/requests/${params.request_id}`, {
          headers: { 'X-API-Key': options.apiKey },
        })
        const data = await response.json() as Record<string, unknown>

        return JSON.stringify({
          requestId: data.id,
          decision: data.decision,
          resolvedBy: data.resolvedBy,
          reason: data.reason,
        })
      },
    },

    // ── create_session ───────────────────────────────────────────────────
    {
      name: 'agent_guard_create_session',
      description:
        'Create a time-limited spending session with a fixed budget. ' +
        'Ideal for scoped tasks: "spend up to $20 on API calls in the next hour". ' +
        'Spends within the session are auto-approved up to the budget.',
      parameters: {
        type: 'object',
        properties: {
          max_amount_usdc: { type: 'number', description: 'Maximum session budget in USDC' },
          duration_minutes: { type: 'number', description: 'Session duration in minutes' },
          purpose: { type: 'string', description: 'Session purpose' },
          allowed_merchants: { type: 'array', items: { type: 'string' }, description: 'Restrict to these merchants' },
        },
        required: ['max_amount_usdc', 'duration_minutes'],
      },
      execute: async (params) => {
        const baseUrl = options.baseUrl ?? 'https://api.agentguard.io'
        const response = await fetch(`${baseUrl}/v1/sessions`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-API-Key': options.apiKey,
          },
          body: JSON.stringify({
            agentId: options.agentId,
            maxAmountUsdc: params.max_amount_usdc,
            durationMinutes: params.duration_minutes,
            purpose: params.purpose,
            allowedMerchants: params.allowed_merchants,
          }),
        })
        const data = await response.json() as Record<string, unknown>

        return JSON.stringify({
          sessionId: data.id,
          budget: data.maxAmountUsdc,
          expiresAt: data.expiresAt,
          status: data.status,
          message: 'Session created. Use session_spend for payments within this session.',
        })
      },
    },
  ]
}

// ── LangChain Integration Helper ─────────────────────────────────────────────

/**
 * Convert Agent Guard tools to LangChain-compatible tool format.
 * Usage:
 *   import { toLangChainTools } from '@agent-guard/solana-plugin'
 *   const tools = toLangChainTools(options)
 *   const agent = createReactAgent({ llm, tools })
 */
export function toLangChainTools(options: AgentGuardPluginOptions) {
  const tools = createAgentGuardTools(options)

  return tools.map((tool) => ({
    name: tool.name,
    description: tool.description,
    schema: tool.parameters,
    func: async (input: string) => {
      const params = JSON.parse(input)
      return tool.execute(params)
    },
  }))
}

export { AgentGuard } from '@agent-guard/sdk'
export type { AuthorizeParams, AuthorizeResult, Chain } from '@agent-guard/sdk'
export default agentGuardPlugin
