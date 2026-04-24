/**
 * @agent-guard/sdk
 *
 * Lightweight client SDK for integrating Agent Guard into any AI agent.
 * Framework-agnostic — works with LangChain, AutoGen, custom agents, etc.
 *
 * Usage:
 *   const guard = new AgentGuard({ agentId: '...', apiKey: '...' })
 *   const result = await guard.authorize({ chain: 'solana', to: '...', amount: '5000000', token: 'USDC' })
 *   if (result.decision === 'allow') { // execute transaction }
 *   if (result.decision === 'ask_user') { await guard.waitForApproval(result.requestId) }
 */

export type Chain =
  | 'solana'
  | 'solana-devnet'
  | 'ethereum'
  | 'base'
  | 'polygon'
  | 'arbitrum'

export type Decision = 'allow' | 'deny' | 'ask_user'

export interface AuthorizeParams {
  chain: Chain
  to: string
  amount: string
  token?: string
  tokenAddress?: string
  from?: string
  metadata?: {
    purpose?: string
    merchant?: string
    category?: string
    isRecurring?: boolean
  }
}

export interface AuthorizeResult {
  decision: Decision
  requestId: string
  reason: string
  ruleTriggered?: string
  expiresAt?: string
  approvalUrl?: string
  timeoutAction?: 'allow' | 'deny'
}

export interface AgentGuardOptions {
  agentId: string
  apiKey: string
  baseUrl?: string
  /** Timeout for waitForApproval polling in ms (default: 5 min) */
  pollTimeout?: number
  /** Poll interval in ms (default: 3s) */
  pollInterval?: number
}

export class AgentGuard {
  private readonly agentId: string
  private readonly apiKey: string
  private readonly baseUrl: string
  private readonly pollTimeout: number
  private readonly pollInterval: number

  constructor(options: AgentGuardOptions) {
    this.agentId = options.agentId
    this.apiKey = options.apiKey
    this.baseUrl = options.baseUrl ?? 'https://api.agentguard.io'
    this.pollTimeout = options.pollTimeout ?? 5 * 60 * 1000
    this.pollInterval = options.pollInterval ?? 3000
  }

  /**
   * Authorize a transaction before execution.
   * Returns allow | deny | ask_user immediately.
   */
  async authorize(params: AuthorizeParams): Promise<AuthorizeResult> {
    const response = await this.request('POST', '/v1/authorize', {
      agentId: this.agentId,
      chain: params.chain,
      transaction: {
        from: params.from,
        to: params.to,
        amount: params.amount,
        token: params.token ?? 'USDC',
        tokenAddress: params.tokenAddress,
        metadata: params.metadata,
      },
    })

    return response as AuthorizeResult
  }

  /**
   * Poll until a pending request is resolved (approved/denied/timeout).
   * Use after receiving decision === 'ask_user'.
   */
  async waitForApproval(requestId: string): Promise<'allow' | 'deny'> {
    const deadline = Date.now() + this.pollTimeout

    while (Date.now() < deadline) {
      const req = await this.request('GET', `/v1/requests/${requestId}`)
      const { decision } = req as { decision: string }

      if (decision === 'allow') return 'allow'
      if (decision === 'deny') return 'deny'
      // 'ask_user' | 'pending' — still waiting

      await sleep(this.pollInterval)
    }

    throw new Error(`Approval timeout for request ${requestId}`)
  }

  /**
   * Convenience: authorize and wait if needed.
   * Returns the final decision ('allow' | 'deny').
   */
  async check(params: AuthorizeParams): Promise<'allow' | 'deny'> {
    const result = await this.authorize(params)

    if (result.decision === 'allow') return 'allow'
    if (result.decision === 'deny') return 'deny'

    // ask_user — wait for human
    return this.waitForApproval(result.requestId)
  }

  private async request(method: string, path: string, body?: unknown): Promise<unknown> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': this.apiKey,
      },
      body: body ? JSON.stringify(body) : undefined,
    })

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: response.statusText }))
      throw new Error(`AgentGuard API error ${response.status}: ${JSON.stringify(error)}`)
    }

    return response.json()
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

export default AgentGuard
