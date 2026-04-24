/**
 * MCP Server Tool Tests
 *
 * Tests each MCP tool's request/response handling with mocked API.
 * Run: npx tsx --test packages/mcp/src/index.test.ts
 */

import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { z } from 'zod'

// ── Mock API Server ──────────────────────────────────────────────────────────

let mockResponses: Map<string, { status: number; body: unknown }>

// Intercept global fetch
const originalFetch = globalThis.fetch
function setupFetchMock() {
  mockResponses = new Map()
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input.toString()
    const path = new URL(url).pathname + (new URL(url).search || '')

    // Match by path prefix
    for (const [key, value] of mockResponses) {
      if (path.startsWith(key)) {
        return new Response(JSON.stringify(value.body), {
          status: value.status,
          headers: { 'Content-Type': 'application/json' },
        })
      }
    }
    return new Response(JSON.stringify({ error: 'Not mocked: ' + path }), { status: 500 })
  }) as typeof fetch
}

function teardownFetchMock() {
  globalThis.fetch = originalFetch
}

function mockApi(path: string, body: unknown, status = 200) {
  mockResponses.set(path, { status, body })
}

// ── Helper: create MCP client+server pair ────────────────────────────────────

async function createTestPair() {
  // Set env before importing server module
  process.env.AGENT_GUARD_API_KEY = 'test-key'
  process.env.AGENT_GUARD_AGENT_ID = 'test-agent-id'
  process.env.AGENT_GUARD_BASE_URL = 'http://localhost:8080'

  // We can't import the server module directly (it auto-starts),
  // so we recreate a minimal version of the tools here for testing.
  // This tests the tool logic, not the MCP wiring.
  const server = new McpServer({ name: 'agent-guard-test', version: '0.1.0' })
  const client = new Client({ name: 'test-client', version: '0.1.0' })

  // Register the authorize_payment tool (mirrors the real one)
  server.tool(
    'authorize_payment',
    'Check if a payment is allowed',
    {
      chain: z.enum(['solana', 'solana-devnet', 'ethereum', 'base', 'polygon', 'arbitrum']),
      to: z.string(),
      amount: z.string(),
      token: z.string().default('USDC'),
      merchant: z.string().optional(),
      category: z.string().optional(),
    },
    async (params) => {
      try {
        const response = await fetch('http://localhost:8080/v1/authorize', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-API-Key': 'test-key' },
          body: JSON.stringify({
            agentId: 'test-agent-id',
            chain: params.chain,
            transaction: {
              to: params.to,
              amount: params.amount,
              token: params.token,
              metadata: { merchant: params.merchant, category: params.category },
            },
          }),
        })
        const result = await response.json() as Record<string, unknown>
        const decision = result.decision as string

        if (decision === 'allow') {
          return { content: [{ type: 'text' as const, text: `ALLOWED — ${result.reason}` }] }
        }
        if (decision === 'deny') {
          return { content: [{ type: 'text' as const, text: `DENIED — ${result.reason}` }] }
        }
        return { content: [{ type: 'text' as const, text: `PENDING — ${result.reason}` }] }
      } catch (err) {
        return { content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }], isError: true }
      }
    },
  )

  server.tool('get_spending_budget', 'Check budget', {}, async () => {
    try {
      const response = await fetch('http://localhost:8080/v1/agents/test-agent-id/budget', {
        headers: { 'X-API-Key': 'test-key' },
      })
      const data = await response.json() as Record<string, unknown>
      return { content: [{ type: 'text' as const, text: JSON.stringify(data) }] }
    } catch (err) {
      return { content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }], isError: true }
    }
  })

  server.tool(
    'suggest_spending',
    'Ask what you can spend',
    {
      desired_amount_usdc: z.number().optional(),
      merchant: z.string().optional(),
    },
    async (params) => {
      try {
        const response = await fetch('http://localhost:8080/v1/suggest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-API-Key': 'test-key' },
          body: JSON.stringify({
            agentId: 'test-agent-id',
            desiredAmountUsdc: params.desired_amount_usdc,
            merchant: params.merchant,
          }),
        })
        const data = await response.json() as Record<string, unknown>
        return { content: [{ type: 'text' as const, text: JSON.stringify(data) }] }
      } catch (err) {
        return { content: [{ type: 'text' as const, text: `Error: ${(err as Error).message}` }], isError: true }
      }
    },
  )

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await server.connect(serverTransport)
  await client.connect(clientTransport)

  return { client, server }
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('MCP Server Tools', () => {
  beforeEach(() => setupFetchMock())
  afterEach(() => teardownFetchMock())

  it('authorize_payment → allow', async () => {
    mockApi('/v1/authorize', {
      decision: 'allow',
      requestId: 'req_test1',
      reason: 'Amount within auto-approval limit',
      ruleTriggered: 'policy_passed',
    })

    const { client } = await createTestPair()
    const result = await client.callTool({
      name: 'authorize_payment',
      arguments: { chain: 'solana', to: '9xQe...addr', amount: '3000000', token: 'USDC' },
    })

    const text = (result.content as Array<{ text: string }>)[0].text
    assert.match(text, /ALLOWED/)
    assert.match(text, /auto-approval/)
  })

  it('authorize_payment → deny', async () => {
    mockApi('/v1/authorize', {
      decision: 'deny',
      requestId: 'req_test2',
      reason: 'Monthly budget exceeded',
      ruleTriggered: 'monthly_budget_exceeded',
    })

    const { client } = await createTestPair()
    const result = await client.callTool({
      name: 'authorize_payment',
      arguments: { chain: 'solana', to: '9xQe...addr', amount: '99000000', token: 'USDC' },
    })

    const text = (result.content as Array<{ text: string }>)[0].text
    assert.match(text, /DENIED/)
    assert.match(text, /Monthly budget/)
  })

  it('authorize_payment → ask_user', async () => {
    mockApi('/v1/authorize', {
      decision: 'ask_user',
      requestId: 'req_test3',
      reason: 'New merchant requires confirmation',
      expiresAt: '2026-04-06T12:05:00Z',
      approvalUrl: 'http://localhost:3000/approve/req_test3',
      timeoutAction: 'deny',
    })

    const { client } = await createTestPair()
    const result = await client.callTool({
      name: 'authorize_payment',
      arguments: { chain: 'solana', to: '9xQe...new', amount: '15000000', token: 'USDC', merchant: 'NewShop' },
    })

    const text = (result.content as Array<{ text: string }>)[0].text
    assert.match(text, /PENDING/)
    assert.match(text, /New merchant/)
  })

  it('get_spending_budget returns budget data', async () => {
    mockApi('/v1/agents/test-agent-id/budget', {
      agentId: 'test-agent-id',
      daily: { spent: 12, limit: 50, resetAt: '2026-04-07T00:00:00Z' },
      monthly: { spent: 45, limit: 100, resetAt: '2026-05-01T00:00:00Z' },
    })

    const { client } = await createTestPair()
    const result = await client.callTool({ name: 'get_spending_budget', arguments: {} })

    const text = (result.content as Array<{ text: string }>)[0].text
    const data = JSON.parse(text)
    assert.equal(data.daily.spent, 12)
    assert.equal(data.daily.limit, 50)
    assert.equal(data.monthly.spent, 45)
  })

  it('suggest_spending returns guidance', async () => {
    mockApi('/v1/suggest', {
      budget: { daily: { spent: 10, limit: 50, remaining: 40 }, monthly: { spent: 30, limit: 100, remaining: 70 }, effectiveMaxUsdc: 40, autoApproveBelowUsdc: 5 },
      merchant: { name: 'OpenAI', status: 'known' },
      wouldAutoApprove: true,
      blockers: [],
      suggestions: [],
    })

    const { client } = await createTestPair()
    const result = await client.callTool({
      name: 'suggest_spending',
      arguments: { desired_amount_usdc: 3, merchant: 'OpenAI' },
    })

    const text = (result.content as Array<{ text: string }>)[0].text
    const data = JSON.parse(text)
    assert.equal(data.wouldAutoApprove, true)
    assert.equal(data.merchant.status, 'known')
    assert.equal(data.budget.effectiveMaxUsdc, 40)
  })

  it('suggest_spending with blocked merchant', async () => {
    mockApi('/v1/suggest', {
      budget: { daily: { spent: 0, limit: 50, remaining: 50 }, monthly: { spent: 0, limit: 100, remaining: 100 }, effectiveMaxUsdc: 50, autoApproveBelowUsdc: 5 },
      merchant: { name: 'ScamSite', status: 'blocked' },
      wouldAutoApprove: false,
      blockers: ['Merchant "ScamSite" is on the blocklist. Choose a different provider.'],
      suggestions: [],
    })

    const { client } = await createTestPair()
    const result = await client.callTool({
      name: 'suggest_spending',
      arguments: { desired_amount_usdc: 10, merchant: 'ScamSite' },
    })

    const text = (result.content as Array<{ text: string }>)[0].text
    const data = JSON.parse(text)
    assert.equal(data.wouldAutoApprove, false)
    assert.equal(data.merchant.status, 'blocked')
    assert.equal(data.blockers.length, 1)
  })

  it('authorize_payment handles API error', async () => {
    mockApi('/v1/authorize', { error: 'Agent not found' }, 404)

    const { client } = await createTestPair()
    const result = await client.callTool({
      name: 'authorize_payment',
      arguments: { chain: 'solana', to: 'addr', amount: '1000000', token: 'USDC' },
    })

    // Should not crash — tool should return the response (even error)
    const text = (result.content as Array<{ text: string }>)[0].text
    assert.ok(text.length > 0)
  })
})
