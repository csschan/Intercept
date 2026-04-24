/**
 * Session Routes — Spending Session lifecycle
 *
 * POST   /v1/sessions              — create session
 * GET    /v1/sessions?agentId=     — list sessions
 * GET    /v1/sessions/:id          — get session + spend log
 * POST   /v1/sessions/:id/spend    — spend within session
 * POST   /v1/sessions/:id/revoke   — revoke session
 */

import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { eq, and, desc, sql as rawSql } from 'drizzle-orm'
import { nanoid } from 'nanoid'
import { db, agents, policies, owners, spendingSessions, sessionSpends } from '../db/index.js'
import { hashPolicy, policyToRules } from '../services/chain.js'

// Lazy-load Solana session client
async function getSessionChainClient() {
  if (!process.env.SOLANA_PRIVATE_KEY) return null
  try {
    const mod = await import('@agent-guard/solana')
    return mod.getSpendingSessionClient()
  } catch {
    return null
  }
}

export async function sessionRoutes(app: FastifyInstance) {

  // POST /v1/sessions — create a spending session
  app.post<{
    Body: {
      agentId: string
      maxAmountUsdc: number
      durationMinutes: number
      allowedMerchants?: string[]      // display names (display only)
      allowedRecipients?: string[]     // on-chain addresses (the unforgeable binding)
      allowedCategories?: string[]
      purpose?: string
    }
  }>('/v1/sessions', async (request, reply) => {
    const { agentId, maxAmountUsdc, durationMinutes, allowedMerchants, allowedRecipients, allowedCategories, purpose } = request.body

    if (!agentId || !maxAmountUsdc || !durationMinutes) {
      return reply.status(400).send({ error: 'agentId, maxAmountUsdc, durationMinutes required' })
    }

    const agent = await db.query.agents.findFirst({ where: eq(agents.id, agentId) })
    if (!agent) return reply.status(404).send({ error: 'Agent not found' })

    // Load policy for validation
    let policyHash = ''
    if (agent.policyId) {
      const policy = await db.query.policies.findFirst({ where: eq(policies.id, agent.policyId) })
      if (policy) {
        const rules = policyToRules(policy)
        policyHash = hashPolicy(rules)

        // Validate session against policy hard rules
        if (policy.blockedCategories && allowedCategories) {
          const blocked = (policy.blockedCategories as string[]).filter(c => allowedCategories.includes(c))
          if (blocked.length > 0) {
            return reply.status(403).send({ error: `Categories blocked by policy: ${blocked.join(', ')}` })
          }
        }
        if (policy.dailyLimitUsdc && maxAmountUsdc > Number(policy.dailyLimitUsdc)) {
          return reply.status(403).send({ error: `Session budget $${maxAmountUsdc} exceeds daily limit $${policy.dailyLimitUsdc}` })
        }
      }
    }

    const sessionId = `sess_${nanoid(16)}`
    const sessionKey = `sk_${nanoid(32)}`
    const expiresAt = durationMinutes === 0
      ? new Date('2099-12-31') // permanent
      : new Date(Date.now() + durationMinutes * 60 * 1000)

    const [session] = await db.insert(spendingSessions).values({
      id: sessionId,
      agentId,
      ownerId: agent.ownerId,
      maxAmountUsdc: maxAmountUsdc.toString(),
      expiresAt,
      allowedMerchants: allowedMerchants ?? [],
      allowedRecipients: allowedRecipients ?? [],
      allowedCategories: allowedCategories ?? [],
      purpose,
      policySnapshotId: agent.policyId,
      policyHash,
      status: 'active',
    } as any).returning()

    // Save session key (not in drizzle schema, use raw SQL)
    await db.execute(rawSql`UPDATE spending_sessions SET session_key = ${sessionKey} WHERE id = ${sessionId}`)

    // Sync to chain (fire-and-forget)
    getSessionChainClient().then(async (client) => {
      if (!client) return
      try {
        const result = await client.createSession({
          sessionId,
          agentId,
          maxAmountUsdc,
          expiresAt: Math.floor(expiresAt.getTime() / 1000),
          allowedMerchants: allowedMerchants ?? [],
          policyHash: Buffer.from(policyHash, 'hex'),
        })
        await db.update(spendingSessions).set({
          onChainPda: result.pda,
          onChainSignature: result.signature,
        }).where(eq(spendingSessions.id, sessionId))
        app.log.info(`[chain] Session ${sessionId} created on-chain: ${result.pda}`)
      } catch (err) {
        app.log.error(`[chain] Session sync failed: ${err}`)
      }
    }).catch(() => {})

    return reply.status(201).send({
      ...session,
      sessionKey,
      onboarding: {
        mcp: {
          description: 'Add to your Claude/Cursor MCP config',
          config: {
            mcpServers: {
              intercept: {
                command: 'npx',
                args: ['@intercept/mcp'],
                env: { INTERCEPT_SESSION_KEY: sessionKey },
              },
            },
          },
        },
        sdk: {
          description: 'npm install @intercept/sdk',
          code: `import { Intercept } from '@intercept/sdk'\nconst guard = new Intercept('${sessionKey}')\n\n// Before any payment:\nconst result = await guard.check({ to, amount, token, chain })\nif (result.allow) { /* sign & pay */ }`,
        },
        api: {
          description: 'Direct API call',
          curl: `curl -X POST https://api.intercept.security/v1/authorize \\\n  -H "x-session-key: ${sessionKey}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"to":"0x...","amount":"1000000","token":"USDC","chain":"base"}'`,
        },
      },
    })
  })

  // GET /v1/sessions?agentId= — list sessions
  app.get<{ Querystring: { agentId?: string; ownerId?: string } }>(
    '/v1/sessions',
    async (request, reply) => {
      const { agentId, ownerId } = request.query
      if (!agentId && !ownerId) return reply.status(400).send({ error: 'agentId or ownerId required' })

      const where = agentId
        ? eq(spendingSessions.agentId, agentId)
        : eq(spendingSessions.ownerId, ownerId!)

      const sessions = await db.query.spendingSessions.findMany({
        where,
        orderBy: desc(spendingSessions.createdAt),
      })

      // Lazy expiration check
      const now = new Date()
      for (const s of sessions) {
        if (s.status === 'active' && new Date(s.expiresAt) <= now) {
          await db.update(spendingSessions).set({ status: 'expired' }).where(eq(spendingSessions.id, s.id))
          s.status = 'expired'
        }
      }

      return reply.send(sessions)
    },
  )

  // GET /v1/sessions/:id — session detail + spend log
  app.get<{ Params: { id: string } }>(
    '/v1/sessions/:id',
    async (request, reply) => {
      const session = await db.query.spendingSessions.findFirst({
        where: eq(spendingSessions.id, request.params.id),
      })
      if (!session) return reply.status(404).send({ error: 'Session not found' })

      // Lazy expiration
      if (session.status === 'active' && new Date(session.expiresAt) <= new Date()) {
        await db.update(spendingSessions).set({ status: 'expired' }).where(eq(spendingSessions.id, session.id))
        session.status = 'expired'
      }

      const spends = await db.query.sessionSpends.findMany({
        where: eq(sessionSpends.sessionId, session.id),
        orderBy: desc(sessionSpends.createdAt),
      })

      return reply.send({ ...session, spends })
    },
  )

  // POST /v1/sessions/:id/spend — spend within session
  app.post<{
    Params: { id: string }
    Body: {
      to: string
      amountUsdc: number
      token?: string
      merchant?: string
      category?: string
      purpose?: string
    }
  }>('/v1/sessions/:id/spend', async (request, reply) => {
    const { to, amountUsdc, token, merchant, category, purpose } = request.body

    if (!to || !amountUsdc) return reply.status(400).send({ error: 'to and amountUsdc required' })

    const session = await db.query.spendingSessions.findFirst({
      where: eq(spendingSessions.id, request.params.id),
    })
    if (!session) return reply.status(404).send({ error: 'Session not found' })

    // Check active
    if (session.status !== 'active') {
      return reply.status(410).send({ error: `Session is ${session.status}` })
    }

    // Check expiration
    if (new Date(session.expiresAt) <= new Date()) {
      await db.update(spendingSessions).set({ status: 'expired' }).where(eq(spendingSessions.id, session.id))
      return reply.status(410).send({ error: 'Session has expired' })
    }

    // Check budget
    const spent = Number(session.spentSoFar)
    const max = Number(session.maxAmountUsdc)
    if (spent + amountUsdc > max) {
      return reply.status(403).send({
        error: 'Budget exceeded',
        remaining: max - spent,
        requested: amountUsdc,
      })
    }

    // Recipient address allowlist — the unforgeable binding.
    // If set, the destination address MUST be in the list. Names are ignored
    // because agents could spoof them; addresses cannot be spoofed.
    if (session.allowedRecipients && session.allowedRecipients.length > 0) {
      if (!session.allowedRecipients.includes(to)) {
        return reply.status(403).send({
          error: `Recipient address "${to}" is not in the session allowlist`,
          allowedRecipients: session.allowedRecipients,
        })
      }
    }

    // Update spent
    const newSpent = spent + amountUsdc
    const newStatus = newSpent >= max ? 'exhausted' : 'active'
    await db.update(spendingSessions).set({
      spentSoFar: newSpent.toString(),
      status: newStatus as any,
    }).where(eq(spendingSessions.id, session.id))

    // Record spend
    await db.insert(sessionSpends).values({
      sessionId: session.id,
      agentId: session.agentId,
      toAddress: to,
      amountUsdc: amountUsdc.toString(),
      token: token ?? 'USDC',
      merchant,
      category,
      purpose,
    })

    // Also update agent's daily/monthly budget
    await db.execute(
      `UPDATE agents SET
        daily_spent_usdc = COALESCE(daily_spent_usdc, 0) + ${amountUsdc},
        monthly_spent_usdc = COALESCE(monthly_spent_usdc, 0) + ${amountUsdc}
      WHERE id = '${session.agentId}'`
    )

    // Sync spend to chain (fire-and-forget)
    getSessionChainClient().then(async (client) => {
      if (!client || !merchant) return
      try {
        await client.spendFromSession({
          sessionId: session.id,
          amountUsdc,
          merchant,
        })
      } catch {}
    }).catch(() => {})

    return reply.send({
      allowed: true,
      spent: newSpent,
      remaining: max - newSpent,
      sessionStatus: newStatus,
      expiresAt: session.expiresAt,
    })
  })

  // POST /v1/sessions/:id/revoke — revoke a session
  app.post<{ Params: { id: string }; Body: { reason?: string } }>(
    '/v1/sessions/:id/revoke',
    async (request, reply) => {
      const session = await db.query.spendingSessions.findFirst({
        where: eq(spendingSessions.id, request.params.id),
      })
      if (!session) return reply.status(404).send({ error: 'Session not found' })

      if (session.status !== 'active') {
        return reply.status(400).send({ error: `Session is already ${session.status}` })
      }

      await db.update(spendingSessions).set({
        status: 'revoked',
        revokedAt: new Date(),
        revokedReason: request.body?.reason,
      }).where(eq(spendingSessions.id, session.id))

      // Revoke on-chain
      getSessionChainClient().then(async (client) => {
        if (!client) return
        try {
          await client.revokeSession(session.id)
        } catch {}
      }).catch(() => {})

      return reply.send({ ...session, status: 'revoked' })
    },
  )

  // GET /v1/sessions/:id/stats — session usage stats
  app.get<{ Params: { id: string } }>(
    '/v1/sessions/:id/stats',
    async (request, reply) => {
      const { id } = request.params
      const session = await db.query.spendingSessions.findFirst({ where: eq(spendingSessions.id, id) })
      if (!session) return reply.status(404).send({ error: 'Session not found' })

      // Get call history for this session
      const { sql: rawSql } = await import('drizzle-orm')
      const history = await db.execute(rawSql.raw(
        `SELECT decision, source_type, COUNT(*) as cnt, SUM(CAST(amount_usdc AS NUMERIC)) as total_usdc
         FROM auth_requests WHERE session_id = '${id}'
         GROUP BY decision, source_type`
      ))

      const recentCalls = await db.execute(rawSql.raw(
        `SELECT id, to_address, amount_usdc, token, decision, reason, source_type, resource_url, created_at
         FROM auth_requests WHERE session_id = '${id}'
         ORDER BY created_at DESC LIMIT 20`
      ))

      return reply.send({
        session: {
          id: session.id,
          status: session.status,
          maxAmountUsdc: session.maxAmountUsdc,
          spentSoFar: session.spentSoFar,
          expiresAt: session.expiresAt,
          totalCalls: (session as any).total_calls ?? 0,
          totalDenied: (session as any).total_denied ?? 0,
        },
        breakdown: (history as any[]).map(r => ({
          decision: r.decision,
          sourceType: r.source_type,
          count: Number(r.cnt),
          totalUsdc: Number(r.total_usdc ?? 0),
        })),
        recentCalls: (recentCalls as any[]).map(r => ({
          id: r.id,
          to: r.to_address,
          amountUsdc: Number(r.amount_usdc ?? 0),
          token: r.token,
          decision: r.decision,
          reason: r.reason,
          sourceType: r.source_type,
          resourceUrl: r.resource_url,
          createdAt: r.created_at,
        })),
      })
    },
  )

  // GET /v1/billing?ownerId= — billing info
  app.get<{ Querystring: { ownerId: string } }>(
    '/v1/billing',
    async (request, reply) => {
      const { ownerId } = request.query
      if (!ownerId) return reply.status(400).send({ error: 'ownerId required' })

      const { sql: rawSql } = await import('drizzle-orm')
      const billingRow = await db.execute(rawSql.raw(
        `SELECT * FROM billing WHERE owner_id = '${ownerId}'`
      ))
      const billing = (billingRow as any[])[0]

      // Total usage across all sessions
      const usageRow = await db.execute(rawSql.raw(
        `SELECT COUNT(*) as total_calls, COUNT(CASE WHEN decision = 'deny' THEN 1 END) as denied
         FROM auth_requests WHERE owner_id = '${ownerId}'`
      ))
      const usage = (usageRow as any[])[0]

      return reply.send({
        balance: Number(billing?.balance_usdc ?? 0),
        totalSpent: Number(billing?.total_spent ?? 0),
        totalCalls: Number(usage?.total_calls ?? 0),
        totalDenied: Number(usage?.denied ?? 0),
        costPerCall: 0.005,
      })
    },
  )
}
