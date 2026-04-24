/**
 * Agent Routes
 * CRUD for agent management + history/budget queries
 */

import type { FastifyInstance } from 'fastify'
import { eq, desc, and, gte, sql } from 'drizzle-orm'
import { db, agents, authRequests, auditLogs, knownMerchants } from '../db/index.js'

export async function agentRoutes(app: FastifyInstance) {
  // POST /v1/agents — register new agent
  app.post<{
    Body: {
      ownerId: string
      name: string
      description?: string
      walletAddress?: string
      webhookUrl?: string
    }
  }>('/v1/agents', async (request, reply) => {
    const { ownerId, name, description, walletAddress, webhookUrl } = request.body
    if (!ownerId || !name) return reply.status(400).send({ error: 'ownerId and name are required' })

    const [agent] = await db
      .insert(agents)
      .values({ ownerId, name, description, walletAddress, webhookUrl })
      .returning()

    return reply.status(201).send(agent)
  })

  // GET /v1/agents — list agents for owner
  app.get<{ Querystring: { ownerId: string } }>('/v1/agents', async (request, reply) => {
    const { ownerId } = request.query
    if (!ownerId) return reply.status(400).send({ error: 'ownerId is required' })

    const result = await db.query.agents.findMany({
      where: eq(agents.ownerId, ownerId),
      orderBy: [desc(agents.createdAt)],
    })
    return reply.send(result)
  })

  // GET /v1/agents/:id — single agent detail
  app.get<{ Params: { id: string } }>('/v1/agents/:id', async (request, reply) => {
    const agent = await db.query.agents.findFirst({ where: eq(agents.id, request.params.id) })
    if (!agent) return reply.status(404).send({ error: 'Agent not found' })
    return reply.send(agent)
  })

  // GET /v1/history?ownerId= — all requests across all agents for an owner
  app.get<{ Querystring: { ownerId: string; limit?: string } }>(
    '/v1/history',
    async (request, reply) => {
      const { ownerId } = request.query
      if (!ownerId) return reply.status(400).send({ error: 'ownerId is required' })
      const limit = Math.min(Number(request.query.limit ?? 100), 200)

      const history = await db.query.authRequests.findMany({
        where: eq(authRequests.ownerId, ownerId),
        orderBy: [desc(authRequests.createdAt)],
        limit,
      })
      return reply.send(history)
    },
  )

  // GET /v1/agents/:id/history — spending history
  app.get<{ Params: { id: string }; Querystring: { limit?: string; offset?: string } }>(
    '/v1/agents/:id/history',
    async (request, reply) => {
      const limit = Math.min(Number(request.query.limit ?? 50), 100)
      const offset = Number(request.query.offset ?? 0)

      const history = await db.query.authRequests.findMany({
        where: eq(authRequests.agentId, request.params.id),
        orderBy: [desc(authRequests.createdAt)],
        limit,
        offset,
      })
      return reply.send(history)
    },
  )

  // GET /v1/agents/:id/budget — current budget status
  app.get<{ Params: { id: string } }>('/v1/agents/:id/budget', async (request, reply) => {
    const agent = await db.query.agents.findFirst({ where: eq(agents.id, request.params.id) })
    if (!agent) return reply.status(404).send({ error: 'Agent not found' })

    const policy = agent.policyId
      ? await db.query.policies.findFirst({ where: eq((await import('../db/schema.js')).policies.id, agent.policyId) })
      : null

    return reply.send({
      agentId: agent.id,
      daily: {
        spent: Number(agent.dailySpentUsdc),
        limit: policy?.dailyLimitUsdc ? Number(policy.dailyLimitUsdc) : null,
        resetAt: agent.dailyResetAt,
      },
      monthly: {
        spent: Number(agent.monthlySpentUsdc),
        limit: policy?.monthlyLimitUsdc ? Number(policy.monthlyLimitUsdc) : null,
        resetAt: agent.monthlyResetAt,
      },
    })
  })

  // GET /v1/agents/:id/security — agent security profile
  app.get<{ Params: { id: string } }>('/v1/agents/:id/security', async (request, reply) => {
    const agentId = request.params.id
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)

    const [agent, recentRequests, securityEvents] = await Promise.all([
      db.query.agents.findFirst({ where: eq(agents.id, agentId) }),

      // All requests in last 7 days with their security context
      db.query.authRequests.findMany({
        where: and(
          eq(authRequests.agentId, agentId),
          gte(authRequests.createdAt, sevenDaysAgo),
        ),
        orderBy: [desc(authRequests.createdAt)],
        limit: 200,
      }),

      // Security override events (injection detected, anomaly, etc.)
      db.query.auditLogs.findMany({
        where: and(
          eq(auditLogs.agentId, agentId),
          eq(auditLogs.event, 'security_override'),
          gte(auditLogs.createdAt, sevenDaysAgo),
        ),
        orderBy: [desc(auditLogs.createdAt)],
        limit: 50,
      }),
    ])

    if (!agent) return reply.status(404).send({ error: 'Agent not found' })

    // Aggregate security metrics
    const totalRequests = recentRequests.length
    const overridesApplied = securityEvents.length

    const injectionAttempts = recentRequests.filter(r => {
      const ctx = r.securityContext as Record<string, unknown> | null
      return ctx && ctx.injectionRisk !== 'none'
    })

    const anomalyDetections = recentRequests.filter(r => {
      const ctx = r.securityContext as Record<string, unknown> | null
      return ctx && (ctx.anomalyScore as number ?? 0) >= 30
    })

    const addressFlags = recentRequests.filter(r => {
      const ctx = r.securityContext as Record<string, unknown> | null
      return ctx && ctx.addressRisk !== 'safe'
    })

    // Risk trend: average anomaly score per day over last 7 days
    const dailyScores: Record<string, number[]> = {}
    for (const req of recentRequests) {
      const ctx = req.securityContext as Record<string, unknown> | null
      if (!ctx) continue
      const day = req.createdAt.toISOString().slice(0, 10)
      if (!dailyScores[day]) dailyScores[day] = []
      dailyScores[day].push(ctx.anomalyScore as number ?? 0)
    }
    const riskTrend = Object.entries(dailyScores).map(([date, scores]) => ({
      date,
      avgAnomalyScore: Math.round(scores.reduce((a, b) => a + b, 0) / scores.length),
    }))

    // Overall risk level for this agent
    const hasHighRisk = securityEvents.some(e => {
      const data = e.data as Record<string, unknown> | null
      return data && ['address_blacklisted', 'prompt_injection_high', 'behavioral_anomaly_high'].includes(data.ruleTriggered as string)
    })
    const hasMediumRisk = overridesApplied > 0
    const overallRisk = hasHighRisk ? 'high' : hasMediumRisk ? 'medium' : 'low'

    return reply.send({
      agentId,
      agentName: agent.name,
      period: '7d',
      overallRisk,
      summary: {
        totalRequests,
        overridesApplied,
        injectionAttempts: injectionAttempts.length,
        anomalyDetections: anomalyDetections.length,
        suspiciousAddresses: addressFlags.length,
      },
      recentSecurityEvents: securityEvents.slice(0, 10).map(e => ({
        timestamp: e.createdAt,
        ruleTriggered: (e.data as Record<string, unknown>)?.ruleTriggered,
        originalDecision: (e.data as Record<string, unknown>)?.originalDecision,
        newDecision: (e.data as Record<string, unknown>)?.newDecision,
      })),
      riskTrend,
    })
  })

  // ── Known Merchants (address-based binding) ──────────────────────────────

  // GET /v1/agents/:id/merchants — list registered merchants for an agent
  app.get<{ Params: { id: string } }>('/v1/agents/:id/merchants', async (request, reply) => {
    const merchants = await db.query.knownMerchants.findMany({
      where: eq(knownMerchants.agentId, request.params.id),
      orderBy: [desc(knownMerchants.firstSeenAt)],
    })
    return reply.send(merchants)
  })

  // POST /v1/agents/:id/merchants — register a merchant with name + address
  app.post<{
    Params: { id: string }
    Body: { identifier: string; address: string; chain?: string; category?: string }
  }>('/v1/agents/:id/merchants', async (request, reply) => {
    const { identifier, address, chain, category } = request.body
    if (!identifier || !address) {
      return reply.status(400).send({ error: 'identifier and address are required' })
    }

    const agent = await db.query.agents.findFirst({ where: eq(agents.id, request.params.id) })
    if (!agent) return reply.status(404).send({ error: 'Agent not found' })

    const [merchant] = await db
      .insert(knownMerchants)
      .values({
        agentId: request.params.id,
        identifier,
        address,
        chain: chain ?? null,
        category: category ?? null,
      })
      .returning()

    return reply.status(201).send(merchant)
  })

  // DELETE /v1/agents/:id/merchants/:merchantId
  app.delete<{ Params: { id: string; merchantId: string } }>(
    '/v1/agents/:id/merchants/:merchantId',
    async (request, reply) => {
      await db
        .delete(knownMerchants)
        .where(
          and(
            eq(knownMerchants.id, request.params.merchantId),
            eq(knownMerchants.agentId, request.params.id),
          ),
        )
      return reply.status(204).send()
    },
  )

  // GET /v1/requests/pending — pending approvals for owner
  app.get<{ Querystring: { ownerId: string } }>('/v1/requests/pending', async (request, reply) => {
    const { ownerId } = request.query
    if (!ownerId) return reply.status(400).send({ error: 'ownerId is required' })

    const pending = await db.query.authRequests.findMany({
      where: and(
        eq(authRequests.ownerId, ownerId),
        eq(authRequests.decision, 'ask_user' as any),
      ),
      orderBy: [desc(authRequests.createdAt)],
      limit: 50,
    })
    return reply.send(pending)
  })
}
