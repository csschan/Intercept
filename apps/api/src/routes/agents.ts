/**
 * Agent Routes
 * CRUD for agent management + history/budget queries
 * All routes require API key authentication (owner derived from key)
 */

import type { FastifyInstance } from 'fastify'
import { eq, desc, and, gte } from 'drizzle-orm'
import { db, agents, authRequests, auditLogs, knownMerchants } from '../db/index.js'

export async function agentRoutes(app: FastifyInstance) {

  // POST /v1/agents — register new agent
  app.post<{
    Body: { name: string; description?: string; walletAddress?: string; webhookUrl?: string }
  }>('/v1/agents', async (request, reply) => {
    const owner = (request as any).owner
    if (!owner) return reply.status(401).send({ error: 'Not authenticated' })

    const { name, description, walletAddress, webhookUrl } = request.body
    if (!name) return reply.status(400).send({ error: 'name is required' })

    const [agent] = await db
      .insert(agents)
      .values({ ownerId: owner.id, name, description, walletAddress, webhookUrl })
      .returning()

    return reply.status(201).send(agent)
  })

  // GET /v1/agents — list my agents
  app.get('/v1/agents', async (request, reply) => {
    const owner = (request as any).owner
    if (!owner) return reply.status(401).send({ error: 'Not authenticated' })

    const result = await db.query.agents.findMany({
      where: eq(agents.ownerId, owner.id),
      orderBy: [desc(agents.createdAt)],
    })
    return reply.send(result)
  })

  // GET /v1/agents/:id — single agent detail (must belong to me)
  app.get<{ Params: { id: string } }>('/v1/agents/:id', async (request, reply) => {
    const owner = (request as any).owner
    if (!owner) return reply.status(401).send({ error: 'Not authenticated' })

    const agent = await db.query.agents.findFirst({
      where: and(eq(agents.id, request.params.id), eq(agents.ownerId, owner.id)),
    })
    if (!agent) return reply.status(404).send({ error: 'Agent not found' })
    return reply.send(agent)
  })

  // GET /v1/history — all requests across my agents
  app.get<{ Querystring: { limit?: string } }>(
    '/v1/history',
    async (request, reply) => {
      const owner = (request as any).owner
      if (!owner) return reply.status(401).send({ error: 'Not authenticated' })
      const limit = Math.min(Number(request.query.limit ?? 100), 200)

      const history = await db.query.authRequests.findMany({
        where: eq(authRequests.ownerId, owner.id),
        orderBy: [desc(authRequests.createdAt)],
        limit,
      })
      return reply.send(history)
    },
  )

  // GET /v1/agents/:id/history — spending history for my agent
  app.get<{ Params: { id: string }; Querystring: { limit?: string; offset?: string } }>(
    '/v1/agents/:id/history',
    async (request, reply) => {
      const owner = (request as any).owner
      if (!owner) return reply.status(401).send({ error: 'Not authenticated' })
      const limit = Math.min(Number(request.query.limit ?? 50), 100)
      const offset = Number(request.query.offset ?? 0)

      // Verify agent belongs to owner
      const agent = await db.query.agents.findFirst({
        where: and(eq(agents.id, request.params.id), eq(agents.ownerId, owner.id)),
      })
      if (!agent) return reply.status(404).send({ error: 'Agent not found' })

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
    const owner = (request as any).owner
    if (!owner) return reply.status(401).send({ error: 'Not authenticated' })

    const agent = await db.query.agents.findFirst({
      where: and(eq(agents.id, request.params.id), eq(agents.ownerId, owner.id)),
    })
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
    const owner = (request as any).owner
    if (!owner) return reply.status(401).send({ error: 'Not authenticated' })

    const agentId = request.params.id
    const agent = await db.query.agents.findFirst({
      where: and(eq(agents.id, agentId), eq(agents.ownerId, owner.id)),
    })
    if (!agent) return reply.status(404).send({ error: 'Agent not found' })

    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)

    const [recentRequests, securityEvents] = await Promise.all([
      db.query.authRequests.findMany({
        where: and(eq(authRequests.agentId, agentId), gte(authRequests.createdAt, sevenDaysAgo)),
        orderBy: [desc(authRequests.createdAt)],
        limit: 200,
      }),
      db.query.auditLogs.findMany({
        where: and(eq(auditLogs.agentId, agentId), eq(auditLogs.event, 'security_override'), gte(auditLogs.createdAt, sevenDaysAgo)),
        orderBy: [desc(auditLogs.createdAt)],
        limit: 50,
      }),
    ])

    const totalRequests = recentRequests.length
    const overridesApplied = securityEvents.length
    const injectionAttempts = recentRequests.filter(r => {
      const ctx = r.securityContext as Record<string, unknown> | null
      return ctx && ctx.injectionRisk !== 'none'
    }).length
    const anomalyDetections = recentRequests.filter(r => {
      const ctx = r.securityContext as Record<string, unknown> | null
      return ctx && (ctx.anomalyScore as number ?? 0) >= 30
    }).length

    const hasHighRisk = securityEvents.some(e => {
      const data = e.data as Record<string, unknown> | null
      return data && ['address_blacklisted', 'prompt_injection_high', 'behavioral_anomaly_high'].includes(data.ruleTriggered as string)
    })
    const overallRisk = hasHighRisk ? 'high' : overridesApplied > 0 ? 'medium' : 'low'

    return reply.send({
      agentId,
      agentName: agent.name,
      period: '7d',
      overallRisk,
      summary: { totalRequests, overridesApplied, injectionAttempts, anomalyDetections },
      recentSecurityEvents: securityEvents.slice(0, 10).map(e => ({
        timestamp: e.createdAt,
        ruleTriggered: (e.data as Record<string, unknown>)?.ruleTriggered,
        newDecision: (e.data as Record<string, unknown>)?.newDecision,
      })),
    })
  })

  // ── Known Merchants ────────────────────────────────────────────────────────

  app.get<{ Params: { id: string } }>('/v1/agents/:id/merchants', async (request, reply) => {
    const owner = (request as any).owner
    if (!owner) return reply.status(401).send({ error: 'Not authenticated' })

    const agent = await db.query.agents.findFirst({
      where: and(eq(agents.id, request.params.id), eq(agents.ownerId, owner.id)),
    })
    if (!agent) return reply.status(404).send({ error: 'Agent not found' })

    const merchants = await db.query.knownMerchants.findMany({
      where: eq(knownMerchants.agentId, request.params.id),
      orderBy: [desc(knownMerchants.firstSeenAt)],
    })
    return reply.send(merchants)
  })

  app.post<{
    Params: { id: string }
    Body: { identifier: string; address: string; chain?: string; category?: string }
  }>('/v1/agents/:id/merchants', async (request, reply) => {
    const owner = (request as any).owner
    if (!owner) return reply.status(401).send({ error: 'Not authenticated' })

    const { identifier, address, chain, category } = request.body
    if (!identifier || !address) return reply.status(400).send({ error: 'identifier and address are required' })

    const agent = await db.query.agents.findFirst({
      where: and(eq(agents.id, request.params.id), eq(agents.ownerId, owner.id)),
    })
    if (!agent) return reply.status(404).send({ error: 'Agent not found' })

    const [merchant] = await db
      .insert(knownMerchants)
      .values({ agentId: request.params.id, identifier, address, chain: chain ?? null, category: category ?? null })
      .returning()

    return reply.status(201).send(merchant)
  })

  app.delete<{ Params: { id: string; merchantId: string } }>(
    '/v1/agents/:id/merchants/:merchantId',
    async (request, reply) => {
      const owner = (request as any).owner
      if (!owner) return reply.status(401).send({ error: 'Not authenticated' })

      await db.delete(knownMerchants).where(
        and(eq(knownMerchants.id, request.params.merchantId), eq(knownMerchants.agentId, request.params.id)),
      )
      return reply.status(204).send()
    },
  )

  // GET /v1/requests/pending — pending approvals for me
  app.get('/v1/requests/pending', async (request, reply) => {
    const owner = (request as any).owner
    if (!owner) return reply.status(401).send({ error: 'Not authenticated' })

    const pending = await db.query.authRequests.findMany({
      where: and(eq(authRequests.ownerId, owner.id), eq(authRequests.decision, 'ask_user' as any)),
      orderBy: [desc(authRequests.createdAt)],
      limit: 50,
    })
    return reply.send(pending)
  })
}
