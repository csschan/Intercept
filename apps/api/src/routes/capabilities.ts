/**
 * Capability & Pre-Call Assessment Routes
 *
 * POST /v1/assess            — pre-call assessment before calling an agent
 * GET  /v1/capabilities/:chain/:id — get agent capabilities
 * GET  /v1/capabilities/search — search agents by capability
 * POST /v1/whitelist         — add agent to whitelist
 * GET  /v1/whitelist          — list whitelisted agents
 * DELETE /v1/whitelist/:id    — remove from whitelist
 */

import type { FastifyInstance } from 'fastify'
import { db } from '../db/index.js'
import { sql } from 'drizzle-orm'
import { assessAgentBeforeCall, indexAgentCapabilities, getIndexerStats } from '../services/capability-indexer.js'

export async function capabilityRoutes(app: FastifyInstance) {

  // POST /v1/assess — pre-call assessment
  app.post<{
    Body: { targetAgentId: string; targetChain: string; intendedAction: string; maxBudget?: number; callerId?: string }
  }>('/v1/assess', async (request, reply) => {
    const { targetAgentId, targetChain, intendedAction, maxBudget, callerId } = request.body
    const result = await assessAgentBeforeCall(targetAgentId, targetChain, intendedAction, maxBudget ?? 0, callerId)
    return reply.send(result)
  })

  // GET /v1/capabilities/:chain/:id
  app.get<{ Params: { chain: string; id: string } }>(
    '/v1/capabilities/:chain/:id',
    async (request, reply) => {
      const { chain, id } = request.params

      const caps = await db.execute(sql.raw(
        `SELECT capability, category, confidence, source, last_checked FROM agent_capabilities
         WHERE agent_id = '${id}' AND chain = '${chain}' ORDER BY confidence DESC`
      ))
      const eps = await db.execute(sql.raw(
        `SELECT endpoint_type, url, status, tools_count, tools_list, pricing, last_checked FROM agent_endpoints
         WHERE agent_id = '${id}' AND chain = '${chain}'`
      ))

      return reply.send({
        agentId: id, chain,
        capabilities: (caps as any[]).map(r => ({
          capability: r.capability, category: r.category,
          confidence: Number(r.confidence), source: r.source,
          lastChecked: r.last_checked,
        })),
        endpoints: (eps as any[]).map(r => ({
          type: r.endpoint_type, url: r.url, status: r.status,
          toolsCount: Number(r.tools_count),
          tools: r.tools_list,
          pricing: r.pricing,
          lastChecked: r.last_checked,
        })),
      })
    },
  )

  // GET /v1/capabilities/search?q=security&category=security
  app.get<{ Querystring: { q?: string; category?: string; chain?: string; limit?: string } }>(
    '/v1/capabilities/search',
    async (request, reply) => {
      const { q, category, chain, limit: limitParam } = request.query
      const limit = Math.min(Number(limitParam ?? 20), 100)

      let query = `
        SELECT DISTINCT c.agent_id, c.chain, c.capability, c.category, c.confidence,
               a.security_score, a.wallet
        FROM agent_capabilities c
        LEFT JOIN erc8004_agents a ON c.agent_id = a.agent_id AND c.chain = a.chain
      `
      const conditions: string[] = []
      if (q) conditions.push(`c.capability ILIKE '%${q}%'`)
      if (category) conditions.push(`c.category = '${category}'`)
      if (chain) conditions.push(`c.chain = '${chain}'`)
      if (conditions.length > 0) query += ` WHERE ${conditions.join(' AND ')}`
      query += ` ORDER BY c.confidence DESC, a.security_score DESC NULLS LAST LIMIT ${limit}`

      const result = await db.execute(sql.raw(query))

      return reply.send({
        results: (result as any[]).map(r => ({
          agentId: r.agent_id, chain: r.chain,
          capability: r.capability, category: r.category,
          confidence: Number(r.confidence),
          securityScore: r.security_score,
          wallet: r.wallet,
        })),
      })
    },
  )

  // POST /v1/whitelist — add to whitelist
  app.post<{
    Body: { ownerId?: string; agentId: string; chain: string; level?: string; reason?: string }
  }>('/v1/whitelist', async (request, reply) => {
    const { ownerId, agentId, chain, level, reason } = request.body
    await db.execute(sql.raw(
      `INSERT INTO agent_whitelist (owner_id, agent_id, chain, level, reason)
       VALUES (${ownerId ? `'${ownerId}'` : 'NULL'}, '${agentId}', '${chain}', '${level ?? 'user'}', '${(reason ?? '').replace(/'/g, "''")}')
       ON CONFLICT (owner_id, agent_id, chain) DO UPDATE SET reason = EXCLUDED.reason`
    ))
    return reply.send({ success: true })
  })

  // GET /v1/whitelist?ownerId=xxx
  app.get<{ Querystring: { ownerId?: string } }>(
    '/v1/whitelist',
    async (request, reply) => {
      const { ownerId } = request.query
      let query = `SELECT * FROM agent_whitelist`
      if (ownerId) query += ` WHERE owner_id = '${ownerId}' OR level = 'system'`
      else query += ` WHERE level = 'system'`
      query += ` ORDER BY added_at DESC`

      const result = await db.execute(sql.raw(query))
      return reply.send({
        whitelist: (result as any[]).map(r => ({
          id: r.id, agentId: r.agent_id, chain: r.chain,
          level: r.level, reason: r.reason, addedAt: r.added_at,
        })),
      })
    },
  )

  // DELETE /v1/whitelist/:id
  app.delete<{ Params: { id: string } }>(
    '/v1/whitelist/:id',
    async (request, reply) => {
      await db.execute(sql.raw(`DELETE FROM agent_whitelist WHERE id = ${request.params.id}`))
      return reply.send({ success: true })
    },
  )

  // POST /v1/capabilities/index/:chain/:id — manually trigger indexing
  app.post<{ Params: { chain: string; id: string } }>(
    '/v1/capabilities/index/:chain/:id',
    async (request, reply) => {
      const { chain, id } = request.params
      // Get URI
      const rows = await db.execute(sql.raw(
        `SELECT uri FROM erc8004_agents WHERE agent_id = '${id}' AND chain = '${chain}' LIMIT 1`
      ))
      const uri = (rows as any[])[0]?.uri ?? null
      const result = await indexAgentCapabilities(id, chain, uri)
      return reply.send({ success: true, ...result })
    },
  )

  // GET /v1/capabilities/stats
  app.get('/v1/capabilities/stats', async (_request, reply) => {
    const capCount = await db.execute(sql.raw(`SELECT COUNT(*) as cnt FROM agent_capabilities`))
    const epCount = await db.execute(sql.raw(`SELECT COUNT(*) as cnt FROM agent_endpoints`))
    const catCount = await db.execute(sql.raw(
      `SELECT category, COUNT(*) as cnt FROM agent_capabilities GROUP BY category ORDER BY cnt DESC`
    ))

    return reply.send({
      totalCapabilities: Number((capCount as any[])[0]?.cnt ?? 0),
      totalEndpoints: Number((epCount as any[])[0]?.cnt ?? 0),
      byCategory: (catCount as any[]).map(r => ({ category: r.category, count: Number(r.cnt) })),
      indexer: getIndexerStats(),
    })
  })
}
