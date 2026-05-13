/**
 * Auth Routes — Owner registration and API key management
 *
 * POST /v1/auth/register — create owner, return API key (shown once)
 * GET  /v1/auth/me       — get current owner info (requires API key)
 * POST /v1/auth/rotate   — rotate API key (requires current API key)
 */

import type { FastifyInstance } from 'fastify'
import { eq } from 'drizzle-orm'
import { nanoid } from 'nanoid'
import { db, owners } from '../db/index.js'
import { hashApiKey } from '../lib/hash.js'

export async function authRoutes(app: FastifyInstance) {

  // POST /v1/auth/register — create new owner account
  app.post<{
    Body: { email?: string; telegramChatId?: string; slackWebhookUrl?: string }
  }>('/v1/auth/register', async (request, reply) => {
    const { email, telegramChatId, slackWebhookUrl } = request.body ?? {}

    // Check if email already registered
    if (email) {
      const existing = await db.query.owners.findFirst({ where: eq(owners.email, email) })
      if (existing) return reply.status(409).send({ error: 'Email already registered' })
    }

    // Generate API key
    const rawApiKey = `ag_${nanoid(32)}`
    const hashedKey = hashApiKey(rawApiKey)
    const prefix = rawApiKey.slice(0, 12) + '...'

    const [owner] = await db
      .insert(owners)
      .values({
        email: email ?? null,
        telegramChatId: telegramChatId ?? null,
        slackWebhookUrl: slackWebhookUrl ?? null,
        apiKey: hashedKey,
        apiKeyPrefix: prefix,
      })
      .returning()

    return reply.status(201).send({
      id: owner.id,
      email: owner.email,
      apiKey: rawApiKey,           // shown ONLY once — not stored in plaintext
      apiKeyPrefix: prefix,
      message: 'Save your API key — it will not be shown again.',
    })
  })

  // GET /v1/auth/me — get current owner info
  app.get('/v1/auth/me', async (request, reply) => {
    const owner = (request as any).owner
    if (!owner) return reply.status(401).send({ error: 'Not authenticated' })

    const full = await db.query.owners.findFirst({ where: eq(owners.id, owner.id) })
    if (!full) return reply.status(404).send({ error: 'Owner not found' })

    return reply.send({
      id: full.id,
      email: full.email,
      apiKeyPrefix: full.apiKeyPrefix,
      telegramChatId: full.telegramChatId ? '***configured***' : null,
      slackWebhookUrl: full.slackWebhookUrl ? '***configured***' : null,
      createdAt: full.createdAt,
    })
  })

  // POST /v1/auth/rotate — rotate API key
  app.post('/v1/auth/rotate', async (request, reply) => {
    const owner = (request as any).owner
    if (!owner) return reply.status(401).send({ error: 'Not authenticated' })

    const rawApiKey = `ag_${nanoid(32)}`
    const hashedKey = hashApiKey(rawApiKey)
    const prefix = rawApiKey.slice(0, 12) + '...'

    await db
      .update(owners)
      .set({ apiKey: hashedKey, apiKeyPrefix: prefix })
      .where(eq(owners.id, owner.id))

    return reply.send({
      apiKey: rawApiKey,
      apiKeyPrefix: prefix,
      message: 'API key rotated. Save your new key — it will not be shown again.',
    })
  })
}
