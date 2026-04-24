/**
 * API Key validation hook for Fastify
 *
 * Checks X-API-Key header against the owners table.
 * Attach to routes that require authentication.
 */

import type { FastifyInstance } from 'fastify'
import { eq } from 'drizzle-orm'
import { db, owners } from '../db/index.js'

export async function validateApiKey(app: FastifyInstance) {
  app.addHook('preHandler', async (request, reply) => {
    // Skip health check
    if (request.url === '/health') return

    const apiKey = request.headers['x-api-key'] as string | undefined
    if (!apiKey) {
      return reply.status(401).send({ error: 'Missing X-API-Key header' })
    }

    const owner = await db.query.owners.findFirst({
      where: eq(owners.apiKey, apiKey),
    })

    if (!owner) {
      return reply.status(401).send({ error: 'Invalid API key' })
    }

    // Attach owner to request for downstream use
    ;(request as any).owner = owner
  })
}
