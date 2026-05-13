/**
 * API Key validation hook for Fastify
 *
 * Checks X-API-Key header against the owners table (SHA-256 hashed).
 * Attaches authenticated owner to request for downstream use.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify'
import { eq } from 'drizzle-orm'
import { db, owners } from '../db/index.js'
import { hashApiKey } from './hash.js'

// Routes that don't require authentication
const PUBLIC_ROUTES = [
  '/health',
  '/v1/auth/register',
  '/v1/auth/login',
  '/v1/monitor/',         // monitor is public (read-only agent data)
  '/v1/security/',        // security guides are public
  '/v1/x402/',            // x402 demo endpoints
]

function isPublicRoute(url: string): boolean {
  return PUBLIC_ROUTES.some(r => url === r || url.startsWith(r))
}

export interface AuthenticatedRequest extends FastifyRequest {
  owner: { id: string; email: string | null; apiKeyPrefix: string | null }
}

export async function registerAuthHook(app: FastifyInstance) {
  app.addHook('preHandler', async (request, reply) => {
    // Skip public routes
    if (isPublicRoute(request.url)) return

    // Session key auth is handled inside authorize endpoint
    if (request.headers['x-session-key']) return

    const apiKey = request.headers['x-api-key'] as string | undefined
    if (!apiKey) {
      return reply.status(401).send({ error: 'Missing X-API-Key header' })
    }

    const hashedKey = hashApiKey(apiKey)
    const owner = await db.query.owners.findFirst({
      where: eq(owners.apiKey, hashedKey),
    })

    if (!owner) {
      return reply.status(401).send({ error: 'Invalid API key' })
    }

    // Attach owner to request for downstream use
    ;(request as any).owner = { id: owner.id, email: owner.email, apiKeyPrefix: owner.apiKeyPrefix }
  })
}
