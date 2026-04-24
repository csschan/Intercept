/**
 * Security Routes — bridges the SlowMist Agent Security Skill to HTTP clients
 *
 * The MCP server can read the vendored SlowMist files directly from disk.
 * The browser-based dashboard (and any HTTP client) can't, so we expose the
 * same advisory layer over HTTP.
 *
 * GET /v1/security/review-guide?type=onchain
 *
 * Source: packages/security-skill/ (vendored MIT, see ATTRIBUTION.md there)
 */

import type { FastifyInstance } from 'fastify'
import { readFile } from 'fs/promises'
import { fileURLToPath } from 'url'
import { dirname, resolve } from 'path'

// apps/api/src/routes/security.ts → packages/security-skill/
const __dirname = dirname(fileURLToPath(import.meta.url))
const SKILL_ROOT = resolve(__dirname, '..', '..', '..', '..', 'packages', 'security-skill')

const GUIDES = {
  onchain: 'reviews/onchain.md',
  skill_mcp: 'reviews/skill-mcp.md',
  repository: 'reviews/repository.md',
  url_document: 'reviews/url-document.md',
  product_service: 'reviews/product-service.md',
  message_share: 'reviews/message-share.md',
  red_flags: 'patterns/red-flags.md',
  social_engineering: 'patterns/social-engineering.md',
  supply_chain: 'patterns/supply-chain.md',
  index: 'SKILL.md',
} as const

type GuideType = keyof typeof GUIDES

export async function securityRoutes(app: FastifyInstance) {
  // GET /v1/security/review-guide?type=onchain
  app.get<{ Querystring: { type?: string } }>(
    '/v1/security/review-guide',
    async (request, reply) => {
      const type = (request.query.type ?? 'index') as GuideType
      const relativePath = GUIDES[type]
      if (!relativePath) {
        return reply.status(400).send({
          error: `Unknown review guide type: ${type}`,
          availableTypes: Object.keys(GUIDES),
        })
      }

      try {
        const content = await readFile(resolve(SKILL_ROOT, relativePath), 'utf8')
        return reply.send({
          type,
          source: 'https://github.com/slowmist/slowmist-agent-security',
          license: 'MIT',
          path: relativePath,
          content,
        })
      } catch (err: any) {
        return reply.status(500).send({
          error: 'Failed to read review guide',
          message: err?.message ?? 'Unknown error',
        })
      }
    },
  )

  // GET /v1/security/review-guides — list all available guides
  app.get('/v1/security/review-guides', async (_request, reply) => {
    return reply.send({
      source: 'https://github.com/slowmist/slowmist-agent-security',
      license: 'MIT',
      vendoredAt: 'packages/security-skill',
      guides: Object.entries(GUIDES).map(([type, path]) => ({ type, path })),
    })
  })
}
