/**
 * Agent Skill Review Routes
 *
 * Full SlowMist Agent Security Skill — all 6 review types:
 *   POST /v1/review/skill       — Skill / MCP installation review
 *   POST /v1/review/repository  — GitHub repository review
 *   POST /v1/review/url         — URL / document review
 *   POST /v1/review/product     — Product / service / API review
 *   POST /v1/review/message     — Social message / share review
 *   GET  /v1/review/checklist/:type — Get raw checklist markdown
 */

import type { FastifyInstance } from 'fastify'
import { reviewSkillMcp, reviewRepository, reviewUrl, reviewProduct, reviewMessage } from '../services/skill-reviewer.js'
import { readFileSync } from 'fs'
import { join } from 'path'

export async function reviewRoutes(app: FastifyInstance) {

  // POST /v1/review/skill
  app.post<{ Body: { name: string; source: string; author?: string; repoUrl?: string; hasExecutableCode?: boolean; fileTypes?: string[]; permissions?: string[] } }>(
    '/v1/review/skill',
    async (request, reply) => {
      const result = await reviewSkillMcp(request.body)
      return reply.send(result)
    },
  )

  // POST /v1/review/repository
  app.post<{ Body: { url: string; owner?: string; stars?: number; forks?: number; createdAt?: string; lastCommit?: string; contributors?: number; hasLicense?: boolean; isVerifiedOrg?: boolean } }>(
    '/v1/review/repository',
    async (request, reply) => {
      const result = await reviewRepository(request.body)
      return reply.send(result)
    },
  )

  // POST /v1/review/url
  app.post<{ Body: { url: string; contentType?: string; hasCodeBlocks?: boolean; hasExternalLinks?: boolean; domain?: string } }>(
    '/v1/review/url',
    async (request, reply) => {
      const result = await reviewUrl(request.body)
      return reply.send(result)
    },
  )

  // POST /v1/review/product
  app.post<{ Body: { name: string; type: 'api' | 'sdk' | 'service' | 'platform'; hasAudit?: boolean; auditBy?: string; teamKnown?: boolean; incidentHistory?: boolean; permissionsRequired?: string[] } }>(
    '/v1/review/product',
    async (request, reply) => {
      const result = await reviewProduct(request.body)
      return reply.send(result)
    },
  )

  // POST /v1/review/message
  app.post<{ Body: { content: string; source: 'twitter' | 'discord' | 'telegram' | 'other'; recommends?: string; hasUrl?: boolean; hasCode?: boolean; urgencyLanguage?: boolean } }>(
    '/v1/review/message',
    async (request, reply) => {
      const result = await reviewMessage(request.body)
      return reply.send(result)
    },
  )

  // GET /v1/review/checklist/:type — raw markdown checklist
  app.get<{ Params: { type: string } }>(
    '/v1/review/checklist/:type',
    async (request, reply) => {
      const { type } = request.params
      const paths: Record<string, string> = {
        'skill-mcp': 'reviews/skill-mcp.md',
        'repository': 'reviews/repository.md',
        'url-document': 'reviews/url-document.md',
        'onchain': 'reviews/onchain.md',
        'product-service': 'reviews/product-service.md',
        'message-share': 'reviews/message-share.md',
        'red-flags': 'patterns/red-flags.md',
        'social-engineering': 'patterns/social-engineering.md',
        'supply-chain': 'patterns/supply-chain.md',
      }
      const path = paths[type]
      if (!path) return reply.status(400).send({ error: 'Invalid type', available: Object.keys(paths) })

      try {
        const content = readFileSync(join(process.cwd(), '..', 'packages', 'security-skill', path), 'utf-8')
        return reply.send({ type, path, content, length: content.length })
      } catch {
        return reply.status(404).send({ error: 'Checklist not found' })
      }
    },
  )
}
