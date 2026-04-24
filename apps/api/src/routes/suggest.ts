/**
 * POST /v1/suggest
 *
 * Agent-initiated query: "What CAN I spend?"
 * Returns spending constraints so the agent can plan within budget.
 *
 * This is the key difference from the old REST-only model:
 * Instead of just blocking transactions, we help agents make better decisions.
 */

import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { eq, and } from 'drizzle-orm'
import { db, agents, policies, knownMerchants } from '../db/index.js'

const SuggestBodySchema = z.object({
  agentId: z.string().uuid(),
  /** What the agent wants to do (optional, for smarter suggestions) */
  intent: z.string().optional(),
  /** Desired amount in USDC (optional, to check feasibility) */
  desiredAmountUsdc: z.number().optional(),
  /** Target merchant (optional, to check allowlist/blocklist) */
  merchant: z.string().optional(),
  /** Target category */
  category: z.string().optional(),
})

export async function suggestRoutes(app: FastifyInstance) {
  app.post<{ Body: z.infer<typeof SuggestBodySchema> }>(
    '/v1/suggest',
    {},
    async (request, reply) => {
      const parseResult = SuggestBodySchema.safeParse(request.body)
      if (!parseResult.success) {
        return reply.status(400).send({ error: 'Invalid request', details: parseResult.error.flatten() })
      }
      const { agentId, desiredAmountUsdc, merchant, category } = parseResult.data

      const agent = await db.query.agents.findFirst({
        where: and(eq(agents.id, agentId), eq(agents.status, 'active')),
      })
      if (!agent) return reply.status(404).send({ error: 'Agent not found or inactive' })

      const policy = agent.policyId
        ? await db.query.policies.findFirst({ where: eq(policies.id, agent.policyId) })
        : null

      // Calculate available budget
      const dailySpent = Number(agent.dailySpentUsdc)
      const monthlySpent = Number(agent.monthlySpentUsdc)
      const dailyLimit = policy?.dailyLimitUsdc ? Number(policy.dailyLimitUsdc) : null
      const monthlyLimit = policy?.monthlyLimitUsdc ? Number(policy.monthlyLimitUsdc) : null

      const dailyRemaining = dailyLimit != null ? Math.max(0, dailyLimit - dailySpent) : null
      const monthlyRemaining = monthlyLimit != null ? Math.max(0, monthlyLimit - monthlySpent) : null

      // Effective max = min of all applicable limits
      const limits = [dailyRemaining, monthlyRemaining].filter((v): v is number => v != null)
      const effectiveMax = limits.length > 0 ? Math.min(...limits) : null

      const autoApproveBelow = policy?.autoApproveBelowUsdc ? Number(policy.autoApproveBelowUsdc) : null

      // Check merchant status
      let merchantStatus: 'known' | 'new' | 'blocked' | 'not_in_allowlist' | null = null
      if (merchant) {
        const blocklist = (policy?.merchantBlocklist as string[]) ?? []
        const allowlist = (policy?.merchantAllowlist as string[]) ?? []

        if (blocklist.some(b => b.toLowerCase() === merchant.toLowerCase())) {
          merchantStatus = 'blocked'
        } else if (allowlist.length > 0 && !allowlist.some(a => a.toLowerCase() === merchant.toLowerCase())) {
          merchantStatus = 'not_in_allowlist'
        } else {
          const known = await db.query.knownMerchants.findFirst({
            where: and(eq(knownMerchants.agentId, agentId), eq(knownMerchants.identifier, merchant)),
          })
          merchantStatus = known ? 'known' : 'new'
        }
      }

      // Check category status
      let categoryStatus: 'allowed' | 'blocked' | 'needs_approval' | null = null
      if (category) {
        const blockedCats = (policy?.blockedCategories as string[]) ?? []
        const allowedCats = (policy?.allowedCategories as string[]) ?? []

        if (blockedCats.some(c => c.toLowerCase() === category.toLowerCase())) {
          categoryStatus = 'blocked'
        } else if (allowedCats.length > 0 && !allowedCats.some(c => c.toLowerCase() === category.toLowerCase())) {
          categoryStatus = 'needs_approval'
        } else {
          categoryStatus = 'allowed'
        }
      }

      // Build suggestions
      const suggestions: string[] = []
      const blockers: string[] = []

      if (merchantStatus === 'blocked') {
        blockers.push(`Merchant "${merchant}" is on the blocklist. Choose a different provider.`)
      }
      if (categoryStatus === 'blocked') {
        blockers.push(`Category "${category}" is blocked by policy.`)
      }

      if (desiredAmountUsdc != null) {
        if (effectiveMax != null && desiredAmountUsdc > effectiveMax) {
          suggestions.push(
            `Requested $${desiredAmountUsdc} exceeds available budget ($${effectiveMax.toFixed(2)}). ` +
            `Consider reducing to $${effectiveMax.toFixed(2)} or splitting into smaller transactions.`
          )
        }
        if (autoApproveBelow != null && desiredAmountUsdc > autoApproveBelow) {
          suggestions.push(
            `Amount $${desiredAmountUsdc} exceeds auto-approve threshold ($${autoApproveBelow}). ` +
            `Transactions ≤ $${autoApproveBelow} will be auto-approved. Above that requires human approval.`
          )
        }
      }

      if (merchantStatus === 'new' && policy?.requireConfirmationNewMerchant) {
        suggestions.push(`"${merchant}" is a new merchant — first transaction will require human approval.`)
      }

      if (merchantStatus === 'not_in_allowlist') {
        suggestions.push(`"${merchant}" is not on the approved merchant list — transaction will require human approval.`)
      }

      // Determine if the desired action would be auto-approved
      let wouldAutoApprove = true
      if (blockers.length > 0) wouldAutoApprove = false
      if (merchantStatus === 'new' && policy?.requireConfirmationNewMerchant) wouldAutoApprove = false
      if (merchantStatus === 'not_in_allowlist') wouldAutoApprove = false
      if (desiredAmountUsdc != null) {
        if (effectiveMax != null && desiredAmountUsdc > effectiveMax) wouldAutoApprove = false
        if (autoApproveBelow != null && desiredAmountUsdc > autoApproveBelow) wouldAutoApprove = false
      }

      return reply.send({
        budget: {
          daily: { spent: dailySpent, limit: dailyLimit, remaining: dailyRemaining },
          monthly: { spent: monthlySpent, limit: monthlyLimit, remaining: monthlyRemaining },
          effectiveMaxUsdc: effectiveMax,
          autoApproveBelowUsdc: autoApproveBelow,
        },
        merchant: merchantStatus ? { name: merchant, status: merchantStatus } : undefined,
        category: categoryStatus ? { name: category, status: categoryStatus } : undefined,
        wouldAutoApprove,
        blockers,
        suggestions,
        allowedTokens: (policy?.tokenAllowlist as string[])?.length
          ? policy!.tokenAllowlist
          : 'all',
      })
    },
  )
}
