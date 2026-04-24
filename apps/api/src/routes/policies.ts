/**
 * Policy Routes
 * GET/POST/PATCH /v1/policies
 * POST /v1/policies/parse  (NLP → structured)
 */

import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { eq, and } from 'drizzle-orm'
import { db, policies, agents, owners } from '../db/index.js'
import { parsePolicy } from '../services/nlp.js'
import { syncPolicyToChain, verifyPolicyOnChain, policyToRules } from '../services/chain.js'

const PolicyRulesSchema = z.object({
  autoApproveBelowUsdc: z.number().nonnegative().optional(),
  requireApprovalAboveUsdc: z.number().nonnegative().optional(),
  dailyLimitUsdc: z.number().positive().optional(),
  monthlyLimitUsdc: z.number().positive().optional(),
  allowRecurring: z.boolean().optional(),
  allowAutoPurchase: z.boolean().optional(),
  requireConfirmationNewMerchant: z.boolean().optional(),
  allowedCategories: z.array(z.string()).optional(),
  blockedCategories: z.array(z.string()).optional(),
  merchantAllowlist: z.array(z.string()).optional(),
  merchantBlocklist: z.array(z.string()).optional(),
  tokenAllowlist: z.array(z.string()).optional(),
  timeoutSeconds: z.number().int().min(30).max(86400).optional(),
  timeoutAction: z.enum(['allow', 'deny']).optional(),
})

export async function policyRoutes(app: FastifyInstance) {
  // POST /v1/policies/parse — NLP to structured
  app.post<{ Body: { text: string; agentId?: string } }>(
    '/v1/policies/parse',
    async (request, reply) => {
      const { text, agentId } = request.body
      if (!text || text.trim().length < 3) {
        return reply.status(400).send({ error: 'text is required' })
      }

      // Load current policy for context
      let currentPolicy = undefined
      if (agentId) {
        const agent = await db.query.agents.findFirst({ where: eq(agents.id, agentId) })
        if (agent?.policyId) {
          currentPolicy = await db.query.policies.findFirst({ where: eq(policies.id, agent.policyId) })
        }
      }

      const currentPolicyForNlp = currentPolicy
        ? {
            autoApproveBelowUsdc: currentPolicy.autoApproveBelowUsdc ? Number(currentPolicy.autoApproveBelowUsdc) : undefined,
            requireApprovalAboveUsdc: currentPolicy.requireApprovalAboveUsdc ? Number(currentPolicy.requireApprovalAboveUsdc) : undefined,
            dailyLimitUsdc: currentPolicy.dailyLimitUsdc ? Number(currentPolicy.dailyLimitUsdc) : undefined,
            monthlyLimitUsdc: currentPolicy.monthlyLimitUsdc ? Number(currentPolicy.monthlyLimitUsdc) : undefined,
          }
        : undefined
      const result = await parsePolicy(text, currentPolicyForNlp)

      if (result.ambiguous.length > 0) {
        return reply.status(422).send({
          error: 'Ambiguous input — please clarify',
          ambiguous: result.ambiguous,
          confirmationMessage: result.confirmationMessage,
          partialParsed: result.parsed,
        })
      }

      return reply.send(result)
    },
  )

  // POST /v1/policies — create policy for an agent
  app.post<{ Body: z.infer<typeof PolicyRulesSchema> & { agentId: string; rawText?: string } }>(
    '/v1/policies',
    async (request, reply) => {
      const { agentId, rawText, ...rules } = request.body

      const agent = await db.query.agents.findFirst({ where: eq(agents.id, agentId) })
      if (!agent) return reply.status(404).send({ error: 'Agent not found' })

      const [created] = await db
        .insert(policies)
        .values({
          ownerId: agent.ownerId,
          rawText,
          autoApproveBelowUsdc: rules.autoApproveBelowUsdc?.toString(),
          requireApprovalAboveUsdc: rules.requireApprovalAboveUsdc?.toString(),
          dailyLimitUsdc: rules.dailyLimitUsdc?.toString(),
          monthlyLimitUsdc: rules.monthlyLimitUsdc?.toString(),
          allowRecurring: rules.allowRecurring ?? true,
          allowAutoPurchase: rules.allowAutoPurchase ?? false,
          requireConfirmationNewMerchant: rules.requireConfirmationNewMerchant ?? false,
          allowedCategories: rules.allowedCategories ?? [],
          blockedCategories: rules.blockedCategories ?? [],
          merchantAllowlist: rules.merchantAllowlist ?? [],
          merchantBlocklist: rules.merchantBlocklist ?? [],
          tokenAllowlist: rules.tokenAllowlist ?? [],
          timeoutSeconds: rules.timeoutSeconds ?? 300,
          timeoutAction: rules.timeoutAction ?? 'deny',
        })
        .returning()

      // Link policy to agent
      await db.update(agents).set({ policyId: created.id }).where(eq(agents.id, agentId))

      // Sync policy hash to Solana and update DB with hash
      const rulesForChainCreate = policyToRules(created)
      syncPolicyToChain({ agentId, rules: rulesForChainCreate }).then(async (chainResult) => {
        if (chainResult) {
          await db.update(policies).set({ onChainHash: chainResult.hash }).where(eq(policies.id, created.id))
          app.log.info(`[chain] Policy ${created.id} synced: ${chainResult.explorerUrl}`)
        }
      }).catch(() => {})

      return reply.status(201).send(created)
    },
  )

  // GET /v1/policies/:agentId — get agent's policy
  app.get<{ Params: { agentId: string } }>(
    '/v1/policies/:agentId',
    async (request, reply) => {
      const agent = await db.query.agents.findFirst({ where: eq(agents.id, request.params.agentId) })
      if (!agent) return reply.status(404).send({ error: 'Agent not found' })
      if (!agent.policyId) return reply.status(404).send({ error: 'No policy set for this agent' })

      const policy = await db.query.policies.findFirst({ where: eq(policies.id, agent.policyId) })
      return reply.send(policy)
    },
  )

  // GET /v1/policies/:agentId/verify — check on-chain verification
  app.get<{ Params: { agentId: string } }>(
    '/v1/policies/:agentId/verify',
    async (request, reply) => {
      const agent = await db.query.agents.findFirst({ where: eq(agents.id, request.params.agentId) })
      if (!agent?.policyId) return reply.status(404).send({ error: 'No policy found' })

      const policy = await db.query.policies.findFirst({ where: eq(policies.id, agent.policyId) })
      if (!policy) return reply.status(404).send({ error: 'Policy not found' })

      const rules = policyToRules(policy)

      // Use the signing wallet's pubkey as owner (same key that saved the policy)
      const { getPolicyRegistryClient } = await import('@agent-guard/solana').catch(() => ({ getPolicyRegistryClient: null as any }))
      if (!getPolicyRegistryClient) {
        return reply.send({ verified: false, reason: 'Solana not configured', onChainHash: policy.onChainHash })
      }
      const client = getPolicyRegistryClient()
      const ownerPubkey = (client as any).wallet.publicKey.toBase58()

      const result = await verifyPolicyOnChain(ownerPubkey, agent.id, rules)
      // Get PDA for explorer URL
      const pda = await client.getPolicy(ownerPubkey, agent.id)
      const explorerUrl = pda
        ? client.getExplorerUrl(
            // compute pda address from client
            (await (client as any).getPolicyPDA(
              (client as any).wallet.publicKey,
              (await import('@agent-guard/solana')).PolicyRegistryClient.uuidToBytes(agent.id),
            ))[0].toBase58(),
            (process.env.SOLANA_NETWORK as 'devnet' | 'mainnet-beta') ?? 'devnet',
          )
        : null
      return reply.send({
        ...result,
        storedHash: policy.onChainHash,
        explorerUrl,
      })
    },
  )

  // PATCH /v1/policies/:policyId — update policy
  app.patch<{ Params: { policyId: string }; Body: z.infer<typeof PolicyRulesSchema> & { rawText?: string } }>(
    '/v1/policies/:policyId',
    async (request, reply) => {
      const { rawText, ...rules } = request.body
      const updates: Record<string, unknown> = { updatedAt: new Date() }

      if (rawText !== undefined) updates.rawText = rawText
      if (rules.autoApproveBelowUsdc !== undefined) updates.autoApproveBelowUsdc = rules.autoApproveBelowUsdc.toString()
      if (rules.requireApprovalAboveUsdc !== undefined) updates.requireApprovalAboveUsdc = rules.requireApprovalAboveUsdc.toString()
      if (rules.dailyLimitUsdc !== undefined) updates.dailyLimitUsdc = rules.dailyLimitUsdc.toString()
      if (rules.monthlyLimitUsdc !== undefined) updates.monthlyLimitUsdc = rules.monthlyLimitUsdc.toString()
      if (rules.allowRecurring !== undefined) updates.allowRecurring = rules.allowRecurring
      if (rules.allowAutoPurchase !== undefined) updates.allowAutoPurchase = rules.allowAutoPurchase
      if (rules.requireConfirmationNewMerchant !== undefined) updates.requireConfirmationNewMerchant = rules.requireConfirmationNewMerchant
      if (rules.allowedCategories !== undefined) updates.allowedCategories = rules.allowedCategories
      if (rules.blockedCategories !== undefined) updates.blockedCategories = rules.blockedCategories
      if (rules.merchantAllowlist !== undefined) updates.merchantAllowlist = rules.merchantAllowlist
      if (rules.merchantBlocklist !== undefined) updates.merchantBlocklist = rules.merchantBlocklist
      if (rules.tokenAllowlist !== undefined) updates.tokenAllowlist = rules.tokenAllowlist
      if (rules.timeoutSeconds !== undefined) updates.timeoutSeconds = rules.timeoutSeconds
      if (rules.timeoutAction !== undefined) updates.timeoutAction = rules.timeoutAction

      const [updated] = await db
        .update(policies)
        .set(updates as any)
        .where(eq(policies.id, request.params.policyId))
        .returning()

      if (!updated) return reply.status(404).send({ error: 'Policy not found' })

      // Sync updated policy hash to Solana (fire-and-forget)
      // Need agentId — look up which agent owns this policy
      const linkedAgent = await db.query.agents.findFirst({ where: eq(agents.policyId, updated.id) })
      if (linkedAgent) {
        const rulesForChainUpdate = policyToRules(updated)
        syncPolicyToChain({ agentId: linkedAgent.id, rules: rulesForChainUpdate }).then(async (chainResult) => {
          if (chainResult) {
            await db.update(policies).set({ onChainHash: chainResult.hash }).where(eq(policies.id, updated.id))
            app.log.info(`[chain] Policy ${updated.id} updated on-chain: ${chainResult.explorerUrl}`)
          }
        }).catch(() => {})
      }

      return reply.send(updated)
    },
  )
}
