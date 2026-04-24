/**
 * POST /v1/authorize
 *
 * Core authorization endpoint. Accepts a transaction from any agent,
 * evaluates it against the agent's policy, and returns allow | deny | ask_user.
 */

import type { FastifyInstance } from 'fastify'
import { z } from 'zod'
import { eq, and, gte, sql } from 'drizzle-orm'
import { nanoid } from 'nanoid'
import { db, agents, policies, authRequests, auditLogs, knownMerchants, owners } from '../db/index.js'
import { evaluatePolicy } from '../lib/policy-engine.js'
import { runSecurityChecks, applySecurityOverride } from '../lib/security-checks.js'
import { parseSolanaTransaction } from '../adapters/solana.js'
import { parseEVMTransaction } from '../adapters/evm.js'
import { sendApprovalRequest } from '../services/notify.js'
import { executeSolanaTransfer } from '../services/solana-transfer.js'
import { executeArcTransfer } from '../services/arc-transfer.js'
import type { NormalizedTransaction, PolicyRules, AuthorizeResponse } from '../types/index.js'

// ── Validation Schema ──────────────────────────────────────────────────────────

const TransactionSchema = z.object({
  type: z.enum(['transfer', 'swap', 'contract_call', 'approve', 'other']).optional(),
  from: z.string().optional(),
  to: z.string(),
  amount: z.string(),
  token: z.string().default('USDC'),
  tokenAddress: z.string().optional(),
  metadata: z
    .object({
      purpose: z.string().optional(),
      merchant: z.string().optional(),
      merchantAddress: z.string().optional(),
      category: z.string().optional(),
      isRecurring: z.boolean().optional(),
      isNewMerchant: z.boolean().optional(),
      notes: z.string().optional(),
    })
    .optional(),
  // EVM-specific (optional)
  value: z.string().optional(),
  data: z.string().optional(),
  contractAddress: z.string().optional(),
})

const AuthorizeBodySchema = z.object({
  agentId: z.string().uuid(),
  chain: z.enum(['solana', 'solana-devnet', 'ethereum', 'base', 'polygon', 'arbitrum', 'arc-testnet']),
  transaction: TransactionSchema,
})

// ── Route ──────────────────────────────────────────────────────────────────────

export async function authorizeRoutes(app: FastifyInstance) {
  app.post<{ Body: z.infer<typeof AuthorizeBodySchema> }>(
    '/v1/authorize',
    {},
    async (request, reply) => {
      // 0. Authenticate — Session Key or API Key
      const sessionKey = request.headers['x-session-key'] as string | undefined
      const apiKey = request.headers['x-api-key'] as string | undefined
      let sessionContext: { sessionId: string; agentId: string; ownerId: string; x402MaxPerCall?: number } | null = null

      if (sessionKey) {
        // Session Key auth — auto-resolves agent + session
        const sessionRow = await db.execute(
          sql.raw(`SELECT id, agent_id, owner_id, status, expires_at, x402_max_per_call FROM spending_sessions WHERE session_key = '${sessionKey}' LIMIT 1`)
        )
        const sess = (sessionRow as any[])[0]
        if (!sess) return reply.status(401).send({ error: 'Invalid session key' })
        if (sess.status !== 'active') return reply.status(403).send({ error: 'Session is not active' })
        if (new Date(sess.expires_at) < new Date()) return reply.status(403).send({ error: 'Session expired' })
        sessionContext = { sessionId: sess.id, agentId: sess.agent_id, ownerId: sess.owner_id, x402MaxPerCall: Number(sess.x402_max_per_call ?? 1) }
      } else if (apiKey) {
        const keyOwner = await db.query.owners.findFirst({ where: eq(owners.apiKey, apiKey) })
        if (!keyOwner) return reply.status(401).send({ error: 'Invalid API key' })
      } else {
        return reply.status(401).send({ error: 'x-session-key or x-api-key header required' })
      }

      // 1. Validate input
      const body = request.body as any
      // If session key auth, agentId is auto-filled from session
      if (sessionContext && !body.agentId) {
        body.agentId = sessionContext.agentId
      }
      const parseResult = AuthorizeBodySchema.safeParse(body)
      if (!parseResult.success) {
        return reply.status(400).send({ error: 'Invalid request', details: parseResult.error.flatten() })
      }
      const { agentId, chain, transaction } = parseResult.data

      // 2. Load agent + policy
      const agent = await db.query.agents.findFirst({
        where: and(eq(agents.id, agentId), eq(agents.status, 'active')),
      })
      if (!agent) return reply.status(404).send({ error: 'Agent not found or inactive' })

      const policy = agent.policyId
        ? await db.query.policies.findFirst({ where: eq(policies.id, agent.policyId) })
        : null

      // 3. Load owner for notifications
      const owner = await db.query.owners.findFirst({ where: eq(owners.id, agent.ownerId) })
      if (!owner) return reply.status(500).send({ error: 'Owner not found' })

      // 4. Reset budget counters if needed
      await resetBudgetIfNeeded(agent)
      const freshAgent = await db.query.agents.findFirst({ where: eq(agents.id, agentId) })!

      // 5. Parse transaction into normalized format
      let normalized: NormalizedTransaction
      const isSolana = chain === 'solana' || chain === 'solana-devnet'

      if (isSolana) {
        normalized = parseSolanaTransaction(
          {
            from: transaction.from,
            to: transaction.to,
            amount: transaction.amount,
            token: transaction.token,
            metadata: transaction.metadata,
            rawTxData: transaction,
          },
          chain,
        )
      } else {
        normalized = parseEVMTransaction({
          from: transaction.from,
          to: transaction.to,
          value: transaction.amount,
          data: transaction.data,
          contractAddress: transaction.contractAddress,
          chain,
          metadata: transaction.metadata,
          rawTxData: transaction,
        })
      }

      // 6. Check if merchant is new
      const merchantIdentifier = normalized.metadata.merchant ?? normalized.toAddress
      const knownMerchant = await db.query.knownMerchants.findFirst({
        where: and(
          eq(knownMerchants.agentId, agentId),
          eq(knownMerchants.identifier, merchantIdentifier),
        ),
      })
      normalized.metadata.isNewMerchant = !knownMerchant

      // 7. Build policy rules (defaults if no policy set)
      const rules: PolicyRules = policy
        ? {
            autoApproveBelowUsdc: policy.autoApproveBelowUsdc ? Number(policy.autoApproveBelowUsdc) : undefined,
            requireApprovalAboveUsdc: policy.requireApprovalAboveUsdc ? Number(policy.requireApprovalAboveUsdc) : undefined,
            dailyLimitUsdc: policy.dailyLimitUsdc ? Number(policy.dailyLimitUsdc) : undefined,
            monthlyLimitUsdc: policy.monthlyLimitUsdc ? Number(policy.monthlyLimitUsdc) : undefined,
            allowRecurring: policy.allowRecurring,
            allowAutoPurchase: policy.allowAutoPurchase,
            requireConfirmationNewMerchant: policy.requireConfirmationNewMerchant,
            allowedCategories: (policy.allowedCategories as string[]) ?? [],
            blockedCategories: (policy.blockedCategories as string[]) ?? [],
            merchantAllowlist: (policy.merchantAllowlist as string[]) ?? [],
            merchantBlocklist: (policy.merchantBlocklist as string[]) ?? [],
            tokenAllowlist: (policy.tokenAllowlist as string[]) ?? [],
            timeoutSeconds: policy.timeoutSeconds,
            timeoutAction: policy.timeoutAction,
          }
        : {
            // No policy = ask user for everything (safe default)
            allowRecurring: true,
            allowAutoPurchase: false,
            requireConfirmationNewMerchant: true,
            allowedCategories: [],
            blockedCategories: [],
            merchantAllowlist: [],
            merchantBlocklist: [],
            tokenAllowlist: [],
            timeoutSeconds: 300,
            timeoutAction: 'deny',
          }

      // 8. Run policy engine
      const authDecision = evaluatePolicy(
        normalized,
        rules,
        {
          dailySpentUsdc: Number(freshAgent!.dailySpentUsdc),
          monthlySpentUsdc: Number(freshAgent!.monthlySpentUsdc),
        },
      )

      // 8b-pre. x402 amount sanity check
      const purposeText = normalized.metadata.purpose ?? ''
      if (purposeText.includes('x402') || purposeText.includes('402')) {
        const x402Max = sessionContext?.x402MaxPerCall ?? 10
        if (normalized.amountUsdc > x402Max) {
          const finalDecision = { decision: 'deny' as const, reason: `x402 payment $${normalized.amountUsdc.toFixed(2)} exceeds per-call limit $${x402Max}`, ruleTriggered: 'x402_amount_exceeded' }
          // Fast path — skip remaining checks
          const requestId = `req_${nanoid(16)}`
          const now = new Date()
          await db.insert(authRequests).values({
            id: requestId, agentId, ownerId: agent.ownerId, chain: chain as any,
            txType: 'transfer' as any, toAddress: normalized.toAddress,
            amountRaw: normalized.amountRaw, amountUsdc: normalized.amountUsdc.toString(),
            token: normalized.token, txMetadata: normalized.metadata,
            decision: 'deny' as any, reason: finalDecision.reason, ruleTriggered: finalDecision.ruleTriggered,
            resolvedBy: 'auto' as any, resolvedAt: now,
            sourceType: 'x402', resourceUrl: purposeText.match(/https?:\/\/[^\s]+/)?.[0] ?? null,
            sessionId: sessionContext?.sessionId ?? null,
          } as any)
          return reply.send({ decision: 'deny', requestId, reason: finalDecision.reason, ruleTriggered: finalDecision.ruleTriggered })
        }
      }

      // 8b. Run security checks (prompt injection, address blacklist, anomaly, sessions)
      const security = await runSecurityChecks(
        agentId,
        normalized,
        rules.dailyLimitUsdc,
      )

      // Security layer can only make the decision more conservative (never more permissive)
      const securityOverride = applySecurityOverride(security, authDecision.decision)
      const finalDecision = securityOverride?.shouldOverride
        ? { decision: securityOverride.newDecision, reason: securityOverride.reason, ruleTriggered: securityOverride.ruleTriggered }
        : authDecision

      // 9. Create request record
      const requestId = `req_${nanoid(16)}`
      const now = new Date()
      const expiresAt = finalDecision.decision === 'ask_user'
        ? new Date(now.getTime() + rules.timeoutSeconds * 1000)
        : null

      // Detect x402 context from metadata
      const isX402 = !!(normalized.metadata.purpose?.includes('x402') || normalized.metadata.purpose?.includes('402'))
      const resourceUrl = normalized.metadata.purpose?.match(/https?:\/\/[^\s]+/)?.[0] ?? null
      const sourceType = isX402 ? 'x402' : 'direct'

      await db.insert(authRequests).values({
        id: requestId,
        agentId,
        ownerId: agent.ownerId,
        chain: chain as any,
        txType: (normalized.txType ?? 'transfer') as any,
        fromAddress: normalized.fromAddress,
        toAddress: normalized.toAddress,
        amountRaw: normalized.amountRaw,
        amountUsdc: normalized.amountUsdc.toString(),
        token: normalized.token,
        tokenAddress: normalized.tokenAddress,
        txMetadata: normalized.metadata,
        rawTxData: normalized.rawTxData as any,
        decision: finalDecision.decision === 'ask_user' ? 'ask_user' : finalDecision.decision as any,
        reason: finalDecision.reason,
        ruleTriggered: finalDecision.ruleTriggered,
        resolvedBy: finalDecision.decision !== 'ask_user' ? 'auto' : undefined,
        resolvedAt: finalDecision.decision !== 'ask_user' ? now : undefined,
        expiresAt,
        securityContext: {
          ...security,
          overrideApplied: securityOverride?.shouldOverride ?? false,
          originalPolicyDecision: securityOverride?.shouldOverride ? authDecision.decision : undefined,
          isX402,
          sourceType,
        } as any,
        resourceUrl,
        sessionId: sessionContext?.sessionId ?? null,
        sourceType,
      } as any)

      // Update session call counter
      if (sessionContext) {
        await db.execute(sql.raw(
          `UPDATE spending_sessions SET total_calls = total_calls + 1${finalDecision.decision === 'deny' ? ', total_denied = total_denied + 1' : ''} WHERE id = '${sessionContext.sessionId}'`
        )).catch(() => {})
      }

      // 10. Audit log
      await db.insert(auditLogs).values({
        requestId,
        agentId,
        ownerId: agent.ownerId,
        event: 'decision_made',
        data: {
          decision: finalDecision.decision,
          reason: finalDecision.reason,
          rule: finalDecision.ruleTriggered,
          securityOverride: securityOverride?.shouldOverride ?? false,
          overallRiskLevel: security.overallRiskLevel,
        },
      })

      // 10b. Log security alert if override was applied
      if (securityOverride?.shouldOverride) {
        await db.insert(auditLogs).values({
          requestId,
          agentId,
          ownerId: agent.ownerId,
          event: 'security_override',
          data: {
            ruleTriggered: securityOverride.ruleTriggered,
            injectionRisk: security.injectionRisk,
            injectionSignals: security.injectionSignals,
            addressRisk: security.addressRisk,
            addressFlags: security.addressFlags,
            anomalyScore: security.anomalyScore,
            anomalyFlags: security.anomalyFlags,
            sessionAnomalyScore: security.sessionAnomalyScore,
            originalDecision: authDecision.decision,
            newDecision: securityOverride.newDecision,
          },
        })
      }

      // 11. If allow, record merchant + update budget
      if (finalDecision.decision === 'allow') {
        if (!knownMerchant) {
          await db.insert(knownMerchants).values({ agentId, identifier: merchantIdentifier }).catch(() => {})
        }
        await updateBudget(agentId, normalized.amountUsdc)
      }

      // 12. If ask_user, send notifications
      if (finalDecision.decision === 'ask_user') {
        const approvalUrl = `${process.env.APP_URL ?? 'http://localhost:3000'}/approve/${requestId}`
        sendApprovalRequest(
          {
            telegramChatId: owner.telegramChatId,
            email: owner.email,
            slackWebhookUrl: owner.slackWebhookUrl,
          },
          {
            requestId,
            agentName: agent.name,
            tx: normalized,
            reason: finalDecision.reason,
            approvalUrl,
            expiresAt: expiresAt!,
          },
        ).catch(console.error)

        scheduleTimeout(requestId, rules.timeoutSeconds, rules.timeoutAction, agentId, agent.ownerId, normalized.amountUsdc)

        const response: AuthorizeResponse = {
          decision: 'ask_user',
          requestId,
          reason: finalDecision.reason,
          ruleTriggered: finalDecision.ruleTriggered,
          expiresAt: expiresAt!.toISOString(),
          approvalUrl: `${process.env.APP_URL ?? 'http://localhost:3000'}/approve/${requestId}`,
          timeoutAction: rules.timeoutAction,
        }
        return reply.status(202).send(response)
      }

      const response: AuthorizeResponse = {
        decision: finalDecision.decision,
        requestId,
        reason: finalDecision.reason,
        ruleTriggered: finalDecision.ruleTriggered,
      }
      return reply.status(200).send(response)
    },
  )

  // ── GET /v1/requests/:id ───────────────────────────────────────────────────

  app.get<{ Params: { id: string } }>(
    '/v1/requests/:id',
    {},
    async (request, reply) => {
      const req = await db.query.authRequests.findFirst({
        where: eq(authRequests.id, request.params.id),
      })
      if (!req) return reply.status(404).send({ error: 'Request not found' })
      return reply.send(req)
    },
  )

  // ── POST /v1/requests/:id/resolve (manual approval) ───────────────────────

  app.post<{ Params: { id: string }; Body: { action: 'approve' | 'deny' } }>(
    '/v1/requests/:id/resolve',
    {},
    async (request, reply) => {
      const { action } = request.body
      if (!['approve', 'deny'].includes(action)) {
        return reply.status(400).send({ error: 'action must be approve or deny' })
      }

      const req = await db.query.authRequests.findFirst({
        where: eq(authRequests.id, request.params.id),
      })
      if (!req) return reply.status(404).send({ error: 'Request not found' })
      if (req.decision !== 'ask_user') {
        return reply.status(409).send({ error: 'Request already resolved', decision: req.decision })
      }
      if (req.expiresAt && new Date() > req.expiresAt) {
        return reply.status(410).send({ error: 'Request expired' })
      }

      const newDecision = action === 'approve' ? 'allow' : 'deny'
      const now = new Date()

      await db
        .update(authRequests)
        .set({ decision: newDecision as any, resolvedBy: 'human', resolvedAt: now })
        .where(eq(authRequests.id, request.params.id))

      await db.insert(auditLogs).values({
        requestId: request.params.id,
        agentId: req.agentId,
        ownerId: req.ownerId,
        event: action === 'approve' ? 'human_approved' : 'human_denied',
        data: { action },
      })

      if (action === 'approve' && req.amountUsdc) {
        await updateBudget(req.agentId, Number(req.amountUsdc))
        // Add merchant to known list
        const merchantId = (req.txMetadata as any)?.merchant ?? req.toAddress
        if (merchantId) {
          await db.insert(knownMerchants).values({ agentId: req.agentId, identifier: merchantId }).catch(() => {})
        }
      }

      // Deliver webhook to agent if configured
      deliverWebhook(req.agentId, request.params.id, newDecision).catch(console.error)

      return reply.send({ decision: newDecision, requestId: request.params.id })
    },
  )

  // ── POST /v1/requests/:id/execute (execute real on-chain transfer) ─────────

  app.post<{ Params: { id: string } }>(
    '/v1/requests/:id/execute',
    {},
    async (request, reply) => {
      const req = await db.query.authRequests.findFirst({
        where: eq(authRequests.id, request.params.id),
      })
      if (!req) return reply.status(404).send({ error: 'Request not found' })
      if (req.decision !== 'allow') {
        return reply.status(409).send({ error: 'Request not authorized for execution', decision: req.decision })
      }

      // Idempotent — return cached result if already executed
      if (req.txSignature) {
        return reply.send({
          signature: req.txSignature,
          explorerUrl: req.txExplorerUrl,
          cached: true,
        })
      }

      try {
        const isArc = req.chain === 'arc-testnet'
        const isSolana = req.chain === 'solana' || req.chain === 'solana-devnet'

        let result: { signature: string; explorerUrl: string; fromAddress: string; toAddress: string; amountUsdc: number; network: string; [k: string]: unknown }

        if (isArc) {
          result = await executeArcTransfer({
            toAddress: req.toAddress,
            amountUsdc: Number(req.amountUsdc ?? 0),
          })
        } else if (isSolana) {
          result = await executeSolanaTransfer({
            toAddress: req.toAddress,
            amountUsdc: Number(req.amountUsdc ?? 0),
          })
        } else {
          return reply.status(501).send({ error: `On-chain execution not yet supported for chain: ${req.chain}` })
        }

        await db
          .update(authRequests)
          .set({ txSignature: result.signature, txExplorerUrl: result.explorerUrl })
          .where(eq(authRequests.id, request.params.id))

        await db.insert(auditLogs).values({
          requestId: req.id,
          agentId: req.agentId,
          ownerId: req.ownerId,
          event: 'tx_executed',
          data: {
            signature: result.signature,
            explorerUrl: result.explorerUrl,
            fromAddress: result.fromAddress,
            toAddress: result.toAddress,
            amountUsdc: result.amountUsdc,
            network: result.network,
          },
        })

        return reply.send({
          signature: result.signature,
          explorerUrl: result.explorerUrl,
          fromAddress: result.fromAddress,
          toAddress: result.toAddress,
          amountUsdc: result.amountUsdc,
          network: result.network,
        })
      } catch (err: any) {
        return reply.status(500).send({ error: 'Transfer failed', message: err?.message ?? 'Unknown error' })
      }
    },
  )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function updateBudget(agentId: string, amountUsdc: number) {
  const agent = await db.query.agents.findFirst({ where: eq(agents.id, agentId) })
  if (!agent) return
  await db
    .update(agents)
    .set({
      dailySpentUsdc: (Number(agent.dailySpentUsdc) + amountUsdc).toString(),
      monthlySpentUsdc: (Number(agent.monthlySpentUsdc) + amountUsdc).toString(),
    })
    .where(eq(agents.id, agentId))
}

async function resetBudgetIfNeeded(agent: typeof agents.$inferSelect) {
  const now = new Date()
  const updates: Partial<typeof agents.$inferInsert> = {}

  if (now >= new Date(agent.dailyResetAt)) {
    updates.dailySpentUsdc = '0'
    const nextReset = new Date(now)
    nextReset.setDate(nextReset.getDate() + 1)
    nextReset.setHours(0, 0, 0, 0)
    updates.dailyResetAt = nextReset
  }

  if (now >= new Date(agent.monthlyResetAt)) {
    updates.monthlySpentUsdc = '0'
    const nextReset = new Date(now)
    nextReset.setMonth(nextReset.getMonth() + 1)
    nextReset.setDate(1)
    nextReset.setHours(0, 0, 0, 0)
    updates.monthlyResetAt = nextReset
  }

  if (Object.keys(updates).length > 0) {
    await db.update(agents).set(updates as any).where(eq(agents.id, agent.id))
  }
}

function scheduleTimeout(
  requestId: string,
  seconds: number,
  action: 'allow' | 'deny',
  agentId: string,
  ownerId: string,
  amountUsdc: number,
) {
  setTimeout(async () => {
    const req = await db.query.authRequests.findFirst({
      where: eq(authRequests.id, requestId),
    })
    if (!req || req.decision !== 'ask_user') return

    await db
      .update(authRequests)
      .set({ decision: action as any, resolvedBy: 'timeout', resolvedAt: new Date() })
      .where(eq(authRequests.id, requestId))

    await db.insert(auditLogs).values({
      requestId,
      agentId,
      ownerId,
      event: 'timeout',
      data: { action, seconds },
    })

    if (action === 'allow') {
      await updateBudget(agentId, amountUsdc)
    }

    deliverWebhook(agentId, requestId, action).catch(console.error)
  }, seconds * 1000)
}

async function deliverWebhook(agentId: string, requestId: string, decision: string) {
  const agent = await db.query.agents.findFirst({ where: eq(agents.id, agentId) })
  if (!agent?.webhookUrl) return

  await fetch(agent.webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ requestId, decision, agentId, timestamp: new Date().toISOString() }),
  })

  await db
    .update(authRequests)
    .set({ webhookDelivered: true })
    .where(eq(authRequests.id, requestId))
}
