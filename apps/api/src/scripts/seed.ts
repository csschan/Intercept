/**
 * Demo Seed Script
 *
 * Creates a complete demo dataset: owner + agent + policy + known merchants + sample history.
 * Produces deterministic IDs so the frontend .env can reference them.
 *
 * Run: cd apps/api && npx tsx src/scripts/seed.ts
 */

import 'dotenv/config'
import { db, owners, agents, policies, authRequests, auditLogs, knownMerchants } from '../db/index.js'
import { nanoid } from 'nanoid'
import { eq, or } from 'drizzle-orm'

// Real Solana devnet addresses for demo merchants (well-known program accounts)
const MERCHANT_ADDRESSES: Record<string, string> = {
  OpenAI: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',     // SPL Token Program
  GitHub: 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bDM',    // ATA Program
  AWS: 'ComputeBudget111111111111111111111111111111',            // Compute Budget Program
  Pinecone: 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr',    // Memo Program
  CryptoCasino: 'namesLPsPKB6NQYLJTQcaLUomR6GCiakDoJfRMF5trd', // Name Service (blocked — never executed)
  TokenShop: 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4',   // Jupiter (blocked — never executed)
}

const FIXED_OWNER_ID = '8a29fa32-08c3-43f7-b624-6e4047970eb0'
const FIXED_AGENT_ID = '03c7f8ae-efaf-47ba-8048-1000c76029c7'
const FIXED_API_KEY = 'ag_demo_Fu-gl86lXj40yeMT9YrfAAoIXwl8PzYG'
const DEMO_EMAIL = 'demo@agentguard.io'

async function seed() {
  console.log('🌱 Seeding demo data...\n')

  // ── 1. Owner ──────────────────────────────────────────────────────────────

  // Find any existing owner by ID OR by email (handles both fresh and re-seed cases)
  const existingOwners = await db.query.owners.findMany({
    where: or(eq(owners.id, FIXED_OWNER_ID), eq(owners.email, DEMO_EMAIL)),
  })

  if (existingOwners.length > 0) {
    console.log('⚠️  Existing demo data found. Cleaning up for fresh seed...')
    for (const existing of existingOwners) {
      // Find all agents for this owner
      const ownerAgents = await db.query.agents.findMany({ where: eq(agents.ownerId, existing.id) })
      for (const agent of ownerAgents) {
        await db.delete(knownMerchants).where(eq(knownMerchants.agentId, agent.id)).catch(() => {})
      }
      await db.delete(auditLogs).where(eq(auditLogs.ownerId, existing.id)).catch(() => {})
      await db.delete(authRequests).where(eq(authRequests.ownerId, existing.id)).catch(() => {})
      await db.delete(agents).where(eq(agents.ownerId, existing.id)).catch(() => {})
      await db.delete(policies).where(eq(policies.ownerId, existing.id)).catch(() => {})
      await db.delete(owners).where(eq(owners.id, existing.id)).catch(() => {})
    }
    console.log('   Cleaned.\n')
  }

  await db.insert(owners).values({
    id: FIXED_OWNER_ID,
    email: 'demo@agentguard.io',
    telegramChatId: process.env.TELEGRAM_DEMO_CHAT_ID || null,
    apiKey: FIXED_API_KEY,
  })
  console.log('✅ Owner created')
  console.log(`   ID:      ${FIXED_OWNER_ID}`)
  console.log(`   API Key: ${FIXED_API_KEY}`)
  console.log(`   Email:   demo@agentguard.io\n`)

  // ── 2. Policy ─────────────────────────────────────────────────────────────

  const [policy] = await db.insert(policies).values({
    ownerId: FIXED_OWNER_ID,
    autoApproveBelowUsdc: '5',
    requireApprovalAboveUsdc: '10',
    dailyLimitUsdc: '50',
    monthlyLimitUsdc: '100',
    allowRecurring: false,
    allowAutoPurchase: true,
    requireConfirmationNewMerchant: true,
    allowedCategories: ['api_credits', 'developer_tools', 'saas', 'cloud_compute', 'infrastructure', 'email'],
    blockedCategories: ['gambling', 'adult_content'],
    merchantAllowlist: [],
    merchantBlocklist: ['CryptoCasino', 'SketchyExchange'],
    tokenAllowlist: ['USDC', 'SOL'],
    timeoutSeconds: 300,
    timeoutAction: 'deny',
    rawText: '低于5美元自动通过，超过10美元先问我，每日上限50美元，每月最多100美元，新商家必须确认，不允许自动续费，禁止赌博类支出，只允许USDC和SOL',
  }).returning()

  console.log('✅ Policy created')
  console.log(`   ID: ${policy.id}`)
  console.log('   Rules: auto-approve <$5, ask_user >$10, daily $50, monthly $100')
  console.log('   Blocked: gambling, CryptoCasino, SketchyExchange')
  console.log('   Tokens: USDC, SOL only\n')

  // ── 3. Agent ──────────────────────────────────────────────────────────────

  const tomorrow = new Date()
  tomorrow.setDate(tomorrow.getDate() + 1)
  tomorrow.setHours(0, 0, 0, 0)

  const nextMonth = new Date()
  nextMonth.setMonth(nextMonth.getMonth() + 1)
  nextMonth.setDate(1)
  nextMonth.setHours(0, 0, 0, 0)

  await db.insert(agents).values({
    id: FIXED_AGENT_ID,
    ownerId: FIXED_OWNER_ID,
    policyId: policy.id,
    name: 'Research Agent',
    description: 'AI research assistant — summarizes papers, calls APIs, provisions compute',
    walletAddress: 'BKoex6j8S5vFZNAVpNScfmKjoCbeTkWwq3A1Y9QUfBLa',
    status: 'active',
    dailySpentUsdc: '0',
    monthlySpentUsdc: '0',
    dailyResetAt: tomorrow,
    monthlyResetAt: nextMonth,
  })

  console.log('✅ Agent created')
  console.log(`   ID:   ${FIXED_AGENT_ID}`)
  console.log('   Name: Research Agent\n')

  // ── 4. Known Merchants ────────────────────────────────────────────────────

  const knownMerchantList = [
    { identifier: 'OpenAI',   address: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',     category: 'api_credits' },
    { identifier: 'GitHub',   address: 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bDM',    category: 'developer_tools' },
    { identifier: 'AWS',      address: 'ComputeBudget111111111111111111111111111111',         category: 'cloud_compute' },
    { identifier: 'Pinecone', address: 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr',     category: 'infrastructure' },
    { identifier: 'Resend',   address: 'namesLPsPKB6NQYLJTQcaLUomR6GCiakDoJfRMF5trd',     category: 'email' },
  ]
  for (const m of knownMerchantList) {
    await db.insert(knownMerchants).values({
      agentId: FIXED_AGENT_ID,
      identifier: m.identifier,
      address: m.address,
      chain: 'solana-devnet',
      category: m.category,
    })
  }
  console.log(`✅ Known merchants: ${knownMerchantList.map(m => m.identifier).join(', ')}\n`)

  // ── 5. Sample transaction history ─────────────────────────────────────────

  const sampleTxs = [
    { merchant: 'OpenAI', amount: 3, token: 'USDC', decision: 'allow', rule: 'policy_passed', reason: 'Amount $3.00 is within auto-approval limit' },
    { merchant: 'GitHub', amount: 4, token: 'USDC', decision: 'allow', rule: 'policy_passed', reason: 'Amount $4.00 is within auto-approval limit' },
    { merchant: 'AWS', amount: 15, token: 'USDC', decision: 'allow', rule: 'amount_above_approval_threshold', reason: 'Human approved after review', resolvedBy: 'human' as const },
    { merchant: 'Pinecone', amount: 2, token: 'USDC', decision: 'allow', rule: 'policy_passed', reason: 'Amount $2.00 is within auto-approval limit' },
    { merchant: 'CryptoCasino', amount: 25, token: 'USDC', decision: 'deny', rule: 'merchant_blocklist', reason: 'Merchant "CryptoCasino" is on the blocklist' },
    { merchant: 'TokenShop', amount: 1, token: 'BONK', decision: 'deny', rule: 'token_not_in_allowlist', reason: 'Token BONK is not in the allowed token list' },
  ]

  for (const tx of sampleTxs) {
    const reqId = `req_${nanoid(16)}`
    const createdAt = new Date(Date.now() - Math.random() * 3600000) // within last hour

    await db.insert(authRequests).values({
      id: reqId,
      agentId: FIXED_AGENT_ID,
      ownerId: FIXED_OWNER_ID,
      chain: 'solana-devnet',
      txType: 'transfer',
      toAddress: MERCHANT_ADDRESSES[tx.merchant] ?? `merchant_${tx.merchant.toLowerCase().replace(/\s/g, '_')}`,
      amountRaw: String(tx.amount * 1_000_000),
      amountUsdc: String(tx.amount),
      token: tx.token,
      txMetadata: { merchant: tx.merchant, category: 'api_credits' },
      decision: tx.decision as any,
      reason: tx.reason,
      ruleTriggered: tx.rule,
      resolvedBy: tx.resolvedBy ?? 'auto',
      resolvedAt: createdAt,
      createdAt,
    })

    await db.insert(auditLogs).values({
      requestId: reqId,
      agentId: FIXED_AGENT_ID,
      ownerId: FIXED_OWNER_ID,
      event: 'decision_made',
      data: { decision: tx.decision, reason: tx.reason, rule: tx.rule },
    })
  }
  console.log(`✅ Sample history: ${sampleTxs.length} transactions\n`)

  // ── Done ──────────────────────────────────────────────────────────────────

  console.log('═'.repeat(50))
  console.log('📋 Environment variables for frontend (.env.local):')
  console.log('')
  console.log(`NEXT_PUBLIC_DEMO_OWNER_ID=${FIXED_OWNER_ID}`)
  console.log(`NEXT_PUBLIC_API_URL=http://localhost:8080`)
  console.log('')
  console.log('📋 Environment variables for MCP Server:')
  console.log('')
  console.log(`AGENT_GUARD_API_KEY=${FIXED_API_KEY}`)
  console.log(`AGENT_GUARD_AGENT_ID=${FIXED_AGENT_ID}`)
  console.log(`AGENT_GUARD_BASE_URL=http://localhost:8080`)
  console.log('')
  console.log('═'.repeat(50))
  console.log('\n🧪 Quick test:')
  console.log(`
curl -s -X POST http://localhost:8080/v1/authorize \\
  -H "Content-Type: application/json" \\
  -H "x-api-key: ${FIXED_API_KEY}" \\
  -d '{
    "agentId": "${FIXED_AGENT_ID}",
    "chain": "solana-devnet",
    "transaction": {
      "to": "9xQeOpenAiAddress",
      "amount": "3000000",
      "token": "USDC",
      "metadata": { "merchant": "OpenAI", "category": "api_credits" }
    }
  }' | jq .
  `)

  process.exit(0)
}

seed().catch(err => {
  console.error('❌ Seed failed:', err)
  process.exit(1)
})
