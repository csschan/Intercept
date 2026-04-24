/**
 * Agent Guard — External Agent Demo
 *
 * This script simulates a "Research Agent" that autonomously
 * purchases AI services and cloud resources to complete tasks.
 *
 * It integrates with Agent Guard for every payment:
 *   - Small known expenses → auto approved
 *   - Large or new merchants → waits for human approval
 *   - Blocked categories → immediately denied
 *
 * Run:
 *   npx tsx demos/external-agent.ts
 */

const AGENT_GUARD_URL = 'http://localhost:8080'
const API_KEY = 'ag_demo_Fu-gl86lXj40yeMT9YrfAAoIXwl8PzYG'
const AGENT_ID = '03c7f8ae-efaf-47ba-8048-1000c76029c7'

// ── Colors ────────────────────────────────────────────────────────────────────
const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  white: '\x1b[37m',
}

function log(prefix: string, color: string, msg: string) {
  console.log(`${color}${prefix}${c.reset} ${msg}`)
}

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

// ── Agent Guard Client ────────────────────────────────────────────────────────

interface AuthorizeRequest {
  agentId: string
  chain: string
  toAddress: string
  amountRaw: string
  token: string
  metadata: {
    purpose: string
    merchant: string
    category: string
    isRecurring?: boolean
  }
}

interface AuthorizeResponse {
  decision: 'allow' | 'deny' | 'ask_user'
  requestId: string
  reason: string
  ruleTriggered?: string
  expiresAt?: string
}

async function authorize(tx: AuthorizeRequest): Promise<AuthorizeResponse> {
  const body = {
    agentId: tx.agentId,
    chain: tx.chain,
    transaction: {
      to: tx.toAddress,
      amount: tx.amountRaw,
      token: tx.token,
      metadata: tx.metadata,
    },
  }
  const res = await fetch(`${AGENT_GUARD_URL}/v1/authorize`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': API_KEY,
    },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(`Auth failed: ${JSON.stringify(err)}`)
  }
  return res.json()
}

async function pollForDecision(requestId: string, timeoutMs = 120_000): Promise<'approve' | 'deny' | 'timeout'> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    await sleep(2000)
    const res = await fetch(`${AGENT_GUARD_URL}/v1/requests/${requestId}`, {
      headers: { 'x-api-key': API_KEY },
    })
    if (!res.ok) continue
    const req = await res.json()
    if (req.decision === 'allow') return 'approve'
    if (req.decision === 'deny') return 'deny'
    // still ask_user — keep polling
    const remaining = Math.round((deadline - Date.now()) / 1000)
    process.stdout.write(`\r  ${c.yellow}⏳ Waiting for human approval... ${remaining}s remaining${c.reset}   `)
  }
  process.stdout.write('\n')
  return 'timeout'
}

// ── The "Research Agent" Tasks ────────────────────────────────────────────────

interface Task {
  name: string
  description: string
  payment: {
    merchant: string
    category: string
    amountUsdc: number
    purpose: string
    isRecurring?: boolean
    token?: string
  }
}

// Policy on this agent:
//   auto-approve  < $10   (known merchants)
//   ask_user      > $40
//   daily cap       $300
//   blocked: gambling, adult_content
//   blocked tokens: BONK

const TASKS: Task[] = [
  {
    name: 'Summarize research papers',
    description: 'Call GPT-4 API to summarize 20 AI papers',
    payment: {
      merchant: 'OpenAI',
      category: 'api_credits',
      amountUsdc: 4.50,
      purpose: 'GPT-4o API calls for paper summarization',
    },
  },
  {
    name: 'Store embeddings',
    description: 'Upload 50k vectors to Pinecone vector DB',
    payment: {
      merchant: 'Pinecone',
      category: 'infrastructure',
      amountUsdc: 8.00,
      purpose: 'Vector storage for research embeddings',
    },
  },
  {
    name: 'Send digest email',
    description: 'Email research findings to subscribers',
    payment: {
      merchant: 'Resend',
      category: 'email',
      amountUsdc: 3.00,
      purpose: 'Transactional email — weekly research digest',
    },
  },
  {
    name: 'Spin up GPU for training',
    description: 'Launch p3.2xlarge for 2h fine-tuning run',
    payment: {
      merchant: 'AWS',
      category: 'cloud_compute',
      amountUsdc: 47.00,
      purpose: 'GPU compute for model fine-tuning',
    },
  },
  {
    name: 'Subscribe to dataset feed',
    description: 'Monthly bulk access to ArXiv + PubMed',
    payment: {
      merchant: 'DataVendor Pro',
      category: 'data',
      amountUsdc: 120.00,
      purpose: 'Monthly academic dataset subscription',
      isRecurring: true,
    },
  },
  {
    name: 'Attempt: gambling site',
    description: 'Should be blocked by category policy',
    payment: {
      merchant: 'CryptoCasino',
      category: 'gambling',
      amountUsdc: 25.00,
      purpose: 'Blocked category test',
    },
  },
  {
    name: 'Attempt: buy BONK',
    description: 'Should be blocked — BONK is on token blocklist',
    payment: {
      merchant: 'Jupiter DEX',
      category: 'defi',
      amountUsdc: 10.00,
      purpose: 'Token swap USDC → BONK',
      token: 'BONK',
    },
  },
]

// ── Main ──────────────────────────────────────────────────────────────────────

async function runAgent() {
  console.log()
  console.log(`${c.bold}${c.cyan}╔══════════════════════════════════════════════════════╗${c.reset}`)
  console.log(`${c.bold}${c.cyan}║        Agent Guard — External Agent Demo             ║${c.reset}`)
  console.log(`${c.bold}${c.cyan}╚══════════════════════════════════════════════════════╝${c.reset}`)
  console.log()
  console.log(`${c.dim}Agent ID : ${AGENT_ID}${c.reset}`)
  console.log(`${c.dim}Guard URL: ${AGENT_GUARD_URL}${c.reset}`)
  console.log(`${c.dim}Policy   : auto-approve <$10 | ask_user >$40 | daily cap $300 | block gambling/BONK${c.reset}`)
  console.log()

  let allowed = 0, denied = 0, waitedFor = 0

  for (let i = 0; i < TASKS.length; i++) {
    const task = TASKS[i]
    const amountRaw = Math.round(task.payment.amountUsdc * 1_000_000).toString()
    const token = task.payment.token ?? 'USDC'

    console.log(`${c.bold}── Task ${i + 1}/${TASKS.length}: ${task.name}${c.reset}`)
    console.log(`   ${c.dim}${task.description}${c.reset}`)
    console.log(`   Payment: ${c.white}$${task.payment.amountUsdc} ${token}${c.reset} → ${c.white}${task.payment.merchant}${c.reset} (${task.payment.category})`)
    console.log(`   ${c.dim}Requesting authorization from Agent Guard...${c.reset}`)

    let result: AuthorizeResponse
    try {
      result = await authorize({
        agentId: AGENT_ID,
        chain: 'solana-devnet',
        toAddress: `merchant_${task.payment.merchant.toLowerCase().replace(/\s/g, '_')}`,
        amountRaw,
        token,
        metadata: {
          purpose: task.payment.purpose,
          merchant: task.payment.merchant,
          category: task.payment.category,
          isRecurring: task.payment.isRecurring,
        },
      })
    } catch (err) {
      log('  [ERROR]', c.red, `${err}`)
      console.log()
      continue
    }

    if (result.decision === 'allow') {
      log('  [ALLOW]', c.green, `${c.bold}Auto-approved${c.reset} — ${result.reason}`)
      log('  [EXEC] ', c.green, `Executing payment... done ✓`)
      allowed++

    } else if (result.decision === 'deny') {
      log('  [DENY] ', c.red, `${c.bold}Blocked${c.reset} — ${result.reason}`)
      log('  [SKIP] ', c.red, `Payment cancelled. Moving to next task.`)
      denied++

    } else if (result.decision === 'ask_user') {
      log('  [HOLD] ', c.yellow, `${c.bold}Needs human approval${c.reset} — ${result.reason}`)
      console.log(`   ${c.dim}Request ID: ${result.requestId}${c.reset}`)
      console.log(`   ${c.yellow}→ Check your Dashboard: http://localhost:3000/dashboard/pending${c.reset}`)
      console.log()

      const decision = await pollForDecision(result.requestId, 90_000)
      console.log()

      if (decision === 'approve') {
        log('  [ALLOW]', c.green, `${c.bold}Human approved ✓${c.reset} — Executing payment...`)
        allowed++
        waitedFor++
      } else if (decision === 'deny') {
        log('  [DENY] ', c.red, `${c.bold}Human denied${c.reset} — Payment cancelled.`)
        denied++
        waitedFor++
      } else {
        log('  [TIMEOUT]', c.yellow, `No response within 90s — applying timeout policy (deny)`)
        denied++
      }
    }

    console.log()
    await sleep(800)
  }

  // Summary
  console.log(`${c.bold}${c.cyan}╔══════════════════════════════════════════════════════╗${c.reset}`)
  console.log(`${c.bold}${c.cyan}║                    Session Summary                   ║${c.reset}`)
  console.log(`${c.bold}${c.cyan}╚══════════════════════════════════════════════════════╝${c.reset}`)
  console.log()
  console.log(`  Tasks run      : ${TASKS.length}`)
  console.log(`  ${c.green}Payments allowed: ${allowed}${c.reset}`)
  console.log(`  ${c.red}Payments denied : ${denied}${c.reset}`)
  console.log(`  ${c.yellow}Human approvals : ${waitedFor}${c.reset}`)
  console.log()
  console.log(`  ${c.dim}View full history: http://localhost:3000/dashboard/history${c.reset}`)
  console.log(`  ${c.dim}On-chain policy : https://explorer.solana.com/address/EKzvg64PgWHiqyajeSGewC28JPSAHRty1sMjUhHNAp9L?cluster=devnet${c.reset}`)
  console.log()
}

runAgent().catch(err => {
  console.error(`${c.red}Fatal error:${c.reset}`, err)
  process.exit(1)
})
