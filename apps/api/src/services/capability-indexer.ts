/**
 * Capability Indexer
 *
 * Scans agent registration files, A2A cards, and MCP endpoints
 * to build a searchable index of agent capabilities.
 *
 * Also provides pre-call assessment for agent-to-agent interactions.
 */

import { db } from '../db/index.js'
import { sql } from 'drizzle-orm'

// ── Capability Taxonomy ────────────────────────────────────────────────────────

const CAPABILITY_CATEGORIES: Record<string, string[]> = {
  defi: ['swap', 'exchange', 'lending', 'borrow', 'yield', 'farm', 'stake', 'bridge', 'liquidity', 'pool', 'vault', 'amm', 'dex'],
  security: ['audit', 'scan', 'monitor', 'security', 'vulnerability', 'exploit', 'review', 'verify', 'guard', 'protect', 'detect'],
  data: ['price', 'feed', 'oracle', 'analytics', 'index', 'query', 'data', 'market', 'chart', 'track', 'aggregate'],
  ai: ['inference', 'llm', 'gpt', 'claude', 'embedding', 'fine-tune', 'train', 'predict', 'classify', 'generate', 'model'],
  nft: ['mint', 'nft', 'collectible', 'art', 'metadata', 'collection', 'marketplace', 'royalty'],
  social: ['post', 'tweet', 'discord', 'telegram', 'moderate', 'community', 'notify', 'alert', 'message', 'chat'],
  trading: ['trade', 'arbitrage', 'snipe', 'bot', 'signal', 'copy', 'strategy', 'order', 'position', 'portfolio'],
  infra: ['rpc', 'storage', 'compute', 'relay', 'node', 'ipfs', 'api', 'gateway', 'proxy', 'hosting'],
  payment: ['pay', 'invoice', 'transfer', 'remit', 'billing', 'subscription', 'checkout'],
  governance: ['dao', 'vote', 'proposal', 'governance', 'treasury', 'multisig'],
}

function classifyCapability(text: string): { capability: string; category: string }[] {
  const lower = text.toLowerCase()
  const results: { capability: string; category: string }[] = []
  const seen = new Set<string>()

  for (const [category, keywords] of Object.entries(CAPABILITY_CATEGORIES)) {
    for (const keyword of keywords) {
      if (lower.includes(keyword) && !seen.has(keyword)) {
        results.push({ capability: keyword, category })
        seen.add(keyword)
      }
    }
  }

  return results
}

// ── Registration File Parser ───────────────────────────────────────────────────

interface ParsedRegistration {
  name: string
  description: string
  capabilities: { capability: string; category: string }[]
  endpoints: { type: string; url: string }[]
  raw: any
}

async function parseRegistrationFile(uri: string | null): Promise<ParsedRegistration | null> {
  if (!uri) return null

  try {
    let data: any

    if (uri.startsWith('data:application/json;base64,')) {
      data = JSON.parse(Buffer.from(uri.replace('data:application/json;base64,', ''), 'base64').toString())
    } else if (uri.startsWith('http')) {
      const res = await fetch(uri, { signal: AbortSignal.timeout(8000) })
      if (!res.ok) return null
      data = await res.json()
    } else {
      return null
    }

    const name = data.name ?? ''
    const description = data.description ?? ''

    // Extract capabilities from name + description
    const capabilities = classifyCapability(`${name} ${description}`)

    // Extract endpoints
    const endpoints: { type: string; url: string }[] = []
    if (data.services) {
      for (const svc of data.services) {
        if (svc.endpoint || svc.url) {
          endpoints.push({ type: (svc.name ?? svc.type ?? 'web').toLowerCase(), url: svc.endpoint ?? svc.url })
        }
      }
    }
    // Check for x402 support
    if (data.x402Support || data.x402) {
      capabilities.push({ capability: 'x402-payment', category: 'payment' })
    }

    return { name, description, capabilities, endpoints, raw: data }
  } catch {
    return null
  }
}

// ── A2A Agent Card Parser ──────────────────────────────────────────────────────

async function fetchA2ACard(url: string): Promise<{ capabilities: string[]; tools: string[] } | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) })
    if (!res.ok) return null
    const card = await res.json()

    const capabilities: string[] = []
    const tools: string[] = []

    // A2A cards declare skills/capabilities
    if (card.skills) {
      for (const skill of card.skills) {
        if (skill.name) tools.push(skill.name)
        if (skill.description) {
          const classified = classifyCapability(skill.description)
          for (const c of classified) capabilities.push(c.capability)
        }
      }
    }
    if (card.capabilities) {
      for (const cap of card.capabilities) {
        if (typeof cap === 'string') capabilities.push(cap)
        else if (cap.name) capabilities.push(cap.name)
      }
    }

    return { capabilities, tools }
  } catch {
    return null
  }
}

// ── MCP Endpoint Scanner ───────────────────────────────────────────────────────

async function fetchMCPTools(url: string): Promise<{ tools: string[]; pricing: Record<string, any> } | null> {
  try {
    // MCP uses JSON-RPC to list tools
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      signal: AbortSignal.timeout(5000),
    })
    if (!res.ok) return null
    const data = await res.json()

    const tools: string[] = []
    if (data.result?.tools) {
      for (const tool of data.result.tools) {
        if (tool.name) tools.push(tool.name)
      }
    }

    return { tools, pricing: {} }
  } catch {
    return null
  }
}

// ── Index a single agent ───────────────────────────────────────────────────────

export async function indexAgentCapabilities(
  agentId: string,
  chain: string,
  uri: string | null,
): Promise<{ capabilities: number; endpoints: number }> {
  let capCount = 0
  let epCount = 0

  // 1. Parse registration file
  const reg = await parseRegistrationFile(uri)

  if (reg) {
    // Save capabilities
    for (const cap of reg.capabilities) {
      await db.execute(sql.raw(
        `INSERT INTO agent_capabilities (agent_id, chain, capability, category, source, confidence, last_checked)
         VALUES ('${agentId}', '${chain}', '${cap.capability}', '${cap.category}', 'registration', 0.6, NOW())
         ON CONFLICT (agent_id, chain, capability) DO UPDATE SET
           category = EXCLUDED.category, last_checked = NOW()`
      )).catch(() => {})
      capCount++
    }

    // Save + probe endpoints
    for (const ep of reg.endpoints) {
      let status = 'unknown'
      let toolsList: string[] = []

      if (ep.type === 'a2a') {
        const card = await fetchA2ACard(ep.url)
        if (card) {
          status = 'online'
          toolsList = card.tools
          // Add discovered capabilities
          for (const cap of card.capabilities) {
            const classified = classifyCapability(cap)
            for (const c of classified) {
              await db.execute(sql.raw(
                `INSERT INTO agent_capabilities (agent_id, chain, capability, category, source, confidence, last_checked)
                 VALUES ('${agentId}', '${chain}', '${c.capability}', '${c.category}', 'a2a', 0.8, NOW())
                 ON CONFLICT (agent_id, chain, capability) DO UPDATE SET
                   confidence = GREATEST(agent_capabilities.confidence, 0.8), last_checked = NOW()`
              )).catch(() => {})
              capCount++
            }
          }
        } else {
          status = 'offline'
        }
      } else if (ep.type === 'mcp') {
        const mcp = await fetchMCPTools(ep.url)
        if (mcp) {
          status = 'online'
          toolsList = mcp.tools
          for (const tool of mcp.tools) {
            const classified = classifyCapability(tool)
            for (const c of classified) {
              await db.execute(sql.raw(
                `INSERT INTO agent_capabilities (agent_id, chain, capability, category, source, confidence, last_checked)
                 VALUES ('${agentId}', '${chain}', '${c.capability}', '${c.category}', 'mcp', 0.9, NOW())
                 ON CONFLICT (agent_id, chain, capability) DO UPDATE SET
                   confidence = GREATEST(agent_capabilities.confidence, 0.9), last_checked = NOW()`
              )).catch(() => {})
              capCount++
            }
          }
        } else {
          status = 'offline'
        }
      } else {
        // Web endpoint — just check if reachable
        try {
          const res = await fetch(ep.url, { method: 'HEAD', signal: AbortSignal.timeout(3000) })
          status = res.ok ? 'online' : 'offline'
        } catch {
          status = 'offline'
        }
      }

      await db.execute(sql.raw(
        `INSERT INTO agent_endpoints (agent_id, chain, endpoint_type, url, status, tools_count, tools_list, last_checked)
         VALUES ('${agentId}', '${chain}', '${ep.type}', '${ep.url.replace(/'/g, "''")}', '${status}', ${toolsList.length}, '${JSON.stringify(toolsList)}', NOW())
         ON CONFLICT (agent_id, chain, endpoint_type) DO UPDATE SET
           url = EXCLUDED.url, status = EXCLUDED.status, tools_count = EXCLUDED.tools_count,
           tools_list = EXCLUDED.tools_list, last_checked = NOW()`
      )).catch(() => {})
      epCount++
    }
  }

  return { capabilities: capCount, endpoints: epCount }
}

// ── Pre-Call Assessment ────────────────────────────────────────────────────────

export interface PreCallAssessment {
  agentId: string
  chain: string
  name: string
  wallet: string | null       // payment address — use this for authorize_payment
  securityScore: number | null
  grade: string | null
  capabilities: { capability: string; category: string; confidence: number; source: string }[]
  endpoints: { type: string; url: string; status: string; toolsCount: number }[]
  canDoAction: boolean
  matchedCapabilities: string[]
  isWhitelisted: boolean
  whitelistReason: string | null
  pricing: string
  recommendation: 'proceed' | 'caution' | 'reject' | 'unknown'
  reasons: string[]
}

export async function assessAgentBeforeCall(
  targetAgentId: string,
  targetChain: string,
  intendedAction: string,
  maxBudget: number,
  callerId?: string,
): Promise<PreCallAssessment> {
  const reasons: string[] = []

  // 1. Get agent basic info
  const agentRows = await db.execute(sql.raw(
    `SELECT agent_id, chain, security_score, wallet, uri FROM erc8004_agents
     WHERE agent_id = '${targetAgentId}' AND chain = '${targetChain}' LIMIT 1`
  ))
  const agent = (agentRows as any[])[0]

  let name = `Agent #${targetAgentId}`
  let wallet: string | null = null
  let securityScore: number | null = null
  let grade: string | null = null

  if (agent) {
    wallet = agent.wallet ?? null
    securityScore = agent.security_score
    // Get dimensions for grade
    const dimRows = await db.execute(sql.raw(
      `SELECT * FROM erc8004_dimensions WHERE agent_id = '${targetAgentId}' AND chain = '${targetChain}' LIMIT 1`
    ))
    const dim = (dimRows as any[])[0]
    if (dim) {
      const avg = (Number(dim.fund_safety) + Number(dim.logic_transparency) + Number(dim.compliance) + Number(dim.tech_stability) + Number(dim.behavior_consistency)) / 5
      grade = avg >= 90 ? 'A' : avg >= 75 ? 'B' : avg >= 60 ? 'C' : avg >= 40 ? 'D' : 'F'
    }
  }

  // 2. Get capabilities
  const capRows = await db.execute(sql.raw(
    `SELECT capability, category, confidence, source FROM agent_capabilities
     WHERE agent_id = '${targetAgentId}' AND chain = '${targetChain}'
     ORDER BY confidence DESC`
  ))
  const capabilities = (capRows as any[]).map(r => ({
    capability: r.capability, category: r.category,
    confidence: Number(r.confidence), source: r.source,
  }))

  // 3. Get endpoints
  const epRows = await db.execute(sql.raw(
    `SELECT endpoint_type, url, status, tools_count FROM agent_endpoints
     WHERE agent_id = '${targetAgentId}' AND chain = '${targetChain}'`
  ))
  const endpoints = (epRows as any[]).map(r => ({
    type: r.endpoint_type, url: r.url, status: r.status, toolsCount: Number(r.tools_count),
  }))

  // 4. Check if action matches capabilities
  const actionKeywords = classifyCapability(intendedAction)
  const matchedCapabilities: string[] = []
  for (const ak of actionKeywords) {
    if (capabilities.some(c => c.capability === ak.capability)) {
      matchedCapabilities.push(ak.capability)
    }
  }
  const canDoAction = matchedCapabilities.length > 0 || capabilities.length === 0 // if no caps indexed, can't say no

  // 5. Check whitelist
  let isWhitelisted = false
  let whitelistReason: string | null = null

  // System whitelist
  const sysWl = await db.execute(sql.raw(
    `SELECT reason FROM agent_whitelist WHERE agent_id = '${targetAgentId}' AND chain = '${targetChain}' AND level = 'system' LIMIT 1`
  ))
  if ((sysWl as any[]).length > 0) {
    isWhitelisted = true
    whitelistReason = (sysWl as any[])[0].reason ?? 'System verified'
  }

  // User whitelist
  if (callerId) {
    const userWl = await db.execute(sql.raw(
      `SELECT reason FROM agent_whitelist WHERE agent_id = '${targetAgentId}' AND chain = '${targetChain}' AND owner_id = '${callerId}' LIMIT 1`
    ))
    if ((userWl as any[]).length > 0) {
      isWhitelisted = true
      whitelistReason = (userWl as any[])[0].reason ?? 'User trusted'
    }
  }

  // 6. Determine recommendation
  let recommendation: PreCallAssessment['recommendation'] = 'unknown'

  if (isWhitelisted) {
    recommendation = 'proceed'
    reasons.push('Agent is whitelisted')
  } else if (securityScore !== null) {
    if (securityScore >= 80) {
      recommendation = 'proceed'
      reasons.push(`Security score ${securityScore}/100 — safe`)
    } else if (securityScore >= 50) {
      recommendation = 'caution'
      reasons.push(`Security score ${securityScore}/100 — proceed with caution`)
    } else {
      recommendation = 'reject'
      reasons.push(`Security score ${securityScore}/100 — high risk`)
    }
  } else {
    recommendation = 'caution'
    reasons.push('Agent has not been security-analyzed yet')
  }

  if (!canDoAction && capabilities.length > 0) {
    recommendation = 'caution'
    reasons.push(`Agent does not declare "${intendedAction}" capability`)
  }

  if (endpoints.every(e => e.status === 'offline') && endpoints.length > 0) {
    recommendation = 'reject'
    reasons.push('All endpoints are offline')
  }

  if (!wallet) {
    if (recommendation === 'proceed') recommendation = 'caution'
    reasons.push('No wallet bound — cannot make payment to this agent')
  } else {
    reasons.push(`Payment address: ${wallet}`)
  }

  if (capabilities.length === 0) {
    reasons.push('No capabilities indexed — unknown agent abilities')
  }

  // Pricing — currently unknown for most agents
  const pricing = 'Unknown — may use x402 Payment Required'

  return {
    agentId: targetAgentId, chain: targetChain, name, wallet,
    securityScore, grade,
    capabilities, endpoints, canDoAction, matchedCapabilities,
    isWhitelisted, whitelistReason, pricing,
    recommendation, reasons,
  }
}

// ── Auto Indexer (background task) ─────────────────────────────────────────────

let indexerRunning = false
let indexerStats = { totalIndexed: 0, lastRound: 0 }

async function indexRound() {
  if (indexerRunning) return
  indexerRunning = true

  try {
    // Get agents with URI that haven't been indexed recently
    const rows = await db.execute(sql.raw(
      `SELECT agent_id, chain, uri FROM erc8004_agents
       WHERE uri IS NOT NULL
       AND agent_id NOT IN (SELECT DISTINCT agent_id FROM agent_capabilities WHERE last_checked > NOW() - INTERVAL '24 hours')
       LIMIT 5`
    ))

    for (const row of rows as any[]) {
      try {
        const result = await indexAgentCapabilities(row.agent_id, row.chain, row.uri)
        if (result.capabilities > 0 || result.endpoints > 0) {
          console.log(`[capability-indexer] Indexed ${row.chain}/#${row.agent_id}: ${result.capabilities} caps, ${result.endpoints} endpoints`)
          indexerStats.totalIndexed++
        }
      } catch {}
    }

    indexerStats.lastRound = Date.now()
  } catch {}

  indexerRunning = false
}

export function startCapabilityIndexer() {
  console.log('[capability-indexer] Starting background indexer')
  setTimeout(() => {
    indexRound()
    setInterval(indexRound, 5 * 60 * 1000) // Every 5 minutes
  }, 30_000) // Start after 30s
}

export function getIndexerStats() {
  return { ...indexerStats, running: indexerRunning }
}
