/**
 * Marketplace Scanner
 *
 * Fetches agent skills from agentic.market (Coinbase x402 Bazaar)
 * and stores them for security analysis.
 *
 * API: https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources
 */

import { db } from '../db/index.js'
import { sql } from 'drizzle-orm'

const BAZAAR_API = 'https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources'

// ── Types ──────────────────────────────────────────────────────────────────────

export interface MarketplaceSkill {
  resource: string          // endpoint URL
  description: string
  network: string           // 'base', 'base-sepolia', etc.
  payTo: string             // wallet address
  amount: string            // max amount in raw units
  asset: string             // USDC contract address
  lastUpdated: string
  inputSchema: any
  outputSchema: any
}

// ── Fetch from Bazaar ──────────────────────────────────────────────────────────

export async function fetchMarketplaceSkills(limit: number = 100, offset: number = 0): Promise<{ skills: MarketplaceSkill[]; total: number }> {
  try {
    const res = await fetch(`${BAZAAR_API}?limit=${limit}&offset=${offset}`, {
      signal: AbortSignal.timeout(15000),
    })
    if (!res.ok) return { skills: [], total: 0 }
    const data = await res.json()

    const skills: MarketplaceSkill[] = []
    for (const item of data.items ?? []) {
      const accept = (item.accepts ?? [])[0] ?? {}
      skills.push({
        resource: accept.resource ?? item.resource ?? '',
        description: accept.description ?? '',
        network: accept.network ?? '',
        payTo: accept.payTo ?? '',
        amount: accept.maxAmountRequired ?? '0',
        asset: accept.asset ?? '',
        lastUpdated: item.lastUpdated ?? '',
        inputSchema: accept.outputSchema?.input ?? null,
        outputSchema: accept.outputSchema?.output ?? null,
      })
    }

    return { skills, total: data.pagination?.total ?? 0 }
  } catch (err) {
    console.error('[marketplace] Fetch failed:', err)
    return { skills: [], total: 0 }
  }
}

// ── Security Analysis ──────────────────────────────────────────────────────────

interface SkillAnalysis {
  riskScore: number       // 0-100 (higher = riskier)
  flags: string[]
  safetyScore: number     // 100 - riskScore
}

function analyzeSkill(skill: MarketplaceSkill): SkillAnalysis {
  const flags: string[] = []
  let riskScore = 0

  // Check URL
  const url = skill.resource
  try {
    const u = new URL(url)
    if (u.protocol !== 'https:') { flags.push('not_https'); riskScore += 20 }
    // Known trusted domains
    const trusted = ['openai.com', 'anthropic.com', 'heurist.xyz', 'quicknode.com', 'coinbase.com', 'stripe.com', 'cloudflare.com', 'aws.amazon.com']
    if (!trusted.some(d => u.hostname.endsWith(d))) {
      // Not a known domain — not necessarily bad, just unknown
      flags.push('unknown_domain')
      riskScore += 5
    }
  } catch {
    flags.push('invalid_url')
    riskScore += 30
  }

  // Check description for social engineering
  const desc = (skill.description ?? '').toLowerCase()
  if (/guaranteed|100% safe|risk.?free|no risk/i.test(desc)) { flags.push('unrealistic_promises'); riskScore += 15 }
  if (/private.?key|seed.?phrase|mnemonic/i.test(desc)) { flags.push('credential_harvesting'); riskScore += 40 }
  if (/act now|limited time|hurry|urgent/i.test(desc)) { flags.push('urgency_language'); riskScore += 10 }

  // Check input schema for suspicious fields
  if (skill.inputSchema) {
    const schemaStr = JSON.stringify(skill.inputSchema).toLowerCase()
    if (schemaStr.includes('private_key') || schemaStr.includes('seed_phrase') || schemaStr.includes('mnemonic')) {
      flags.push('requests_private_key')
      riskScore += 50
    }
    if (schemaStr.includes('password') || schemaStr.includes('secret')) {
      flags.push('requests_secret')
      riskScore += 20
    }
  }

  // Check price — extremely high price is suspicious
  const amount = Number(skill.amount)
  if (amount > 10_000_000) { // > $10 USDC (6 decimals)
    flags.push('high_price')
    riskScore += 10
  }

  // Check network — testnet is less risky but also less legitimate
  if (skill.network.includes('sepolia') || skill.network.includes('testnet')) {
    flags.push('testnet')
    riskScore += 5
  }

  return {
    riskScore: Math.min(100, riskScore),
    flags,
    safetyScore: Math.max(0, 100 - Math.min(100, riskScore)),
  }
}

// ── Store to DB ────────────────────────────────────────────────────────────────

export async function storeMarketplaceSkills(skills: MarketplaceSkill[]) {
  let stored = 0
  for (const skill of skills) {
    const analysis = analyzeSkill(skill)

    // Extract a short name from URL
    let name = skill.resource
    try {
      const u = new URL(skill.resource)
      name = u.pathname.split('/').filter(Boolean).pop() ?? u.hostname
    } catch {}

    // Determine chain from network
    const chain = skill.network.includes('base') ? 'base' : skill.network.includes('solana') ? 'solana' : 'base'

    try {
      await db.execute(sql.raw(`
        INSERT INTO marketplace_skills (
          resource_url, name, description, network, chain, pay_to, amount_raw,
          safety_score, risk_flags, source, input_schema, last_updated, scanned_at
        ) VALUES (
          '${skill.resource.replace(/'/g, "''")}',
          '${name.replace(/'/g, "''")}',
          '${(skill.description ?? '').slice(0, 500).replace(/'/g, "''")}',
          '${skill.network}',
          '${chain}',
          '${skill.payTo}',
          '${skill.amount}',
          ${analysis.safetyScore},
          '${JSON.stringify(analysis.flags)}',
          'agentic.market',
          '${JSON.stringify(skill.inputSchema ?? {}).replace(/'/g, "''")}',
          ${skill.lastUpdated ? `'${skill.lastUpdated}'` : 'NOW()'},
          NOW()
        ) ON CONFLICT (resource_url) DO UPDATE SET
          safety_score = EXCLUDED.safety_score,
          risk_flags = EXCLUDED.risk_flags,
          scanned_at = NOW()
      `))
      stored++
    } catch {}
  }
  return stored
}

// ── Background Scanner ─────────────────────────────────────────────────────────

let scannerRunning = false
let scannerStats = { totalScanned: 0, totalStored: 0, lastRun: 0 }

export async function runMarketplaceScan(maxPages: number = 5) {
  if (scannerRunning) return scannerStats
  scannerRunning = true

  const batchSize = 100
  let totalFetched = 0
  let totalStored = 0

  for (let page = 0; page < maxPages; page++) {
    const { skills, total } = await fetchMarketplaceSkills(batchSize, page * batchSize)
    if (skills.length === 0) break
    totalFetched += skills.length
    totalStored += await storeMarketplaceSkills(skills)
    console.log(`[marketplace] Page ${page + 1}: fetched ${skills.length}, stored ${totalStored}/${totalFetched} (total available: ${total})`)

    // Rate limit
    await new Promise(r => setTimeout(r, 1000))
  }

  scannerStats = { totalScanned: totalFetched, totalStored: totalStored, lastRun: Date.now() }
  scannerRunning = false
  console.log(`[marketplace] Scan complete: ${totalStored} skills stored`)
  return scannerStats
}

export function getMarketplaceStats() {
  return { ...scannerStats, running: scannerRunning }
}
