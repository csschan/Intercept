/**
 * Auto Analyzer — Background task that continuously analyzes unscored agents
 *
 * Runs on a timer, picks unscored agents from DB, runs full analysis,
 * saves results back. Rate-limited to avoid API throttling.
 */

import { db } from '../db/index.js'
import { sql } from 'drizzle-orm'
import { getAgentTransactions, enrichAgent, SUPPORTED_CHAINS } from './erc8004.js'
import { indexAgentCapabilities } from './capability-indexer.js'
import { runSlowMistAnalysis } from './slowmist-analyzer.js'
import { profileAgent } from './agent-profiler.js'

// ── Config ─────────────────────────────────────────────────────────────────────

const BATCH_SIZE = 5               // agents per round
const INTERVAL_MS = 3 * 60 * 1000  // 3 minutes between rounds
const STALE_HOURS = 24             // re-analyze after 24 hours
const CONCURRENCY = 2              // parallel analyses (GoPlus rate limit)

// ── State ──────────────────────────────────────────────────────────────────────

let running = false
let timer: ReturnType<typeof setInterval> | null = null
let stats = {
  totalAnalyzed: 0,
  lastRoundAnalyzed: 0,
  lastRoundTime: 0,
  errors: 0,
  isRunning: false,
}

// ── Analyze a single agent ─────────────────────────────────────────────────────

async function analyzeAgent(agentId: string, chain: string, wallet: string): Promise<boolean> {
  try {
    // Fetch transactions
    const transactions = await getAgentTransactions(chain, wallet, 20)

    // Run full analysis
    const slowmist = await runSlowMistAnalysis(agentId, chain, wallet, transactions)
    const profile = await profileAgent(chain, wallet, transactions, {}, {}, {})

    // Compute unified score (same formula as monitor route)
    const dim = profile.dimensions
    const dimAvg = (dim.fundSafety + dim.logicTransparency + dim.compliance + dim.techStability + dim.behaviorConsistency) / 5
    const rugPenalty = Math.round(profile.rugPullIndex.score * 0.3)
    const gasPenalty = profile.gasAnomaly.detected ? 5 : 0
    const driftPenalty = Math.round(profile.logicDrift.score * 0.15)
    const checklistWorst = Math.max(...slowmist.checklist.map(c => c.score), 0)
    const checklistPenalty = Math.round(checklistWorst * 0.2)
    const securityScore = transactions.length === 0
      ? Math.min(50, Math.round(dimAvg) - rugPenalty)
      : Math.max(0, Math.min(100, Math.round(dimAvg) - rugPenalty - gasPenalty - driftPenalty - checklistPenalty))

    // Save score to agents table
    await db.execute(sql.raw(
      `UPDATE erc8004_agents SET security_score = ${securityScore}, tx_count = ${transactions.length}, top_flag = '${(slowmist.checklist.filter(c => c.status === 'fail' || c.status === 'warn').sort((a, b) => b.score - a.score)[0]?.name ?? '').replace(/'/g, "''")}', scored_at = NOW() WHERE chain = '${chain}' AND agent_id = '${agentId}'`
    ))

    // Save dimensions
    await db.execute(sql.raw(
      `INSERT INTO erc8004_dimensions (agent_id, chain, fund_safety, logic_transparency, compliance, tech_stability, behavior_consistency, rug_pull_index, gas_anomaly_score, scored_at)
       VALUES ('${agentId}', '${chain}', ${profile.dimensions.fundSafety}, ${profile.dimensions.logicTransparency}, ${profile.dimensions.compliance}, ${profile.dimensions.techStability}, ${profile.dimensions.behaviorConsistency}, ${profile.rugPullIndex.score}, ${profile.gasAnomaly.detected ? 50 : 0}, NOW())
       ON CONFLICT (chain, agent_id) DO UPDATE SET
         fund_safety = EXCLUDED.fund_safety, logic_transparency = EXCLUDED.logic_transparency,
         compliance = EXCLUDED.compliance, tech_stability = EXCLUDED.tech_stability,
         behavior_consistency = EXCLUDED.behavior_consistency, rug_pull_index = EXCLUDED.rug_pull_index,
         gas_anomaly_score = EXCLUDED.gas_anomaly_score, scored_at = NOW()`
    ))

    // Save alerts
    for (const alert of profile.alerts) {
      await db.execute(sql.raw(
        `INSERT INTO erc8004_alerts (agent_id, chain, alert_type, severity, title, detail)
         VALUES ('${agentId}', '${chain}', '${alert.alertType}', '${alert.severity}', '${alert.title.replace(/'/g, "''")}', '${(alert.detail ?? '').replace(/'/g, "''")}')`
      )).catch(() => {})
    }

    // Enrich URI + index capabilities
    try {
      const meta = await enrichAgent(chain, BigInt(agentId))
      if (meta.uri) {
        await db.execute(sql.raw(
          `UPDATE erc8004_agents SET uri = '${meta.uri.replace(/'/g, "''")}' WHERE chain = '${chain}' AND agent_id = '${agentId}' AND (uri IS NULL OR uri = '')`
        )).catch(() => {})
        const capResult = await indexAgentCapabilities(agentId, chain, meta.uri)
        if (capResult.capabilities > 0) {
          console.log(`[auto-analyzer] 📋 ${chain}/#${agentId} indexed ${capResult.capabilities} capabilities`)
        }
      }
    } catch {}

    console.log(`[auto-analyzer] ✅ ${chain}/#${agentId} score=${securityScore} txs=${transactions.length} grade=${profile.overallGrade}`)
    return true
  } catch (err: any) {
    console.error(`[auto-analyzer] ❌ ${chain}/#${agentId} failed: ${err?.message?.slice(0, 100) ?? err}`)
    // Mark as scored with null to avoid retrying immediately — will retry after STALE_HOURS
    await db.execute(sql.raw(
      `UPDATE erc8004_agents SET scored_at = NOW() WHERE chain = '${chain}' AND agent_id = '${agentId}'`
    )).catch(() => {})
    return false
  }
}

// ── Run one round ──────────────────────────────────────────────────────────────

async function runRound() {
  if (running) return
  running = true
  stats.isRunning = true
  const roundStart = Date.now()
  let analyzed = 0

  try {
    // Priority 1: Agents with wallet but never scored
    let rows = await db.execute(sql.raw(
      `SELECT agent_id, chain, wallet FROM erc8004_agents
       WHERE wallet IS NOT NULL AND security_score IS NULL AND (scored_at IS NULL OR scored_at < NOW() - INTERVAL '1 hour')
       ORDER BY RANDOM() LIMIT ${BATCH_SIZE}`
    ))
    let agents = rows as any[]

    // Priority 2: If none unscored, find stale scores to refresh
    if (agents.length === 0) {
      rows = await db.execute(sql.raw(
        `SELECT agent_id, chain, wallet FROM erc8004_agents
         WHERE wallet IS NOT NULL AND scored_at < NOW() - INTERVAL '${STALE_HOURS} hours'
         ORDER BY scored_at ASC NULLS FIRST LIMIT ${BATCH_SIZE}`
      ))
      agents = rows as any[]
    }

    if (agents.length === 0) {
      console.log('[auto-analyzer] All agents are up to date')
      running = false
      stats.isRunning = false
      return
    }

    console.log(`[auto-analyzer] Round starting: ${agents.length} agents to analyze`)

    // Process in batches of CONCURRENCY
    for (let i = 0; i < agents.length; i += CONCURRENCY) {
      const batch = agents.slice(i, i + CONCURRENCY)
      const results = await Promise.allSettled(
        batch.map((a: any) => analyzeAgent(a.agent_id, a.chain, a.wallet))
      )
      for (const r of results) {
        if (r.status === 'fulfilled' && r.value) analyzed++
        else stats.errors++
      }
      // Small delay between batches to avoid rate limits
      if (i + CONCURRENCY < agents.length) {
        await new Promise(resolve => setTimeout(resolve, 2000))
      }
    }
  } catch (err) {
    console.error('[auto-analyzer] Round failed:', err)
  }

  stats.totalAnalyzed += analyzed
  stats.lastRoundAnalyzed = analyzed
  stats.lastRoundTime = Date.now() - roundStart
  stats.isRunning = false
  running = false

  console.log(`[auto-analyzer] Round complete: ${analyzed} analyzed in ${stats.lastRoundTime}ms`)
}

// ── Start / Stop ───────────────────────────────────────────────────────────────

export function startAutoAnalyzer() {
  if (timer) return
  console.log(`[auto-analyzer] Starting (batch=${BATCH_SIZE}, interval=${INTERVAL_MS / 1000}s, concurrency=${CONCURRENCY})`)

  // Run first round after 10 seconds (let server start up)
  setTimeout(() => {
    runRound()
    timer = setInterval(runRound, INTERVAL_MS)
  }, 10_000)
}

export function stopAutoAnalyzer() {
  if (timer) {
    clearInterval(timer)
    timer = null
    console.log('[auto-analyzer] Stopped')
  }
}

export function getAutoAnalyzerStats() {
  return { ...stats }
}

// ── Enrich wallets for agents missing them ─────────────────────────────────────

export async function enrichMissingWallets(limit: number = 10) {
  const rows = await db.execute(sql.raw(
    `SELECT agent_id, chain FROM erc8004_agents WHERE wallet IS NULL ORDER BY RANDOM() LIMIT ${limit}`
  ))

  let enriched = 0
  for (const row of rows as any[]) {
    try {
      const meta = await enrichAgent(row.chain, BigInt(row.agent_id))
      if (meta.wallet) {
        await db.execute(sql.raw(
          `UPDATE erc8004_agents SET wallet = '${meta.wallet}' WHERE chain = '${row.chain}' AND agent_id = '${row.agent_id}'`
        ))
        enriched++
      }
    } catch {}
  }

  console.log(`[auto-analyzer] Enriched ${enriched}/${(rows as any[]).length} wallets`)
  return enriched
}
