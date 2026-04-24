/**
 * ERC-8004 Agent Monitor Routes
 *
 * GET  /v1/monitor/agents          — list agents (from DB, instant)
 * GET  /v1/monitor/agents/:chain/:id — agent detail + reputation + txs
 * GET  /v1/monitor/chains          — supported chains info
 * GET  /v1/monitor/stats           — aggregate stats
 * POST /v1/monitor/scan            — trigger incremental scan (background)
 */

import type { FastifyInstance } from 'fastify'
import {
  SUPPORTED_CHAINS,
  IDENTITY_REGISTRY,
  REPUTATION_REGISTRY,
  getRegisteredAgents,
  enrichAgent,
  getAgentReputation,
  getAgentTransactions,
} from '../services/erc8004.js'
import { runSlowMistAnalysis } from '../services/slowmist-analyzer.js'
import { profileAgent } from '../services/agent-profiler.js'
import { runDeepAnalysis, type DeepAnalysis } from '../services/deep-analyzer.js'
import { getSolanaAgents, getSolanaAgentDetail, getSolanaWalletTransactions, getSolanaGlobalStats } from '../services/solana-agent-registry.js'
import { db } from '../db/index.js'
import { sql } from 'drizzle-orm'

// Track if a scan is currently running
let scanning = false
let lastScanTime = 0

export async function monitorRoutes(app: FastifyInstance) {

  // GET /v1/monitor/chains
  app.get('/v1/monitor/chains', async (_request, reply) => {
    const evmChains = Object.entries(SUPPORTED_CHAINS).map(([key, val]) => ({
      key,
      label: val.label,
      color: val.color,
      chainId: val.chain.id,
      identityRegistry: IDENTITY_REGISTRY,
      reputationRegistry: REPUTATION_REGISTRY,
    }))
    // Add Solana
    evmChains.push({
      key: 'solana',
      label: 'Solana',
      color: '#9945FF',
      chainId: 0,
      identityRegistry: '8oo4dC4JvBLwy5tGgiH3WwK4B9PWxL9Z4XjA2jzkQMbQ',
      reputationRegistry: 'AToMw53aiPQ8j7iHVb4fGt6nzUNxUhcPc3tbPBZuzVVb',
    })
    return reply.send(evmChains)
  })

  // GET /v1/monitor/agents?chains=ethereum,bsc
  // Reads from DB — instant response
  app.get<{
    Querystring: { chains?: string; limit?: string }
  }>('/v1/monitor/agents', async (request, reply) => {
    const { chains: chainsParam, limit: limitParam } = request.query
    const limit = Math.min(Number(limitParam ?? 2000), 5000)

    let query = `SELECT * FROM erc8004_agents`
    const conditions: string[] = []

    if (chainsParam) {
      const chains = chainsParam.split(',').filter(Boolean).map(c => `'${c}'`).join(',')
      conditions.push(`chain IN (${chains})`)
    }

    if (conditions.length > 0) query += ` WHERE ${conditions.join(' AND ')}`
    query += ` ORDER BY security_score ASC NULLS LAST, block_number DESC LIMIT ${limit}`

    const result = await db.execute(sql.raw(query))

    // Get cursors for scan status
    const cursors = await db.execute(sql.raw('SELECT * FROM erc8004_scan_cursors ORDER BY chain'))

    // Get alert counts per agent
    const alertRows = await db.execute(sql.raw(
      `SELECT agent_id, chain, COUNT(*) as alert_count,
              COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count,
              COUNT(CASE WHEN severity = 'warning' THEN 1 END) as warning_count
       FROM erc8004_alerts GROUP BY agent_id, chain`
    )).catch(() => [])
    const alertMap: Record<string, { total: number; critical: number; warning: number }> = {}
    for (const r of alertRows as any[]) {
      alertMap[`${r.chain}:${r.agent_id}`] = { total: Number(r.alert_count), critical: Number(r.critical_count), warning: Number(r.warning_count) }
    }

    // Get all capabilities grouped by agent
    const capRows = await db.execute(sql.raw(
      `SELECT agent_id, chain, array_agg(DISTINCT category) as categories, array_agg(DISTINCT capability) as skills
       FROM agent_capabilities GROUP BY agent_id, chain`
    )).catch(() => [])
    const capMap: Record<string, { categories: string[]; skills: string[] }> = {}
    for (const r of capRows as any[]) {
      capMap[`${r.chain}:${r.agent_id}`] = { categories: r.categories ?? [], skills: r.skills ?? [] }
    }

    // EVM agents from DB (includes persisted scores + capabilities)
    const evmAgents = (result as any[]).map(r => {
      const caps = capMap[`${r.chain}:${r.agent_id}`]
      const alerts = alertMap[`${r.chain}:${r.agent_id}`]
      return {
        agentId: r.agent_id,
        owner: r.owner,
        chain: r.chain,
        chainLabel: r.chain_label,
        blockNumber: r.block_number,
        txHash: r.tx_hash,
        wallet: r.wallet,
        uri: r.uri,
        securityScore: r.security_score,
        txCount: r.tx_count ?? 0,
        topFlag: r.top_flag ?? '',
        source: 'erc-8004',
        skills: caps?.skills ?? [],
        categories: caps?.categories ?? [],
        alertCount: alerts?.total ?? 0,
        criticalAlerts: alerts?.critical ?? 0,
        warningAlerts: alerts?.warning ?? 0,
      }
    })

    // Include Solana agents if not filtered out
    const selectedChains = chainsParam?.split(',').filter(Boolean)
    let allAgents = evmAgents
    if (!selectedChains || selectedChains.includes('solana')) {
      try {
        const solAgents = await getSolanaAgents(Math.min(limit, 500))
        const mapped = solAgents.map(a => ({
          agentId: a.agentId,
          owner: a.owner,
          chain: 'solana',
          chainLabel: 'Solana',
          blockNumber: a.createdAt.toString(),
          txHash: a.assetId,
          wallet: a.wallet,
          uri: null,
          name: a.name,
          source: 'solana-registry',
        }))
        allAgents = [...evmAgents, ...mapped]
      } catch {}
    }


    return reply.send({
      agents: allAgents,
      total: allAgents.length,
      scanStatus: {
        scanning,
        lastScanTime,
        cursors: (cursors as any[]).map(c => ({
          chain: c.chain,
          lastBlock: c.last_block,
          agentCount: c.agent_count,
          updatedAt: c.updated_at,
        })),
      },
    })
  })

  // POST /v1/monitor/scan?chains=ethereum,bsc
  // Trigger incremental scan — runs in background, returns immediately
  app.post<{
    Querystring: { chains?: string }
  }>('/v1/monitor/scan', async (request, reply) => {
    if (scanning) {
      return reply.send({ status: 'already_scanning', lastScanTime })
    }

    const chainsParam = request.query.chains
    const chainKeys = chainsParam
      ? chainsParam.split(',').filter(k => SUPPORTED_CHAINS[k])
      : Object.keys(SUPPORTED_CHAINS)

    scanning = true
    reply.send({ status: 'scan_started', chains: chainKeys })

    // Run scan in background
    runIncrementalScan(chainKeys, app).finally(() => {
      scanning = false
      lastScanTime = Date.now()
    })
  })

  // GET /v1/monitor/agents/:chain/:id — agent detail
  app.get<{
    Params: { chain: string; id: string }
  }>('/v1/monitor/agents/:chain/:id', async (request, reply) => {
    const { chain, id } = request.params

    // ── Solana agent detail — same pipeline as EVM ─────────────────────
    if (chain === 'solana') {
      let detail: Awaited<ReturnType<typeof getSolanaAgentDetail>>
      try {
        detail = await getSolanaAgentDetail(id)
      } catch (err) {
        app.log.error(`Solana agent fetch failed: ${err}`)
        detail = null
      }
      if (!detail) return reply.status(404).send({ error: 'Agent not found' })

      // Convert Solana txs to AgentTransaction format
      const transactions: any[] = []
      if (detail.wallet) {
        let solTxs: any[] = []
        try { solTxs = await getSolanaWalletTransactions(detail.wallet, 20) } catch {}
        for (const t of solTxs) {
          transactions.push({
            hash: t.hash, from: detail.wallet, to: '', value: 0n,
            blockNumber: BigInt(t.slot ?? 0), timestamp: t.blockTime,
            chain: 'solana', methodName: t.memo ? 'memo' : 'transaction',
            isError: t.isError, tokenName: 'SOL', txType: 'normal',
          })
        }
      }

      // Run SAME analysis pipeline as EVM (even without wallet — use empty wallet)
      const walletAddr = detail.wallet ?? detail.owner
      const slowmist = await runSlowMistAnalysis(detail.agentId, 'solana', walletAddr, transactions)
      const profile = await profileAgent('solana', walletAddr, transactions, {}, {}, {})

      const totalTxs = transactions.length
      const suspiciousTxs = transactions.filter(t => t.riskLevel === 'suspicious').length
      const dangerousTxs = transactions.filter(t => t.riskLevel === 'dangerous').length
      const failedTxs = transactions.filter(t => t.isError).length
      // Unified Score (same formula as EVM)
      let securityScore: number | null = null
      {
        const dim = profile.dimensions
        const dimAvg = (dim.fundSafety + dim.logicTransparency + dim.compliance + dim.techStability + dim.behaviorConsistency) / 5
        const rugPenalty = Math.round(profile.rugPullIndex.score * 0.3)
        const gasPenalty = profile.gasAnomaly.detected ? 5 : 0
        const driftPenalty = Math.round(profile.logicDrift.score * 0.15)
        const checklistWorst = Math.max(...slowmist.checklist.map(c => c.score), 0)
        const checklistPenalty = Math.round(checklistWorst * 0.2)
        if (totalTxs === 0) {
          securityScore = Math.min(50, Math.round(dimAvg) - rugPenalty)
        } else {
          securityScore = Math.max(0, Math.min(100, Math.round(dimAvg) - rugPenalty - gasPenalty - driftPenalty - checklistPenalty))
        }
      }

      // Build findings from checklist
      const findings: any[] = []
      for (const item of slowmist.checklist) {
        findings.push({
          severity: item.status === 'fail' ? 'critical' : item.status === 'warn' ? 'warning' : 'info',
          title: `Step ${item.step}: ${item.name} — ${item.status.toUpperCase()}`,
          detail: item.findings.join(' · '),
          source: item.source,
        })
      }
      // Unified verdict
      const verdictLabel = securityScore >= 80 ? 'SAFE' : securityScore >= 50 ? 'CAUTION' : securityScore >= 30 ? 'HIGH RISK' : 'REJECT'
      const deductions: string[] = []
      if (profile.rugPullIndex.score > 0) deductions.push(`Rug-Pull ${profile.rugPullIndex.score}/100 (-${Math.round(profile.rugPullIndex.score * 0.3)})`)
      if (profile.gasAnomaly.detected) deductions.push(`Gas anomaly (-5)`)
      if (profile.logicDrift.score > 0) deductions.push(`Logic drift ${profile.logicDrift.score}% (-${Math.round(profile.logicDrift.score * 0.15)})`)
      findings.unshift({
        severity: securityScore >= 80 ? 'info' : securityScore >= 50 ? 'warning' : 'critical',
        title: `Verdict: ${verdictLabel} (Score ${securityScore}/100)`,
        detail: deductions.length > 0 ? `Deductions: ${deductions.join(', ')}. Final: ${securityScore}/100.` : `No deductions. Score: ${securityScore}/100.`,
        source: 'Unified Security Score',
      })

      // Add Solana-specific reputation info
      if (detail.totalFeedback > 0) {
        findings.push({ severity: 'info', title: `${detail.totalFeedback} on-chain feedback on Solana Registry`, detail: `Average rating: ${detail.stats?.averageRating ?? 'N/A'}`, source: 'Solana Agent Registry' })
      } else {
        findings.push({ severity: 'info', title: 'No on-chain reputation', detail: 'No feedback on Solana Agent Registry.', source: 'Solana Agent Registry' })
      }

      const counterparties = new Set<string>()
      for (const tx of transactions) {
        if (tx.to) counterparties.add(tx.to)
      }

      return reply.send({
        agentId: detail.agentId, chain: 'solana', chainLabel: 'Solana',
        wallet: detail.wallet, uri: null, name: detail.name, description: detail.description,
        reputation: detail.stats ? {
          feedbackCount: detail.stats.totalFeedbackCount,
          summaryValue: detail.stats.averageRating ?? 0,
          clients: detail.feedback.map(f => f.client).filter(Boolean),
        } : { feedbackCount: detail.totalFeedback, summaryValue: 0, clients: [] },
        transactions: transactions.map(t => ({
          hash: t.hash, from: t.from, to: t.to, value: (t.value ?? 0n).toString(),
          blockNumber: (t.blockNumber ?? 0n).toString(), timestamp: t.timestamp,
          chain: 'solana', methodName: t.methodName, isError: t.isError,
          tokenName: t.tokenName, txType: t.txType,
          riskLevel: t.riskLevel ?? 'safe', riskFlags: t.riskFlags ?? [],
          riskScore: (t as any).riskScore ?? 0,
        })),
        securityAnalysis: {
          score: securityScore,
          totalTransactions: totalTxs,
          safe: totalTxs - suspiciousTxs - dangerousTxs,
          suspicious: suspiciousTxs, dangerous: dangerousTxs,
          failed: failedTxs,
          uniqueCounterparties: counterparties.size,
          findings,
        },
        slowmistReport: {
          overallScore: slowmist.overallScore, riskLevel: slowmist.riskLevel,
          verdict: slowmist.verdict, verdictReason: slowmist.verdictReason,
          summary: slowmist.summary, behaviorTags: slowmist.behaviorTags,
          activityLevel: slowmist.activityLevel, fundingSource: slowmist.fundingSource,
          checklist: slowmist.checklist, metadata: slowmist.metadata,
        },
        profile: {
          dimensions: profile.dimensions, overallGrade: profile.overallGrade,
          rugPullIndex: profile.rugPullIndex, gasAnomaly: profile.gasAnomaly,
          logicDrift: profile.logicDrift, alerts: profile.alerts,
        },
        ownerAnalysis: null,
      })
    }

    // ── EVM agent detail ─────────────────────────────────────────────────
    if (!SUPPORTED_CHAINS[chain]) {
      return reply.status(400).send({ error: `Unsupported chain: ${chain}` })
    }

    const agentId = BigInt(id)

    const [metadata, reputation] = await Promise.all([
      enrichAgent(chain, agentId),
      getAgentReputation(chain, agentId),
    ])

    let transactions: Awaited<ReturnType<typeof getAgentTransactions>> = []
    if (metadata.wallet) {
      transactions = await getAgentTransactions(chain, metadata.wallet, 30)
    }

    // ── Get owner info for cross-chain correlation ──────────────────────
    const ownerInfo = await getOwnerAnalysis(chain, id)
    const ownerAgentCount = ownerInfo?.totalAgents ?? 1
    const ownerRiskScore = ownerInfo?.riskScore ?? 0

    // ── Run full on-chain security checklist ──────────────────────────
    const slowmist = metadata.wallet
      ? await runSlowMistAnalysis(id, chain, metadata.wallet, transactions, ownerAgentCount, ownerRiskScore)
      : null

    // ── Run multi-dimension profiler ────────────────────────────────
    // Extract analysis data from slowmist for profiler input
    const addressRes: Record<string, { score: number; flags: string[] }> = {}
    const contractRes: Record<string, string[]> = {}
    const tokenRes: Record<string, string[]> = {}
    if (slowmist) {
      // Rebuild from checklist findings (the data was computed in slowmist)
      for (const item of slowmist.checklist) {
        if (item.step === 1) {
          for (const f of item.findings) {
            const match = f.match(/^(.+?)\.\.\. flagged: (.+)$/)
            if (match) addressRes[match[1]] = { score: item.score, flags: match[2].split(', ') }
          }
        }
        if (item.step === 2) {
          for (const f of item.findings) {
            const match = f.match(/^(.+?)\.\.\.: (.+)$/)
            if (match) contractRes[match[1]] = match[2].split(', ')
          }
        }
        if (item.step === 3) {
          for (const f of item.findings) {
            const match = f.match(/^(.+?): (.+)$/)
            if (match) tokenRes[match[1]] = match[2].split(', ')
          }
        }
      }
    }
    const profile = metadata.wallet
      ? await profileAgent(chain, metadata.wallet, transactions, addressRes, contractRes, tokenRes)
      : null

    const totalTxs = transactions.length
    const suspiciousTxs = transactions.filter(t => t.riskLevel === 'suspicious').length
    const dangerousTxs = transactions.filter(t => t.riskLevel === 'dangerous').length
    const failedTxs = transactions.filter(t => t.isError).length

    // ── Deep Analysis (26 dimensions) ───────────────────────────────
    const goplusChainId = { ethereum: '1', bsc: '56', polygon: '137', arbitrum: '42161', base: '8453', optimism: '10' }[chain] ?? ''

    // Collect all agent wallets for graph analysis
    const allWalletsResult = await db.execute(sql.raw(
      `SELECT agent_id, wallet FROM erc8004_agents WHERE wallet IS NOT NULL AND chain = '${chain}' LIMIT 100`
    )).catch(() => [])
    const allAgentWallets: Record<string, string> = {}
    for (const r of allWalletsResult as any[]) {
      if (r.wallet) allAgentWallets[r.agent_id] = r.wallet
    }

    let deepAnalysis: DeepAnalysis | null = null
    if (metadata.wallet && totalTxs > 0) {
      deepAnalysis = await runDeepAnalysis(goplusChainId, metadata.wallet, transactions, metadata.uri ?? null, allAgentWallets).catch(() => null)
    }

    // ── Unified Score: combines ALL factors ──────────────────────────
    let securityScore: number | null = null
    if (slowmist && profile) {
      const dim = profile.dimensions
      const dimAvg = (dim.fundSafety + dim.logicTransparency + dim.compliance + dim.techStability + dim.behaviorConsistency) / 5

      // Penalties from profiler
      const rugPenalty = Math.round(profile.rugPullIndex.score * 0.3)
      const gasPenalty = profile.gasAnomaly.detected ? 5 : 0
      const driftPenalty = Math.round(profile.logicDrift.score * 0.15)

      // Penalty from checklist
      const checklistWorst = Math.max(...slowmist.checklist.map(c => c.score), 0)
      const checklistPenalty = Math.round(checklistWorst * 0.2)

      // Penalty from deep analysis (capped at 20 to avoid double-counting)
      const deepPenalty = Math.min(20, deepAnalysis?.totalPenalty ?? 0)

      if (totalTxs === 0) {
        securityScore = Math.min(50, Math.round(dimAvg) - rugPenalty)
      } else {
        securityScore = Math.max(0, Math.min(100,
          Math.round(dimAvg) - rugPenalty - gasPenalty - driftPenalty - checklistPenalty - deepPenalty
        ))
      }
    }

    // Save to DB
    if (profile && securityScore !== null && chain !== 'solana') {
      await db.execute(sql.raw(
        `UPDATE erc8004_agents SET security_score = ${securityScore}, tx_count = ${totalTxs}, scored_at = NOW() WHERE chain = '${chain}' AND agent_id = '${id}'`
      )).catch(() => {})
      await db.execute(sql.raw(
        `INSERT INTO erc8004_dimensions (agent_id, chain, fund_safety, logic_transparency, compliance, tech_stability, behavior_consistency, rug_pull_index, gas_anomaly_score, scored_at)
         VALUES ('${id}', '${chain}', ${profile.dimensions.fundSafety}, ${profile.dimensions.logicTransparency}, ${profile.dimensions.compliance}, ${profile.dimensions.techStability}, ${profile.dimensions.behaviorConsistency}, ${profile.rugPullIndex.score}, ${profile.gasAnomaly.detected ? 50 : 0}, NOW())
         ON CONFLICT (chain, agent_id) DO UPDATE SET
           fund_safety = EXCLUDED.fund_safety, logic_transparency = EXCLUDED.logic_transparency,
           compliance = EXCLUDED.compliance, tech_stability = EXCLUDED.tech_stability,
           behavior_consistency = EXCLUDED.behavior_consistency, rug_pull_index = EXCLUDED.rug_pull_index,
           gas_anomaly_score = EXCLUDED.gas_anomaly_score, scored_at = NOW()`
      )).catch(() => {})
      for (const alert of profile.alerts) {
        await db.execute(sql.raw(
          `INSERT INTO erc8004_alerts (agent_id, chain, alert_type, severity, title, detail)
           VALUES ('${id}', '${chain}', '${alert.alertType}', '${alert.severity}', '${alert.title.replace(/'/g, "''")}', '${(alert.detail ?? '').replace(/'/g, "''")}')`
        )).catch(() => {})
      }
    }

    // Convert SlowMist checklist to findings
    const findings: { severity: 'info' | 'warning' | 'critical'; title: string; detail: string; source: string }[] = []

    // Convert SlowMist checklist items to findings
    if (slowmist) {
      for (const item of slowmist.checklist) {
        const severity = item.status === 'fail' ? 'critical' as const : item.status === 'warn' ? 'warning' as const : 'info' as const
        findings.push({
          severity,
          title: `Step ${item.step}: ${item.name} — ${item.status.toUpperCase()}`,
          detail: item.findings.join(' · '),
          source: item.source,
        })
      }

      // Add ERC-8004 identity/reputation findings
      if (!metadata.uri) {
        findings.push({ severity: 'info', title: 'No metadata URI registered', detail: 'No tokenURI set — off-chain identity unverifiable.', source: 'ERC-8004 Identity Registry' })
      }
      if (!reputation || reputation.feedbackCount === 0) {
        findings.push({ severity: 'info', title: 'No on-chain reputation', detail: 'Zero feedback on ERC-8004 Reputation Registry. Trust level undetermined.', source: 'ERC-8004 Reputation Registry' })
      } else if (reputation.summaryValue < 0) {
        findings.push({ severity: 'critical', title: `Negative reputation: ${reputation.summaryValue.toFixed(1)}`, detail: `${reputation.feedbackCount} reviews, negative score.`, source: 'ERC-8004 Reputation Registry' })
      } else {
        findings.push({ severity: 'info', title: `Reputation: ${reputation.summaryValue.toFixed(1)}`, detail: `${reputation.feedbackCount} reviews from ${reputation.clients.length} reviewers.`, source: 'ERC-8004 Reputation Registry' })
      }

      // Overall verdict using UNIFIED score
      const verdictLabel = securityScore !== null
        ? (securityScore >= 80 ? 'SAFE' : securityScore >= 50 ? 'CAUTION' : securityScore >= 30 ? 'HIGH RISK' : 'REJECT')
        : 'UNKNOWN'
      const verdictSeverity = securityScore !== null
        ? (securityScore >= 80 ? 'info' as const : securityScore >= 50 ? 'warning' as const : 'critical' as const)
        : 'warning' as const

      // Build unified reason
      const deductions: string[] = []
      if (profile) {
        if (profile.rugPullIndex.score > 0) deductions.push(`Rug-Pull ${profile.rugPullIndex.score}/100 (-${Math.round(profile.rugPullIndex.score * 0.3)})`)
        if (profile.gasAnomaly.detected) deductions.push(`Gas anomaly (-5)`)
        if (profile.logicDrift.score > 0) deductions.push(`Logic drift ${profile.logicDrift.score}% (-${Math.round(profile.logicDrift.score * 0.15)})`)
      }
      const checklistWorstVal = Math.max(...slowmist.checklist.map(c => c.score), 0)
      if (checklistWorstVal > 0) deductions.push(`Checklist (-${Math.round(checklistWorstVal * 0.2)})`)
      if (deepAnalysis && deepAnalysis.totalPenalty > 0) {
        const deepCapped = Math.min(20, deepAnalysis.totalPenalty)
        deductions.push(`Deep analysis: ${deepAnalysis.penalties.map(p => p.reason).slice(0, 3).join('; ')} (-${deepCapped})`)
      }

      const verdictDetail = deductions.length > 0
        ? `Deductions: ${deductions.join(' · ')}. Final: ${securityScore}/100.`
        : `All checks passed. No deductions. Score: ${securityScore}/100.`

      findings.unshift({
        severity: verdictSeverity,
        title: `Verdict: ${verdictLabel} (Score ${securityScore}/100)`,
        detail: verdictDetail,
        source: 'Unified Security Score',
      })
    } else {
      findings.push({ severity: 'warning', title: 'No wallet bound via ERC-8004', detail: 'Cannot run security analysis without a wallet address.', source: 'ERC-8004 Identity Registry' })
    }

    // Counterparties for response
    const counterparties = new Set<string>()
    for (const tx of transactions) {
      if (tx.from?.toLowerCase() === metadata.wallet?.toLowerCase()) counterparties.add(tx.to)
      else counterparties.add(tx.from)
    }

    // ── Fetch agent description + capabilities + endpoints ─────────
    let agentName: string | null = null
    let agentDescription: string | null = null
    if (metadata.uri) {
      try {
        let regData: any = null
        if (metadata.uri.startsWith('data:application/json;base64,')) {
          regData = JSON.parse(Buffer.from(metadata.uri.replace('data:application/json;base64,', ''), 'base64').toString())
        } else if (metadata.uri.startsWith('http')) {
          const regRes = await fetch(metadata.uri, { signal: AbortSignal.timeout(5000) }).catch(() => null)
          if (regRes?.ok) regData = await regRes.json()
        }
        if (regData) {
          agentName = regData.name ?? null
          agentDescription = regData.description ?? null
        }
      } catch {}
    }

    // Get indexed capabilities + endpoints from DB
    const capsResult = await db.execute(sql.raw(
      `SELECT capability, category, confidence, source FROM agent_capabilities WHERE agent_id = '${id}' AND chain = '${chain}' ORDER BY confidence DESC`
    )).catch(() => [])
    const epsResult = await db.execute(sql.raw(
      `SELECT endpoint_type, url, status, tools_count, tools_list FROM agent_endpoints WHERE agent_id = '${id}' AND chain = '${chain}'`
    )).catch(() => [])

    return reply.send({
      agentId: id,
      chain,
      chainLabel: SUPPORTED_CHAINS[chain].label,
      ...metadata,
      name: agentName,
      description: agentDescription,
      capabilities: (capsResult as any[]).map(r => ({ capability: r.capability, category: r.category, confidence: Number(r.confidence), source: r.source })),
      endpoints: (epsResult as any[]).map(r => ({ type: r.endpoint_type, url: r.url, status: r.status, toolsCount: Number(r.tools_count), tools: r.tools_list })),
      reputation: reputation ? {
        feedbackCount: reputation.feedbackCount,
        summaryValue: reputation.summaryValue,
        clients: reputation.clients,
      } : null,
      transactions: transactions.map(t => ({
        hash: t.hash,
        from: t.from,
        to: t.to,
        value: t.value.toString(),
        blockNumber: t.blockNumber.toString(),
        timestamp: t.timestamp,
        chain: t.chain,
        methodName: t.methodName,
        isError: t.isError,
        tokenName: t.tokenName,
        tokenDecimals: t.tokenDecimals,
        txType: t.txType,
        riskLevel: t.riskLevel,
        riskFlags: t.riskFlags,
        riskScore: (t as any).riskScore ?? 0,
      })),
      securityAnalysis: {
        score: securityScore,
        totalTransactions: totalTxs,
        safe: totalTxs - suspiciousTxs - dangerousTxs,
        suspicious: suspiciousTxs,
        dangerous: dangerousTxs,
        failed: failedTxs,
        uniqueCounterparties: counterparties.size,
        findings,
      },
      slowmistReport: slowmist ? {
        overallScore: slowmist.overallScore,
        riskLevel: slowmist.riskLevel,
        verdict: slowmist.verdict,
        verdictReason: slowmist.verdictReason,
        summary: slowmist.summary,
        behaviorTags: slowmist.behaviorTags,
        activityLevel: slowmist.activityLevel,
        fundingSource: slowmist.fundingSource,
        checklist: slowmist.checklist,
        metadata: slowmist.metadata,
      } : null,
      ownerAnalysis: ownerInfo,
      deepAnalysis: deepAnalysis ? {
        approvalRisks: deepAnalysis.approvalRisks,
        claimConsistency: deepAnalysis.claimConsistency,
        graph: { nodes: deepAnalysis.graph.nodes.length, edges: deepAnalysis.graph.edges.length, rings: deepAnalysis.graph.rings.length, stars: deepAnalysis.graph.stars },
        amountDistribution: deepAnalysis.amountDistribution,
        probePattern: deepAnalysis.probePattern,
        frequencyTrend: deepAnalysis.frequencyTrend,
        scheduledPattern: deepAnalysis.scheduledPattern,
        redFlagMatches: deepAnalysis.redFlagMatches,
        socialEngineeringMatches: deepAnalysis.socialEngineeringMatches,
        penalties: deepAnalysis.penalties,
        totalPenalty: deepAnalysis.totalPenalty,
      } : null,
      // Multi-dimension profile
      profile: profile ? {
        dimensions: profile.dimensions,
        overallGrade: profile.overallGrade,
        rugPullIndex: profile.rugPullIndex,
        gasAnomaly: profile.gasAnomaly,
        logicDrift: profile.logicDrift,
        alerts: profile.alerts,
      } : null,
    })
  })

  // GET /v1/monitor/risk-report — reads from DB (instant), only analyzes new agents
  app.get<{ Querystring: { sample?: string } }>(
    '/v1/monitor/risk-report',
    async (request, reply) => {
      // 1. Read ALL scored agents from DB (instant)
      const scoredRows = await db.execute(sql.raw(
        `SELECT agent_id, chain, owner, security_score, tx_count, top_flag FROM erc8004_agents WHERE security_score IS NOT NULL ORDER BY security_score ASC`
      ))
      const dbScored = (scoredRows as any[]).map(r => ({
        agentId: r.agent_id, chain: r.chain, owner: r.owner,
        score: Number(r.security_score), topFlag: r.top_flag ?? '', txCount: Number(r.tx_count ?? 0),
      }))

      // 2. Read dimension data from DB
      const dimRows = await db.execute(sql.raw(
        `SELECT * FROM erc8004_dimensions ORDER BY scored_at DESC LIMIT 100`
      ))
      const dimensions = (dimRows as any[]).map(r => ({
        agentId: r.agent_id, chain: r.chain,
        fundSafety: Number(r.fund_safety), logicTransparency: Number(r.logic_transparency),
        compliance: Number(r.compliance), techStability: Number(r.tech_stability),
        behaviorConsistency: Number(r.behavior_consistency), rugPullIndex: Number(r.rug_pull_index),
      }))

      // 3. Read recent alerts
      const alertRows = await db.execute(sql.raw(
        `SELECT alert_type, severity, COUNT(*) as cnt FROM erc8004_alerts GROUP BY alert_type, severity ORDER BY cnt DESC LIMIT 20`
      ))
      const topFlags = (alertRows as any[]).map(r => ({
        flag: r.alert_type, count: Number(r.cnt), label: r.alert_type.replace(/_/g, ' '),
        pct: 0,
      }))

      // Compute aggregates
      const allScored = dbScored
      const totalTxs = allScored.reduce((s, a) => s + a.txCount, 0)
      const flaggedAgents = allScored.filter(a => a.score < 70 && a.txCount > 0)

      // Count wallets
      const noWalletResult = await db.execute(sql.raw(
        `SELECT COUNT(*) as cnt FROM erc8004_agents WHERE wallet IS NULL`
      ))
      const noWallet = Number((noWalletResult as any[])[0]?.cnt ?? 0)

      // Estimate risk breakdown from dimension data
      let totalSafe = 0, totalSuspicious = 0, totalDangerous = 0
      for (const a of allScored) {
        if (a.score >= 80) totalSafe++
        else if (a.score >= 50) totalSuspicious++
        else totalDangerous++
      }

      const totalRated = totalSafe + totalSuspicious + totalDangerous

      return reply.send({
        analyzed: allScored.length,
        totalTransactions: totalRated,
        risk: {
          safe: totalSafe,
          suspicious: totalSuspicious,
          dangerous: totalDangerous,
          failed: 0,
          noWallet,
        },
        topFlags,
        flaggedAgents: flaggedAgents.sort((a, b) => a.score - b.score).slice(0, 10),
        agentScores: allScored,
        dimensions,
      })
    },
  )

  // GET /v1/monitor/timeline?chain=ethereum&agentId=31939&limit=50
  app.get<{ Querystring: { chain?: string; agentId?: string; limit?: string } }>(
    '/v1/monitor/timeline',
    async (request, reply) => {
      const { chain, agentId, limit: limitParam } = request.query
      const limit = Math.min(Number(limitParam ?? 50), 200)

      let query = `SELECT * FROM erc8004_alerts`
      const conditions: string[] = []
      if (chain) conditions.push(`chain = '${chain}'`)
      if (agentId) conditions.push(`agent_id = '${agentId}'`)
      if (conditions.length > 0) query += ` WHERE ${conditions.join(' AND ')}`
      query += ` ORDER BY created_at DESC LIMIT ${limit}`

      const result = await db.execute(sql.raw(query))
      return reply.send({
        alerts: (result as any[]).map(r => ({
          id: r.id,
          agentId: r.agent_id,
          chain: r.chain,
          alertType: r.alert_type,
          severity: r.severity,
          title: r.title,
          detail: r.detail,
          createdAt: r.created_at,
        })),
      })
    },
  )

  // GET /v1/monitor/heatmap — sector-level safety overview
  app.get('/v1/monitor/heatmap', async (_request, reply) => {
    // Primary: dimension scores by chain
    const dimResult = await db.execute(sql.raw(`
      SELECT chain,
        COUNT(*) as agent_count,
        AVG(fund_safety) as avg_fund_safety,
        AVG(logic_transparency) as avg_logic_transparency,
        AVG(compliance) as avg_compliance,
        AVG(tech_stability) as avg_tech_stability,
        AVG(behavior_consistency) as avg_behavior_consistency,
        AVG(rug_pull_index) as avg_rug_pull
      FROM erc8004_dimensions
      GROUP BY chain
    `))

    // Fallback: chains with security_score but no dimensions
    const scoreResult = await db.execute(sql.raw(`
      SELECT chain, COUNT(*) as agent_count, AVG(security_score) as avg_score
      FROM erc8004_agents
      WHERE security_score IS NOT NULL
      AND chain NOT IN (SELECT DISTINCT chain FROM erc8004_dimensions)
      GROUP BY chain
    `))

    const sectors: any[] = []

    // Add dimension-based chains
    for (const r of dimResult as any[]) {
      sectors.push({
        chain: r.chain,
        label: SUPPORTED_CHAINS[r.chain]?.label ?? r.chain,
        color: SUPPORTED_CHAINS[r.chain]?.color ?? '#888',
        agentCount: Number(r.agent_count),
        avgScores: {
          fundSafety: Math.round(Number(r.avg_fund_safety ?? 0)),
          logicTransparency: Math.round(Number(r.avg_logic_transparency ?? 0)),
          compliance: Math.round(Number(r.avg_compliance ?? 0)),
          techStability: Math.round(Number(r.avg_tech_stability ?? 0)),
          behaviorConsistency: Math.round(Number(r.avg_behavior_consistency ?? 0)),
        },
        avgRugPull: Math.round(Number(r.avg_rug_pull ?? 0)),
        overallSafety: Math.round(
          (Number(r.avg_fund_safety ?? 0) + Number(r.avg_logic_transparency ?? 0) +
           Number(r.avg_compliance ?? 0) + Number(r.avg_tech_stability ?? 0) +
           Number(r.avg_behavior_consistency ?? 0)) / 5
        ),
      })
    }

    // Add fallback chains (use security_score as overallSafety)
    for (const r of scoreResult as any[]) {
      const avg = Math.round(Number(r.avg_score ?? 0))
      sectors.push({
        chain: r.chain,
        label: SUPPORTED_CHAINS[r.chain]?.label ?? r.chain,
        color: SUPPORTED_CHAINS[r.chain]?.color ?? '#888',
        agentCount: Number(r.agent_count),
        avgScores: { fundSafety: avg, logicTransparency: avg, compliance: avg, techStability: avg, behaviorConsistency: avg },
        avgRugPull: 0,
        overallSafety: avg,
      })
    }

    return reply.send({ sectors })
  })

  // GET /v1/monitor/stats
  app.get('/v1/monitor/stats', async (_request, reply) => {
    const countResult = await db.execute(sql.raw(
      `SELECT chain, chain_label, COUNT(*) as count FROM erc8004_agents GROUP BY chain, chain_label`
    ))
    const rows = countResult as any[]

    const totalAgents = rows.reduce((s, r) => s + Number(r.count), 0)

    const ownerResult = await db.execute(sql.raw(
      `SELECT COUNT(DISTINCT owner) as unique_owners FROM erc8004_agents`
    ))
    const uniqueOwners = Number((ownerResult as any[])[0]?.unique_owners ?? 0)

    // Add Solana stats
    let solanaCount = 0
    try {
      const solStats = await getSolanaGlobalStats()
      if (solStats) solanaCount = solStats.totalAgents
    } catch {}

    const byChain = rows.map(r => ({
      chain: r.chain,
      label: r.chain_label,
      color: SUPPORTED_CHAINS[r.chain]?.color ?? '#888',
      count: Number(r.count),
    }))
    if (solanaCount > 0) {
      byChain.push({ chain: 'solana', label: 'Solana', color: '#9945FF', count: solanaCount })
    }

    return reply.send({
      totalAgents: totalAgents + solanaCount,
      uniqueOwners,
      byChain,
      scanning,
      lastScanTime,
    })
  })

  // Auto-scan on first boot if DB is empty
  const existing = await db.execute(sql.raw('SELECT COUNT(*) as cnt FROM erc8004_agents'))
  if (Number((existing as any[])[0]?.cnt ?? 0) === 0) {
    app.log.info('[monitor] No cached agents — starting initial scan in background')
    scanning = true
    runIncrementalScan(Object.keys(SUPPORTED_CHAINS), app).finally(() => {
      scanning = false
      lastScanTime = Date.now()
    })
  }
}

// ── Owner Analysis ───────────────────────────────────────────────────────────

async function getOwnerAnalysis(chain: string, agentId: string) {
  try {
    // Get this agent's owner
    const agentRow = await db.execute(sql.raw(
      `SELECT owner, chain FROM erc8004_agents WHERE agent_id = '${agentId}' AND chain = '${chain}' LIMIT 1`
    ))
    const agent = (agentRow as any[])[0]
    if (!agent) return null

    const owner = agent.owner

    // Count how many agents this owner has across all chains
    const countResult = await db.execute(sql.raw(
      `SELECT chain, chain_label, COUNT(*) as count FROM erc8004_agents WHERE owner = '${owner}' GROUP BY chain, chain_label`
    ))
    const byChain = (countResult as any[]).map(r => ({ chain: r.chain, label: r.chain_label, count: Number(r.count) }))
    const totalAgents = byChain.reduce((s, r) => s + r.count, 0)

    // Get the agent IDs owned
    const agentListResult = await db.execute(sql.raw(
      `SELECT agent_id, chain, chain_label FROM erc8004_agents WHERE owner = '${owner}' ORDER BY block_number DESC LIMIT 20`
    ))
    const ownedAgents = (agentListResult as any[]).map(r => ({ agentId: r.agent_id, chain: r.chain, chainLabel: r.chain_label }))

    // Check owner address risk via GoPlus
    const goplusChainId = { ethereum: '1', bsc: '56', polygon: '137', arbitrum: '42161', base: '8453', optimism: '10' }[chain]
    let ownerRisk: { score: number; flags: string[] } = { score: 0, flags: [] }
    if (goplusChainId) {
      try {
        const res = await fetch(
          `https://api.gopluslabs.io/api/v1/address_security/${owner}?chain_id=${goplusChainId}`,
          { signal: AbortSignal.timeout(3000) },
        )
        if (res.ok) {
          const data: any = await res.json()
          const r = data.result ?? {}
          const flags: string[] = []
          let score = 0
          if (r.is_blacklisted === '1') { flags.push('blacklisted'); score = 100 }
          if (r.is_phishing_activities === '1') { flags.push('phishing'); score = Math.max(score, 95) }
          if (r.is_sanctioned === '1') { flags.push('sanctioned'); score = Math.max(score, 100) }
          if (r.is_mixer === '1') { flags.push('mixer'); score = Math.max(score, 70) }
          if (r.cybercrime === '1') { flags.push('cybercrime'); score = Math.max(score, 90) }
          ownerRisk = { score, flags }
        }
      } catch {}
    }

    // ── Cross-agent interaction analysis ────────────────────────────────
    // Check if sibling agents' wallets have transacted with each other
    // Enrich wallets for siblings that don't have one cached
    const siblingWallets: Record<string, string> = {} // agentId → wallet
    for (const a of ownedAgents) {
      // Check DB first
      const row = await db.execute(sql.raw(
        `SELECT wallet FROM erc8004_agents WHERE agent_id = '${a.agentId}' AND chain = '${a.chain}' LIMIT 1`
      ))
      const wallet = (row as any[])[0]?.wallet
      if (wallet) {
        siblingWallets[a.agentId] = wallet.toLowerCase()
      } else {
        // Try to enrich on the fly (limit to 5 to avoid slowness)
        if (Object.keys(siblingWallets).length < 5) {
          try {
            const meta = await enrichAgent(a.chain, BigInt(a.agentId))
            if (meta.wallet) {
              siblingWallets[a.agentId] = meta.wallet.toLowerCase()
              // Cache it
              await db.execute(sql.raw(`UPDATE erc8004_agents SET wallet = '${meta.wallet}' WHERE chain = '${a.chain}' AND agent_id = '${a.agentId}'`))
            }
          } catch {}
        }
      }
    }

    // For each pair of sibling wallets, check if they share counterparties
    // by fetching recent txs for up to 3 siblings
    const interactions: { from: string; fromAgent: string; to: string; toAgent: string; chain: string }[] = []
    const siblingEntries = Object.entries(siblingWallets).slice(0, 5)
    const siblingWalletSet = new Set(Object.values(siblingWallets))

    for (const [sibAgentId, sibWallet] of siblingEntries) {
      try {
        const txs = await getAgentTransactions(chain, sibWallet, 15)
        for (const tx of txs) {
          const to = tx.to?.toLowerCase() ?? ''
          const from = tx.from?.toLowerCase() ?? ''
          // Check if this tx is to/from another sibling wallet
          if (siblingWalletSet.has(to) && to !== sibWallet) {
            const toAgent = Object.entries(siblingWallets).find(([_, w]) => w === to)?.[0] ?? '?'
            interactions.push({ from: sibWallet, fromAgent: sibAgentId, to, toAgent, chain })
          }
          if (siblingWalletSet.has(from) && from !== sibWallet) {
            const fromAgent = Object.entries(siblingWallets).find(([_, w]) => w === from)?.[0] ?? '?'
            interactions.push({ from, fromAgent, to: sibWallet, toAgent: sibAgentId, chain })
          }
        }
      } catch {}
    }

    // Deduplicate interactions
    const seen = new Set<string>()
    const uniqueInteractions = interactions.filter(i => {
      const key = [i.fromAgent, i.toAgent].sort().join('-')
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })

    return {
      address: owner,
      totalAgents,
      byChain,
      ownedAgents,
      siblingWallets: Object.entries(siblingWallets).map(([id, w]) => ({ agentId: id, wallet: w })),
      interactions: uniqueInteractions,
      riskScore: ownerRisk.score,
      riskFlags: ownerRisk.flags,
      riskLevel: ownerRisk.score >= 91 ? 'malicious' : ownerRisk.score >= 31 ? 'suspicious' : 'clean',
    }
  } catch {
    return null
  }
}

// ── Incremental Scan ─────────────────────────────────────────────────────────

async function runIncrementalScan(chainKeys: string[], app: FastifyInstance) {
  for (const chainKey of chainKeys) {
    try {
      // Get cursor: where did we stop last time?
      const cursorRows = await db.execute(sql.raw(
        `SELECT last_block FROM erc8004_scan_cursors WHERE chain = '${chainKey}'`
      ))
      const lastBlock = (cursorRows as any[])[0]?.last_block
      const fromBlock = lastBlock ? BigInt(lastBlock) + 1n : undefined

      app.log.info(`[monitor] Scanning ${chainKey} from block ${fromBlock?.toString() ?? 'default'}...`)

      const agents = await getRegisteredAgents(chainKey, fromBlock ?? 0n)

      if (agents.length > 0) {
        // Upsert agents into DB + enrich wallet
        for (const a of agents) {
          let wallet: string | null = null
          try {
            const meta = await enrichAgent(chainKey, a.agentId)
            wallet = meta.wallet ?? null
          } catch {}

          await db.execute(sql.raw(
            `INSERT INTO erc8004_agents (agent_id, owner, chain, chain_label, block_number, tx_hash, wallet)
             VALUES ('${a.agentId.toString()}', '${a.owner}', '${a.chain}', '${a.chainLabel}', '${a.blockNumber.toString()}', '${a.txHash}', ${wallet ? `'${wallet}'` : 'NULL'})
             ON CONFLICT (chain, agent_id) DO UPDATE SET
               owner = EXCLUDED.owner,
               block_number = EXCLUDED.block_number,
               tx_hash = EXCLUDED.tx_hash,
               wallet = COALESCE(EXCLUDED.wallet, erc8004_agents.wallet)`
          ))
        }

        // Update cursor to latest block
        const maxBlock = agents.reduce((max, a) => a.blockNumber > max ? a.blockNumber : max, 0n)
        await db.execute(sql.raw(
          `INSERT INTO erc8004_scan_cursors (chain, last_block, agent_count, updated_at)
           VALUES ('${chainKey}', '${maxBlock.toString()}', ${agents.length}, NOW())
           ON CONFLICT (chain) DO UPDATE SET
             last_block = EXCLUDED.last_block,
             agent_count = erc8004_scan_cursors.agent_count + EXCLUDED.agent_count,
             updated_at = NOW()`
        ))
      } else {
        // No new agents but update cursor to current block so next scan is fast
        const { createPublicClient, http } = await import('viem')
        const config = SUPPORTED_CHAINS[chainKey]
        const client = createPublicClient({ chain: config.chain, transport: http(config.rpcUrl) })
        const currentBlock = await client.getBlockNumber()

        await db.execute(sql.raw(
          `INSERT INTO erc8004_scan_cursors (chain, last_block, agent_count, updated_at)
           VALUES ('${chainKey}', '${currentBlock.toString()}', 0, NOW())
           ON CONFLICT (chain) DO UPDATE SET
             last_block = '${currentBlock.toString()}',
             updated_at = NOW()`
        ))
      }

      app.log.info(`[monitor] ${chainKey}: found ${agents.length} new agents`)
    } catch (err) {
      app.log.error(`[monitor] Scan failed for ${chainKey}: ${err}`)
    }
  }
}
