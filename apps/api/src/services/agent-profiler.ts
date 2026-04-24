/**
 * Agent Profiler — Multi-Dimension Security Analysis
 *
 * Produces a professional risk profile covering:
 *   1. Fund Safety         — rug-pull index, TVL risk, capital flow
 *   2. Logic Transparency  — contract verified, proxy, owner perms
 *   3. Compliance          — address blacklist, sanctions, AML
 *   4. Tech Stability      — failure rate, gas anomaly, infra dependency
 *   5. Behavior Consistency — logic drift, velocity change, pattern shift
 *
 * Each dimension scored 0-100 (higher = safer).
 * Also produces: rug-pull index, gas anomaly alerts, and timeline events.
 */

import type { AgentTransaction } from './erc8004.js'

// ── Types ──────────────────────────────────────────────────────────────────────

export interface DimensionScores {
  fundSafety: number           // 0-100
  logicTransparency: number    // 0-100
  compliance: number           // 0-100
  techStability: number        // 0-100
  behaviorConsistency: number  // 0-100
}

export interface RugPullIndex {
  score: number                // 0-100, higher = more likely rug
  factors: string[]
}

export interface GasAnomaly {
  detected: boolean
  avgGas: number
  maxGas: number
  anomalyTxs: number
  detail: string
}

export interface LogicDrift {
  detected: boolean
  score: number                // 0-100, how much drift
  previousPattern: string
  currentPattern: string
  detail: string
}

export interface AlertEvent {
  alertType: string
  severity: 'info' | 'warning' | 'critical'
  title: string
  detail: string
  metadata?: Record<string, any>
}

export interface AgentProfile {
  dimensions: DimensionScores
  rugPullIndex: RugPullIndex
  gasAnomaly: GasAnomaly
  logicDrift: LogicDrift
  alerts: AlertEvent[]
  overallGrade: 'A' | 'B' | 'C' | 'D' | 'F'
}

// ── GoPlus helpers ─────────────────────────────────────────────────────────────

const GOPLUS_CHAINS: Record<string, string> = {
  ethereum: '1', bsc: '56', polygon: '137',
  arbitrum: '42161', base: '8453', optimism: '10', solana: 'solana',
}

async function goplusFetch(url: string): Promise<any> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) })
    if (!res.ok) return null
    return (await res.json()).result ?? null
  } catch { return null }
}

// ── Dimension 1: Fund Safety ───────────────────────────────────────────────────

async function scoreFundSafety(
  chain: string,
  transactions: AgentTransaction[],
  tokenResults: Record<string, string[]>,
  walletAddress: string,
): Promise<{ score: number; rugPull: RugPullIndex; alerts: AlertEvent[] }> {
  let score = 100
  const rugFactors: string[] = []
  const alerts: AlertEvent[] = []
  const w = walletAddress.toLowerCase()

  // Check token risks (honeypot, hidden mint, high tax)
  for (const [token, flags] of Object.entries(tokenResults)) {
    if (flags.includes('honeypot')) { score -= 40; rugFactors.push('honeypot_token') }
    if (flags.includes('hidden_mint')) { score -= 20; rugFactors.push('hidden_mint') }
    if (flags.some(f => f.includes('tax'))) { score -= 15; rugFactors.push('high_tax') }
    if (flags.includes('cannot_sell_all')) { score -= 25; rugFactors.push('cannot_sell') }
    if (flags.includes('ownership_takeback')) { score -= 20; rugFactors.push('ownership_takeback') }
  }

  // Large outbound concentration (possible drain)
  const outbound = transactions.filter(t => t.from?.toLowerCase() === w && Number(t.value) > 0)
  const totalOutValue = outbound.reduce((s, t) => s + Number(t.value) / Math.pow(10, t.tokenDecimals ?? 18), 0)
  const inbound = transactions.filter(t => t.to?.toLowerCase() === w && Number(t.value) > 0)
  const totalInValue = inbound.reduce((s, t) => s + Number(t.value) / Math.pow(10, t.tokenDecimals ?? 18), 0)

  // Net outflow ratio
  if (totalOutValue > totalInValue * 3 && totalOutValue > 10) {
    score -= 20
    rugFactors.push('heavy_net_outflow')
    alerts.push({ alertType: 'fund_drain', severity: 'warning', title: 'Heavy net outflow detected', detail: `Outbound (${totalOutValue.toFixed(2)}) is 3x+ inbound (${totalInValue.toFixed(2)})` })
  }

  // Single address receiving most outbound
  const outByAddr: Record<string, number> = {}
  for (const tx of outbound) {
    if (tx.to) outByAddr[tx.to.toLowerCase()] = (outByAddr[tx.to.toLowerCase()] ?? 0) + Number(tx.value) / Math.pow(10, tx.tokenDecimals ?? 18)
  }
  const topRecipient = Object.entries(outByAddr).sort((a, b) => b[1] - a[1])[0]
  if (topRecipient && totalOutValue > 0 && topRecipient[1] / totalOutValue > 0.8) {
    score -= 10
    rugFactors.push('concentrated_outflow')
  }

  const rugScore = Math.min(100, rugFactors.length * 20)

  return {
    score: Math.max(0, score),
    rugPull: { score: rugScore, factors: rugFactors },
    alerts,
  }
}

// ── Dimension 2: Logic Transparency ────────────────────────────────────────────

function scoreLogicTransparency(
  contractResults: Record<string, string[]>,
): { score: number; alerts: AlertEvent[] } {
  let score = 100
  const alerts: AlertEvent[] = []

  let unverified = 0, proxies = 0, selfDestruct = 0
  for (const [addr, flags] of Object.entries(contractResults)) {
    if (flags.includes('unverified_source')) { unverified++; score -= 20 }
    if (flags.includes('upgradeable_proxy')) { proxies++; score -= 10 }
    if (flags.includes('self_destruct')) { selfDestruct++; score -= 25 }
  }

  if (unverified > 0) alerts.push({ alertType: 'unverified_contract', severity: 'warning', title: `${unverified} unverified contract(s)`, detail: 'Cannot audit source code. Logic is opaque.' })
  if (selfDestruct > 0) alerts.push({ alertType: 'self_destruct', severity: 'critical', title: `${selfDestruct} contract(s) with selfdestruct`, detail: 'Contract can be destroyed, removing all funds.' })

  return { score: Math.max(0, score), alerts }
}

// ── Dimension 3: Compliance ────────────────────────────────────────────────────

function scoreCompliance(
  addressResults: Record<string, { score: number; flags: string[] }>,
): { score: number; alerts: AlertEvent[] } {
  let score = 100
  const alerts: AlertEvent[] = []

  let flaggedCount = 0
  for (const [addr, result] of Object.entries(addressResults)) {
    if (result.flags.length > 0) {
      flaggedCount++
      score -= Math.min(30, result.score / 3)
      if (result.flags.includes('sanctioned')) {
        alerts.push({ alertType: 'sanctioned_interaction', severity: 'critical', title: `Interaction with sanctioned address`, detail: `${addr.slice(0, 12)}... is sanctioned` })
      }
      if (result.flags.includes('mixer')) {
        alerts.push({ alertType: 'mixer_interaction', severity: 'warning', title: `Interaction with mixer`, detail: `${addr.slice(0, 12)}... flagged as mixer` })
      }
    }
  }

  if (flaggedCount === 0 && Object.keys(addressResults).length > 0) {
    score = 100
  }

  return { score: Math.max(0, score), alerts }
}

// ── Dimension 4: Tech Stability ────────────────────────────────────────────────

function scoreTechStability(
  transactions: AgentTransaction[],
): { score: number; gasAnomaly: GasAnomaly; alerts: AlertEvent[] } {
  let score = 100
  const alerts: AlertEvent[] = []
  const total = transactions.length

  if (total === 0) {
    return { score: 50, gasAnomaly: { detected: false, avgGas: 0, maxGas: 0, anomalyTxs: 0, detail: 'No transactions' }, alerts }
  }

  // Failure rate
  const failed = transactions.filter(t => t.isError).length
  const failRate = failed / total
  if (failRate > 0.5) { score -= 40; alerts.push({ alertType: 'high_failure_rate', severity: 'critical', title: `${(failRate * 100).toFixed(0)}% failure rate`, detail: `${failed}/${total} transactions failed` }) }
  else if (failRate > 0.2) { score -= 20 }
  else if (failRate > 0.05) { score -= 5 }

  // Gas anomaly (using value as proxy if gas data not available)
  // In real implementation, Etherscan returns gasUsed. For now, detect patterns.
  const timestamps = transactions.map(t => t.timestamp ?? 0).filter(t => t > 0).sort()
  let gasAnomaly: GasAnomaly = { detected: false, avgGas: 0, maxGas: 0, anomalyTxs: 0, detail: 'Normal gas patterns' }

  // Detect rapid burst (potential front-running indicator)
  if (timestamps.length >= 3) {
    let burstCount = 0
    for (let i = 0; i < timestamps.length - 2; i++) {
      if (timestamps[i + 2] - timestamps[i] < 15) burstCount++ // 3 txs in 15 sec = front-running speed
    }
    if (burstCount > 0) {
      gasAnomaly = { detected: true, avgGas: 0, maxGas: 0, anomalyTxs: burstCount, detail: `${burstCount} burst(s) of 3+ txs within 15 seconds — possible front-running` }
      score -= 15
      alerts.push({ alertType: 'gas_anomaly', severity: 'warning', title: 'Rapid tx burst detected', detail: gasAnomaly.detail })
    }
  }

  return { score: Math.max(0, score), gasAnomaly, alerts }
}

// ── Dimension 5: Behavior Consistency ──────────────────────────────────────────

function scoreBehaviorConsistency(
  transactions: AgentTransaction[],
  walletAddress: string,
): { score: number; logicDrift: LogicDrift; alerts: AlertEvent[] } {
  let score = 100
  const alerts: AlertEvent[] = []
  const w = walletAddress.toLowerCase()
  const total = transactions.length

  if (total < 5) {
    return {
      score: 80,
      logicDrift: { detected: false, score: 0, previousPattern: 'N/A', currentPattern: 'N/A', detail: 'Not enough data for drift analysis' },
      alerts,
    }
  }

  // Split transactions into first half vs second half (time-based)
  const sorted = [...transactions].sort((a, b) => (a.timestamp ?? 0) - (b.timestamp ?? 0))
  const mid = Math.floor(sorted.length / 2)
  const firstHalf = sorted.slice(0, mid)
  const secondHalf = sorted.slice(mid)

  // Compare behavior patterns between halves
  const categorize = (txs: AgentTransaction[]) => {
    const cats: Record<string, number> = {}
    for (const tx of txs) {
      const method = tx.methodName?.toLowerCase() ?? 'unknown'
      const isOut = tx.from?.toLowerCase() === w
      let cat: string
      if (['register', 'setmetadata', 'setagentwallet'].includes(method)) cat = 'registration'
      else if (['approve', 'setapprovalforall'].includes(method)) cat = 'approval'
      else if (method.includes('swap')) cat = 'swap'
      else if (isOut && Number(tx.value) > 0) cat = 'transfer_out'
      else if (!isOut && Number(tx.value) > 0) cat = 'transfer_in'
      else cat = 'contract_call'
      cats[cat] = (cats[cat] ?? 0) + 1
    }
    return cats
  }

  const pattern1 = categorize(firstHalf)
  const pattern2 = categorize(secondHalf)

  // Calculate drift as cosine distance
  const allCats = new Set([...Object.keys(pattern1), ...Object.keys(pattern2)])
  let dotProduct = 0, mag1 = 0, mag2 = 0
  for (const cat of allCats) {
    const v1 = (pattern1[cat] ?? 0) / firstHalf.length
    const v2 = (pattern2[cat] ?? 0) / secondHalf.length
    dotProduct += v1 * v2
    mag1 += v1 * v1
    mag2 += v2 * v2
  }
  const similarity = mag1 > 0 && mag2 > 0 ? dotProduct / (Math.sqrt(mag1) * Math.sqrt(mag2)) : 1
  const driftScore = Math.round((1 - similarity) * 100)

  // Get dominant category for each half
  const dominant1 = Object.entries(pattern1).sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'unknown'
  const dominant2 = Object.entries(pattern2).sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'unknown'

  let logicDrift: LogicDrift = {
    detected: driftScore > 40,
    score: driftScore,
    previousPattern: dominant1,
    currentPattern: dominant2,
    detail: driftScore > 40
      ? `Significant behavior shift: ${dominant1} → ${dominant2} (drift ${driftScore}%)`
      : `Consistent behavior (drift ${driftScore}%)`,
  }

  if (driftScore > 60) {
    score -= 30
    alerts.push({ alertType: 'logic_drift', severity: 'critical', title: 'Major behavior drift detected', detail: logicDrift.detail })
  } else if (driftScore > 40) {
    score -= 15
    alerts.push({ alertType: 'logic_drift', severity: 'warning', title: 'Behavior pattern shift', detail: logicDrift.detail })
  }

  // Check for sudden transfer_out spike (rug pull precursor)
  const recentOutRatio = (pattern2['transfer_out'] ?? 0) / secondHalf.length
  const earlyOutRatio = (pattern1['transfer_out'] ?? 0) / firstHalf.length
  if (recentOutRatio > earlyOutRatio * 3 && recentOutRatio > 0.5) {
    score -= 20
    alerts.push({ alertType: 'drain_precursor', severity: 'critical', title: 'Sudden outbound transfer spike', detail: `Transfer out ratio jumped from ${(earlyOutRatio * 100).toFixed(0)}% to ${(recentOutRatio * 100).toFixed(0)}% — possible drain` })
  }

  return { score: Math.max(0, score), logicDrift, alerts }
}

// ── Main Profiler ──────────────────────────────────────────────────────────────

export async function profileAgent(
  chain: string,
  walletAddress: string,
  transactions: AgentTransaction[],
  addressResults: Record<string, { score: number; flags: string[] }>,
  contractResults: Record<string, string[]>,
  tokenResults: Record<string, string[]>,
): Promise<AgentProfile> {

  // Run all dimension analyses
  const [fund, logic, compliance, tech, behavior] = await Promise.all([
    scoreFundSafety(chain, transactions, tokenResults, walletAddress),
    Promise.resolve(scoreLogicTransparency(contractResults)),
    Promise.resolve(scoreCompliance(addressResults)),
    Promise.resolve(scoreTechStability(transactions)),
    Promise.resolve(scoreBehaviorConsistency(transactions, walletAddress)),
  ])

  const dimensions: DimensionScores = {
    fundSafety: fund.score,
    logicTransparency: logic.score,
    compliance: compliance.score,
    techStability: tech.score,
    behaviorConsistency: behavior.score,
  }

  // Collect all alerts
  const alerts = [...fund.alerts, ...logic.alerts, ...compliance.alerts, ...tech.alerts, ...behavior.alerts]

  // Overall grade
  const avg = (dimensions.fundSafety + dimensions.logicTransparency + dimensions.compliance + dimensions.techStability + dimensions.behaviorConsistency) / 5
  let overallGrade: AgentProfile['overallGrade']
  if (avg >= 90) overallGrade = 'A'
  else if (avg >= 75) overallGrade = 'B'
  else if (avg >= 60) overallGrade = 'C'
  else if (avg >= 40) overallGrade = 'D'
  else overallGrade = 'F'

  return {
    dimensions,
    rugPullIndex: fund.rugPull,
    gasAnomaly: tech.gasAnomaly,
    logicDrift: behavior.logicDrift,
    alerts,
    overallGrade,
  }
}
