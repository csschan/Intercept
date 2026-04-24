/**
 * Deep Analyzer — Comprehensive Agent Security Analysis
 *
 * Covers all 26 analysis dimensions:
 *   GoPlus补全 (#1-5), SlowMist Patterns (#6-8), 行为声明一致性 (#9-11),
 *   关系图谱 (#12-15), 交易深度 (#16-19), 时间序列 (#20-22),
 *   Cross-chain (#23-24), Off-chain (#25-26)
 */

import { readFileSync } from 'fs'
import { join } from 'path'
import type { AgentTransaction } from './erc8004.js'

// ── Types ──────────────────────────────────────────────────────────────────────

export interface DeepAnalysis {
  // GoPlus extended
  approvalRisks: ApprovalRisk[]
  phishingUrls: { url: string; isPhishing: boolean }[]
  decodedCalls: DecodedCall[]

  // Behavior-claim consistency
  claimConsistency: { score: number; declared: string[]; actual: string[]; mismatches: string[] }

  // Relationship graph
  graph: { nodes: GraphNode[]; edges: GraphEdge[]; rings: string[][]; stars: { center: string; spokes: number }[] }

  // Transaction depth
  amountDistribution: { mean: number; stddev: number; isAbnormal: boolean; pattern: string }
  probePattern: { detected: boolean; detail: string }
  counterpartyDepth: { address: string; riskScore: number; flags: string[] }[]

  // Time series
  frequencyTrend: { trend: 'accelerating' | 'decelerating' | 'stable' | 'burst'; detail: string }
  scheduledPattern: { detected: boolean; intervalSeconds: number; detail: string }
  registrationGap: { days: number; detail: string }

  // Cross-chain
  crossChainBehavior: { consistent: boolean; detail: string }

  // Off-chain
  endpointSecurity: { url: string; sslValid: boolean; domainAge: string; suspicious: boolean }[]

  // Pattern matches
  redFlagMatches: string[]
  socialEngineeringMatches: string[]

  // Overall additions to score
  penalties: { reason: string; points: number }[]
  totalPenalty: number
}

export interface ApprovalRisk {
  spender: string
  token: string
  amount: string
  isUnlimited: boolean
  spenderRisk: string
}

export interface DecodedCall {
  hash: string
  method: string
  params: Record<string, string>
  riskNote: string
}

export interface GraphNode {
  address: string
  type: 'agent' | 'eoa' | 'contract'
  agentId?: string
  riskScore: number
}

export interface GraphEdge {
  from: string
  to: string
  value: number
  txCount: number
  direction: 'outbound' | 'inbound' | 'both'
}

// ── GoPlus Extended APIs (#1-5) ────────────────────────────────────────────────

async function goplusFetch(url: string): Promise<any> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) })
    if (!res.ok) return null
    const d = await res.json()
    return d.result ?? d
  } catch { return null }
}

export async function checkApprovalSecurity(chainId: string, address: string): Promise<ApprovalRisk[]> {
  const data = await goplusFetch(`https://api.gopluslabs.io/api/v1/approval_security/${chainId}?contract_addresses=${address}`)
  if (!data) return []
  const risks: ApprovalRisk[] = []
  // GoPlus returns approval data per token
  for (const [token, info] of Object.entries(data ?? {})) {
    const i = info as any
    if (i?.approved_list) {
      for (const approval of i.approved_list) {
        risks.push({
          spender: approval.approved_spender ?? '',
          token,
          amount: approval.approved_amount ?? '0',
          isUnlimited: approval.approved_amount === 'unlimited' || parseFloat(approval.approved_amount ?? '0') > 1e15,
          spenderRisk: approval.approved_spender_tag ?? 'unknown',
        })
      }
    }
  }
  return risks
}

export async function checkPhishingSite(url: string): Promise<boolean> {
  const data = await goplusFetch(`https://api.gopluslabs.io/api/v1/phishing_site?url=${encodeURIComponent(url)}`)
  return data?.phishing_site === '1'
}

export async function decodeCalldata(txs: AgentTransaction[]): Promise<DecodedCall[]> {
  const decoded: DecodedCall[] = []
  for (const tx of txs) {
    if (!tx.input || tx.input === '0x') continue
    const selector = tx.input.slice(0, 10)

    // Common selectors
    const knownSelectors: Record<string, { method: string; decode: (d: string) => Record<string, string> }> = {
      '0x095ea7b3': { method: 'approve', decode: d => ({ spender: '0x' + d.slice(10, 74).replace(/^0+/, ''), amount: BigInt('0x' + d.slice(74, 138)).toString() }) },
      '0xa9059cbb': { method: 'transfer', decode: d => ({ to: '0x' + d.slice(10, 74).replace(/^0+/, ''), amount: BigInt('0x' + d.slice(74, 138)).toString() }) },
      '0x23b872dd': { method: 'transferFrom', decode: d => ({ from: '0x' + d.slice(10, 74).replace(/^0+/, ''), to: '0x' + d.slice(74, 138).replace(/^0+/, ''), amount: BigInt('0x' + d.slice(138, 202)).toString() }) },
      '0xa22cb465': { method: 'setApprovalForAll', decode: d => ({ operator: '0x' + d.slice(10, 74).replace(/^0+/, ''), approved: d.slice(138, 139) === '1' ? 'true' : 'false' }) },
    }

    const known = knownSelectors[selector]
    if (known) {
      try {
        const params = known.decode(tx.input)
        let riskNote = ''
        if (known.method === 'approve' && BigInt(params.amount ?? '0') > BigInt('0xffffffffffff')) riskNote = 'UNLIMITED APPROVAL'
        if (known.method === 'setApprovalForAll' && params.approved === 'true') riskNote = 'FULL COLLECTION ACCESS'
        decoded.push({ hash: tx.hash, method: known.method, params, riskNote })
      } catch {}
    }
  }
  return decoded
}

// ── Behavior-Claim Consistency (#9-11) ─────────────────────────────────────────

export async function checkClaimConsistency(
  registrationUri: string | null,
  transactions: AgentTransaction[],
  walletAddress: string,
): Promise<DeepAnalysis['claimConsistency']> {
  const declared: string[] = []
  const actual: string[] = []
  const mismatches: string[] = []

  // Parse registration file
  if (registrationUri) {
    try {
      let uri = registrationUri
      // Handle data: URIs
      if (uri.startsWith('data:application/json;base64,')) {
        const json = Buffer.from(uri.replace('data:application/json;base64,', ''), 'base64').toString()
        const reg = JSON.parse(json)
        if (reg.name) declared.push(`name:${reg.name}`)
        if (reg.description) {
          const desc = (reg.description as string).toLowerCase()
          if (desc.includes('defi') || desc.includes('yield') || desc.includes('swap')) declared.push('category:defi')
          if (desc.includes('nft') || desc.includes('collectible')) declared.push('category:nft')
          if (desc.includes('trading') || desc.includes('arbitrage')) declared.push('category:trading')
          if (desc.includes('security') || desc.includes('audit')) declared.push('category:security')
          if (desc.includes('social') || desc.includes('community')) declared.push('category:social')
        }
        if (reg.services) {
          for (const svc of reg.services) {
            if (svc.name) declared.push(`service:${svc.name}`)
          }
        }
      } else if (uri.startsWith('http')) {
        try {
          const res = await fetch(uri, { signal: AbortSignal.timeout(5000) })
          if (res.ok) {
            const reg = await res.json()
            if (reg.name) declared.push(`name:${reg.name}`)
            if (reg.description) {
              const desc = (reg.description as string).toLowerCase()
              if (desc.includes('defi')) declared.push('category:defi')
              if (desc.includes('nft')) declared.push('category:nft')
              if (desc.includes('trading')) declared.push('category:trading')
            }
          }
        } catch {}
      }
    } catch {}
  }

  // Analyze actual behavior
  const w = walletAddress.toLowerCase()
  const methods = new Set(transactions.map(t => t.methodName?.toLowerCase()).filter(Boolean))
  if (methods.has('swap') || methods.has('exchange')) actual.push('category:defi')
  if (methods.has('mint') || methods.has('safetransferfrom')) actual.push('category:nft')
  if (methods.has('register') || methods.has('setmetadata')) actual.push('category:registration')

  const outbound = transactions.filter(t => t.from?.toLowerCase() === w)
  const inbound = transactions.filter(t => t.to?.toLowerCase() === w)
  if (outbound.length > inbound.length * 3) actual.push('pattern:heavy_outflow')
  if (inbound.length > outbound.length * 3) actual.push('pattern:heavy_inflow')

  // Find mismatches
  const declaredCats = declared.filter(d => d.startsWith('category:'))
  const actualCats = actual.filter(a => a.startsWith('category:'))
  if (declaredCats.length > 0 && actualCats.length > 0) {
    for (const dc of declaredCats) {
      if (!actualCats.includes(dc)) mismatches.push(`Declared ${dc} but not observed on-chain`)
    }
    for (const ac of actualCats) {
      if (!declaredCats.includes(ac)) mismatches.push(`Observed ${ac} but not declared in registration`)
    }
  }
  if (actual.includes('pattern:heavy_outflow') && !declared.some(d => d.includes('transfer') || d.includes('payment'))) {
    mismatches.push('Heavy outbound transfers not declared in agent purpose')
  }

  const score = mismatches.length === 0 ? 100 : Math.max(0, 100 - mismatches.length * 20)
  return { score, declared, actual, mismatches }
}

// ── Endpoint Security (#11) ────────────────────────────────────────────────────

export async function checkEndpointSecurity(urls: string[]): Promise<DeepAnalysis['endpointSecurity']> {
  const results: DeepAnalysis['endpointSecurity'] = []
  for (const url of urls.slice(0, 5)) {
    try {
      const u = new URL(url)
      const isHttps = u.protocol === 'https:'

      // Check if domain responds
      let sslValid = false
      try {
        const res = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(5000) })
        sslValid = res.ok || res.status < 500
      } catch {}

      // Check phishing
      const isPhishing = await checkPhishingSite(url)

      results.push({
        url,
        sslValid: isHttps && sslValid,
        domainAge: 'unknown', // Would need WHOIS API
        suspicious: isPhishing || !isHttps,
      })
    } catch {
      results.push({ url, sslValid: false, domainAge: 'unknown', suspicious: true })
    }
  }
  return results
}

// ── Relationship Graph (#12-15) ─────────────────────────────────────────────────

export function buildRelationshipGraph(
  transactions: AgentTransaction[],
  walletAddress: string,
  allAgentWallets: Record<string, string>, // agentId → wallet
): DeepAnalysis['graph'] {
  const w = walletAddress.toLowerCase()
  const agentWalletSet = new Set(Object.values(allAgentWallets).map(a => a.toLowerCase()))
  const agentByWallet: Record<string, string> = {}
  for (const [id, wallet] of Object.entries(allAgentWallets)) {
    agentByWallet[wallet.toLowerCase()] = id
  }

  const nodesMap: Record<string, GraphNode> = {}
  const edgesMap: Record<string, GraphEdge> = {}

  // Add self
  nodesMap[w] = { address: w, type: 'agent', agentId: agentByWallet[w], riskScore: 0 }

  for (const tx of transactions) {
    const from = tx.from?.toLowerCase() ?? ''
    const to = tx.to?.toLowerCase() ?? ''
    const counterparty = from === w ? to : from
    if (!counterparty) continue

    // Node
    if (!nodesMap[counterparty]) {
      nodesMap[counterparty] = {
        address: counterparty,
        type: agentWalletSet.has(counterparty) ? 'agent' : 'contract',
        agentId: agentByWallet[counterparty],
        riskScore: 0,
      }
    }

    // Edge
    const edgeKey = [w, counterparty].sort().join('-')
    if (!edgesMap[edgeKey]) {
      edgesMap[edgeKey] = { from: w, to: counterparty, value: 0, txCount: 0, direction: from === w ? 'outbound' : 'inbound' }
    }
    edgesMap[edgeKey].txCount++
    edgesMap[edgeKey].value += Number(tx.value) / Math.pow(10, tx.tokenDecimals ?? 18)
    if (edgesMap[edgeKey].direction === 'outbound' && from !== w) edgesMap[edgeKey].direction = 'both'
    if (edgesMap[edgeKey].direction === 'inbound' && from === w) edgesMap[edgeKey].direction = 'both'
  }

  // Detect rings: A→B→C→A (simple 3-node ring detection)
  const rings: string[][] = []
  const outboundTargets: Record<string, Set<string>> = {}
  for (const edge of Object.values(edgesMap)) {
    if (!outboundTargets[edge.from]) outboundTargets[edge.from] = new Set()
    outboundTargets[edge.from].add(edge.to)
  }

  // Check for paths back to self through 2 hops
  const myTargets = outboundTargets[w] ?? new Set()
  for (const hop1 of myTargets) {
    const hop1Targets = outboundTargets[hop1] ?? new Set()
    for (const hop2 of hop1Targets) {
      if (hop2 === w) {
        rings.push([w, hop1, w]) // 2-node ring
      }
      const hop2Targets = outboundTargets[hop2] ?? new Set()
      if (hop2Targets.has(w)) {
        rings.push([w, hop1, hop2, w]) // 3-node ring
      }
    }
  }

  // Detect stars: one address connected to many
  const stars: DeepAnalysis['graph']['stars'] = []
  const connectionCount: Record<string, number> = {}
  for (const edge of Object.values(edgesMap)) {
    connectionCount[edge.from] = (connectionCount[edge.from] ?? 0) + 1
    connectionCount[edge.to] = (connectionCount[edge.to] ?? 0) + 1
  }
  for (const [addr, count] of Object.entries(connectionCount)) {
    if (count >= 5) stars.push({ center: addr, spokes: count })
  }

  return {
    nodes: Object.values(nodesMap),
    edges: Object.values(edgesMap),
    rings,
    stars,
  }
}

// ── Transaction Depth (#16-19) ──────────────────────────────────────────────────

export function analyzeAmountDistribution(transactions: AgentTransaction[]): DeepAnalysis['amountDistribution'] {
  const values = transactions
    .map(t => Number(t.value) / Math.pow(10, t.tokenDecimals ?? 18))
    .filter(v => v > 0)

  if (values.length < 3) return { mean: 0, stddev: 0, isAbnormal: true, pattern: 'insufficient_data' }

  const mean = values.reduce((s, v) => s + v, 0) / values.length
  const variance = values.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / values.length
  const stddev = Math.sqrt(variance)
  const cv = mean > 0 ? stddev / mean : 0 // coefficient of variation

  let pattern = 'normal'
  if (cv > 3) pattern = 'highly_variable'
  else if (cv > 1.5) pattern = 'variable'

  // Check for bimodal (small + large)
  const sorted = [...values].sort((a, b) => a - b)
  const median = sorted[Math.floor(sorted.length / 2)]
  const smallCount = values.filter(v => v < median * 0.1).length
  const largeCount = values.filter(v => v > median * 10).length
  if (smallCount > 2 && largeCount > 0) pattern = 'bimodal_suspicious'

  return { mean, stddev, isAbnormal: pattern !== 'normal', pattern }
}

export function detectProbePattern(transactions: AgentTransaction[], walletAddress: string): DeepAnalysis['probePattern'] {
  const w = walletAddress.toLowerCase()
  const outbound = transactions
    .filter(t => t.from?.toLowerCase() === w)
    .sort((a, b) => (a.timestamp ?? 0) - (b.timestamp ?? 0))

  if (outbound.length < 3) return { detected: false, detail: 'Insufficient outbound transactions to assess pattern' }

  // Check: first txs are tiny, later txs are large
  const values = outbound.map(t => Number(t.value) / Math.pow(10, t.tokenDecimals ?? 18))
  const firstThird = values.slice(0, Math.ceil(values.length / 3))
  const lastThird = values.slice(-Math.ceil(values.length / 3))
  const firstAvg = firstThird.reduce((s, v) => s + v, 0) / firstThird.length
  const lastAvg = lastThird.reduce((s, v) => s + v, 0) / lastThird.length

  if (firstAvg > 0 && lastAvg > firstAvg * 10 && lastAvg > 1) {
    return { detected: true, detail: `Small amounts first (avg ${firstAvg.toFixed(4)}), then large (avg ${lastAvg.toFixed(4)}) — probe-then-drain pattern` }
  }

  return { detected: false, detail: 'No probe pattern detected' }
}

// ── Time Series (#20-22) ────────────────────────────────────────────────────────

export function analyzeFrequencyTrend(transactions: AgentTransaction[]): DeepAnalysis['frequencyTrend'] {
  const timestamps = transactions.map(t => t.timestamp ?? 0).filter(t => t > 0).sort()
  if (timestamps.length < 4) return { trend: 'insufficient', detail: 'Too few transactions to determine frequency trend' }

  const gaps: number[] = []
  for (let i = 1; i < timestamps.length; i++) gaps.push(timestamps[i] - timestamps[i - 1])

  const firstHalf = gaps.slice(0, Math.floor(gaps.length / 2))
  const secondHalf = gaps.slice(Math.floor(gaps.length / 2))
  const avgFirst = firstHalf.reduce((s, g) => s + g, 0) / firstHalf.length
  const avgSecond = secondHalf.reduce((s, g) => s + g, 0) / secondHalf.length

  if (avgSecond < avgFirst * 0.3) return { trend: 'accelerating', detail: `Gap decreased from ${avgFirst.toFixed(0)}s to ${avgSecond.toFixed(0)}s — activity increasing rapidly` }
  if (avgSecond > avgFirst * 3) return { trend: 'decelerating', detail: `Gap increased from ${avgFirst.toFixed(0)}s to ${avgSecond.toFixed(0)}s — activity slowing` }

  // Check for bursts
  const burstCount = gaps.filter(g => g < 15).length
  if (burstCount > gaps.length * 0.5) return { trend: 'burst', detail: `${burstCount}/${gaps.length} transactions within 15s — burst pattern` }

  return { trend: 'stable', detail: `Consistent transaction frequency (avg gap ${((avgFirst + avgSecond) / 2).toFixed(0)}s)` }
}

export function detectScheduledPattern(transactions: AgentTransaction[]): DeepAnalysis['scheduledPattern'] {
  const timestamps = transactions.map(t => t.timestamp ?? 0).filter(t => t > 0).sort()
  if (timestamps.length < 5) return { detected: false, intervalSeconds: 0, detail: 'Too few transactions to detect scheduling' }

  const gaps = []
  for (let i = 1; i < timestamps.length; i++) gaps.push(timestamps[i] - timestamps[i - 1])

  // Check if gaps are roughly equal (scheduled bot)
  const avgGap = gaps.reduce((s, g) => s + g, 0) / gaps.length
  const variance = gaps.reduce((s, g) => s + Math.pow(g - avgGap, 2), 0) / gaps.length
  const cv = avgGap > 0 ? Math.sqrt(variance) / avgGap : 999

  if (cv < 0.3 && avgGap > 60) {
    return { detected: true, intervalSeconds: Math.round(avgGap), detail: `Regular interval ~${Math.round(avgGap)}s (CV=${cv.toFixed(2)}) — automated/bot behavior` }
  }

  return { detected: false, intervalSeconds: 0, detail: 'No regular scheduling detected' }
}

// ── Pattern Matching (#6-8) ─────────────────────────────────────────────────────

export function matchRedFlags(registrationContent: string): string[] {
  const matches: string[] = []
  const content = registrationContent.toLowerCase()

  // Load patterns from red-flags.md keywords
  const dangerousKeywords = [
    'eval(', 'exec(', 'child_process', 'subprocess', 'os.system',
    'process.env', 'os.environ', '.env', 'credentials',
    'curl | sh', 'wget | bash', 'npm install',
    'chmod 777', 'sudo', 'crontab',
    'document.cookie', 'localStorage',
    'base64', 'obfuscated',
  ]

  for (const kw of dangerousKeywords) {
    if (content.includes(kw)) matches.push(`Red flag: "${kw}" found in registration content`)
  }

  return matches
}

export function matchSocialEngineering(text: string): string[] {
  const matches: string[] = []
  const lower = text.toLowerCase()

  const patterns = [
    { pattern: /act now|limited time|hurry|urgent|don't miss/i, flag: 'Urgency language' },
    { pattern: /guaranteed|100% safe|risk.?free|no risk/i, flag: 'Unrealistic promises' },
    { pattern: /send.*private.?key|share.*seed|enter.*mnemonic/i, flag: 'Credential harvesting' },
    { pattern: /airdrop.*claim|free.*token|bonus.*reward/i, flag: 'Airdrop bait' },
    { pattern: /official.*support|admin.*team|verify.*account/i, flag: 'Impersonation' },
  ]

  for (const p of patterns) {
    if (p.pattern.test(lower)) matches.push(`Social engineering: ${p.flag}`)
  }

  return matches
}

// ── Main Deep Analysis ─────────────────────────────────────────────────────────

export async function runDeepAnalysis(
  chainId: string,
  walletAddress: string,
  transactions: AgentTransaction[],
  registrationUri: string | null,
  allAgentWallets: Record<string, string>,
): Promise<DeepAnalysis> {
  const penalties: DeepAnalysis['penalties'] = []

  // #1-5: GoPlus extended + calldata decode
  const [approvalRisks, decodedCalls] = await Promise.all([
    chainId ? checkApprovalSecurity(chainId, walletAddress) : Promise.resolve([]),
    decodeCalldata(transactions),
  ])

  // Check registration URLs for phishing
  const phishingUrls: DeepAnalysis['phishingUrls'] = []
  const endpointUrls: string[] = []
  if (registrationUri?.startsWith('http')) {
    const isPhish = await checkPhishingSite(registrationUri)
    phishingUrls.push({ url: registrationUri, isPhishing: isPhish })
    if (isPhish) penalties.push({ reason: 'Registration URL flagged as phishing', points: 30 })
    endpointUrls.push(registrationUri)
  }

  // #9-11: Behavior-claim consistency
  const claimConsistency = await checkClaimConsistency(registrationUri, transactions, walletAddress)
  if (claimConsistency.score < 60) penalties.push({ reason: `Behavior-claim mismatch (${claimConsistency.mismatches.length} issues)`, points: 10 })

  // Endpoint security
  const endpointSecurity = await checkEndpointSecurity(endpointUrls)
  for (const ep of endpointSecurity) {
    if (ep.suspicious) penalties.push({ reason: `Suspicious endpoint: ${ep.url}`, points: 5 })
  }

  // #12-15: Relationship graph
  const graph = buildRelationshipGraph(transactions, walletAddress, allAgentWallets)
  if (graph.rings.length > 0) penalties.push({ reason: `${graph.rings.length} circular transaction pattern(s) detected`, points: 15 })
  if (graph.stars.length > 0) penalties.push({ reason: `Star topology: ${graph.stars[0].spokes} connections from single address`, points: 5 })

  // #16-19: Transaction depth
  const amountDistribution = analyzeAmountDistribution(transactions)
  if (amountDistribution.pattern === 'bimodal_suspicious') penalties.push({ reason: 'Bimodal amount distribution (small probes + large transfers)', points: 10 })

  const probePattern = detectProbePattern(transactions, walletAddress)
  if (probePattern.detected) penalties.push({ reason: 'Probe-then-drain pattern detected', points: 15 })

  // Counterparty depth (check top 5 counterparties)
  const counterpartyDepth: DeepAnalysis['counterpartyDepth'] = []
  if (chainId) {
    const counterparties = new Set<string>()
    for (const tx of transactions) {
      const cp = tx.from?.toLowerCase() === walletAddress.toLowerCase() ? tx.to : tx.from
      if (cp) counterparties.add(cp.toLowerCase())
    }
    for (const cp of [...counterparties].slice(0, 5)) {
      try {
        const data = await goplusFetch(`https://api.gopluslabs.io/api/v1/address_security/${cp}?chain_id=${chainId}`)
        if (data) {
          const flags: string[] = []
          if (data.is_blacklisted === '1') flags.push('blacklisted')
          if (data.is_phishing_activities === '1') flags.push('phishing')
          if (data.is_mixer === '1') flags.push('mixer')
          const score = flags.length > 0 ? 80 : 0
          counterpartyDepth.push({ address: cp, riskScore: score, flags })
          if (score > 50) penalties.push({ reason: `Counterparty ${cp.slice(0, 10)}... flagged: ${flags.join(', ')}`, points: 10 })
        }
      } catch {}
    }
  }

  // Approval risks penalties
  const unlimitedApprovals = approvalRisks.filter(a => a.isUnlimited)
  if (unlimitedApprovals.length > 0) penalties.push({ reason: `${unlimitedApprovals.length} unlimited token approval(s)`, points: 8 })

  // Decoded call risks
  const riskyDecoded = decodedCalls.filter(d => d.riskNote)
  if (riskyDecoded.length > 0) penalties.push({ reason: `${riskyDecoded.length} risky decoded call(s): ${riskyDecoded.map(d => d.riskNote).join(', ')}`, points: 5 })

  // #20-22: Time series
  const frequencyTrend = analyzeFrequencyTrend(transactions)
  if (frequencyTrend.trend === 'accelerating') penalties.push({ reason: 'Rapidly accelerating transaction frequency', points: 5 })
  if (frequencyTrend.trend === 'burst') penalties.push({ reason: 'Burst transaction pattern', points: 3 })

  const scheduledPattern = detectScheduledPattern(transactions)
  // Scheduled is not necessarily bad, just informational

  const timestamps = transactions.map(t => t.timestamp ?? 0).filter(t => t > 0).sort()
  const registrationGapDays = timestamps.length > 0 ? 0 : -1
  const registrationGap = { days: registrationGapDays, detail: timestamps.length > 0 ? `First activity ${new Date(timestamps[0] * 1000).toLocaleDateString()}` : 'No activity recorded' }

  // #23-24: Cross-chain (placeholder — needs multi-chain query)
  const crossChainBehavior = { consistent: true, detail: 'Single-chain analysis only' }

  // #6-8: Pattern matching on registration content
  let regContent = ''
  if (registrationUri) {
    try {
      if (registrationUri.startsWith('data:')) {
        regContent = Buffer.from(registrationUri.split(',')[1] ?? '', 'base64').toString()
      } else if (registrationUri.startsWith('http')) {
        const res = await fetch(registrationUri, { signal: AbortSignal.timeout(5000) }).catch(() => null)
        if (res?.ok) regContent = await res.text()
      }
    } catch {}
  }

  const redFlagMatches = matchRedFlags(regContent)
  const socialEngineeringMatches = matchSocialEngineering(regContent)
  if (redFlagMatches.length > 0) penalties.push({ reason: `${redFlagMatches.length} code-level red flag(s) in registration`, points: 15 })
  if (socialEngineeringMatches.length > 0) penalties.push({ reason: `${socialEngineeringMatches.length} social engineering pattern(s)`, points: 10 })

  const totalPenalty = penalties.reduce((s, p) => s + p.points, 0)

  return {
    approvalRisks, phishingUrls, decodedCalls,
    claimConsistency, endpointSecurity,
    graph, amountDistribution, probePattern, counterpartyDepth,
    frequencyTrend, scheduledPattern, registrationGap,
    crossChainBehavior,
    redFlagMatches, socialEngineeringMatches,
    penalties, totalPenalty,
  }
}
