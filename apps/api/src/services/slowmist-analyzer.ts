/**
 * On-Chain Security Analyzer
 *
 * Full security checklist for ERC-8004 agent transactions.
 *
 * Steps:
 *   1. Address Risk Assessment    — GoPlus address_security
 *   2. Smart Contract Review      — GoPlus contract_security
 *   3. Token Security             — GoPlus token_security
 *   4. Approval Pattern Detection — decode approve/permit params
 *   5. Address Poisoning          — similar-address detection (with known-contract exclusion)
 *   6. Funding Source Analysis    — trace first inbound tx origin
 *   7. Behavioral Analysis        — velocity, concentration, failure, time-series
 *   8. Cross-Chain Correlation    — same owner behavior across chains
 *   9. Risk Scoring & Verdict     — thresholds ≤30/31-70/71-90/≥91
 */

import { IDENTITY_REGISTRY, REPUTATION_REGISTRY, type AgentTransaction } from './erc8004.js'

// ── Known safe contracts (never flag interactions with these) ──────────────────

const KNOWN_SAFE_CONTRACTS = new Set([
  IDENTITY_REGISTRY.toLowerCase(),
  REPUTATION_REGISTRY.toLowerCase(),
  // Common infra contracts
  '0x0000000000000068f116a894984e2db1123eb395', // Seaport
  '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2', // WETH
  '0xdac17f958d2ee523a2206206994597c13d831ec7', // USDT
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', // USDC
])

function isKnownSafe(addr: string): boolean {
  return KNOWN_SAFE_CONTRACTS.has(addr.toLowerCase())
}

// ── Types ──────────────────────────────────────────────────────────────────────

export interface ChecklistItem {
  step: number
  name: string
  status: 'pass' | 'warn' | 'fail' | 'skip'
  score: number
  source: string
  checks: string[]
  findings: string[]
}

export interface BehaviorTag {
  tag: string
  count: number
  percentage: number
}

export interface SlowMistReport {
  agentId: string
  chain: string
  walletAddress: string
  checklist: ChecklistItem[]
  overallScore: number
  riskLevel: 'low' | 'medium' | 'high' | 'severe'
  verdict: 'safe' | 'caution' | 'reject'
  verdictReason: string
  summary: string
  behaviorTags: BehaviorTag[]
  activityLevel: 'dormant' | 'low' | 'moderate' | 'high' | 'very_high'
  fundingSource: { address: string; label: string } | null
  metadata: {
    addressesScanned: number
    contractsScanned: number
    tokensScanned: number
    transactionsAnalyzed: number
    timestamp: number
  }
}

// ── GoPlus API ─────────────────────────────────────────────────────────────────

const GOPLUS_CHAIN_IDS: Record<string, string> = {
  ethereum: '1', bsc: '56', polygon: '137',
  arbitrum: '42161', base: '8453', optimism: '10',
  solana: 'solana',
}

async function goplusFetch(url: string): Promise<any> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(5000) })
    if (!res.ok) return null
    return (await res.json()).result ?? null
  } catch { return null }
}

// ── Step 1: Address Risk Assessment ────────────────────────────────────────────

async function step1(
  addresses: string[], chainId: string,
): Promise<{ item: ChecklistItem; results: Record<string, { score: number; flags: string[] }> }> {
  const results: Record<string, { score: number; flags: string[] }> = {}
  const checks = ['AML risk score', 'Blacklist / phishing / sanctioned / mixer', 'Cybercrime / money laundering']
  const findings: string[] = []
  let worst = 0

  if (!chainId) {
    return { item: { step: 1, name: 'Address Risk Assessment', status: 'skip', score: 0, source: 'Address Security API', checks, findings: ['Chain not supported'] }, results }
  }

  // Filter out known safe contracts — no need to check them
  const toCheck = addresses.filter(a => !isKnownSafe(a)).slice(0, 20)
  const skipped = addresses.length - toCheck.length

  await Promise.all(toCheck.map(async (addr) => {
    const r = await goplusFetch(`https://api.gopluslabs.io/api/v1/address_security/${addr}?chain_id=${chainId}`)
    if (!r) { results[addr] = { score: 0, flags: [] }; return }
    const flags: string[] = []
    let score = 0
    if (r.is_blacklisted === '1')              { flags.push('blacklisted'); score = 100 }
    if (r.is_phishing_activities === '1')       { flags.push('phishing'); score = Math.max(score, 95) }
    if (r.is_sanctioned === '1')               { flags.push('sanctioned'); score = Math.max(score, 100) }
    if (r.is_honeypot_related_address === '1')  { flags.push('honeypot_related'); score = Math.max(score, 80) }
    if (r.is_mixer === '1')                     { flags.push('mixer'); score = Math.max(score, 70) }
    if (r.cybercrime === '1')                   { flags.push('cybercrime'); score = Math.max(score, 90) }
    if (r.money_laundering === '1')             { flags.push('money_laundering'); score = Math.max(score, 85) }
    if (r.financial_crime === '1')              { flags.push('financial_crime'); score = Math.max(score, 85) }
    results[addr] = { score, flags }
    if (score > worst) worst = score
    if (flags.length > 0) findings.push(`${addr.slice(0, 10)}... flagged: ${flags.join(', ')}`)
  }))

  if (findings.length === 0) {
    findings.push(`${toCheck.length} addresses scanned — all clean`)
    if (skipped > 0) findings.push(`${skipped} known contracts skipped`)
  }

  return {
    item: { step: 1, name: 'Address Risk Assessment', status: worst >= 91 ? 'fail' : worst >= 31 ? 'warn' : 'pass', score: worst, source: 'Address Security API', checks, findings },
    results,
  }
}

// ── Step 2: Smart Contract Review ──────────────────────────────────────────────

async function step2(
  contracts: string[], chainId: string,
): Promise<{ item: ChecklistItem; results: Record<string, { flags: string[] }> }> {
  const results: Record<string, { flags: string[] }> = {}
  const checks = ['Source verified', 'Proxy / upgradeable', 'Owner privileges', 'Self-destruct', 'Mint function']
  const findings: string[] = []
  let worst = 0

  // Filter out known safe contracts
  const toCheck = contracts.filter(a => !isKnownSafe(a)).slice(0, 10)

  if (!chainId || toCheck.length === 0) {
    const msg = contracts.length > 0 ? `${contracts.length} contract(s) are all known safe — skipped` : 'No unknown contract interactions'
    return { item: { step: 2, name: 'Smart Contract Review', status: 'pass', score: 0, source: 'Contract Security API', checks, findings: [msg] }, results }
  }

  await Promise.all(toCheck.map(async (addr) => {
    const r = await goplusFetch(`https://api.gopluslabs.io/api/v1/contract_security/${addr}?chain_id=${chainId}`)
    if (!r) { results[addr] = { flags: [] }; return }
    const flags: string[] = []
    let score = 0
    if (r.is_open_source !== '1') { flags.push('unverified_source'); score = Math.max(score, 71) }
    if (r.is_proxy === '1') { flags.push('upgradeable_proxy'); score = Math.max(score, 35) }
    if (r.self_destruct === '1') { flags.push('self_destruct'); score = Math.max(score, 80) }
    if (r.is_mintable === '1') { flags.push('mintable'); score = Math.max(score, 40) }
    results[addr] = { flags }
    if (score > worst) worst = score
    if (flags.length > 0) findings.push(`${addr.slice(0, 10)}...: ${flags.join(', ')}`)
  }))

  if (findings.length === 0) findings.push(`${toCheck.length} contracts reviewed — all verified & safe`)

  return {
    item: { step: 2, name: 'Smart Contract Review', status: worst >= 71 ? 'fail' : worst >= 31 ? 'warn' : 'pass', score: worst, source: 'Contract Security API', checks, findings },
    results,
  }
}

// ── Step 3: Token Security ─────────────────────────────────────────────────────

async function step3(
  tokenAddrs: string[], chainId: string,
): Promise<{ item: ChecklistItem; results: Record<string, { flags: string[] }> }> {
  const results: Record<string, { flags: string[] }> = {}
  const checks = ['Honeypot', 'Hidden mint', 'High tax (>10%)', 'Blacklist', 'Sell restrictions', 'Ownership takeback']
  const findings: string[] = []
  let worst = 0

  if (!chainId || tokenAddrs.length === 0) {
    return { item: { step: 3, name: 'Token Security', status: 'skip', score: 0, source: 'Token Security API', checks, findings: ['No ERC-20 token interactions'] }, results }
  }

  const batch = tokenAddrs.slice(0, 10)
  const data = await goplusFetch(`https://api.gopluslabs.io/api/v1/token_security/${chainId}?contract_addresses=${batch.join(',')}`)

  if (data) {
    for (const [addr, info] of Object.entries(data)) {
      const r = info as any
      const flags: string[] = []
      let score = 0
      if (r.is_honeypot === '1') { flags.push('honeypot'); score = Math.max(score, 95) }
      if (r.is_mintable === '1' && r.owner_address) { flags.push('hidden_mint'); score = Math.max(score, 50) }
      const buyTax = parseFloat(r.buy_tax ?? '0')
      const sellTax = parseFloat(r.sell_tax ?? '0')
      if (buyTax > 0.1) { flags.push(`buy_tax_${(buyTax*100).toFixed(0)}%`); score = Math.max(score, 60) }
      if (sellTax > 0.1) { flags.push(`sell_tax_${(sellTax*100).toFixed(0)}%`); score = Math.max(score, 60) }
      if (r.cannot_sell_all === '1') { flags.push('cannot_sell_all'); score = Math.max(score, 70) }
      if (r.can_take_back_ownership === '1') { flags.push('ownership_takeback'); score = Math.max(score, 50) }
      if (r.is_blacklisted === '1') { flags.push('has_blacklist'); score = Math.max(score, 30) }
      results[addr.toLowerCase()] = { flags }
      if (score > worst) worst = score
      if (flags.length > 0) findings.push(`${r.token_name ?? addr.slice(0, 10)}: ${flags.join(', ')}`)
    }
  }

  if (findings.length === 0 && batch.length > 0) findings.push(`${batch.length} tokens analyzed — no issues`)

  return {
    item: { step: 3, name: 'Token Security', status: worst >= 71 ? 'fail' : worst >= 31 ? 'warn' : 'pass', score: worst, source: 'Token Security API', checks, findings },
    results,
  }
}

// ── Step 4: Approval Pattern Detection ─────────────────────────────────────────

function step4(txs: AgentTransaction[]): ChecklistItem {
  const checks = ['approve(spender, uint256.max)', 'setApprovalForAll', 'Spender address risk']
  const findings: string[] = []
  let worst = 0
  let unlimited = 0, nftAll = 0, normal = 0

  for (const tx of txs) {
    const method = tx.methodName?.toLowerCase() ?? ''
    if (method === 'approve') {
      const dec = tx.tokenDecimals ?? 18
      const val = Number(tx.value) / Math.pow(10, dec)
      if (val > 1e12 || tx.value > BigInt('0xffffffffffffff')) {
        unlimited++
        // Check who is being approved (the 'to' address)
        const spender = tx.to ?? 'unknown'
        if (isKnownSafe(spender)) {
          findings.push(`Unlimited approve to known safe contract ${spender.slice(0, 10)}... — acceptable`)
        } else {
          findings.push(`⚠ Unlimited approve to ${spender.slice(0, 10)}... — verify spender is trusted`)
          worst = Math.max(worst, 60)
        }
      } else {
        normal++
      }
    }
    if (method === 'setapprovalforall') {
      nftAll++
      worst = Math.max(worst, 50)
      findings.push(`⚠ setApprovalForAll to ${tx.to?.slice(0, 10) ?? '?'}... — full collection access granted`)
    }
  }

  if (normal > 0) findings.push(`${normal} bounded approve() calls — normal`)
  if (unlimited === 0 && nftAll === 0 && normal === 0) findings.push('No approval calls detected')

  return { step: 4, name: 'Approval Pattern Detection', status: worst >= 71 ? 'fail' : worst >= 31 ? 'warn' : 'pass', score: worst, source: 'Approval Pattern Detection', checks, findings }
}

// ── Step 5: Address Poisoning Detection ────────────────────────────────────────

function step5(txs: AgentTransaction[], wallet: string): ChecklistItem {
  const checks = ['Similar-prefix-suffix detection (excluding known contracts)', 'Tiny-value inbound from look-alike']
  const findings: string[] = []
  let score = 0
  const w = wallet.toLowerCase()

  const outbound = new Set<string>()
  const inbound = new Map<string, number>() // address → value

  for (const tx of txs) {
    const to = tx.to?.toLowerCase() ?? ''
    const from = tx.from?.toLowerCase() ?? ''
    if (from === w && to && !isKnownSafe(to)) outbound.add(to)
    if (to === w && from && !isKnownSafe(from)) {
      const val = Number(tx.value) / Math.pow(10, tx.tokenDecimals ?? 18)
      inbound.set(from, val)
    }
  }

  // Check for similar-looking addresses only among non-contract EOAs
  for (const outAddr of outbound) {
    const prefix = outAddr.slice(0, 6)
    const suffix = outAddr.slice(-4)
    for (const [inAddr, val] of inbound) {
      if (inAddr !== outAddr && inAddr.startsWith(prefix) && inAddr.endsWith(suffix)) {
        // Only flag if the inbound was a tiny value (dust tx — classic poisoning)
        if (val < 0.01) {
          findings.push(`⚠ Poisoning detected: ${inAddr.slice(0, 12)}... sent dust (${val.toFixed(6)}) mimicking ${outAddr.slice(0, 12)}...`)
          score = Math.max(score, 75)
        } else {
          findings.push(`Similar addresses found but inbound value is substantial (${val.toFixed(4)}) — likely not poisoning`)
        }
      }
    }
  }

  if (findings.length === 0) findings.push('No address poisoning patterns detected')

  return { step: 5, name: 'Address Poisoning Detection', status: score >= 71 ? 'fail' : score >= 31 ? 'warn' : 'pass', score, source: 'Address Poisoning Detection', checks, findings }
}

// ── Step 6: Funding Source Analysis ────────────────────────────────────────────

function step6(txs: AgentTransaction[], wallet: string): { item: ChecklistItem; fundingSource: SlowMistReport['fundingSource'] } {
  const checks = ['First inbound transaction origin', 'Primary funding address', 'Funding concentration']
  const findings: string[] = []
  let score = 0
  const w = wallet.toLowerCase()
  let fundingSource: SlowMistReport['fundingSource'] = null

  // Find inbound transactions sorted by time (earliest first)
  const inbound = txs
    .filter(tx => tx.to?.toLowerCase() === w && Number(tx.value) > 0)
    .sort((a, b) => (a.timestamp ?? 0) - (b.timestamp ?? 0))

  if (inbound.length === 0) {
    findings.push('No inbound funding transactions found in scan window')
    return { item: { step: 6, name: 'Funding Source Analysis', status: 'skip', score: 0, source: 'Funding Trace', checks, findings }, fundingSource }
  }

  // First funder
  const firstFunder = inbound[0].from ?? 'unknown'
  const firstVal = Number(inbound[0].value) / Math.pow(10, inbound[0].tokenDecimals ?? 18)
  fundingSource = { address: firstFunder, label: isKnownSafe(firstFunder) ? 'known_contract' : 'eoa' }
  findings.push(`Initial funding from ${firstFunder.slice(0, 12)}... (${firstVal.toFixed(4)} ${inbound[0].tokenName ?? 'tokens'})`)

  // Funding concentration — is most money from one source?
  const fundingByAddr: Record<string, number> = {}
  let totalFunding = 0
  for (const tx of inbound) {
    const from = tx.from?.toLowerCase() ?? ''
    const val = Number(tx.value) / Math.pow(10, tx.tokenDecimals ?? 18)
    fundingByAddr[from] = (fundingByAddr[from] ?? 0) + val
    totalFunding += val
  }

  const topFunder = Object.entries(fundingByAddr).sort((a, b) => b[1] - a[1])[0]
  if (topFunder && totalFunding > 0) {
    const pct = Math.round((topFunder[1] / totalFunding) * 100)
    if (pct > 90 && inbound.length > 3) {
      findings.push(`${pct}% of all funding from single address ${topFunder[0].slice(0, 10)}... — high concentration`)
      score = Math.max(score, 25)
    } else {
      findings.push(`Primary funder: ${topFunder[0].slice(0, 10)}... (${pct}% of total)`)
    }
  }

  findings.push(`${inbound.length} inbound txs, ${Object.keys(fundingByAddr).length} unique funders`)

  return {
    item: { step: 6, name: 'Funding Source Analysis', status: score >= 31 ? 'warn' : 'pass', score, source: 'Funding Trace', checks, findings },
    fundingSource,
  }
}

// ── Step 7: Behavioral Analysis ────────────────────────────────────────────────

function step7(txs: AgentTransaction[], wallet: string): ChecklistItem {
  const checks = ['Failure rate', 'Large outbound', 'Counterparty concentration (excl. known contracts)', 'Transaction velocity', 'Time-series pattern']
  const findings: string[] = []
  let worst = 0
  const w = wallet.toLowerCase()
  const total = txs.length

  if (total === 0) {
    return { step: 7, name: 'Behavioral Analysis', status: 'skip', score: 0, source: 'Behavior Engine', checks, findings: ['No transactions'] }
  }

  // Failure rate
  const failed = txs.filter(t => t.isError).length
  if (failed > 0) {
    const pct = Math.round((failed / total) * 100)
    if (pct > 50) {
      findings.push(`${failed}/${total} failed (${pct}%) — extremely high`)
      worst = Math.max(worst, 75)
    } else if (pct > 20) {
      findings.push(`${failed}/${total} failed (${pct}%) — elevated`)
      worst = Math.max(worst, 40)
    } else {
      findings.push(`${failed}/${total} failed (${pct}%)`)
      worst = Math.max(worst, 15)
    }
  } else {
    findings.push('0 failed transactions')
  }

  // Large outbound (exclude known contracts)
  const largeOut = txs.filter(t => {
    if (t.from?.toLowerCase() !== w) return false
    if (isKnownSafe(t.to ?? '')) return false
    return Number(t.value) / Math.pow(10, t.tokenDecimals ?? 18) > 100
  })
  if (largeOut.length > 0) {
    findings.push(`${largeOut.length} large outbound (>100 tokens) to unknown addresses`)
    worst = Math.max(worst, 40)
  }

  // Counterparty concentration (EXCLUDE known safe contracts)
  const outByAddr: Record<string, number> = {}
  let outTotal = 0
  for (const tx of txs) {
    if (tx.from?.toLowerCase() !== w || !tx.to) continue
    if (isKnownSafe(tx.to)) continue // Don't count ERC-8004 registry etc
    const to = tx.to.toLowerCase()
    outByAddr[to] = (outByAddr[to] ?? 0) + 1
    outTotal++
  }
  if (outTotal > 5) {
    const top = Object.entries(outByAddr).sort((a, b) => b[1] - a[1])[0]
    if (top && top[1] > outTotal * 0.6) {
      findings.push(`${top[1]}/${outTotal} outbound txs to ${top[0].slice(0, 10)}... — high concentration`)
      worst = Math.max(worst, 35)
    }
  }

  // Velocity — rapid bursts
  const timestamps = txs.map(t => t.timestamp ?? 0).filter(t => t > 0).sort()
  if (timestamps.length >= 5) {
    let burstFound = false
    for (let i = 0; i < timestamps.length - 4; i++) {
      if (timestamps[i + 4] - timestamps[i] < 60) {
        if (!burstFound) {
          findings.push('Rapid burst detected (5+ txs within 60 seconds)')
          worst = Math.max(worst, 30)
          burstFound = true
        }
      }
    }
  }

  // Time-series: check if activity pattern changed (gap then sudden burst)
  if (timestamps.length >= 3) {
    const gaps: number[] = []
    for (let i = 1; i < timestamps.length; i++) {
      gaps.push(timestamps[i] - timestamps[i - 1])
    }
    const avgGap = gaps.reduce((s, g) => s + g, 0) / gaps.length
    const lastGap = gaps[gaps.length - 1]

    // If last gap is much shorter than average = sudden activity spike
    if (avgGap > 3600 && lastGap < 60 && gaps.length > 5) {
      findings.push('Activity spike detected — long dormancy followed by rapid transactions')
      worst = Math.max(worst, 35)
    }
  }

  if (findings.length <= 1) findings.push(`${total} transactions analyzed — normal patterns`)

  return { step: 7, name: 'Behavioral Analysis', status: worst >= 71 ? 'fail' : worst >= 31 ? 'warn' : 'pass', score: worst, source: 'Behavior Engine', checks, findings }
}

// ── Step 8: Cross-Chain Correlation ────────────────────────────────────────────
// Note: this is a placeholder — full implementation requires querying
// the DB for other agents owned by the same owner on other chains.
// The monitor route fills this via ownerAnalysis.

function step8(ownerAgentCount: number, ownerRiskScore: number): ChecklistItem {
  const checks = ['Owner agent count across chains', 'Owner address risk']
  const findings: string[] = []
  let score = 0

  if (ownerAgentCount > 10) {
    findings.push(`Owner controls ${ownerAgentCount} agents — high proliferation`)
    score = Math.max(score, 25)
  } else if (ownerAgentCount > 1) {
    findings.push(`Owner controls ${ownerAgentCount} agents`)
  } else {
    findings.push('Single agent per owner')
  }

  if (ownerRiskScore > 0) {
    findings.push(`Owner address risk score: ${ownerRiskScore}/100`)
    score = Math.max(score, ownerRiskScore)
  } else {
    findings.push('Owner address clean')
  }

  return { step: 8, name: 'Cross-Chain Correlation', status: score >= 71 ? 'fail' : score >= 31 ? 'warn' : 'pass', score, source: 'Owner Analysis', checks, findings }
}

// ── Step 9: Risk Scoring ───────────────────────────────────────────────────────

/**
 * Step 9: Unified Safety Score
 *
 * Combines:
 *   - Checklist risk scores (worst finding = penalty)
 *   - Whether agent has activity (no activity = unknown, not safe)
 *   - Number of checks that passed vs failed
 *
 * Output: overallScore is a SAFETY score (0=dangerous, 100=safe)
 * NOT a risk score. This aligns with Security Dimensions (also 0-100 safety).
 */
function step9(
  checklist: ChecklistItem[],
  txCount: number,
  dimensions?: { fundSafety: number; logicTransparency: number; compliance: number; techStability: number; behaviorConsistency: number },
): {
  overallScore: number; riskLevel: SlowMistReport['riskLevel']; verdict: SlowMistReport['verdict']; verdictReason: string
} {
  const worstRisk = Math.max(...checklist.map(c => c.score), 0)
  const passCount = checklist.filter(c => c.status === 'pass').length
  const warnCount = checklist.filter(c => c.status === 'warn').length
  const failCount = checklist.filter(c => c.status === 'fail').length
  const skipCount = checklist.filter(c => c.status === 'skip').length

  // Calculate safety score
  let safetyScore: number

  if (txCount === 0) {
    // No transactions = can't assess properly
    // If dimensions exist, use them but cap at 50 (can't be fully trusted without activity)
    if (dimensions) {
      const dimAvg = Math.round((dimensions.fundSafety + dimensions.logicTransparency + dimensions.compliance + dimensions.techStability + dimensions.behaviorConsistency) / 5)
      safetyScore = Math.min(dimAvg, 50)
    } else {
      safetyScore = 0 // truly unknown
    }
  } else if (dimensions) {
    // Has activity + dimensions: weighted average
    // 60% dimensions average + 40% checklist safety (100 - worstRisk)
    const dimAvg = (dimensions.fundSafety + dimensions.logicTransparency + dimensions.compliance + dimensions.techStability + dimensions.behaviorConsistency) / 5
    const checklistSafety = 100 - worstRisk
    safetyScore = Math.round(dimAvg * 0.6 + checklistSafety * 0.4)
  } else {
    // Has activity but no dimensions (shouldn't happen, fallback)
    safetyScore = 100 - worstRisk
  }

  // Determine verdict from safety score
  let riskLevel: SlowMistReport['riskLevel']
  let verdict: SlowMistReport['verdict']
  if (safetyScore >= 80) { riskLevel = 'low'; verdict = 'safe' }
  else if (safetyScore >= 60) { riskLevel = 'medium'; verdict = 'caution' }
  else if (safetyScore >= 30) { riskLevel = 'high'; verdict = 'caution' }
  else { riskLevel = 'severe'; verdict = 'reject' }

  // Build reason
  const reasons: string[] = []
  for (const item of checklist) {
    if (item.status === 'fail') {
      const detail = item.findings.filter(f => f.startsWith('⚠') || f.includes('flagged')).join('; ') || item.findings[0]
      reasons.push(`❌ ${item.name} (-${item.score} risk): ${detail}`)
    } else if (item.status === 'warn') {
      reasons.push(`⚠️ ${item.name} (-${item.score} risk): ${item.findings[0]}`)
    }
  }

  let verdictReason: string
  if (txCount === 0) {
    verdictReason = `No on-chain activity detected. Safety score capped at ${safetyScore}/100.`
    if (skipCount > 0) verdictReason += ` ${skipCount} checks skipped due to missing data.`
    verdictReason += ` Cannot fully assess without transaction history.`
  } else if (reasons.length === 0) {
    verdictReason = `${passCount} checks passed, ${skipCount} skipped. Safety score: ${safetyScore}/100.`
    if (dimensions) {
      const dim = dimensions
      verdictReason += ` Dimensions: Fund ${dim.fundSafety}, Logic ${dim.logicTransparency}, Compliance ${dim.compliance}, Tech ${dim.techStability}, Behavior ${dim.behaviorConsistency}.`
    }
  } else {
    verdictReason = `${reasons.length} issue(s):\n${reasons.join('\n')}\n\nSafety score: ${safetyScore}/100 (${riskLevel.toUpperCase()}).`
    if (safetyScore < 30) verdictReason += '\nDO NOT INTERACT — severe risk.'
    else if (safetyScore < 60) verdictReason += '\nRequire human confirmation before proceeding.'
  }

  return { overallScore: safetyScore, riskLevel, verdict, verdictReason }
}

// ── Behavior Tagging ─────────────────────────────────────────────────────────

function analyzeBehavior(txs: AgentTransaction[], wallet: string): {
  tags: BehaviorTag[]; activityLevel: SlowMistReport['activityLevel']
} {
  const w = wallet.toLowerCase()
  const total = txs.length
  if (total === 0) return { tags: [], activityLevel: 'dormant' }

  const cats: Record<string, number> = {}
  for (const tx of txs) {
    const method = tx.methodName?.toLowerCase() ?? ''
    const isOut = tx.from?.toLowerCase() === w
    let cat: string

    if (['register', 'setmetadata', 'setagentwallet', 'setagenturi'].includes(method)) cat = 'ERC-8004 Registration'
    else if (['approve', 'setapprovalforall'].includes(method)) cat = 'Token Approval'
    else if (method.includes('swap') || method.includes('exchange')) cat = 'DEX Swap'
    else if (['transfer', 'transferfrom', 'safetransferfrom'].includes(method)) cat = isOut ? 'Token Send' : 'Token Receive'
    else if (tx.txType === 'erc20') cat = isOut ? 'ERC-20 Send' : 'ERC-20 Receive'
    else if (method.includes('mint') || method.includes('claim')) cat = 'Mint / Claim'
    else if (method.includes('stake') || method.includes('deposit') || method.includes('withdraw')) cat = 'DeFi'
    else if (method.includes('buy') || method.includes('sell') || method.includes('order')) cat = 'Trading'
    else if (method && method !== 'transfer' && method !== 'contract_call') cat = `Contract: ${method}`
    else if (isOut && Number(tx.value) > 0) cat = 'Native Send'
    else if (!isOut && Number(tx.value) > 0) cat = 'Native Receive'
    else cat = 'Other'

    cats[cat] = (cats[cat] ?? 0) + 1
  }

  const tags = Object.entries(cats)
    .sort((a, b) => b[1] - a[1])
    .map(([tag, count]) => ({ tag, count, percentage: Math.round((count / total) * 100) }))

  const timestamps = txs.map(t => t.timestamp ?? 0).filter(t => t > 0).sort()
  const span = timestamps.length >= 2 ? (timestamps[timestamps.length - 1] - timestamps[0]) / 86400 : 0
  const rate = span > 0 ? total / span : total

  let activityLevel: SlowMistReport['activityLevel']
  if (total <= 2) activityLevel = 'low'
  else if (rate >= 10) activityLevel = 'very_high'
  else if (rate >= 3) activityLevel = 'high'
  else if (rate >= 0.5) activityLevel = 'moderate'
  else activityLevel = 'low'

  return { tags, activityLevel }
}

// ── Main Analyzer ──────────────────────────────────────────────────────────────

export async function runSlowMistAnalysis(
  agentId: string,
  chain: string,
  walletAddress: string,
  transactions: AgentTransaction[],
  ownerAgentCount: number = 1,
  ownerRiskScore: number = 0,
): Promise<SlowMistReport> {
  const chainId = GOPLUS_CHAIN_IDS[chain] ?? ''
  const w = walletAddress.toLowerCase()

  // Collect addresses
  const counterparties = new Set<string>()
  const contracts = new Set<string>()
  const tokens = new Set<string>()

  for (const tx of transactions) {
    const addr = tx.from?.toLowerCase() === w ? tx.to : tx.from
    if (addr && addr !== '0x0000000000000000000000000000000000000000') counterparties.add(addr.toLowerCase())
    if (tx.methodName && !['transfer', 'approve'].includes(tx.methodName) && tx.to) contracts.add(tx.to.toLowerCase())
    if (tx.txType === 'erc20' && tx.contractAddress) tokens.add(tx.contractAddress.toLowerCase())
  }

  // ── Solana-specific checklist ──────────────────────────────────────────
  if (chain === 'solana') {
    const { runSolanaStep1_AddressRisk, runSolanaStep2_ProgramReview, runSolanaStep3_TokenSecurity, runSolanaStep4_DelegateAuthority } = await import('./solana-security.js')

    const [sol1, sol3] = await Promise.all([
      runSolanaStep1_AddressRisk([walletAddress, ...counterparties]),
      runSolanaStep3_TokenSecurity([...tokens]),
    ])
    const sol2 = await runSolanaStep2_ProgramReview([...contracts])
    const sol4 = runSolanaStep4_DelegateAuthority(transactions)
    const sol6 = step6(transactions, walletAddress)
    const sol7 = step7(transactions, walletAddress)
    const sol8 = step8(ownerAgentCount, ownerRiskScore)

    const checklist = [sol1.item, sol2, sol3.item, sol4, sol6.item, sol7, sol8]

    // Per-tx risk from address results
    for (const tx of transactions) {
      tx.riskFlags = []
      let riskScore = 0
      const cp = tx.from?.toLowerCase() === w ? (tx.to?.toLowerCase() ?? '') : (tx.from?.toLowerCase() ?? '')
      const ar = sol1.results[cp]
      if (ar && ar.score > 0) { tx.riskFlags.push(...ar.flags.map(f => `address:${f}`)); riskScore = Math.max(riskScore, ar.score) }
      if (tx.isError) { tx.riskFlags.push('failed_tx'); riskScore = Math.max(riskScore, 15) }
      if (riskScore >= 91) tx.riskLevel = 'dangerous'
      else if (riskScore >= 31) tx.riskLevel = 'suspicious'
      else tx.riskLevel = 'safe'
      ;(tx as any).riskScore = riskScore
    }

    const dimScores = {
      fundSafety: Math.max(0, 100 - sol3.item.score),
      logicTransparency: Math.max(0, 100 - sol2.score),
      compliance: Math.max(0, 100 - sol1.item.score),
      techStability: Math.max(0, transactions.length > 0 ? 100 - (transactions.filter(t => t.isError).length / transactions.length * 100) : 50),
      behaviorConsistency: Math.max(0, 100 - sol7.score),
    }

    const { overallScore, riskLevel, verdict, verdictReason } = step9(checklist, transactions.length, dimScores)
    const { tags: behaviorTags, activityLevel } = analyzeBehavior(transactions, walletAddress)
    const passCount = checklist.filter(c => c.status === 'pass').length
    const warnCount = checklist.filter(c => c.status === 'warn').length
    const failCount = checklist.filter(c => c.status === 'fail').length
    const topBehavior = behaviorTags.slice(0, 3).map(t => `${t.tag} (${t.percentage}%)`).join(', ')

    return {
      agentId, chain, walletAddress, checklist,
      overallScore, riskLevel, verdict, verdictReason,
      summary: `${failCount > 0 ? `${failCount} critical.` : ''} ${warnCount > 0 ? `${warnCount} warnings.` : 'All checks passed.'} Activity: ${activityLevel}. ${topBehavior || 'Solana agent'}.`,
      behaviorTags, activityLevel,
      fundingSource: sol6.fundingSource,
      metadata: { addressesScanned: counterparties.size + 1, contractsScanned: contracts.size, tokensScanned: tokens.size, transactionsAnalyzed: transactions.length, timestamp: Date.now() },
    }
  }

  // ── EVM checklist (original) ───────────────────────────────────────────

  // Run steps 1-3 in parallel (API calls)
  const [s1, s2, s3] = await Promise.all([
    step1([...counterparties], chainId),
    step2([...contracts], chainId),
    step3([...tokens], chainId),
  ])

  // Steps 4-8 are local analysis
  const s4 = step4(transactions)
  const s5 = step5(transactions, walletAddress)
  const s6 = step6(transactions, walletAddress)
  const s7 = step7(transactions, walletAddress)
  const s8 = step8(ownerAgentCount, ownerRiskScore)

  const checklist = [s1.item, s2.item, s3.item, s4, s5, s6.item, s7, s8]

  // Apply per-transaction risk scores
  for (const tx of transactions) {
    tx.riskFlags = []
    let riskScore = 0
    const toAddr = tx.to?.toLowerCase() ?? ''
    const counterparty = tx.from?.toLowerCase() === w ? toAddr : (tx.from?.toLowerCase() ?? '')

    // Skip known safe
    if (isKnownSafe(toAddr) && Number(tx.value) === 0) {
      tx.riskLevel = 'safe'
      ;(tx as any).riskScore = 0
      continue
    }

    const ar = s1.results[counterparty]
    if (ar && ar.score > 0) { tx.riskFlags.push(...ar.flags.map(f => `address:${f}`)); riskScore = Math.max(riskScore, ar.score) }

    const cr = s2.results[toAddr]
    if (cr && cr.flags.length > 0) { tx.riskFlags.push(...cr.flags.map(f => `contract:${f}`)); if (cr.flags.includes('unverified_source')) riskScore = Math.max(riskScore, 71) }

    if (tx.contractAddress) {
      const tr = s3.results[tx.contractAddress.toLowerCase()]
      if (tr && tr.flags.length > 0) { tx.riskFlags.push(...tr.flags.map(f => `token:${f}`)); if (tr.flags.some(f => f === 'honeypot')) riskScore = Math.max(riskScore, 95) }
    }

    const method = tx.methodName?.toLowerCase() ?? ''
    if (method === 'approve' && !isKnownSafe(toAddr)) {
      const val = Number(tx.value) / Math.pow(10, tx.tokenDecimals ?? 18)
      if (val > 1e12) { tx.riskFlags.push('unlimited_approval'); riskScore = Math.max(riskScore, 60) }
    }
    if (method === 'setapprovalforall') { tx.riskFlags.push('nft_approval_all'); riskScore = Math.max(riskScore, 50) }
    if (tx.isError) { tx.riskFlags.push('failed_tx'); riskScore = Math.max(riskScore, 15) }

    if (riskScore >= 91) tx.riskLevel = 'dangerous'
    else if (riskScore >= 31) tx.riskLevel = 'suspicious'
    else tx.riskLevel = 'safe'
    ;(tx as any).riskScore = riskScore
  }

  const { tags: behaviorTags, activityLevel } = analyzeBehavior(transactions, walletAddress)

  // Import profileAgent dimensions for unified scoring
  // We compute a lightweight version here (the full profiler runs separately in the route)
  const dimScores = {
    fundSafety: Math.max(0, 100 - (s3.item.score * 0.5) - (s1.results ? Object.values(s1.results).filter(r => r.score > 50).length * 15 : 0)),
    logicTransparency: Math.max(0, 100 - (s2.item.score)),
    compliance: Math.max(0, 100 - (s1.item.score * 0.3)),
    techStability: Math.max(0, transactions.length > 0 ? 100 - (transactions.filter(t => t.isError).length / transactions.length * 100) - (s7.score > 30 ? 15 : 0) : 50),
    behaviorConsistency: Math.max(0, 100 - s7.score),
  }

  const { overallScore, riskLevel, verdict, verdictReason } = step9(checklist, transactions.length, dimScores)

  const passCount = checklist.filter(c => c.status === 'pass').length
  const warnCount = checklist.filter(c => c.status === 'warn').length
  const failCount = checklist.filter(c => c.status === 'fail').length
  const topBehavior = behaviorTags.slice(0, 3).map(t => `${t.tag} (${t.percentage}%)`).join(', ')

  const summary = failCount > 0
    ? `${failCount} critical, ${warnCount} warnings. Activity: ${activityLevel}. Behavior: ${topBehavior || 'unknown'}.`
    : warnCount > 0
      ? `${warnCount} warning(s). Activity: ${activityLevel}. Behavior: ${topBehavior || 'unknown'}.`
      : `All ${passCount} checks passed (${overallScore}/100). Activity: ${activityLevel}. Behavior: ${topBehavior || 'unknown'}.`

  return {
    agentId, chain, walletAddress, checklist,
    overallScore, riskLevel, verdict, verdictReason, summary,
    behaviorTags, activityLevel,
    fundingSource: s6.fundingSource,
    metadata: {
      addressesScanned: counterparties.size,
      contractsScanned: contracts.size,
      tokensScanned: tokens.size,
      transactionsAnalyzed: transactions.length,
      timestamp: Date.now(),
    },
  }
}
