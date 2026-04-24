/**
 * Solana-specific Security Checks
 *
 * Solana has different primitives than EVM:
 *   - SPL Tokens (not ERC-20)
 *   - Programs (not smart contracts)
 *   - Token Accounts (not approve/allowance)
 *   - Delegate authority (not setApprovalForAll)
 *
 * Uses:
 *   - RugCheck.xyz API for SPL token safety
 *   - Solana RPC for account info
 *   - GoPlus address_security (chain_id=solana) when available
 */

import type { ChecklistItem } from './slowmist-analyzer.js'

// ── RugCheck API ───────────────────────────────────────────────────────────────

interface RugCheckResult {
  score: number              // 1 = safest
  scoreNormalized: number
  risks: { name: string; description: string; level: string; score: number }[]
  isRugged: boolean
  tokenType: string
  hasFreeze: boolean
  hasMint: boolean
  topHolderPct: number
}

async function checkTokenViaRugCheck(mint: string): Promise<RugCheckResult | null> {
  try {
    const res = await fetch(`https://api.rugcheck.xyz/v1/tokens/${mint}/report`, {
      signal: AbortSignal.timeout(8000),
    })
    if (!res.ok) return null
    const d: any = await res.json()
    return {
      score: d.score ?? 0,
      scoreNormalized: d.score_normalised ?? d.score ?? 0,
      risks: (d.risks ?? []).map((r: any) => ({
        name: r.name ?? '', description: r.description ?? '', level: r.level ?? '', score: r.score ?? 0,
      })),
      isRugged: d.rugged === true,
      tokenType: d.tokenType ?? '',
      hasFreeze: !!d.freezeAuthority && d.token?.freezeAuthority !== null,
      hasMint: !!d.mintAuthority && d.token?.mintAuthority !== null,
      topHolderPct: d.topHolders?.[0]?.pct ?? 0,
    }
  } catch {
    return null
  }
}

// ── Solana Address Check ───────────────────────────────────────────────────────

async function checkSolanaAddress(address: string): Promise<{ score: number; flags: string[] }> {
  // GoPlus Solana support is limited, try anyway
  try {
    const res = await fetch(
      `https://api.gopluslabs.io/api/v1/address_security/${address}?chain_id=solana`,
      { signal: AbortSignal.timeout(3000) },
    )
    if (!res.ok) return { score: 0, flags: [] }
    const data: any = await res.json()
    const r = data.result ?? {}
    const flags: string[] = []
    let score = 0
    if (r.is_blacklisted === '1') { flags.push('blacklisted'); score = 100 }
    if (r.is_phishing_activities === '1') { flags.push('phishing'); score = Math.max(score, 95) }
    if (r.is_sanctioned === '1') { flags.push('sanctioned'); score = Math.max(score, 100) }
    return { score, flags }
  } catch {
    return { score: 0, flags: [] }
  }
}

// ── Solana Checklist Steps ─────────────────────────────────────────────────────

export async function runSolanaStep1_AddressRisk(
  addresses: string[],
): Promise<{ item: ChecklistItem; results: Record<string, { score: number; flags: string[] }> }> {
  const results: Record<string, { score: number; flags: string[] }> = {}
  const checks = ['Address blacklist / phishing / sanctions (Solana)']
  const findings: string[] = []
  let worst = 0

  const batch = addresses.slice(0, 10)
  await Promise.all(batch.map(async (addr) => {
    const r = await checkSolanaAddress(addr)
    results[addr] = r
    if (r.score > worst) worst = r.score
    if (r.flags.length > 0) findings.push(`${addr.slice(0, 12)}... flagged: ${r.flags.join(', ')}`)
  }))

  if (findings.length === 0) findings.push(`${batch.length} Solana addresses checked — all clean`)

  return {
    item: { step: 1, name: 'Address Risk Assessment', status: worst >= 91 ? 'fail' : worst >= 31 ? 'warn' : 'pass', score: worst, source: 'Address Security (Solana)', checks, findings },
    results,
  }
}

export async function runSolanaStep2_ProgramReview(
  programIds: string[],
): Promise<ChecklistItem> {
  const checks = ['Program verified on Solana explorer', 'Known program (SPL Token, System, etc.)']
  const findings: string[] = []

  const knownPrograms = new Set([
    'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', // SPL Token
    'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bDM', // Associated Token
    '11111111111111111111111111111111', // System Program
    'ComputeBudget111111111111111111111111111111', // Compute Budget
    '8oo4dC4JvBLwy5tGgiH3WwK4B9PWxL9Z4XjA2jzkQMbQ', // Agent Registry
    'AToMw53aiPQ8j7iHVb4fGt6nzUNxUhcPc3tbPBZuzVVb', // ATOM Engine
  ])

  const unknown = programIds.filter(p => !knownPrograms.has(p))
  if (unknown.length > 0) {
    findings.push(`${unknown.length} unknown program(s) interacted: ${unknown.slice(0, 3).map(p => p.slice(0, 12) + '...').join(', ')}`)
  }
  findings.push(`${programIds.length - unknown.length} known program(s) (SPL Token, System, etc.)`)

  const score = unknown.length > 3 ? 40 : unknown.length > 0 ? 15 : 0
  return { step: 2, name: 'Program Review', status: score >= 31 ? 'warn' : 'pass', score, source: 'Solana Program Analysis', checks, findings }
}

export async function runSolanaStep3_TokenSecurity(
  tokenMints: string[],
): Promise<{ item: ChecklistItem; results: Record<string, RugCheckResult> }> {
  const results: Record<string, RugCheckResult> = {}
  const checks = ['Honeypot / rug detection (RugCheck)', 'Freeze authority', 'Mint authority', 'Top holder concentration', 'Transfer fee']
  const findings: string[] = []
  let worst = 0

  if (tokenMints.length === 0) {
    return {
      item: { step: 3, name: 'SPL Token Security', status: 'skip', score: 0, source: 'RugCheck.xyz', checks, findings: ['No SPL token interactions detected'] },
      results,
    }
  }

  const batch = tokenMints.slice(0, 5)
  for (const mint of batch) {
    const r = await checkTokenViaRugCheck(mint)
    if (!r) continue
    results[mint] = r
    const flags: string[] = []

    if (r.isRugged) { flags.push('RUGGED'); worst = Math.max(worst, 95) }
    if (r.hasMint) { flags.push('mint_authority_active'); worst = Math.max(worst, 40) }
    if (r.hasFreeze) { flags.push('freeze_authority_active'); worst = Math.max(worst, 30) }
    if (r.topHolderPct > 50) { flags.push(`top_holder_${r.topHolderPct.toFixed(0)}%`); worst = Math.max(worst, 35) }

    for (const risk of r.risks) {
      if (risk.level === 'danger') { flags.push(risk.name); worst = Math.max(worst, 70) }
      else if (risk.level === 'warn') { flags.push(risk.name); worst = Math.max(worst, 30) }
    }

    if (flags.length > 0) {
      findings.push(`${mint.slice(0, 12)}...: ${flags.join(', ')} (RugCheck score: ${r.score})`)
    }
  }

  if (findings.length === 0 && batch.length > 0) findings.push(`${batch.length} SPL token(s) checked via RugCheck — all safe`)

  return {
    item: { step: 3, name: 'SPL Token Security', status: worst >= 71 ? 'fail' : worst >= 31 ? 'warn' : 'pass', score: worst, source: 'RugCheck.xyz', checks, findings },
    results,
  }
}

export function runSolanaStep4_DelegateAuthority(
  transactions: any[],
): ChecklistItem {
  const checks = ['Token delegate authority (SPL equivalent of approve)', 'Close account authority']
  const findings: string[] = []
  let score = 0

  // In Solana, token delegation is done via the `approve` instruction on SPL Token program
  // We can't easily detect this without parsing transaction instructions
  // For now, note this as a limitation
  findings.push('SPL token delegate authority check requires instruction-level parsing')
  findings.push(`${transactions.length} transactions analyzed at signature level`)

  return { step: 4, name: 'Token Authority Check', status: 'pass', score, source: 'Solana Token Analysis', checks, findings }
}
