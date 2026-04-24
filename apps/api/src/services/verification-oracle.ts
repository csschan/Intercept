/**
 * Verification Oracle
 *
 * Intercept as a Verification-as-a-Service:
 *   1. Run full security analysis on an ERC-8004 agent
 *   2. Generate a signed verification report (hash proof)
 *   3. Write the result to ERC-8004 Reputation Registry on-chain
 *   4. Return a verifiable certificate
 *
 * "The most expensive thing in the future is not intelligence, but verification."
 */

import { createHash } from 'crypto'
import { createWalletClient, createPublicClient, http, parseAbiItem, type Chain } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { mainnet, bsc, arbitrum, base, polygon, optimism } from 'viem/chains'
import { IDENTITY_REGISTRY, REPUTATION_REGISTRY, SUPPORTED_CHAINS } from './erc8004.js'
import { runSlowMistAnalysis, type SlowMistReport } from './slowmist-analyzer.js'
import { profileAgent, type AgentProfile } from './agent-profiler.js'

// ── Types ──────────────────────────────────────────────────────────────────────

export interface VerificationReport {
  // Identity
  agentId: string
  chain: string
  walletAddress: string | null

  // Scores
  securityScore: number
  grade: string
  verdict: string
  riskLevel: string

  // Dimensions
  dimensions: {
    fundSafety: number
    logicTransparency: number
    compliance: number
    techStability: number
    behaviorConsistency: number
  }

  // Key findings
  criticalIssues: number
  warnings: number
  checksRun: number
  checksPassed: number

  // Proof
  reportHash: string       // SHA-256 of the full report data
  timestamp: number
  verifier: string         // Intercept's verifier address
  signature: string        // hex signature of reportHash

  // On-chain
  onChainTxHash: string | null   // tx hash of giveFeedback call
  onChainStatus: 'pending' | 'submitted' | 'confirmed' | 'skipped'

  // Full data (for deep inspection)
  checklist: SlowMistReport['checklist']
  alerts: AgentProfile['alerts']
  verdictReason: string
}

// ── Chain config ───────────────────────────────────────────────────────────────

const CHAIN_MAP: Record<string, Chain> = {
  ethereum: mainnet, bsc, arbitrum, base, polygon, optimism,
}

const REPUTATION_ABI = [
  parseAbiItem('function giveFeedback(uint256 agentId, int128 value, uint8 valueDecimals, string tag1, string tag2, string endpoint, string feedbackURI, bytes32 feedbackHash)'),
] as const

// ── Report Hash ────────────────────────────────────────────────────────────────

function computeReportHash(data: {
  agentId: string; chain: string; securityScore: number; grade: string;
  verdict: string; dimensions: Record<string, number>; timestamp: number;
}): string {
  const payload = JSON.stringify(data, Object.keys(data).sort())
  return '0x' + createHash('sha256').update(payload).digest('hex')
}

// ── Sign report ────────────────────────────────────────────────────────────────

function getVerifierAccount() {
  // Use Arc testnet key as verifier identity (same key, different purpose)
  const pk = process.env.VERIFIER_PRIVATE_KEY ?? process.env.ARC_TESTNET_PRIVATE_KEY
  if (!pk) return null
  return privateKeyToAccount(pk as `0x${string}`)
}

async function signReport(reportHash: string): Promise<{ signature: string; verifier: string }> {
  const account = getVerifierAccount()
  if (!account) return { signature: '0x', verifier: '0x0' }

  const signature = await account.signMessage({
    message: reportHash,
  })

  return { signature, verifier: account.address }
}

// ── Write to ERC-8004 Reputation Registry ──────────────────────────────────────

async function writeToReputationRegistry(
  chain: string,
  agentId: string,
  score: number,
  reportHash: string,
): Promise<{ txHash: string | null; status: string }> {
  const chainConfig = SUPPORTED_CHAINS[chain]
  if (!chainConfig) return { txHash: null, status: 'chain_not_supported' }

  const account = getVerifierAccount()
  if (!account) return { txHash: null, status: 'no_verifier_key' }

  try {
    const walletClient = createWalletClient({
      account,
      chain: CHAIN_MAP[chain],
      transport: http(chainConfig.rpcUrl),
    })

    // Convert score to int128 feedback value
    // Score 0-100 → feedback value 0-10000 (2 decimals)
    const feedbackValue = BigInt(score * 100)

    const txHash = await walletClient.writeContract({
      address: REPUTATION_REGISTRY as `0x${string}`,
      abi: REPUTATION_ABI,
      functionName: 'giveFeedback',
      args: [
        BigInt(agentId),
        feedbackValue,           // int128 value
        2,                       // uint8 valueDecimals (2 = score/100)
        'intercept-security',    // tag1
        'verification',          // tag2
        'https://intercept.security/verify',  // endpoint
        '',                      // feedbackURI (could be IPFS link to full report)
        reportHash as `0x${string}`,  // feedbackHash
      ],
    })

    return { txHash, status: 'submitted' }
  } catch (err: any) {
    console.error(`[verify] Failed to write to Reputation Registry:`, err?.message ?? err)
    // Don't fail the verification — on-chain write is optional
    return { txHash: null, status: `failed: ${err?.message?.slice(0, 100) ?? 'unknown'}` }
  }
}

// ── Main Verification Function ─────────────────────────────────────────────────

export async function verifyAgent(
  agentId: string,
  chain: string,
  walletAddress: string | null,
  transactions: any[],
  writeOnChain: boolean = false,
  ownerAgentCount: number = 1,
  ownerRiskScore: number = 0,
): Promise<VerificationReport> {
  const timestamp = Date.now()
  const wallet = walletAddress ?? ''

  // 1. Run full security analysis
  const slowmist = await runSlowMistAnalysis(agentId, chain, wallet, transactions, ownerAgentCount, ownerRiskScore)

  // 2. Run multi-dimension profiler
  const profile = await profileAgent(chain, wallet, transactions, {}, {}, {})

  // 3. Run deep analysis (26 dimensions)
  let deepPenalty = 0
  try {
    const { runDeepAnalysis } = await import('./deep-analyzer.js')
    const goplusChainId = { ethereum: '1', bsc: '56', polygon: '137', arbitrum: '42161', base: '8453', optimism: '10' }[chain] ?? ''
    if (wallet && transactions.length > 0) {
      const deep = await runDeepAnalysis(goplusChainId, wallet, transactions, null, {})
      deepPenalty = Math.min(20, deep.totalPenalty)
    }
  } catch {}

  // 4. Compute unified score (same formula as monitor route)
  const dim = profile.dimensions
  const dimAvg = (dim.fundSafety + dim.logicTransparency + dim.compliance + dim.techStability + dim.behaviorConsistency) / 5
  const rugPenalty = Math.round(profile.rugPullIndex.score * 0.3)
  const gasPenalty = profile.gasAnomaly.detected ? 5 : 0
  const driftPenalty = Math.round(profile.logicDrift.score * 0.15)
  const checklistWorst = Math.max(...slowmist.checklist.map(c => c.score), 0)
  const checklistPenalty = Math.round(checklistWorst * 0.2)

  const securityScore = transactions.length === 0
    ? Math.min(50, Math.round(dimAvg) - rugPenalty)
    : Math.max(0, Math.min(100, Math.round(dimAvg) - rugPenalty - gasPenalty - driftPenalty - checklistPenalty - deepPenalty))
  const grade = profile.overallGrade

  // 4. Generate report hash (deterministic)
  const reportHash = computeReportHash({
    agentId, chain, securityScore, grade,
    verdict: slowmist.verdict,
    dimensions: profile.dimensions,
    timestamp,
  })

  // 5. Sign the report
  const { signature, verifier } = await signReport(reportHash)

  // 6. Optionally write to on-chain Reputation Registry
  let onChainTxHash: string | null = null
  let onChainStatus: VerificationReport['onChainStatus'] = 'skipped'

  if (writeOnChain && chain !== 'solana') {
    const result = await writeToReputationRegistry(chain, agentId, securityScore, reportHash)
    onChainTxHash = result.txHash
    onChainStatus = result.txHash ? 'submitted' : 'skipped'
  }

  // 7. Build report
  const criticalIssues = slowmist.checklist.filter(c => c.status === 'fail').length
  const warnings = slowmist.checklist.filter(c => c.status === 'warn').length
  const checksRun = slowmist.checklist.filter(c => c.status !== 'skip').length
  const checksPassed = slowmist.checklist.filter(c => c.status === 'pass').length

  return {
    agentId, chain,
    walletAddress: walletAddress,
    securityScore, grade,
    verdict: slowmist.verdict,
    riskLevel: slowmist.riskLevel,
    dimensions: profile.dimensions,
    criticalIssues, warnings, checksRun, checksPassed,
    reportHash, timestamp, verifier, signature,
    onChainTxHash, onChainStatus,
    checklist: slowmist.checklist,
    alerts: profile.alerts,
    verdictReason: slowmist.verdictReason,
  }
}
