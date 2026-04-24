/**
 * Solana Agent Registry (ERC-8004 on Solana)
 *
 * Uses the 8004-indexer GraphQL API to query registered agents.
 * Program: 8oo4dC4JvBLwy5tGgiH3WwK4B9PWxL9Z4XjA2jzkQMbQ
 * API: https://8004-indexer-main.qnt.sh/v2/graphql
 */

const GRAPHQL_URL = 'https://8004-indexer-main.qnt.sh/v2/graphql'

// ── Types ──────────────────────────────────────────────────────────────────────

export interface SolanaAgent {
  agentId: string
  owner: string
  wallet: string | null
  name: string
  description: string | null
  totalFeedback: number
  createdAt: number
  assetId: string   // Solana asset public key
}

export interface SolanaAgentDetail {
  agentId: string
  owner: string
  wallet: string | null
  name: string
  description: string | null
  totalFeedback: number
  createdAt: number
  assetId: string
  stats: {
    totalFeedbackCount: number
    averageRating: number | null
    qualityScore: number | null
    trustTier: string | null
  } | null
  feedback: {
    value: string
    tag1: string
    tag2: string
    client: string
    createdAt: number
  }[]
}

// ── GraphQL helper ─────────────────────────────────────────────────────────────

async function gql(query: string, variables?: Record<string, any>, retries = 2): Promise<any> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(GRAPHQL_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, variables }),
        signal: AbortSignal.timeout(15000),
      })
      if (!res.ok) continue
      const data = await res.json()
      if (data.errors) {
        console.error('[solana-registry] GraphQL errors:', data.errors)
        return null
      }
      return data.data
    } catch (err) {
      if (attempt < retries) continue
      console.error('[solana-registry] GraphQL fetch failed after retries:', err)
      return null
    }
  }
  return null
}

// ── Fetch agents ───────────────────────────────────────────────────────────────

export async function getSolanaAgents(limit: number = 100): Promise<SolanaAgent[]> {
  const data = await gql(`{
    agents(first: ${limit}, orderBy: createdAt, orderDirection: desc) {
      id agentId owner agentWallet createdAt totalFeedback
      registrationFile { name description }
    }
  }`)
  if (!data?.agents) return []

  return data.agents.map((a: any) => ({
    agentId: a.agentId?.toString() ?? a.id,
    owner: a.owner,
    wallet: a.agentWallet || null,
    name: a.registrationFile?.name ?? `Agent #${a.agentId ?? a.id}`,
    description: a.registrationFile?.description ?? null,
    totalFeedback: Number(a.totalFeedback ?? 0),
    createdAt: Number(a.createdAt ?? 0),
    assetId: a.id,
  }))
}

// ── Fetch agent detail ─────────────────────────────────────────────────────────

export async function getSolanaAgentDetail(assetId: string): Promise<SolanaAgentDetail | null> {
  const data = await gql(`{
    agent(id: "${assetId}") {
      id agentId owner agentWallet createdAt totalFeedback
      registrationFile { name description }
      stats { totalFeedback averageFeedbackValue }
      feedback(first: 20) { value tag1 tag2 clientAddress createdAt }
    }
  }`)
  if (!data?.agent) return null

  const a = data.agent
  return {
    agentId: a.agentId?.toString() ?? a.id,
    owner: a.owner,
    wallet: a.agentWallet || null,
    name: a.registrationFile?.name ?? `Agent #${a.agentId}`,
    description: a.registrationFile?.description ?? null,
    totalFeedback: Number(a.totalFeedback ?? 0),
    createdAt: Number(a.createdAt ?? 0),
    assetId: a.id,
    stats: a.stats ? {
      totalFeedbackCount: Number(a.stats.totalFeedback ?? 0),
      averageRating: a.stats.averageFeedbackValue ? Number(a.stats.averageFeedbackValue) : null,
      qualityScore: null,
      trustTier: null,
    } : null,
    feedback: (a.feedback ?? []).map((f: any) => ({
      value: f.value,
      tag1: f.tag1 ?? '',
      tag2: f.tag2 ?? '',
      client: f.clientAddress ?? '',
      createdAt: Number(f.createdAt ?? 0),
    })),
  }
}

// ── Fetch Solana transactions for a wallet ──────────────────────────────────────

export async function getSolanaWalletTransactions(walletAddress: string, limit: number = 20): Promise<any[]> {
  try {
    const rpcUrl = process.env.SOLANA_RPC_URL ?? 'https://api.mainnet-beta.solana.com'

    const sigRes = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getSignaturesForAddress',
        params: [walletAddress, { limit }],
      }),
      signal: AbortSignal.timeout(10000),
    })

    const sigData: any = await sigRes.json()
    const signatures = sigData.result ?? []

    return signatures.map((sig: any) => ({
      hash: sig.signature,
      blockTime: sig.blockTime,
      slot: sig.slot,
      isError: sig.err !== null,
      memo: sig.memo,
    }))
  } catch (err) {
    console.error('[solana-registry] Failed to fetch transactions:', err)
    return []
  }
}

// ── Global stats ───────────────────────────────────────────────────────────────

export async function getSolanaGlobalStats(): Promise<{ totalAgents: number; totalFeedback: number } | null> {
  const data = await gql(`{ globalStats { totalAgents totalFeedback } }`)
  if (!data?.globalStats) return null
  return {
    totalAgents: Number(data.globalStats.totalAgents ?? 0),
    totalFeedback: Number(data.globalStats.totalFeedback ?? 0),
  }
}
