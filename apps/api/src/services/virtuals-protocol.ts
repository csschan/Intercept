/**
 * Virtuals Protocol Integration
 *
 * Identifies agents on Base that are part of the Virtuals Protocol ecosystem.
 * Uses the Virtuals API to fetch agent tokens, then cross-references with
 * ERC-8004 agent wallet/owner addresses to tag them.
 *
 * Key identifiers:
 *   - VIRTUAL Token (Base): 0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b
 *   - Each Virtuals agent has: AgentNft token ID, ERC-20 agent token, ERC-6551 TBA
 */

// ── Types ──────────────────────────────────────────────────────────────────────

export interface VirtualsAgent {
  id: number
  name: string
  symbol: string
  tokenAddress: string       // ERC-20 agent token on Base
  tbaAddress?: string        // Token Bound Account (ERC-6551)
  imageUrl?: string
  category?: string
  mcap?: number
  holders?: number
  virtualId?: string         // Virtuals platform ID
}

// ── Cache ──────────────────────────────────────────────────────────────────────

let virtualsCache: Map<string, VirtualsAgent> = new Map()  // keyed by lowercase address
let lastFetchTime = 0
const CACHE_TTL = 10 * 60 * 1000  // 10 minutes

// ── Fetch Virtuals agents ──────────────────────────────────────────────────────

export async function fetchVirtualsAgents(): Promise<VirtualsAgent[]> {
  // Return cache if fresh
  if (Date.now() - lastFetchTime < CACHE_TTL && virtualsCache.size > 0) {
    return Array.from(virtualsCache.values())
  }

  try {
    // Virtuals public API — fetch agents
    const res = await fetch('https://api.virtuals.io/api/virtuals?limit=500', {
      headers: { 'origin': 'https://app.virtuals.io' },
      signal: AbortSignal.timeout(10000),
    })

    if (!res.ok) {
      console.error(`[virtuals] API returned ${res.status}`)
      return Array.from(virtualsCache.values())
    }

    const data = await res.json() as any
    const tokens = data?.data ?? data ?? []

    if (!Array.isArray(tokens)) {
      console.error('[virtuals] Unexpected response format')
      return Array.from(virtualsCache.values())
    }

    const newCache = new Map<string, VirtualsAgent>()

    for (const t of tokens) {
      // Virtuals API returns walletAddress (owner) and sentientWalletAddress (TBA/agent wallet)
      const tokenAddress = (t.tokenAddress ?? t.token_address ?? t.walletAddress ?? '').toLowerCase()
      const tbaAddress = (t.sentientWalletAddress ?? t.tbaAddress ?? '').toLowerCase()

      if (!tokenAddress && !tbaAddress) continue

      const agent: VirtualsAgent = {
        id: t.id ?? 0,
        name: t.name ?? 'Unknown',
        symbol: t.symbol ?? '',
        tokenAddress,
        tbaAddress: tbaAddress || undefined,
        imageUrl: t.image?.url ?? t.image ?? t.imageUrl,
        category: t.category ?? t.role,
        mcap: Number(t.mcap ?? t.market_cap ?? 0),
        holders: Number(t.holders ?? t.holderCount ?? 0),
        virtualId: String(t.id ?? ''),
      }

      // Index by both token address and TBA address for matching
      if (tokenAddress) newCache.set(tokenAddress, agent)
      if (tbaAddress) newCache.set(tbaAddress, agent)
    }

    virtualsCache = newCache
    lastFetchTime = Date.now()
    console.log(`[virtuals] Cached ${tokens.length} agents (${newCache.size} addresses indexed)`)

    return Array.from(new Map([...newCache].filter(([, v]) => v.name !== 'Unknown')).values())
  } catch (err) {
    console.error('[virtuals] Failed to fetch agents:', err)
    return Array.from(virtualsCache.values())
  }
}

// ── Match function ─────────────────────────────────────────────────────────────

/**
 * Check if an address (owner or wallet) belongs to a Virtuals Protocol agent.
 * Returns the Virtuals agent info if matched, null otherwise.
 */
export function matchVirtualsAgent(address: string): VirtualsAgent | null {
  if (!address) return null
  return virtualsCache.get(address.toLowerCase()) ?? null
}

/**
 * Enrich a list of agents with Virtuals Protocol tags.
 * Call fetchVirtualsAgents() first to populate the cache.
 */
export function tagVirtualsAgents(agents: Array<{
  owner: string
  wallet?: string | null
  chain: string
}>): Map<number, VirtualsAgent> {
  const matches = new Map<number, VirtualsAgent>()

  for (let i = 0; i < agents.length; i++) {
    const a = agents[i]
    if (a.chain !== 'base') continue

    const match = matchVirtualsAgent(a.owner) ?? (a.wallet ? matchVirtualsAgent(a.wallet) : null)
    if (match) matches.set(i, match)
  }

  return matches
}
