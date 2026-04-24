/**
 * Price Service
 *
 * Fetches real-time SOL and ETH prices with fallback to cached values.
 * Uses CoinGecko free API (no key needed, 30 req/min).
 * Falls back to hardcoded prices if API is unreachable.
 */

interface PriceCache {
  sol: number
  eth: number
  updatedAt: number
}

const FALLBACK: PriceCache = { sol: 140, eth: 2000, updatedAt: 0 }
const CACHE_TTL_MS = 60_000 // 1 minute

let cache: PriceCache = { ...FALLBACK }
let fetching = false

async function fetchPrices(): Promise<PriceCache> {
  if (fetching) return cache
  fetching = true

  try {
    const res = await fetch(
      'https://api.coingecko.com/api/v3/simple/price?ids=solana,ethereum&vs_currencies=usd',
      { signal: AbortSignal.timeout(5000) },
    )

    if (!res.ok) throw new Error(`CoinGecko ${res.status}`)

    const data = await res.json() as {
      solana?: { usd: number }
      ethereum?: { usd: number }
    }

    cache = {
      sol: data.solana?.usd ?? cache.sol,
      eth: data.ethereum?.usd ?? cache.eth,
      updatedAt: Date.now(),
    }

    return cache
  } catch (err) {
    // Silently fall back to last known / hardcoded prices
    console.warn(`[price] CoinGecko fetch failed, using cached: SOL=$${cache.sol}, ETH=$${cache.eth}`)
    return cache
  } finally {
    fetching = false
  }
}

/**
 * Get current SOL price in USD.
 */
export async function getSolPrice(): Promise<number> {
  if (Date.now() - cache.updatedAt > CACHE_TTL_MS) {
    await fetchPrices()
  }
  return cache.sol
}

/**
 * Get current ETH price in USD.
 */
export async function getEthPrice(): Promise<number> {
  if (Date.now() - cache.updatedAt > CACHE_TTL_MS) {
    await fetchPrices()
  }
  return cache.eth
}

/**
 * Get all prices (for debug/health).
 */
export async function getAllPrices(): Promise<PriceCache> {
  if (Date.now() - cache.updatedAt > CACHE_TTL_MS) {
    await fetchPrices()
  }
  return { ...cache }
}
