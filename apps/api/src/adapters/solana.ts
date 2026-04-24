/**
 * Solana Chain Adapter
 *
 * Parses Solana transaction descriptions into NormalizedTransaction.
 * Also provides helpers for devnet/mainnet token price fetching.
 */

import type { NormalizedTransaction, Chain, TxMetadata } from '../types/index.js'

// Known SPL token mints
const KNOWN_TOKENS: Record<string, { symbol: string; decimals: number; usdPrice: number }> = {
  // USDC on Solana (mainnet)
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: { symbol: 'USDC', decimals: 6, usdPrice: 1 },
  // USDC on Solana (devnet)
  '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU': { symbol: 'USDC', decimals: 6, usdPrice: 1 },
  // USDT on Solana
  Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB: { symbol: 'USDT', decimals: 6, usdPrice: 1 },
}

import { getSolPrice } from '../services/price.js'

// Synchronous fallback — updated by async price fetch
let SOL_USD_PRICE = 140
getSolPrice().then(p => { SOL_USD_PRICE = p }).catch(() => {})
// Refresh every 60s
setInterval(() => { getSolPrice().then(p => { SOL_USD_PRICE = p }).catch(() => {}) }, 60_000)

export interface SolanaTransactionInput {
  from?: string
  to: string
  amount: string              // in lamports (SOL) or smallest unit (SPL)
  token?: string              // 'SOL' or SPL mint address
  metadata?: Partial<TxMetadata>
  rawTxData?: unknown
}

export function parseSolanaTransaction(
  input: SolanaTransactionInput,
  chain: Chain = 'solana',
): NormalizedTransaction {
  const token = input.token ?? 'SOL'
  const isSol = token === 'SOL'

  let amountUsdc: number
  let tokenSymbol: string
  let tokenAddress: string | undefined

  if (isSol) {
    // lamports → SOL → USD
    const sol = Number(input.amount) / 1_000_000_000
    amountUsdc = sol * SOL_USD_PRICE
    tokenSymbol = 'SOL'
  } else {
    // Look up by mint address first, then by symbol
    const known = KNOWN_TOKENS[token] ?? Object.values(KNOWN_TOKENS).find(t => t.symbol === token)
    if (known) {
      const humanAmount = Number(input.amount) / Math.pow(10, known.decimals)
      amountUsdc = humanAmount * known.usdPrice
      tokenSymbol = known.symbol
      tokenAddress = token.length > 10 ? token : undefined // only set if looks like a mint address
    } else {
      // Unknown SPL token — use raw amount, flag for ask_user
      amountUsdc = Number(input.amount)
      tokenSymbol = token.slice(0, 8) + '...'
      tokenAddress = token
    }
  }

  return {
    chain,
    txType: 'transfer',
    fromAddress: input.from,
    toAddress: input.to,
    amountRaw: input.amount,
    amountUsdc,
    token: tokenSymbol,
    tokenAddress,
    metadata: {
      isNewMerchant: false, // resolved later against known_merchants table
      isRecurring: false,
      ...input.metadata,
    },
    rawTxData: input.rawTxData,
  }
}

export function formatSolanaAmount(amountRaw: string, token: string): string {
  if (token === 'SOL') {
    const sol = Number(amountRaw) / 1_000_000_000
    return `${sol.toFixed(4)} SOL`
  }
  const known = Object.values(KNOWN_TOKENS).find(t => t.symbol === token)
  if (known) {
    const human = Number(amountRaw) / Math.pow(10, known.decimals)
    return `${human.toFixed(2)} ${token}`
  }
  return `${amountRaw} (${token})`
}
