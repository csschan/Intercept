/**
 * EVM Chain Adapter
 *
 * Parses EVM transaction descriptions (ETH/ERC20) into NormalizedTransaction.
 * Designed with the same interface as the Solana adapter so the authorization
 * service can stay chain-agnostic.
 */

import { decodeFunctionData, erc20Abi, formatEther, formatUnits } from 'viem'
import type { NormalizedTransaction, Chain, TxType, TxMetadata } from '../types/index.js'

// Known ERC20 tokens per chain (add more as needed)
const KNOWN_ERC20: Record<string, { symbol: string; decimals: number; usdPrice: number }> = {
  // USDC (Ethereum mainnet)
  '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': { symbol: 'USDC', decimals: 6, usdPrice: 1 },
  // USDC (Base)
  '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913': { symbol: 'USDC', decimals: 6, usdPrice: 1 },
  // USDC (Arc — system precompile, 6 decimals via ERC-20 interface)
  '0x3600000000000000000000000000000000000000': { symbol: 'USDC', decimals: 6, usdPrice: 1 },
  // USDT (Ethereum)
  '0xdac17f958d2ee523a2206206994597c13d831ec7': { symbol: 'USDT', decimals: 6, usdPrice: 1 },
  // WETH
  '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2': { symbol: 'WETH', decimals: 18, usdPrice: 2000 },
}

import { getEthPrice } from '../services/price.js'

let ETH_USD_PRICE = 2000
getEthPrice().then(p => { ETH_USD_PRICE = p }).catch(() => {})
setInterval(() => { getEthPrice().then(p => { ETH_USD_PRICE = p }).catch(() => {}) }, 60_000)

export interface EVMTransactionInput {
  from?: string
  to: string
  value?: string             // native ETH in wei
  data?: string              // calldata hex
  contractAddress?: string   // if it's an ERC20 call, the token contract
  chain?: Chain
  metadata?: Partial<TxMetadata>
  rawTxData?: unknown
}

export function parseEVMTransaction(input: EVMTransactionInput): NormalizedTransaction {
  const chain = input.chain ?? 'ethereum'

  // Case 1: Native transfer (no data or empty data)
  // On Arc, the native currency is USDC (6 decimals), not ETH.
  const isArc = chain === 'arc-testnet'
  if (!input.data || input.data === '0x' || input.data === '') {
    const rawAmount = input.value ?? '0'

    let token: string
    let amountUsdc: number
    if (isArc) {
      // Arc native = USDC. Amount comes in as 6-decimal micro-units.
      token = 'USDC'
      amountUsdc = Number(rawAmount) / 1_000_000
    } else {
      // Standard EVM = ETH in wei (18 decimals)
      token = 'ETH'
      amountUsdc = Number(formatEther(BigInt(rawAmount))) * ETH_USD_PRICE
    }

    return {
      chain,
      txType: 'transfer',
      fromAddress: input.from,
      toAddress: input.to,
      amountRaw: rawAmount,
      amountUsdc,
      token,
      metadata: {
        isRecurring: false,
        isNewMerchant: false,
        ...input.metadata,
      },
      rawTxData: input.rawTxData,
      data: input.data,
      contractAddress: input.contractAddress,
    }
  }

  // Case 2: ERC20 transfer / approve
  try {
    const decoded = decodeFunctionData({ abi: erc20Abi, data: input.data as `0x${string}` })
    const contractAddress = (input.contractAddress ?? input.to).toLowerCase()
    const tokenInfo = KNOWN_ERC20[contractAddress]

    if (decoded.functionName === 'transfer') {
      const [recipient, rawAmount] = decoded.args as [string, bigint]
      const humanAmount = tokenInfo
        ? Number(formatUnits(rawAmount, tokenInfo.decimals))
        : Number(rawAmount)
      const usdAmount = tokenInfo ? humanAmount * tokenInfo.usdPrice : humanAmount

      return {
        chain,
        txType: 'transfer',
        fromAddress: input.from,
        toAddress: recipient,
        amountRaw: rawAmount.toString(),
        amountUsdc: usdAmount,
        token: tokenInfo?.symbol ?? contractAddress.slice(0, 8),
        tokenAddress: contractAddress,
        metadata: {
          isRecurring: false,
          isNewMerchant: false,
          ...input.metadata,
        },
        rawTxData: input.rawTxData,
      }
    }

    if (decoded.functionName === 'approve') {
      const [spender, rawAmount] = decoded.args as [string, bigint]
      return {
        chain,
        txType: 'approve',
        fromAddress: input.from,
        toAddress: spender,
        amountRaw: rawAmount.toString(),
        amountUsdc: 0, // approvals don't move funds directly
        token: tokenInfo?.symbol ?? contractAddress.slice(0, 8),
        tokenAddress: contractAddress,
        metadata: {
          contractMethod: 'approve',
          isRecurring: false,
          isNewMerchant: false,
          ...input.metadata,
        },
        rawTxData: input.rawTxData,
      }
    }
  } catch {
    // Not an ERC20 call — treat as generic contract interaction
  }

  // Case 3: Generic contract call
  return {
    chain,
    txType: 'contract_call',
    fromAddress: input.from,
    toAddress: input.to,
    amountRaw: input.value ?? '0',
    amountUsdc: Number(formatEther(BigInt(input.value ?? '0'))) * ETH_USD_PRICE,
    token: 'ETH',
    metadata: {
      contractMethod: input.data?.slice(0, 10), // 4-byte selector
      isRecurring: false,
      isNewMerchant: false,
      ...input.metadata,
    },
    rawTxData: input.rawTxData,
  }
}
