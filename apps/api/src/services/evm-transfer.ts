/**
 * EVM Transfer Service
 *
 * Executes USDC transfers on EVM chains (Ethereum, Base, Arbitrum)
 * after Intercept authorization.
 *
 * Uses viem for transaction signing and broadcasting.
 * Requires EVM_PRIVATE_KEY environment variable.
 */

import {
  createWalletClient,
  createPublicClient,
  http,
  parseAbi,
  type Hex,
  type Chain,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { mainnet, base, arbitrum } from 'viem/chains'

// ── USDC Contract Addresses ──────────────────────────────────────────────────

const USDC_CONTRACTS: Record<string, Hex> = {
  ethereum: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
  base: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  arbitrum: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831',
}

const CHAIN_CONFIG: Record<string, Chain> = {
  ethereum: mainnet,
  base: base,
  arbitrum: arbitrum,
}

const EXPLORER_URLS: Record<string, string> = {
  ethereum: 'https://etherscan.io',
  base: 'https://basescan.org',
  arbitrum: 'https://arbiscan.io',
}

const ERC20_ABI = parseAbi([
  'function transfer(address to, uint256 amount) returns (bool)',
  'function balanceOf(address account) view returns (uint256)',
])

// ── Types ───────────────────────────────────────────────────────────────────

export interface EVMTransferResult {
  signature: string
  explorerUrl: string
  fromAddress: string
  toAddress: string
  amountUsdc: number
  amountRaw: string
  network: string
  chain: string
}

// ── Execute ─────────────────────────────────────────────────────────────────

export async function executeEVMTransfer(params: {
  chain: string
  toAddress: string
  amountUsdc: number
}): Promise<EVMTransferResult> {
  const { chain, toAddress, amountUsdc } = params

  const privateKey = process.env.EVM_PRIVATE_KEY
  if (!privateKey) throw new Error('EVM_PRIVATE_KEY not configured')

  const chainDef = CHAIN_CONFIG[chain]
  if (!chainDef) throw new Error(`Unsupported EVM chain: ${chain}`)

  const usdcAddress = USDC_CONTRACTS[chain]
  if (!usdcAddress) throw new Error(`No USDC contract for chain: ${chain}`)

  const account = privateKeyToAccount(privateKey as Hex)

  const walletClient = createWalletClient({
    account,
    chain: chainDef,
    transport: http(),
  })

  const publicClient = createPublicClient({
    chain: chainDef,
    transport: http(),
  })

  // USDC uses 6 decimals
  const amountRaw = BigInt(Math.round(amountUsdc * 1_000_000))

  // Check balance first
  const balance = await publicClient.readContract({
    address: usdcAddress,
    abi: ERC20_ABI,
    functionName: 'balanceOf',
    args: [account.address],
  })

  if (balance < amountRaw) {
    throw new Error(`Insufficient USDC balance on ${chain}: have ${Number(balance) / 1e6}, need ${amountUsdc}`)
  }

  // Execute ERC-20 transfer
  const txHash = await walletClient.writeContract({
    address: usdcAddress,
    abi: ERC20_ABI,
    functionName: 'transfer',
    args: [toAddress as Hex, amountRaw],
  })

  // Wait for confirmation
  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash })

  const explorerBase = EXPLORER_URLS[chain] ?? 'https://etherscan.io'

  return {
    signature: txHash,
    explorerUrl: `${explorerBase}/tx/${txHash}`,
    fromAddress: account.address,
    toAddress,
    amountUsdc,
    amountRaw: amountRaw.toString(),
    network: chainDef.name,
    chain,
  }
}
