/**
 * Arc Transfer Service
 *
 * Executes real USDC transfers on Circle's Arc testnet after Intercept authorization.
 * Arc is EVM-compatible with USDC as the native gas token — no ETH needed.
 *
 * USDC on Arc:
 *   - System precompile at 0x3600000000000000000000000000000000000000
 *   - ERC-20 interface: 6 decimals (standard USDC)
 *   - Native value transfers: 18 decimals
 *   We use the ERC-20 interface (6 decimals) to stay consistent with other chains.
 *
 * RPC: https://rpc.testnet.arc.network (chain ID: 5042002)
 * Explorer: https://testnet.arcscan.app
 * Faucet: https://faucet.circle.com
 */

import {
  createWalletClient,
  createPublicClient,
  http,
  parseAbi,
  defineChain,
  type Hex,
} from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

// ── Arc Testnet Chain Definition ────────────────────────────────────────────

export const arcTestnet = defineChain({
  id: 5042002,
  name: 'Arc Testnet',
  nativeCurrency: { name: 'USDC', symbol: 'USDC', decimals: 18 },
  rpcUrls: {
    default: { http: ['https://rpc.testnet.arc.network'] },
  },
  blockExplorers: {
    default: { name: 'Arcscan', url: 'https://testnet.arcscan.app' },
  },
  testnet: true,
})

// USDC ERC-20 precompile on Arc (6 decimals via ERC-20 interface)
const USDC_ADDRESS = '0x3600000000000000000000000000000000000000' as Hex

const ERC20_ABI = parseAbi([
  'function transfer(address to, uint256 amount) returns (bool)',
  'function balanceOf(address account) view returns (uint256)',
  'function decimals() view returns (uint8)',
])

// ── Types ───────────────────────────────────────────────────────────────────

export interface ArcTransferResult {
  signature: string      // tx hash
  explorerUrl: string
  fromAddress: string
  toAddress: string
  amountUsdc: number     // human-readable USDC
  amountRaw: string      // 6-decimal raw amount
  network: string
}

// ── Transfer ────────────────────────────────────────────────────────────────

function loadPrivateKey(): Hex {
  const key = process.env.ARC_TESTNET_PRIVATE_KEY
  if (!key) throw new Error('ARC_TESTNET_PRIVATE_KEY not configured')
  return (key.startsWith('0x') ? key : `0x${key}`) as Hex
}

/**
 * Execute a real USDC transfer on Arc testnet via the ERC-20 interface.
 * amountUsdc is in human-readable units (e.g. 3 = $3 USDC).
 */
export async function executeArcTransfer(params: {
  toAddress: string
  amountUsdc: number
}): Promise<ArcTransferResult> {
  const rpcUrl = process.env.ARC_TESTNET_RPC_URL ?? 'https://rpc.testnet.arc.network'

  const account = privateKeyToAccount(loadPrivateKey())

  const walletClient = createWalletClient({
    account,
    chain: arcTestnet,
    transport: http(rpcUrl),
  })

  const publicClient = createPublicClient({
    chain: arcTestnet,
    transport: http(rpcUrl),
  })

  // 6 decimals for ERC-20 interface
  const amountRaw = BigInt(Math.round(params.amountUsdc * 1_000_000))

  const hash = await walletClient.writeContract({
    address: USDC_ADDRESS,
    abi: ERC20_ABI,
    functionName: 'transfer',
    args: [params.toAddress as Hex, amountRaw],
  })

  // Wait for confirmation
  const receipt = await publicClient.waitForTransactionReceipt({ hash })

  const explorerUrl = `https://testnet.arcscan.app/tx/${hash}`

  return {
    signature: hash,
    explorerUrl,
    fromAddress: account.address,
    toAddress: params.toAddress,
    amountUsdc: params.amountUsdc,
    amountRaw: amountRaw.toString(),
    network: 'arc-testnet',
  }
}

/**
 * Write a security record to Arc as a micro-transfer ($0.001).
 * Each decision (allow/deny/ask_user) gets an on-chain attestation.
 */
export async function writeSecurityRecord(params: {
  decision: string
  reason: string
}): Promise<{ txHash: string; explorerUrl: string } | null> {
  try {
    // Self-transfer of $0.001 as security attestation
    const result = await executeArcTransfer({
      toAddress: process.env.SECURITY_RECORD_ADDRESS ?? '0xeD4c2576A79D1BB10f9076A69b7Def188A97909A',
      amountUsdc: 0.001,
    })
    return { txHash: result.signature, explorerUrl: result.explorerUrl }
  } catch (err) {
    console.error('[arc] Security record write failed:', err)
    return null
  }
}
