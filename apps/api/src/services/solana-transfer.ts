/**
 * Solana Transfer Service
 *
 * Executes real SOL transfers on Solana devnet after Intercept authorization.
 * Used by POST /v1/requests/:id/execute to produce verifiable on-chain evidence.
 *
 * Demo amounts: 1 USDC → 10,000 lamports (0.00001 SOL ≈ $0.0015)
 * This keeps costs negligible while producing real Explorer-visible transactions.
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} from '@solana/web3.js'

// Demo merchant addresses (well-known Solana program accounts — always exist on devnet)
// These serve as stand-in "merchant wallets" for demonstration
export const DEMO_MERCHANT_ADDRESSES: Record<string, string> = {
  openai: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',       // SPL Token Program
  github: 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJe1bDM',      // Associated Token Account Program
  aws: 'ComputeBudget111111111111111111111111111111',             // Compute Budget Program
  pinecone: 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr',      // Memo Program
  resend: 'namesLPsPKB6NQYLJTQcaLUomR6GCiakDoJfRMF5trd',        // Name Service
}

// Fallback demo address (Memo program) for unknown merchants
const FALLBACK_DEMO_ADDRESS = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'

// 1 USDC = 10,000 lamports for demo (≈ $0.0015 total per dollar)
const LAMPORTS_PER_USDC = 10_000
// Minimum: 1 lamport. Maximum per tx: 0.01 SOL (safety cap for demo)
const MAX_LAMPORTS_PER_TX = Math.floor(0.01 * LAMPORTS_PER_SOL)

function loadPayerKeypair(): Keypair {
  const rawKey = process.env.SOLANA_PRIVATE_KEY
  if (!rawKey) throw new Error('SOLANA_PRIVATE_KEY not configured')

  const keyBytes = rawKey.trim().startsWith('[')
    ? Uint8Array.from(JSON.parse(rawKey))
    : Buffer.from(rawKey, 'base64')

  return Keypair.fromSecretKey(keyBytes)
}

/**
 * Resolve a toAddress field to a valid Solana PublicKey.
 * Handles merchant_openai-style strings from demo data.
 */
export function resolveRecipientAddress(toAddress: string): PublicKey {
  // Try parsing directly as a base58 public key
  try {
    return new PublicKey(toAddress)
  } catch {
    // Extract merchant name from patterns like "merchant_openai" or "openai"
    const name = toAddress.replace(/^merchant_/, '').toLowerCase()
    const mapped = DEMO_MERCHANT_ADDRESSES[name] ?? FALLBACK_DEMO_ADDRESS
    return new PublicKey(mapped)
  }
}

export interface TransferResult {
  signature: string
  explorerUrl: string
  fromAddress: string
  toAddress: string
  lamports: number
  amountUsdc: number
  network: string
}

/**
 * Execute a real SOL transfer on Solana devnet.
 * Converts USDC amount → lamports using demo scaling factor.
 */
export async function executeSolanaTransfer(params: {
  toAddress: string
  amountUsdc: number
}): Promise<TransferResult> {
  const payer = loadPayerKeypair()
  const network = (process.env.SOLANA_NETWORK as 'devnet' | 'mainnet-beta') ?? 'devnet'
  const rpcUrl = process.env.SOLANA_RPC_URL ?? 'https://api.devnet.solana.com'
  const connection = new Connection(rpcUrl, 'confirmed')

  const recipient = resolveRecipientAddress(params.toAddress)
  const lamports = Math.min(
    Math.max(1, Math.round(params.amountUsdc * LAMPORTS_PER_USDC)),
    MAX_LAMPORTS_PER_TX,
  )

  const tx = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: payer.publicKey,
      toPubkey: recipient,
      lamports,
    }),
  )

  const signature = await sendAndConfirmTransaction(connection, tx, [payer], {
    commitment: 'confirmed',
  })

  const clusterParam = network === 'devnet' ? '?cluster=devnet' : ''
  const explorerUrl = `https://explorer.solana.com/tx/${signature}${clusterParam}`

  return {
    signature,
    explorerUrl,
    fromAddress: payer.publicKey.toBase58(),
    toAddress: recipient.toBase58(),
    lamports,
    amountUsdc: params.amountUsdc,
    network,
  }
}
