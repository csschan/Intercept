/**
 * SpendingSession TypeScript Client
 *
 * Wraps the Anchor spending_session program for use in the Intercept API.
 */

import {
  Connection,
  Keypair,
  PublicKey,
  clusterApiUrl,
} from '@solana/web3.js'
import anchorPkg, { AnchorProvider, Program, Wallet, type Idl } from '@coral-xyz/anchor'
const { BN } = anchorPkg
type BN = InstanceType<typeof anchorPkg.BN>
import { createHash } from 'crypto'
import { SESSION_IDL } from './session-idl.js'

const PROGRAM_ID = new PublicKey('DmBoKbEr7rcdcdCEFq94w2rfF6EtSthxqhSM25uCnFDG')

export interface SessionClientOptions {
  rpcUrl?: string
  privateKey?: string
  network?: 'devnet' | 'mainnet-beta'
}

export interface OnChainSession {
  owner: string
  agentId: string
  sessionId: string
  maxAmountUsdc: number
  spentSoFar: number
  expiresAt: number
  merchantCount: number
  status: number // 0=active, 1=exhausted, 2=expired, 3=revoked
  policyHash: string
  createdAt: number
}

export class SpendingSessionClient {
  private connection: Connection
  private provider: AnchorProvider
  private program: Program<Idl>
  wallet: Keypair

  constructor(options: SessionClientOptions = {}) {
    const rpcUrl = options.rpcUrl ?? clusterApiUrl(options.network ?? 'devnet')
    this.connection = new Connection(rpcUrl, 'confirmed')

    const rawKey = options.privateKey ?? process.env.SOLANA_PRIVATE_KEY
    if (rawKey) {
      const keyBytes = rawKey.startsWith('[')
        ? Uint8Array.from(JSON.parse(rawKey))
        : Buffer.from(rawKey, 'base64')
      this.wallet = Keypair.fromSecretKey(keyBytes)
    } else {
      this.wallet = Keypair.generate()
    }

    const anchorWallet = new Wallet(this.wallet)
    this.provider = new AnchorProvider(this.connection, anchorWallet, {
      commitment: 'confirmed',
    })
    this.program = new Program(SESSION_IDL as unknown as Idl, this.provider)
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  /** Convert a string to 16-byte session ID (SHA-256 truncated) */
  static sessionIdToBytes(sessionId: string): Uint8Array {
    const hash = createHash('sha256').update(sessionId).digest()
    return new Uint8Array(hash.slice(0, 16))
  }

  /** Convert a string to 32-byte merchant identifier */
  static merchantToBytes(merchant: string): number[] {
    const bytes = new Array(32).fill(0)
    const encoded = Buffer.from(merchant, 'utf-8')
    for (let i = 0; i < Math.min(encoded.length, 32); i++) {
      bytes[i] = encoded[i]
    }
    return bytes
  }

  /** Convert a UUID string to 32-byte array */
  static uuidToBytes(uuid: string): number[] {
    const hex = uuid.replace(/-/g, '')
    const bytes = new Array(32).fill(0)
    for (let i = 0; i < Math.min(hex.length / 2, 32); i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    }
    return bytes
  }

  /** Derive PDA for a session */
  getSessionPDA(sessionIdBytes: Uint8Array): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [Buffer.from('session'), this.wallet.publicKey.toBuffer(), Buffer.from(sessionIdBytes)],
      PROGRAM_ID,
    )
  }

  getExplorerUrl(pda: string, network: 'devnet' | 'mainnet-beta' = 'devnet'): string {
    const cluster = network === 'devnet' ? '?cluster=devnet' : ''
    return `https://explorer.solana.com/address/${pda}${cluster}`
  }

  // ── On-chain Operations ──────────────────────────────────────────────────

  async createSession(params: {
    sessionId: string
    agentId: string
    maxAmountUsdc: number   // in USDC (not micro-units)
    expiresAt: number       // unix timestamp
    allowedMerchants: string[]
    policyHash: Buffer
  }): Promise<{ signature: string; pda: string }> {
    const sessionIdBytes = SpendingSessionClient.sessionIdToBytes(params.sessionId)
    const agentIdArray = SpendingSessionClient.uuidToBytes(params.agentId)
    const maxMicroUsdc = Math.round(params.maxAmountUsdc * 1_000_000)
    const merchants = params.allowedMerchants.map(m => SpendingSessionClient.merchantToBytes(m))
    const policyHashArray = Array.from(params.policyHash)

    const [pda] = this.getSessionPDA(sessionIdBytes)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const methods = (this.program as any).methods
    const signature = await methods
      .createSession(
        Array.from(sessionIdBytes),
        agentIdArray,
        new BN(maxMicroUsdc),
        new BN(params.expiresAt),
        merchants,
        policyHashArray,
      )
      .accounts({
        sessionAccount: pda,
        owner: this.wallet.publicKey,
        systemProgram: new PublicKey('11111111111111111111111111111111'),
      })
      .rpc()

    return { signature, pda: pda.toBase58() }
  }

  async spendFromSession(params: {
    sessionId: string
    amountUsdc: number    // in USDC
    merchant: string
  }): Promise<{ signature: string }> {
    const sessionIdBytes = SpendingSessionClient.sessionIdToBytes(params.sessionId)
    const merchantBytes = SpendingSessionClient.merchantToBytes(params.merchant)
    const microUsdc = Math.round(params.amountUsdc * 1_000_000)

    const [pda] = this.getSessionPDA(sessionIdBytes)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const methods = (this.program as any).methods
    const signature = await methods
      .spendFromSession(new BN(microUsdc), merchantBytes)
      .accounts({
        sessionAccount: pda,
        owner: this.wallet.publicKey,
      })
      .rpc()

    return { signature }
  }

  async revokeSession(sessionId: string): Promise<{ signature: string }> {
    const sessionIdBytes = SpendingSessionClient.sessionIdToBytes(sessionId)
    const [pda] = this.getSessionPDA(sessionIdBytes)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const methods = (this.program as any).methods
    const signature = await methods
      .revokeSession()
      .accounts({
        sessionAccount: pda,
        owner: this.wallet.publicKey,
      })
      .rpc()

    return { signature }
  }

  async getSession(sessionId: string): Promise<OnChainSession | null> {
    try {
      const sessionIdBytes = SpendingSessionClient.sessionIdToBytes(sessionId)
      const [pda] = this.getSessionPDA(sessionIdBytes)
      const account = await (this.program.account as any).spendingSessionAccount.fetch(pda)

      return {
        owner: account.owner.toBase58(),
        agentId: Buffer.from(account.agentId).toString('hex'),
        sessionId,
        maxAmountUsdc: (account.maxAmountUsdc as BN).toNumber() / 1_000_000,
        spentSoFar: (account.spentSoFar as BN).toNumber() / 1_000_000,
        expiresAt: (account.expiresAt as BN).toNumber(),
        merchantCount: account.merchantCount,
        status: account.status,
        policyHash: Buffer.from(account.policyHash).toString('hex'),
        createdAt: (account.createdAt as BN).toNumber(),
      }
    } catch {
      return null
    }
  }
}

// ── Singleton ──────────────────────────────────────────────────────────────────

let _sessionClient: SpendingSessionClient | null = null

export function getSpendingSessionClient(): SpendingSessionClient {
  if (!_sessionClient) {
    _sessionClient = new SpendingSessionClient({
      rpcUrl: process.env.SOLANA_RPC_URL,
      privateKey: process.env.SOLANA_PRIVATE_KEY,
      network: (process.env.SOLANA_NETWORK as 'devnet' | 'mainnet-beta') ?? 'devnet',
    })
  }
  return _sessionClient
}
