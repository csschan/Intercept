/**
 * PolicyRegistry TypeScript Client
 *
 * Wraps the Anchor program for use in the Intercept API.
 * Called by apps/api/src/services/chain.ts after saving a policy.
 */

import {
  Connection,
  Keypair,
  PublicKey,
  clusterApiUrl,
} from '@solana/web3.js'
import anchor, { AnchorProvider, Program, Wallet, type Idl } from '@coral-xyz/anchor'
const { BN } = anchor
import { createHash } from 'crypto'
import { IDL } from './idl.js'

const PROGRAM_ID = new PublicKey('FKvRpAWkPHh6HqQkvSfABAkrMrhaJz195q5Rw2NvznGG')

export interface PolicyRegistryClientOptions {
  /** Solana RPC endpoint. Defaults to devnet. */
  rpcUrl?: string
  /** Base58 or JSON array private key for the signing wallet */
  privateKey?: string
  /** Network: 'devnet' | 'mainnet-beta' */
  network?: 'devnet' | 'mainnet-beta'
}

export interface OnChainPolicy {
  owner: string
  agentId: string        // UUID string
  policyHash: string     // hex string
  metadataUri: string
  version: number
  updatedAt: number      // unix timestamp
}

export class PolicyRegistryClient {
  private connection: Connection
  private provider: AnchorProvider
  private program: Program<Idl>
  private wallet: Keypair

  constructor(options: PolicyRegistryClientOptions = {}) {
    const rpcUrl = options.rpcUrl ?? clusterApiUrl(options.network ?? 'devnet')
    this.connection = new Connection(rpcUrl, 'confirmed')

    // Load wallet from env or provided key
    const rawKey = options.privateKey ?? process.env.SOLANA_PRIVATE_KEY
    if (rawKey) {
      const keyBytes = rawKey.startsWith('[')
        ? Uint8Array.from(JSON.parse(rawKey))
        : Buffer.from(rawKey, 'base64')
      this.wallet = Keypair.fromSecretKey(keyBytes)
    } else {
      // Dev mode: generate ephemeral wallet (no on-chain writes will persist)
      this.wallet = Keypair.generate()
    }

    const anchorWallet = new Wallet(this.wallet)
    this.provider = new AnchorProvider(this.connection, anchorWallet, {
      commitment: 'confirmed',
    })

    this.program = new Program(IDL as unknown as Idl, this.provider)
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  /**
   * Compute SHA-256 hash of a policy JSON object.
   * This is the canonical hash stored on-chain.
   */
  static hashPolicy(policyJson: object): Buffer {
    const canonical = JSON.stringify(policyJson, Object.keys(policyJson).sort())
    return createHash('sha256').update(canonical).digest()
  }

  /**
   * Derive the PDA address for an agent's policy account.
   */
  async getPolicyPDA(ownerPubkey: PublicKey, agentIdBytes: Uint8Array): Promise<[PublicKey, number]> {
    return PublicKey.findProgramAddressSync(
      [Buffer.from('policy'), ownerPubkey.toBuffer(), Buffer.from(agentIdBytes)],
      PROGRAM_ID,
    )
  }

  /**
   * Convert a UUID string to 32-byte array (pad with zeros if needed).
   */
  static uuidToBytes(uuid: string): Uint8Array {
    const hex = uuid.replace(/-/g, '')
    const bytes = new Uint8Array(32)
    for (let i = 0; i < Math.min(hex.length / 2, 32); i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    }
    return bytes
  }

  // ── On-chain Operations ────────────────────────────────────────────────────

  /**
   * Initialize (or update if exists) the on-chain policy record.
   * Returns the transaction signature and PDA address.
   */
  async savePolicy(
    agentId: string,
    policyJson: object,
    metadataUri?: string,
  ): Promise<{ signature: string; pda: string; hash: string }> {
    const agentIdBytes = PolicyRegistryClient.uuidToBytes(agentId)
    const policyHash = PolicyRegistryClient.hashPolicy(policyJson)
    const hashArray = Array.from(policyHash) as number[]
    const agentIdArray = Array.from(agentIdBytes) as number[]
    const uri = metadataUri ?? `agentguard://policies/${agentId}`

    const [pda] = await this.getPolicyPDA(this.wallet.publicKey, agentIdBytes)

    // Check if account already exists
    const existing = await this.connection.getAccountInfo(pda)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const methods = (this.program as any).methods
    let signature: string
    if (existing) {
      // Update
      signature = await methods
        .updatePolicy(hashArray, uri)
        .accounts({ policyAccount: pda, owner: this.wallet.publicKey })
        .rpc()
    } else {
      // Initialize
      signature = await methods
        .initializePolicy(agentIdArray, hashArray, uri)
        .accounts({
          policyAccount: pda,
          owner: this.wallet.publicKey,
          systemProgram: new PublicKey('11111111111111111111111111111111'),
        })
        .rpc()
    }

    return {
      signature,
      pda: pda.toBase58(),
      hash: policyHash.toString('hex'),
    }
  }

  /**
   * Fetch the on-chain policy record for an agent.
   */
  async getPolicy(ownerPubkey: string, agentId: string): Promise<OnChainPolicy | null> {
    try {
      const agentIdBytes = PolicyRegistryClient.uuidToBytes(agentId)
      const [pda] = await this.getPolicyPDA(new PublicKey(ownerPubkey), agentIdBytes)

      const account = await (this.program.account as any).policyAccount.fetch(pda)

      return {
        owner: account.owner.toBase58(),
        agentId,
        policyHash: Buffer.from(account.policyHash).toString('hex'),
        metadataUri: account.metadataUri,
        version: account.version,
        updatedAt: account.updatedAt.toNumber(),
      }
    } catch {
      return null
    }
  }

  /**
   * Verify that the local policy hash matches on-chain.
   * Returns true if they match.
   */
  async verifyPolicy(
    ownerPubkey: string,
    agentId: string,
    policyJson: object,
  ): Promise<boolean> {
    const onChain = await this.getPolicy(ownerPubkey, agentId)
    if (!onChain) return false

    const localHash = PolicyRegistryClient.hashPolicy(policyJson).toString('hex')
    return onChain.policyHash === localHash
  }

  /**
   * Get the Solana Explorer URL for a policy account.
   */
  getExplorerUrl(pda: string, network: 'devnet' | 'mainnet-beta' = 'devnet'): string {
    const cluster = network === 'devnet' ? '?cluster=devnet' : ''
    return `https://explorer.solana.com/address/${pda}${cluster}`
  }
}

// ── Singleton for use in API ───────────────────────────────────────────────────

let _client: PolicyRegistryClient | null = null

export function getPolicyRegistryClient(): PolicyRegistryClient {
  if (!_client) {
    _client = new PolicyRegistryClient({
      rpcUrl: process.env.SOLANA_RPC_URL,
      privateKey: process.env.SOLANA_PRIVATE_KEY,
      network: (process.env.SOLANA_NETWORK as 'devnet' | 'mainnet-beta') ?? 'devnet',
    })
  }
  return _client
}
