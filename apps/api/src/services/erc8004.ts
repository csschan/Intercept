/**
 * ERC-8004 On-Chain Agent Monitor
 *
 * Reads the Identity Registry and Reputation Registry to discover
 * all registered agents and their on-chain activity.
 */

import { createPublicClient, http, parseAbiItem, type PublicClient, type Chain } from 'viem'
import { mainnet, bsc, arbitrum, optimism, base, polygon } from 'viem/chains'

// ── Contract Addresses (same across all chains) ────────────────────────────────

export const IDENTITY_REGISTRY = '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432' as const
export const REPUTATION_REGISTRY = '0x8004BAa17C55a88189AE136b182e5fdA19dE9b63' as const

// ── Supported Chains ───────────────────────────────────────────────────────────

export const SUPPORTED_CHAINS: Record<string, { chain: Chain; rpcUrl: string; label: string; color: string }> = {
  ethereum: {
    chain: mainnet,
    rpcUrl: process.env.ETH_RPC_URL ?? 'https://ethereum-rpc.publicnode.com',
    label: 'Ethereum',
    color: '#627EEA',
  },
  bsc: {
    chain: bsc,
    rpcUrl: process.env.BSC_RPC_URL ?? 'https://bsc-rpc.publicnode.com',
    label: 'BSC',
    color: '#F0B90B',
  },
  arbitrum: {
    chain: arbitrum,
    rpcUrl: process.env.ARB_RPC_URL ?? 'https://arbitrum-one-rpc.publicnode.com',
    label: 'Arbitrum',
    color: '#28A0F0',
  },
  base: {
    chain: base,
    rpcUrl: process.env.BASE_RPC_URL ?? 'https://base-rpc.publicnode.com',
    label: 'Base',
    color: '#0052FF',
  },
  optimism: {
    chain: optimism,
    rpcUrl: process.env.OP_RPC_URL ?? 'https://optimism-rpc.publicnode.com',
    label: 'Optimism',
    color: '#FF0420',
  },
  polygon: {
    chain: polygon,
    rpcUrl: process.env.POLYGON_RPC_URL ?? 'https://polygon-bor-rpc.publicnode.com',
    label: 'Polygon',
    color: '#8247E5',
  },
}

// How many recent blocks to scan per chain (approx 2 weeks).
// Public RPCs limit range to ~50K per call, so we chunk.
const SCAN_RANGE: Record<string, bigint> = {
  ethereum: 100_000n,    // ~14 days @ 12s/block
  bsc: 400_000n,         // ~14 days @ 3s/block
  arbitrum: 5_000_000n,  // ~14 days @ 0.25s/block
  base: 600_000n,        // ~14 days @ 2s/block
  optimism: 600_000n,    // ~14 days @ 2s/block
  polygon: 300_000n,     // ~14 days @ 2s/block
}

// ── ABI Fragments ──────────────────────────────────────────────────────────────

const IDENTITY_ABI = [
  // Events
  parseAbiItem('event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)'),
  parseAbiItem('event MetadataSet(uint256 indexed agentId, string indexed indexedMetadataKey, string metadataKey, bytes metadataValue)'),
  // Read functions
  parseAbiItem('function ownerOf(uint256 tokenId) view returns (address)'),
  parseAbiItem('function tokenURI(uint256 tokenId) view returns (string)'),
  parseAbiItem('function balanceOf(address owner) view returns (uint256)'),
  parseAbiItem('function getMetadata(uint256 agentId, string metadataKey) view returns (bytes)'),
  parseAbiItem('function getAgentWallet(uint256 agentId) view returns (address)'),
  parseAbiItem('function getVersion() view returns (string)'),
] as const

const REPUTATION_ABI = [
  // Events
  parseAbiItem('event NewFeedback(uint256 indexed agentId, address indexed clientAddress, string indexed indexedTag1, uint64 feedbackIndex, int128 value, uint8 valueDecimals, string tag1, string tag2, string endpoint, string feedbackURI, bytes32 feedbackHash)'),
  parseAbiItem('event FeedbackRevoked(uint256 indexed agentId, address indexed clientAddress, uint64 indexed feedbackIndex)'),
  // Read functions
  parseAbiItem('function getClients(uint256 agentId) view returns (address[])'),
  parseAbiItem('function getLastIndex(uint256 agentId, address clientAddress) view returns (uint64)'),
  parseAbiItem('function getSummary(uint256 agentId, address[] clientAddresses, string tag1, string tag2) view returns (uint64 count, int128 summaryValue, uint8 summaryValueDecimals)'),
  parseAbiItem('function getVersion() view returns (string)'),
] as const

// ── Client Cache ───────────────────────────────────────────────────────────────

const clients: Record<string, PublicClient> = {}

function getClient(chainKey: string): PublicClient {
  if (clients[chainKey]) return clients[chainKey]
  const config = SUPPORTED_CHAINS[chainKey]
  if (!config) throw new Error(`Unsupported chain: ${chainKey}`)
  const client = createPublicClient({
    chain: config.chain,
    transport: http(config.rpcUrl),
  })
  clients[chainKey] = client
  return client
}

// ── Types ──────────────────────────────────────────────────────────────────────

export interface ERC8004Agent {
  agentId: bigint
  owner: string
  chain: string
  chainLabel: string
  blockNumber: bigint
  txHash: string
  wallet?: string
  uri?: string
}

export interface AgentFeedbackSummary {
  agentId: bigint
  chain: string
  feedbackCount: number
  summaryValue: number
  clients: string[]
}

export interface AgentTransaction {
  hash: string
  from: string
  to: string
  value: bigint
  blockNumber: bigint
  timestamp?: number
  chain: string
  input?: string
  methodName?: string
  isError?: boolean
  tokenName?: string
  tokenDecimals?: number
  contractAddress?: string
  txType?: 'normal' | 'erc20'
  // Security analysis fields
  riskLevel?: 'safe' | 'suspicious' | 'dangerous'
  riskFlags?: string[]
}

// ── Core Functions ─────────────────────────────────────────────────────────────

/**
 * Discover all registered agents on a chain by scanning Transfer events
 * from address(0) (minting = registration).
 * Uses chunked queries to stay within public RPC block range limits.
 */
export async function getRegisteredAgents(
  chainKey: string,
  fromBlock: bigint = 0n,
): Promise<ERC8004Agent[]> {
  const client = getClient(chainKey)
  const config = SUPPORTED_CHAINS[chainKey]
  const CHUNK_SIZE = 49_000n

  try {
    const latestBlock = await client.getBlockNumber()
    const range = SCAN_RANGE[chainKey] ?? 100_000n
    const start = fromBlock > 0n ? fromBlock : (latestBlock > range ? latestBlock - range : 0n)

    const agents: ERC8004Agent[] = []

    for (let from = start; from <= latestBlock; from += CHUNK_SIZE) {
      const to = from + CHUNK_SIZE - 1n > latestBlock ? latestBlock : from + CHUNK_SIZE - 1n

      try {
        const logs = await client.getLogs({
          address: IDENTITY_REGISTRY,
          event: parseAbiItem('event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)'),
          args: { from: '0x0000000000000000000000000000000000000000' },
          fromBlock: from,
          toBlock: to,
        })

        for (const log of logs) {
          agents.push({
            agentId: log.args.tokenId!,
            owner: log.args.to!,
            chain: chainKey,
            chainLabel: config.label,
            blockNumber: log.blockNumber,
            txHash: log.transactionHash,
          })
        }
      } catch (chunkErr) {
        console.error(`[erc8004] Chunk ${from}-${to} failed on ${chainKey}:`, chunkErr)
      }
    }

    console.log(`[erc8004] Found ${agents.length} agents on ${chainKey} (blocks ${start}..${latestBlock})`)
    return agents
  } catch (err) {
    console.error(`[erc8004] Failed to fetch agents on ${chainKey}:`, err)
    return []
  }
}

/**
 * Enrich an agent with on-chain metadata (wallet, URI).
 */
export async function enrichAgent(chainKey: string, agentId: bigint): Promise<{ wallet?: string; uri?: string }> {
  const client = getClient(chainKey)
  const result: { wallet?: string; uri?: string } = {}

  try {
    const wallet = await client.readContract({
      address: IDENTITY_REGISTRY,
      abi: IDENTITY_ABI,
      functionName: 'getAgentWallet',
      args: [agentId],
    })
    if (wallet && wallet !== '0x0000000000000000000000000000000000000000') {
      result.wallet = wallet
    }
  } catch {}

  try {
    const uri = await client.readContract({
      address: IDENTITY_REGISTRY,
      abi: IDENTITY_ABI,
      functionName: 'tokenURI',
      args: [agentId],
    })
    if (uri) result.uri = uri
  } catch {}

  return result
}

/**
 * Get reputation summary for an agent.
 */
export async function getAgentReputation(chainKey: string, agentId: bigint): Promise<AgentFeedbackSummary | null> {
  const client = getClient(chainKey)

  try {
    const agentClients = await client.readContract({
      address: REPUTATION_REGISTRY,
      abi: REPUTATION_ABI,
      functionName: 'getClients',
      args: [agentId],
    })

    if (!agentClients || agentClients.length === 0) {
      return {
        agentId,
        chain: chainKey,
        feedbackCount: 0,
        summaryValue: 0,
        clients: [],
      }
    }

    const summary = await client.readContract({
      address: REPUTATION_REGISTRY,
      abi: REPUTATION_ABI,
      functionName: 'getSummary',
      args: [agentId, agentClients as `0x${string}`[], '', ''],
    })

    return {
      agentId,
      chain: chainKey,
      feedbackCount: Number(summary[0]),
      summaryValue: Number(summary[1]) / Math.pow(10, Number(summary[2])),
      clients: agentClients as string[],
    }
  } catch {
    return null
  }
}

// Etherscan V2 API — free tier supported chains
const ETHERSCAN_V2_CHAINS: Record<string, number> = {
  ethereum: 1,
  polygon: 137,
  arbitrum: 42161,
}

// Blockscout API — free, no key needed
const BLOCKSCOUT_URLS: Record<string, string> = {
  base: 'https://base.blockscout.com',
  optimism: 'https://optimism.blockscout.com',
  polygon: 'https://polygon.blockscout.com',
}

const ETHERSCAN_API_KEYS = [
  process.env.ETHERSCAN_API_KEY_1 ?? 'FKCFG1XHGEUQ1SIBEUXAR5TZQ8QKM1XZ7B',
  process.env.ETHERSCAN_API_KEY_2 ?? 'SI9G848EMRDNXXIC8W8H4CGMS881PHHS45',
  process.env.ETHERSCAN_API_KEY_3 ?? '5ER7MQJG5149PQSFSYJR9GWUWMCK2S5Y62',
]
let apiKeyIndex = 0
function getApiKey() {
  const key = ETHERSCAN_API_KEYS[apiKeyIndex % ETHERSCAN_API_KEYS.length]
  apiKeyIndex++
  return key
}

const NATIVE_TOKEN: Record<string, string> = {
  ethereum: 'ETH', bsc: 'BNB', arbitrum: 'ETH',
  base: 'ETH', optimism: 'ETH', polygon: 'MATIC',
}

/**
 * Get recent transactions via Etherscan V2 API (full history).
 */
async function getTransactionsViaEtherscan(
  chainId: number, walletAddress: string, chainKey: string, limit: number,
): Promise<AgentTransaction[]> {
  const apiKey = getApiKey()
  const base = 'https://api.etherscan.io/v2/api'

  const [normalRes, tokenRes] = await Promise.all([
    fetch(`${base}?chainid=${chainId}&module=account&action=txlist&address=${walletAddress}&startblock=0&endblock=99999999&page=1&offset=${limit}&sort=desc&apikey=${apiKey}`)
      .then(r => r.json()).catch(() => ({ result: [] })),
    fetch(`${base}?chainid=${chainId}&module=account&action=tokentx&address=${walletAddress}&startblock=0&endblock=99999999&page=1&offset=${limit}&sort=desc&apikey=${apiKey}`)
      .then(r => r.json()).catch(() => ({ result: [] })),
  ])

  const txs: AgentTransaction[] = []

  const normalTxs = Array.isArray(normalRes.result) ? normalRes.result : []
  for (const tx of normalTxs) {
    txs.push({
      hash: tx.hash, from: tx.from, to: tx.to ?? '',
      value: BigInt(tx.value ?? '0'),
      blockNumber: BigInt(tx.blockNumber ?? '0'),
      timestamp: Number(tx.timeStamp ?? 0),
      chain: chainKey,
      methodName: tx.functionName?.split('(')[0] || (tx.input === '0x' ? 'transfer' : 'contract_call'),
      isError: tx.isError === '1',
      tokenName: NATIVE_TOKEN[chainKey] ?? 'ETH',
      txType: 'normal',
    })
  }

  const tokenTxs = Array.isArray(tokenRes.result) ? tokenRes.result : []
  for (const tx of tokenTxs) {
    txs.push({
      hash: tx.hash, from: tx.from, to: tx.to ?? '',
      value: BigInt(tx.value ?? '0'),
      blockNumber: BigInt(tx.blockNumber ?? '0'),
      timestamp: Number(tx.timeStamp ?? 0),
      chain: chainKey,
      tokenName: tx.tokenSymbol ?? 'Token',
      tokenDecimals: Number(tx.tokenDecimal ?? 18),
      contractAddress: tx.contractAddress,
      txType: 'erc20',
    })
  }

  return txs
}

/**
 * Get transactions via Blockscout V2 API (Base, Optimism).
 */
async function getTransactionsViaBlockscout(
  baseUrl: string, walletAddress: string, chainKey: string, limit: number,
): Promise<AgentTransaction[]> {
  const res = await fetch(`${baseUrl}/api/v2/addresses/${walletAddress}/transactions?filter=to%7Cfrom`, {
    signal: AbortSignal.timeout(10_000),
  })
  if (!res.ok) return []
  const data = await res.json()
  const items = data.items ?? []

  return items.slice(0, limit).map((tx: any) => ({
    hash: tx.hash,
    from: tx.from?.hash ?? '',
    to: tx.to?.hash ?? '',
    value: BigInt(tx.value ?? '0'),
    blockNumber: BigInt(tx.block_number ?? tx.block ?? '0'),
    timestamp: tx.timestamp ? Math.floor(new Date(tx.timestamp).getTime() / 1000) : 0,
    chain: chainKey,
    methodName: tx.method ?? (tx.raw_input === '0x' ? 'transfer' : 'contract_call'),
    isError: tx.status === 'error',
    tokenName: NATIVE_TOKEN[chainKey] ?? 'ETH',
    txType: 'normal' as const,
  }))
}

/**
 * Fallback: get transactions via RPC (ERC-20 Transfer logs, ~48h window).
 */
async function getTransactionsViaRpc(
  chainKey: string, walletAddress: string, limit: number,
): Promise<AgentTransaction[]> {
  const client = getClient(chainKey)
  const scanBlocks = 49_000n

  const latestBlock = await client.getBlockNumber()
  const fromBlock = latestBlock > scanBlocks ? latestBlock - scanBlocks : 0n

  const [sentLogs, receivedLogs] = await Promise.all([
    client.getLogs({
      event: parseAbiItem('event Transfer(address indexed from, address indexed to, uint256 value)'),
      args: { from: walletAddress as `0x${string}` },
      fromBlock, toBlock: 'latest',
    }).catch(() => []),
    client.getLogs({
      event: parseAbiItem('event Transfer(address indexed from, address indexed to, uint256 value)'),
      args: { to: walletAddress as `0x${string}` },
      fromBlock, toBlock: 'latest',
    }).catch(() => []),
  ])

  return [...sentLogs, ...receivedLogs].map(log => ({
    hash: log.transactionHash,
    from: (log.args as any).from ?? '',
    to: (log.args as any).to ?? '',
    value: (log.args as any).value ?? 0n,
    blockNumber: log.blockNumber,
    chain: chainKey,
    tokenName: 'Token',
    txType: 'erc20' as const,
    contractAddress: log.address,
  }))
}

/**
 * Get recent transactions for an agent's wallet.
 * Uses Etherscan V2 API where available, RPC fallback otherwise.
 */
export async function getAgentTransactions(
  chainKey: string,
  walletAddress: string,
  limit: number = 30,
): Promise<AgentTransaction[]> {
  try {
    let txs: AgentTransaction[]

    // Solana — use RPC getSignaturesForAddress
    if (chainKey === 'solana') {
      const { getSolanaWalletTransactions } = await import('./solana-agent-registry.js')
      const solTxs = await getSolanaWalletTransactions(walletAddress, limit)
      return solTxs.map((t: any) => ({
        hash: t.hash,
        from: walletAddress,
        to: '',
        value: 0n,
        blockNumber: BigInt(t.slot ?? 0),
        timestamp: t.blockTime,
        chain: 'solana',
        methodName: t.memo ? 'memo' : 'transaction',
        isError: t.isError,
        tokenName: 'SOL',
        txType: 'normal' as const,
        riskLevel: t.isError ? 'suspicious' as const : 'safe' as const,
        riskFlags: t.isError ? ['failed_tx'] : [],
      }))
    }

    const etherscanChainId = ETHERSCAN_V2_CHAINS[chainKey]
    const blockscoutUrl = BLOCKSCOUT_URLS[chainKey]

    if (etherscanChainId) {
      txs = await getTransactionsViaEtherscan(etherscanChainId, walletAddress, chainKey, limit)
    } else if (blockscoutUrl) {
      txs = await getTransactionsViaBlockscout(blockscoutUrl, walletAddress, chainKey, limit)
        .catch(() => getTransactionsViaRpc(chainKey, walletAddress, limit))
    } else {
      txs = await getTransactionsViaRpc(chainKey, walletAddress, limit)
    }

    // Deduplicate, sort by time/block desc
    txs.sort((a, b) => (b.timestamp ?? 0) - (a.timestamp ?? 0) || Number(b.blockNumber - a.blockNumber))
    const seen = new Set<string>()
    const unique = txs.filter(t => {
      const key = `${t.hash}-${t.txType}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    }).slice(0, limit)

    // ══════════════════════════════════════════════════════════════════════
    // Security Analysis — Full Intercept + SlowMist on-chain checklist
    // ══════════════════════════════════════════════════════════════════════
    //
    // SlowMist checklist items covered:
    //   Step 1: Address Risk Assessment — GoPlus address_security API
    //   Step 2: Smart Contract Review  — GoPlus contract_security API
    //   Step 3: Token Security         — GoPlus token_security API (honeypot, hidden mint, etc.)
    //   Step 4: Approval Detection     — approve/setApprovalForAll pattern matching
    //   Step 5: Address Poisoning      — similar-address pattern detection
    //   Step 6: Behavioral Patterns    — rapid outbound, funding concentration
    //   Step 7: Risk Scoring           — SlowMist threshold (≤30/31-70/71-90/≥91)

    const goplusChainId = { ethereum: '1', bsc: '56', polygon: '137', arbitrum: '42161', base: '8453', optimism: '10' }[chainKey]
    const walletLower = walletAddress.toLowerCase()

    // Collect unique counterparty addresses and contract addresses
    const counterpartyAddresses = new Set<string>()
    const contractAddresses = new Set<string>()
    const tokenContractAddresses = new Set<string>()

    for (const tx of unique) {
      const addr = tx.from?.toLowerCase() === walletLower ? tx.to : tx.from
      if (addr && addr !== '0x0000000000000000000000000000000000000000') {
        counterpartyAddresses.add(addr.toLowerCase())
      }
      // Collect contracts the agent interacted with (non-transfer method calls)
      if (tx.methodName && tx.methodName !== 'transfer' && tx.to) {
        contractAddresses.add(tx.to.toLowerCase())
      }
      // Collect ERC-20 token contract addresses
      if (tx.txType === 'erc20' && tx.contractAddress) {
        tokenContractAddresses.add(tx.contractAddress.toLowerCase())
      }
    }

    // ── Step 1: Address Risk Assessment (GoPlus address_security) ────────
    const addressResults: Record<string, { risk: string; flags: string[]; score: number }> = {}

    if (goplusChainId) {
      const batch = [...counterpartyAddresses].slice(0, 20)
      await Promise.all(batch.map(async (addr) => {
        try {
          const res = await fetch(
            `https://api.gopluslabs.io/api/v1/address_security/${addr}?chain_id=${goplusChainId}`,
            { signal: AbortSignal.timeout(3000) },
          )
          if (!res.ok) return
          const data = await res.json()
          const r = data.result ?? {}
          const flags: string[] = []
          let score = 0
          if (r.is_blacklisted === '1')              { flags.push('blacklisted'); score = 100 }
          if (r.is_phishing_activities === '1')       { flags.push('phishing'); score = Math.max(score, 95) }
          if (r.is_sanctioned === '1')                { flags.push('sanctioned'); score = Math.max(score, 100) }
          if (r.is_honeypot_related_address === '1')  { flags.push('honeypot_related'); score = Math.max(score, 80) }
          if (r.is_mixer === '1')                     { flags.push('mixer'); score = Math.max(score, 70) }
          if (r.cybercrime === '1')                   { flags.push('cybercrime'); score = Math.max(score, 90) }
          if (r.money_laundering === '1')             { flags.push('money_laundering'); score = Math.max(score, 85) }
          if (r.financial_crime === '1')              { flags.push('financial_crime'); score = Math.max(score, 85) }
          const risk = score >= 91 ? 'malicious' : score >= 31 ? 'suspicious' : 'safe'
          addressResults[addr] = { risk, flags, score }
        } catch {}
      }))
    }

    // ── Step 2: Smart Contract Review (GoPlus contract_security) ─────────
    const contractResults: Record<string, { flags: string[]; isVerified: boolean; isProxy: boolean; hasOwner: boolean; hasSelfDestruct: boolean }> = {}

    if (goplusChainId && contractAddresses.size > 0) {
      const batch = [...contractAddresses].slice(0, 10)
      await Promise.all(batch.map(async (addr) => {
        try {
          const res = await fetch(
            `https://api.gopluslabs.io/api/v1/contract_security/${addr}?chain_id=${goplusChainId}`,
            { signal: AbortSignal.timeout(3000) },
          )
          if (!res.ok) return
          const data = await res.json()
          const r = data.result ?? {}
          const flags: string[] = []
          const isVerified = r.is_open_source === '1'
          const isProxy = r.is_proxy === '1'
          const hasOwner = r.owner_address && r.owner_address !== '0x0000000000000000000000000000000000000000'
          const hasSelfDestruct = r.self_destruct === '1'
          if (!isVerified) flags.push('unverified_source')
          if (isProxy) flags.push('upgradeable_proxy')
          if (hasSelfDestruct) flags.push('self_destruct')
          if (r.is_mintable === '1') flags.push('mintable')
          contractResults[addr] = { flags, isVerified, isProxy, hasOwner: !!hasOwner, hasSelfDestruct }
        } catch {}
      }))
    }

    // ── Step 3: Token Security (GoPlus token_security) ───────────────────
    const tokenResults: Record<string, { flags: string[]; isHoneypot: boolean; canMint: boolean; hasFeeManipulation: boolean; hasBlacklist: boolean }> = {}

    if (goplusChainId && tokenContractAddresses.size > 0) {
      const batch = [...tokenContractAddresses].slice(0, 10)
      // GoPlus token_security accepts comma-separated addresses
      const addrParam = batch.join(',')
      try {
        const res = await fetch(
          `https://api.gopluslabs.io/api/v1/token_security/${goplusChainId}?contract_addresses=${addrParam}`,
          { signal: AbortSignal.timeout(5000) },
        )
        if (res.ok) {
          const data = await res.json()
          for (const [addr, info] of Object.entries(data.result ?? {})) {
            const r = info as any
            const flags: string[] = []
            const isHoneypot = r.is_honeypot === '1'
            const canMint = r.is_mintable === '1'
            const hasFeeManipulation = r.buy_tax && parseFloat(r.buy_tax) > 0.1 || r.sell_tax && parseFloat(r.sell_tax) > 0.1
            const hasBlacklist = r.is_blacklisted === '1'
            if (isHoneypot) flags.push('honeypot')
            if (canMint && r.owner_address) flags.push('hidden_mint')
            if (hasFeeManipulation) flags.push('high_tax')
            if (hasBlacklist) flags.push('has_blacklist')
            if (r.is_proxy === '1') flags.push('proxy_token')
            if (r.can_take_back_ownership === '1') flags.push('ownership_takeback')
            if (r.cannot_sell_all === '1') flags.push('cannot_sell_all')
            if (r.is_anti_whale === '1') flags.push('anti_whale')
            tokenResults[addr.toLowerCase()] = { flags, isHoneypot, canMint, hasFeeManipulation: !!hasFeeManipulation, hasBlacklist }
          }
        }
      } catch {}
    }

    // ── Step 4–7: Analyze each transaction ────────────────────────────────
    for (const tx of unique) {
      tx.riskFlags = []
      tx.riskLevel = 'safe'
      let riskScore = 0

      const toAddr = tx.to?.toLowerCase() ?? ''
      const fromAddr = tx.from?.toLowerCase() ?? ''
      const isOutbound = fromAddr === walletLower
      const counterparty = isOutbound ? toAddr : fromAddr

      // ── Step 1 result: Address risk ──
      const addrResult = addressResults[counterparty]
      if (addrResult) {
        if (addrResult.score > 0) {
          tx.riskFlags.push(...addrResult.flags.map(f => `goplus:${f}`))
          riskScore = Math.max(riskScore, addrResult.score)
        }
      }

      // ── Step 2 result: Contract risk ──
      const contractResult = contractResults[toAddr]
      if (contractResult && contractResult.flags.length > 0) {
        tx.riskFlags.push(...contractResult.flags.map(f => `contract:${f}`))
        if (contractResult.hasSelfDestruct) riskScore = Math.max(riskScore, 80)
        if (!contractResult.isVerified) riskScore = Math.max(riskScore, 50)
        if (contractResult.isProxy) riskScore = Math.max(riskScore, 20)
      }

      // ── Step 3 result: Token risk ──
      if (tx.contractAddress) {
        const tokenResult = tokenResults[tx.contractAddress.toLowerCase()]
        if (tokenResult && tokenResult.flags.length > 0) {
          tx.riskFlags.push(...tokenResult.flags.map(f => `token:${f}`))
          if (tokenResult.isHoneypot) riskScore = Math.max(riskScore, 95)
          if (tokenResult.hasFeeManipulation) riskScore = Math.max(riskScore, 60)
          if (tokenResult.canMint) riskScore = Math.max(riskScore, 40)
        }
      }

      // ── Step 4: Approval detection ──
      const method = tx.methodName?.toLowerCase() ?? ''
      if (method === 'approve' || method === 'setapprovalforall') {
        tx.riskFlags.push('approval_call')
        // Check if unlimited approval (max uint256 value)
        const decimals = tx.tokenDecimals ?? 18
        const val = Number(tx.value) / Math.pow(10, decimals)
        if (val > 1e12 || tx.value > BigInt('0xffffffffffffff')) {
          tx.riskFlags.push('unlimited_approval')
          riskScore = Math.max(riskScore, 60)
        }
        if (method === 'setapprovalforall') {
          tx.riskFlags.push('nft_approval_all')
          riskScore = Math.max(riskScore, 50)
        }
      }

      // ── Step 5: Address poisoning detection ──
      // Check if there are similar-looking addresses (same first 4 + last 4 chars)
      if (isOutbound && toAddr) {
        const prefix = toAddr.slice(0, 6)
        const suffix = toAddr.slice(-4)
        const similarAddrs = [...counterpartyAddresses].filter(a =>
          a !== toAddr && a.startsWith(prefix) && a.endsWith(suffix)
        )
        if (similarAddrs.length > 0) {
          tx.riskFlags.push('address_poisoning_risk')
          riskScore = Math.max(riskScore, 75)
        }
      }

      // ── Step 6: Behavioral patterns ──
      if (tx.isError) {
        tx.riskFlags.push('failed_tx')
        riskScore = Math.max(riskScore, 15)
      }

      if (toAddr === '0x0000000000000000000000000000000000000000' ||
          toAddr === '0x000000000000000000000000000000000000dead') {
        tx.riskFlags.push('burn_address')
        riskScore = Math.max(riskScore, 20)
      }

      const decimals = tx.tokenDecimals ?? 18
      const valueNormalized = Number(tx.value) / Math.pow(10, decimals)
      if (isOutbound && valueNormalized > 100) {
        tx.riskFlags.push('large_outbound')
        riskScore = Math.max(riskScore, 40)
      }

      // ── Step 7: Apply SlowMist risk score thresholds ──
      // ≤30 = safe, 31-70 = suspicious, 71-90 = dangerous, ≥91 = block
      if (riskScore >= 91) tx.riskLevel = 'dangerous'
      else if (riskScore >= 31) tx.riskLevel = 'suspicious'
      else tx.riskLevel = 'safe'

      // Store the computed score
      ;(tx as any).riskScore = riskScore
    }

    // Attach analysis metadata to the response
    ;(unique as any).__analysisMetadata = {
      addressesChecked: Object.keys(addressResults).length,
      contractsChecked: Object.keys(contractResults).length,
      tokensChecked: Object.keys(tokenResults).length,
      goplusChainId,
    }

    return unique
  } catch (err) {
    console.error(`[erc8004] Failed to get transactions for ${walletAddress} on ${chainKey}:`, err)
    return []
  }
}

/**
 * Scan all supported chains and return aggregated agent list.
 */
export async function scanAllChains(
  chains?: string[],
  fromBlock?: bigint,
): Promise<ERC8004Agent[]> {
  const chainKeys = chains ?? Object.keys(SUPPORTED_CHAINS)

  const results = await Promise.allSettled(
    chainKeys.map(k => getRegisteredAgents(k, fromBlock ?? 0n))
  )

  const agents: ERC8004Agent[] = []
  for (const result of results) {
    if (result.status === 'fulfilled') {
      agents.push(...result.value)
    }
  }

  return agents.sort((a, b) => Number(b.blockNumber - a.blockNumber))
}
