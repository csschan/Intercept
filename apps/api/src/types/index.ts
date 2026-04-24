// ── Chain Types ───────────────────────────────────────────────────────────────

export type Chain =
  | 'solana'
  | 'solana-devnet'
  | 'ethereum'
  | 'base'
  | 'polygon'
  | 'arbitrum'
  | 'arc-testnet'

export type TxType = 'transfer' | 'swap' | 'contract_call' | 'approve' | 'other'

export type Decision = 'allow' | 'deny' | 'ask_user'

// ── Normalized Transaction ────────────────────────────────────────────────────
// Chain-agnostic representation used by the policy engine

export interface NormalizedTransaction {
  chain: Chain
  txType: TxType
  fromAddress?: string
  toAddress: string
  amountRaw: string          // smallest unit (lamports, wei, etc.)
  amountUsdc: number         // USD-equivalent for policy evaluation
  token: string              // 'SOL' | 'USDC' | 'ETH' | mint/contract address
  tokenAddress?: string
  metadata: TxMetadata
  rawTxData?: unknown        // original tx object from agent
  // EVM-specific fields for deep security analysis
  data?: string              // calldata hex
  contractAddress?: string   // ERC-20 token contract being interacted with
}

export interface TxMetadata {
  purpose?: string
  merchant?: string          // human-readable name or domain
  merchantAddress?: string   // on-chain address
  category?: string          // 'api_credits' | 'developer_tools' | 'saas' | etc.
  isRecurring?: boolean
  isNewMerchant?: boolean
  contractMethod?: string    // for contract_call type
  notes?: string
}

// ── Policy ────────────────────────────────────────────────────────────────────

export interface PolicyRules {
  autoApproveBelowUsdc?: number
  requireApprovalAboveUsdc?: number
  dailyLimitUsdc?: number
  monthlyLimitUsdc?: number
  allowRecurring: boolean
  allowAutoPurchase: boolean
  requireConfirmationNewMerchant: boolean
  allowedCategories: string[]
  blockedCategories: string[]
  merchantAllowlist: string[]
  merchantBlocklist: string[]
  tokenAllowlist: string[]
  timeoutSeconds: number
  timeoutAction: 'allow' | 'deny'
}

// ── Decision Result ───────────────────────────────────────────────────────────

export interface AuthDecision {
  decision: Decision
  reason: string
  ruleTriggered?: string
}

// ── Authorization Request / Response ─────────────────────────────────────────

export interface AuthorizeRequest {
  agentId: string
  chain: Chain
  transaction: {
    type?: TxType
    from?: string
    to: string
    amount: string
    token: string
    tokenAddress?: string
    metadata?: Partial<TxMetadata>
  }
}

export interface AuthorizeResponse {
  decision: Decision
  requestId: string
  reason: string
  ruleTriggered?: string
  // Only present when decision === 'ask_user'
  expiresAt?: string
  approvalUrl?: string
  timeoutAction?: 'allow' | 'deny'
}

// ── NLP Parsing ───────────────────────────────────────────────────────────────

export interface ParsedPolicy {
  autoApproveBelowUsdc?: number
  requireApprovalAboveUsdc?: number
  dailyLimitUsdc?: number
  monthlyLimitUsdc?: number
  allowRecurring?: boolean
  requireConfirmationNewMerchant?: boolean
  allowedCategories?: string[]
  blockedCategories?: string[]
  merchantBlocklist?: string[]
  tokenAllowlist?: string[]
}

export interface ParsePolicyResponse {
  parsed: ParsedPolicy
  confirmationMessage: string
  ambiguous: string[]       // fields that couldn't be confidently parsed
}
