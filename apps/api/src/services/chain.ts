/**
 * Chain Service
 *
 * Handles on-chain operations after off-chain policy is saved.
 * Currently: writes policy hash to Solana PolicyRegistry program.
 *
 * This runs async after the policy is saved to PostgreSQL —
 * it does NOT block the API response.
 */

import { createHash } from 'crypto'

// Lazy-import the Solana client to avoid crashing if SOLANA_PRIVATE_KEY
// is not configured in development.
// The actual client lives in packages/solana — imported dynamically so the
// API boots fine without the package built.
async function getSolanaClient() {
  if (!process.env.SOLANA_PRIVATE_KEY) return null
  try {
    const mod = await import('@agent-guard/solana')
    return mod.getPolicyRegistryClient()
  } catch {
    return null
  }
}

export interface PolicyForChain {
  agentId: string
  ownerPublicKey?: string
  rules: object
}

/**
 * Normalize a DB policy row into the canonical rules object used for hashing.
 * MUST be identical between sync and verify.
 */
export function policyToRules(policy: {
  autoApproveBelowUsdc?: string | number | null
  requireApprovalAboveUsdc?: string | number | null
  dailyLimitUsdc?: string | number | null
  monthlyLimitUsdc?: string | number | null
  allowRecurring?: boolean
  allowAutoPurchase?: boolean
  requireConfirmationNewMerchant?: boolean
  allowedCategories?: string[] | null
  blockedCategories?: string[] | null
  merchantAllowlist?: string[] | null
  merchantBlocklist?: string[] | null
  tokenAllowlist?: string[] | null
  timeoutSeconds?: number
  timeoutAction?: string
}): Record<string, unknown> {
  return {
    autoApproveBelowUsdc: policy.autoApproveBelowUsdc != null ? Number(policy.autoApproveBelowUsdc) : null,
    requireApprovalAboveUsdc: policy.requireApprovalAboveUsdc != null ? Number(policy.requireApprovalAboveUsdc) : null,
    dailyLimitUsdc: policy.dailyLimitUsdc != null ? Number(policy.dailyLimitUsdc) : null,
    monthlyLimitUsdc: policy.monthlyLimitUsdc != null ? Number(policy.monthlyLimitUsdc) : null,
    allowRecurring: policy.allowRecurring ?? true,
    allowAutoPurchase: policy.allowAutoPurchase ?? false,
    requireConfirmationNewMerchant: policy.requireConfirmationNewMerchant ?? false,
    allowedCategories: policy.allowedCategories ?? [],
    blockedCategories: policy.blockedCategories ?? [],
    merchantAllowlist: policy.merchantAllowlist ?? [],
    merchantBlocklist: policy.merchantBlocklist ?? [],
    tokenAllowlist: policy.tokenAllowlist ?? [],
    timeoutSeconds: policy.timeoutSeconds ?? 300,
    timeoutAction: policy.timeoutAction ?? 'deny',
  }
}

/**
 * Compute the canonical hash of a policy object.
 * Must match exactly what the Solana client uses.
 */
export function hashPolicy(rules: object): string {
  const canonical = JSON.stringify(rules, Object.keys(rules as Record<string, unknown>).sort())
  return createHash('sha256').update(canonical).digest('hex')
}

/**
 * Write policy hash to Solana (fire-and-forget).
 * Returns the on-chain result if successful, null if Solana is not configured.
 */
export async function syncPolicyToChain(
  policy: PolicyForChain,
): Promise<{ pda: string; hash: string; signature: string; explorerUrl: string } | null> {
  try {
    const client = await getSolanaClient()
    if (!client) return null

    const result = await client.savePolicy(policy.agentId, policy.rules)
    const explorerUrl = client.getExplorerUrl(
      result.pda,
      (process.env.SOLANA_NETWORK as 'devnet' | 'mainnet-beta') ?? 'devnet',
    )

    console.log(`[chain] Policy synced on-chain: ${explorerUrl}`)
    return { ...result, explorerUrl }
  } catch (err) {
    // On-chain sync failure should never block the API
    console.error('[chain] Failed to sync policy to Solana:', err)
    return null
  }
}

/**
 * Verify that an agent's local policy still matches what's on-chain.
 * Used for audit / tamper detection.
 */
export async function verifyPolicyOnChain(
  ownerPublicKey: string,
  agentId: string,
  rules: object,
): Promise<{ verified: boolean; onChainHash?: string; localHash: string }> {
  const localHash = hashPolicy(rules)

  try {
    const client = await getSolanaClient()
    if (!client) return { verified: false, localHash }

    const matches = await client.verifyPolicy(ownerPublicKey, agentId, rules)
    const onChain = await client.getPolicy(ownerPublicKey, agentId)

    return {
      verified: matches,
      onChainHash: onChain?.policyHash,
      localHash,
    }
  } catch {
    return { verified: false, localHash }
  }
}
