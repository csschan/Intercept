/**
 * Policy Engine
 *
 * Pure function: takes a normalized transaction + policy rules + budget state
 * Returns: allow | deny | ask_user with reason
 *
 * Decision priority (first match wins):
 * 1. Token blocklist (hard deny)
 * 2. Merchant blocklist (hard deny)
 * 3. Category blocklist (hard deny)
 * 4. Daily budget exceeded (deny)
 * 5. Monthly budget exceeded (deny)
 * 6. Recurring not allowed (deny)
 * 7. New merchant requires confirmation (ask_user)
 * 8. Amount above require_approval threshold (ask_user)
 * 9. Amount above auto_approve threshold (ask_user)
 * 10. Category not in allowlist (ask_user)
 * 11. Default: allow
 */

import type { NormalizedTransaction, PolicyRules, AuthDecision } from '../types/index.js'

export interface BudgetState {
  dailySpentUsdc: number
  monthlySpentUsdc: number
}

export function evaluatePolicy(
  tx: NormalizedTransaction,
  rules: PolicyRules,
  budget: BudgetState,
): AuthDecision {
  const amount = tx.amountUsdc
  const merchant = tx.metadata.merchant || tx.metadata.merchantAddress || tx.toAddress
  const category = tx.metadata.category?.toLowerCase()

  // ── Hard Denies ────────────────────────────────────────────────────────────

  // Token not in allowlist
  if (rules.tokenAllowlist.length > 0) {
    const tokenId = tx.token.toUpperCase()
    const allowed = rules.tokenAllowlist.map(t => t.toUpperCase())
    if (!allowed.includes(tokenId) && !allowed.includes(tx.tokenAddress ?? '')) {
      return {
        decision: 'deny',
        reason: `Token ${tx.token} is not in the allowed token list`,
        ruleTriggered: 'token_not_in_allowlist',
      }
    }
  }

  // Merchant blocklist
  if (rules.merchantBlocklist.length > 0 && merchant) {
    const blocked = rules.merchantBlocklist.map(m => m.toLowerCase())
    if (blocked.includes(merchant.toLowerCase())) {
      return {
        decision: 'deny',
        reason: `Merchant "${merchant}" is on the blocklist`,
        ruleTriggered: 'merchant_blocklist',
      }
    }
  }

  // Category blocklist
  if (rules.blockedCategories.length > 0 && category) {
    const blocked = rules.blockedCategories.map(c => c.toLowerCase())
    if (blocked.includes(category)) {
      return {
        decision: 'deny',
        reason: `Category "${category}" is blocked`,
        ruleTriggered: 'category_blocklist',
      }
    }
  }

  // Recurring not allowed
  if (!rules.allowRecurring && tx.metadata.isRecurring) {
    return {
      decision: 'deny',
      reason: 'Recurring payments are not allowed for this agent',
      ruleTriggered: 'recurring_not_allowed',
    }
  }

  // Daily budget exceeded
  if (rules.dailyLimitUsdc !== undefined) {
    if (budget.dailySpentUsdc + amount > rules.dailyLimitUsdc) {
      return {
        decision: 'deny',
        reason: `Daily budget exceeded: would spend $${(budget.dailySpentUsdc + amount).toFixed(2)} of $${rules.dailyLimitUsdc} limit`,
        ruleTriggered: 'daily_budget_exceeded',
      }
    }
  }

  // Monthly budget exceeded
  if (rules.monthlyLimitUsdc !== undefined) {
    if (budget.monthlySpentUsdc + amount > rules.monthlyLimitUsdc) {
      return {
        decision: 'deny',
        reason: `Monthly budget exceeded: would spend $${(budget.monthlySpentUsdc + amount).toFixed(2)} of $${rules.monthlyLimitUsdc} limit`,
        ruleTriggered: 'monthly_budget_exceeded',
      }
    }
  }

  // ── Ask User ───────────────────────────────────────────────────────────────

  // New merchant requires confirmation
  if (rules.requireConfirmationNewMerchant && tx.metadata.isNewMerchant) {
    return {
      decision: 'ask_user',
      reason: `New merchant "${merchant}" requires your confirmation`,
      ruleTriggered: 'new_merchant_confirmation',
    }
  }

  // Amount requires approval
  if (rules.requireApprovalAboveUsdc !== undefined && amount > rules.requireApprovalAboveUsdc) {
    return {
      decision: 'ask_user',
      reason: `Amount $${amount.toFixed(2)} exceeds auto-approval threshold of $${rules.requireApprovalAboveUsdc}`,
      ruleTriggered: 'amount_above_approval_threshold',
    }
  }

  // Merchant not in allowlist (only if allowlist is defined)
  if (rules.merchantAllowlist.length > 0 && merchant) {
    const allowed = rules.merchantAllowlist.map(m => m.toLowerCase())
    if (!allowed.includes(merchant.toLowerCase())) {
      return {
        decision: 'ask_user',
        reason: `Merchant "${merchant}" is not on the approved list`,
        ruleTriggered: 'merchant_not_in_allowlist',
      }
    }
  }

  // Category not in allowlist (only if allowlist is defined)
  if (rules.allowedCategories.length > 0 && category) {
    const allowed = rules.allowedCategories.map(c => c.toLowerCase())
    if (!allowed.includes(category)) {
      return {
        decision: 'ask_user',
        reason: `Category "${category}" is not in the approved list`,
        ruleTriggered: 'category_not_in_allowlist',
      }
    }
  }

  // Amount above auto-approve threshold (but below require-approval threshold)
  if (rules.autoApproveBelowUsdc !== undefined && amount > rules.autoApproveBelowUsdc) {
    return {
      decision: 'ask_user',
      reason: `Amount $${amount.toFixed(2)} exceeds auto-approval limit of $${rules.autoApproveBelowUsdc}`,
      ruleTriggered: 'amount_above_auto_approve',
    }
  }

  // ── Allow ──────────────────────────────────────────────────────────────────

  const autoReason = rules.autoApproveBelowUsdc !== undefined
    ? `Amount $${amount.toFixed(2)} is within auto-approval limit`
    : 'Transaction meets all policy requirements'

  return {
    decision: 'allow',
    reason: autoReason,
    ruleTriggered: 'policy_passed',
  }
}
