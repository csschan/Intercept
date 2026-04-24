/**
 * Policy Engine Tests
 * Uses Node.js native test runner (no extra deps needed)
 * Run: npx tsx --test apps/api/src/lib/policy-engine.test.ts
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { evaluatePolicy, type BudgetState } from './policy-engine.js'
import type { NormalizedTransaction, PolicyRules } from '../types/index.js'

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeTx(overrides: Partial<NormalizedTransaction> = {}): NormalizedTransaction {
  return {
    chain: 'solana',
    txType: 'transfer',
    toAddress: '9xQe...merchant1',
    amountRaw: '1000000',
    amountUsdc: 1,
    token: 'USDC',
    metadata: {},
    ...overrides,
  }
}

function makeRules(overrides: Partial<PolicyRules> = {}): PolicyRules {
  return {
    allowRecurring: true,
    allowAutoPurchase: true,
    requireConfirmationNewMerchant: false,
    allowedCategories: [],
    blockedCategories: [],
    merchantAllowlist: [],
    merchantBlocklist: [],
    tokenAllowlist: [],
    timeoutSeconds: 300,
    timeoutAction: 'deny',
    ...overrides,
  }
}

const zeroBudget: BudgetState = { dailySpentUsdc: 0, monthlySpentUsdc: 0 }

// ── Tests ────────────────────────────────────────────────────────────────────

describe('evaluatePolicy', () => {
  // ── Allow ────────────────────────────────────────────────────────────────

  it('should allow a normal transaction that meets all rules', () => {
    const result = evaluatePolicy(makeTx(), makeRules(), zeroBudget)
    assert.equal(result.decision, 'allow')
    assert.equal(result.ruleTriggered, 'policy_passed')
  })

  it('should allow when amount is below autoApproveBelowUsdc', () => {
    const result = evaluatePolicy(
      makeTx({ amountUsdc: 3 }),
      makeRules({ autoApproveBelowUsdc: 5 }),
      zeroBudget,
    )
    assert.equal(result.decision, 'allow')
    assert.match(result.reason, /within auto-approval/)
  })

  // ── Deny: Token ──────────────────────────────────────────────────────────

  it('should deny if token is not in allowlist', () => {
    const result = evaluatePolicy(
      makeTx({ token: 'BONK' }),
      makeRules({ tokenAllowlist: ['USDC', 'SOL'] }),
      zeroBudget,
    )
    assert.equal(result.decision, 'deny')
    assert.equal(result.ruleTriggered, 'token_not_in_allowlist')
  })

  it('should allow if token IS in allowlist (case-insensitive)', () => {
    const result = evaluatePolicy(
      makeTx({ token: 'usdc' }),
      makeRules({ tokenAllowlist: ['USDC'] }),
      zeroBudget,
    )
    assert.equal(result.decision, 'allow')
  })

  it('should skip token check when allowlist is empty', () => {
    const result = evaluatePolicy(
      makeTx({ token: 'BONK' }),
      makeRules({ tokenAllowlist: [] }),
      zeroBudget,
    )
    assert.equal(result.decision, 'allow')
  })

  // ── Deny: Merchant blocklist ─────────────────────────────────────────────

  it('should deny if merchant is on blocklist', () => {
    const result = evaluatePolicy(
      makeTx({ metadata: { merchant: 'ScamSite' } }),
      makeRules({ merchantBlocklist: ['scamsite'] }),
      zeroBudget,
    )
    assert.equal(result.decision, 'deny')
    assert.equal(result.ruleTriggered, 'merchant_blocklist')
  })

  // ── Deny: Category blocklist ─────────────────────────────────────────────

  it('should deny if category is blocked', () => {
    const result = evaluatePolicy(
      makeTx({ metadata: { category: 'gambling' } }),
      makeRules({ blockedCategories: ['Gambling'] }),
      zeroBudget,
    )
    assert.equal(result.decision, 'deny')
    assert.equal(result.ruleTriggered, 'category_blocklist')
  })

  // ── Deny: Recurring ──────────────────────────────────────────────────────

  it('should deny recurring payment when not allowed', () => {
    const result = evaluatePolicy(
      makeTx({ metadata: { isRecurring: true } }),
      makeRules({ allowRecurring: false }),
      zeroBudget,
    )
    assert.equal(result.decision, 'deny')
    assert.equal(result.ruleTriggered, 'recurring_not_allowed')
  })

  it('should allow recurring payment when allowed', () => {
    const result = evaluatePolicy(
      makeTx({ metadata: { isRecurring: true } }),
      makeRules({ allowRecurring: true }),
      zeroBudget,
    )
    assert.equal(result.decision, 'allow')
  })

  // ── Deny: Budget ─────────────────────────────────────────────────────────

  it('should deny when daily budget would be exceeded', () => {
    const result = evaluatePolicy(
      makeTx({ amountUsdc: 20 }),
      makeRules({ dailyLimitUsdc: 50 }),
      { dailySpentUsdc: 40, monthlySpentUsdc: 0 },
    )
    assert.equal(result.decision, 'deny')
    assert.equal(result.ruleTriggered, 'daily_budget_exceeded')
  })

  it('should deny when monthly budget would be exceeded', () => {
    const result = evaluatePolicy(
      makeTx({ amountUsdc: 10 }),
      makeRules({ monthlyLimitUsdc: 100 }),
      { dailySpentUsdc: 0, monthlySpentUsdc: 95 },
    )
    assert.equal(result.decision, 'deny')
    assert.equal(result.ruleTriggered, 'monthly_budget_exceeded')
  })

  it('should allow when budget is exactly at the limit', () => {
    const result = evaluatePolicy(
      makeTx({ amountUsdc: 10 }),
      makeRules({ dailyLimitUsdc: 50 }),
      { dailySpentUsdc: 40, monthlySpentUsdc: 0 },
    )
    assert.equal(result.decision, 'allow')
  })

  // ── Ask User: New merchant ───────────────────────────────────────────────

  it('should ask_user for new merchant when flag is set', () => {
    const result = evaluatePolicy(
      makeTx({ metadata: { isNewMerchant: true, merchant: 'NewShop' } }),
      makeRules({ requireConfirmationNewMerchant: true }),
      zeroBudget,
    )
    assert.equal(result.decision, 'ask_user')
    assert.equal(result.ruleTriggered, 'new_merchant_confirmation')
  })

  // ── Ask User: Amount thresholds ──────────────────────────────────────────

  it('should ask_user when amount exceeds requireApprovalAboveUsdc', () => {
    const result = evaluatePolicy(
      makeTx({ amountUsdc: 150 }),
      makeRules({ requireApprovalAboveUsdc: 100 }),
      zeroBudget,
    )
    assert.equal(result.decision, 'ask_user')
    assert.equal(result.ruleTriggered, 'amount_above_approval_threshold')
  })

  it('should ask_user when amount exceeds autoApproveBelowUsdc', () => {
    const result = evaluatePolicy(
      makeTx({ amountUsdc: 10 }),
      makeRules({ autoApproveBelowUsdc: 5 }),
      zeroBudget,
    )
    assert.equal(result.decision, 'ask_user')
    assert.equal(result.ruleTriggered, 'amount_above_auto_approve')
  })

  // ── Ask User: Merchant not in allowlist ──────────────────────────────────

  it('should ask_user when merchant is not in allowlist', () => {
    const result = evaluatePolicy(
      makeTx({ metadata: { merchant: 'UnknownShop' } }),
      makeRules({ merchantAllowlist: ['TrustedShop'] }),
      zeroBudget,
    )
    assert.equal(result.decision, 'ask_user')
    assert.equal(result.ruleTriggered, 'merchant_not_in_allowlist')
  })

  // ── Ask User: Category not in allowlist ──────────────────────────────────

  it('should ask_user when category is not in allowlist', () => {
    const result = evaluatePolicy(
      makeTx({ metadata: { category: 'entertainment' } }),
      makeRules({ allowedCategories: ['api_credits', 'developer_tools'] }),
      zeroBudget,
    )
    assert.equal(result.decision, 'ask_user')
    assert.equal(result.ruleTriggered, 'category_not_in_allowlist')
  })

  // ── Priority: deny before ask_user ───────────────────────────────────────

  it('should deny (budget) before ask_user (new merchant)', () => {
    const result = evaluatePolicy(
      makeTx({ amountUsdc: 20, metadata: { isNewMerchant: true } }),
      makeRules({
        dailyLimitUsdc: 10,
        requireConfirmationNewMerchant: true,
      }),
      { dailySpentUsdc: 0, monthlySpentUsdc: 0 },
    )
    assert.equal(result.decision, 'deny')
    assert.equal(result.ruleTriggered, 'daily_budget_exceeded')
  })

  it('should deny (token blocklist) before deny (budget)', () => {
    const result = evaluatePolicy(
      makeTx({ token: 'SCAM', amountUsdc: 999 }),
      makeRules({ tokenAllowlist: ['USDC'], dailyLimitUsdc: 10 }),
      zeroBudget,
    )
    assert.equal(result.decision, 'deny')
    assert.equal(result.ruleTriggered, 'token_not_in_allowlist')
  })
})
