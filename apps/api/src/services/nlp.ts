/**
 * NLP Policy Parser
 *
 * Uses Claude to convert natural language spending rules into structured JSON.
 * Enforces strict schema — ambiguous input is flagged, not guessed.
 */

import OpenAI from 'openai'
import type { ParsedPolicy, ParsePolicyResponse } from '../types/index.js'

const client = new OpenAI({
  baseURL: process.env.CLAUDE_PROXY_URL ?? 'http://localhost:3456/v1',
  apiKey: process.env.CLAUDE_PROXY_KEY ?? 'proxy',
})

const SYSTEM_PROMPT = `You are a spending policy parser for an AI agent authorization system.

Your job: convert natural language spending rules into structured JSON.

Output ONLY valid JSON matching this exact schema:
{
  "parsed": {
    "autoApproveBelowUsdc": number | null,
    "requireApprovalAboveUsdc": number | null,
    "dailyLimitUsdc": number | null,
    "monthlyLimitUsdc": number | null,
    "allowRecurring": boolean | null,
    "requireConfirmationNewMerchant": boolean | null,
    "allowedCategories": string[] | null,
    "blockedCategories": string[] | null,
    "merchantBlocklist": string[] | null,
    "tokenAllowlist": string[] | null
  },
  "confirmationMessage": "A plain-language summary of what you understood",
  "ambiguous": ["list of phrases that were too vague to parse confidently"]
}

Rules:
- null means "not specified" (keep existing value)
- If user says "automatically approve under X", set autoApproveBelowUsdc = X
- If user says "ask me for anything over Y", set requireApprovalAboveUsdc = Y
- Currency: treat $, USD, USDC, dollars as USDC
- Categories: normalize to snake_case (e.g., "developer tools" → "developer_tools")
- If a phrase is ambiguous (e.g., "not too much"), add it to ambiguous[] and set null
- Never guess at a number — if unsure, add to ambiguous[]
- confirmationMessage should be in the same language as the user's input

Common categories: api_credits, developer_tools, saas, cloud_services, data_services, entertainment, gambling, adult_content`

const FEW_SHOT_EXAMPLES = [
  {
    input: '这个 agent 每月最多花 50 美元，低于 5 美元自动通过，新商家先问我',
    output: {
      parsed: {
        autoApproveBelowUsdc: 5,
        requireApprovalAboveUsdc: null,
        dailyLimitUsdc: null,
        monthlyLimitUsdc: 50,
        allowRecurring: null,
        requireConfirmationNewMerchant: true,
        allowedCategories: null,
        blockedCategories: null,
        merchantBlocklist: null,
        tokenAllowlist: null,
      },
      confirmationMessage:
        '系统理解：每月预算上限 $50 USDC；$5 以下自动通过；遇到新商家先通知你确认。',
      ambiguous: [],
    },
  },
  {
    input: 'Auto approve anything under $10, never allow gambling, block automatic renewals',
    output: {
      parsed: {
        autoApproveBelowUsdc: 10,
        requireApprovalAboveUsdc: null,
        dailyLimitUsdc: null,
        monthlyLimitUsdc: null,
        allowRecurring: false,
        requireConfirmationNewMerchant: null,
        allowedCategories: null,
        blockedCategories: ['gambling'],
        merchantBlocklist: null,
        tokenAllowlist: null,
      },
      confirmationMessage:
        'Understood: auto-approve under $10; block all gambling purchases; no automatic renewals.',
      ambiguous: [],
    },
  },
  {
    input: 'Only spend USDC, max $200 per month, ask me before anything',
    output: {
      parsed: {
        autoApproveBelowUsdc: 0,
        requireApprovalAboveUsdc: 0,
        dailyLimitUsdc: null,
        monthlyLimitUsdc: 200,
        allowRecurring: null,
        requireConfirmationNewMerchant: null,
        allowedCategories: null,
        blockedCategories: null,
        merchantBlocklist: null,
        tokenAllowlist: ['USDC'],
      },
      confirmationMessage:
        'Understood: USDC only; $200/month cap; ask you before every transaction.',
      ambiguous: [],
    },
  },
]

export async function parsePolicy(
  userText: string,
  currentPolicy?: Partial<ParsedPolicy>,
): Promise<ParsePolicyResponse> {
  const examples = FEW_SHOT_EXAMPLES.map(
    e => `User: "${e.input}"\nOutput: ${JSON.stringify(e.output, null, 2)}`,
  ).join('\n\n')

  const currentContext = currentPolicy
    ? `\nCurrent policy (for context): ${JSON.stringify(currentPolicy, null, 2)}`
    : ''

  const message = await client.chat.completions.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 1024,
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      {
        role: 'user',
        content: `Here are examples of how to parse policies:\n\n${examples}${currentContext}\n\nNow parse this policy:\n"${userText}"`,
      },
    ],
  })

  const text = message.choices[0]?.message?.content
  if (!text) throw new Error('Empty response from Claude')

  // Extract JSON from response (Claude sometimes adds markdown code blocks)
  const jsonMatch = text.match(/\{[\s\S]*\}/)
  if (!jsonMatch) throw new Error('No JSON found in Claude response')

  const result = JSON.parse(jsonMatch[0]) as ParsePolicyResponse


  // Remove null values from parsed (keep only explicitly set fields)
  const cleaned: ParsedPolicy = {}
  for (const [key, value] of Object.entries(result.parsed)) {
    if (value !== null && value !== undefined) {
      ;(cleaned as Record<string, unknown>)[key] = value
    }
  }
  result.parsed = cleaned

  return result
}
