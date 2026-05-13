/**
 * Pattern Learner
 *
 * Periodically analyzes denied transactions to discover new attack patterns.
 * Uses LLM to extract regex rules from real deny data, then adds them to
 * the L1 detection engine automatically.
 *
 * Flow:
 *   1. Query auth_requests for recent denies (prompt_injection, phishing, social_engineering)
 *   2. Extract the purpose/notes text that triggered the deny
 *   3. Feed to LLM: "Here are attack texts. Extract new regex patterns not covered by existing rules."
 *   4. LLM returns structured patterns
 *   5. Validate each regex (must compile, must not false-positive on benign text)
 *   6. Insert into learned_patterns table
 *   7. security-checks.ts loads them at runtime
 */

import { db } from '../db/index.js'
import { sql } from 'drizzle-orm'

// ── LLM client (uses Claude proxy) ──────────────────────────────────────────

const PROXY_URL = process.env.CLAUDE_PROXY_URL ?? 'http://localhost:3456/v1'
const PROXY_KEY = process.env.CLAUDE_PROXY_KEY ?? 'proxy'

async function callLLM(systemPrompt: string, userPrompt: string): Promise<string> {
  const res = await fetch(`${PROXY_URL}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${PROXY_KEY}`,
    },
    body: JSON.stringify({
      model: 'claude-haiku-4',
      max_tokens: 2000,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
    }),
    signal: AbortSignal.timeout(120000),
  })

  if (!res.ok) throw new Error(`LLM proxy error: ${res.status}`)
  const data = await res.json() as any
  return data.choices?.[0]?.message?.content ?? ''
}

// ── Existing hardcoded patterns (to avoid duplicates) ───────────────────────

const EXISTING_KEYWORDS = [
  'ignore', 'override', 'bypass', 'forget', 'disregard', 'new instructions',
  'system prompt', 'send all', 'transfer all', 'maximum amount', 'skip approval',
  'urgent', 'immediately', 'emergency', 'act now', 'limited time',
  'DAN:', 'god mode', 'developer mode', 'jailbreak',
  'officially recommended', 'certified safe', 'endorsed',
  'safe read-only', 'harmless', 'completely safe',
  'auto-confirm', '--force', '-y',
  'airdrop', 'whitelist spot', 'exclusive access', 'pre-sale',
  'guaranteed', 'risk-free', 'double your',
  'approve all', 'unlimited approval', 'sign quickly',
]

// ── Benign test texts (for false-positive validation) ───────────────────────

const BENIGN_TEXTS = [
  'Purchase API credits for document analysis',
  'Pay for cloud compute resources',
  'Monthly subscription renewal for SaaS tool',
  'Transfer USDC to vendor for completed work',
  'Buy 100 tokens for testing purposes',
  'Pay freelancer for design work',
  'Renew annual license for development tools',
  'Purchase storage on decentralized network',
]

// ── Main: analyze and learn ─────────────────────────────────────────────────

export async function learnNewPatterns(): Promise<{
  analyzed: number
  newPatterns: number
  skipped: number
}> {
  console.log('[pattern-learner] Starting analysis...')

  // 1. Get recent deny texts (last 7 days, injection/phishing/social_engineering)
  const denyRows = await db.execute(sql`
    SELECT tx_metadata, reason, rule_triggered
    FROM auth_requests
    WHERE decision = 'deny'
      AND rule_triggered IN ('prompt_injection_high', 'phishing_detected', 'social_engineering_detected')
      AND created_at > NOW() - INTERVAL '7 days'
    ORDER BY created_at DESC
    LIMIT 200
  `)

  const denyTexts = (denyRows as any[])
    .map(r => {
      const meta = r.tx_metadata as any
      return [meta?.purpose, meta?.notes, meta?.merchant].filter(Boolean).join(' | ')
    })
    .filter(t => t.length > 10)

  if (denyTexts.length < 3) {
    console.log('[pattern-learner] Not enough deny data to analyze (need ≥3)')
    return { analyzed: 0, newPatterns: 0, skipped: 0 }
  }

  // Deduplicate
  const uniqueTexts = [...new Set(denyTexts)]
  console.log(`[pattern-learner] Analyzing ${uniqueTexts.length} unique deny texts`)

  // 2. Get existing learned patterns to avoid duplicates
  const existingRows = await db.execute(sql`
    SELECT pattern, label FROM learned_patterns WHERE status = 'active'
  `)
  const existingPatterns = (existingRows as any[]).map(r => r.pattern)

  // 3. Call LLM to extract new patterns
  const systemPrompt = `You are a security pattern analyst for an AI agent payment security system.

Your job: analyze attack texts that were blocked, and extract NEW regex patterns that could catch similar future attacks.

Rules:
- Output ONLY valid JSON array, no other text
- Each entry: {"pattern": "regex_string", "label": "short_name", "weight": 20-40, "confidence": 0.5-1.0}
- Patterns must be JavaScript-compatible regex (case-insensitive flag will be added)
- Patterns should be specific enough to not match normal payment purposes
- Do NOT output patterns for these already-covered keywords: ${EXISTING_KEYWORDS.slice(0, 30).join(', ')}
- Focus on novel phrasing, obfuscation techniques, or new attack vectors
- Output 0-5 patterns. If nothing new, output empty array []
- Weight guide: 20=low confidence, 30=medium, 40=high confidence`

  const userPrompt = `Here are ${uniqueTexts.length} attack texts that were blocked by our system. Find new patterns:

${uniqueTexts.slice(0, 50).map((t, i) => `${i + 1}. "${t}"`).join('\n')}

Extract new regex patterns NOT already covered by our existing rules. Output JSON array only.`

  let llmResponse: string
  try {
    llmResponse = await callLLM(systemPrompt, userPrompt)
  } catch (err) {
    console.error('[pattern-learner] LLM call failed:', err)
    return { analyzed: uniqueTexts.length, newPatterns: 0, skipped: 0 }
  }

  // 4. Parse LLM response
  let candidates: Array<{ pattern: string; label: string; weight: number; confidence: number }>
  try {
    // Extract JSON from response (LLM might wrap in markdown code block)
    const jsonMatch = llmResponse.match(/\[[\s\S]*\]/)
    if (!jsonMatch) {
      console.log('[pattern-learner] No JSON array found in LLM response')
      return { analyzed: uniqueTexts.length, newPatterns: 0, skipped: 0 }
    }
    candidates = JSON.parse(jsonMatch[0])
    if (!Array.isArray(candidates)) throw new Error('Not an array')
  } catch {
    console.error('[pattern-learner] Failed to parse LLM response')
    return { analyzed: uniqueTexts.length, newPatterns: 0, skipped: 0 }
  }

  console.log(`[pattern-learner] LLM suggested ${candidates.length} patterns`)

  // 5. Validate each pattern
  let newPatterns = 0
  let skipped = 0

  for (const candidate of candidates) {
    // a. Must have required fields
    if (!candidate.pattern || !candidate.label) {
      skipped++
      continue
    }

    // b. Must compile as valid regex
    let regex: RegExp
    try {
      regex = new RegExp(candidate.pattern, 'i')
    } catch {
      console.log(`[pattern-learner] Invalid regex: ${candidate.pattern}`)
      skipped++
      continue
    }

    // c. Must not already exist
    if (existingPatterns.includes(candidate.pattern)) {
      skipped++
      continue
    }

    // d. Must not false-positive on benign texts
    const falsePositives = BENIGN_TEXTS.filter(t => regex.test(t))
    if (falsePositives.length > 0) {
      console.log(`[pattern-learner] False positive on benign text: "${candidate.pattern}" matched "${falsePositives[0]}"`)
      skipped++
      continue
    }

    // e. Must match at least one deny text (sanity check)
    const truePositives = uniqueTexts.filter(t => regex.test(t))
    if (truePositives.length === 0) {
      skipped++
      continue
    }

    // 6. Insert into DB
    try {
      await db.execute(sql`
        INSERT INTO learned_patterns (pattern, label, weight, source, example_text, confidence)
        VALUES (${candidate.pattern}, ${candidate.label}, ${candidate.weight ?? 25}, 'llm', ${truePositives[0].slice(0, 500)}, ${candidate.confidence ?? 0.8})
        ON CONFLICT (pattern) WHERE status = 'active' DO NOTHING
      `)
      newPatterns++
      console.log(`[pattern-learner] ✅ New pattern: "${candidate.label}" → /${candidate.pattern}/i (weight: ${candidate.weight}, matched ${truePositives.length} attacks)`)
    } catch (err) {
      console.error(`[pattern-learner] DB insert failed:`, err)
      skipped++
    }
  }

  console.log(`[pattern-learner] Done: ${newPatterns} new, ${skipped} skipped`)
  return { analyzed: uniqueTexts.length, newPatterns, skipped }
}

// ── Load learned patterns for L1 engine ─────────────────────────────────────

let cachedLearnedRules: Array<{ label: string; weight: number; pattern: RegExp }> = []
let lastRuleLoad = 0
const RULE_CACHE_TTL = 5 * 60_000 // refresh every 5 minutes

export async function getLearnedRules(): Promise<Array<{ label: string; weight: number; pattern: RegExp }>> {
  if (Date.now() - lastRuleLoad < RULE_CACHE_TTL && cachedLearnedRules.length > 0) {
    return cachedLearnedRules
  }

  try {
    const rows = await db.execute(sql`
      SELECT pattern, label, weight FROM learned_patterns
      WHERE status = 'active'
      ORDER BY hit_count DESC, created_at DESC
    `)

    cachedLearnedRules = (rows as any[])
      .map(r => {
        try {
          return { label: `learned:${r.label}`, weight: Number(r.weight), pattern: new RegExp(r.pattern, 'i') }
        } catch {
          return null
        }
      })
      .filter(Boolean) as typeof cachedLearnedRules

    lastRuleLoad = Date.now()
    return cachedLearnedRules
  } catch {
    return cachedLearnedRules // return stale cache on error
  }
}

// ── Update hit count when a learned pattern matches ─────────────────────────

export async function recordPatternHit(label: string) {
  const cleanLabel = label.replace('learned:', '')
  await db.execute(sql`
    UPDATE learned_patterns SET hit_count = hit_count + 1, last_hit_at = NOW()
    WHERE label = ${cleanLabel} AND status = 'active'
  `).catch(() => {})
}
