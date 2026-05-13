/**
 * Shared Threat Intelligence
 *
 * Every deny decision feeds the global threat database.
 * Every authorize check queries it first.
 *
 * This is Intercept's network effect:
 *   Agent A gets attacked → address stored → Agent B protected instantly.
 */

import { db, threatIntel } from '../db/index.js'
import { eq, and, sql, gte } from 'drizzle-orm'

// ── In-memory cache for hot-path lookups ────────────────────────────────────

interface ThreatEntry {
  threatType: string
  severity: string
  reason: string
  reportCount: number
}

let threatCache = new Map<string, ThreatEntry>()  // key = lowercase threat_value
let lastCacheRefresh = 0
const CACHE_TTL = 60_000  // refresh every 60 seconds

async function refreshCache() {
  if (Date.now() - lastCacheRefresh < CACHE_TTL && threatCache.size > 0) return

  try {
    const rows = await db
      .select()
      .from(threatIntel)
      .where(eq(threatIntel.status, 'active'))

    const newCache = new Map<string, ThreatEntry>()
    for (const r of rows) {
      newCache.set(r.threatValue.toLowerCase(), {
        threatType: r.threatType,
        severity: r.severity,
        reason: r.reason,
        reportCount: r.reportCount,
      })
    }
    threatCache = newCache
    lastCacheRefresh = Date.now()
  } catch {
    // Cache refresh failure — keep stale cache
  }
}

// ── Query: check if address/URL/token is in threat database ─────────────────

export interface ThreatMatch {
  matched: boolean
  threatType: string
  severity: string
  reason: string
  reportCount: number
}

const NO_MATCH: ThreatMatch = { matched: false, threatType: '', severity: '', reason: '', reportCount: 0 }

/**
 * Check if an address is in the shared threat database.
 * Runs on every authorize_payment call — must be fast.
 */
export async function checkThreatIntel(
  address: string,
  chain?: string,
): Promise<ThreatMatch> {
  await refreshCache()

  const key = address.toLowerCase()
  const hit = threatCache.get(key)
  if (hit) {
    return {
      matched: true,
      threatType: hit.threatType,
      severity: hit.severity,
      reason: `[Shared Intel] ${hit.reason} (reported ${hit.reportCount}x)`,
      reportCount: hit.reportCount,
    }
  }
  return NO_MATCH
}

/**
 * Check multiple values at once (address + URL + token).
 * Returns the highest-severity match.
 */
export async function checkThreatIntelBatch(
  values: { value: string; type: string }[],
): Promise<ThreatMatch> {
  await refreshCache()

  let worst: ThreatMatch = NO_MATCH
  const severityRank: Record<string, number> = { critical: 3, high: 2, medium: 1 }

  for (const { value } of values) {
    const hit = threatCache.get(value.toLowerCase())
    if (hit && (severityRank[hit.severity] ?? 0) > (severityRank[worst.severity] ?? 0)) {
      worst = {
        matched: true,
        threatType: hit.threatType,
        severity: hit.severity,
        reason: `[Shared Intel] ${hit.reason} (reported ${hit.reportCount}x)`,
        reportCount: hit.reportCount,
      }
    }
  }
  return worst
}

// ── Write: record a threat from a deny decision ─────────────────────────────

export async function reportThreat(params: {
  threatType: 'address' | 'url' | 'injection_pattern' | 'token'
  threatValue: string
  chain?: string
  reason: string
  ruleTriggered?: string
  severity?: 'critical' | 'high' | 'medium'
  sourceAgentId?: string
  sourceRequestId?: string
}): Promise<void> {
  const { threatType, threatValue, chain, reason, ruleTriggered, severity, sourceAgentId, sourceRequestId } = params
  const value = threatValue.toLowerCase()

  try {
    // Upsert: increment report count if already exists
    await db.execute(sql`
      INSERT INTO threat_intel (threat_type, threat_value, chain, reason, rule_triggered, severity, source_agent_id, source_request_id)
      VALUES (${threatType}, ${value}, ${chain ?? null}, ${reason}, ${ruleTriggered ?? null}, ${severity ?? 'high'}, ${sourceAgentId ?? null}, ${sourceRequestId ?? null})
      ON CONFLICT (threat_type, threat_value, chain) WHERE status = 'active'
      DO UPDATE SET
        report_count = threat_intel.report_count + 1,
        last_reported_at = NOW(),
        severity = CASE WHEN ${severity ?? 'high'} = 'critical' THEN 'critical' ELSE threat_intel.severity END
    `)

    // Invalidate cache so next query picks it up
    lastCacheRefresh = 0
  } catch (err) {
    console.error('[threat-intel] Failed to report threat:', err)
  }
}

// ── Stats ───────────────────────────────────────────────────────────────────

export async function getThreatIntelStats() {
  const rows = await db.execute(sql`
    SELECT
      threat_type,
      COUNT(*) as count,
      SUM(report_count) as total_reports,
      MAX(last_reported_at) as latest
    FROM threat_intel
    WHERE status = 'active'
    GROUP BY threat_type
  `)

  const total = await db.execute(sql`
    SELECT COUNT(*) as total FROM threat_intel WHERE status = 'active'
  `)

  return {
    totalThreats: Number((total as any[])[0]?.total ?? 0),
    byType: (rows as any[]).map(r => ({
      type: r.threat_type,
      count: Number(r.count),
      totalReports: Number(r.total_reports),
      latestReport: r.latest,
    })),
    cacheSize: threatCache.size,
  }
}
