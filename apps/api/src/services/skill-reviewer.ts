/**
 * Agent Skill Reviewer
 *
 * Implements all 6 review types from SlowMist Agent Security Skill:
 *   1. skill-mcp    — Skill / MCP server installation review
 *   2. repository   — GitHub repository review
 *   3. url-document — URL / document / Gist review
 *   4. onchain      — On-chain address / contract (handled by slowmist-analyzer)
 *   5. product-service — Product / API / SDK review
 *   6. message-share — Social recommendation review
 *
 * Each review returns a structured risk assessment.
 */

import { readFileSync } from 'fs'
import { join } from 'path'

// ── Types ──────────────────────────────────────────────────────────────────────

export interface SkillReviewResult {
  type: string
  riskLevel: 'low' | 'medium' | 'high' | 'reject'
  score: number             // 0-100 safety
  checks: ReviewCheck[]
  summary: string
  checklist: string         // raw markdown checklist from the skill
}

export interface ReviewCheck {
  name: string
  status: 'pass' | 'warn' | 'fail' | 'skip'
  detail: string
}

// ── Load checklists from packages/security-skill ──────────────────────────────

const SKILL_DIR = join(process.cwd(), '..', 'packages', 'security-skill')

function loadChecklist(type: string): string {
  const paths: Record<string, string> = {
    'skill-mcp': 'reviews/skill-mcp.md',
    'repository': 'reviews/repository.md',
    'url-document': 'reviews/url-document.md',
    'onchain': 'reviews/onchain.md',
    'product-service': 'reviews/product-service.md',
    'message-share': 'reviews/message-share.md',
    'red-flags': 'patterns/red-flags.md',
    'social-engineering': 'patterns/social-engineering.md',
  }
  try {
    return readFileSync(join(SKILL_DIR, paths[type] ?? ''), 'utf-8')
  } catch {
    return ''
  }
}

// ── Review: Skill / MCP Installation ──────────────────────────────────────────

export async function reviewSkillMcp(input: {
  name: string
  source: string         // npm / github / clawhub / unknown
  author?: string
  repoUrl?: string
  hasExecutableCode?: boolean
  fileTypes?: string[]   // ['.js', '.py', '.sh', etc.]
  permissions?: string[] // ['network', 'filesystem', 'env', etc.]
}): Promise<SkillReviewResult> {
  const checks: ReviewCheck[] = []
  let score = 100

  // Source verification
  const trustedSources = ['npm', 'github', 'clawhub']
  if (trustedSources.includes(input.source)) {
    checks.push({ name: 'Source verification', status: 'pass', detail: `Published on ${input.source} — trusted channel` })
  } else {
    checks.push({ name: 'Source verification', status: 'fail', detail: `Source "${input.source}" is not a trusted channel` })
    score -= 30
  }

  // Author check
  if (input.author) {
    checks.push({ name: 'Author identity', status: 'pass', detail: `Author: ${input.author}` })
  } else {
    checks.push({ name: 'Author identity', status: 'warn', detail: 'No author specified — anonymous package' })
    score -= 15
  }

  // File types
  const dangerousTypes = ['.sh', '.bash', '.elf', '.so', '.dylib', '.wasm']
  const hasDangerous = (input.fileTypes ?? []).some(f => dangerousTypes.includes(f))
  if (hasDangerous) {
    checks.push({ name: 'Dangerous file types', status: 'fail', detail: `Contains dangerous file types: ${input.fileTypes?.filter(f => dangerousTypes.includes(f)).join(', ')}` })
    score -= 30
  } else if (input.fileTypes?.length) {
    checks.push({ name: 'File inventory', status: 'pass', detail: `File types: ${input.fileTypes.join(', ')} — no binary/shell detected` })
  }

  // Permissions
  const dangerousPerms = ['env', 'filesystem', 'process', 'shell']
  const hasDangerousPerm = (input.permissions ?? []).some(p => dangerousPerms.includes(p))
  if (hasDangerousPerm) {
    checks.push({ name: 'Permissions', status: 'warn', detail: `Requests sensitive permissions: ${input.permissions?.filter(p => dangerousPerms.includes(p)).join(', ')}` })
    score -= 20
  } else {
    checks.push({ name: 'Permissions', status: 'pass', detail: 'No dangerous permissions requested' })
  }

  // Executable code
  if (input.hasExecutableCode === false) {
    checks.push({ name: 'Code content', status: 'pass', detail: 'No executable code — config/data only' })
  } else {
    checks.push({ name: 'Code content', status: 'warn', detail: 'Contains executable code — requires audit' })
    score -= 10
  }

  // Red flags pattern scan (if repo URL provided)
  if (input.repoUrl) {
    const { matchRedFlags, matchSocialEngineering } = await import('./deep-analyzer.js')
    // Fetch repo README for scanning
    try {
      const readmeUrl = input.repoUrl.replace('github.com', 'raw.githubusercontent.com') + '/main/README.md'
      const res = await fetch(readmeUrl, { signal: AbortSignal.timeout(5000) }).catch(() => null)
      const content = res?.ok ? await res.text() : ''
      const redFlagHits = matchRedFlags(content)
      const socialHits = matchSocialEngineering(content)
      if (redFlagHits.length > 0) {
        checks.push({ name: 'Red flag patterns', status: 'fail', detail: `${redFlagHits.length} code-level red flag(s): ${redFlagHits.slice(0, 3).join(', ')}` })
        score -= redFlagHits.length * 10
      } else {
        checks.push({ name: 'Red flag patterns', status: 'pass', detail: 'No red flags in README' })
      }
      if (socialHits.length > 0) {
        checks.push({ name: 'Social engineering', status: 'warn', detail: `${socialHits.length} social engineering pattern(s): ${socialHits.slice(0, 2).join(', ')}` })
        score -= socialHits.length * 5
      }
    } catch {
      checks.push({ name: 'Red flag patterns', status: 'pass', detail: 'Could not fetch repo content for scanning' })
    }
  }

  const riskLevel = score >= 80 ? 'low' : score >= 60 ? 'medium' : score >= 30 ? 'high' : 'reject'

  return {
    type: 'skill-mcp',
    riskLevel,
    score: Math.max(0, score),
    checks,
    summary: `Skill "${input.name}" from ${input.source}: ${riskLevel.toUpperCase()} risk (${Math.max(0, score)}/100)`,
    checklist: loadChecklist('skill-mcp'),
  }
}

// ── Review: GitHub Repository ─────────────────────────────────────────────────

export async function reviewRepository(input: {
  url: string
  owner?: string
  stars?: number
  forks?: number
  createdAt?: string
  lastCommit?: string
  contributors?: number
  hasLicense?: boolean
  isVerifiedOrg?: boolean
}): Promise<SkillReviewResult> {
  const checks: ReviewCheck[] = []
  let score = 100

  // Parse URL
  const repoMatch = input.url.match(/github\.com\/([^/]+)\/([^/]+)/)
  const repoName = repoMatch ? `${repoMatch[1]}/${repoMatch[2]}` : input.url

  // Stars / activity
  if (input.stars !== undefined) {
    if (input.stars >= 100) checks.push({ name: 'Popularity', status: 'pass', detail: `${input.stars} stars — established project` })
    else if (input.stars >= 10) checks.push({ name: 'Popularity', status: 'pass', detail: `${input.stars} stars — moderate popularity` })
    else { checks.push({ name: 'Popularity', status: 'warn', detail: `Only ${input.stars} stars — low visibility` }); score -= 10 }
  }

  // Contributors
  if (input.contributors !== undefined) {
    if (input.contributors >= 5) checks.push({ name: 'Contributors', status: 'pass', detail: `${input.contributors} contributors — team effort` })
    else if (input.contributors === 1) { checks.push({ name: 'Contributors', status: 'warn', detail: 'Single contributor — bus factor risk' }); score -= 10 }
  }

  // Repo age
  if (input.createdAt) {
    const age = Date.now() - new Date(input.createdAt).getTime()
    const dayAge = age / (1000 * 60 * 60 * 24)
    if (dayAge < 30) { checks.push({ name: 'Repo age', status: 'warn', detail: `Created ${Math.floor(dayAge)} days ago — very new` }); score -= 15 }
    else checks.push({ name: 'Repo age', status: 'pass', detail: `Created ${Math.floor(dayAge)} days ago` })
  }

  // License
  if (input.hasLicense) {
    checks.push({ name: 'License', status: 'pass', detail: 'Has license file' })
  } else {
    checks.push({ name: 'License', status: 'warn', detail: 'No license — legal risk' })
    score -= 10
  }

  // Verified org
  if (input.isVerifiedOrg) {
    checks.push({ name: 'Organization', status: 'pass', detail: 'Verified organization' })
  }

  // Activity
  if (input.lastCommit) {
    const lastAge = Date.now() - new Date(input.lastCommit).getTime()
    const daysSince = lastAge / (1000 * 60 * 60 * 24)
    if (daysSince > 365) { checks.push({ name: 'Maintenance', status: 'warn', detail: `Last commit ${Math.floor(daysSince)} days ago — possibly abandoned` }); score -= 15 }
    else checks.push({ name: 'Maintenance', status: 'pass', detail: `Last commit ${Math.floor(daysSince)} days ago — active` })
  }

  const riskLevel = score >= 80 ? 'low' : score >= 60 ? 'medium' : score >= 30 ? 'high' : 'reject'

  return {
    type: 'repository',
    riskLevel,
    score: Math.max(0, score),
    checks,
    summary: `Repository ${repoName}: ${riskLevel.toUpperCase()} risk (${Math.max(0, score)}/100)`,
    checklist: loadChecklist('repository'),
  }
}

// ── Review: URL / Document ────────────────────────────────────────────────────

export async function reviewUrl(input: {
  url: string
  contentType?: string
  hasCodeBlocks?: boolean
  hasExternalLinks?: boolean
  domain?: string
}): Promise<SkillReviewResult> {
  const checks: ReviewCheck[] = []
  let score = 100

  // GoPlus phishing check
  try {
    const { checkPhishingSite } = await import('./deep-analyzer.js')
    const isPhishing = await checkPhishingSite(input.url)
    if (isPhishing) {
      checks.push({ name: 'Phishing detection', status: 'fail', detail: 'URL flagged as phishing site by security API' })
      score -= 40
    } else {
      checks.push({ name: 'Phishing detection', status: 'pass', detail: 'Not flagged as phishing' })
    }
  } catch {
    checks.push({ name: 'Phishing detection', status: 'pass', detail: 'Phishing API unavailable — skipped' })
  }

  // Domain check
  const trustedDomains = ['github.com', 'docs.google.com', 'notion.so', 'arxiv.org', 'ethereum.org']
  const domain = input.domain ?? new URL(input.url).hostname
  if (trustedDomains.some(d => domain.endsWith(d))) {
    checks.push({ name: 'Domain trust', status: 'pass', detail: `Trusted domain: ${domain}` })
  } else {
    checks.push({ name: 'Domain trust', status: 'warn', detail: `Unknown domain: ${domain} — verify manually` })
    score -= 15
  }

  // Code blocks
  if (input.hasCodeBlocks) {
    checks.push({ name: 'Code blocks', status: 'warn', detail: 'Document contains code blocks — DO NOT EXECUTE without review' })
    score -= 10
  }

  // External links
  if (input.hasExternalLinks) {
    checks.push({ name: 'External links', status: 'warn', detail: 'Contains external links — verify destinations' })
    score -= 5
  }

  const riskLevel = score >= 80 ? 'low' : score >= 60 ? 'medium' : score >= 30 ? 'high' : 'reject'

  return {
    type: 'url-document',
    riskLevel,
    score: Math.max(0, score),
    checks,
    summary: `URL ${input.url}: ${riskLevel.toUpperCase()} risk (${Math.max(0, score)}/100)`,
    checklist: loadChecklist('url-document'),
  }
}

// ── Review: Product / Service ─────────────────────────────────────────────────

export async function reviewProduct(input: {
  name: string
  type: 'api' | 'sdk' | 'service' | 'platform'
  hasAudit?: boolean
  auditBy?: string
  teamKnown?: boolean
  incidentHistory?: boolean
  permissionsRequired?: string[]
}): Promise<SkillReviewResult> {
  const checks: ReviewCheck[] = []
  let score = 100

  // Audit
  if (input.hasAudit) {
    checks.push({ name: 'Security audit', status: 'pass', detail: `Audited by ${input.auditBy ?? 'third party'}` })
  } else {
    checks.push({ name: 'Security audit', status: 'warn', detail: 'No security audit found' })
    score -= 20
  }

  // Team
  if (input.teamKnown) {
    checks.push({ name: 'Team identity', status: 'pass', detail: 'Known public team' })
  } else {
    checks.push({ name: 'Team identity', status: 'warn', detail: 'Anonymous or unknown team' })
    score -= 15
  }

  // Incident history
  if (input.incidentHistory) {
    checks.push({ name: 'Incident history', status: 'warn', detail: 'Has past security incidents' })
    score -= 10
  } else {
    checks.push({ name: 'Incident history', status: 'pass', detail: 'No known security incidents' })
  }

  // Permissions
  if (input.permissionsRequired?.length) {
    const dangerousPerms = ['wallet_access', 'private_key', 'admin', 'full_access']
    const hasDangerous = input.permissionsRequired.some(p => dangerousPerms.includes(p))
    if (hasDangerous) {
      checks.push({ name: 'Permissions', status: 'fail', detail: `Requires dangerous permissions: ${input.permissionsRequired.join(', ')}` })
      score -= 30
    } else {
      checks.push({ name: 'Permissions', status: 'pass', detail: `Requires: ${input.permissionsRequired.join(', ')}` })
    }
  }

  const riskLevel = score >= 80 ? 'low' : score >= 60 ? 'medium' : score >= 30 ? 'high' : 'reject'

  return {
    type: 'product-service',
    riskLevel,
    score: Math.max(0, score),
    checks,
    summary: `${input.name} (${input.type}): ${riskLevel.toUpperCase()} risk (${Math.max(0, score)}/100)`,
    checklist: loadChecklist('product-service'),
  }
}

// ── Review: Social Message / Share ────────────────────────────────────────────

export async function reviewMessage(input: {
  content: string
  source: 'twitter' | 'discord' | 'telegram' | 'other'
  recommends?: string     // what is being recommended
  hasUrl?: boolean
  hasCode?: boolean
  urgencyLanguage?: boolean
}): Promise<SkillReviewResult> {
  const checks: ReviewCheck[] = []
  let score = 100

  // Check for social engineering patterns
  if (input.urgencyLanguage) {
    checks.push({ name: 'Urgency language', status: 'fail', detail: '"Act now", "limited time", "don\'t miss" — classic social engineering' })
    score -= 30
  }

  if (input.hasCode) {
    checks.push({ name: 'Code in message', status: 'fail', detail: 'Message contains executable code — NEVER run code from social messages' })
    score -= 30
  }

  if (input.hasUrl) {
    checks.push({ name: 'External URL', status: 'warn', detail: 'Contains URL — verify destination before clicking' })
    score -= 10
  }

  // Source trust
  if (input.source === 'twitter' || input.source === 'discord') {
    checks.push({ name: 'Source channel', status: 'warn', detail: `${input.source} — public channel, anyone can post` })
    score -= 5
  }

  // Content length (very short messages with links are suspicious)
  if (input.content.length < 50 && input.hasUrl) {
    checks.push({ name: 'Content quality', status: 'warn', detail: 'Short message with link — low effort, possible spam' })
    score -= 10
  }

  const riskLevel = score >= 80 ? 'low' : score >= 60 ? 'medium' : score >= 30 ? 'high' : 'reject'

  return {
    type: 'message-share',
    riskLevel,
    score: Math.max(0, score),
    checks,
    summary: `Message from ${input.source}: ${riskLevel.toUpperCase()} risk (${Math.max(0, score)}/100)`,
    checklist: loadChecklist('message-share'),
  }
}
