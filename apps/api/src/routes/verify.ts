/**
 * Verification Oracle Routes
 *
 * POST /v1/verify/:chain/:agentId  — run verification, return signed report
 * GET  /v1/verify/:chain/:agentId  — get cached verification (if exists)
 * GET  /v1/verify/certificate/:hash — lookup verification by report hash
 *
 * Intercept as verification-as-a-service for the agent economy.
 */

import type { FastifyInstance } from 'fastify'
import { db } from '../db/index.js'
import { sql } from 'drizzle-orm'
import { verifyAgent, type VerificationReport } from '../services/verification-oracle.js'
import { enrichAgent, getAgentTransactions, SUPPORTED_CHAINS } from '../services/erc8004.js'
import { getSolanaAgentDetail, getSolanaWalletTransactions } from '../services/solana-agent-registry.js'

export async function verifyRoutes(app: FastifyInstance) {

  // Ensure DB table exists
  await db.execute(sql.raw(`
    CREATE TABLE IF NOT EXISTS verification_reports (
      id SERIAL PRIMARY KEY,
      agent_id TEXT NOT NULL,
      chain TEXT NOT NULL,
      security_score INTEGER NOT NULL,
      grade TEXT NOT NULL,
      verdict TEXT NOT NULL,
      risk_level TEXT NOT NULL,
      report_hash TEXT NOT NULL UNIQUE,
      verifier TEXT NOT NULL,
      signature TEXT NOT NULL,
      on_chain_tx TEXT,
      on_chain_status TEXT DEFAULT 'skipped',
      dimensions JSONB,
      critical_issues INTEGER DEFAULT 0,
      warnings INTEGER DEFAULT 0,
      checks_run INTEGER DEFAULT 0,
      checks_passed INTEGER DEFAULT 0,
      verdict_reason TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_verify_agent ON verification_reports(chain, agent_id);
    CREATE INDEX IF NOT EXISTS idx_verify_hash ON verification_reports(report_hash);
  `)).catch(() => {}) // ignore if exists

  // POST /v1/verify/:chain/:agentId — run verification
  app.post<{
    Params: { chain: string; agentId: string }
    Querystring: { writeOnChain?: string }
  }>('/v1/verify/:chain/:agentId', async (request, reply) => {
    const { chain, agentId } = request.params
    const writeOnChain = request.query.writeOnChain === 'true'

    app.log.info(`[verify] Starting verification for agent ${agentId} on ${chain}`)

    // Fetch agent data
    let walletAddress: string | null = null
    let transactions: any[] = []

    if (chain === 'solana') {
      const detail = await getSolanaAgentDetail(agentId).catch(() => null)
      if (!detail) return reply.status(404).send({ error: 'Agent not found on Solana' })
      walletAddress = detail.wallet
      if (walletAddress) {
        try {
          const solTxs = await getSolanaWalletTransactions(walletAddress, 20)
          transactions = solTxs.map((t: any) => ({
            hash: t.hash, from: walletAddress, to: '', value: 0n,
            blockNumber: BigInt(t.slot ?? 0), timestamp: t.blockTime,
            chain: 'solana', methodName: t.memo ? 'memo' : 'transaction',
            isError: t.isError, tokenName: 'SOL', txType: 'normal',
          }))
        } catch {}
      }
    } else {
      if (!SUPPORTED_CHAINS[chain]) return reply.status(400).send({ error: `Unsupported chain: ${chain}` })
      const metadata = await enrichAgent(chain, BigInt(agentId))
      walletAddress = metadata.wallet ?? null
      if (walletAddress) {
        transactions = await getAgentTransactions(chain, walletAddress, 30)
      }
    }

    // Run verification
    const report = await verifyAgent(agentId, chain, walletAddress, transactions, writeOnChain)

    // Save to DB
    await db.execute(sql.raw(`
      INSERT INTO verification_reports (agent_id, chain, security_score, grade, verdict, risk_level, report_hash, verifier, signature, on_chain_tx, on_chain_status, dimensions, critical_issues, warnings, checks_run, checks_passed, verdict_reason)
      VALUES ('${agentId}', '${chain}', ${report.securityScore}, '${report.grade}', '${report.verdict}', '${report.riskLevel}', '${report.reportHash}', '${report.verifier}', '${report.signature}', ${report.onChainTxHash ? `'${report.onChainTxHash}'` : 'NULL'}, '${report.onChainStatus}', '${JSON.stringify(report.dimensions)}', ${report.criticalIssues}, ${report.warnings}, ${report.checksRun}, ${report.checksPassed}, '${(report.verdictReason ?? '').replace(/'/g, "''")}')
      ON CONFLICT (report_hash) DO NOTHING
    `)).catch((err) => app.log.error(`[verify] DB save failed: ${err}`))

    app.log.info(`[verify] Agent ${agentId} on ${chain}: score=${report.securityScore} grade=${report.grade} verdict=${report.verdict}`)

    return reply.send({
      verification: {
        agentId: report.agentId,
        chain: report.chain,
        walletAddress: report.walletAddress,
        securityScore: report.securityScore,
        grade: report.grade,
        verdict: report.verdict,
        riskLevel: report.riskLevel,
        dimensions: report.dimensions,
        criticalIssues: report.criticalIssues,
        warnings: report.warnings,
        checksRun: report.checksRun,
        checksPassed: report.checksPassed,
      },
      proof: {
        reportHash: report.reportHash,
        timestamp: report.timestamp,
        verifier: report.verifier,
        signature: report.signature,
      },
      onChain: {
        txHash: report.onChainTxHash,
        status: report.onChainStatus,
        registry: '0x8004BAa17C55a88189AE136b182e5fdA19dE9b63',
      },
      checklist: report.checklist,
      alerts: report.alerts,
      verdictReason: report.verdictReason,
    })
  })

  // GET /v1/verify/:chain/:agentId — get latest verification
  app.get<{ Params: { chain: string; agentId: string } }>(
    '/v1/verify/:chain/:agentId',
    async (request, reply) => {
      const { chain, agentId } = request.params
      const result = await db.execute(sql.raw(
        `SELECT * FROM verification_reports WHERE chain = '${chain}' AND agent_id = '${agentId}' ORDER BY created_at DESC LIMIT 1`
      ))
      const row = (result as any[])[0]
      if (!row) return reply.status(404).send({ error: 'No verification found. POST to run verification.' })

      return reply.send({
        verification: {
          agentId: row.agent_id,
          chain: row.chain,
          securityScore: row.security_score,
          grade: row.grade,
          verdict: row.verdict,
          riskLevel: row.risk_level,
          dimensions: row.dimensions,
          criticalIssues: row.critical_issues,
          warnings: row.warnings,
          checksRun: row.checks_run,
          checksPassed: row.checks_passed,
        },
        proof: {
          reportHash: row.report_hash,
          timestamp: new Date(row.created_at).getTime(),
          verifier: row.verifier,
          signature: row.signature,
        },
        onChain: {
          txHash: row.on_chain_tx,
          status: row.on_chain_status,
        },
        verdictReason: row.verdict_reason,
        createdAt: row.created_at,
      })
    },
  )

  // GET /v1/verify/certificate/:hash — lookup by report hash
  app.get<{ Params: { hash: string } }>(
    '/v1/verify/certificate/:hash',
    async (request, reply) => {
      const { hash } = request.params
      const result = await db.execute(sql.raw(
        `SELECT * FROM verification_reports WHERE report_hash = '${hash}' LIMIT 1`
      ))
      const row = (result as any[])[0]
      if (!row) return reply.status(404).send({ error: 'Certificate not found' })

      return reply.send({
        valid: true,
        verification: {
          agentId: row.agent_id,
          chain: row.chain,
          securityScore: row.security_score,
          grade: row.grade,
          verdict: row.verdict,
          riskLevel: row.risk_level,
          dimensions: row.dimensions,
        },
        proof: {
          reportHash: row.report_hash,
          verifier: row.verifier,
          signature: row.signature,
          timestamp: new Date(row.created_at).getTime(),
        },
        onChain: {
          txHash: row.on_chain_tx,
          status: row.on_chain_status,
        },
      })
    },
  )

  // GET /v1/verify/stats — verification stats
  app.get('/v1/verify/stats', async (_request, reply) => {
    const result = await db.execute(sql.raw(`
      SELECT
        COUNT(*) as total,
        COUNT(DISTINCT agent_id || '-' || chain) as unique_agents,
        AVG(security_score) as avg_score,
        COUNT(CASE WHEN verdict = 'safe' THEN 1 END) as safe_count,
        COUNT(CASE WHEN verdict = 'caution' THEN 1 END) as caution_count,
        COUNT(CASE WHEN verdict = 'reject' THEN 1 END) as reject_count,
        COUNT(CASE WHEN on_chain_status = 'submitted' THEN 1 END) as on_chain_count
      FROM verification_reports
    `))
    const row = (result as any[])[0] ?? {}

    return reply.send({
      totalVerifications: Number(row.total ?? 0),
      uniqueAgents: Number(row.unique_agents ?? 0),
      averageScore: Math.round(Number(row.avg_score ?? 0)),
      verdicts: {
        safe: Number(row.safe_count ?? 0),
        caution: Number(row.caution_count ?? 0),
        reject: Number(row.reject_count ?? 0),
      },
      onChainWritten: Number(row.on_chain_count ?? 0),
    })
  })
}
