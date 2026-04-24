import 'dotenv/config'
import Fastify from 'fastify'
import cors from '@fastify/cors'
import rateLimit from '@fastify/rate-limit'

import { authorizeRoutes } from './routes/authorize.js'
import { policyRoutes } from './routes/policies.js'
import { agentRoutes } from './routes/agents.js'
import { sessionRoutes } from './routes/sessions.js'
import { suggestRoutes } from './routes/suggest.js'
import { securityRoutes } from './routes/security.js'
import { x402Routes } from './routes/x402.js'
import { monitorRoutes } from './routes/monitor.js'
import { verifyRoutes } from './routes/verify.js'
import { reviewRoutes } from './routes/review.js'
import { capabilityRoutes } from './routes/capabilities.js'
import { startAutoAnalyzer, getAutoAnalyzerStats, enrichMissingWallets } from './services/auto-analyzer.js'
import { startCapabilityIndexer } from './services/capability-indexer.js'
// import { runMarketplaceScan, getMarketplaceStats } from './services/marketplace-scanner.js'
import { startTelegramBot } from './services/telegram-bot.js'

const app = Fastify({
  logger: {
    level: process.env.LOG_LEVEL ?? 'info',
    transport:
      process.env.NODE_ENV !== 'production'
        ? { target: 'pino-pretty', options: { colorize: true } }
        : undefined,
  },
})

// ── Plugins ───────────────────────────────────────────────────────────────────

await app.register(cors, {
  origin: process.env.CORS_ORIGIN ?? '*',
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  exposedHeaders: ['PAYMENT-REQUIRED', 'payment-required'],
})

await app.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute',
})

// ── Health ────────────────────────────────────────────────────────────────────

app.get('/health', async () => ({ status: 'ok', timestamp: new Date().toISOString() }))

app.get('/v1/auto-analyzer/status', async () => getAutoAnalyzerStats())

// ── Routes ────────────────────────────────────────────────────────────────────

await app.register(authorizeRoutes)
await app.register(policyRoutes)
await app.register(agentRoutes)
await app.register(sessionRoutes)
await app.register(suggestRoutes)
await app.register(securityRoutes)
await app.register(x402Routes)
await app.register(monitorRoutes)
await app.register(verifyRoutes)
await app.register(reviewRoutes)
await app.register(capabilityRoutes)


// ── Start ─────────────────────────────────────────────────────────────────────

const port = Number(process.env.PORT ?? 8080)
const host = process.env.HOST ?? '0.0.0.0'

try {
  await app.listen({ port, host })
  app.log.info(`Intercept API running at http://${host}:${port}`)

  // Start Telegram bot (non-blocking, only if token is set)
  startTelegramBot()

  // Start auto-analyzer background task
  startAutoAnalyzer()

  // Enrich missing wallets on startup
  enrichMissingWallets(20).catch(() => {})

  // Start capability indexer
  startCapabilityIndexer()

} catch (err) {
  app.log.error(err)
  process.exit(1)
}
