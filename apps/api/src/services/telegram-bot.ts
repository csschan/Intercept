/**
 * Telegram Bot — Bidirectional Approval
 *
 * Listens for callback_query events from inline keyboard buttons
 * sent by the notify service. When a user taps Allow/Deny in Telegram,
 * this handler resolves the authorization request.
 *
 * Start: called from index.ts at boot time.
 */

import TelegramBot from 'node-telegram-bot-api'
import { eq } from 'drizzle-orm'
import { db, authRequests, auditLogs, agents, knownMerchants } from '../db/index.js'

let bot: TelegramBot | null = null

export function startTelegramBot() {
  const token = process.env.TELEGRAM_BOT_TOKEN
  if (!token) {
    console.log('[telegram] No TELEGRAM_BOT_TOKEN — skipping bot startup')
    return
  }

  bot = new TelegramBot(token, { polling: true })
  console.log('[telegram] Bot started with polling')

  bot.on('callback_query', async (query) => {
    const data = query.data
    if (!data) return

    // Format: "approve:req_xxxx" or "deny:req_xxxx"
    const [action, requestId] = data.split(':')
    if (!requestId || !['approve', 'deny'].includes(action)) {
      await bot!.answerCallbackQuery(query.id, { text: 'Invalid action' })
      return
    }

    try {
      // Load the request
      const req = await db.query.authRequests.findFirst({
        where: eq(authRequests.id, requestId),
      })

      if (!req) {
        await bot!.answerCallbackQuery(query.id, { text: '❌ Request not found' })
        return
      }

      // Already resolved?
      if (req.decision !== 'ask_user') {
        await bot!.answerCallbackQuery(query.id, {
          text: `Already resolved: ${req.decision.toUpperCase()}`,
        })
        // Update the message to show it's done
        if (query.message) {
          await bot!.editMessageText(
            `${query.message.text}\n\n✅ Already resolved: ${req.decision}`,
            { chat_id: query.message.chat.id, message_id: query.message.message_id },
          ).catch(() => {})
        }
        return
      }

      // Expired?
      if (req.expiresAt && new Date() > req.expiresAt) {
        await bot!.answerCallbackQuery(query.id, { text: '⏰ Request has expired' })
        return
      }

      // Resolve
      const newDecision = action === 'approve' ? 'allow' : 'deny'
      const now = new Date()

      await db
        .update(authRequests)
        .set({ decision: newDecision as any, resolvedBy: 'human', resolvedAt: now })
        .where(eq(authRequests.id, requestId))

      await db.insert(auditLogs).values({
        requestId,
        agentId: req.agentId,
        ownerId: req.ownerId,
        event: action === 'approve' ? 'human_approved' : 'human_denied',
        data: { action, source: 'telegram' },
      })

      // If approved, update budget + merchant
      if (action === 'approve' && req.amountUsdc) {
        const agent = await db.query.agents.findFirst({ where: eq(agents.id, req.agentId) })
        if (agent) {
          const amount = Number(req.amountUsdc)
          await db.update(agents).set({
            dailySpentUsdc: (Number(agent.dailySpentUsdc) + amount).toString(),
            monthlySpentUsdc: (Number(agent.monthlySpentUsdc) + amount).toString(),
          }).where(eq(agents.id, req.agentId))
        }

        const merchantId = (req.txMetadata as any)?.merchant ?? req.toAddress
        if (merchantId) {
          await db.insert(knownMerchants)
            .values({ agentId: req.agentId, identifier: merchantId })
            .catch(() => {})
        }
      }

      // Update Telegram message
      const emoji = action === 'approve' ? '✅' : '❌'
      const label = action === 'approve' ? 'APPROVED' : 'DENIED'
      await bot!.answerCallbackQuery(query.id, { text: `${emoji} ${label}` })

      if (query.message) {
        await bot!.editMessageText(
          `${query.message.text}\n\n${emoji} ${label} by you via Telegram`,
          {
            chat_id: query.message.chat.id,
            message_id: query.message.message_id,
            parse_mode: 'Markdown',
          },
        ).catch(() => {})
      }

      // Deliver webhook to agent
      const agent = await db.query.agents.findFirst({ where: eq(agents.id, req.agentId) })
      if (agent?.webhookUrl) {
        fetch(agent.webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            requestId, decision: newDecision, agentId: req.agentId,
            timestamp: now.toISOString(), source: 'telegram',
          }),
        }).catch(() => {})
      }

      console.log(`[telegram] ${requestId} → ${label} by chat ${query.message?.chat.id}`)
    } catch (err) {
      console.error('[telegram] callback_query error:', err)
      await bot!.answerCallbackQuery(query.id, { text: '❌ Internal error' }).catch(() => {})
    }
  })

  // Handle /start command — show chat ID for setup
  bot.onText(/\/start/, async (msg) => {
    await bot!.sendMessage(msg.chat.id, [
      '🛡️ *Intercept Bot*',
      '',
      'I will notify you when your AI agent needs spending approval.',
      '',
      `Your Chat ID: \`${msg.chat.id}\``,
      '',
      'Add this Chat ID to your Intercept owner profile to receive notifications.',
    ].join('\n'), { parse_mode: 'Markdown' })
  })
}

export function stopTelegramBot() {
  if (bot) {
    bot.stopPolling()
    bot = null
  }
}
