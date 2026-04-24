/**
 * Notification Service
 *
 * Sends human-approval requests via Telegram, Email, or Slack.
 * Each channel is optional — configured via environment variables.
 */

import TelegramBot from 'node-telegram-bot-api'
import { Resend } from 'resend'
import type { NormalizedTransaction } from '../types/index.js'

export interface ApprovalNotificationPayload {
  requestId: string
  agentName: string
  tx: NormalizedTransaction
  reason: string
  approvalUrl: string
  expiresAt: Date
}

// ── Telegram ──────────────────────────────────────────────────────────────────

let telegramBot: TelegramBot | null = null

function getTelegramBot(): TelegramBot | null {
  if (!process.env.TELEGRAM_BOT_TOKEN) return null
  if (!telegramBot) telegramBot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN)
  return telegramBot
}

async function sendTelegram(chatId: string, payload: ApprovalNotificationPayload): Promise<void> {
  const bot = getTelegramBot()
  if (!bot) return

  const { requestId, agentName, tx, reason, approvalUrl, expiresAt } = payload
  const amount = tx.amountUsdc.toFixed(2)
  const token = tx.token
  const merchant = tx.metadata.merchant ?? tx.toAddress.slice(0, 12) + '...'
  const chain = tx.chain.toUpperCase()
  const expiresIn = Math.round((expiresAt.getTime() - Date.now()) / 60000)

  const message = [
    `🔔 *Agent Spending Request*`,
    ``,
    `*Agent:* ${agentName}`,
    `*Action:* Send \`${amount} ${token}\` (${chain})`,
    `*To:* \`${merchant}\``,
    `*Reason flagged:* ${reason}`,
    ``,
    `Expires in ${expiresIn} min`,
  ].join('\n')

  await bot.sendMessage(chatId, message, {
    parse_mode: 'Markdown',
    reply_markup: {
      inline_keyboard: [
        [
          { text: '✅ Allow', callback_data: `approve:${requestId}` },
          { text: '❌ Deny', callback_data: `deny:${requestId}` },
        ],
        [{ text: '🔗 View Details', url: approvalUrl }],
      ],
    },
  })
}

// ── Email ─────────────────────────────────────────────────────────────────────

let resendClient: Resend | null = null

function getResend(): Resend | null {
  if (!process.env.RESEND_API_KEY) return null
  if (!resendClient) resendClient = new Resend(process.env.RESEND_API_KEY)
  return resendClient
}

async function sendEmail(email: string, payload: ApprovalNotificationPayload): Promise<void> {
  const resend = getResend()
  if (!resend) return

  const { requestId, agentName, tx, reason, approvalUrl, expiresAt } = payload
  const amount = tx.amountUsdc.toFixed(2)
  const merchant = tx.metadata.merchant ?? tx.toAddress

  await resend.emails.send({
    from: process.env.RESEND_FROM_EMAIL ?? 'noreply@agentguard.io',
    to: email,
    subject: `[Intercept] ${agentName} wants to spend $${amount} ${tx.token}`,
    html: `
      <h2>Agent Spending Request</h2>
      <table>
        <tr><td><strong>Agent</strong></td><td>${agentName}</td></tr>
        <tr><td><strong>Amount</strong></td><td>${amount} ${tx.token}</td></tr>
        <tr><td><strong>Merchant</strong></td><td>${merchant}</td></tr>
        <tr><td><strong>Reason flagged</strong></td><td>${reason}</td></tr>
        <tr><td><strong>Expires</strong></td><td>${expiresAt.toISOString()}</td></tr>
      </table>
      <br/>
      <a href="${approvalUrl}?action=approve&id=${requestId}"
         style="background:#16a34a;color:white;padding:12px 24px;text-decoration:none;border-radius:6px;margin-right:8px">
        ✅ Allow
      </a>
      <a href="${approvalUrl}?action=deny&id=${requestId}"
         style="background:#dc2626;color:white;padding:12px 24px;text-decoration:none;border-radius:6px">
        ❌ Deny
      </a>
      <br/><br/>
      <small>Request ID: ${requestId}</small>
    `,
  })
}

// ── Slack ─────────────────────────────────────────────────────────────────────

async function sendSlack(webhookUrl: string, payload: ApprovalNotificationPayload): Promise<void> {
  const { agentName, tx, reason, approvalUrl, requestId } = payload
  const amount = tx.amountUsdc.toFixed(2)
  const merchant = tx.metadata.merchant ?? tx.toAddress

  const body = {
    text: `Intercept: ${agentName} wants to spend ${amount} ${tx.token}`,
    blocks: [
      {
        type: 'header',
        text: { type: 'plain_text', text: '🔔 Agent Spending Request' },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Agent:*\n${agentName}` },
          { type: 'mrkdwn', text: `*Amount:*\n${amount} ${tx.token}` },
          { type: 'mrkdwn', text: `*Merchant:*\n${merchant}` },
          { type: 'mrkdwn', text: `*Flagged:*\n${reason}` },
        ],
      },
      {
        type: 'actions',
        elements: [
          {
            type: 'button',
            text: { type: 'plain_text', text: '✅ Allow' },
            style: 'primary',
            url: `${approvalUrl}?action=approve&id=${requestId}`,
          },
          {
            type: 'button',
            text: { type: 'plain_text', text: '❌ Deny' },
            style: 'danger',
            url: `${approvalUrl}?action=deny&id=${requestId}`,
          },
        ],
      },
    ],
  }

  await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

// ── Public API ────────────────────────────────────────────────────────────────

export interface NotifyConfig {
  telegramChatId?: string | null
  email?: string | null
  slackWebhookUrl?: string | null
}

export async function sendApprovalRequest(
  config: NotifyConfig,
  payload: ApprovalNotificationPayload,
): Promise<void> {
  const promises: Promise<void>[] = []

  if (config.telegramChatId) {
    promises.push(sendTelegram(config.telegramChatId, payload))
  }
  if (config.email) {
    promises.push(sendEmail(config.email, payload))
  }
  if (config.slackWebhookUrl) {
    promises.push(sendSlack(config.slackWebhookUrl, payload))
  }

  await Promise.allSettled(promises) // don't fail if one channel errors
}
