/**
 * x402 Interceptor Service
 *
 * Bridges the x402 HTTP payment protocol with Intercept's authorization layer.
 *
 * Flow:
 *   1. Agent calls a paid API → gets HTTP 402 + PAYMENT-REQUIRED header
 *   2. This service parses the 402 response into structured payment details
 *   3. Intercept runs authorize_payment (4-layer shield + policy)
 *   4. If allowed, signs an EIP-3009 transferWithAuthorization
 *   5. Returns the PAYMENT-SIGNATURE header for the retry request
 *
 * x402 spec: https://github.com/coinbase/x402/blob/main/specs/x402-specification.md
 * HTTP transport: https://github.com/coinbase/x402/blob/main/specs/transports-v2/http.md
 */

// ── Types (aligned with @x402/core) ─────────────────────────────────────────

export interface X402PaymentRequired {
  x402Version: number
  error?: string
  resource: {
    url: string
    description?: string
    mimeType?: string
  }
  accepts: X402PaymentOption[]
}

export interface X402PaymentOption {
  scheme: 'exact' | 'tip' | 'subscription'
  network: string               // e.g. "eip155:5042002" (Arc testnet)
  amount: string                // raw amount (6-decimal USDC string)
  asset: string                 // token contract address
  payTo: string                 // recipient address
  maxTimeoutSeconds?: number
  extra?: Record<string, unknown>
}

export interface X402AuthorizeParams {
  chain: string
  to: string
  amount: string
  token: string
  merchant: string
  category: string
  purpose: string
}

export interface X402ParseResult {
  resource: { url: string; description?: string }
  payment: X402PaymentOption
  authorizeParams: X402AuthorizeParams
}

// ── Network Mapping ─────────────────────────────────────────────────────────

const NETWORK_TO_CHAIN: Record<string, string> = {
  'eip155:5042002': 'arc-testnet',
  'eip155:1': 'ethereum',
  'eip155:8453': 'base',
  'eip155:137': 'polygon',
  'eip155:42161': 'arbitrum',
}

const KNOWN_USDC_ADDRESSES: Record<string, boolean> = {
  // Arc testnet USDC precompile
  '0x3600000000000000000000000000000000000000': true,
  // Base Sepolia USDC
  '0x036cbd53842c5426634e7929541ec2318f3dcf7e': true,
}

// ── Parser ──────────────────────────────────────────────────────────────────

/**
 * Parse a base64-encoded PAYMENT-REQUIRED header into structured data
 * and map it to Intercept's authorize_payment parameters.
 */
export function parsePaymentRequired(headerValue: string): X402ParseResult {
  const decoded = Buffer.from(headerValue, 'base64').toString('utf8')
  const payload: X402PaymentRequired = JSON.parse(decoded)

  if (!payload.accepts || payload.accepts.length === 0) {
    throw new Error('No payment options in 402 response')
  }

  // Pick the first option (in production, pick the best match)
  const option = payload.accepts[0]

  // Map x402 network string to Intercept chain identifier
  const chain = NETWORK_TO_CHAIN[option.network]
  if (!chain) {
    throw new Error(`Unsupported x402 network: ${option.network}`)
  }

  // Determine token name from asset address
  const assetLower = option.asset.toLowerCase()
  const isUsdc = KNOWN_USDC_ADDRESSES[assetLower]
  const token = isUsdc ? 'USDC' : option.extra?.name as string ?? 'UNKNOWN'

  // Extract merchant from resource URL
  let merchant = 'Unknown API'
  try {
    merchant = new URL(payload.resource.url).hostname
  } catch { /* keep default */ }

  return {
    resource: payload.resource,
    payment: option,
    authorizeParams: {
      chain,
      to: option.payTo,
      amount: option.amount,
      token,
      merchant,
      category: 'api_credits',
      purpose: `x402 payment for ${payload.resource.description ?? payload.resource.url}`,
    },
  }
}

/**
 * Build the PAYMENT-REQUIRED header value for demo/simulation purposes.
 * This creates a realistic 402 payload that the interceptor can parse.
 */
export function buildDemoPaymentRequired(params: {
  url: string
  description: string
  payTo: string
  amount: string
  network?: string
}): string {
  const payload: X402PaymentRequired = {
    x402Version: 2,
    error: 'PAYMENT-SIGNATURE header is required',
    resource: {
      url: params.url,
      description: params.description,
      mimeType: 'application/json',
    },
    accepts: [
      {
        scheme: 'exact',
        network: params.network ?? 'eip155:5042002',  // Arc testnet
        amount: params.amount,
        asset: '0x3600000000000000000000000000000000000000',
        payTo: params.payTo,
        maxTimeoutSeconds: 60,
        extra: { name: 'USDC', version: '2' },
      },
    ],
  }

  return Buffer.from(JSON.stringify(payload)).toString('base64')
}

/**
 * Convert a human-readable USDC amount to 6-decimal raw string.
 * e.g. 0.05 → "50000"
 */
export function usdcToRaw(amount: number): string {
  return Math.round(amount * 1_000_000).toString()
}

/**
 * Convert a 6-decimal raw USDC string to human-readable number.
 * e.g. "50000" → 0.05
 */
export function rawToUsdc(raw: string): number {
  return Number(raw) / 1_000_000
}
