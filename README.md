# Intercept

Real-time security layer for AI agent payments. Every time an agent attempts a transaction, Intercept intercepts the call, runs a 6-layer security scan, and returns `allow`, `deny`, or `ask_user` — before anything hits the chain.

## The Problem

AI agents are gaining the ability to move money autonomously. But the security tools that exist today were built for humans — popup confirmations, manual reviews, multisig approvals. None of that works when an agent is running unattended at 3am.

Intercept sits between the agent and the blockchain. One function call. No private keys. No custody. Just a security verdict on every payment.

## How It Works

```
Agent calls authorize_payment()
        │
        ▼
┌─────────────────────┐
│   6-Layer Security  │
│   Engine            │
│                     │
│   Rules · LLM ·    │
│   Address · Behavior│
│   Token · Phishing  │
└────────┬────────────┘
         │
    ┌────┼────┐
    ▼    ▼    ▼
  ALLOW DENY ASK_USER
```

The security engine runs prompt injection detection, LLM semantic analysis, address blacklist checks (GoPlus / Solscan), behavioral anomaly detection, token security analysis (Rugcheck for Solana, GoPlus for EVM), and phishing/social engineering pattern matching — all concurrently, in under 2 seconds.

## Project Structure

```
intercept/
├── apps/
│   ├── api/            # Fastify backend — security engine + REST API
│   └── web/            # Next.js dashboard — monitor, demo, config
├── packages/
│   ├── mcp/            # MCP server — exposes tools to AI agents
│   ├── sdk/            # @agent-guard/sdk — client library
│   ├── security-skill/ # SlowMist security checklist integration
│   └── solana/         # Anchor program — on-chain policy registry
```

## Quick Start

### Prerequisites

- Node.js 20+
- PostgreSQL 16+
- pnpm or npm

### Setup

```bash
# Install dependencies
npm install

# Configure environment
cp apps/api/.env.example apps/api/.env
# Set: DATABASE_URL, ANTHROPIC_API_KEY

# Run database migrations
cd apps/api
npx drizzle-kit migrate

# Start API server
npm run dev

# In another terminal — start frontend
cd apps/web
npm run dev
```

API runs on `http://localhost:8080`, frontend on `http://localhost:3000`.

## API

### Authorize a Payment

```bash
POST /v1/authorize
```

```json
{
  "agentId": "uuid",
  "chain": "solana",
  "transaction": {
    "to": "RecipientAddress",
    "amount": "5000000",
    "token": "USDC",
    "tokenAddress": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "metadata": {
      "merchant": "OpenAI",
      "category": "api_credits",
      "purpose": "Purchase API credits"
    }
  }
}
```

Response:

```json
{
  "decision": "allow",
  "requestId": "req_xxx",
  "reason": "Within policy limits",
  "securityChecks": {
    "injectionRisk": "none",
    "addressRisk": "safe",
    "tokenRisk": "safe",
    "anomalyRiskLevel": "normal",
    "overallRiskLevel": "none"
  }
}
```

### Policy Management

```bash
POST /v1/policies              # Create policy
GET  /v1/policies/:agentId     # Get agent policy
PATCH /v1/policies/:policyId   # Update policy
POST /v1/policies/parse        # Natural language → structured policy
```

### Human Approval

```bash
POST /v1/requests/:id/resolve
{ "action": "approve" | "deny" }
```

### Agent Monitor

```bash
GET /v1/monitor/agents         # List tracked agents across chains
GET /v1/monitor/agents/:chain/:id  # Agent detail + security analysis
GET /v1/monitor/stats          # Aggregate stats
```

## SDK

```typescript
import { AgentGuard } from '@agent-guard/sdk'

const guard = new AgentGuard({ agentId: '...', apiKey: '...' })

const result = await guard.authorize({
  chain: 'solana',
  to: 'RecipientPublicKey',
  amount: '5000000',
  token: 'USDC',
  metadata: { merchant: 'OpenAI' }
})

if (result.decision === 'allow') {
  // proceed with transaction
}
```

## Supported Chains

| Chain | Security Coverage |
|---|---|
| Solana | Address (Solscan) · Token (Rugcheck) · Full engine |
| Ethereum | Address + Contract + Token (GoPlus) · Full engine |
| BSC | Address + Contract + Token (GoPlus) · Full engine |
| Base | Address + Contract + Token (GoPlus) · Full engine |
| Arbitrum | Address + Contract + Token (GoPlus) · Full engine |

## Tech Stack

Fastify · Next.js · PostgreSQL · Drizzle ORM · Solana Web3.js · Rugcheck API · GoPlus API · Anthropic Claude · SlowMist Security Skill

## License

MIT
