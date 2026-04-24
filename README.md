# Intercept

The security middleware for x402 agentic payments. Returns `allow / deny / ask_user` before any on-chain transaction executes.

## Project Structure

```
intercept/
├── apps/
│   ├── api/          # Fastify backend API
│   └── web/          # Next.js frontend Dashboard
├── packages/
│   ├── mcp/          # MCP server integration
│   ├── sdk/          # @agent-guard/sdk client
│   ├── security-skill/ # Claude Code security skill
│   └── solana/       # Anchor on-chain program (policy registry)
```

## Getting Started

### 1. Environment Variables

```bash
cp apps/api/.env.example apps/api/.env
# Fill in DATABASE_URL, ANTHROPIC_API_KEY, TELEGRAM_BOT_TOKEN, etc.
```

### 2. Database

```bash
# Start local PostgreSQL
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=password -e POSTGRES_DB=agent_guard postgres:16

# Run migrations
cd apps/api && npm run db:migrate
```

### 3. Start Development Servers

```bash
# API (port 8080)
npm run dev:api

# Web (port 3000)
npm run dev:web
```

## API Reference

### Core: Authorize Transaction

```bash
POST /v1/authorize
{
  "agentId": "uuid",
  "chain": "solana",
  "transaction": {
    "to": "RecipientAddress",
    "amount": "5000000",   # 5 USDC (6 decimals)
    "token": "USDC",
    "metadata": {
      "merchant": "OpenAI",
      "category": "api_credits"
    }
  }
}

# Response
{ "decision": "allow" | "deny" | "ask_user", "requestId": "req_xxx", "reason": "..." }
```

### Natural Language Policy Configuration

```bash
POST /v1/policies/parse
{ "text": "Auto-approve under $5, ask me for new merchants, max $100 per month" }
```

### Human Approval

```bash
POST /v1/requests/:id/resolve
{ "action": "approve" | "deny" }
```

## SDK Usage

```typescript
import { AgentGuard } from '@agent-guard/sdk'

const guard = new AgentGuard({ agentId: '...', apiKey: '...' })

// Call before any transaction
const result = await guard.authorize({
  chain: 'solana',
  to: 'RecipientPublicKey',
  amount: '5000000',
  token: 'USDC',
  metadata: { merchant: 'OpenAI', category: 'api_credits' }
})

if (result.decision === 'allow') {
  // Execute Solana transaction
}
if (result.decision === 'ask_user') {
  // Wait for user approval via Telegram/Email
  const final = await guard.waitForApproval(result.requestId)
}
```

## Supported Chains

| Chain | Status |
|---|---|
| Solana (mainnet/devnet) | Full support |
| Ethereum | EVM interface |
| Base | EVM interface |
| Polygon | EVM interface |
| Arbitrum | EVM interface |
| Arc Testnet | Testnet support |
