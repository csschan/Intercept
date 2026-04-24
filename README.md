# Agent Guard

AI Agent 的链上支出授权层。在任何交易执行前，返回 `allow / deny / ask_user`。

## 项目结构

```
agent-guard/
├── apps/
│   ├── api/          # Fastify 后端 API
│   └── web/          # Next.js 前端 Dashboard
├── packages/
│   ├── sdk/          # @agent-guard/sdk 客户端
│   └── solana/       # Anchor 链上程序 (on-chain policy registry)
```

## 快速开始

### 1. 环境变量

```bash
cp apps/api/.env.example apps/api/.env
# 填入 DATABASE_URL, ANTHROPIC_API_KEY, TELEGRAM_BOT_TOKEN 等
```

### 2. 数据库

```bash
# 启动本地 PostgreSQL
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=password -e POSTGRES_DB=agent_guard postgres:16

# 运行迁移
cd apps/api && npm run db:migrate
```

### 3. 启动开发服务器

```bash
# API (port 8080)
npm run dev:api

# Web (port 3000)
npm run dev:web
```

## API 快速参考

### 核心：授权交易

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

### 自然语言配置规则

```bash
POST /v1/policies/parse
{ "text": "低于5美元自动通过，新商家先问我，每月最多100美元" }
```

### 人工审批

```bash
POST /v1/requests/:id/resolve
{ "action": "approve" | "deny" }
```

## SDK 使用

```typescript
import { AgentGuard } from '@agent-guard/sdk'

const guard = new AgentGuard({ agentId: '...', apiKey: '...' })

// 在交易前调用
const result = await guard.authorize({
  chain: 'solana',
  to: 'RecipientPublicKey',
  amount: '5000000',
  token: 'USDC',
  metadata: { merchant: 'OpenAI', category: 'api_credits' }
})

if (result.decision === 'allow') {
  // 执行 Solana 交易
}
if (result.decision === 'ask_user') {
  // 等待用户在 Telegram/Email 审批
  const final = await guard.waitForApproval(result.requestId)
}
```

## 支持的链

| Chain | 状态 |
|---|---|
| Solana (mainnet/devnet) | ✅ 完整支持 |
| Ethereum | ✅ EVM 接口 |
| Base | ✅ EVM 接口 |
| Polygon | ✅ EVM 接口 |
| Arbitrum | ✅ EVM 接口 |
