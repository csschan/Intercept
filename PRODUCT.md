# Agent Guard — 产品文档

> 最后更新：2026-03-27

---

## 一、产品定位

**Agent Guard 是 AI Agent 的支出授权层（Layer 2）。**

在 AI Agent 执行任何链上或链下支付前，Agent Guard 拦截该请求，根据用户预设规则返回三种决策：

```
allow      → 自动通过，Agent 继续执行
deny       → 拒绝，记录原因
ask_user   → 暂停，通知用户，等待人工审批
```

---

## 二、核心价值主张

> "你的 AI Agent 能做事，但花钱之前必须经过你。"

**解决的真实痛点：**
- 用户被 Agent 3 天烧掉 $223（Privacy.com 真实案例）
- 用户单月被 Agent 自动消费 $3,600
- Agent 在循环 bug 中单日损失 $200
- 82% 企业有 Agent 在生产环境，只有 44% 有治理策略

---

## 三、竞品分析与市场定位

### Agent Payment 五层架构

```
Layer 0  协议标准      Stripe MPP / Visa TAP / Mastercard Agent Pay / Google AP2
Layer 1  钱包基础设施   Skyfire / Coinbase AgentKit / Crossmint / Natural.co
Layer 2  ★ 授权决策层  ← Agent Guard 在这里（目前无纯玩家）
Layer 3  卡片发行      Crossmint / AgentCard
Layer 4  支付轨道      Mastercard / Visa / ACH / Solana / x402
```

### 主要竞品逐一拆解

| 产品 | 真实层级 | 有 allow/deny/ask_user？ | 有自然语言规则？ | 致命弱点 |
|---|---|---|---|---|
| **Skyfire** | 钱包 + 身份 | 仅数字阈值报警 | 无 | Crypto-only，无法控制法币 API 支出 |
| **Crossmint** | 钱包 + 虚拟卡 | 有限，需预设参数 | 无 | 支付层产品，授权是附属功能 |
| **Coinbase AgentKit** | 钱包基础设施 | 仅消费上限 | 无 | 无 ask_user 机制，无人工审批工作流 |
| **AgentCard** | 卡片发行 | 全手动，无策略引擎 | 无 | 不可扩展，每张卡都要手动批 |
| **Mastercard Agent Pay** | 协议标准 | 只在 MC 网络内 | 无 | 需要卡网络合作才能接入 |
| **Stripe MPP** | 协议标准 | 完全没有 | 无 | 纯 enabler，设计上不做授权 |
| **xpay** | x402 代理 | 无 ask_user | YAML | 仅限 x402 API，不通用 |
| **Natural.co** | B2B 支付轨道 | 愿景中有，未上线 | 规划中 | B2B 特定场景，未完成 |

### 核心结论

**Layer 2（授权决策层）目前没有纯粹的独立产品占据。**

所有现有竞品解决的是"Agent 怎么能付钱"，Agent Guard 解决的是"Agent 该不该被允许付这笔钱"。两者互补，不是竞争。

---

## 四、市场可行性

### 需求真实性：高

**有真实损失记录：**
- 真实烧钱案例有文档记录（Privacy.com 博客）
- Adversa AI 2025 报告：部分 AI 安全事故造成 $100K+ 损失
- Gartner：40%+ agentic AI 项目因缺乏控制将在 2027 年前被取消

**市场用钱投票：**
- Skyfire $9.5M（a16z, Coinbase Ventures 参投）
- Crossmint $23.6M（Ribbit Capital, Franklin Templeton）
- Natural $9.8M（Abstract, Human Capital）
- Noma Security $100M Series B（8 个月从 stealth 到融资）

**企业采购信号：**
- 50% 高管为 agentic AI 安全预算了 $1000-5000 万
- 98% 企业计划增加治理预算，年均增长 24%

### 监管催化剂

| 法规 | 关键日期 | 对产品的意义 |
|---|---|---|
| EU AI Act 高风险条款 | **2026-08-02 强制执行** | 金融/医疗 Agent 必须有人类监督控制机制 |
| DORA（欧盟金融数字韧性法） | 2025-01-17 已生效 | AI 必须纳入 ICT 风险管理框架 |
| EU AI Act Article 9 | 同上 | 高风险 AI 系统必须有文档化控制机制 |

**EU AI Act 罚款上限：全球年营收的 7%（最高 €3500 万）**

---

## 五、Colosseum Frontier 黑客松策略

### 基本信息
- 主办方：Colosseum
- 时间：2026-04-06 至 2026-05-11（35天）
- 准备期：2026-03-27 至 2026-04-05（10天）

### 定位

Agent Guard 在黑客松中的定位：

```
Solana = 支付轨道（Layer 4）
Agent Guard = 授权决策层（Layer 2），坐在 Solana 上方
```

Solana 是 demo 场景的支付执行层，不是产品本身。这个定位在黑客松里很强：展示 AI × 支付 × 治理的完整闭环。

### 差异化技术点

1. **On-chain Policy Registry**（Anchor program）
   - 把每个 Agent 的 policy hash 存上链
   - 任何人可在 Solana Explorer 验证 Agent 的支出受治理
   - 评审能链上核实，不只是 demo

2. **框架原生拦截**（LangChain / MCP Gateway）
   - 不是外挂，是嵌入 Agent 执行链的中间件

3. **自然语言 Policy 配置**
   - 用 Claude API 解析，行业内无同类产品

### Demo 流程（3 分钟）

```
Step 1: 用户输入
"这个 Agent 每月最多花 100 USDC，低于 5 美元自动通过，新商家先问我"
→ Claude 解析 → 显示确认 → Policy hash 写入 Solana 链上

Step 2: Agent 发起小额交易（3 USDC，known merchant）
→ /v1/authorize → allow → 广播 Solana 交易

Step 3: Agent 发起中额交易（20 USDC，new merchant）
→ /v1/authorize → ask_user
→ Telegram 实时收到通知（现场演示）
→ 用户点 Allow → 交易完成

Step 4: Agent 发起超限交易（200 USDC，超月限）
→ /v1/authorize → deny → Dashboard 记录

Step 5: 展示 Solana Explorer — Policy hash 在链上可查
```

### 胜率评估

| 维度 | 评分 | 说明 |
|---|---|---|
| 赛道契合度 | ★★★★★ | AI × Solana 是 2026 最热交叉点 |
| 问题真实性 | ★★★★★ | 有真实损失案例，有市场调研背书 |
| 竞品稀缺性 | ★★★★☆ | Solana-native agent 授权层几乎没有 |
| 技术可行性 | ★★★★☆ | 所有零件都存在，35 天可做到 MVP |
| Demo 故事性 | ★★★★☆ | 场景清晰，非技术评审也能理解 |

**综合估计：进入决赛圈 40-50%，获奖 20-30%**

---

## 六、技术架构

### 系统架构图

```
AI Agent (任意框架)
    ↓ POST /v1/authorize
Agent Guard API (Fastify + TypeScript)
    ├── Chain Adapter Layer
    │   ├── Solana Adapter (SOL/USDC/SPL)
    │   └── EVM Adapter (ETH/ERC20, viem)
    ├── Policy Engine (规则评估，<50ms P99)
    │   └── 11 条规则，优先级顺序执行
    ├── NLP Parser (Claude API → 结构化 JSON)
    └── Decision: allow / deny / ask_user
         ↓ ask_user
    Human Approval Workflow
    ├── Telegram Bot (实时双向)
    ├── Email (Resend)
    └── Slack Webhook
         ↓
    PostgreSQL (policy/audit log)
    Redis (热路径缓存/队列)
    Solana (on-chain policy hash, Anchor)
```

### 技术栈

| 层级 | 选型 | 原因 |
|---|---|---|
| API 框架 | Fastify v5 + TypeScript | 比 Express 快 2x，原生 TS |
| 数据库 | PostgreSQL + Drizzle ORM | 类型安全，迁移可靠 |
| 缓存 | Redis (Upstash) | 热路径 policy 缓存 |
| NLP | Anthropic Claude claude-sonnet-4-6 | Few-shot + JSON schema 约束 |
| Solana | @solana/web3.js v1 + Anchor | 成熟生态 |
| EVM | viem | 现代，Tree-shakeable |
| 前端 | Next.js 14 App Router + shadcn/ui | 快速 UI |
| 通知 | Telegram Bot API + Resend | 黑客松期间最快验证 |
| 部署 | Railway (API) + Vercel (Web) | 零配置，快速上线 |

### Policy Engine 决策优先级

```
1. Token 不在白名单       → deny
2. 商家在黑名单           → deny
3. 类别在黑名单           → deny
4. 不允许自动续费          → deny
5. 日预算超限             → deny
6. 月预算超限             → deny
7. 新商家需确认           → ask_user
8. 金额超过审批阈值        → ask_user
9. 商家不在白名单          → ask_user
10. 类别不在白名单         → ask_user
11. 金额超过自动通过阈值    → ask_user
12. 默认                 → allow
```

---

## 七、核心 API

### POST /v1/authorize

```typescript
// Request
{
  "agentId": "uuid",
  "chain": "solana" | "solana-devnet" | "ethereum" | "base" | "polygon",
  "transaction": {
    "to": "address",
    "amount": "5000000",      // 最小单位 (USDC: 6位, SOL: lamports)
    "token": "USDC",
    "metadata": {
      "merchant": "OpenAI",
      "category": "api_credits",
      "isRecurring": false,
      "isNewMerchant": true
    }
  }
}

// Response: allow
{ "decision": "allow", "requestId": "req_xxx", "reason": "Amount within auto-approve limit" }

// Response: ask_user
{
  "decision": "ask_user",
  "requestId": "req_xxx",
  "reason": "New merchant requires confirmation",
  "expiresAt": "2026-04-06T12:05:00Z",
  "approvalUrl": "https://agentguard.io/approve/req_xxx",
  "timeoutAction": "deny"
}

// Response: deny
{ "decision": "deny", "requestId": "req_xxx", "reason": "Monthly budget exceeded" }
```

### POST /v1/policies/parse（NLP）

```typescript
// Request
{ "text": "低于5美元自动通过，新商家先问我，每月最多100美元" }

// Response
{
  "parsed": {
    "autoApproveBelowUsdc": 5,
    "requireConfirmationNewMerchant": true,
    "monthlyLimitUsdc": 100
  },
  "confirmationMessage": "系统理解：$5 以下自动通过；遇到新商家先通知你；每月上限 $100 USDC。",
  "ambiguous": []
}
```

---

## 八、SDK 使用

```typescript
import { AgentGuard } from '@agent-guard/sdk'

const guard = new AgentGuard({ agentId: '...', apiKey: '...' })

// 方式一：分步控制
const result = await guard.authorize({
  chain: 'solana',
  to: 'RecipientPublicKey',
  amount: '5000000',   // 5 USDC
  token: 'USDC',
  metadata: { merchant: 'OpenAI', category: 'api_credits' }
})

if (result.decision === 'allow') { /* 执行交易 */ }
if (result.decision === 'deny')  { /* 记录并跳过 */ }
if (result.decision === 'ask_user') {
  const final = await guard.waitForApproval(result.requestId)
  // final === 'allow' | 'deny'
}

// 方式二：一行搞定
const decision = await guard.check({ chain: 'solana', to: '...', amount: '5000000', token: 'USDC' })
if (decision === 'allow') { /* 执行 */ }
```

---

## 九、商业模式（黑客松后）

### 定位路径：Kong / HashiCorp 模式

```
开源 SDK（LangChain 插件、MCP 网关集成）
        ↓ 开发者社区采用
企业控制台（审计日志、审批工作流、合规报告、SSO）
        ↓ CISO / CFO 采购
$60K-600K ACV / 年
```

### 定价结构

| 层级 | 价格 | 内容 |
|---|---|---|
| Free | $0 | 5 个 Agent，基础日志 |
| Startup | $500-2000/月 | 50 个 Agent，完整审计，Slack/Email 审批 |
| Enterprise | $5000-50000+/月 | 无限 Agent，SSO，合规报告，SLA |

### 理想客户画像（ICP）

**优先级一：** 金融服务、医疗机构（EU AI Act 强制合规，$1000万+ 预算）

**优先级二：** 大型企业 AI 平台团队（已有 Agent 在生产，治理缺失）

**优先级三：** 构建 Agent 产品的 SaaS 公司（下游客户要求）

**开发者（底部漏斗）：** 病毒传播源，通过 OSS 进入

---

## 十、45 天执行计划

| 阶段 | 时间 | 目标 |
|---|---|---|
| 准备期 | 03/27 - 04/05 | 环境搭建、跑通 Solana devnet 转账 |
| Week 1 | 04/06 - 04/12 | Policy Engine + /v1/authorize 核心 API |
| Week 2 | 04/13 - 04/19 | NLP 解析 + Solana Adapter + Anchor on-chain |
| Week 3 | 04/20 - 04/26 | Telegram Bot + Human approval workflow |
| Week 4 | 04/27 - 05/03 | Dashboard + EVM Adapter + SDK |
| Week 5 | 05/04 - 05/11 | Demo 打磨、视频录制、Pitch deck |

---

## 十一、待完成（代码层面）

- [ ] Anchor on-chain Policy Registry（Solana 程序）
- [ ] Telegram Bot 双向审批（callback_query 处理）
- [ ] 数据库迁移文件生成（`npm run db:generate`）
- [ ] Demo 数据种子脚本
- [ ] Pitch deck（5-7 页）
- [ ] 3 分钟演示视频

---

## 十二、参考资源

### 竞品
- [Skyfire](https://skyfire.xyz) — Agent 钱包 + KYA 身份
- [Crossmint Agentic Payments](https://crossmint.com/solutions/agentic-payments)
- [Coinbase AgentKit](https://www.coinbase.com/developer-platform/discover/launches/agentic-wallets)
- [AgentCard](https://agentcard.sh)
- [Natural.co](https://natural.co)

### 协议标准
- [Stripe MPP](https://stripe.com/blog/machine-payments-protocol)
- [Mastercard Agent Pay](https://www.mastercard.com/us/en/business/artificial-intelligence/mastercard-agent-pay.html)
- [Visa Trusted Agent Protocol](https://developer.visa.com/capabilities/trusted-agent-protocol)
- [Google AP2 Protocol](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol)

### 黑客松
- [Colosseum Frontier](https://www.colosseum.org/frontier) — 2026-04-06 至 2026-05-11
