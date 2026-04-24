# Trigger Matrix

This is the decision tree the agent should follow when it encounters any situation that the Intercept Skill is responsible for. Each row maps a real-world situation to the exact tool the agent should call, and where it sits on the **Advisory ↔ Enforcement** spectrum.

> **Rule of thumb:** If money or external code is involved, this Skill activates. If the agent is unsure whether it activates, it activates.

## Payment Triggers (Enforcement Layer)

| Situation | First Tool | Then |
|-----------|-----------|------|
| Agent decides to send any token, swap, or invoke a payable contract method | `authorize_payment` | If `allow`, optionally call the API's `/v1/requests/:id/execute` to broadcast on-chain |
| Agent wants to know "what can I afford right now?" | `suggest_spending` | Compare result to intended spend |
| Agent wants to know "how much have I already spent today/this month?" | `get_spending_budget` | — |
| Agent expects to make many payments to the same set of merchants over a window | `create_spending_session` then `session_spend` for each charge | The session is bound to specific recipient addresses (not names) and a max budget |
| Agent submitted a request and got `decision: ask_user` | `get_request_status` (poll) or `list_pending_approvals` | Wait for the human to resolve via dashboard / Telegram / email |
| Agent wants to inspect its own behavior before doing something risky | `check_security_profile` | Read the 7-day audit summary and adjust |
| Agent wants to look back at what it has already done | `get_transaction_history` | — |

## External-Input Triggers (Advisory Layer)

| Situation | Tool | Args |
|-----------|------|------|
| Encountering a new on-chain address (recipient, contract, DApp) | `get_security_review_guide` | `{ type: "onchain" }` |
| Asked to install a Skill, MCP server, npm/pip/cargo package | `get_security_review_guide` | `{ type: "skill_mcp" }` |
| Asked to evaluate a GitHub repository | `get_security_review_guide` | `{ type: "repository" }` |
| Sent a URL, document, Gist, or markdown file | `get_security_review_guide` | `{ type: "url_document" }` |
| Connecting to an unfamiliar API or service | `get_security_review_guide` | `{ type: "product_service" }` |
| Tool recommended in a chat by an unknown party | `get_security_review_guide` | `{ type: "message_share" }` |
| Need to recognize a specific class of attack | `get_security_review_guide` | `{ type: "red_flags" / "social_engineering" / "supply_chain" }` |
| Want the overview of all review types | `get_security_review_guide` | `{ type: "index" }` |

## Combined Workflows

### "Pay this unfamiliar address"

```
1. get_security_review_guide({ type: "onchain" })   ← load AML rubric + contract checklist
2. (agent runs the checks the guide describes)
3. authorize_payment({ to, amount, token, ... })    ← server-side enforcement
4. if decision === "allow": POST /v1/requests/:id/execute
   if decision === "ask_user": poll get_request_status
   if decision === "deny": stop
```

### "Install this MCP server my friend recommended"

```
1. get_security_review_guide({ type: "message_share" })  ← validate the recommender first
2. get_security_review_guide({ type: "skill_mcp" })      ← then the install-time checklist
3. (agent reviews the package contents using the red_flags library)
4. STOP and ask the human before installing if anything matched.
```

### "Pay the OpenAI subscription monthly"

```
1. create_spending_session({
     maxAmountUsdc: 25,
     durationMinutes: 43200,             // 30 days
     allowedRecipients: ["<OpenAI address from known_merchants>"],
     purpose: "OpenAI API subscription",
   })
2. Use session_spend for each charge.
3. The server enforces:
   - amount cap
   - expiry
   - recipient address allowlist (the merchant name is irrelevant — addresses cannot be spoofed)
```

## Default Disciplines

1. **Never call `/execute` without `authorize_payment` first.** The MCP tool layer makes this the only sanctioned path, but the discipline must be explicit in agent instructions.
2. **For anything `ask_user`, the agent waits.** Don't try to reroute through a different tool to avoid the human. The dashboard records the attempt.
3. **`allowedRecipients` beats `allowedMerchants`.** Names get spoofed, addresses don't.
4. **When in doubt, escalate.** The Skill is fail-safe by design — every layer can only make the decision more conservative, never more permissive.
