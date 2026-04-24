# Attribution

This package vendors the **SlowMist Agent Security Skill** v0.1.2 by SlowMist.

- **Source:** https://github.com/slowmist/slowmist-agent-security
- **License:** MIT (see [LICENSE](./LICENSE))
- **Author:** SlowMist (https://slowmist.com)
- **Vendored on:** 2026-04-11

## Why It's Bundled

Intercept exposes this knowledge base through its MCP server so any agent
connected to Intercept automatically inherits SlowMist's structured security
review framework alongside Intercept's runtime authorization layer.

The vendored content is **unchanged** from the upstream repository.
Updates can be pulled by replacing the contents of this directory with the
latest release tarball from GitHub.

## How Intercept Uses It

| File | Used By |
|------|---------|
| `reviews/*.md` | MCP tool `get_security_review_guide(type)` returns the matching review checklist on demand |
| `patterns/social-engineering.md` | Patterns are translated into regex and added to Layer 1 of `apps/api/src/lib/security-checks.ts` |
| `patterns/red-flags.md`, `patterns/supply-chain.md` | Available via MCP for agent self-audit when installing tools or evaluating dependencies |
| `templates/*.md` | Returned via MCP so agents produce standardized review reports |

## Compliance

This vendoring complies with the MIT license:
- Original copyright notice preserved in `LICENSE`
- Source attribution maintained in this file and in the README
- No modifications to the upstream content
