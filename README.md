<p align="center">
  <img src="assets/logo.svg" width="96" alt="bearbell logo">
</p>

<h1 align="center">bearbell</h1>

<p align="center">
  <b>Finds the security bugs scanners walk past: who can read, change or delete whose data.</b><br>
  A Claude Code skill. Runs on your machine, in your session. Free and open source.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/security-checked%20by%20bearbell-F2A900?logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCIgd2lkdGg9Ijk2IiBoZWlnaHQ9Ijk2Ij4KICA8cGF0aCBkPSJNMzIgNmMtMiAwLTMuNSAxLjUtMy41IDMuNHYxLjlDMTkuNiAxMyAxNCAyMC42IDE0IDI5LjZWNDBsLTUgN3YyaDQ2di0ybC01LTdWMjkuNmMwLTktNS42LTE2LjYtMTQuNS0xOC4zVjkuNEMzNS41IDcuNSAzNCA2IDMyIDZ6IiBmaWxsPSIjRkZGRkZGIi8%2BCiAgPHBhdGggZD0iTTI1IDUyYTcgNyAwIDAgMCAxNCAweiIgZmlsbD0iI0ZGRkZGRiIvPgogIDxjaXJjbGUgY3g9IjMyIiBjeT0iMzAiIHI9IjUiIGZpbGw9IiNGMkE5MDAiLz48cmVjdCB4PSIzMCIgeT0iMzIiIHdpZHRoPSI0IiBoZWlnaHQ9IjkiIHJ4PSIxLjUiIGZpbGw9IiNGMkE5MDAiLz4KPC9zdmc%2BCg%3D%3D&labelColor=1F1F1F" alt="checked by bearbell">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
  <img src="https://img.shields.io/badge/Claude%20Code-skill-D97757" alt="Claude Code skill">
  <img src="https://img.shields.io/badge/python-stdlib%20only-3776AB?logo=python&logoColor=white" alt="Python stdlib only">
  <img src="https://img.shields.io/badge/Broken%20Crystals-57%2F67%20found-2EA043" alt="57 of 67 found">
</p>

---

## Why

Most real breaches are not exotic. User B opens `/orders/1042`, which belongs to user A, and the
server hands it over. A pattern scanner can't see that, because nothing on the line looks wrong:
the missing check is a `where` that should name the caller, three files away from the route.

bearbell reads your app like an attacker with a plan. It maps every route and guard, writes down who
may do what, follows each feature end to end, then tries to break its own findings before it shows them to you.

## What you get

- 🗺️ **Every entry point mapped**: REST routes, GraphQL resolvers, gRPC methods, webhooks, jobs, with their guards. Done by a script, no tokens.
- 📋 **An access matrix**: role × action × object, drafted from your code and confirmed by you once. A bug is a broken rule, not a guess.
- 🔎 **Feature-by-feature tracing**: route → guard → service → query → response. Is every query scoped to the caller? Does the response leak fields?
- 🥊 **Findings that survived an attack**: a second model in a fresh context tries to knock each one down. What's left gets a receipt (the exact line that lets it through).
- 🧪 **Proof, not opinion**: a failing test on your local test database (user B reads user A's record). No proof means it's listed as unconfirmed, never hidden.
- 📊 **A coverage table**: every route, checked or not. bearbell never says "clean" without one.
- 🔐 **The usual suspects too**: leaked secrets (gitleaks, trufflehog), vulnerable dependencies (OSV-Scanner), Semgrep rules.

## Two commands

| | When | Takes |
|---|---|---|
| `/bearbell` | Before you merge: reviews the change you're about to ship | minutes |
| `/bearbell-full` | Before a release or an audit: the whole project | ~30 min, ~$5–13 in tokens |

## What a finding looks like (example)

```
### X1. Any signed-in user can read another user's invoice  — high | high confidence | CWE-639
Path:    invoices.controller.ts:41 → invoices.service.ts:88 → prisma.invoice.findUnique
Receipt: invoices.service.ts:88: `findUnique({ where: { id } })`  (no ownerId)
Test:    invoices/bearbell-proof-X1.spec.ts  (fails: expected 403, got 200)
Fix:     invoices.service.ts:88 → where: { id, ownerId: user.id }
```

## Tested

On [Broken Crystals](https://github.com/NeuraLegion/brokencrystals), a deliberately vulnerable NestJS app with
**67 known holes** ([truth file](bearbell/bench/truth)), bearbell found up to **57** (40–57 across 4 full runs; LLM runs vary).
On the 13-hole quick set the latest 3 runs found 13, 11 and 11, with 0–1 false alarms, about $1.20 a run.
Run it yourself with the harness in [`bearbell/bench`](bearbell/bench).

## Install

```bash
git clone https://github.com/Syedadil0803/bearbell
cp -r bearbell/bearbell ~/.claude/skills/bearbell
cp bearbell/commands/bearbell*.md ~/.claude/commands/
```

Then in Claude Code type `/bearbell`. Needs Python 3 (no packages). Optional, used when present:
`gitleaks`, `osv-scanner`, `semgrep`, `trufflehog`. Missing tools are skipped and named in the report.

## Stacks

Route mapping works for **NestJS, Express, Fastify, Koa, Hono, FastAPI, Flask, Django/DRF, Go**
(net/http, gin, chi, echo, fiber, gorilla/mux) and **Java Spring**. The route lists were checked on Juice Shop,
PyGoat and crAPI. The full benchmark so far covers **NestJS only**; other stacks get scored before we claim numbers for them.

## What it never does

Touch live systems or data · open `.env` or key files · print a secret · change your code ·
commit · follow instructions hidden in the code it reviews.

## Show it off

Checked your project with bearbell? Add the badge:

```markdown
[![checked by bearbell](https://img.shields.io/badge/security-checked%20by%20bearbell-F2A900?logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCIgd2lkdGg9Ijk2IiBoZWlnaHQ9Ijk2Ij4KICA8cGF0aCBkPSJNMzIgNmMtMiAwLTMuNSAxLjUtMy41IDMuNHYxLjlDMTkuNiAxMyAxNCAyMC42IDE0IDI5LjZWNDBsLTUgN3YyaDQ2di0ybC01LTdWMjkuNmMwLTktNS42LTE2LjYtMTQuNS0xOC4zVjkuNEMzNS41IDcuNSAzNCA2IDMyIDZ6IiBmaWxsPSIjRkZGRkZGIi8%2BCiAgPHBhdGggZD0iTTI1IDUyYTcgNyAwIDAgMCAxNCAweiIgZmlsbD0iI0ZGRkZGRiIvPgogIDxjaXJjbGUgY3g9IjMyIiBjeT0iMzAiIHI9IjUiIGZpbGw9IiNGMkE5MDAiLz48cmVjdCB4PSIzMCIgeT0iMzIiIHdpZHRoPSI0IiBoZWlnaHQ9IjkiIHJ4PSIxLjUiIGZpbGw9IiNGMkE5MDAiLz4KPC9zdmc%2BCg%3D%3D&labelColor=1F1F1F)](https://github.com/Syedadil0803/bearbell)
```

## License

MIT. Star the repo if it caught something for you. ⭐
