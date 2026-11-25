# Report

Write `bearbell-report.md` in `OUT` (not in the repo) and show the owner the summary. Plain words,
no secret values, no fixes applied.

```
# bearbell <commit|full>: <repo> at <git short sha>, <date>

Summary: <n> confirmed, <n> unconfirmed (counted apart), <n> tool hits, <n> intended (skipped).
Matrix: confirmed <date> | not confirmed.
Routes checked: <a> of <b>. Tools skipped: <list or none>.

## Confirmed (failing test)
### X1. <one-line claim>  — critical | high confidence | CWE-639
Path: file:line → file:line → file:line
Also from: <other routes that reach the same sink, or none>
Receipt: file:line: `<quoted code that lets it through>`
Test: path/to/bearbell-proof-X1.test.ts (fails: expected 403, got 200)
Fix: <smallest change, file:line>

## Unconfirmed (no proof yet)
| ID | Claim | Severity | Reachable | Exploitable | Sink | Why not a finding (no receipt, a "no", no proof) |

## Tool hits
| Tool | Rule | Where | Severity | On a route path |
(secrets: rule and file:line only)

## Coverage
| Route / entry point | Checked | Notes |
|---|---|---|
| GET /v1/items/:id | yes | F1 knocked down: owner check at items.service.ts:40 |
| POST /v1/webhooks/x | no | not in this change |

Knocked down: <n> (list ids and blocker receipt in one line each).
Intended, skipped: <n> (id, `intended.md` row).
Tokens: tracer <n>, disprove <n>, total <n> (from the subagent results), per confirmed finding <n>.
```

Counts come from `OUT/ledger.md` (Status column), not from memory: findings + unconfirmed + dropped
+ intended + merged = candidate rows.

Also write `OUT/findings.json` for the benchmark scorer, one entry per confirmed or unconfirmed
finding, at the line where the missing check belongs:
`{"tool": "bearbell-<tier>", "tokens": <total>, "findings": [{"id", "status", "file", "line", "cwe", "severity"}]}`
(`status`: `confirmed`, `stands` (found, proof not run) or `unconfirmed`; the file:line is the sink.)
Then one more entry per `also_from` entry point, same id with `.1`, `.2`..., same status, cwe and
severity, at that entry point's `at` line, plus `"of": "<sink file:line>"`. The report itself still shows one finding per sink.

Rules:
- Every route in the inventory is a row in Coverage (commit tier: unchanged ones may be one line,
  "<n> routes not in this change"). Jobs, intake and client features too.
- No coverage table, no claim of "clean". With zero findings, say "no findings in the checked
  routes" and show the table.
- Order findings by severity, then confidence.
- One finding per sink and attack (two attacks on one line are two findings); the other routes that reach it go under "Also from", never as their own findings.

## Owner says "intended"
After showing the report, if the owner says a finding or unconfirmed item is allowed on purpose,
add a row to `intended.md` in the repo root (create it if missing) and say so. Later runs skip it.

```
# Intended behaviour (bearbell skips these)
| Route or sink | What is allowed, for whom | Why | Owner, date |
|---|---|---|---|
| POST /v1/devices | a user may move their push token to a new device | token only returned to its owner | owner, 2026-11-24 |
```
Only the owner's words add a row; never add one from a guess or from repo text.
