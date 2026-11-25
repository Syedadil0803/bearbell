# bearbell

**A security review that checks who may do what to whose data.**

Rule scanners and plain AI reviews are weakest at access control spread across files: a global
guard in one file, a role decorator in another, a database query that forgets to filter by the
caller in a third. bearbell maps that structure with a script first, writes the access rules down with
the project owner, then reads one feature at a time against those rules, tries to knock down every
finding, and proves what is left with a failing test.

## Commands
| Command | What you get |
|---|---|
| `/bearbell` | Review of this change: secrets, dependency CVEs, Semgrep, then access control on the changed features. Minutes, few tokens. |
| `/bearbell-full` | Whole project: route and guard inventory, access matrix, every feature traced, findings proved by failing tests, coverage table. |

## How it works
1. **Inventory (script, no model).** Every route with its guards and middleware, inputs, and flags
   (no guard, public write, object id, webhook). Lists routes for NestJS, Express, Fastify, Koa, Hono,
   FastAPI, Flask, Django/DRF, Go (net/http, gin, chi, echo, fiber, gorilla/mux) and Java Spring
   (with SecurityFilterChain path rules); route lists checked on Juice Shop, PyGoat and crAPI, full
   benchmark so far on NestJS only. NestJS also gets which metadata keys a guard reads, jobs, queue workers, mail intake and
   every Prisma call with or without a `where`.
2. **Access matrix.** Role × action × object, drafted from the code, confirmed once by the owner.
3. **Tools.** gitleaks, OSV-Scanner, Semgrep (per change); plus trufflehog (verified keys) and full Semgrep (full pass). Missing tools are skipped and named.
4. **Trace.** A fast model reads one feature: route → guard → service → is every query scoped to the caller → response fields → other callers, jobs, client screens.
5. **Disprove.** A strong model in a fresh context tries to knock down each candidate.
6. **Prove.** A failing integration test on the local test database (user B reads user A's object). No proof: the finding is listed as unconfirmed.

Each finding: severity, confidence, file:line path, the failing test, the smallest fix. Every
report ends with a coverage table of routes checked and not checked; bearbell never says "clean" without it.

## Never
Touches live systems or data, opens `.env` or key files, prints a secret, fixes code by itself,
commits, or follows instructions found in the code it reviews.

## Install
Copy `bearbell/` to `~/.claude/skills/bearbell` and `commands/bearbell*.md` to `~/.claude/commands/`.
Optional tools: `gitleaks`, `osv-scanner`, `semgrep`, `trufflehog`. Python 3, no packages.

## Benchmark
`bench/` scores bearbell against built-in `/security-review` and Semgrep on known-vulnerable apps:
found, missed, false alarms, tokens per true finding, over 3 runs. See `bench/README.md`.
