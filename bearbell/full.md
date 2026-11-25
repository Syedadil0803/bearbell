# /bearbell-full: review the whole project

Goal: a senior-style review of every entry point, against written access rules.
`X` is this skill's folder; `OUT` is a scratch folder outside the repo.

1. **Threat model in five lines.** From the README, CLAUDE.md, docs and the inventory: who the users
   and roles are, what the valuable data is, every way in (HTTP, webhooks, mail or chat intake,
   jobs, admin tools, mobile app, AI features), and where trust changes (public → signed in → role → owner of the object).
2. **Inventory (no model).** For each backend (NestJS, Express, Fastify, Koa, Hono, FastAPI, Flask,
   Django/DRF, Go net/http, gin, chi, echo, fiber, gorilla/mux, Java Spring):
   `python3 X/scripts/inventory.py <backend> --json OUT/inventory.json --md OUT/inventory.md --matrix OUT/matrix-rows.md --ledger OUT/ledger.md`
   Run each script command on its own: nothing chained before or after it (`cd`, `mkdir`, `wc`, `&&`, `;`, `|`).
   The scripts make OUT themselves. A chained command can hit a permission prompt, and the run then skips steps.
   Two or more backends: one ledger each (`OUT/ledger-<backend>.md`), each checked at step 7.
   Read `OUT/inventory.md` first, not the source. "Stacks: none found" means list routes by reading.
   Mount prefixes (app.use, include(), PathPrefix) are applied when the mounted file is found; paths under
   a mount whose file was not found stay relative to it. Check its header: global guards, guard classes,
   which decorators set which metadata key, and "decorators no guard reads" (a role or public marker
   nobody enforces is a finding on its own).
3. **Access matrix.** If `access-matrix.md` is missing, copy `X/access-matrix.md` to the repo
   root, paste `OUT/matrix-rows.md` into its table and fill roles, objects and business rules from
   the code. Every row stays `guess` until the owner confirms. Show the owner the short list of
   rows to decide (who may do what to whose data) and stop until they answer: the matrix is the
   rulebook, and a guessed rule cannot prove a bug. If they say go on without it, mark every finding "matrix not confirmed".
   If the file exists, add rows for new routes as `guess` and list them.
   Read `intended.md` too if it exists: its rows are owner-approved behaviour, skipped by `trace.md`.
4. **Tools (no model).** `python3 X/scripts/tools.py . --tier full --out OUT`
   (gitleaks over history, trufflehog verified only, OSV-Scanner, full Semgrep). Run it on the build
   box if the project has one. Tool hits go into the report as their own section; read each Semgrep
   hit only if it sits on a route or job path.
5. **Features.** One per controller, resolver or route file (never one per area: grouped files get skimmed), one per job or intake channel, one per AI feature, one for
   auth itself (login, codes, tokens, sessions, logout), and one for the mobile or web client (token
   storage, hidden-button-only checks, deep links). Order: public and write routes first, then
   routes with `object-id`, then the rest.
6. **Trace, disprove, prove.** Follow `trace.md` for every feature, with two tracer runs per feature
   (their union goes to disprove: runs vary, two catch more).
7. **Ledger gate.** `python3 X/scripts/inventory.py --check OUT/ledger.md` must print `ledger complete`.
   Anything it lists: trace it, or write `skip: <why>` in its row. Only then write the report.
8. **Report.** Follow `report.md`. Every route from the inventory appears in the coverage table.
