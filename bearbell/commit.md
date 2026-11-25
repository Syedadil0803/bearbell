# /bearbell: review this change

Goal: catch a new hole before it is committed, in a few minutes and few tokens.
`X` below is this skill's folder; `OUT` is a scratch folder outside the repo (e.g. `$TMPDIR/bearbell-<repo>`).

1. **Tools (no model).** From the repo root:
   `python3 X/scripts/tools.py . --tier commit [--base REF] --out OUT`
   gitleaks on staged changes, OSV-Scanner only if a lockfile changed, Semgrep on changed files.
   Missing tools are listed as skipped; say so in the report.
2. **Inventory (no model).** For each backend folder in the repo:
   `python3 X/scripts/inventory.py <backend> --json OUT/inventory.json --md OUT/inventory.md --ledger OUT/ledger.md`
   "Stacks: none found" (a framework it does not know): say so and let the tracer find routes by reading.
3. **Pick features.** A feature is one controller or route file (urls.py, router) plus what it calls, or one job/intake entry.
   Take the features whose controller, route file, service, DTO or schema, guard, middleware, decorator, DB schema or client screen
   changed. For a changed service, `grep -rl` its class name to find the controllers that use it.
   A changed guard, decorator, `app.module` or `main.ts` touches every route: run `/bearbell-full` instead and say why.
4. **Matrix.** Read `access-matrix.md` in the repo root (or `docs/`). Missing: use the route's own
   decorators as the rule, mark every finding "matrix not confirmed", and suggest `/bearbell-full`.
   Read `intended.md` next to it if present: owner-approved behaviour, skipped by `trace.md`.
5. **Trace, disprove, prove.** Follow `trace.md` for each picked feature (one tracer run, not two).
6. **Ledger gate.** Mark every route outside the picked features `skip: not in this change`, then
   `python3 X/scripts/inventory.py --check OUT/ledger.md` must print `ledger complete`.
7. **Report.** Follow `report.md`. The coverage table lists the picked features' routes as checked
   and every other route as "not in this change".
