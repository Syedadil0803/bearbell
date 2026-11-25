# bearbell benchmark

Does bearbell find more real holes than the built-in `/security-review` and Semgrep, with fewer false
alarms, and at what token cost per true finding?

## Targets
`targets.json`: Broken Crystals and VuNAPI (NestJS), crAPI (business logic, not NestJS). Public
apps are probably in model training data, so the result that counts is a real project's past audit
with its fixes reverted. That truth file and its results name a client, so they stay out of this repo.

## Steps (on a build box, one target at a time)
1. Clone the target, note `git rev-parse HEAD` into `ref`. Run it in Docker only if a proof test needs it.
2. Write `truth/<name>.json` (format in `score.py`): each known vuln with file, line and CWE, plus
   traps (safe code that looks unsafe). Take vulns from the target's own docs, check each in code.
3. Get the owner's OK on the token budget: `runs × 2` Claude runs per target.
4. `bench/run.sh <name> <checkout> truth/<name>.json 3`
   Quick check after a skill change (one run, a few files, a few minutes):
   `BENCH_ONLY=bearbell BENCH_FILES=<a.ts,b.ts> bench/run.sh <name> <checkout> truth/<name>.json 1`.
   Broken Crystals quick set (13 vulns, 2 traps; REST + gRPC + GraphQL on shared sinks, so it tests also_from):
   `src/products/products.controller.ts,src/products/products.resolver.ts,src/products/products.service.ts,src/file/file.controller.ts,src/file/file.service.ts,src/testimonials/testimonials.service.ts`.
   Same set on old runs: trial 12/13, step 4 7/13, ledger 6/13 (2 alarms). Run the full target only before a release.
5. Read `results/<name>/score.md`. Then patch the found vulns and rescan: a finding still reported
   after its fix is a false alarm.

## Scoring
A finding matches a known vuln on file + CWE + line within 10. Per run: found, missed, false
alarms, traps hit, tokens and cost per true finding. Across 3 runs: found min-max and found in
every run (stability). `results/` is not committed.
