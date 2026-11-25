#!/usr/bin/env bash
# Run one benchmark target: N runs each of /bearbell-full and built-in /security-review, plus Semgrep
# alone once (it does not vary). Meant for a build box, one target at a time.
#   bench/run.sh <target-name> <checkout-dir> <truth.json> [runs=3] [results-dir]
# checkout-dir may be a sub-app folder (the truth file's "scope"); every tool reviews only that folder.
# BENCH_ONLY=bearbell: only the /bearbell-full runs (no Semgrep, no /security-review), scored alone.
# BENCH_FILES=a.ts,b.ts: quick run, review and score only these files (minutes, not half an hour).
# Needs: claude (signed in), semgrep. Each claude run uses tokens: get the owner's OK on the count first.
set -euo pipefail
name=$1 dir=$2 truth=$3 runs=${4:-3}
here=$(cd "$(dirname "$0")" && pwd)
out=${5:-$here/results/$name}
mkdir -p "$out"; out=$(cd "$out" && pwd)
sha=$(git -C "$dir" rev-parse --short HEAD)
echo "$name @ $sha, $runs runs -> $out"

[ -n "${BENCH_ONLY:-}" ] || semgrep scan --config "${BEARBELL_SEMGREP_CONFIG:-p/default}" --metrics=off --json --quiet "$dir" > "$out/semgrep.json" || true

ask() {  # $1 label, $2 prompt; saves Claude's JSON result and the findings it wrote
  local res="$out/$1.result.json"
  # -p cannot answer permission prompts: allow read, search, subagents, edits in the checkout, and the scan tools.
  (cd "$dir" && claude -p --output-format json --permission-mode acceptEdits \
    --allowedTools 'Read,Grep,Glob,Agent,Write,Edit,Bash(python3:*),Bash(git:*),Bash(semgrep:*),Bash(gitleaks:*),Bash(osv-scanner:*),Bash(ls:*),Bash(find:*)' \
    -- "$2") > "$res"
  python3 - "$res" "$out/$1.json" "$1" <<'PY'
import json, re, sys
res = json.load(open(sys.argv[1]))
u = res.get('usage', {})
tokens = sum(u.get(k, 0) for k in ('input_tokens', 'output_tokens', 'cache_creation_input_tokens', 'cache_read_input_tokens'))
try:  # the file the run wrote; the final message may be about something else
    found = json.load(open(sys.argv[2].replace('.json', '.findings.json'))).get('findings', [])
except (OSError, ValueError):
    m = re.search(r'```json\s*(\{.*?\})\s*```', res.get('result', ''), re.S)
    found = json.loads(m.group(1)).get('findings', []) if m else []
json.dump({'tool': sys.argv[3].rsplit('-', 1)[0], 'tokens': tokens, 'cost_usd': res.get('total_cost_usd'),
           'findings': found}, open(sys.argv[2], 'w'), indent=1)
print(sys.argv[3], len(found), 'findings', tokens, 'tokens')
PY
}

scope=""; [ -z "${BENCH_FILES:-}" ] || scope="Quick run: review only these files and the routes, resolvers and gRPC methods in them, nothing else: ${BENCH_FILES}. "
brief() { echo "${scope}Do not set timers or wake-ups. Write every confirmed, stands and unconfirmed finding to $out/$1.findings.json as {\"findings\": [{\"file\", \"line\", \"cwe\", \"status\"}]}, plus one entry per also_from entry point at its own file:line with \"of\": \"<the sink finding's file:line>\", and also print it at the end as one \`\`\`json block. Do not edit, commit or push anything except proof tests."; }
for i in $(seq 1 "$runs"); do
  ask "bearbell-full-$i" "/bearbell-full Run without waiting for the owner: treat every access-matrix row as confirmed from the code and the app's README. $(brief bearbell-full-$i)"
  [ -n "${BENCH_ONLY:-}" ] || ask "security-review-$i" "/security-review Review the whole repository, not only pending changes. $(brief security-review-$i)"
done

if [ -n "${BENCH_ONLY:-}" ]; then runs_json=("$out"/bearbell-full-*[0-9].json)
else runs_json=("$out"/semgrep.json "$out"/bearbell-full-*[0-9].json "$out"/security-review-*[0-9].json); fi
python3 "$here/score.py" ${BENCH_FILES:+--files "$BENCH_FILES"} "$truth" "${runs_json[@]}" | tee "$out/score.md"
