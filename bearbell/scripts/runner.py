#!/usr/bin/env python3
"""Step runner for /bearbell-full: fixed step order, and no step counts as done until its output
passes a check. The session asks this script what to do next instead of deciding. Stdlib only.

  python3 runner.py start <repo> <OUT> [--files a.ts,b.ts]   # writes OUT/run.json, prints step 1
  python3 runner.py next <OUT>     # checks the current step; done -> prints the next one, else what is missing (exit 1)
  python3 runner.py status <OUT>   # every step, done or open; exit 0 only when the run is complete
  python3 runner.py --selftest
"""
import glob
import json
import os
import subprocess
import sys

X = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # the skill folder
QUESTIONS = [f'q{i}' for i in range(1, 9)]  # the 8 tracer questions in trace.md, asked on every route


def script(name, *args):
    p = subprocess.run([sys.executable, os.path.join(X, 'scripts', name), *args], capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def need(*paths):
    return [f'missing: {p}' for p in paths if not os.path.exists(p)]


def passes(name, md):
    if not os.path.exists(md):
        return [f'missing: {md}']
    code, out = script(name, '--check', md)
    return [] if code == 0 else out.splitlines()


def ledger_rows(run):
    """Entry rows of the ledger in scope: (file, entry, tracer cell)."""
    rows, table = [], False
    for line in open(os.path.join(run['out'], 'ledger.md')).read().splitlines():
        if line.startswith('| Feature'):
            table = True
        elif line.startswith('| ID |') or line.startswith('## '):
            table = False
        elif table and line.startswith('|') and not line.startswith('|---'):
            c = [x.strip() for x in line.strip().strip('|').split('|')]
            if len(c) >= 5 and (not run['files'] or c[0] in run['files']):
                rows.append((c[0], c[1].strip('`'), c[3]))
    return rows


def answers_complete(run):
    """Every traced route in scope has an answer to every core question in some OUT/trace/*.json."""
    got = {}
    for f in glob.glob(os.path.join(run['out'], 'trace', '*.json')):
        try:
            for route, a in (json.load(open(f)).get('answers') or {}).items():
                got.setdefault(route, {}).update({q: v for q, v in a.items() if str(v).strip()})
        except (OSError, ValueError, AttributeError):
            return [f'not valid JSON with an "answers" object: {f}']
    left = []
    for _, entry, tracer in ledger_rows(run):
        if tracer.startswith('skip:'):
            continue
        miss = [q for q in QUESTIONS if q not in got.get(entry, {})]
        if miss:
            left.append(f"unanswered: {entry} ({', '.join(miss)})")
    return left


def traced(run):
    left = [f'not traced: {e} ({f})' for f, e, t in ledger_rows(run) if not t]
    return left or answers_complete(run)


def report_ok(run):
    out = run['out']
    left = need(os.path.join(out, 'bearbell-report.md'), os.path.join(out, 'findings.json'))
    if left:
        return left
    if '## Coverage' not in open(os.path.join(out, 'bearbell-report.md')).read():
        left.append('bearbell-report.md has no "## Coverage" table')
    try:
        json.load(open(os.path.join(out, 'findings.json')))['findings']
    except (ValueError, KeyError, TypeError):
        left.append('findings.json is not {"findings": [...]}')
        return left
    if run['files']:  # scoped run: a finding outside the given files is out of scope, not a finding
        for f in json.load(open(os.path.join(out, 'findings.json')))['findings']:
            if not any(str(f.get('file', '')).endswith(x) for x in run['files']):
                left.append(f"outside --files, move to the report's notes: {f.get('id')} {f.get('file')}")
    return left


# (title, what to do, check). {X} skill folder, {R} repo, {O} OUT, {F} ' --files ...' or ''.
STEPS = [
    ('Inventory', 'Run on its own line: python3 {X}/scripts/inventory.py {R} --json {O}/inventory.json '
     '--md {O}/inventory.md --matrix {O}/matrix-rows.md --ledger {O}/ledger.md\nThen read {O}/inventory.md (full.md step 2).',
     lambda r: need(*(os.path.join(r['out'], f) for f in ('inventory.json', 'inventory.md', 'ledger.md')))),
    ('Every file', 'Run: python3 {X}/scripts/entrypoints.py {R} --md {O}/files.md{F}\nFill every row of {O}/files.md '
     '(Entry point yes/no, Ways in, Note). Run any "Route table commands" it lists if the app can run locally. '
     'Add a ledger row for every way in the inventory missed.',
     lambda r: passes('entrypoints.py', os.path.join(r['out'], 'files.md'))),
    ('Access matrix', 'full.md step 3. Write it to {R}/access-matrix.md, or to {O}/access-matrix.md when you must not edit the repo.',
     lambda r: [] if any(os.path.exists(os.path.join(d, 'access-matrix.md')) for d in (r['repo'], r['out']))
     else ['missing: access-matrix.md (repo root or OUT)']),
    ('Tools', 'Run: python3 {X}/scripts/tools.py {R} --tier full --out {O}',
     lambda r: need(os.path.join(r['out'], 'tools-full.json'))),
    ('Suspect lines', 'Run: python3 {X}/scripts/suspects.py {R} --md {O}/suspects.md{F}',
     lambda r: need(os.path.join(r['out'], 'suspects.md'))),
    ('Trace', 'trace.md part 1, one tracer per feature (full.md steps 5-6). Save each tracer reply to '
     '{O}/trace/<feature>-<n>.json. Fill the ledger and the suspects rows of the traced files as you go.',
     traced),
    ('Disprove', 'trace.md part 2 on every candidate. Every row of {O}/suspects.md needs a verdict and receipt.',
     lambda r: passes('suspects.py', os.path.join(r['out'], 'suspects.md'))),
    ('Proof', 'trace.md part 3. Then every ledger candidate needs Verdict and Status.',
     lambda r: passes('inventory.py', os.path.join(r['out'], 'ledger.md'))),
    ('Report', 'Follow report.md: {O}/bearbell-report.md and {O}/findings.json.', report_ok),
]


def load(out):
    return json.load(open(os.path.join(out, 'run.json')))


def save(run):
    json.dump(run, open(os.path.join(run['out'], 'run.json'), 'w'), indent=1)


def show(run):
    i = len(run['done'])
    if i == len(STEPS):
        return 'run complete'
    title, do, _ = STEPS[i]
    F = f" --files {','.join(run['files'])}" if run['files'] else ''
    text = do.format(X=X, R=run['repo'], O=run['out'], F=F)
    return (f'Step {i + 1}/{len(STEPS)}: {title}\n{text}\n'
            f'When done, run: python3 {X}/scripts/runner.py next {run["out"]}')


def main(argv):
    if '--selftest' in argv:
        return selftest()
    if len(argv) >= 3 and argv[0] == 'start':
        files = argv[argv.index('--files') + 1].split(',') if '--files' in argv else []
        out = os.path.abspath(argv[2])
        os.makedirs(os.path.join(out, 'trace'), exist_ok=True)
        run = {'repo': os.path.abspath(argv[1]), 'out': out, 'files': files, 'done': []}
        save(run)
        print(show(run))
        return 0
    if len(argv) == 2 and argv[0] in ('next', 'status'):
        run = load(os.path.abspath(argv[1]))
        if argv[0] == 'status':
            for i, (title, _, _) in enumerate(STEPS):
                print(f"{i + 1}. {title}: {'done' if i < len(run['done']) else 'open'}")
            return 0 if len(run['done']) == len(STEPS) else 1
        i = len(run['done'])
        if i < len(STEPS):
            left = STEPS[i][2](run)
            if left:
                print(f'Step {i + 1} ({STEPS[i][0]}) is not done:\n' + '\n'.join(left[:40]))
                return 1
            run['done'].append(STEPS[i][0])
            save(run)
        print(show(run))
        return 0
    sys.exit(__doc__)


def selftest():
    import tempfile
    t = tempfile.mkdtemp()
    repo, out = os.path.join(t, 'repo'), os.path.join(t, 'out')
    os.makedirs(repo)
    assert main(['start', repo, out, '--files', 'a.ts']) == 0
    assert main(['next', out]) == 1                        # no inventory yet: refused
    ledger = ('| Feature (file) | Entry point | At | Tracer | Candidates |\n|---|---|---|---|---|\n'
              '| a.ts | `GET /a` | a.ts:3 | T1 | none |\n| b.ts | `GET /b` | b.ts:1 |  |  |\n')
    for f, s in (('inventory.json', '{}'), ('inventory.md', ''), ('ledger.md', ledger)):
        open(os.path.join(out, f), 'w').write(s)
    run = load(out)
    assert STEPS[0][2](run) == []
    assert traced(run) == ['unanswered: GET /a (q1, q2, q3, q4, q5, q6, q7, q8)']  # b.ts out of scope
    json.dump({'answers': {'GET /a': {q: 'a.ts:3 ok' for q in QUESTIONS[:7]}}}, open(os.path.join(out, 'trace', 'a-1.json'), 'w'))
    assert traced(run) == ['unanswered: GET /a (q8)']
    json.dump({'answers': {'GET /a': {'q8': 'a.ts:4 limit capped'}}}, open(os.path.join(out, 'trace', 'a-2.json'), 'w'))
    assert traced(run) == []                               # answers join across tracer runs
    run['files'] = []
    assert traced(run) == ['not traced: GET /b (b.ts)']     # whole project: b.ts needs a tracer
    run['done'] = [s[0] for s in STEPS[:8]]
    assert report_ok(run) and not show(run).startswith('run complete')
    open(os.path.join(out, 'bearbell-report.md'), 'w').write('# r\n## Coverage\n')
    open(os.path.join(out, 'findings.json'), 'w').write('{"findings": [{"id": "F1", "file": "src/main.ts"}]}')
    run['files'] = ['src/a.ts']
    assert report_ok(run) == ['outside --files, move to the report\'s notes: F1 src/main.ts']
    open(os.path.join(out, 'findings.json'), 'w').write('{"findings": [{"id": "F1", "file": "src/a.ts"}]}')
    assert report_ok(run) == []
    run['done'].append('Report')
    assert show(run) == 'run complete'
    print('selftest ok')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
