#!/usr/bin/env python3
"""Score review runs against a ground-truth file. Stdlib only.

  python3 score.py truth.json run1.json [run2.json ...]
  python3 score.py --files src/a.ts,src/b.ts truth.json run1.json   # quick run: only these files count
  python3 score.py --selftest

truth.json: {"target": "...", "ref": "<sha>", "vulns": [{"id", "file", "line", "cwe", "also_lines"?, "cwe_alt"?}],
             "traps": [{"file", "line", "note"}]}          # traps: safe code that looks unsafe
run.json:   {"tool": "...", "tokens": 12345, "cost_usd": 0.4,
             "findings": [{"file", "line", "cwe", "status"?, "of"?}]}  # or raw Semgrep --json output
A finding with "of": "file:line" is an extra entry point of the sink finding at that file:line. If it
hits a vuln itself it counts; if not, it is neither hit nor alarm when its sink hit a vuln or is also_real, else an alarm.
Findings with status "unconfirmed" are scored apart: they never count as found or as false alarms;
the table shows how many there were and how many of them hit a known vuln.
A finding matches a vuln when the file path ends the same, the line is within 10 and the CWE
is equal or in the same family (FAMILIES; a finding without a CWE matches on file and line only).
A vuln's optional "also_lines" are other lines of the same hole (its sink, the constant that sets it),
"also_at" ["file:line"] the same hole in another file (the service sink of a controller's vuln),
"cwe_alt" other CWEs reviewers fairly give it; all are set by reading the code, never from one tool's run.
"""
import json
import re
import sys

WINDOW = 10
# CWEs reviewers use for the same hole; a finding in the vuln's family counts as a match.
FAMILIES = [{'284', '285', '639', '862', '863', '566', '932'},        # access control / IDOR
            {'287', '306', '345', '347', '290', '1390', '798', '321'},  # auth, tokens, JWT, hard-coded keys
            {'74', '77', '78', '88'}, {'89', '564', '943'},             # command / SQL, NoSQL
            {'79', '80', '116'}, {'22', '23', '36', '73'},              # XSS / path
            {'200', '201', '209', '213', '359', '497'},                 # data exposure
            {'915', '1321', '20'}, {'400', '770', '799', '307'}]        # mass assignment / rate limits


def norm_cwe(c):
    m = re.search(r'(\d+)', str(c or ''))
    return m.group(1) if m else None


def same_cwe(a, b):
    return a == b or any(a in f and b in f for f in FAMILIES)


def same_file(a, b):
    a, b = a.strip('./'), b.strip('./')
    return a.endswith(b) or b.endswith(a)


def load_run(path):
    d = json.load(open(path))
    if 'results' in d and 'findings' not in d:  # raw Semgrep JSON
        d = {'tool': 'semgrep', 'tokens': 0, 'findings': [
            {'file': r['path'], 'line': r['start']['line'],
             'cwe': (r.get('extra', {}).get('metadata', {}).get('cwe') or [None])[0]}
            for r in d['results']]}
    return d


def hits_vuln(f, fl, fc, v):
    lines = [int(v['line'])] + [int(x) for x in v.get('also_lines', [])]
    cwes = [norm_cwe(v.get('cwe'))] + [norm_cwe(c) for c in v.get('cwe_alt', [])]
    at = [(v['file'], x) for x in lines] + [(a.rpartition(':')[0], int(a.rpartition(':')[2])) for a in v.get('also_at', [])]
    return (any(same_file(f['file'], af) and abs(fl - al) <= WINDOW for af, al in at)
            and (not fc or any(same_cwe(fc, c) for c in cwes if c)))


def only_files(truth, files):
    """Quick runs review a few files: keep the truth rows in them and score no finding outside them."""
    keep = lambda rows: [r for r in rows if any(same_file(r['file'], f) for f in files)]
    return dict(truth, vulns=keep(truth['vulns']), traps=keep(truth.get('traps', [])),
                also_real=keep(truth.get('also_real', [])), only=files)


def score(truth, run):
    hits, alarms, traps_hit, extra, unconf, unconf_true = set(), 0, 0, 0, 0, 0
    skip = ['/' + d.strip('/') + '/' for d in truth.get('skip_dirs', [])]
    near_rows = lambda g, rows: any(same_file(g['file'], r['file']) and abs(int(g.get('line') or 0) - int(r['line'])) <= WINDOW
                                    for r in truth.get(rows, []))
    sink_hit = lambda ref: any(not g.get('of') and g.get('status') != 'unconfirmed' and same_file(g['file'], ref.rpartition(':')[0])
                               and int(g.get('line') or 0) == int(ref.rpartition(':')[2] or 0)
                               and (any(hits_vuln(g, int(g['line']), norm_cwe(g.get('cwe')), v) for v in truth['vulns'])
                                    or (near_rows(g, 'also_real') and not near_rows(g, 'traps')))
                               for g in run['findings'])
    for f in run['findings']:
        if any(d in '/' + f['file'].lstrip('./') for d in skip):
            continue  # outside the reviewed code (e.g. the client): not scored
        if truth.get('only') and not any(same_file(f['file'], x) for x in truth['only']):
            continue  # quick run: outside the chosen files
        fl, fc = int(f.get('line') or 0), norm_cwe(f.get('cwe'))
        match = [v for v in truth['vulns'] if hits_vuln(f, fl, fc, v)]
        if f.get('status') == 'unconfirmed':
            unconf += 1
            unconf_true += bool(match)
            continue
        if match:  # one finding credits one vuln: the nearest, so overlapping windows don't inflate
            hits.add(min(match, key=lambda v: abs(fl - int(v['line'])))['id'])
            continue
        if f.get('of') and sink_hit(f['of']):
            continue  # another way into a hole that was found (or is real but undocumented): not a second alarm
        near = lambda rows: near_rows(f, rows)
        if near('traps'):  # a trap beats also_real: flagging safe code is an alarm
            alarms += 1
            traps_hit += 1
        elif near('also_real'):  # real but undocumented: neither hit nor alarm (CWE not checked)
            extra += 1
        else:
            alarms += 1
    found = len(hits)
    tokens = run.get('tokens') or 0
    return {'tool': run.get('tool', '?'), 'found': found, 'missed': len(truth['vulns']) - found,
            'false_alarms': alarms, 'traps_hit': traps_hit, 'extra_real': extra,
            'unconfirmed': unconf, 'unconfirmed_true': unconf_true,
            'tokens_per_true': round(tokens / found) if found else None,
            'cost_per_true': round(run['cost_usd'] / found, 3) if found and run.get('cost_usd') else None,
            'found_ids': sorted(hits)}


def table(truth, scores):
    L = [f"{truth['target']} @ {truth.get('ref', '?')[:10]}: {len(truth['vulns'])} known vulns, "
         f"{len(truth.get('traps', []))} traps", '',
         '| Tool | Run | Found | Missed | False alarms | Traps hit | Undocumented real | Unconfirmed (true) '
         '| Tokens / true | Cost / true |', '|---|---|---|---|---|---|---|---|---|---|']
    for i, s in enumerate(scores, 1):
        L.append(f"| {s['tool']} | {i} | {s['found']} | {s['missed']} | {s['false_alarms']} | "
                 f"{s['traps_hit']} | {s['extra_real']} | {s['unconfirmed']} ({s['unconfirmed_true']}) | "
                 f"{s['tokens_per_true'] or '-'} | {s['cost_per_true'] or '-'} |")
    by_tool = {}
    for s in scores:
        by_tool.setdefault(s['tool'], []).append(s)
    L += ['', '| Tool | Runs | Found min-max | Found every run |', '|---|---|---|---|']
    for tool, ss in by_tool.items():
        always = set.intersection(*(set(s['found_ids']) for s in ss))
        L.append(f"| {tool} | {len(ss)} | {min(s['found'] for s in ss)}-{max(s['found'] for s in ss)} | {len(always)} |")
    return '\n'.join(L)


def selftest():
    truth = {'target': 't', 'ref': 'abc', 'vulns': [
        {'id': 'V1', 'file': 'src/a.ts', 'line': 20, 'cwe': 'CWE-639'},
        {'id': 'V2', 'file': 'src/b.ts', 'line': 5, 'cwe': 'CWE-89', 'also_at': ['src/s.ts:20']},
        {'id': 'V3', 'file': 'src/e.ts', 'line': 10, 'cwe': 'CWE-347', 'cwe_alt': ['CWE-327'], 'also_lines': [90]}],
        'traps': [{'file': 'src/c.ts', 'line': 50, 'note': 'looks raw, is parameterised'}],
        'also_real': [{'file': 'src/d.ts', 'line': 3, 'note': 'undocumented'},
                      {'file': 'src/c.ts', 'line': 45, 'note': 'next to the trap'}]}
    truth['skip_dirs'] = ['client']
    run = {'tool': 'bearbell', 'tokens': 1000, 'cost_usd': 0.5, 'findings': [
        {'file': 'repo/src/a.ts', 'line': 27, 'cwe': 'CWE-639'},   # hit V1
        {'file': 'src/b.ts', 'line': 5, 'cwe': 'CWE-79'},          # wrong CWE: alarm
        {'file': 'src/c.ts', 'line': 52},                          # trap
        {'file': 'src/a.ts', 'line': 40, 'cwe': '639'},            # too far: alarm
        {'file': 'src/a.ts', 'line': 15, 'cwe': 'CWE-862'},        # same family as 639: hit V1
        {'file': 'src/c.ts', 'line': 49},                          # near trap and also_real: trap wins
        {'file': 'src/d.ts', 'line': 4},                           # undocumented real: not an alarm
        {'file': 'client/x.ts', 'line': 1},                        # outside scope: ignored
        {'file': 'src/e.ts', 'line': 95, 'cwe': 'CWE-327'},        # alt line + alt CWE: hit V3
        {'file': 'src/z.ts', 'line': 1, 'status': 'unconfirmed'},  # unconfirmed: not an alarm
        {'file': 'src/b.ts', 'line': 5, 'cwe': 'CWE-89', 'status': 'unconfirmed'},  # unconfirmed, true: not found
        {'file': 'src/r.ts', 'line': 7, 'cwe': 'CWE-639', 'of': 'src/a.ts:27'},    # entry point of hit V1: ignored
        {'file': 'src/r.ts', 'line': 9, 'cwe': 'CWE-89', 'of': 'src/b.ts:5'},      # its sink was an alarm: alarm
        {'file': 'src/r.ts', 'line': 30, 'cwe': 'CWE-89', 'of': 'src/d.ts:4'}]}    # its sink is undocumented real: ignored
    s = score(truth, run)
    assert (s['found'], s['missed'], s['false_alarms'], s['traps_hit'], s['extra_real']) == (2, 1, 5, 2, 1), s
    assert s['tokens_per_true'] == 500 and s['cost_per_true'] == 0.25, s
    assert (s['unconfirmed'], s['unconfirmed_true']) == (2, 1), s
    sem = {'results': [{'path': 'src/b.ts', 'start': {'line': 6},
                        'extra': {'metadata': {'cwe': ['CWE-89: SQL Injection']}}}]}
    import os, tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
        json.dump(sem, f)
    s2 = score(truth, load_run(f.name))
    os.unlink(f.name)
    assert s2['found_ids'] == ['V2'] and s2['tool'] == 'semgrep', s2
    assert '| bearbell | 1 |' in table(truth, [s])
    q = score(only_files(truth, ['src/a.ts']), run)  # quick run on one file: V1 only, b/c/d/e findings ignored
    assert (q['found'], q['missed'], q['false_alarms']) == (1, 0, 1), q  # r.ts entries are outside a.ts
    x = score(truth, {'findings': [{'file': 'src/s.ts', 'line': 22, 'cwe': 'CWE-89'}]})
    assert x['found_ids'] == ['V2'] and x['false_alarms'] == 0, x  # sink in another file: also_at
    print('selftest ok')


def main(argv):
    if '--selftest' in argv:
        return selftest()
    if len(argv) < 2:
        sys.exit(__doc__)
    files = None
    if argv[0] == '--files':
        files, argv = argv[1].split(','), argv[2:]
    truth = json.load(open(argv[0]))
    if files:
        truth = only_files(truth, files)
    print(table(truth, [score(truth, load_run(p)) for p in argv[1:]]))


if __name__ == '__main__':
    main(sys.argv[1:])
