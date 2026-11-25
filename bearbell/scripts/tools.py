#!/usr/bin/env python3
"""Run the security tools bearbell relies on and write one summary. Stdlib only.

Never prints secret values: gitleaks runs with --redact and secret fields are dropped from
every result before writing. Tools that are not installed are skipped and listed as skipped.

  python3 tools.py <repo> --tier commit|full [--base REF] [--out DIR]
  python3 tools.py --selftest

commit tier: gitleaks on staged changes, OSV-Scanner only if a lockfile changed, Semgrep on
changed files. full tier: gitleaks over history, trufflehog (verified only), OSV-Scanner,
Semgrep on the whole repo.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

LOCKFILES = ('package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml',
             'bun.lock', 'Podfile.lock', 'Gemfile.lock', 'poetry.lock', 'requirements.txt',
             'go.sum', 'Cargo.lock', 'composer.lock')
CODE_EXT = ('.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java', '.kt',
            '.swift', '.rb', '.php', '.yml', '.yaml', '.json', '.tf', 'Dockerfile')
SECRET_KEYS = {'Secret', 'Match', 'Raw', 'RawV2', 'Redacted', 'secret', 'match', 'lines', 'line'}
SEMGREP_CONFIG = os.environ.get('BEARBELL_SEMGREP_CONFIG', 'p/default')


def sh(cmd, cwd, timeout=900):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, '', 'timeout'


def scrub(x):
    """Drop every field that can hold a secret value, at any depth."""
    if isinstance(x, dict):
        return {k: scrub(v) for k, v in x.items() if k not in SECRET_KEYS}
    if isinstance(x, list):
        return [scrub(v) for v in x]
    return x


def changed_files(repo, base):
    if base:
        _, out, _ = sh(['git', 'diff', '--name-only', '--diff-filter=ACMR', f'{base}...HEAD'], repo)
        names = set(out.split())
    else:
        names = set()
    for args in (['--cached'], []):
        _, out, _ = sh(['git', 'diff', '--name-only', '--diff-filter=ACMR'] + args, repo)
        names |= set(out.split())
    if not names and not base:
        _, out, _ = sh(['git', 'diff', '--name-only', '--diff-filter=ACMR', 'HEAD~1', 'HEAD'], repo)
        names = set(out.split())
    return sorted(n for n in names if os.path.isfile(os.path.join(repo, n)))


def gitleaks(repo, tier, tmp):
    rep = os.path.join(tmp, 'gitleaks.json')
    cmd = ['gitleaks', 'git', '--redact', '--no-banner', '--exit-code', '0',
           '--report-format', 'json', '--report-path', rep]
    if tier == 'commit':
        cmd += ['--pre-commit', '--staged']
    code, _, err = sh(cmd + ['.'], repo)
    if code != 0:
        return {'error': err.strip()[-300:]}
    rows = json.load(open(rep)) if os.path.getsize(rep) else []
    return {'findings': [{'rule': r.get('RuleID'), 'at': f"{r.get('File')}:{r.get('StartLine')}",
                          'commit': (r.get('Commit') or '')[:10]} for r in rows]}


def trufflehog(repo, tier, tmp):
    code, out, err = sh(['trufflehog', 'git', f'file://{os.path.abspath(repo)}', '--results=verified',
                         '--json', '--no-update'], repo, timeout=1800)
    if code not in (0, 183):
        return {'error': err.strip()[-300:]}
    rows = []
    for line in out.splitlines():
        try:
            r = scrub(json.loads(line))
        except ValueError:
            continue
        git = r.get('SourceMetadata', {}).get('Data', {}).get('Git', {})
        rows.append({'rule': r.get('DetectorName'), 'verified': r.get('Verified'),
                     'at': f"{git.get('file')}:{git.get('line')}", 'commit': (git.get('commit') or '')[:10]})
    return {'findings': rows}


def osv(repo, tier, tmp, changed):
    if tier == 'commit' and not any(os.path.basename(f) in LOCKFILES for f in changed):
        return {'skipped': 'no lockfile changed'}
    code, out, err = sh(['osv-scanner', 'scan', 'source', '-r', '--format', 'json',
                         '--allow-no-lockfiles', '.'], repo)
    if code not in (0, 1):
        return {'error': err.strip()[-300:]}
    try:
        data = json.loads(out or '{}')
    except ValueError:
        return {'error': 'unreadable output'}
    rows = []
    for res in data.get('results', []):
        src = res.get('source', {}).get('path', '')
        for pkg in res.get('packages', []):
            p = pkg.get('package', {})
            for v in pkg.get('vulnerabilities', []):
                sev = next((g.get('max_severity') for g in pkg.get('groups', [])
                            if v.get('id') in g.get('ids', [])), None)
                rows.append({'rule': v.get('id'), 'package': f"{p.get('name')}@{p.get('version')}",
                             'severity': sev or v.get('database_specific', {}).get('severity'),
                             'summary': (v.get('summary') or '')[:120],
                             'at': os.path.relpath(src, os.path.abspath(repo)) if src else None})
    return {'findings': rows}


def semgrep(repo, tier, tmp, changed):
    targets = ['.'] if tier == 'full' else [f for f in changed if f.endswith(CODE_EXT)]
    if not targets:
        return {'skipped': 'no changed code files'}
    code, out, err = sh(['semgrep', 'scan', '--config', SEMGREP_CONFIG, '--metrics=off', '--json',
                         '--quiet', '--disable-version-check'] + targets, repo, timeout=1800)
    if code not in (0, 1):
        return {'error': err.strip()[-300:]}
    try:
        data = json.loads(out or '{}')
    except ValueError:
        return {'error': 'unreadable output'}
    rows = [{'rule': r.get('check_id'), 'at': f"{r.get('path')}:{r.get('start', {}).get('line')}",
             'severity': r.get('extra', {}).get('severity'),
             'message': (r.get('extra', {}).get('message') or '')[:160]} for r in data.get('results', [])]
    return {'findings': rows, 'config': SEMGREP_CONFIG}


def run(repo, tier, base=None, out=None):
    out = out or os.path.join(tempfile.gettempdir(), 'bearbell-' + os.path.basename(os.path.abspath(repo)))
    os.makedirs(out, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix='bearbell-')
    changed = changed_files(repo, base) if tier == 'commit' else []
    plan = [('gitleaks', lambda: gitleaks(repo, tier, tmp))]
    if tier == 'full':
        plan.append(('trufflehog', lambda: trufflehog(repo, tier, tmp)))
    plan += [('osv-scanner', lambda: osv(repo, tier, tmp, changed)),
             ('semgrep', lambda: semgrep(repo, tier, tmp, changed))]
    summary = {'tier': tier, 'changed_files': changed, 'tools': {}}
    for name, fn in plan:
        summary['tools'][name] = fn() if shutil.which(name) else {'skipped': 'not installed'}
    shutil.rmtree(tmp, ignore_errors=True)
    summary = scrub(summary)
    path = os.path.join(out, f'tools-{tier}.json')
    json.dump(summary, open(path, 'w'), indent=1)
    for name, r in summary['tools'].items():
        state = (f"{len(r['findings'])} findings" if 'findings' in r
                 else f"skipped ({r['skipped']})" if 'skipped' in r else f"error: {r['error']}")
        print(f'{name:12} {state}')
    print(f'changed files: {len(changed)}' if tier == 'commit' else '', path, sep='\n' if tier == 'commit' else '')
    return summary


def selftest():
    leak = {'RuleID': 'aws', 'Secret': 'AKIA-REAL', 'Match': 'key=AKIA-REAL',
            'nested': [{'Raw': 'x', 'ok': 1}], 'File': 'a.ts'}
    clean = scrub(leak)
    assert 'AKIA-REAL' not in json.dumps(clean) and clean['nested'] == [{'ok': 1}], clean
    with tempfile.TemporaryDirectory() as d:
        sh(['git', 'init', '-q'], d)
        sh(['git', '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '--allow-empty', '-m', 'a'], d)
        open(os.path.join(d, 'package-lock.json'), 'w').write('{}')
        open(os.path.join(d, 'x.ts'), 'w').write('export const a = 1;\n')
        sh(['git', 'add', '.'], d)
        assert changed_files(d, None) == ['package-lock.json', 'x.ts'], changed_files(d, None)
        assert osv(d, 'commit', d, ['x.ts']) == {'skipped': 'no lockfile changed'}
        assert semgrep(d, 'commit', d, ['README.md']) == {'skipped': 'no changed code files'}
    print('selftest ok')


def main(argv):
    if '--selftest' in argv:
        return selftest()
    opt = lambda k, d=None: next((argv[i + 1] for i, a in enumerate(argv) if a == k and i + 1 < len(argv)), d)
    pos = [a for i, a in enumerate(argv) if not a.startswith('--') and (i == 0 or argv[i - 1] not in
                                                                         ('--tier', '--base', '--out'))]
    tier = opt('--tier', 'commit')
    if not pos or tier not in ('commit', 'full'):
        sys.exit(__doc__)
    run(pos[0], tier, opt('--base'), opt('--out'))


if __name__ == '__main__':
    main(sys.argv[1:])
