#!/usr/bin/env python3
"""bearbell entrypoints: list every source file with generic entry-point signals, so the AI answers one row per file.

  entrypoints.py <repo> --md OUT/files.md [--json OUT/files.json] [--files a,b,c]
  entrypoints.py --check OUT/files.md      (exit 1 while any row is unanswered)
  entrypoints.py --selftest
No per-framework parsers: add a regex to SIGNALS to cover a new stack. Stdlib only.
"""
import argparse, json, os, re, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from inventory import SKIP_DIRS, SKIP_FILE, strip_comments

SRC_EXT = {'.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java', '.kt', '.rb', '.php', '.cs',
           '.rs', '.ex', '.exs', '.scala', '.swift', '.dart'}
CFG_NAMES = {'routes.rb', 'urls.py', 'serverless.yml', 'serverless.yaml', 'firestore.rules', 'storage.rules',
             'database.rules.json', 'vercel.json', 'wrangler.toml'}
EXTRA_SKIP = re.compile(r'/__tests__/|_spec\.rb$|Test\.php$|\.Tests\.cs$|\.pb\.go$|_pb2\.py$|\.g\.dart$|\.d\.ts$|\.min\.js$')
SECRET = re.compile(r'(^|/)\.env|\.(pem|key|p12|pfx|crt|cer|jks|keystore)$|(^|/)id_(rsa|ed25519|ecdsa)$')
HASH_LANGS = {'.py', '.rb', '.ex', '.exs', '.php', '.sql'}  # strip_comments only knows // and /* */
VERBS = 'GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS'

# signal kind -> regex (matched on comment-stripped source). Extend here.
SIGNALS = {k: re.compile(v, re.M) for k, v in {
    'http-route': r"@(Get|Post|Put|Patch|Delete|All|\w*Mapping)\b|@\w+\.(route|get|post|put|patch|delete)\(|"
                  r"\.(get|post|put|patch|delete|all|use|GET|POST|PUT|PATCH|DELETE|Handle)\(\s*['\"`]/|HandleFunc|"
                  r"\bpath\(\s*r?['\"]|re_path\(|^\s*(get|post|put|patch|delete|match)\s+['\"]|^\s*resources?\s+:|Route::",
    'next-route': r"^\s*export\s+(async\s+)?function\s+(%s)\b|^\s*export\s+const\s+(%s)\s*=" % (VERBS, VERBS),
    'server-action': r"['\"]use server['\"]",
    'trpc': r"publicProcedure|protectedProcedure|\b(createTRPCRouter|initTRPC)\b|\.(query|mutation)\(\s*(async\s*)?\(",
    'graphql': r"@Resolver|@Query\(|@Mutation\(|@Subscription\(|\btype\s+(Query|Mutation)\b",
    'grpc': r"@GrpcMethod|@GrpcStreamMethod|\brpc\s+\w+\s*\(",
    'websocket': r"@WebSocketGateway|@SubscribeMessage|\bio\.on\(|\.on\(\s*['\"]connection",
    'job-queue': r"@Processor|@Cron\(|@KafkaListener|@SqsListener|@RabbitListener|new Worker\(|\.subscribe\(|\bconsumer\b",
    'serverless': r"exports\.handler|def lambda_handler|export\s+default\s*\{\s*(async\s+)?fetch|^\s*handler:",
    'webhook': r"/[\w/:{}\[\]-]*webhook",
    'db-rules': r"^\s*match\s+/|\ballow\s+(read|write|get|list|create|update|delete)\b|\"\.(read|write)\"|"
                r"create\s+policy|enable\s+row\s+level\s+security",
    'cli-entry': r"if __name__ == .__main__.|\bfunc main\(",  # weak
}.items()}
SIGNALS['db-rules'] = re.compile(SIGNALS['db-rules'].pattern, re.M | re.I)
SIGNALS['webhook'] = re.compile(SIGNALS['webhook'].pattern, re.M | re.I)
NEXT_PATH = re.compile(r'(^|/)app/(.*/)?route\.[jt]sx?$|(^|/)pages/api/')


def git_files(root):
    r = subprocess.run(['git', '-C', root, 'ls-files', '-z'], capture_output=True, text=True)
    return r.stdout.split('\0') if r.returncode == 0 else None


def all_files(root):
    out = git_files(root)
    if out is None:
        out = []
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.startswith('.')]
            out += [os.path.relpath(os.path.join(d, f), root) for f in files]
    return sorted(p for p in out if p and os.path.isfile(os.path.join(root, p)))


def read(path):
    try:
        if os.path.getsize(path) > 1_000_000:
            return ''
        return open(path, encoding='utf-8', errors='replace').read()
    except OSError:
        return ''


def wanted(rel, root):
    """True when this file should get a row (and be opened)."""
    parts = rel.split('/')
    name, ext = parts[-1], os.path.splitext(parts[-1])[1].lower()
    if SECRET.search(rel) or any(p.startswith('.') for p in parts[:-1]):
        return False
    if ext == '.sql':  # RLS lives in migrations, so that dir is allowed for sql only
        if any(p in SKIP_DIRS - {'migrations'} for p in parts[:-1]):
            return False
        t = read(os.path.join(root, rel)).lower()
        return 'create policy' in t or 'enable row level security' in t
    if any(p in SKIP_DIRS for p in parts[:-1]) or SKIP_FILE.search(name) or EXTRA_SKIP.search(rel):
        return False
    return ext in SRC_EXT or name in CFG_NAMES


def signals(rel, text):
    ext = os.path.splitext(rel)[1].lower()
    if ext in HASH_LANGS:
        text = re.sub(r'^\s*(#|//|--).*$', '', text, flags=re.M)
    elif ext in SRC_EXT or ext == '.dart':
        try:
            text = strip_comments(text)
        except Exception:
            pass
    found = [k for k, rx in SIGNALS.items() if rx.search(text)]
    if NEXT_PATH.search(rel) and 'next-route' not in found:
        found.append('next-route')
    if 'webhook' in rel.lower() and 'webhook' not in found:
        found.append('webhook')
    if os.path.basename(rel) in CFG_NAMES and not found:
        found.append('route-config')
    return found


def scan(root, only=None):
    rows = []
    for rel in all_files(root):
        if only is not None and rel not in only:
            continue
        if wanted(rel, root):
            rows.append((rel, signals(rel, read(os.path.join(root, rel)))))
    return rows


def route_commands(root):
    has = lambda f: os.path.exists(os.path.join(root, f))
    cmds = []
    if has('Gemfile') and has('config/routes.rb'):
        cmds.append('bin/rails routes')
    if has('artisan'):
        cmds.append('php artisan route:list')
    if any('spring-boot' in read(os.path.join(root, f)) for f in ('pom.xml', 'build.gradle', 'build.gradle.kts') if has(f)):
        cmds.append('GET /actuator/mappings (if actuator on)')
    if any(f.startswith('next.config.') for f in os.listdir(root)):
        cmds.append('.next/server/app-paths-manifest.json after next build')
    if has('manage.py'):
        cmds.append('python manage.py show_urls (django-extensions)')
    return cmds


def cell(s):
    return s.replace('|', '/').replace('\n', ' ')


def write_md(path, root, rows):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    lines = ['# bearbell files',
             'For every file: Entry point `yes` or `no`. yes -> Ways in lists each route/handler/rule with its guard '
             '(or `none`). no with signals -> Note says why.',
             'Route table commands: ' + (', '.join('`%s`' % c for c in route_commands(root)) or 'none'), '',
             '| # | File | Signals | Entry point | Ways in (route, guard) | Note |', '|---|---|---|---|---|---|']
    for i, (rel, sig) in enumerate(rows, 1):
        lines.append('| %d | %s | %s |  |  |  |' % (i, cell(rel), ', '.join(sig)))
    open(path, 'w').write('\n'.join(lines) + '\n')


def check(path):
    """Return the list of open-row messages (empty = complete)."""
    open_rows = []
    for line in open(path, encoding='utf-8'):
        c = [x.strip() for x in line.strip().strip('|').split('|')]
        if len(c) < 6 or not c[0].isdigit():
            continue
        _, f, sig, ep, ways, note = c[:6]
        ep = ep.strip('`').lower()
        if ep == '':
            open_rows.append('open: %s (entry point blank)' % f)
        elif ep not in ('yes', 'no'):
            open_rows.append('open: %s (entry point must be yes or no, got %r)' % (f, ep))
        elif ep == 'yes' and not ways:
            open_rows.append('open: %s (yes but Ways in blank)' % f)
        elif ep == 'no' and sig and not note:
            open_rows.append('re-ask: %s (signals: %s)' % (f, sig))
    return open_rows


def selftest():
    files = {
        'app/api/x/route.ts': 'export async function GET(req) { return Response.json({}) }\n',
        'config/routes.rb': "Rails.application.routes.draw do\n  get '/health', to: 'h#i'\n  resources :users\nend\n",
        'routes/web.php': "<?php\nRoute::get('/a', [A::class, 'i']);\n",
        'src/app.js': "const app = require('express')();\napp.post('/login', h);\n// app.get('/old', x)\n",
        'src/util.ts': 'export const add = (a: number, b: number) => a + b;\n',
        'src/a.spec.ts': "app.get('/t', x)\n",
        'node_modules/p/index.js': "app.get('/n', x)\n",
        '.env': 'SECRET=1\n',
        'firestore.rules': 'service cloud.firestore { match /users/{id} { allow read: if true; } }\n',
        'db/policy.sql': 'alter table t enable row level security;\n',
        'db/plain.sql': 'select 1;\n',
    }
    with tempfile.TemporaryDirectory() as d:
        for p, t in files.items():
            os.makedirs(os.path.dirname(os.path.join(d, p)), exist_ok=True)
            open(os.path.join(d, p), 'w').write(t)
        got = dict(scan(d))
        assert 'next-route' in got['app/api/x/route.ts']
        assert 'http-route' in got['config/routes.rb']
        assert 'http-route' in got['routes/web.php']
        assert 'http-route' in got['src/app.js']
        assert got['src/util.ts'] == []
        assert 'db-rules' in got['firestore.rules'] and 'db-rules' in got['db/policy.sql']
        assert not any(k in got for k in ('src/a.spec.ts', 'node_modules/p/index.js', '.env', 'db/plain.sql'))
        assert dict(scan(d, {'src/util.ts', 'src/a.spec.ts'})) == {'src/util.ts': []}
        md = os.path.join(d, 'out', 'files.md')
        write_md(md, d, scan(d))
        assert len(check(md)) == len(got)  # every row blank
        assert 'rails routes' not in open(md).read()
        rows = {}
        for i, line in enumerate(open(md)):
            if line.startswith('| ') and line.split('|')[1].strip().isdigit():
                rows[line.split('|')[2].strip()] = i

        def edit(cells):  # cells: file -> (ep, ways, note)
            ls = open(md).read().split('\n')
            for f, (ep, ways, note) in cells.items():
                c = ls[rows[f]].split('|')
                c[4], c[5], c[6] = ' %s ' % ep, ' %s ' % ways, ' %s ' % note
                ls[rows[f]] = '|'.join(c)
            open(md, 'w').write('\n'.join(ls))
        edit({'src/app.js': ('yes', '', ''), 'src/util.ts': ('maybe', '', '')})
        out = check(md)
        assert any('src/app.js' in o and 'Ways in' in o for o in out) and any('src/util.ts' in o for o in out)
        edit({'src/app.js': ('yes', 'POST /login / none', ''), 'src/util.ts': ('no', '', ''),
              'config/routes.rb': ('no', '', '')})
        out = check(md)
        assert any(o.startswith('re-ask: config/routes.rb') for o in out), out
        assert not any('src/app.js' in o or 'src/util.ts' in o for o in out)
        done = {f: ('no', '', 'x') if got[f] else ('no', '', '') for f in got}
        done['src/app.js'] = ('yes', 'POST /login | none', '')
        edit(done)
        assert check(md) == [], check(md)
    print('selftest ok')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('repo', nargs='?')
    ap.add_argument('--md')
    ap.add_argument('--json')
    ap.add_argument('--files')
    ap.add_argument('--check')
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.check:
        out = check(a.check)
        print('\n'.join(out) if out else 'files complete')
        sys.exit(1 if out else 0)
    if not a.repo or not a.md:
        ap.error('need <repo> --md OUT/files.md')
    root = os.path.abspath(a.repo)
    only = {f.strip() for f in a.files.split(',') if f.strip()} if a.files else None
    rows = scan(root, only)
    write_md(a.md, root, rows)
    if a.json:
        os.makedirs(os.path.dirname(os.path.abspath(a.json)), exist_ok=True)
        json.dump([{'file': f, 'signals': s} for f, s in rows], open(a.json, 'w'), indent=1)
    print('%d files, %d with signals' % (len(rows), sum(1 for _, s in rows if s)))


if __name__ == '__main__':
    main()
