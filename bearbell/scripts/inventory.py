#!/usr/bin/env python3
"""Route and guard inventory. No model, stdlib only. Stacks: NestJS, Express, Fastify, Koa, Hono,
FastAPI, Flask, Django, DRF, Go net/http, gin, chi, echo, fiber.

Lists every route with its guards and access decorators, inputs, the metadata keys
guards actually read, Prisma calls per file, and other entry points (jobs, webhooks, intake).
Reads source only; never runs it. Skips node_modules, dist, tests, .env* and key files.

  python3 inventory.py <backend-dir> [--json out.json] [--md out.md] [--matrix rows.md] [--ledger ledger.md]
  python3 inventory.py --check ledger.md     # lists every row or candidate still open; exit 1 if any
  python3 inventory.py --selftest
"""
import json
import os
import re
import sys

HTTP = {'Get', 'Post', 'Put', 'Patch', 'Delete', 'All', 'Options', 'Head', 'Search'}
WRITE = {'Post', 'Put', 'Patch', 'Delete', 'All'}
NOISE = {'HttpCode', 'Header', 'Redirect', 'Render', 'Version', 'Sse'}  # no access meaning
JOB_DECOS = {'Cron', 'Interval', 'Timeout', 'Process', 'Processor', 'OnEvent', 'OnQueueActive',
             'OnQueueCompleted', 'OnQueueFailed', 'EventPattern', 'MessagePattern',
             'SubscribeMessage', 'WebSocketGateway', 'OnWorkerEvent'}
ENTRY_HINTS = [  # other ways untrusted input or scheduled work gets in
    (r'\bsetInterval\(', 'timer'),
    (r'\.schedule\(\s*[\'"`\w]', 'schedule'),
    (r'\.work\(\s*[\'"`\w]', 'queue worker'),
    (r'\bnew Worker\(', 'queue worker'),
    (r'\bImapFlow\b|\bimap\b\.connect|mailparser|simpleParser\(', 'mail intake'),
    (r'\.subscribe\(\s*[\'"`]', 'subscriber'),
    (r'\bcron\.schedule\(|\bCronJob\(', 'cron'),
    (r'@(?:Query|Mutation|Subscription)\(\s*\(\s*\)\s*=>', 'graphql'),  # not the @Query('x') param decorator
    (r'@GrpcMethod\(', 'grpc'),
    (r'\b(?:io|socket|ws|wss)\s*\.\s*on\(\s*[\'"`](?!error\b|close\b|disconnect\b)', 'websocket'),
    (r'\b(?:finale|epilogue)\s*\.\s*resource\(', 'auto REST (generated routes, list each model)'),
]
PRISMA_OPS = ('findUniqueOrThrow|findFirstOrThrow|findUnique|findFirst|findMany|createMany|create|'
              'updateMany|update|upsert|deleteMany|delete|count|aggregate|groupBy')
PRISMA_RE = re.compile(r'\b(?:this\.)?(prisma|tx|db|client|trx)\.(\w+)\.(' + PRISMA_OPS + r')\(')
RAW_RE = re.compile(r'\$(queryRawUnsafe|executeRawUnsafe|queryRaw|executeRaw)\b')
SKIP_DIRS = {'node_modules', 'dist', 'build', '.git', 'coverage', 'test', 'tests', '__tests__',
             'secrets', '.next', 'out', 'venv', '__pycache__', 'vendor', 'site-packages', 'migrations'}
SKIP_FILE = re.compile(r'(\.spec|\.test|\.e2e-spec)\.[cm]?[jt]s$|\.d\.ts$|\.min\.js$|^\.env|^test_.*\.py$|'
                       r'_test\.(py|go)$|^conftest\.py$|Tests?\.java$')


def strip_comments(src):
    """Blank out comments, keep strings and newlines so offsets and line numbers stay right."""
    out, i, n = list(src), 0, len(src)
    while i < n:
        c = src[i]
        if c in '\'"`':
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == '\\' else 1
            i = j + 1
        elif src.startswith('//', i):
            j = src.find('\n', i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = ' '
            i = j
        elif src.startswith('/*', i):
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != '\n':
                    out[k] = ' '
            i = j
        else:
            i += 1
    return ''.join(out)


def skip_string(s, i):
    q, j = s[i], i + 1
    while j < len(s) and s[j] != q:
        j += 2 if s[j] == '\\' else 1
    return j + 1


def balanced(s, i, open_='(', close=')'):
    """s[i] == open_; return index just past the matching close."""
    depth, j = 0, i
    while j < len(s):
        c = s[j]
        if c in '\'"`':
            j = skip_string(s, j)
            continue
        if c == open_:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return len(s)


def line_of(s, i):
    return s.count('\n', 0, i) + 1


def first_str(args):
    m = re.search(r'[\'"`]([^\'"`]*)[\'"`]', args or '')
    return m.group(1) if m else None


DECO_RE = re.compile(r'@(\w+)\s*')


def read_decorators(s, i):
    """Read a run of decorators starting at s[i] == '@'. Return (list, index after run)."""
    decos = []
    while True:
        while i < len(s) and s[i].isspace():
            i += 1
        m = DECO_RE.match(s, i)
        if not m:
            return decos, i
        name, j = m.group(1), m.end()
        args = None
        if j < len(s) and s[j] == '(':
            k = balanced(s, j)
            args, j = s[j + 1:k - 1].strip(), k
        decos.append({'name': name, 'args': args})
        i = j


PARAM_RE = re.compile(r'@(\w+)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*(?:(?:private|readonly|public)\s+)*'
                      r'(\w+)\s*\??\s*(?::\s*([^,=)]+))?')


def parse_params(params):
    out = []
    for m in PARAM_RE.finditer(params):
        out.append({'decorator': m.group(1), 'args': m.group(2).strip() or None,
                    'name': m.group(3), 'type': (m.group(4) or '').strip() or None})
    return out


CLASS_RE = re.compile(r'(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+(\w+)'
                      r'(?:\s+extends\s+([\w.]+)(?:<[^{]*?>)?)?(?:\s+implements\s+([^{]+))?\s*\{')
METHOD_RE = re.compile(r'(?:(?:public|private|protected|static|async|override)\s+)*(\w+)\s*(?:<[^(]*?>)?\s*\(')


def scan_file(path, rel):
    try:
        raw = open(path, encoding='utf-8', errors='replace').read()
    except OSError:
        return None
    res = {'classes': [], 'meta_decorators': {}, 'meta_reads': [], 'global_guards': [],
           'prefix': None, 'prisma': [], 'entries': [], 'consts': {}}
    ext = os.path.splitext(rel)[1]
    if ext == '.py':
        res['generic'] = scan_py(strip_py_comments(raw), rel)
        return res
    s = strip_comments(raw)
    if ext in ('.go', '.java'):
        res['generic'] = (scan_go if ext == '.go' else scan_java)(s, rel)
        return res
    res['generic'] = scan_js(s, rel)

    for m in re.finditer(r'\bconst\s+(\w+)\s*=\s*[\'"`]([^\'"`]+)[\'"`]', s):
        res['consts'][m.group(1)] = m.group(2)
    # export const Public = () => SetMetadata('public', true)  /  Reflector.createDecorator
    for m in re.finditer(r'\bconst\s+(\w+)\s*=\s*(?:\([^)]*\)|\w+)\s*(?::\s*[^=]+)?=>\s*SetMetadata\(\s*([^,)]+)', s):
        res['meta_decorators'][m.group(1)] = m.group(2).strip()
    for m in re.finditer(r'\bconst\s+(\w+)\s*=\s*Reflector\.createDecorator', s):
        res['meta_decorators'][m.group(1)] = '@' + m.group(1)
    for m in re.finditer(r'\b(?:reflector|this\.reflector|Reflector)\b[\w.]*\.(?:get|getAll|getAllAndOverride|getAllAndMerge)\s*(?:<[^(]*?>)?\(\s*([^,)]+)', s):
        res['meta_reads'].append({'key': m.group(1).strip(), 'line': line_of(s, m.start())})
    # Helper wrappers, e.g. meta<boolean>('public') where meta wraps getAllAndOverride.
    for w in re.finditer(r'\bconst\s+(\w+)\s*=\s*(?:<[^>]*>)?\s*\([^)]*\)\s*=>\s*[^;]*?reflector[\w.]*\.(?:get|getAll|getAllAndOverride|getAllAndMerge)', s):
        for m in re.finditer(r'\b' + w.group(1) + r'\s*(?:<[^(]*?>)?\(\s*([^,)]+)', s[w.end():]):
            res['meta_reads'].append({'key': m.group(1).strip(), 'line': line_of(s, w.end() + m.start())})
    for m in re.finditer(r'provide\s*:\s*APP_GUARD\s*,\s*use(?:Class|Existing)\s*:\s*(\w+)', s):
        res['global_guards'].append({'guard': m.group(1), 'at': f'{rel}:{line_of(s, m.start())}'})
    for m in re.finditer(r'\.useGlobalGuards\(([^;]*)\)', s):
        for g in re.findall(r'new\s+(\w+)|\b([A-Z]\w+)\b', m.group(1)):
            res['global_guards'].append({'guard': g[0] or g[1], 'at': f'{rel}:{line_of(s, m.start())}'})
    m = re.search(r'\.setGlobalPrefix\(\s*[\'"`]([^\'"`]*)', s)
    if m:
        res['prefix'] = m.group(1)

    for m in PRISMA_RE.finditer(s):
        k = balanced(s, m.end() - 1)
        args = s[m.end():k - 1]
        res['prisma'].append({'line': line_of(s, m.start()), 'model': m.group(2), 'op': m.group(3),
                              'has_where': bool(re.search(r'\bwhere\b', args)),
                              'where': re.sub(r'\s+', ' ', args)[:160]})
    for m in RAW_RE.finditer(s):
        res['prisma'].append({'line': line_of(s, m.start()), 'model': '$raw', 'op': m.group(1),
                              'has_where': None, 'where': None})
    for pat, kind in ENTRY_HINTS:
        for m in list(re.finditer(pat, s))[:1 if kind == 'mail intake' else None]:
            res['entries'].append({'kind': kind, 'at': f'{rel}:{line_of(s, m.start())}',
                                   'text': s[m.start():s.find('\n', m.start())].strip()[:100]})

    # Walk: decorator runs followed by a class header or a member header.
    for cm in CLASS_RE.finditer(s):
        # Decorators directly above the class.
        head = s[:cm.start()]
        cdecos = []
        dm = re.search(r'((?:@\w+\s*(?:\((?:[^()]|\([^()]*\))*\))?\s*)+)$', head)
        if dm:
            cdecos, _ = read_decorators(dm.group(1), 0)
        body_start = cm.end() - 1
        body_end = balanced(s, body_start, '{', '}')
        cls = {'name': cm.group(1), 'extends': cm.group(2),
               'implements': (cm.group(3) or '').strip() or None,
               'file': rel, 'line': line_of(s, cm.start()), 'decorators': cdecos, 'methods': []}
        i = body_start + 1
        while i < body_end - 1:
            c = s[i]
            if c in '\'"`':
                i = skip_string(s, i)
                continue
            if c == '{':
                i = balanced(s, i, '{', '}')
                continue
            if c == '@':
                decos, j = read_decorators(s, i)
                mm = METHOD_RE.match(s, j)
                if mm:
                    pstart = mm.end() - 1
                    pend = balanced(s, pstart)
                    verb_at = next((line_of(s, i + k.start()) for k in re.finditer(r'@(\w+)', s[i:j])
                                    if k.group(1) in HTTP), None)
                    cls['methods'].append({'name': mm.group(1), 'line': line_of(s, j), 'verb_line': verb_at,
                                           'decorators': decos,
                                           'params': parse_params(s[pstart + 1:pend - 1])})
                    i = pend
                    continue
                i = max(j, i + 1)
                continue
            i += 1
        res['classes'].append(cls)
    return res


# ---- Other stacks: Express/Fastify/Koa/Hono, FastAPI/Flask/Django/DRF, Go net/http/gin/chi/echo/fiber.
# Same route shape as NestJS. Guards are names that look like auth (AUTHISH); paths under a mount
# (app.use('/api', router), include(), r.Mount) stay relative and the mount is listed.
AUTHISH = re.compile(r'auth|login|token|jwt|session|perm|role|admin|staff|owner|current_?user|verify|'
                     r'require|protect|guard|IsAuthenticated|signed|logged', re.I)
PUBLICISH = re.compile(r'AllowAny|\bpublic\b|anonymous|skip_?auth|no_?auth|permit_?all', re.I)
PARAMISH = re.compile(r':\w|\{\w|<\w|\(\?P<')
JS_SERVER = re.compile(r'^(app|router|\w*[Rr]outer|routes|fastify|server)$')


def split_args(a):
    """Split call arguments at top-level commas (strings and brackets respected)."""
    out, depth, start, i = [], 0, 0, 0
    while i < len(a):
        c = a[i]
        if c in '\'"`':
            i = skip_string(a, i)
            continue
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == ',' and depth == 0:
            out.append(a[start:i].strip())
            start = i + 1
        i += 1
    last = a[start:].strip()
    return out + [last] if last else out


def str_arg(a):
    m = re.fullmatch(r'r?[\'"`]([^\'"`]*)[\'"`]', a.strip())
    return m.group(1) if m else None


def call_args(s, m):
    """m ends just after '('; return (args list, index after ')')."""
    k = balanced(s, m.end() - 1)
    return split_args(s[m.end():k - 1]), k


def mw_names(arg):
    """Middleware names from one argument: ident, call, array, or a Fastify options object."""
    if arg.startswith('{'):
        hooks = re.findall(r'(?:preHandler|onRequest|preValidation|preParsing|beforeHandler)\s*:\s*(\[[^\]]*\]|[\w.]+)', arg)
        return [n for h in hooks for n in split_args(h.strip('[]'))]
    if arg.startswith('['):
        return [n for n in split_args(arg[1:-1]) if n]
    if re.match(r'(async\s+)?(function\b|\(|\w+\s*=>)', arg):
        return []  # inline handler
    return [arg[:80]]


def generic_route(method, path, handler, at, verb_at, access, inputs=(), glob=()):
    guards = [g for g in list(glob) + list(access) if AUTHISH.search(g) and not PUBLICISH.search(g)]
    is_public = any(PUBLICISH.search(a) for a in access)
    flags = []
    if not guards and not is_public:
        flags.append('no-guard')
    if is_public:
        flags.append('public-write' if method in ('POST', 'PUT', 'PATCH', 'DELETE', 'ANY', 'ALL') else 'public')
    if PARAMISH.search(path):
        flags.append('object-id')
    if re.search(r'webhook|hook|callback|inbound|notify|ipn', path, re.I):
        flags.append('webhook')
    return {'method': method, 'path': path, 'handler': handler, 'at': at, 'verb_at': verb_at,
            'guards': guards, 'access': list(access), 'inputs': list(inputs), 'flags': flags}


def scan_js(s, rel):
    """Express, Fastify, Koa router, Hono. s has comments stripped."""
    out = {'routes': [], 'mounts': [], 'stacks': set(re.findall(
        r'(?:require\(|from\s+)[\'"](express|fastify|koa-router|@koa/router|hono)[\'"]', s))}
    servers = set(re.findall(r'\b(\w+)\s*=\s*(?:express\(|express\.Router\(|Router\(|fastify\(|Fastify\(|'
                             r'new\s+(?:Router|Hono|KoaRouter)\()', s))
    if not out['stacks'] and not servers:
        return out
    out['imports'] = {m.group(1) or m.group(2): m.group(3) for m in re.finditer(
        r'(?:import\s+(?:\*\s+as\s+)?(\w+)\s+from|(?:const|let|var)\s+(\w+)\s*=\s*require\()\s*[\'"](\.[^\'"]+)[\'"]', s)}
    ok = lambda name: name in servers or JS_SERVER.match(name)
    file_mw = []
    for m in re.finditer(r'\b(\w+)\s*\.\s*(use|addHook|register)\s*\(', s):
        if not ok(m.group(1)):
            continue
        args, _ = call_args(s, m)
        at = f'{rel}:{line_of(s, m.start())}'
        if m.group(2) == 'addHook':
            if args and str_arg(args[0]) in ('onRequest', 'preHandler', 'preValidation'):
                file_mw += [a + ' (file-wide)' for a in args[1:]]
        elif m.group(2) == 'register':
            pre = re.search(r'prefix\s*:\s*[\'"`]([^\'"`]+)', ' '.join(args))
            if pre:
                out['mounts'].append({'path': pre.group(1), 'target': args[0][:60], 'at': at})
        elif args and str_arg(args[0]) is not None:
            out['mounts'].append({'path': str_arg(args[0]), 'target': ', '.join(args[1:])[:80], 'at': at})
        else:
            file_mw += [n + ' (file-wide)' for a in args for n in mw_names(a)]
    verbs = 'get|post|put|patch|delete|del|all|options|head'
    calls = []  # (pos, receiver, verb, path, rest-args)
    for m in re.finditer(r'\b(\w+)\s*\.\s*(' + verbs + r')\s*\(', s):
        args, _ = call_args(s, m)
        if ok(m.group(1)) and len(args) >= 2 and (str_arg(args[0]) or '').startswith('/'):
            calls.append((m.start(), m.group(1), m.group(2), str_arg(args[0]), args[1:]))
    for m in re.finditer(r'\b(\w+)\s*\.\s*route\s*\(\s*[\'"`](/[^\'"`]*)[\'"`]\s*\)', s):
        j = m.end()
        while (c := re.match(r'\s*\.\s*(' + verbs + r')\s*\(', s[j:])):
            cm = re.compile(r'\s*\.\s*(' + verbs + r')\s*\(').match(s, j)
            args, j = call_args(s, cm)
            calls.append((cm.start(), m.group(1), c.group(1), m.group(2), args))
    for m in re.finditer(r'\b(\w+)\s*\.\s*route\s*\(\s*\{', s):
        k = balanced(s, m.end() - 1, '{', '}')
        obj = s[m.end() - 1:k]
        meth, url = re.search(r'method\s*:\s*[\'"`](\w+)', obj), re.search(r'url\s*:\s*[\'"`]([^\'"`]+)', obj)
        if meth and url:
            calls.append((m.start(), m.group(1), meth.group(1), url.group(1), [obj]))
    for pos, recv, verb, path, rest in calls:
        handler = rest[-1] if rest else '?'
        mws = [n for a in rest[:-1] for n in mw_names(a)]
        if len(rest) == 1 and handler.startswith('{'):  # fastify.route({ method, url, preHandler, handler })
            mws = mw_names(handler)
            h = re.search(r'handler\s*:\s*([\w.$]+)|\bhandler\b\s*[,}]', handler)
            handler = (h.group(1) or 'handler') if h else '?'
        if not re.fullmatch(r'[\w.$]+', handler):
            handler = '<inline>'
        method = {'del': 'DELETE', 'all': 'ANY'}.get(verb.lower(), verb.upper())
        at = f'{rel}:{line_of(s, pos)}'
        out['routes'].append(generic_route(method, path, handler, at, at, mws, glob=file_mw))
    return out


def scan_go(s, rel):
    """net/http (incl. Go 1.22 "GET /x/{id}"), gin, chi, echo, fiber. s has comments stripped."""
    out = {'routes': [], 'mounts': [], 'stacks': set()}
    for imp, name in (('net/http', 'net/http'), ('gin-gonic/gin', 'gin'), ('go-chi/chi', 'chi'),
                      ('labstack/echo', 'echo'), ('gofiber/fiber', 'fiber'), ('gorilla/mux', 'gorilla')):
        if f'{imp}"' in s or f'{imp}/v' in s:
            out['stacks'].add(name)
    if not out['stacks']:
        return out
    blocks, stack, i = [], [], 0  # brace pairs, to scope r.Use and chi r.Route(...)
    while i < len(s):
        c = s[i]
        if c in '"`\'':
            i = skip_string(s, i)
            continue
        if c == '{':
            stack.append(i)
        elif c == '}' and stack:
            blocks.append((stack.pop(), i))
        i += 1
    inner = lambda p: max((b for b in blocks if b[0] < p < b[1]), default=(0, len(s)))
    groups = {}  # var -> (prefix, guards, parent var)
    for m in re.finditer(r'\b(\w+)\s*:?=\s*(\w+)\s*\.\s*Group\(', s):
        args, _ = call_args(s, m)
        p = str_arg(args[0]) if args else None
        if p is None:
            continue
        pp, pg, _ = groups.get(m.group(2), ('', [], None))
        groups[m.group(1)] = (join_path(pp, p), pg + args[1:], m.group(2))
    for m in re.finditer(r'\b(\w+)\s*:?=\s*(?:\w+\s*\.\s*)*?(\w+)\s*\.\s*PathPrefix\(\s*"([^"]*)"\s*\)\s*\.\s*Subrouter\(\)', s):
        pp, pg, _ = groups.get(m.group(2), ('', [], None))  # gorilla: sub := r.PathPrefix("/api").Subrouter()
        groups[m.group(1)] = (join_path(pp, m.group(3)), pg, m.group(2))
    for m in re.finditer(r'\b(\w+)\s*\.\s*PathPrefix\(\s*"([^"]*)"\s*\)\s*\.\s*(?:Handler|HandlerFunc)\(', s):
        args, _ = call_args(s, m)  # a whole subtree served by one handler, e.g. /debug/pprof/
        at = f'{rel}:{line_of(s, m.start())}'
        out['routes'].append(generic_route('ANY', join_path(groups.get(m.group(1), ('',))[0], m.group(2) + '*'),
                                           args[0] if args and re.fullmatch(r'[\w.]+', args[0]) else '<inline>', at, at, []))
    uses = []
    for m in re.finditer(r'\b(\w+)\s*\.\s*Use\(', s):
        args, _ = call_args(s, m)
        uses.append((m.group(1), m.start(), inner(m.start()), args))
    route_blocks = []
    for m in re.finditer(r'\b\w+\s*\.\s*(Route|Mount)\(\s*"([^"]*)"\s*,', s):
        if m.group(1) == 'Mount':
            out['mounts'].append({'path': m.group(2), 'target': s[m.end():s.find(')', m.end())].strip()[:60],
                                  'at': f'{rel}:{line_of(s, m.start())}'})
            continue
        b = s.find('{', m.end())
        route_blocks.append((b, balanced(s, b, '{', '}'), m.group(2)))
    ancestors = lambda v: [v] + (ancestors(groups[v][2]) if v in groups and groups[v][2] else [])
    rx = re.compile(r'\b(\w+)((?:\s*\.\s*With\([^)]*\))*)\s*\.\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any|'
                    r'Get|Post|Put|Patch|Delete|Head|Options|Handle|HandleFunc|Method|MethodFunc|HandlerFunc)\(')
    for m in rx.finditer(s):
        recv, verb = m.group(1), m.group(3)
        if recv == 'http' and verb not in ('Handle', 'HandleFunc'):
            continue
        args, end = call_args(s, m)
        method = None
        chained = re.match(r'\s*\.\s*Methods\(([^)]*)\)', s[end:])  # gorilla: .HandleFunc(...).Methods("GET")
        if verb in ('Method', 'MethodFunc'):
            if len(args) < 3:
                continue
            method = (str_arg(args[0]) or args[0].replace('http.Method', '')).upper()
            args = args[1:]
        if len(args) < 2 or not (str_arg(args[0]) or '').lstrip('ABCDEFGHIJKLMNOPQRSTUVWXYZ ').startswith('/'):
            continue
        path = str_arg(args[0])
        mm = re.match(r'([A-Z]+)\s+(/.*)', path)
        if mm:
            method, path = mm.groups()
        if chained and not method:
            method = '|'.join(x for x in re.findall(r'"(\w+)"', chained.group(1)) if x != 'OPTIONS') or None
        method = method or ('ANY' if verb in ('Handle', 'HandleFunc', 'HandlerFunc', 'Any') else verb.upper())
        handler, mws = args[-1], args[1:-1]
        while (w := re.fullmatch(r'([\w.]+)\((.+)\)', handler, re.S)) and split_args(w.group(2)):
            if w.group(1) not in ('http.HandlerFunc', 'http.Handler', 'HandlerFunc'):
                mws.append(w.group(1))
            handler = split_args(w.group(2))[0]  # the handler is the first argument
        mws += re.findall(r'With\(([^)]*)\)', m.group(2))
        chain = ancestors(recv)
        for v in chain:
            if v in groups:
                mws += groups[v][1]
        mws += [a for v, p, blk, aa in uses if v in chain and p < m.start() and blk[0] < m.start() < blk[1] for a in aa]
        prefix = groups.get(recv, ('',))[0]
        nest = [p for b, e, p in sorted(route_blocks) if b < m.start() < e]
        at = f'{rel}:{line_of(s, m.start())}'
        out['routes'].append(generic_route(method, join_path(prefix, *nest, path) if path != '/' or prefix or nest else '/',
                                           handler if re.fullmatch(r'[\w.]+', handler) else '<inline>', at, at, mws))
    return out


JAVA_MAP = re.compile(r'@(Get|Post|Put|Patch|Delete|Request)Mapping\b')
JAVA_ACCESS = re.compile(r'@(PreAuthorize|PostAuthorize|Secured|RolesAllowed|PermitAll|DenyAll)\b')


def scan_java(s, rel):
    """Spring MVC/WebFlux controllers, plus SecurityFilterChain path rules (applied in build()). s has comments stripped."""
    out = {'routes': [], 'mounts': [], 'stacks': set(), 'rules': []}
    for m in re.finditer(r'\.\s*(?:requestMatchers|antMatchers|mvcMatchers|pathMatchers)\s*\(', s):
        args, k = call_args(s, m)
        act = re.match(r'\s*\.\s*(\w+)\s*\(([^)]*)\)', s[k:])
        for a in args:
            if str_arg(a) and act:
                out['rules'].append((str_arg(a), act.group(1) + (f'({act.group(2)})' if act.group(2) else ''),
                                     f'{rel}:{line_of(s, m.start())}'))
    for m in re.finditer(r'\.\s*anyRequest\(\)\s*\.\s*(\w+)\s*\(([^)]*)\)', s):  # catch-all, checked last
        out['rules'].append(('/**', m.group(1) + (f'({m.group(2)})' if m.group(2) else '') + ' [anyRequest]',
                             f'{rel}:{line_of(s, m.start())}'))
    cls = re.search(r'\bclass\s+\w+', s)
    if not cls or not re.search(r'@(Rest)?Controller\b', s[:cls.start()]):
        return out
    out['stacks'].add('spring')
    ann_args = lambda m: call_args(s, re.compile(r'\s*\(').match(s, m.end()))[0] if re.match(r'\s*\(', s[m.end():]) else []
    def path_of(args):
        for a in args:
            kv = re.match(r'(value|path)\s*=\s*(.+)', a, re.S)
            v = kv.group(2) if kv else a if '=' not in a else ''
            p = re.search(r'"([^"]*)"', v)
            if p:
                return p.group(1)
        return ''
    head = s[:cls.start()]
    base = next((path_of(ann_args(m)) for m in JAVA_MAP.finditer(head) if m.group(1) == 'Request'), '')
    cls_access = [s[m.start():m.end()] + ''.join(f'({a})' for a in ann_args(m)) for m in JAVA_ACCESS.finditer(head)]
    for m in JAVA_MAP.finditer(s, cls.end()):
        args = ann_args(m)
        verb = m.group(1).upper()
        if verb == 'REQUEST':
            verb = '|'.join(re.findall(r'RequestMethod\.(\w+)', ' '.join(args))) or 'ANY'
        start = max(s.rfind(';', 0, m.start()), s.rfind('}', 0, m.start()), s.rfind('{', 0, m.start())) + 1
        after = balanced(s, s.index('(', m.end())) if re.match(r'\s*\(', s[m.end():]) else m.end()
        sig = re.compile(r'(?:\s*@\w+(?:\s*\([^()]*(?:\([^()]*\)[^()]*)*\))?)*[\w<>\[\],.?\s]*?\b(\w+)\s*\(').match(s, after)
        if not sig:
            continue
        params = s[sig.end():balanced(s, sig.end() - 1) - 1]
        access = cls_access + [s[a.start():a.end()] + ''.join(f'({x})' for x in ann_args(a))
                               for a in JAVA_ACCESS.finditer(s, start, sig.start(1))]
        inputs = [re.sub(r'\s+', ' ', x.strip())[:80] for x in split_args(params)
                  if re.search(r'@(RequestBody|PathVariable|RequestParam|RequestHeader|ModelAttribute)', x)]
        at = f'{rel}:{line_of(s, sig.start(1))}'
        out['routes'].append(generic_route(verb, join_path(base, path_of(args)), sig.group(1), at,
                                           f'{rel}:{line_of(s, m.start())}', access, inputs))
    return out


PY_VERBS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'route', 'api_route', 'websocket'}
HTTP_NAMES = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options'}


def scan_py(src, rel):
    """FastAPI, Flask, Django, DRF, via ast. Routes found here; Django url() views resolved in build()."""
    import ast
    out = {'routes': [], 'mounts': [], 'stacks': set(), 'views': {}, 'urls': [], 'routers': {}, 'global': [], 'imports': {}}
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return out
    u = ast.unparse
    name_of = lambda f: f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ''
    const = lambda n: n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else None
    deps = lambda n: [u(c) for c in ast.walk(n) if isinstance(c, ast.Call) and name_of(c.func) in ('Depends', 'Security')] if n else []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                out['imports'][a.asname or a.name] = (node.level, node.module or '', a.name)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            fn, kw = name_of(node.value.func), {k.arg: k.value for k in node.value.keywords}
            if fn in ('APIRouter', 'Blueprint', 'FastAPI', 'Flask'):
                out['stacks'].add('fastapi' if fn in ('APIRouter', 'FastAPI') else 'flask')
                pre = const(kw.get('prefix') or kw.get('url_prefix') or ast.Constant(''))
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        out['routers'][t.id] = (pre or '', deps(kw.get('dependencies')))
                if fn == 'FastAPI':
                    out['global'] += deps(kw.get('dependencies'))
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'REST_FRAMEWORK' for t in node.targets) \
                and isinstance(node.value, ast.Dict):
            for k, v in zip(node.value.keys, node.value.values):
                if const(k) == 'DEFAULT_PERMISSION_CLASSES':
                    out['global'] += [const(e) or u(e) for e in getattr(v, 'elts', [])]
        if isinstance(node, ast.ClassDef):
            attrs = {t.id: u(st.value) for st in node.body if isinstance(st, ast.Assign)
                     for t in st.targets if isinstance(t, ast.Name)}
            meths = sorted(f.name.upper() for f in node.body
                           if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and f.name in HTTP_NAMES)
            out['views'].setdefault(node.name, []).append({'at': f'{rel}:{node.lineno}', 'methods': meths,
                                       'access': [u(d) for d in node.decorator_list] +
                                       [u(b) for b in node.bases if re.search(r'Mixin|Required|Permission', u(b))] +
                                       [f'{k}={v}' for k, v in attrs.items() if k in ('permission_classes', 'authentication_classes')] +
                                       sorted({u(d) for f in node.body if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
                                               and f.name in HTTP_NAMES for d in f.decorator_list})})
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            route = next((d for d in node.decorator_list if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                          and d.func.attr in PY_VERBS and d.args and const(d.args[0]) is not None), None)
            others = [u(d) for d in node.decorator_list if d is not route]
            api_view = next((d for d in node.decorator_list if isinstance(d, ast.Call) and name_of(d.func) == 'api_view'), None)
            meths = [const(e) for e in getattr(api_view.args[0], 'elts', [])] if api_view and api_view.args else []
            out['views'].setdefault(node.name, []).append({'at': f'{rel}:{node.lineno}', 'methods': meths, 'access': others})
            if route:
                kw = {k.arg: k.value for k in route.keywords}
                verb = route.func.attr
                method = ('WS' if verb == 'websocket' else verb.upper() if verb in HTTP_NAMES else
                          '|'.join(const(e) or '?' for e in getattr(kw.get('methods'), 'elts', [])) or 'GET')
                recv = name_of(route.func.value)
                pre, rdeps = out['routers'].get(recv, ('', []))
                inputs = [f"{a.arg}: {u(a.annotation) if a.annotation else '?'}" for a in node.args.args + node.args.kwonlyargs]
                access = others + rdeps + deps(kw.get('dependencies')) + deps(node.args)
                out['routes'].append(generic_route(method, join_path(pre, const(route.args[0])) if const(route.args[0]) else pre or '/',
                                                   node.name, f'{rel}:{node.lineno}', f'{rel}:{route.lineno}', access, inputs))
        if isinstance(node, ast.Call) and len(node.args) >= 2 and const(node.args[0]) is not None:
            fn = name_of(node.func)
            if fn in ('path', 're_path', 'url', 'register'):
                view = node.args[1]
                if isinstance(view, ast.Call) and name_of(view.func) == 'include':
                    out['mounts'].append({'path': const(node.args[0]), 'target': u(view)[:60], 'at': f'{rel}:{node.lineno}',
                                          'module': const(view.args[0]) if view.args else None})
                    continue
                out['stacks'].add('drf' if fn == 'register' else 'django')
                if isinstance(view, ast.Call) and name_of(view.func) == 'as_view':
                    view = view.func.value
                out['urls'].append({'path': const(node.args[0]), 'view': name_of(view) or u(view)[:40],
                                    'mod': name_of(view.value) if isinstance(view, ast.Attribute) else None,
                                    'regex': fn in ('re_path', 'url'), 'drf_router': fn == 'register', 'at': f'{rel}:{node.lineno}'})
            elif fn == 'add_url_rule':
                vf = next((k.value for k in node.keywords if k.arg == 'view_func'), node.args[2] if len(node.args) > 2 else None)
                out['urls'].append({'path': const(node.args[0]), 'view': name_of(vf) if vf else '?', 'drf_router': False,
                                    'at': f'{rel}:{node.lineno}'})
        if isinstance(node, ast.Call) and name_of(node.func) in ('include_router', 'register_blueprint'):
            pre = next((const(k.value) for k in node.keywords if k.arg in ('prefix', 'url_prefix')), None)
            if pre and node.args:
                out['mounts'].append({'path': pre, 'target': u(node.args[0])[:60], 'at': f'{rel}:{node.lineno}'})
    return out


def strip_py_comments(src):
    import io, tokenize
    lines = src.split('\n')
    try:
        for t in tokenize.generate_tokens(io.StringIO(src).readline):
            if t.type == tokenize.COMMENT:
                r, c = t.start
                lines[r - 1] = lines[r - 1][:c] + ' ' * (len(lines[r - 1]) - c)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return '\n'.join(lines)


def walk(root):
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not x.startswith('.'))
        for f in sorted(files):
            if os.path.splitext(f)[1] in ('.ts', '.js', '.mjs', '.cjs', '.py', '.go', '.java') and not SKIP_FILE.search(f):
                p = os.path.join(d, f)
                yield p, os.path.relpath(p, root)


def join_path(*parts):
    segs = [p.strip('/') for p in parts if p and p.strip('/')]
    return '/' + '/'.join(segs)


def build(root):
    files = {rel: r for p, rel in walk(root) if (r := scan_file(p, rel))}
    consts = {}
    for r in files.values():
        consts.update(r['consts'])
    resolve = lambda k: consts.get(k, k.strip('\'"`'))

    meta_decos = {}  # decorator name -> metadata key
    for r in files.values():
        for name, key in r['meta_decorators'].items():
            meta_decos[name] = resolve(key)
    read_keys = {resolve(x['key']) for r in files.values() for x in r['meta_reads']}
    read_keys |= {'@' + n for n in meta_decos if meta_decos[n].startswith('@')
                  and any(x['key'].strip() == n for r in files.values() for x in r['meta_reads'])}
    global_guards = [g for r in files.values() for g in r['global_guards']]
    prefix = next((r['prefix'] for r in files.values() if r['prefix']), None)
    guard_classes = {c['name']: f"{c['file']}:{c['line']}" for r in files.values()
                     for c in r['classes'] if c['implements'] and 'CanActivate' in c['implements']}
    uses_roles = any(d['name'] in meta_decos and 'role' in d['name'].lower()
                     for r in files.values() for c in r['classes']
                     for m in [c] + c['methods'] for d in m['decorators'])

    routes, jobs = [], []
    for r in files.values():
        for c in r['classes']:
            cnames = {d['name'] for d in c['decorators']}
            ctrl = next((d for d in c['decorators'] if d['name'] == 'Controller'), None)
            for m in c['methods']:
                names = {d['name'] for d in m['decorators']}
                for d in m['decorators']:
                    if d['name'] in JOB_DECOS:
                        jobs.append({'kind': d['name'], 'args': d['args'], 'handler': f"{c['name']}.{m['name']}",
                                     'at': f"{c['file']}:{m['line']}"})
                if not ctrl:
                    continue
                verb = next((d for d in m['decorators'] if d['name'] in HTTP), None)
                if not verb:
                    continue
                cpath = first_str(ctrl['args']) or ''
                if ctrl['args'] and 'path' in ctrl['args']:
                    cpath = first_str(re.search(r'path\s*:\s*([^,}]+)', ctrl['args']).group(1)) or cpath
                path = join_path(prefix, cpath, first_str(verb['args']) or '')
                both = c['decorators'] + m['decorators']
                guards = [g['guard'] + ' (global)' for g in global_guards]
                for d in both:
                    if d['name'] == 'UseGuards':
                        guards += [g.strip() for g in re.split(r',(?![^(]*\))', d['args'] or '') if g.strip()]
                access = [('@' + d['name'] + (f"({d['args']})" if d['args'] else ''))
                          for d in both if d['name'] not in HTTP | NOISE | {'Controller', 'UseGuards'}
                          and not d['name'].startswith('Api')]
                keys = {meta_decos[d['name']] for d in both if d['name'] in meta_decos}
                is_public = any(re.search(r'public|skipauth|anonymous|noauth', k + n, re.I)
                                for k, n in [(meta_decos.get(d['name'], ''), d['name']) for d in both])
                has_role = any('role' in d['name'].lower() for d in both)
                inputs = [f"{p['decorator']}({p['args'] or ''}) {p['name']}: {p['type'] or '?'}"
                          for p in m['params']]
                flags = []
                if not guards and not is_public:
                    flags.append('no-guard')
                if is_public and verb['name'] in WRITE:
                    flags.append('public-write')
                elif is_public:
                    flags.append('public')
                if re.search(r':\w+', path) or any(p['decorator'] == 'Param' for p in m['params']):
                    flags.append('object-id')
                if uses_roles and not has_role and not is_public:
                    flags.append('no-role')
                for k in keys:
                    if k not in read_keys:
                        flags.append(f'unread-meta:{k}')
                if any(p['decorator'] == 'Body' and (not p['type'] or p['type'] in ('any', 'object', 'unknown'))
                       for p in m['params']):
                    flags.append('untyped-body')
                if any(p['decorator'] in ('Req', 'Request') for p in m['params']):
                    flags.append('raw-req')
                if re.search(r'webhook|hook|callback|inbound|notify|ipn', path, re.I):
                    flags.append('webhook')
                routes.append({'method': verb['name'].upper(), 'path': path,
                               'handler': f"{c['name']}.{m['name']}", 'at': f"{c['file']}:{m['line']}",
                               'verb_at': f"{c['file']}:{m['verb_line']}", 'guards': guards, 'access': access, 'inputs': inputs, 'flags': flags})

    gen_by = {rel: r['generic'] for rel, r in files.items() if r.get('generic')}
    gen = list(gen_by.values())
    py_global = [g + ' (global)' for x in gen for g in x.get('global', [])]
    views = {}
    for x in gen:
        for k, vs in x.get('views', {}).items():
            views.setdefault(k, []).extend(vs)
    fdir = lambda rel: os.path.dirname(rel)
    by_stem = lambda stem: [f for f in files if os.path.splitext(f)[0] == stem or f.endswith('/' + stem + '.py')
                            or os.path.splitext(f)[0] == stem + '/index' or f == stem + '/__init__.py']

    def py_target(rel, level, module):  # dotted module seen from rel -> path stem
        if not level:
            return module.replace('.', '/')
        d = fdir(rel)
        for _ in range(level - 1):
            d = os.path.dirname(d)
        return os.path.normpath(os.path.join(d, module.replace('.', '/'))) if module else d

    def pick_view(url, rel):  # the view the url file imports, not just the first with that name
        cands = views.get(url['view'], [])
        imps = gen_by[rel].get('imports', {})
        key = url['mod'] or url['view']
        stem = None
        if key in imps:
            lvl, mod, nm = imps[key]
            stem = py_target(rel, lvl, '.'.join(x for x in (mod, nm if url['mod'] else '') if x))
        pref = [c for c in cands if stem and c['at'].split(':')[0] in by_stem(stem)] or \
               [c for c in cands if fdir(c['at'].split(':')[0]) == fdir(rel)] or cands
        return pref[0] if pref else {}

    # Mount prefixes: app.use('/x', router) and path('x/', include('app.urls')) prefix every route in the target file.
    targets = []
    for rel, x in gen_by.items():
        for mt in x['mounts']:
            if mt.get('module'):
                t = by_stem(mt['module'].replace('.', '/'))
            else:
                ref = x.get('imports', {}).get(mt['target'].split(',')[-1].strip()) or \
                    (re.search(r'require\([\'"](\.[^\'"]+)', mt['target']) or [None, None])[1]
                t = by_stem(os.path.normpath(os.path.join(fdir(rel), ref))) if ref else []
            if t:
                targets.append((rel, mt['path'], sorted(t, key=lambda f: -len(os.path.commonprefix([f, rel])))[0]))
    file_pre = {}
    for _ in range(6):  # nested includes, a few levels deep
        for rel, mp, t in targets:
            if t != rel:
                file_pre[t] = join_path(file_pre.get(rel, ''), mp)
    clean = lambda p: re.sub(r'\(\?P<(\w+)>[^)]*\)', r'{\1}', re.sub(r'^\^|\$$', '', p or ''))
    rules = sorted((r for x in gen for r in x.get('rules', [])), key=lambda r: '[anyRequest]' in r[1])

    def spring_rule(path):  # Spring takes the first matching rule
        for pat, act, at in rules:
            rx = re.escape(pat).replace(r'\*\*', '.*').replace(r'\*', '[^/]*')
            if re.fullmatch(rx, path) or re.fullmatch(rx, path + '/'):
                return [f'security {pat} {act} ({at})']
        return []
    for rel, x in gen_by.items():
        pre = file_pre.get(rel, '')
        for rt in x['routes']:
            path = join_path(pre, rt['path']) if pre else rt['path']
            extra = spring_rule(path) if rel.endswith('.java') else []
            if py_global and rel.endswith('.py') or pre or extra:
                rt.update(generic_route(rt['method'], path, rt['handler'], rt['at'], rt['verb_at'],
                                        rt['access'] + extra, rt['inputs'], py_global if rel.endswith('.py') else ()))
            routes.append(rt)
        for url in x.get('urls', []):
            v = pick_view(url, rel)
            method = '|'.join(v.get('methods') or []) or 'ANY'
            path = join_path(pre, clean(url['path']) if url.get('regex') else url['path'] or '')
            if url['drf_router']:
                path = join_path(path, '{pk}')  # ViewSets also serve detail routes by id
            routes.append(generic_route(method, path, url['view'], v.get('at', url['at']), url['at'],
                                        v.get('access', []), glob=py_global))
    stacks = sorted({st for x in gen for st in x['stacks']} | ({'nestjs'} if any(
        d['name'] == 'Controller' for r in files.values() for c in r['classes'] for d in c['decorators']) else set()))
    mounts = [mt for x in gen for mt in x['mounts']]

    unread = sorted(n for n, k in meta_decos.items() if k not in read_keys)
    prisma = [dict(x, at=f'{rel}:{x["line"]}') for rel, r in files.items() for x in r['prisma']]
    for x in prisma:
        x.pop('line')
        x['flag'] = ('raw-unsafe' if 'Unsafe' in x['op'] else 'raw' if x['model'] == '$raw'
                     else 'no-where' if not x['has_where'] and x['op'] in
                     ('findMany', 'updateMany', 'deleteMany', 'count', 'aggregate', 'groupBy') else None)
    return {
        'root': os.path.basename(os.path.abspath(root)),
        'files_scanned': len(files),
        'stacks': stacks,
        'mounts': mounts,
        'global_prefix': prefix,
        'global_guards': global_guards,
        'guard_classes': guard_classes,
        'access_decorators': meta_decos,
        'metadata_keys_read': sorted(read_keys),
        'decorators_never_read': unread,
        'routes': sorted(routes, key=lambda r: (r['path'], r['method'])),
        'jobs': jobs,
        'other_entry_points': [e for r in files.values() for e in r['entries']],
        'prisma_calls': prisma,
    }


def to_md(inv):
    L = [f"# Route inventory: {inv['root']}", '',
         f"{len(inv['routes'])} routes, {len(inv['jobs'])} decorated jobs, "
         f"{len(inv['other_entry_points'])} other entry points, {len(inv['prisma_calls'])} Prisma calls, "
         f"{inv['files_scanned']} files.", '',
         'Stacks: ' + (', '.join(inv['stacks']) or 'none found: list routes by reading the code'),
         'Mounts (paths below are relative to these): ' + (', '.join(f"{m['path']} → {m['target']} ({m['at']})" for m in inv['mounts']) or 'none'),
         'Global guards: ' + (', '.join(f"{g['guard']} ({g['at']})" for g in inv['global_guards']) or 'none'),
         'Guard classes: ' + (', '.join(f'{k} ({v})' for k, v in inv['guard_classes'].items()) or 'none'),
         'Access decorators → key: ' + (', '.join(f'@{k} → {v}' for k, v in inv['access_decorators'].items()) or 'none'),
         'Decorators no guard reads: ' + (', '.join('@' + d for d in inv['decorators_never_read']) or 'none'),
         '', '| Method | Path | Handler | Access | Flags |', '|---|---|---|---|---|']
    for r in inv['routes']:
        L.append(f"| {r['method']} | `{r['path']}` | {r['at']} | {' '.join(r['access']) or '-'} | {' '.join(r['flags']) or '-'} |")
    if inv['jobs'] or inv['other_entry_points']:
        L += ['', '## Jobs and other entry points', '']
        L += [f"- {j['kind']}({j['args'] or ''}) {j['handler']} ({j['at']})" for j in inv['jobs']]
        L += [f"- {e['kind']}: `{e['text']}` ({e['at']})" for e in inv['other_entry_points']]
    flagged = [p for p in inv['prisma_calls'] if p['flag']]
    if flagged:
        L += ['', '## Prisma calls to look at', '']
        L += [f"- {p['flag']}: {p['model']}.{p['op']} ({p['at']})" for p in flagged]
    L += ['', 'Flags are pointers for the tracer, not findings.']
    return '\n'.join(L) + '\n'


def to_matrix(inv):
    """Draft access matrix rows, one per route. Every row starts as a guess for the owner to confirm."""
    L = ['| Action | Route | Who (from code) | Object | Own only | Owner says | Confirmed |',
         '|---|---|---|---|---|---|---|']
    for r in inv['routes']:
        roles = [a for a in r['access'] if 'role' in a.lower()]
        who = ('anyone (public)' if 'public' in ' '.join(r['flags']) else
               ' '.join(roles) if roles else 'any signed-in user')
        obj = next((seg for seg in reversed(r['path'].split('/')) if seg and not seg.startswith(':')), '-')
        own = 'yes?' if 'object-id' in r['flags'] else '-'
        L.append(f"| {r['handler']} | {r['method']} `{r['path']}` | {who} | {obj} | {own} | guess | |")
    for j in inv['jobs']:
        L.append(f"| {j['handler']} | job {j['kind']} | system | - | - | guess | |")
    return '\n'.join(L) + '\n'


LEDGER_HEAD = '| Feature (file) | Entry point | At | Tracer | Candidates |'
CAND_HEAD = '| ID | Sink (file:line) | Kind | Routes | Merged into | Verdict | Status |'


def to_ledger(inv):
    """The run's own checklist: one row per entry point, grouped by file. The session fills the
    blanks as it goes and `--check` refuses to call the run done while any are left."""
    rows = [(r['at'].rsplit(':', 1)[0], f"{r['method']} {r['path']}", r['at']) for r in inv['routes']]
    rows += [(j['at'].rsplit(':', 1)[0], f"job {j['kind']} {j['handler']}", j['at']) for j in inv['jobs']]
    rows += [(e['at'].rsplit(':', 1)[0], f"{e['kind']}: {e['text']}", e['at']) for e in inv['other_entry_points']]
    L = ['# bearbell ledger', '',
         'Tracer: the tracer id(s) that put this row in `routes_checked`, or `skip: <why>`.',
         'Candidates: their ids, or `none`. Add rows for entry points found by reading.', '',
         LEDGER_HEAD, '|---|---|---|---|---|']
    L += [f"| {f} | `{e.replace('|', '/')}` | {at} |  |  |" for f, e, at in sorted(rows)]  # a | would split the row
    L += ['', '## Candidates', '',
          'One row per tracer candidate, never deleted. Merged into: the id it joined, or `-`.',
          'Verdict: stands, knocked_down or unsure. Status: finding, unconfirmed, dropped, intended or merged.', '',
          CAND_HEAD, '|---|---|---|---|---|---|---|']
    return '\n'.join(L) + '\n'


def check_ledger(text):
    """Open items: entry rows with no tracer or candidates, candidates with no verdict or status."""
    open_, table = [], None
    for line in text.splitlines():
        if line.startswith('| Feature'):
            table = 'entry'
        elif line.startswith('| ID |'):
            table = 'cand'
        elif line.startswith('|') and not line.startswith('|---') and table:
            c = [x.strip() for x in line.strip().strip('|').split('|')]
            if table == 'entry' and len(c) >= 5 and not (c[3] and c[4]):
                open_.append(f"not traced: {c[1]} ({c[2]})")
            if table == 'cand' and len(c) >= 7 and not (c[6] and (c[5] or c[6] == 'merged')):
                open_.append(f"no verdict: {c[0]} {c[1]}")
    return open_


def selftest():
    import tempfile
    files = {
        'src/http.ts': """
            import { SetMetadata } from '@nestjs/common';
            export const IS_PUBLIC = 'isPublic';
            export const Public = () => SetMetadata(IS_PUBLIC, true);
            export const Roles = (...r: string[]) => SetMetadata('roles', r);
            export const Audit = () => SetMetadata('audit', true); // nobody reads this
            @Injectable()
            export class AuthGuard implements CanActivate {
              constructor(private reflector: Reflector) {}
              canActivate(ctx) {
                if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [ctx.getHandler()])) return true;
                const roles = this.reflector.get('roles', ctx.getHandler()); // '{' in a string
                return true;
              }
            }""",
        'src/app.module.ts': """
            @Module({ providers: [{ provide: APP_GUARD, useClass: AuthGuard }] })
            export class AppModule {}
            app.setGlobalPrefix('v1');""",
        'src/items.controller.ts': """
            @Controller('items')
            export class ItemsController {
              constructor(private readonly prisma: PrismaService) {}
              /* @Get('commented-out') */
              @Get(':id')
              @Roles('member')
              get(@Param('id') id: string, @CurrentUser() u: User) {
                return this.prisma.item.findUnique({ where: { id } });
              }
              @Post()
              @Public()
              @HttpCode(201)
              make(@Body() body: any) { const s = "}"; return this.prisma.item.findMany(); }
              @Delete(':id')
              @Audit()
              remove(@Param('id') id: string) {}
            }""",
        'src/jobs.ts': """
            export class Jobs { @Cron('0 * * * *') hourly() {} }
            boss.work('lead.parse', handler);""",
        'src/items.resolver.ts': """
            @Resolver(() => Item)
            export class ItemsResolver {
              @Query(() => [Item]) items(@Args('q') q: string) {}
              @Mutation(() => Item) addItem() {}
              @GrpcMethod('Items', 'Get') get() {}
            }""",
        'src/items.controller.spec.ts': "@Controller('ignored') class X { @Get() a() {} }",
    }
    with tempfile.TemporaryDirectory() as d:
        for rel, text in files.items():
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, 'w').write(text)
        inv = build(d)
    by = {(r['method'], r['path']): r for r in inv['routes']}
    assert set(by) == {('GET', '/v1/items/:id'), ('POST', '/v1/items'), ('DELETE', '/v1/items/:id')}, by.keys()
    g, p, x = by[('GET', '/v1/items/:id')], by[('POST', '/v1/items')], by[('DELETE', '/v1/items/:id')]
    assert g['guards'] == ['AuthGuard (global)'] and 'object-id' in g['flags'] and 'no-role' not in g['flags'], g
    assert g['at'] == 'src/items.controller.ts:8' and g['verb_at'].endswith(':6'), g
    assert "@Roles('member')" in g['access'] and any('CurrentUser' in i for i in g['inputs']), g
    assert 'public-write' in p['flags'] and 'untyped-body' in p['flags'] and 'no-role' not in p['flags'], p
    assert 'no-role' in x['flags'] and 'unread-meta:audit' in x['flags'], x
    assert inv['decorators_never_read'] == ['Audit'], inv['decorators_never_read']
    assert inv['access_decorators']['Public'] == 'isPublic'
    assert [j['kind'] for j in inv['jobs']] == ['Cron']
    assert any(e['kind'] == 'queue worker' for e in inv['other_entry_points'])
    kinds = [e['kind'] for e in inv['other_entry_points']]
    assert kinds.count('graphql') == 2 and kinds.count('grpc') == 1, kinds
    nw = [c for c in inv['prisma_calls'] if c['flag'] == 'no-where']
    assert len(nw) == 1 and nw[0]['model'] == 'item', inv['prisma_calls']
    assert '| DELETE |' in to_md(inv)
    mx = to_matrix(inv)
    assert 'anyone (public)' in mx and "@Roles('member')" in mx and mx.count('| guess |') == 4, mx
    led = to_ledger(inv)
    assert len(check_ledger(led)) == 8, check_ledger(led)  # 3 routes, 1 job, 1 worker, 2 graphql, 1 grpc: all open
    led = led.replace('|  |  |', '| T1 | none |', 7) + '| F1 | src/a.ts:3 | object | GET /x | - | stands |  |\n'
    led += '| F2 | src/a.ts:3 | object | GET /y | F1 |  | merged |\n'
    assert check_ledger(led) == ["not traced: `queue worker: .work('lead.parse', handler)` (src/jobs.ts:3)", 'no verdict: F1 src/a.ts:3'], check_ledger(led)
    selftest_stacks()
    print('selftest ok')


def selftest_stacks():
    import tempfile
    files = {
        'express/server.js': """
            const express = require('express');
            const app = express();
            const router = express.Router();
            app.use(helmet());
            app.use('/api', router);
            const erase = require('./routes/erase');
            app.use('/erase', erase);
            router.get('/users/:id', requireAuth, (req, res) => res.json({}));
            router.post('/login', login);
            app.route('/orders').get(isLoggedIn, listOrders).post(createOrder);
            axios.get('/api/x', cfg);  // a client call, not a route
            // app.get('/commented', x);
            """,
        'express/routes/erase.js': """
            const express = require('express');
            const r = express.Router();
            r.get('/', showErase);
            module.exports = r;
            """,
        'api/urls.py': """
from . import views
urlpatterns = [path('dash/', views.dash), path('v2/', include('api.v2.urls'))]
""",
        'api/views.py': """
@login_required
def dash(request):
    pass
""",
        'api/v2/urls.py': """
from api.v2 import views as v
urlpatterns = [re_path(r'^orders/(?P<order_id>\\d+)$', v.order)]
""",
        'api/v2/views.py': "def order(request):\n    pass\n",
        'go/mux.go': """
package main
import "github.com/gorilla/mux"
func routes() {
    r := mux.NewRouter()
    r.PathPrefix("/debug/").Handler(http.DefaultServeMux)
    r.HandleFunc("/posts", Auth(getPosts, db)).Methods("GET", "OPTIONS")
    s := r.PathPrefix("/v1").Subrouter()
    s.HandleFunc("/x", getX).Methods("POST")
}
""",
        'java/AuthController.java': """
@RestController
@RequestMapping("/auth")
public class AuthController {
  @PostMapping("/login")
  public ResponseEntity<?> login(@Valid @RequestBody LoginForm form) { return null; }
  @PreAuthorize("hasRole('ADMIN')")
  @GetMapping(value = "/users/{id}")
  public User get(@PathVariable Long id) { return null; }
  @RequestMapping(path = "/me", method = RequestMethod.PUT)
  public User me() { return null; }
}
""",
        'java/Sec.java': """
class Sec { void f(HttpSecurity http) {
  http.authorizeHttpRequests(r -> r.requestMatchers("/auth/login").permitAll().anyRequest().authenticated());
} }
""",
        'fast/app.js': """
            import Fastify from 'fastify';
            const fastify = Fastify();
            fastify.get('/items/:id', { preHandler: [fastify.authenticate] }, getItem);
            fastify.route({ method: 'DELETE', url: '/items/:id', handler: del });
            """,
        'py/api.py': """
from fastapi import APIRouter, Depends
router = APIRouter(prefix='/notes', dependencies=[Depends(get_db)])
@router.get('/{note_id}')
async def read_note(note_id: int, user=Depends(get_current_user)):
    return {}
@router.post('/')  # no auth here
def make_note(body: dict):
    return {}
""",
        'py/flaskapp.py': """
from flask import Flask
app = Flask(__name__)
@app.route('/admin/<int:uid>', methods=['POST'])
@login_required
def admin_edit(uid):
    pass
@app.get('/health')
def health():
    pass
""",
        'dj/urls.py': """
from django.urls import path, include
urlpatterns = [
    path('profile/<int:pk>/', views.ProfileView.as_view()),
    path('open/', views.open_page),
    path('api/', include('api.urls')),
]
router.register(r'invoices', InvoiceViewSet)
""",
        'dj/views.py': """
class ProfileView(LoginRequiredMixin, View):
    def get(self, request, pk): pass
    def post(self, request, pk): pass
def open_page(request):
    pass
class InvoiceViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]
def dash(request):
    pass
""",
        'dj/test_views.py': "path('ignored/', x)",
        'go/main.go': """
package main
import (
    "net/http"
    "github.com/gin-gonic/gin"
)
func main() {
    http.HandleFunc("/ping", ping)
    http.Handle("GET /files/{id}", authMiddleware(http.HandlerFunc(getFile)))
    r := gin.Default()
    r.POST("/signup", signup)
    api := r.Group("/api", AuthRequired())
    api.GET("/users/:id", getUser)
    resp, _ := http.Get("https://example.com/")
}
""",
        'go/chi.go': """
package main
import "github.com/go-chi/chi/v5"
func routes() {
    r := chi.NewRouter()
    r.Get("/", home)
    r.Route("/admin", func(r chi.Router) {
        r.Use(AdminOnly)
        r.Delete("/users/{id}", deleteUser)
    })
}
""",
    }
    with tempfile.TemporaryDirectory() as d:
        for rel, text in files.items():
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, 'w').write(text)
        inv = build(d)
    by = {(r['method'], r['path']): r for r in inv['routes']}
    want = {('GET', '/users/:id'), ('POST', '/login'), ('GET', '/orders'), ('POST', '/orders'),
            ('GET', '/items/:id'), ('DELETE', '/items/:id'),
            ('GET', '/notes/{note_id}'), ('POST', '/notes'), ('POST', '/admin/<int:uid>'), ('GET', '/health'),
            ('GET|POST', '/profile/<int:pk>'), ('ANY', '/open'), ('ANY', '/invoices/{pk}'),
            ('ANY', '/ping'), ('GET', '/files/{id}'), ('POST', '/signup'), ('GET', '/api/users/:id'),
            ('GET', '/'), ('DELETE', '/admin/users/{id}'), ('GET', '/erase'), ('ANY', '/api/dash'),
            ('ANY', '/api/v2/orders/{order_id}'), ('ANY', '/debug/*'), ('GET', '/posts'), ('POST', '/v1/x'),
            ('POST', '/auth/login'), ('GET', '/auth/users/{id}'), ('PUT', '/auth/me')}
    assert set(by) == want, (set(by) - want, want - set(by))
    assert inv['stacks'] == ['chi', 'django', 'drf', 'express', 'fastapi', 'fastify', 'flask', 'gin', 'gorilla', 'net/http', 'spring'], inv['stacks']
    ok = lambda k: 'no-guard' not in by[k]['flags']
    assert ok(('GET', '/users/:id')) and 'object-id' in by[('GET', '/users/:id')]['flags']
    assert by[('GET', '/users/:id')]['at'] == 'express/server.js:9' and by[('GET', '/users/:id')]['handler'] == '<inline>'
    assert not ok(('POST', '/login')) and ok(('GET', '/orders')) and not ok(('POST', '/orders'))
    assert ok(('GET', '/items/:id')) and not ok(('DELETE', '/items/:id'))
    assert ok(('GET', '/notes/{note_id}')) and not ok(('POST', '/notes')), by[('POST', '/notes')]
    assert by[('GET', '/notes/{note_id}')]['at'] == 'py/api.py:5' and by[('GET', '/notes/{note_id}')]['verb_at'] == 'py/api.py:4'
    assert ok(('POST', '/admin/<int:uid>')) and not ok(('GET', '/health'))
    assert ok(('GET|POST', '/profile/<int:pk>')) and by[('GET|POST', '/profile/<int:pk>')]['at'] == 'dj/views.py:2'
    assert not ok(('ANY', '/open')) and ok(('ANY', '/invoices/{pk}'))
    assert not ok(('ANY', '/ping')) and ok(('GET', '/files/{id}')) and by[('GET', '/files/{id}')]['handler'] == 'getFile'
    assert not ok(('POST', '/signup')) and ok(('GET', '/api/users/:id'))
    assert not ok(('GET', '/')) and ok(('DELETE', '/admin/users/{id}'))
    assert {m['path'] for m in inv['mounts']} == {'/api', 'api/', '/erase', 'v2/'}, inv['mounts']
    assert by[('ANY', '/api/dash')]['at'] == 'api/views.py:3' and ok(('ANY', '/api/dash'))  # the imported view, not dj/views.py
    assert by[('ANY', '/api/v2/orders/{order_id}')]['at'] == 'api/v2/views.py:1'
    assert ok(('GET', '/posts')) and not ok(('POST', '/v1/x')) and not ok(('ANY', '/debug/*'))
    assert 'public-write' in by[('POST', '/auth/login')]['flags'] and ok(('PUT', '/auth/me'))
    assert ok(('GET', '/auth/users/{id}')) and by[('GET', '/auth/users/{id}')]['handler'] == 'get'
    assert any('PreAuthorize' in a for a in by[('GET', '/auth/users/{id}')]['access'])
    assert by[('POST', '/auth/login')]['inputs'] == ['@Valid @RequestBody LoginForm form']


def main(argv):
    if '--selftest' in argv:
        return selftest()
    if '--check' in argv:
        left = check_ledger(open(argv[argv.index('--check') + 1]).read())
        print('\n'.join(left) or 'ledger complete')
        sys.exit(1 if left else 0)
    args = [a for a in argv if not a.startswith('--')]
    if not args:
        sys.exit(__doc__)
    inv = build(args[0])
    opt = lambda k: next((argv[i + 1] for i, a in enumerate(argv) if a == k and i + 1 < len(argv)), None)
    if opt('--json'):
        json.dump(inv, open(opt('--json'), 'w'), indent=1)
    md = to_md(inv)
    if opt('--md'):
        open(opt('--md'), 'w').write(md)
    if opt('--matrix'):
        open(opt('--matrix'), 'w').write(to_matrix(inv))
    if opt('--ledger'):
        open(opt('--ledger'), 'w').write(to_ledger(inv))
    if not any(opt(k) for k in ('--json', '--md', '--matrix', '--ledger')):
        print(md)
    else:
        print(f"{len(inv['routes'])} routes, {len(inv['jobs'])} jobs, "
              f"{len(inv['other_entry_points'])} other entry points, {len(inv['prisma_calls'])} Prisma calls")


if __name__ == '__main__':
    main(sys.argv[1:])
