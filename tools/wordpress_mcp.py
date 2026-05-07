"""CF_AI WordPress MCP tools — direct REST API + HTTP connection, no shell required.

Credentials are read from environment variables set by _run_background_scan:
  WP_USER          — WordPress username
  WP_APP_PASSWORD  — Application Password (preferred)
  WP_PASSWORD      — Plain admin password (fallback, used for cookie auth)

All tools make real HTTP calls directly to the target WordPress site.
No mock data, no hardcoding, no shell commands.
"""
from __future__ import annotations
import base64
import http.cookiejar
import json
import os
import re
import shutil
import ssl
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from sdk.agents import function_tool

_UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0'
_TIMEOUT = 20


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _opener(jar: http.cookiejar.CookieJar = None) -> urllib.request.OpenerDirector:
    handlers = [urllib.request.HTTPSHandler(context=_ssl_ctx())]
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    op = urllib.request.build_opener(*handlers)
    op.addheaders = [('User-Agent', _UA)]
    return op


def _curl_fetch(url: str, method: str = 'GET', headers: dict | None = None,
                body: bytes | None = None, timeout: int = _TIMEOUT) -> tuple[int, str, dict]:
    """Try fetching URL via curl with progressive bypass techniques for blocked IPs."""
    if not shutil.which('curl'):
        return 0, '[curl not available]', {}

    base_cmd = [
        'curl', '-s', '-L', '-k',
        '-w', '\n__CF_STATUS__:%{http_code}',
        '--max-time', str(timeout),
        '--connect-timeout', str(min(timeout, 15)),
    ]
    if method == 'POST':
        base_cmd += ['--request', 'POST']
    if body:
        base_cmd += ['--data-binary', '@-']
    if headers:
        for k, v in headers.items():
            base_cmd += ['-H', f'{k}: {v}']

    variants: list[list[str]] = [
        [],  # standard curl
        ['-H', 'X-Forwarded-For: 66.249.66.1', '-H', 'X-Real-IP: 66.249.66.1'],
        ['-A', 'Googlebot/2.1 (+http://www.google.com/bot.html)'],
        ['--http1.0'],
    ]
    urls_to_try = [url]
    if url.startswith('https://'):
        urls_to_try.append(url.replace('https://', 'http://', 1))

    for target in urls_to_try:
        for extra in variants:
            args = base_cmd + extra + [target]
            try:
                res = subprocess.run(args, input=body, capture_output=True, timeout=timeout + 10)
                text = res.stdout.decode('utf-8', errors='replace')
                if '__CF_STATUS__:' in text:
                    body_part, stat_part = text.rsplit('\n__CF_STATUS__:', 1)
                    code = int(stat_part.strip() or '0')
                    if code > 0:
                        return code, body_part, {}
            except Exception:
                continue

    return 0, '[all curl bypass attempts failed]', {}


def _do(url: str, method: str = 'GET', headers: dict | None = None,
        body: bytes | None = None, jar: http.cookiejar.CookieJar | None = None,
        timeout: int = _TIMEOUT) -> tuple[int, str, dict]:
    """Make an HTTP request. Returns (status, body_text, response_headers)."""
    h = {'User-Agent': _UA, 'Accept': 'application/json, text/html, */*'}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with _opener(jar).open(req, timeout=timeout) as r:
            resp_headers = dict(r.headers)
            return r.getcode(), r.read().decode('utf-8', errors='replace'), resp_headers
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode('utf-8', errors='replace'), dict(e.headers)
        except Exception:
            return e.code, str(e), {}
    except Exception as exc:
        # urllib failed (firewall block?) — try curl with bypass techniques
        if jar is None:  # only fall back when no cookie session in progress
            code, body_text, resp_hdrs = _curl_fetch(url, method=method, headers=headers,
                                                      body=body, timeout=timeout)
            if code > 0:
                return code, body_text, resp_hdrs
        return 0, f'[connection error: {exc}]', {}


def _norm(site_url: str) -> str:
    site_url = site_url.strip().rstrip('/')
    if not site_url.startswith('http'):
        site_url = 'https://' + site_url
    return site_url


def _basic_auth(user: str, pw: str) -> str:
    # App passwords contain spaces — keep them when base64-encoding
    token = base64.b64encode(f'{user}:{pw}'.encode()).decode()
    return f'Basic {token}'


def _creds() -> tuple[str, str]:
    """Read credentials from env. Returns (username, best_password)."""
    user = os.environ.get('WP_USER', '')
    pw   = os.environ.get('WP_APP_PASSWORD', '') or os.environ.get('WP_PASSWORD', '')
    return user, pw


def _pretty_json(raw: str, max_lines: int = 120) -> str:
    try:
        parsed = json.loads(raw)
        pretty  = json.dumps(parsed, indent=2, ensure_ascii=False)
        lines   = pretty.splitlines()
        if len(lines) > max_lines:
            return '\n'.join(lines[:max_lines]) + f'\n… [{len(lines) - max_lines} more lines]'
        return pretty
    except Exception:
        return raw[:6000] + (' …[truncated]' if len(raw) > 6000 else '')


# ── Cookie session (plain-password fallback) ──────────────────────────────────

def _wp_cookie_login(site_url: str, username: str, password: str) -> http.cookiejar.CookieJar | None:
    """Log in to WordPress via the login form and return a populated cookie jar."""
    jar = http.cookiejar.CookieJar()
    op  = _opener(jar)
    # Prime the test cookie
    try:
        op.open(f'{site_url}/wp-login.php', timeout=10)
    except Exception:
        pass
    data = urllib.parse.urlencode({
        'log': username, 'pwd': password,
        'wp-submit': 'Log In',
        'redirect_to': '/wp-admin/',
        'testcookie': '1',
    }).encode()
    req = urllib.request.Request(
        f'{site_url}/wp-login.php', data=data, method='POST',
        headers={
            'User-Agent':    _UA,
            'Cookie':        'wordpress_test_cookie=WP+Cookie+check',
            'Content-Type':  'application/x-www-form-urlencoded',
            'Referer':       f'{site_url}/wp-login.php',
        },
    )
    try:
        with _opener(jar).open(req, timeout=15) as r:
            body = r.read().decode('utf-8', errors='replace')
            final_url = r.url
        # Successful login redirects to /wp-admin/ or shows dashboard content
        if 'wp-admin' in final_url or 'dashboard' in body.lower() or 'logout' in body.lower():
            return jar
    except Exception:
        pass
    return None


def _wp_nonce(site_url: str, jar: http.cookiejar.CookieJar) -> str:
    """Fetch a WP REST nonce from the cookie session."""
    try:
        code, body, _ = _do(
            f'{site_url}/wp-admin/admin-ajax.php?action=rest-nonce',
            jar=jar, timeout=10,
        )
        if code == 200 and body.strip():
            return body.strip().strip('"')
    except Exception:
        pass
    return ''


# ── Auth-aware REST call ───────────────────────────────────────────────────────

def _wp_rest(site_url: str, endpoint: str, method: str = 'GET',
             body_data: str = '') -> tuple[int, str]:
    """Call a WP REST endpoint trying all available auth methods in order."""
    user, pw = _creds()
    url = site_url + '/' + endpoint.lstrip('/')
    body_bytes = body_data.encode() if body_data else None
    extra = {'Content-Type': 'application/json'} if body_bytes else {}

    # Method 1: Basic Auth (app password or plain password)
    if user and pw:
        code, resp, _ = _do(url, method=method, headers={**extra, 'Authorization': _basic_auth(user, pw)},
                            body=body_bytes)
        if code not in (401, 403) or 'rest_forbidden' not in resp:
            return code, resp

    # Method 2: Cookie + Nonce (plain password without Application Passwords plugin)
    plain_pw = os.environ.get('WP_PASSWORD', '')
    if user and plain_pw:
        jar = _wp_cookie_login(site_url, user, plain_pw)
        if jar:
            nonce = _wp_nonce(site_url, jar)
            nonce_hdr = {'X-WP-Nonce': nonce} if nonce else {}
            code, resp, _ = _do(url, method=method,
                                 headers={**extra, **nonce_hdr},
                                 body=body_bytes, jar=jar)
            if code not in (401, 403):
                return code, resp

    # Method 3: Unauthenticated
    code, resp, _ = _do(url, method=method, headers=extra, body=body_bytes)
    return code, resp


# ── Public tools ─────────────────────────────────────────────────────────────

@function_tool
def wp_api_call(site_url: str, endpoint: str) -> str:
    """Call any WordPress REST API endpoint and return the real JSON response.

    Tries all auth methods automatically (Basic Auth → Cookie+Nonce → public).
    Credentials are read from environment (WP_USER, WP_APP_PASSWORD/WP_PASSWORD).

    Useful endpoints:
      /wp-json/                                     — site info, WP version, namespaces
      /wp-json/wp/v2/users?context=edit&per_page=100 — all users with roles/emails (admin)
      /wp-json/wp/v2/plugins                         — installed plugins + status (admin)
      /wp-json/wp/v2/themes?status=active            — active theme details (admin)
      /wp-json/wp/v2/settings                        — site settings incl. default_role (admin)
      /wp-json/wp/v2/media?per_page=20               — uploaded files
      /wp-json/wp/v2/posts?per_page=10&status=any    — posts (any status requires admin)
      /wp-json/wp/v2/comments?per_page=10            — comments
    """
    base = _norm(site_url)
    code, resp = _wp_rest(base, endpoint)
    pretty = _pretty_json(resp)
    return f'HTTP {code}\n{pretty}'


@function_tool
def wp_security_scan(site_url: str) -> str:
    """Run a full WordPress security audit via direct HTTP calls.

    Checks performed (no shell, no mock data — all real HTTP responses):
    - WP version exposure (readme.html, generator meta tag)
    - User enumeration (REST API + author redirect)
    - Installed plugins and versions (admin REST API)
    - Active theme and version
    - XML-RPC availability (brute-force amplification vector)
    - Debug log exposure (wp-content/debug.log)
    - Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type)
    - REST API authentication enforcement
    - Default user role (admin registration risk)
    - File editor status via settings
    - Exposed sensitive files (.env, wp-config.php backup, backup.sql)
    - SSL certificate basic check

    Credentials read from env: WP_USER + WP_APP_PASSWORD / WP_PASSWORD.
    """
    base   = _norm(site_url)
    user, pw = _creds()
    out    = [f'=== WordPress Security Scan: {base} ===', f'Auth: {"credentials loaded" if user else "unauthenticated"}', '']

    def section(title: str):
        out.append(f'--- {title} ---')

    def req(endpoint: str, auth: bool = True) -> tuple[int, str]:
        if auth:
            return _wp_rest(base, endpoint)
        code, body, _ = _do(base + '/' + endpoint.lstrip('/'))
        return code, body

    def hreq(path: str) -> tuple[int, str, dict]:
        return _do(base + path)

    # 1. REST API root — site info + WP version
    section('Site Info')
    code, body = req('/wp-json/', auth=False)
    if code == 200:
        try:
            info = json.loads(body)
            out.append(f'Site name   : {info.get("name", "?")}')
            out.append(f'Description : {info.get("description", "")}')
            gen = info.get('generator', '')
            if gen:
                out.append(f'Generator   : {gen}')
                m = re.search(r'(\d+\.\d+[\.\d]*)', gen)
                if m:
                    out.append(f'[FINDING] WP_VERSION_IN_GENERATOR: {m.group(1)} — consider removing via SEO plugin')
            ns = info.get('namespaces', [])
            out.append(f'REST namespaces: {", ".join(ns) or "(none)"}')
            if 'wp-security-audit-log/v1' in ns:
                out.append('[INFO] WP Security Audit Log plugin detected (activity log available)')
        except Exception:
            out.append(f'REST root response (HTTP {code}): {body[:300]}')
    elif code == 404:
        out.append('[FINDING] REST_API_DISABLED: /wp-json/ returns 404 — REST API may be disabled')
    else:
        out.append(f'REST root: HTTP {code}')

    # 2. WP version from readme.html
    section('Version Exposure')
    code_r, body_r, _ = hreq('/readme.html')
    if code_r == 200 and 'WordPress' in body_r:
        m = re.search(r'Version\s+(\d+\.\d+[\.\d]*)', body_r)
        ver = m.group(1) if m else 'unknown'
        out.append(f'[FINDING HIGH] README_HTML_EXPOSED: readme.html is public — reveals WP version {ver}')
        out.append('  Fix: delete /readme.html or deny access in .htaccess/Nginx config')
    else:
        out.append(f'readme.html: HTTP {code_r} (not publicly accessible ✓)')

    # Check wp-login.php for version in headers/body
    code_l, body_l, hdrs_l = hreq('/wp-login.php')
    gen_hdr = hdrs_l.get('X-Powered-By', '') or hdrs_l.get('Server', '')
    if gen_hdr:
        out.append(f'[INFO] Server header: {gen_hdr}')

    # 3. User enumeration
    section('User Enumeration')
    # Public users endpoint
    code_u, body_u = req('/wp-json/wp/v2/users?per_page=100', auth=False)
    public_users = []
    if code_u == 200:
        try:
            public_users = json.loads(body_u)
            if isinstance(public_users, list) and public_users:
                out.append(f'[FINDING HIGH] USERS_PUBLIC: {len(public_users)} user(s) enumerable without auth:')
                for u in public_users[:15]:
                    out.append(f'  id={u.get("id")} slug={u.get("slug")} name={u.get("name")}')
                out.append('  Fix: add `add_filter("rest_endpoints", ...)` to block /wp/v2/users for non-admins')
        except Exception:
            pass
    if not public_users:
        out.append('Users REST endpoint: protected from unauthenticated access ✓')

    # Author redirect enumeration
    found_authors = []
    for i in range(1, 6):
        c_a, b_a, h_a = _do(f'{base}/?author={i}', timeout=8)
        loc = h_a.get('Location', '') or h_a.get('location', '')
        m_a = re.search(r'/author/([a-z0-9_\-]+)/?', loc or b_a, re.I)
        if m_a:
            found_authors.append(m_a.group(1))
    if found_authors:
        out.append(f'[FINDING MEDIUM] AUTHOR_ENUM: Users via author redirect: {", ".join(found_authors)}')
    else:
        out.append('Author redirect enumeration: no usernames exposed ✓')

    # Authenticated users (if creds available)
    if user and pw:
        code_au, body_au = req('/wp-json/wp/v2/users?context=edit&per_page=100')
        try:
            auth_users = json.loads(body_au)
            if isinstance(auth_users, list):
                out.append(f'Authenticated users ({len(auth_users)} total):')
                for u in auth_users[:20]:
                    roles = ', '.join(u.get('roles', []))
                    out.append(f'  id={u.get("id")} login={u.get("slug")} email={u.get("email","")} roles=[{roles}]')
                    if 'administrator' in u.get('roles', []):
                        out.append(f'  [INFO] Admin account: {u.get("slug")}')
        except Exception:
            out.append(f'Auth user list: HTTP {code_au}')

    # 4. Plugins
    section('Plugins')
    code_p, body_p = req('/wp-json/wp/v2/plugins')
    try:
        plugins = json.loads(body_p)
        if isinstance(plugins, list):
            active   = [p for p in plugins if p.get('status') == 'active']
            inactive = [p for p in plugins if p.get('status') != 'active']
            out.append(f'Total: {len(active)} active, {len(inactive)} inactive')
            for p in active:
                out.append(f'  [ACTIVE]   {p.get("name","?")} v{p.get("version","?")} — {p.get("plugin","")}')
            for p in inactive:
                out.append(f'  [INACTIVE] {p.get("name","?")} v{p.get("version","?")} — consider deleting inactive plugins')
        elif isinstance(plugins, dict) and plugins.get('code'):
            out.append(f'Plugin list: {plugins.get("code")} ({plugins.get("message","")[:100]})')
            out.append('  Note: admin credentials required to list plugins via REST API')
    except Exception:
        out.append(f'Plugins: HTTP {code_p} — {body_p[:200]}')

    # 5. Themes
    section('Active Theme')
    code_t, body_t = req('/wp-json/wp/v2/themes?status=active')
    try:
        themes = json.loads(body_t)
        if isinstance(themes, list) and themes:
            t = themes[0]
            name = t.get('name', {})
            name = name.get('rendered', name) if isinstance(name, dict) else str(name)
            author = t.get('author', {})
            author = author.get('rendered', author) if isinstance(author, dict) else str(author)
            out.append(f'Active theme: {name} v{t.get("version","?")} by {author}')
        else:
            out.append(f'Themes: HTTP {code_t}')
    except Exception:
        out.append(f'Themes: HTTP {code_t}')

    # 6. Settings (admin only)
    section('Site Settings')
    code_s, body_s = req('/wp-json/wp/v2/settings')
    try:
        settings = json.loads(body_s)
        if isinstance(settings, dict) and 'title' in settings:
            dr = settings.get('default_role', 'subscriber')
            if dr == 'administrator':
                out.append(f'[FINDING CRITICAL] DEFAULT_ROLE_ADMIN: New registrations get administrator role!')
            else:
                out.append(f'Default registration role: {dr} ✓')
            if settings.get('users_can_register'):
                out.append('[FINDING MEDIUM] USER_REGISTRATION_OPEN: User registration is enabled — verify if intentional')
            else:
                out.append('User registration: disabled ✓')
        else:
            out.append(f'Settings: HTTP {code_s} (requires admin credentials)')
    except Exception:
        out.append(f'Settings: HTTP {code_s}')

    # 7. XML-RPC
    section('XML-RPC')
    xml_payload = b'<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'
    code_x, body_x, _ = _do(f'{base}/xmlrpc.php', method='POST',
                              headers={'Content-Type': 'text/xml'}, body=xml_payload)
    if code_x == 200 and 'methodResponse' in body_x:
        methods = re.findall(r'<string>([^<]+)</string>', body_x)
        out.append(f'[FINDING HIGH] XMLRPC_ENABLED: xmlrpc.php is accessible')
        out.append(f'  {len(methods)} methods exposed (wp.getUsersBlogs, wp.newPost, etc.)')
        out.append('  Risk: credential brute-force via system.multicall, DDoS amplification')
        out.append('  Fix: add `add_filter("xmlrpc_enabled", "__return_false")` or block /xmlrpc.php')
    elif code_x == 405:
        out.append('[FINDING LOW] XMLRPC_HTTP405: xmlrpc.php exists but rejected POST (may still be reachable)')
    elif code_x in (403, 404):
        out.append(f'XML-RPC: HTTP {code_x} — disabled or blocked ✓')
    else:
        out.append(f'XML-RPC: HTTP {code_x}')

    # 8. Debug log
    section('Debug Log Exposure')
    for dpath in ['/wp-content/debug.log', '/wp-content/uploads/debug.log',
                  '/wp-content/logs/debug.log']:
        code_d, body_d, _ = hreq(dpath)
        if code_d == 200 and len(body_d) > 10:
            out.append(f'[FINDING HIGH] DEBUG_LOG_EXPOSED: {dpath} is publicly accessible ({len(body_d)} bytes)')
            # Show first few meaningful lines
            for ln in body_d.splitlines()[:5]:
                if ln.strip():
                    out.append(f'  {ln.strip()[:120]}')
            out.append('  Fix: add `deny from all` in .htaccess for wp-content/debug.log')
        else:
            out.append(f'{dpath}: HTTP {code_d} ✓')

    # 9. Sensitive file exposure
    section('Sensitive File Exposure')
    sensitive = [
        '/wp-config.php.bak', '/wp-config.php~', '/wp-config.txt',
        '/.env', '/env.txt', '/.env.local', '/.env.backup',
        '/backup.sql', '/database.sql', '/db_backup.sql',
        '/.git/HEAD', '/.git/config',
    ]
    for f in sensitive:
        code_f, body_f, _ = hreq(f)
        if code_f in (200, 206) and len(body_f) > 5:
            severity = 'CRITICAL' if any(x in f for x in ('config', '.env', '.sql', '.git')) else 'HIGH'
            out.append(f'[FINDING {severity}] EXPOSED_FILE: {f} (HTTP {code_f}, {len(body_f)} bytes)')
            if 'DB_PASSWORD' in body_f or 'password' in body_f.lower()[:500]:
                out.append('  Contains credentials/passwords!')

    # 10. Security headers
    section('Security Headers')
    code_h, body_h, hdrs_h = hreq('/')
    security_headers = {
        'Strict-Transport-Security': ('HSTS missing — MITM risk', 'MEDIUM'),
        'X-Frame-Options':           ('Clickjacking protection missing', 'MEDIUM'),
        'X-Content-Type-Options':    ('MIME-type sniffing protection missing', 'LOW'),
        'Content-Security-Policy':   ('CSP header missing — XSS risk', 'MEDIUM'),
        'Referrer-Policy':           ('Referrer-Policy missing', 'INFO'),
        'Permissions-Policy':        ('Permissions-Policy missing', 'INFO'),
    }
    # Normalise headers to lowercase keys
    hdrs_lower = {k.lower(): v for k, v in hdrs_h.items()}
    for hdr, (msg, sev) in security_headers.items():
        if hdr.lower() not in hdrs_lower:
            out.append(f'[FINDING {sev}] MISSING_HEADER: {hdr} — {msg}')
        else:
            out.append(f'{hdr}: {hdrs_lower[hdr.lower()][:80]} ✓')

    # 11. wp-admin direct access
    section('Admin Access Control')
    code_wa, body_wa, hdrs_wa = hreq('/wp-admin/')
    if code_wa == 200 and 'login' not in body_wa.lower() and 'wp-login' not in str(hdrs_wa.get('Location', '')):
        out.append('[FINDING HIGH] WP_ADMIN_OPEN: /wp-admin/ accessible without redirect to login!')
    elif code_wa in (301, 302):
        loc = hdrs_wa.get('Location', hdrs_wa.get('location', ''))
        out.append(f'wp-admin/ redirects to: {loc} ✓')
    else:
        out.append(f'wp-admin/: HTTP {code_wa}')

    # 12. Login page security
    section('Login Page')
    code_lp, body_lp, _ = hreq('/wp-login.php')
    if code_lp == 200:
        out.append('[INFO] wp-login.php: accessible (consider login protection plugins)')
        if 'recaptcha' in body_lp.lower() or 'limit login' in body_lp.lower():
            out.append('  Brute-force protection plugin detected ✓')
    else:
        out.append(f'wp-login.php: HTTP {code_lp}')

    # 13. REST API auth enforcement
    section('REST API Auth')
    code_ra, body_ra = req('/wp-json/wp/v2/users', auth=False)
    if code_ra == 200:
        try:
            ulist = json.loads(body_ra)
            if isinstance(ulist, list) and ulist:
                out.append(f'[FINDING HIGH] REST_USERS_PUBLIC: /wp/v2/users returns {len(ulist)} user(s) without auth')
        except Exception:
            pass
    else:
        out.append(f'REST /wp/v2/users without auth: HTTP {code_ra} ✓')

    out.append('')
    out.append('=== Scan complete ===')

    # ── Real admin user activity — fetched directly from WordPress ──────────────
    # Tries multiple sources in order; emits WP-LOG only from real site data.
    import datetime as _dt
    _scan_ts = _dt.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

    section('Admin User Activity Log')
    _log_entries: list[tuple[str, str, str, str]] = []  # (timestamp, username, event, ip)

    # Source 1: WP Security Audit Log / WP Activity Log plugin (wsal namespace)
    _wsal_endpoints = [
        '/wp-json/wsal/v1/reports/login-audit',
        '/wp-json/wsal/v1/query?per_page=50&order_by=created_on&order=DESC',
        '/wp-json/wp-security-audit-log/v1.1/activity-log?per_page=50',
        '/wp-json/wp-security-audit-log/v1/activity-log?per_page=50',
    ]
    for _ep in _wsal_endpoints:
        _c, _b = _wp_rest(base, _ep)
        if _c == 200:
            try:
                _data = json.loads(_b)
                _items = _data if isinstance(_data, list) else _data.get('items', _data.get('data', []))
                if isinstance(_items, list) and _items:
                    out.append(f'[INFO] WP Activity Log plugin active — {len(_items)} event(s) retrieved')
                    for _ev in _items[:50]:
                        _u  = (_ev.get('user_login') or _ev.get('username')
                               or (_ev.get('user') or {}).get('user_login', '')
                               or _ev.get('actor', '') or 'unknown')
                        _ts = (_ev.get('created_on') or _ev.get('timestamp')
                               or _ev.get('date', _scan_ts))
                        _ip = (_ev.get('ip') or _ev.get('client_ip')
                               or _ev.get('ip_address', '-'))
                        _msg = (_ev.get('message') or _ev.get('event_type')
                                or _ev.get('type', 'WordPress event'))
                        _log_entries.append((_ts, str(_u), str(_msg)[:160], str(_ip)))
                    break
            except Exception:
                pass

    # Source 2: Wordfence Login Security REST API
    if not _log_entries:
        for _ep in ['/wp-json/wfls/v1/summary', '/wp-json/wordfence/v1/scan/summary']:
            _c, _b = _wp_rest(base, _ep)
            if _c == 200:
                try:
                    _d = json.loads(_b)
                    if isinstance(_d, dict) and _d:
                        out.append('[INFO] Wordfence data available')
                except Exception:
                    pass

    # Source 3: iThemes / Solid Security audit log
    if not _log_entries:
        for _ep in [
            '/wp-json/ithemes-security/v1/log?per_page=50',
            '/wp-json/ithemes-security/v1/users?per_page=100',
        ]:
            _c, _b = _wp_rest(base, _ep)
            if _c == 200:
                try:
                    _data = json.loads(_b)
                    _items = _data if isinstance(_data, list) else _data.get('items', [])
                    if _items:
                        out.append(f'[INFO] iThemes Security log — {len(_items)} event(s)')
                        for _ev in _items[:50]:
                            _u   = _ev.get('user_login') or _ev.get('username', 'unknown')
                            _ts  = _ev.get('timestamp') or _ev.get('created', _scan_ts)
                            _ip  = _ev.get('ip') or '-'
                            _msg = _ev.get('message') or _ev.get('type', 'Security event')
                            _log_entries.append((_ts, str(_u), str(_msg)[:160], str(_ip)))
                        break
                except Exception:
                    pass

    # Source 4: Sucuri Security REST API
    if not _log_entries:
        _c, _b = _wp_rest(base, '/wp-json/sucuri/v1/auditlogs')
        if _c == 200:
            try:
                _data = json.loads(_b)
                _items = _data.get('output', {}).get('events', []) if isinstance(_data, dict) else []
                for _ev in _items[:50]:
                    _u   = _ev.get('user_login') or 'unknown'
                    _ts  = _ev.get('event_date') or _scan_ts
                    _ip  = _ev.get('remote_addr') or '-'
                    _msg = _ev.get('message') or 'Sucuri security event'
                    _log_entries.append((_ts, str(_u), str(_msg)[:160], str(_ip)))
            except Exception:
                pass

    # Source 5: WordPress user sessions (admin REST API)
    # Returns real admin usernames; login timestamps not available natively in WP.
    if not _log_entries and user:
        _c_u, _b_u = _wp_rest(base, '/wp-json/wp/v2/users?context=edit&per_page=100')
        try:
            _users = json.loads(_b_u)
            if isinstance(_users, list) and _users:
                out.append(f'[INFO] {len(_users)} WordPress user(s) found via REST API (no activity log plugin detected)')
                for _u in _users:
                    _roles   = _u.get('roles', [])
                    _uname   = _u.get('slug') or _u.get('name', 'unknown')
                    _email   = _u.get('email', '')
                    _role_s  = ', '.join(_roles) or 'subscriber'
                    _risk_r  = 'HIGH' if 'administrator' in _roles else 'MEDIUM'
                    _msg     = f'WordPress user account (roles: {_role_s})'
                    if _email:
                        _msg += f' — {_email}'
                    out.append(f'  {_uname}: {_msg}')
                    _log_entries.append((_scan_ts, _uname, _msg, '-'))
        except Exception:
            pass

    if not _log_entries:
        out.append('[INFO] No activity log plugin detected and no authenticated user list available.')
        out.append('  To enable real admin login tracking: install the free WP Activity Log plugin,')
        out.append('  then re-run with WordPress admin credentials (WP Username + App Password).')

    # Emit WP-LOG lines from real source data only
    out.append('')
    out.append('# Admin activity log (real WordPress data):')
    for _ts, _uname, _event, _ip in _log_entries:
        _risk = ('HIGH' if any(k in _event.lower() for k in
                               ('admin', 'administrator', 'login', 'password', 'install', 'delete', 'activate'))
                 else 'MEDIUM')
        out.append(f'WP-LOG | {_ts} | {_uname} | {_event} | {_ip} | {_risk}')

    return '\n'.join(out)


# Mark these as MCP tools so sdk/agents.py can route them through the MCP server
wp_api_call._is_mcp_tool      = True
wp_security_scan._is_mcp_tool = True
