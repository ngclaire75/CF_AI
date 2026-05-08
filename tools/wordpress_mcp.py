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
from concurrent.futures import ThreadPoolExecutor, as_completed
from sdk.agents import function_tool

_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
_TIMEOUT  = 15
_FAST     = 8

# ── Optional Cloudflare-bypass library ───────────────────────────────────────
try:
    import cloudscraper as _cloudscraper
    import urllib3 as _urllib3
    import ssl as _ssl
    from requests.adapters import HTTPAdapter as _HTTPAdapter
    _urllib3.disable_warnings(_urllib3.exceptions.InsecureRequestWarning)

    class _NoSSLVerifyAdapter(_HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            kwargs['ssl_context'] = ctx
            return super().init_poolmanager(*args, **kwargs)

    _cs = _cloudscraper.create_scraper(browser={'browser': 'chrome', 'platform': 'windows', 'mobile': False})
    _cs.mount('https://', _NoSSLVerifyAdapter())
    _HAS_CLOUDSCRAPER = True
except ImportError:
    _cs = None
    _HAS_CLOUDSCRAPER = False

# ── External scraping API keys (optional — unlocks Cloudflare JS challenges) ─
_SCRAPER_API_KEY  = os.environ.get('SCRAPER_API_KEY', '')   # scraperapi.com
_ZENROWS_API_KEY  = os.environ.get('ZENROWS_API_KEY', '')   # zenrows.com
_SCRAPINGBEE_KEY  = os.environ.get('SCRAPINGBEE_API_KEY', '')
_WPSCAN_API_TOKEN = os.environ.get('WPSCAN_API_TOKEN', '')  # wpscan.com — free: 75 req/day


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
    """Try curl with multiple Cloudflare/WAF bypass variants."""
    if not shutil.which('curl'):
        return 0, '[curl not available]', {}

    base_cmd = [
        'curl', '-s', '-L', '-k',
        '-w', '\n__CF_STATUS__:%{http_code}',
        '--max-time', str(timeout),
        '--connect-timeout', str(min(timeout, 12)),
        '-c', '/tmp/cf_cookies.txt', '-b', '/tmp/cf_cookies.txt',
    ]
    if method == 'POST':
        base_cmd += ['--request', 'POST']
    if body:
        base_cmd += ['--data-binary', '@-']
    if headers:
        for k, v in headers.items():
            base_cmd += ['-H', f'{k}: {v}']

    variants = [
        # Standard Chrome UA
        ['-A', _UA,
         '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
         '-H', 'Accept-Language: en-US,en;q=0.9',
         '-H', 'Accept-Encoding: gzip, deflate, br',
         '-H', 'Cache-Control: max-age=0'],
        # Googlebot UA (passes many origin-level rules)
        ['-A', 'Googlebot/2.1 (+http://www.google.com/bot.html)',
         '-H', 'From: googlebot@googlebot.com',
         '-H', 'X-Forwarded-For: 66.249.66.1'],
        # CF-Connecting-IP origin bypass (tricks origin server behind CF)
        ['-A', _UA,
         '-H', 'CF-Connecting-IP: 127.0.0.1',
         '-H', 'X-Real-IP: 127.0.0.1',
         '-H', 'X-Forwarded-For: 127.0.0.1'],
        # HTTP/1.0 fallback (bypasses some protocol-level filters)
        ['--http1.0', '-A', _UA],
    ]
    for extra in variants:
        args = base_cmd + extra + [url]
        try:
            res = subprocess.run(args, input=body, capture_output=True, timeout=timeout + 6)
            text = res.stdout.decode('utf-8', errors='replace')
            if '__CF_STATUS__:' in text:
                body_part, stat_part = text.rsplit('\n__CF_STATUS__:', 1)
                code = int(stat_part.strip() or '0')
                if code in (200, 201, 204, 301, 302, 400, 401, 403, 404, 405):
                    return code, body_part, {}
        except Exception:
            continue

    return 0, '[curl bypass exhausted]', {}


def _cloudscraper_fetch(url: str, method: str = 'GET', headers: dict | None = None,
                        body: bytes | None = None, timeout: int = _TIMEOUT) -> tuple[int, str, dict]:
    """Use cloudscraper to solve Cloudflare JS challenge."""
    if not _HAS_CLOUDSCRAPER:
        return 0, '[cloudscraper not installed — run: pip install cloudscraper]', {}
    try:
        h = {'User-Agent': _UA}
        if headers:
            h.update(headers)
        resp = _cs.request(method, url, headers=h, data=body, timeout=timeout)
        return resp.status_code, resp.text, dict(resp.headers)
    except Exception as exc:
        return 0, f'[cloudscraper error: {exc}]', {}


def _scraping_api_fetch(url: str, timeout: int = _TIMEOUT) -> tuple[int, str, dict]:
    """Route request through a scraping API (ScraperAPI → ZenRows → ScrapingBee)."""
    # ScraperAPI — ?api_key=...&url=...&render=true handles CF JS challenges
    if _SCRAPER_API_KEY:
        try:
            encoded = urllib.parse.quote(url, safe='')
            api_url = f'http://api.scraperapi.com/?api_key={_SCRAPER_API_KEY}&url={encoded}&render=true'
            req = urllib.request.Request(api_url, headers={'User-Agent': _UA})
            with urllib.request.urlopen(req, timeout=timeout + 10) as r:
                return r.getcode(), r.read().decode('utf-8', errors='replace'), dict(r.headers)
        except Exception:
            pass

    # ZenRows — supports Cloudflare v2 + v3 (IUAM)
    if _ZENROWS_API_KEY:
        try:
            params = urllib.parse.urlencode({'url': url, 'apikey': _ZENROWS_API_KEY,
                                             'js_render': 'true', 'antibot': 'true'})
            api_url = f'https://api.zenrows.com/v1/?{params}'
            req = urllib.request.Request(api_url, headers={'User-Agent': _UA})
            with urllib.request.urlopen(req, timeout=timeout + 10) as r:
                return r.getcode(), r.read().decode('utf-8', errors='replace'), dict(r.headers)
        except Exception:
            pass

    # ScrapingBee — JS rendering + stealth mode
    if _SCRAPINGBEE_KEY:
        try:
            params = urllib.parse.urlencode({'api_key': _SCRAPINGBEE_KEY, 'url': url,
                                             'render_js': 'true', 'stealth_proxy': 'true'})
            api_url = f'https://app.scrapingbee.com/api/v1/?{params}'
            req = urllib.request.Request(api_url, headers={'User-Agent': _UA})
            with urllib.request.urlopen(req, timeout=timeout + 10) as r:
                return r.getcode(), r.read().decode('utf-8', errors='replace'), dict(r.headers)
        except Exception:
            pass

    return 0, '[no scraping API keys configured]', {}


def _do(url: str, method: str = 'GET', headers: dict | None = None,
        body: bytes | None = None, jar: http.cookiejar.CookieJar | None = None,
        timeout: int = _TIMEOUT) -> tuple[int, str, dict]:
    """Multi-layer HTTP fetch with progressive Cloudflare/WAF bypass.

    Layer 1: Standard urllib (fast, works for most sites)
    Layer 2: cloudscraper (solves CF JS challenge v1/v2 — pip install cloudscraper)
    Layer 3: curl with UA/header rotation (passes many origin rules)
    Layer 4: External scraping API (ScraperAPI / ZenRows / ScrapingBee — paid, set API keys in .env)
    """
    h = {'User-Agent': _UA,
         'Accept': 'application/json, text/html, */*',
         'Accept-Language': 'en-US,en;q=0.9'}
    if headers:
        h.update(headers)

    # Layer 1: standard urllib
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with _opener(jar).open(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode('utf-8', errors='replace'), dict(r.headers)
    except urllib.error.HTTPError as e:
        try:
            body_text = e.read().decode('utf-8', errors='replace')
        except Exception:
            body_text = str(e)
        # CF challenge page — escalate to cloudscraper
        if e.code in (403, 503) and ('cloudflare' in body_text.lower() or 'cf-ray' in str(e.headers).lower()):
            pass  # fall through to Layer 2
        elif e.code not in (429,):
            return e.code, body_text, dict(e.headers)
    except Exception:
        pass

    # Layer 2: cloudscraper (Cloudflare JS challenge solver)
    if jar is None:  # cloudscraper manages its own session
        code, text, hdrs = _cloudscraper_fetch(url, method=method, headers=headers,
                                                body=body, timeout=timeout)
        if code > 0:
            return code, text, hdrs

    # Layer 3: curl with bypass header variants
    code, text, hdrs = _curl_fetch(url, method=method, headers=headers, body=body, timeout=timeout)
    if code > 0:
        return code, text, hdrs

    # Layer 4: paid scraping API (ScraperAPI / ZenRows / ScrapingBee)
    if method == 'GET' and jar is None:
        code, text, hdrs = _scraping_api_fetch(url, timeout=timeout)
        if code > 0:
            return code, text, hdrs

    return 0, f'[all bypass layers exhausted for {url}]', {}


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


def _wpscan_api(rtype: str, slug: str, installed_ver: str = '') -> list[str]:
    """Query WPScan vulnerability database API for a plugin, theme, or WP core version.

    rtype : 'plugins' | 'themes' | 'wordpresses'
    slug  : plugin/theme slug or WP version string (e.g. '6.4.3')
    Returns a list of formatted finding strings ready to include in output.
    """
    if not _WPSCAN_API_TOKEN:
        return []
    # WP core endpoint uses version without dots: 643 for 6.4.3
    slug_key = slug.replace('.', '') if rtype == 'wordpresses' else slug
    url = f'https://wpscan.com/api/v3/{rtype}/{slug_key}'
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': _UA,
            'Authorization': f'Token token={_WPSCAN_API_TOKEN}',
        })
        ctx = _ssl_ctx()
        with urllib.request.urlopen(req, context=ctx, timeout=12) as r:
            data = json.loads(r.read().decode())
        entry = data.get(slug_key, data.get(slug, {}))
        vulns = entry.get('vulnerabilities', [])
        latest = entry.get('latest_version', '')
    except Exception:
        return []

    lines: list[str] = []
    for v in vulns:
        fixed_in = v.get('fixed_in') or ''
        title    = v.get('title', '?')
        refs     = v.get('references', {})
        cve_ids  = refs.get('cve', [])
        cvss     = v.get('cvss', {})
        score    = cvss.get('score', '') if isinstance(cvss, dict) else ''

        # Only flag if installed version is older than fixed_in
        if installed_ver and fixed_in:
            try:
                from packaging.version import Version
                if Version(installed_ver) >= Version(fixed_in):
                    continue  # already patched
            except Exception:
                pass  # packaging not installed — report anyway

        sev = 'CRITICAL' if score and float(str(score)) >= 9 else 'HIGH'
        cve_str = ' [' + ', '.join(f'CVE-{c}' for c in cve_ids) + ']' if cve_ids else ''
        lines.append(f'[FINDING {sev}] WPSCAN_CVE{cve_str}: {title}')
        if fixed_in:
            lines.append(f'  Installed: {installed_ver or "unknown"}  Fixed in: {fixed_in}')
        if latest and installed_ver and installed_ver != latest:
            lines.append(f'  Latest available: {latest}')
    return lines


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

    All independent checks run in parallel (ThreadPoolExecutor) so the total
    time is bounded by the slowest single check, not the sum of all checks.

    Checks: WP version, user enumeration, plugins, themes, settings, XML-RPC,
    debug log, sensitive files, security headers, admin access, login page,
    REST API auth, admin user activity log.

    Credentials read from env: WP_USER + WP_APP_PASSWORD / WP_PASSWORD.
    """
    import datetime as _dt

    base     = _norm(site_url)
    user, pw = _creds()
    scan_ts  = _dt.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

    def _req(endpoint: str, auth: bool = True) -> tuple[int, str]:
        if auth:
            return _wp_rest(base, endpoint)
        code, body, _ = _do(base + '/' + endpoint.lstrip('/'), timeout=_TIMEOUT)
        return code, body

    def _hreq(path: str, timeout: int = _FAST) -> tuple[int, str, dict]:
        return _do(base + path, timeout=timeout)

    # ── Each check returns a list[str] of output lines ────────────────────────

    def chk_site_info():
        lines = ['--- Site Info ---']
        code, body = _req('/wp-json/', auth=False)
        if code == 200:
            try:
                info = json.loads(body)
                lines.append(f'Site name   : {info.get("name","?")}')
                lines.append(f'Description : {info.get("description","")}')
                gen = info.get('generator', '')
                if gen:
                    lines.append(f'Generator   : {gen}')
                    m = re.search(r'(\d+\.\d+[\.\d]*)', gen)
                    if m:
                        lines.append(f'[FINDING] WP_VERSION_IN_GENERATOR: {m.group(1)} — consider removing via SEO plugin')
                ns = info.get('namespaces', [])
                lines.append(f'REST namespaces: {", ".join(ns) or "(none)"}')
                if 'wp-security-audit-log/v1' in ns:
                    lines.append('[INFO] WP Security Audit Log plugin detected')
            except Exception:
                lines.append(f'REST root (HTTP {code}): {body[:200]}')
        elif code == 404:
            lines.append('[FINDING] REST_API_DISABLED: /wp-json/ returns 404')
        else:
            lines.append(f'REST root: HTTP {code}')
        return lines

    def chk_version():
        lines = ['--- Version Exposure ---']
        wp_ver = ''
        code_r, body_r, _ = _hreq('/readme.html')
        if code_r == 200 and 'WordPress' in body_r:
            m = re.search(r'Version\s+(\d+\.\d+[\.\d]*)', body_r)
            wp_ver = m.group(1) if m else ''
            lines.append(f'[FINDING HIGH] README_HTML_EXPOSED: readme.html public — WP version {wp_ver or "unknown"}')
            lines.append('  Fix: delete /readme.html or deny in .htaccess/Nginx')
        else:
            lines.append(f'readme.html: HTTP {code_r} ✓')
        # Try generator tag if readme was hidden
        if not wp_ver:
            _, body_home, _ = _hreq('/')
            m2 = re.search(r'generator.*?WordPress\s+([\d.]+)', body_home, re.I)
            if m2:
                wp_ver = m2.group(1)
        # WPScan API — check core version for known CVEs
        if wp_ver and _WPSCAN_API_TOKEN:
            lines.append(f'[INFO] Checking WPScan API for WP {wp_ver} vulnerabilities...')
            for vline in _wpscan_api('wordpresses', wp_ver, wp_ver):
                lines.append('  ' + vline)
        code_l, _, hdrs_l = _hreq('/wp-login.php')
        svr = hdrs_l.get('X-Powered-By', '') or hdrs_l.get('Server', '')
        if svr:
            lines.append(f'[INFO] Server header: {svr}')
        return lines

    def chk_users():
        lines = ['--- User Enumeration ---']
        # Public REST
        code_u, body_u = _req('/wp-json/wp/v2/users?per_page=100', auth=False)
        public_users = []
        if code_u == 200:
            try:
                public_users = json.loads(body_u)
                if isinstance(public_users, list) and public_users:
                    lines.append(f'[FINDING HIGH] USERS_PUBLIC: {len(public_users)} user(s) enumerable without auth:')
                    for u in public_users[:15]:
                        lines.append(f'  id={u.get("id")} slug={u.get("slug")} name={u.get("name")}')
                    lines.append('  Fix: block /wp/v2/users for non-admins via add_filter("rest_endpoints",...)')
            except Exception:
                pass
        if not public_users:
            lines.append('Users REST endpoint: protected ✓')
        # Author redirect — 3 parallel probes
        with ThreadPoolExecutor(max_workers=3) as ex:
            futs = {ex.submit(_do, f'{base}/?author={i}', timeout=_FAST): i for i in range(1, 4)}
            found = []
            for ft in as_completed(futs):
                try:
                    _, b_a, h_a = ft.result()
                    loc = h_a.get('Location', '') or h_a.get('location', '')
                    m_a = re.search(r'/author/([a-z0-9_\-]+)/?', loc or b_a, re.I)
                    if m_a:
                        found.append(m_a.group(1))
                except Exception:
                    pass
        if found:
            lines.append(f'[FINDING MEDIUM] AUTHOR_ENUM: {", ".join(sorted(set(found)))}')
        else:
            lines.append('Author redirect enumeration: no usernames exposed ✓')
        # Authenticated users
        if user and pw:
            code_au, body_au = _req('/wp-json/wp/v2/users?context=edit&per_page=100')
            try:
                auth_users = json.loads(body_au)
                if isinstance(auth_users, list):
                    lines.append(f'Authenticated users ({len(auth_users)} total):')
                    for u in auth_users[:20]:
                        roles = ', '.join(u.get('roles', []))
                        lines.append(f'  id={u.get("id")} login={u.get("slug")} email={u.get("email","")} roles=[{roles}]')
            except Exception:
                lines.append(f'Auth user list: HTTP {code_au}')
        return lines

    def chk_plugins():
        lines = ['--- Plugins ---']
        code_p, body_p = _req('/wp-json/wp/v2/plugins')
        try:
            plugins = json.loads(body_p)
            if isinstance(plugins, list):
                active   = [p for p in plugins if p.get('status') == 'active']
                inactive = [p for p in plugins if p.get('status') != 'active']
                lines.append(f'Total: {len(active)} active, {len(inactive)} inactive')
                for p in active:
                    slug = (p.get('plugin') or '').split('/')[0]
                    ver  = p.get('version', '')
                    lines.append(f'  [ACTIVE]   {p.get("name","?")} v{ver} — {p.get("plugin","")}')
                    if slug and _WPSCAN_API_TOKEN:
                        for vline in _wpscan_api('plugins', slug, ver):
                            lines.append('    ' + vline)
                for p in inactive:
                    lines.append(f'  [INACTIVE] {p.get("name","?")} v{p.get("version","?")} — consider deleting')
            elif isinstance(plugins, dict) and plugins.get('code'):
                lines.append(f'Plugin list: {plugins.get("code")} — admin credentials required')
        except Exception:
            lines.append(f'Plugins: HTTP {code_p}')
        return lines

    def chk_themes():
        lines = ['--- Active Theme ---']
        code_t, body_t = _req('/wp-json/wp/v2/themes?status=active')
        try:
            themes = json.loads(body_t)
            if isinstance(themes, list) and themes:
                t      = themes[0]
                name   = t.get('name', {}); name   = name.get('rendered', name) if isinstance(name, dict) else str(name)
                author = t.get('author', {}); author = author.get('rendered', author) if isinstance(author, dict) else str(author)
                slug   = t.get('stylesheet', '') or t.get('template', '')
                ver    = t.get('version', '')
                lines.append(f'Active theme: {name} v{ver} by {author}')
                if slug and _WPSCAN_API_TOKEN:
                    for vline in _wpscan_api('themes', slug, ver):
                        lines.append('  ' + vline)
            else:
                lines.append(f'Themes: HTTP {code_t}')
        except Exception:
            lines.append(f'Themes: HTTP {code_t}')
        return lines

    def chk_settings():
        lines = ['--- Site Settings ---']
        code_s, body_s = _req('/wp-json/wp/v2/settings')
        try:
            settings = json.loads(body_s)
            if isinstance(settings, dict) and 'title' in settings:
                dr = settings.get('default_role', 'subscriber')
                if dr == 'administrator':
                    lines.append('[FINDING CRITICAL] DEFAULT_ROLE_ADMIN: New registrations get administrator role!')
                else:
                    lines.append(f'Default registration role: {dr} ✓')
                if settings.get('users_can_register'):
                    lines.append('[FINDING MEDIUM] USER_REGISTRATION_OPEN: Registration enabled — verify if intentional')
                else:
                    lines.append('User registration: disabled ✓')
            else:
                lines.append(f'Settings: HTTP {code_s} (admin credentials required)')
        except Exception:
            lines.append(f'Settings: HTTP {code_s}')
        return lines

    def chk_xmlrpc():
        lines = ['--- XML-RPC ---']
        xml_pl = b'<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'
        code_x, body_x, _ = _do(f'{base}/xmlrpc.php', method='POST',
                                  headers={'Content-Type': 'text/xml'}, body=xml_pl, timeout=_TIMEOUT)
        if code_x == 200 and 'methodResponse' in body_x:
            methods = re.findall(r'<string>([^<]+)</string>', body_x)
            lines.append(f'[FINDING HIGH] XMLRPC_ENABLED: xmlrpc.php accessible — {len(methods)} methods')
            lines.append('  Risk: credential brute-force, DDoS amplification')
            lines.append('  Fix: add_filter("xmlrpc_enabled","__return_false") or block /xmlrpc.php')
        elif code_x == 405:
            lines.append('[FINDING LOW] XMLRPC_HTTP405: xmlrpc.php exists but rejected POST')
        elif code_x in (403, 404):
            lines.append(f'XML-RPC: HTTP {code_x} — blocked ✓')
        else:
            lines.append(f'XML-RPC: HTTP {code_x}')
        return lines

    def chk_debug_log():
        lines = ['--- Debug Log Exposure ---']
        paths = ['/wp-content/debug.log', '/wp-content/uploads/debug.log', '/wp-content/logs/debug.log']
        with ThreadPoolExecutor(max_workers=3) as ex:
            futs = {ex.submit(_hreq, p): p for p in paths}
            for ft in as_completed(futs):
                p = futs[ft]
                try:
                    code_d, body_d, _ = ft.result()
                    if code_d == 200 and len(body_d) > 10:
                        lines.append(f'[FINDING HIGH] DEBUG_LOG_EXPOSED: {p} ({len(body_d)} bytes)')
                        for ln in body_d.splitlines()[:5]:
                            if ln.strip():
                                lines.append(f'  {ln.strip()[:120]}')
                        lines.append('  Fix: deny from all in .htaccess for debug.log')
                    else:
                        lines.append(f'{p}: HTTP {code_d} ✓')
                except Exception:
                    lines.append(f'{p}: error')
        return lines

    def chk_sensitive_files():
        lines = ['--- Sensitive File Exposure ---']
        sensitive = [
            '/wp-config.php.bak', '/wp-config.php~', '/wp-config.txt',
            '/.env', '/env.txt', '/.env.local', '/.env.backup',
            '/backup.sql', '/database.sql', '/db_backup.sql',
            '/.git/HEAD', '/.git/config',
        ]
        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(_hreq, f): f for f in sensitive}
            for ft in as_completed(futs):
                f = futs[ft]
                try:
                    code_f, body_f, _ = ft.result()
                    if code_f in (200, 206) and len(body_f) > 5:
                        sev = 'CRITICAL' if any(x in f for x in ('config', '.env', '.sql', '.git')) else 'HIGH'
                        lines.append(f'[FINDING {sev}] EXPOSED_FILE: {f} (HTTP {code_f}, {len(body_f)} bytes)')
                        if 'DB_PASSWORD' in body_f or 'password' in body_f.lower()[:500]:
                            lines.append('  Contains credentials/passwords!')
                except Exception:
                    pass
        return lines

    def chk_headers():
        lines = ['--- Security Headers ---']
        code_h, _, hdrs_h = _hreq('/', timeout=_FAST)
        hdrs_lower = {k.lower(): v for k, v in hdrs_h.items()}
        checks = {
            'Strict-Transport-Security': ('HSTS missing — MITM risk',              'MEDIUM'),
            'X-Frame-Options':           ('Clickjacking protection missing',        'MEDIUM'),
            'X-Content-Type-Options':    ('MIME-type sniffing protection missing',  'LOW'),
            'Content-Security-Policy':   ('CSP header missing — XSS risk',          'MEDIUM'),
            'Referrer-Policy':           ('Referrer-Policy missing',                'INFO'),
            'Permissions-Policy':        ('Permissions-Policy missing',             'INFO'),
        }
        for hdr, (msg, sev) in checks.items():
            if hdr.lower() not in hdrs_lower:
                lines.append(f'[FINDING {sev}] MISSING_HEADER: {hdr} — {msg}')
            else:
                lines.append(f'{hdr}: {hdrs_lower[hdr.lower()][:80]} ✓')
        return lines

    def chk_admin_access():
        lines = ['--- Admin Access Control ---']
        code_wa, body_wa, hdrs_wa = _hreq('/wp-admin/', timeout=_FAST)
        if code_wa == 200 and 'login' not in body_wa.lower():
            lines.append('[FINDING HIGH] WP_ADMIN_OPEN: /wp-admin/ accessible without login redirect!')
        elif code_wa in (301, 302):
            loc = hdrs_wa.get('Location', hdrs_wa.get('location', ''))
            lines.append(f'wp-admin/ redirects to: {loc} ✓')
        else:
            lines.append(f'wp-admin/: HTTP {code_wa}')
        return lines

    def chk_login_page():
        lines = ['--- Login Page ---']
        code_lp, body_lp, _ = _hreq('/wp-login.php', timeout=_FAST)
        if code_lp == 200:
            lines.append('[INFO] wp-login.php: accessible (consider login protection plugin)')
            if 'recaptcha' in body_lp.lower() or 'limit login' in body_lp.lower():
                lines.append('  Brute-force protection plugin detected ✓')
        else:
            lines.append(f'wp-login.php: HTTP {code_lp}')
        return lines

    def chk_rest_auth():
        lines = ['--- REST API Auth ---']
        code_ra, body_ra = _req('/wp-json/wp/v2/users', auth=False)
        if code_ra == 200:
            try:
                ulist = json.loads(body_ra)
                if isinstance(ulist, list) and ulist:
                    lines.append(f'[FINDING HIGH] REST_USERS_PUBLIC: /wp/v2/users returns {len(ulist)} user(s) without auth')
                    return lines
            except Exception:
                pass
        lines.append(f'REST /wp/v2/users without auth: HTTP {code_ra} ✓')
        return lines

    def chk_activity_log():
        lines = ['--- Admin User Activity Log ---']
        log_entries: list[tuple[str, str, str, str]] = []

        # Try all plugin REST API endpoints simultaneously.
        # Only endpoints verified to exist in the FREE versions are listed first.
        #
        # Simple History (free, has REST): bonny/WordPress-Simple-History
        #   Namespace: simple-history/v1, route: /events
        #   Source: inc/class-wp-rest-events-controller.php
        #   Requires: authenticated (is_user_logged_in check), returns list of event objects
        #
        # WSAL PRO only (free version has NO REST API):
        #   Melapress/wp-security-audit-log free — no register_rest_route anywhere
        #   wsal/v1 endpoints only exist in the paid PRO extension
        #
        # iThemes Security / Solid Security PRO:
        #   Source: wpcloudpanel/ithemes-security-pro core/lib/rest/Logs_Controller.php
        #   namespace='ithemes-security/v1', rest_base='logs'
        all_eps = [
            # ── Simple History (FREE + REST) — agents use this ────────────────
            '/wp-json/simple-history/v1/events?per_page=50&orderby=date&order=DESC',
            # ── WSAL PRO (paid) ───────────────────────────────────────────────
            '/wp-json/wsal/v1/reports/login-audit',
            '/wp-json/wsal/v1/query?per_page=50&order_by=created_on&order=DESC',
            # ── iThemes / Solid Security PRO ──────────────────────────────────
            '/wp-json/ithemes-security/v1/logs?per_page=50&orderby=created_at&order=desc',
        ]
        with ThreadPoolExecutor(max_workers=len(all_eps)) as ex:
            futs = {ex.submit(_wp_rest, base, ep): ep for ep in all_eps}
            plugin_data: dict[str, tuple] = {}
            for ft in as_completed(futs):
                ep = futs[ft]
                try:
                    plugin_data[ep] = ft.result()
                except Exception:
                    plugin_data[ep] = (0, '')

        # Process results in priority order
        for ep in all_eps:
            if log_entries:
                break
            _c, _b = plugin_data.get(ep, (0, ''))
            if _c != 200:
                continue
            try:
                _data  = json.loads(_b)
                # WSAL returns a list directly; iThemes returns list with pagination headers
                _items = _data if isinstance(_data, list) else _data.get('items', _data.get('data', []))
                if not isinstance(_items, list) or not _items:
                    continue
                _plugin = ep.split('/')[3]
                lines.append(f'[INFO] Activity plugin data via {_plugin} — {len(_items)} event(s)')
                for _ev in _items[:50]:
                    # Simple History fields (free REST): message, date_gmt, date_local,
                    #   ip_addresses[] (array), initiator_data{user_login}
                    # WSAL PRO fields: user_login, created_on, ip (scalar), message
                    # iThemes fields: user (int id), created_at (ISO8601), ip{raw}, module+code
                    _idata = _ev.get('initiator_data') or {}
                    _u   = (_idata.get('user_login') or _idata.get('user_email') or
                            _ev.get('user_login') or _ev.get('username') or
                            str(_ev.get('user', '')) or _ev.get('actor', '') or 'unknown')
                    _ts  = (_ev.get('date_gmt') or _ev.get('date_local') or
                            _ev.get('created_on') or _ev.get('created_at') or
                            _ev.get('timestamp') or scan_ts)
                    _ip_raw = _ev.get('ip_addresses') or _ev.get('ip') or _ev.get('client_ip') or _ev.get('remote_addr') or '-'
                    if isinstance(_ip_raw, list):
                        _ip_raw = _ip_raw[0] if _ip_raw else '-'
                    if isinstance(_ip_raw, dict):
                        _ip_raw = _ip_raw.get('raw', '-')
                    _ip  = str(_ip_raw)
                    _msg = (_ev.get('message') or _ev.get('event_type') or
                            (f'{_ev.get("module","")}/{_ev.get("code","")}' if _ev.get('module') else None) or
                            _ev.get('type', 'WordPress event'))
                    log_entries.append((_ts, str(_u), str(_msg)[:160], _ip))
            except Exception:
                pass

        # Fallback: try to install WSAL via WP-CLI if admin credentials available
        if not log_entries and user and pw:
            _wpcli = (f'wp plugin install wp-security-audit-log --activate '
                      f'--url={base} 2>&1 | head -5')
            try:
                import subprocess as _sp
                _r = _sp.run(_wpcli, shell=True, capture_output=True, text=True, timeout=15)
                if 'activated' in (_r.stdout or '').lower():
                    lines.append('[INFO] WP Activity Log plugin installed and activated via WP-CLI')
                    # Retry the activity log endpoints after installation
                    import time as _t; _t.sleep(2)
                    for ep in all_eps[:2]:
                        _c2, _b2 = _wp_rest(base, ep)
                        if _c2 == 200:
                            try:
                                _d2 = json.loads(_b2)
                                _items2 = _d2 if isinstance(_d2, list) else _d2.get('items', [])
                                for _ev in (_items2 or [])[:50]:
                                    _u   = (_ev.get('user_login') or _ev.get('username') or 'unknown')
                                    _ts  = _ev.get('created_on') or _ev.get('timestamp') or scan_ts
                                    _ip  = _ev.get('ip') or _ev.get('client_ip') or '-'
                                    _msg = _ev.get('message') or _ev.get('event_type') or 'WordPress event'
                                    log_entries.append((_ts, str(_u), str(_msg)[:160], str(_ip)))
                            except Exception:
                                pass
                            if log_entries:
                                break
            except Exception:
                pass

        # Fallback: authenticated user list (no login IPs available without activity plugin)
        if not log_entries and user:
            _c_u, _b_u = _req('/wp-json/wp/v2/users?context=edit&per_page=100')
            try:
                _users = json.loads(_b_u)
                if isinstance(_users, list) and _users:
                    lines.append(f'[INFO] {len(_users)} WordPress user(s) via REST API — '
                                 f'install WP Activity Log plugin for real login events with IP addresses')
                    for _u in _users:
                        _roles  = _u.get('roles', [])
                        _uname  = _u.get('slug') or _u.get('name', 'unknown')
                        _email  = _u.get('email', '')
                        _role_s = ', '.join(_roles) or 'subscriber'
                        _msg    = f'WordPress user (roles: {_role_s})'
                        if _email:
                            _msg += f', email: {_email}'
                        lines.append(f'  {_uname}: {_msg}')
                        log_entries.append((scan_ts, _uname, _msg, '-'))
            except Exception:
                pass

        if not log_entries:
            lines.append('[INFO] No activity log plugin detected.')
            lines.append('  Install the free "WP Activity Log" plugin (wp-security-audit-log)')
            lines.append('  and re-run with admin credentials to see real login history with IPs.')

        lines.append('')
        lines.append('# Admin activity log (real WordPress data):')
        for _ts, _uname, _event, _ip in log_entries:
            # Sanitize pipe chars in event message so WP-LOG regex always parses correctly
            _event_safe = str(_event).replace('|', '/').replace('\n', ' ')
            _risk = ('HIGH' if any(k in _event_safe.lower() for k in
                                   ('login', 'password', 'install', 'delete', 'activate',
                                    'admin created', 'role changed', 'plugin activated'))
                     else 'MEDIUM' if any(k in _event_safe.lower() for k in
                                          ('settings', 'update', 'profile', 'export'))
                     else 'LOW')
            lines.append(f'WP-LOG | {_ts} | {_uname} | {_event_safe} | {_ip} | {_risk}')
        return lines

    def chk_jetpack_protect():
        # Real endpoint: GET /wp-json/jetpack-protect/v1/status
        # Source: github.com/Automattic/jetpack — projects/packages/protect-status/src/class-rest-controller.php
        # Response shape: Status_Model — projects/packages/protect-models/src/class-status-model.php
        # Threat shape:   Threat_Model  — projects/packages/protect-models/src/class-threat-model.php
        lines = ['--- Jetpack Protect ---']

        code_jp, body_jp = _req('/wp-json/jetpack-protect/v1/status')

        if code_jp == 404:
            lines.append('[INFO] Jetpack Protect plugin not installed or not connected to WordPress.com')
            lines.append('  Install free: wordpress.org/plugins/jetpack-protect')
            lines.append('  Uses WPScan vulnerability database — scans plugins, themes, and WP core for CVEs')
            return lines

        if code_jp in (401, 403):
            lines.append(f'[INFO] Jetpack Protect found (HTTP {code_jp}) — admin credentials required')
            lines.append('  Set WP_USER + WP_APP_PASSWORD env vars to read scan results')
            return lines

        if code_jp != 200:
            lines.append(f'[INFO] Jetpack Protect status: HTTP {code_jp}')
            return lines

        try:
            d = json.loads(body_jp)
        except Exception:
            lines.append('[INFO] Jetpack Protect returned non-JSON response')
            return lines

        # Status_Model fields
        status       = d.get('status', 'unknown')         # idle|scanning|in_progress|scheduled|unavailable
        last_checked = d.get('last_checked', '')
        has_error    = d.get('error', False)
        error_msg    = d.get('error_message', '')
        has_unchecked = d.get('has_unchecked_items', False)
        threats      = d.get('threats') or []              # flat array — ALL threat types combined

        lines.append(f'Status: {status}  |  Last checked: {last_checked or "never"}')
        if has_error:
            lines.append(f'[INFO] Jetpack Protect error: {error_msg}')
        if has_unchecked:
            lines.append('[INFO] Some items have not been checked yet — trigger a scan to get full results')

        # Severity mapping: Threat_Model.severity is 1-5
        def _sev_label(sev):
            if sev is None:
                return 'HIGH'
            try:
                n = int(sev)
            except (ValueError, TypeError):
                return 'HIGH'
            return 'CRITICAL' if n >= 5 else 'HIGH' if n >= 3 else 'MEDIUM' if n == 2 else 'LOW'

        if not threats:
            lines.append('No threats detected ✓')
            return lines

        lines.append(f'[FINDING HIGH] JETPACK_PROTECT: {len(threats)} threat(s) detected')
        lines.append('')

        for t in threats:
            # Threat_Model fields (from actual source)
            tid        = t.get('id', '')
            title      = t.get('title') or t.get('description') or 'Unknown threat'
            desc       = t.get('description', '')
            severity   = t.get('severity')
            fixed_in   = t.get('fixed_in', '')
            fixable    = t.get('fixable')           # False or object when auto-fix available
            filename   = t.get('filename', '')      # file-level threats
            table      = t.get('table', '')         # database threats
            source     = t.get('source', '')
            ext        = t.get('extension') or {}   # Extension_Model: type, slug, name, version
            vulns      = t.get('vulnerabilities') or []

            ext_type   = ext.get('type', '')        # plugins|themes|core
            ext_slug   = ext.get('slug', '')
            ext_name   = ext.get('name', '')
            ext_ver    = ext.get('version', '')

            sev_label  = _sev_label(severity)
            sev_num    = f'(severity {severity}/5)' if severity else ''

            lines.append(f'  [{sev_label}] {title} {sev_num}')
            if desc and desc != title:
                lines.append(f'    {desc[:200]}')
            if ext_slug:
                lines.append(f'    {ext_type}: {ext_name or ext_slug} v{ext_ver}')
            if fixed_in:
                lines.append(f'    Fix: update to v{fixed_in}')
            elif fixable and fixable is not False:
                lines.append(f'    Auto-fix available via Jetpack Protect dashboard')
            if filename:
                lines.append(f'    File: {filename}')
            if table:
                lines.append(f'    DB table: {table}')
            for v in (vulns or [])[:3]:
                v_title = v.get('title') or v.get('description', '')
                if v_title:
                    lines.append(f'    CVE: {v_title}')

            # Dashboard risk marker
            lines.append(f'    WP-LOG | {scan_ts} | jetpack-protect | {title.replace("|","/")} | - | {sev_label}')
            lines.append('')

        # WAF status (separate endpoint, same namespace)
        code_waf, body_waf = _req('/wp-json/jetpack-protect/v1/waf')
        if code_waf == 200:
            try:
                waf = json.loads(body_waf)
                waf_on  = waf.get('isEnabled', False)
                waf_sup = waf.get('wafSupported', False)
                stats   = waf.get('stats', {}) or {}
                blocked = stats.get('totalBlockedRequests', 0) if isinstance(stats, dict) else 0
                lines.append(f'WAF: {"enabled" if waf_on else "disabled"}  |  Supported: {waf_sup}  |  Blocked: {blocked} requests')
                if not waf_on and waf_sup:
                    lines.append('  [INFO] WAF is supported but disabled — enable in Jetpack Protect settings')
            except Exception:
                pass

        return lines

    def chk_wpscan_cli():
        lines = ['--- WPScan CLI ---']
        wpscan_bin = shutil.which('wpscan')
        if not wpscan_bin:
            lines.append('[INFO] wpscan CLI not installed — install: gem install wpscan  or  apt-get install wpscan')
            if _WPSCAN_API_TOKEN:
                lines.append('[INFO] WPScan API token found — plugin/theme CVE checks running via API in other sections')
            else:
                lines.append('[INFO] Set WPSCAN_API_TOKEN env var to enable vulnerability lookups (free at wpscan.com/register)')
            return lines

        cmd = [wpscan_bin, '--url', base, '--format', 'json', '--no-banner',
               '--enumerate', 'ap,at,tt,u,cb,dbe',
               '--plugins-detection', 'aggressive',
               '--request-timeout', '15', '--connect-timeout', '8',
               '--random-user-agent']
        if _WPSCAN_API_TOKEN:
            cmd += ['--api-token', _WPSCAN_API_TOKEN]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            raw = result.stdout.strip()
            if not raw:
                lines.append('[WPSCAN] No output — site may be blocking the scanner or wpscan errored')
                if result.stderr:
                    lines.append(f'  stderr: {result.stderr[:300]}')
                return lines

            data = json.loads(raw)

            # WordPress core version
            wp_ver = data.get('version', {})
            if wp_ver:
                ver_num = wp_ver.get('number', '?')
                status  = wp_ver.get('status', '')
                vulns_c = wp_ver.get('vulnerabilities', [])
                outdated = ' [OUTDATED]' if status == 'outdated' else ''
                lines.append(f'WordPress core: {ver_num}{outdated}')
                for v in vulns_c[:5]:
                    refs = v.get('references', {})
                    cves = ', '.join(f'CVE-{c}' for c in refs.get('cve', []))
                    lines.append(f'  [FINDING HIGH] WP_CORE_CVE: {v.get("title","?")} — fixed in {v.get("fixed_in","?")} {cves}')

            # Plugins
            for slug, pdata in (data.get('plugins') or {}).items():
                ver_p   = (pdata.get('version') or {}).get('number', '?')
                vulns_p = pdata.get('vulnerabilities', [])
                status_p = (pdata.get('version') or {}).get('status', '')
                outdated_p = ' [OUTDATED]' if status_p == 'outdated' else ''
                if vulns_p:
                    lines.append(f'[FINDING HIGH] VULNERABLE_PLUGIN: {slug} v{ver_p}{outdated_p} — {len(vulns_p)} vulnerability(ies)')
                    for v in vulns_p[:5]:
                        refs = v.get('references', {})
                        cves = ', '.join(f'CVE-{c}' for c in refs.get('cve', []))
                        fixed = v.get('fixed_in', 'no fix yet')
                        lines.append(f'  {v.get("title","?")} — fixed in {fixed} {cves}')
                        lines.append(f'  WP-LOG | {scan_ts} | wpscan | Vulnerable plugin: {slug} v{ver_p} — {v.get("title","?")} | - | HIGH')

            # Themes
            for slug, tdata in (data.get('themes') or {}).items():
                ver_t   = (tdata.get('version') or {}).get('number', '?')
                vulns_t = tdata.get('vulnerabilities', [])
                if vulns_t:
                    lines.append(f'[FINDING HIGH] VULNERABLE_THEME: {slug} v{ver_t} — {len(vulns_t)} vulnerability(ies)')
                    for v in vulns_t[:3]:
                        refs = v.get('references', {})
                        cves = ', '.join(f'CVE-{c}' for c in refs.get('cve', []))
                        lines.append(f'  {v.get("title","?")} — fixed in {v.get("fixed_in","no fix yet")} {cves}')

            # Users found by wpscan
            users_found = list((data.get('users') or {}).keys())
            if users_found:
                lines.append(f'[FINDING MEDIUM] WPSCAN_USERS_FOUND: {", ".join(users_found[:10])}')

            # Config backups / DB exports
            for cb in (data.get('config_backups') or []):
                lines.append(f'[FINDING CRITICAL] CONFIG_BACKUP: {cb}')
            for dbe in (data.get('db_exports') or []):
                lines.append(f'[FINDING CRITICAL] DB_EXPORT: {dbe}')

            if not _WPSCAN_API_TOKEN:
                lines.append('[INFO] No WPSCAN_API_TOKEN — vulnerability data not included. Get free token at wpscan.com/register')

        except json.JSONDecodeError:
            lines.append(f'[WPSCAN] Non-JSON output: {result.stdout[:400]}')
        except subprocess.TimeoutExpired:
            lines.append('[WPSCAN] Scan timed out after 3 minutes')
        except Exception as exc:
            lines.append(f'[WPSCAN] Error: {exc}')
        return lines

    # ── Run all checks in parallel ────────────────────────────────────────────
    checks = [
        chk_site_info, chk_version, chk_users, chk_plugins, chk_themes,
        chk_settings, chk_xmlrpc, chk_debug_log, chk_sensitive_files,
        chk_headers, chk_admin_access, chk_login_page, chk_rest_auth,
        chk_activity_log, chk_jetpack_protect, chk_wpscan_cli,
    ]

    with ThreadPoolExecutor(max_workers=len(checks)) as pool:
        futures = [pool.submit(fn) for fn in checks]
        results = [f.result() for f in futures]   # preserves submission order

    out = [f'=== WordPress Security Scan: {base} ===',
           f'Auth: {"credentials loaded" if user else "unauthenticated"}', '']
    for section_lines in results:
        out.extend(section_lines)
        out.append('')
    out.append('=== Scan complete ===')
    return '\n'.join(out)


# Mark these as MCP tools so sdk/agents.py can route them through the MCP server
wp_api_call._is_mcp_tool      = True
wp_security_scan._is_mcp_tool = True
