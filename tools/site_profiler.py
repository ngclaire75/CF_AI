"""
CF_AI — Intelligent website fingerprinting and technology profiler.
Call profile_target() FIRST on any engagement to detect CMS, framework,
server stack, and get a recommended tool list for that specific site type.
"""
from __future__ import annotations
import re
import json
import subprocess
from sdk.agents import function_tool

_UA  = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
_TO  = 10  # per-request timeout


def _fetch(url: str, method: str = 'GET', follow: bool = True) -> tuple[int, dict, str]:
    """Return (status, headers_lower, body). Empty on error."""
    flags = ['-s', '-L' if follow else '-I', '-4',
             '--connect-timeout', '8', '--max-time', str(_TO),
             '-D', '-',          # dump headers to stdout
             '-A', _UA,
             '-H', 'Accept: text/html,application/xhtml+xml,*/*;q=0.8',
             '-H', 'Accept-Language: en-US,en;q=0.9',
             url]
    try:
        r = subprocess.run(['curl'] + flags, capture_output=True, text=True, timeout=_TO + 5)
        raw = r.stdout
    except Exception:
        return 0, {}, ''

    # Split header block from body
    parts    = raw.split('\r\n\r\n', 1)
    hdr_raw  = parts[0] if parts else ''
    body     = parts[1] if len(parts) > 1 else ''

    # Status line
    status = 0
    for line in hdr_raw.splitlines():
        m = re.match(r'HTTP/[\d.]+ (\d{3})', line)
        if m:
            status = int(m.group(1))

    # Headers → lower-case dict (last value wins on dupes)
    headers: dict[str, str] = {}
    for line in hdr_raw.splitlines()[1:]:
        if ':' in line:
            k, _, v = line.partition(':')
            headers[k.strip().lower()] = v.strip()

    return status, headers, body


def _probe(url: str) -> tuple[int, dict, str]:
    """Quick probe — returns status, headers, first 6000 chars of body."""
    s, h, b = _fetch(url)
    return s, h, b[:6000]


# ── Fingerprint rules ──────────────────────────────────────────────────────────

_WP_BODY  = re.compile(r'wp-content/|wp-includes/|/wp-json/|xmlrpc\.php|wp-login\.php', re.I)
_WP_VER   = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress ([0-9.]+)', re.I)
_JML_BODY = re.compile(r'Joomla!|/media/jui/|/administrator/|com_content|option=com_', re.I)
_JML_VER  = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla! ([0-9.]+)', re.I)
_DRP_BODY = re.compile(r'Drupal\.settings|/sites/default/|drupal\.js|Drupal\s', re.I)
_DRP_VER  = re.compile(r'Drupal ([0-9]+)', re.I)
_LRV_BODY = re.compile(r'laravel_session|_token.*csrf|Laravel', re.I)
_DJG_BODY = re.compile(r'csrfmiddlewaretoken|django|/static/admin/', re.I)
_FLK_BODY = re.compile(r'Werkzeug|Flask', re.I)
_EXP_BODY = re.compile(r'"express"|"version"\s*:\s*"[0-9]', re.I)
_SBT_BODY = re.compile(r'/actuator/|spring\.io|SpringApplication', re.I)
_NET_BODY = re.compile(r'__VIEWSTATE|\.aspx|ASP\.NET|\.axd', re.I)
_RUBY_BODY= re.compile(r'rails|rack\.session|Phusion Passenger', re.I)
_SPA_BODY = re.compile(r'<div id=["\']app["\']|<div id=["\']root["\']|__NEXT_DATA__|__nuxt|ng-version=', re.I)
_PHP_BODY = re.compile(r'\.php[\?/"]|X-Powered-By:\s*PHP', re.I)

_TECH_MAP = {
    'woocommerce':   re.compile(r'woocommerce|wc-ajax=', re.I),
    'elementor':     re.compile(r'elementor', re.I),
    'contact-form-7':re.compile(r'wpcf7', re.I),
    'yoast-seo':     re.compile(r'yoast|rank-math', re.I),
    'next.js':       re.compile(r'__NEXT_DATA__|_next/static', re.I),
    'nuxt.js':       re.compile(r'__nuxt|_nuxt/', re.I),
    'react':         re.compile(r'react\.development|react\.production|ReactDOM', re.I),
    'vue':           re.compile(r'vue\.js|vue\.min\.js|__vue_app__', re.I),
    'angular':       re.compile(r'ng-version=|angular\.min\.js|zone\.js', re.I),
    'jquery':        re.compile(r'jquery[.-][\d.]+\.min\.js|jquery\.min\.js', re.I),
    'bootstrap':     re.compile(r'bootstrap[.-][\d.]+\.min|bootstrap\.bundle', re.I),
    'cloudflare':    re.compile(r'__cf_|cf-ray|cf-cache-status', re.I),
    'recaptcha':     re.compile(r'recaptcha|g-recaptcha', re.I),
    'google-analytics':re.compile(r'gtag\(|UA-\d{6,}-\d|G-[A-Z0-9]{10}', re.I),
    'shopify':       re.compile(r'Shopify\.theme|cdn\.shopify\.com', re.I),
    'magento':       re.compile(r'Mage\.Cookies|requirejs/text!Mage', re.I),
    'wix':           re.compile(r'wix\.com|_wixCIDX', re.I),
}


def _detect(url: str, status: int, headers: dict, body: str, full_body: str) -> dict:
    combined = full_body + json.dumps(headers)

    cms       = None
    cms_ver   = None
    framework = None
    server    = headers.get('server', '')
    powered   = headers.get('x-powered-by', '')
    generator = headers.get('x-generator', '')
    php       = bool(re.search(r'php', powered, re.I) or re.search(r'\.php', url, re.I))
    java      = bool(re.search(r'java|tomcat|jetty', server, re.I))

    # CMS detection
    if _WP_BODY.search(combined) or 'wordpress' in generator.lower():
        cms = 'wordpress'
        m   = _WP_VER.search(combined)
        cms_ver = m.group(1) if m else None
    elif _JML_BODY.search(combined) or 'joomla' in generator.lower():
        cms = 'joomla'
        m   = _JML_VER.search(combined)
        cms_ver = m.group(1) if m else None
    elif _DRP_BODY.search(combined) or 'drupal' in generator.lower() or 'drupal' in headers.get('x-generator','').lower():
        cms = 'drupal'
        m   = _DRP_VER.search(combined)
        cms_ver = m.group(1) if m else None
    elif _NET_BODY.search(combined) or 'asp.net' in powered.lower():
        framework = 'dotnet'
        php = False
    elif _SBT_BODY.search(combined) or java:
        framework = 'spring'
        php = False
    elif _DJG_BODY.search(combined):
        framework = 'django'
        php = False
    elif _FLK_BODY.search(combined) or 'werkzeug' in server.lower():
        framework = 'flask'
        php = False
    elif _LRV_BODY.search(combined):
        framework = 'laravel'
        php = True
    elif _RUBY_BODY.search(combined) or 'passenger' in server.lower():
        framework = 'rails'
        php = False
    elif re.search(r'express', powered, re.I) or _EXP_BODY.search(combined):
        framework = 'express'
        php = False
    elif _SPA_BODY.search(combined) and not php:
        framework = 'spa'

    # Technologies
    techs = [t for t, pat in _TECH_MAP.items() if pat.search(combined)]

    # Admin/interesting paths per type
    admin_paths: list[str] = []
    api_endpoints: list[str] = []
    if cms == 'wordpress':
        admin_paths   = ['/wp-admin/', '/wp-login.php', '/xmlrpc.php']
        api_endpoints = ['/wp-json/', '/wp-json/wp/v2/users', '/wp-json/wp/v2/posts']
    elif cms == 'joomla':
        admin_paths   = ['/administrator/', '/administrator/index.php']
        api_endpoints = ['/api/index.php/v1/']
    elif cms == 'drupal':
        admin_paths   = ['/user/login', '/admin/']
        api_endpoints = ['/jsonapi/', '/api/']
    elif framework == 'django':
        admin_paths   = ['/admin/', '/admin/login/']
        api_endpoints = ['/api/', '/api/v1/', '/graphql']
    elif framework in ('flask', 'express', 'rails', 'spring'):
        admin_paths   = ['/admin', '/dashboard', '/management']
        api_endpoints = ['/api/', '/api/v1/', '/api/v2/', '/swagger-ui.html', '/api-docs', '/graphql']
    elif framework == 'dotnet':
        admin_paths   = ['/admin', '/elmah.axd', '/trace.axd']
        api_endpoints = ['/api/', '/swagger/', '/api/values']
    elif framework == 'spring':
        admin_paths   = ['/actuator/']
        api_endpoints = ['/actuator/env', '/actuator/health', '/actuator/mappings']

    # Recommended tools
    tools_to_run: list[str] = ['nuclei_scan', 'hunt_js_secrets']
    tools_to_skip: list[str] = []
    notes: list[str] = []

    if cms == 'wordpress':
        tools_to_run += ['scan_wordpress', 'nuclei_scan(tags=wordpress,wp-plugin)']
        tools_to_skip += ['scan_joomla', 'scan_drupal', 'scan_spring', 'scan_dotnet']
        notes.append('WordPress {}: check xmlrpc.php (brute/SSRF), REST API user enum, outdated plugins'.format(cms_ver or '(version unknown)'))
        if 'woocommerce' in techs:
            notes.append('WooCommerce detected — check /wp-json/wc/v3/ for unauthenticated order/customer data')
    elif cms == 'joomla':
        tools_to_run += ['scan_joomla', 'nuclei_scan(tags=joomla)']
        tools_to_skip += ['scan_wordpress', 'scan_drupal', 'scan_spring', 'scan_dotnet']
        notes.append('Joomla {}: check /administrator/ brute, configuration.php exposure, CVEs'.format(cms_ver or ''))
    elif cms == 'drupal':
        tools_to_run += ['scan_drupal', 'nuclei_scan(tags=drupal)']
        tools_to_skip += ['scan_wordpress', 'scan_joomla', 'scan_spring', 'scan_dotnet']
        notes.append('Drupal {}: check Drupalgeddon (SA-CORE-2018-002), REST API, CHANGELOG.txt version leak'.format(cms_ver or ''))
    elif framework == 'django':
        tools_to_run += ['scan_django_flask', 'nuclei_scan(tags=python,django)']
        tools_to_skip += ['scan_wordpress', 'scan_joomla', 'scan_drupal', 'scan_spring', 'scan_dotnet']
        notes.append('Django: check debug mode (?debug=true), /admin/, CSRF bypass, header injection')
    elif framework == 'flask':
        tools_to_run += ['scan_django_flask', 'nuclei_scan(tags=python,flask)']
        notes.append('Flask/Werkzeug: check debug console (/console), SSTI, open redirects')
    elif framework == 'laravel':
        tools_to_run += ['scan_laravel', 'nuclei_scan(tags=laravel,php)']
        notes.append('Laravel: check .env exposure, debug mode, APP_KEY, deserialization (CVE-2021-3129)')
    elif framework == 'express':
        tools_to_run += ['scan_nodejs', 'nuclei_scan(tags=node,express)']
        tools_to_skip += ['scan_wordpress', 'scan_joomla', 'scan_drupal', 'scan_dotnet']
        notes.append('Express/Node.js: check /api/ for IDOR, JWT none-alg, package.json exposure, prototype pollution')
    elif framework == 'spring':
        tools_to_run += ['scan_java_spring', 'nuclei_scan(tags=spring,java,actuator)']
        tools_to_skip += ['scan_wordpress', 'scan_joomla', 'scan_drupal']
        notes.append('Spring Boot: check /actuator/ endpoints (env, mappings, heapdump), SSRF, SpEL injection')
    elif framework == 'dotnet':
        tools_to_run += ['scan_dotnet', 'nuclei_scan(tags=aspx,iis,dotnet)']
        tools_to_skip += ['scan_wordpress', 'scan_joomla', 'scan_drupal']
        notes.append('.NET/ASP.NET: check ViewState MAC bypass, elmah.axd, trace.axd, padding oracle')
    elif framework == 'rails':
        tools_to_run += ['nuclei_scan(tags=ruby,rails)']
        notes.append('Rails: check CSRF, mass assignment, CVE-2019-5420 (file disclosure)')
    elif framework == 'spa':
        tools_to_run  = ['hunt_js_secrets', 'nuclei_scan(tags=xss,cors,jwt)']
        notes.append('SPA detected: focus on JS bundle secrets, API endpoint enumeration, CORS misconfig, JWT')
    else:
        notes.append('Unknown stack — run broad nuclei + JS scan. Check headers for clues.')

    if php and cms is None:
        tools_to_run.append('nuclei_scan(tags=php,lfi,rfi)')
        notes.append('Generic PHP: check LFI (?page=../), RFI, phpinfo.php, exposed composer.json')

    if 'cloudflare' in techs:
        notes.append('Cloudflare WAF detected — use WAF bypass layers (Googlebot UA, Origin-IP, cloudscraper)')

    return {
        'url':               url,
        'status':            status,
        'cms':               cms,
        'cms_version':       cms_ver,
        'framework':         framework or ('php' if php else 'unknown'),
        'server':            server,
        'x_powered_by':      powered,
        'php':               php,
        'technologies':      techs,
        'admin_paths':       admin_paths,
        'api_endpoints':     api_endpoints,
        'tools_to_run':      list(dict.fromkeys(tools_to_run)),
        'tools_to_skip':     tools_to_skip,
        'notes':             notes,
    }


@function_tool
def profile_target(target: str) -> str:
    """Fingerprint a web target: detect CMS, framework, server stack, technologies.

    ALWAYS call this first on any new engagement before running other tools.
    Returns a structured profile with recommended tools and checks to run or skip
    — this prevents wasting time on irrelevant tests and focuses effort on the
    attack surface that actually exists.

    Args:
        target: Domain or URL, e.g. example.com or https://example.com

    Returns:
        JSON profile: cms, framework, server, technologies, admin_paths,
        api_endpoints, tools_to_run, tools_to_skip, notes.
    """
    if not target.startswith('http'):
        target = 'https://' + target

    target = target.rstrip('/')

    # Primary probe — homepage
    status, headers, body = _probe(target)
    full_body = body

    # If CF challenge or empty, try with Googlebot UA
    if status in (403, 503, 0) or len(body) < 200:
        try:
            r = subprocess.run(
                ['curl', '-s', '-L', '-4', '--connect-timeout', '8', '--max-time', str(_TO),
                 '-A', 'Googlebot/2.1 (+http://www.google.com/bot.html)',
                 '-H', 'X-Forwarded-For: 66.249.66.1', '-D', '-', target],
                capture_output=True, text=True, timeout=_TO + 5
            )
            parts = r.stdout.split('\r\n\r\n', 1)
            if len(parts) > 1 and len(parts[1]) > len(body):
                hdr_raw = parts[0]
                body    = parts[1][:6000]
                full_body = body
                for line in hdr_raw.splitlines()[1:]:
                    if ':' in line:
                        k, _, v = line.partition(':')
                        headers[k.strip().lower()] = v.strip()
        except Exception:
            pass

    # Secondary probes to confirm CMS / tech
    extra_signals = ''
    for path in ['/wp-json/', '/administrator/', '/user/login',
                 '/actuator/health', '/api/', '/robots.txt', '/sitemap.xml']:
        ps, ph, pb = _probe(target + path)
        if ps == 200 and pb:
            extra_signals += pb[:500]

    profile = _detect(target, status, headers, full_body + extra_signals, full_body + extra_signals)

    # ── Format output ──────────────────────────────────────────────────────────
    lines = [
        '╔══ SITE PROFILE ═══════════════════════════════════════════╗',
        '  URL        : {}'.format(profile['url']),
        '  Status     : HTTP {}'.format(profile['status']),
        '  CMS        : {}{}'.format(
            profile['cms'] or '(none detected)',
            ' v{}'.format(profile['cms_version']) if profile['cms_version'] else ''),
        '  Framework  : {}'.format(profile['framework']),
        '  Server     : {}'.format(profile['server'] or '(hidden)'),
        '  X-Powered-By: {}'.format(profile['x_powered_by'] or '(not set)'),
        '  Technologies: {}'.format(', '.join(profile['technologies']) or 'none detected'),
        '',
        '  Admin Paths : {}'.format(', '.join(profile['admin_paths']) or 'none'),
        '  API Endpoints: {}'.format(', '.join(profile['api_endpoints']) or 'none'),
        '',
        '  ✓ RUN THESE TOOLS:',
    ]
    for t in profile['tools_to_run']:
        lines.append('      → {}'.format(t))
    if profile['tools_to_skip']:
        lines.append('  ✗ SKIP (not relevant):')
        lines.append('      {}'.format(', '.join(profile['tools_to_skip'])))
    lines.append('')
    lines.append('  NOTES:')
    for n in profile['notes']:
        lines.append('    • {}'.format(n))
    lines.append('╚════════════════════════════════════════════════════════════╝')
    lines.append('')
    lines.append('JSON: ' + json.dumps(profile))

    return '\n'.join(lines)
