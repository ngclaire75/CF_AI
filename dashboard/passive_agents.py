"""
passive_agents.py — Passive intelligence runners for the CF_AI security dashboard.

Each runner takes (domain: str, on_text: Callable[[str], None]) -> None and streams
formatted findings via on_text. Uses only stdlib (urllib.request). No crashes.
"""

from __future__ import annotations

import json
import os
import re
import socket
import time
import urllib.request
import urllib.parse
import concurrent.futures
from pathlib import Path
from typing import Callable

_TIMEOUT = 12  # seconds per HTTP call

_RETIREJS_URL   = ('https://raw.githubusercontent.com/RetireJS/retire.js'
                   '/master/repository/jsrepository.json')
_RETIREJS_CACHE = Path(__file__).parent.parent / 'data' / 'retirejs_db.json'
_RETIREJS_TTL   = 86400  # 24 h — re-fetch once per day

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get_json(url: str, headers: dict | None = None) -> object:
    """Fetch URL and return parsed JSON, or raise on error."""
    req = urllib.request.Request(url, headers=headers or {})
    req.add_header('User-Agent', 'CF_AI-PassiveScanner/1.0')
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return json.loads(resp.read().decode('utf-8', errors='replace'))


def _get_text(url: str, headers: dict | None = None) -> str:
    """Fetch URL and return raw text, or raise on error."""
    req = urllib.request.Request(url, headers=headers or {})
    req.add_header('User-Agent', 'CF_AI-PassiveScanner/1.0')
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return resp.read().decode('utf-8', errors='replace')


def _get_response(url: str, headers: dict | None = None):
    """Fetch URL and return (text_body, response_headers_dict). Raises on error."""
    req = urllib.request.Request(url, headers=headers or {})
    req.add_header('User-Agent', 'CF_AI-PassiveScanner/1.0')
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        body = resp.read().decode('utf-8', errors='replace')
        resp_headers = dict(resp.headers)
        return body, resp_headers


# ---------------------------------------------------------------------------
# DNS via Cloudflare DoH
# ---------------------------------------------------------------------------

def _doh_query(name: str, rtype: str) -> list[str]:
    """Query Cloudflare DoH and return answer values."""
    url = f'https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(name)}&type={rtype}'
    try:
        data = _get_json(url, headers={'Accept': 'application/dns-json'})
        answers = data.get('Answer', [])
        return [a.get('data', '').rstrip('.') for a in answers if a.get('data')]
    except Exception:
        return []


def _resolve_ip(domain: str) -> str | None:
    """Resolve domain to first IPv4 address, return None on failure."""
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

def _parse_version(ver_str: str) -> tuple[int, ...]:
    """Parse version string to a tuple of ints, ignoring pre-release suffixes."""
    # Strip anything after a letter (a, b, rc, etc.)
    clean = re.split(r'[a-zA-Z]', ver_str.strip())[0].rstrip('.')
    parts = []
    for p in clean.split('.'):
        try:
            parts.append(int(p))
        except ValueError:
            break
    return tuple(parts) if parts else (0,)


def _version_below(ver_str: str, threshold: str) -> bool:
    """Return True if ver_str < threshold (version comparison)."""
    try:
        return _parse_version(ver_str) < _parse_version(threshold)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Tech fingerprint patterns
# ---------------------------------------------------------------------------

_TECH_PATTERNS = [
    ('WordPress',        ['/wp-content/', '/wp-includes/', 'wp-json', 'WordPress']),
    ('Joomla',           ['/components/com_', 'Joomla!', '/templates/system/']),
    ('Drupal',           ['Drupal.settings', '/sites/default/files/', 'X-Generator: Drupal']),
    ('Shopify',          ['cdn.shopify.com', 'Shopify.theme', 'myshopify.com']),
    ('Wix',              ['wixstatic.com', 'X-Wix-', 'wix.com']),
    ('Squarespace',      ['squarespace.com', 'static1.squarespace.com']),
    ('React',            ['__REACT_', 'react.development.js', 'react-dom', 'data-reactroot']),
    ('Next.js',          ['__NEXT_DATA__', '_next/static/', 'next/dist']),
    ('Angular',          ['ng-version', 'angular.min.js', 'ng-app', '__ng_']),
    ('Vue.js',           ['vue.min.js', '__vue__', 'v-app', 'v-bind']),
    ('jQuery',           ['jquery.min.js', 'jQuery v', 'jquery-']),
    ('Bootstrap',        ['bootstrap.min.css', 'bootstrap.min.js', 'Bootstrap']),
    ('Tailwind',         ['tailwindcss', 'tw-']),
    ('Laravel',          ['laravel_session', 'XSRF-TOKEN', 'Laravel']),
    ('Django',           ['csrfmiddlewaretoken', 'django', '__admin_media_prefix__']),
    ('Rails',            ['authenticity_token', 'data-remote="true"', 'rails-ujs']),
    ('ASP.NET',          ['__VIEWSTATE', 'asp.net', 'X-AspNet-Version', 'X-Powered-By: ASP.NET']),
    ('PHP',              ['X-Powered-By: PHP', '.php?', 'PHPSESSID']),
    ('Node.js',          ['X-Powered-By: Express', 'connect.sid', 'Node.js']),
    ('Nginx',            ['Server: nginx', 'nginx/']),
    ('Apache',           ['Server: Apache', 'Apache/']),
    ('Cloudflare',       ['CF-Ray', '__cfduid', 'cf-cache-status', 'cloudflare']),
    ('Google Analytics', ['google-analytics.com/analytics.js', 'gtag(', 'UA-', 'G-']),
    ('Google Tag Manager', ['googletagmanager.com/gtm.js', 'GTM-']),
    ('reCAPTCHA',        ['recaptcha.net', 'google.com/recaptcha']),
    ('Stripe',           ['js.stripe.com', 'Stripe(']),
    ('Intercom',         ['widget.intercom.io', 'intercomSettings']),
    ('HubSpot',          ['js.hs-scripts.com', 'hubspot.com']),
    ('Zendesk',          ['static.zdassets.com', 'zE(']),
    ('Font Awesome',     ['fontawesome', 'fa-']),
]

# ---------------------------------------------------------------------------
# Full Retire.js database — live-fetched, locally cached, 24 h TTL
# ---------------------------------------------------------------------------

def _load_retirejs_db() -> tuple[dict, str]:
    """Return (db_dict, source_label) where source is 'live', 'cached', or 'builtin'.

    Priority:
    1. Fresh local cache  (< 24 h old)
    2. Fetch from GitHub  (and save to cache)
    3. Stale cache        (any age, beats builtin)
    4. Empty dict         (all API calls failed — supply-chain still runs, finds nothing)
    """
    # 1. Fresh cache
    if _RETIREJS_CACHE.exists():
        age = time.time() - _RETIREJS_CACHE.stat().st_mtime
        if age < _RETIREJS_TTL:
            try:
                db = json.loads(_RETIREJS_CACHE.read_text('utf-8'))
                if isinstance(db, dict) and len(db) > 50:
                    return db, f'cached ({int(age/3600)}h old, {len(db)} libraries)'
            except Exception:
                pass

    # 2. Live fetch
    try:
        req = urllib.request.Request(
            _RETIREJS_URL,
            headers={'User-Agent': 'CF_AI-PassiveScanner/1.0',
                     'Accept': 'application/json'},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode('utf-8', errors='replace')
        db = json.loads(raw)
        if isinstance(db, dict) and len(db) > 50:
            try:
                _RETIREJS_CACHE.parent.mkdir(parents=True, exist_ok=True)
                _RETIREJS_CACHE.write_text(raw, encoding='utf-8')
            except Exception:
                pass
            return db, f'live (fetched {len(db)} libraries from github.com/RetireJS)'
    except Exception:
        pass

    # 3. Stale cache fallback
    if _RETIREJS_CACHE.exists():
        try:
            db = json.loads(_RETIREJS_CACHE.read_text('utf-8'))
            if isinstance(db, dict) and len(db) > 50:
                age_h = int((time.time() - _RETIREJS_CACHE.stat().st_mtime) / 3600)
                return db, f'stale cache ({age_h}h old — offline?)'
        except Exception:
            pass

    return {}, 'unavailable — no DB loaded, no JS vulns will be checked'


_RJS_VER_PH = '§§version§§'   # §§version§§ placeholder in Retire.js patterns
_RJS_VER_RE = '([0-9][^\\s/\'"<>]*)'             # capture group that replaces the placeholder


def _js_pat_to_python(pat: str) -> str:
    """Convert a Retire.js extractor pattern to a Python-compatible regex.

    Retire.js patterns use §§version§§ (§§version§§) as a
    placeholder that should become a capturing group for the version string.
    Patterns may also be wrapped in JS regex literal syntax: /pattern/flags.
    """
    pat = pat.strip()
    # Strip JS regex literal wrapper /.../ (keep flags for now, Python handles case via re.I)
    m = re.match(r'^/(.+)/[gimsuy]*$', pat, re.DOTALL)
    if m:
        pat = m.group(1)
    # Replace the version placeholder with a named capture group
    pat = pat.replace(_RJS_VER_PH, _RJS_VER_RE)
    return pat


_VER_CLEANUP_RE = re.compile(r'[./](min|js|css|bundle|esm|cjs)$', re.I)


def _fetch_script_head(url: str, max_bytes: int = 4096) -> str:
    """Fetch the first max_bytes of a JS file for content-based fingerprinting.
    Returns '' on any error — always safe to call.
    """
    try:
        # Only fetch absolute URLs; skip data: and blob: schemes
        if not url.startswith(('http://', 'https://')):
            return ''
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'CF_AI-PassiveScanner/1.0',
                     'Range': f'bytes=0-{max_bytes - 1}'},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.read(max_bytes).decode('utf-8', errors='replace')
    except Exception:
        return ''


def _check_scripts_against_retirejs(
    script_urls: list[str],
    db: dict,
    fetch_content: bool = True,
    max_content_fetches: int = 12,
) -> list[dict]:
    """Match script URLs against the full Retire.js vulnerability DB.

    Two detection passes:
    1. URL/filename pattern matching  — fast, no network calls
    2. File-content pattern matching  — fetches first 4KB of each script (up to
       max_content_fetches scripts) to catch libraries like Lodash that don't
       encode the version in their filename.

    Returns a list of finding dicts sorted CRITICAL → HIGH → MEDIUM → LOW → INFO.
    """
    sev_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    findings: list[dict] = []
    seen: set[tuple] = set()

    # Pre-compile all patterns per library per extractor type
    lib_patterns: list[tuple[str, str, list[tuple[str, re.Pattern]]]] = []
    for lib_key, lib_data in db.items():
        if not isinstance(lib_data, dict) or not lib_data.get('vulnerabilities'):
            continue
        extractors = lib_data.get('extractors', {})
        compiled: list[tuple[str, re.Pattern]] = []
        for etype in ('filename', 'uri', 'filecontent'):
            for raw_pat in extractors.get(etype, []):
                if not isinstance(raw_pat, str):
                    continue
                try:
                    compiled.append((etype, re.compile(
                        _js_pat_to_python(raw_pat), re.IGNORECASE | re.DOTALL)))
                except re.error:
                    pass
        if compiled:
            lib_display = (lib_data.get('bowername', [lib_key])[0]
                           if lib_data.get('bowername') else lib_key)
            lib_patterns.append((lib_display, lib_key, compiled))

    def _record_vuln(lib_display: str, url: str, detected_ver: str,
                     vulns: list[dict]) -> None:
        # Strip .min/.js/.css suffix that sometimes bleeds into the version capture
        ver = _VER_CLEANUP_RE.sub('', detected_ver).strip(' \t\r\n')
        for vuln in vulns:
            below       = vuln.get('below', '') or ''
            at_or_above = vuln.get('atOrAbove', '') or ''
            if not below:
                continue
            if not _version_below(ver, below):
                continue
            if at_or_above and _version_below(ver, at_or_above):
                continue
            ids     = vuln.get('identifiers', {}) or {}
            cves    = ids.get('CVE', []) or []
            summary = (ids.get('summary', '')
                       or (cves[0] if cves else f'{lib_display} < {below}'))
            sev = (vuln.get('severity') or 'medium').upper()
            if sev not in sev_rank:
                sev = 'MEDIUM'
            key = (lib_display, url, below)
            if key not in seen:
                seen.add(key)
                findings.append({
                    'lib':         lib_display,
                    'version':     ver,
                    'below':       below,
                    'at_or_above': at_or_above,
                    'cves':        cves[:5],
                    'severity':    sev,
                    'summary':     summary[:250],
                    'url':         url,
                })

    # ── Pass 1: URL/filename matching (no network) ────────────────────────────
    for url in script_urls:
        url_clean    = url.split('?')[0].split('#')[0]
        url_filename = url_clean.rsplit('/', 1)[-1]

        for lib_display, lib_key, compiled in lib_patterns:
            for etype, pat in compiled:
                if etype == 'filecontent':
                    continue
                target = url_filename if etype == 'filename' else url_clean
                try:
                    m = pat.search(target)
                    if not m:
                        continue
                    try:
                        detected_ver = m.group(1)
                    except IndexError:
                        continue
                    _record_vuln(lib_display, url, detected_ver,
                                 db[lib_key]['vulnerabilities'])
                    break
                except Exception:
                    continue

    # ── Pass 2: File-content matching (fetches script heads in parallel) ──────
    if fetch_content:
        # Only fetch absolute external URLs not already confirmed vulnerable
        confirmed_urls = {f['url'] for f in findings}
        to_fetch = [
            u for u in script_urls
            if u.startswith(('http://', 'https://')) and u not in confirmed_urls
        ][:max_content_fetches]

        if to_fetch:
            contents: dict[str, str] = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                fmap = {pool.submit(_fetch_script_head, u): u for u in to_fetch}
                for fut in concurrent.futures.as_completed(fmap, timeout=15):
                    u = fmap[fut]
                    try:
                        contents[u] = fut.result() or ''
                    except Exception:
                        contents[u] = ''

            for url, content in contents.items():
                if not content:
                    continue
                for lib_display, lib_key, compiled in lib_patterns:
                    for etype, pat in compiled:
                        if etype != 'filecontent':
                            continue
                        try:
                            m = pat.search(content)
                            if not m:
                                continue
                            try:
                                detected_ver = m.group(1)
                            except IndexError:
                                continue
                            _record_vuln(lib_display, url, detected_ver,
                                         db[lib_key]['vulnerabilities'])
                            break
                        except Exception:
                            continue

    findings.sort(key=lambda f: (sev_rank.get(f['severity'], 5), f['lib']))
    return findings

# ---------------------------------------------------------------------------
# Dangling DNS cloud provider CNAME suffixes
# ---------------------------------------------------------------------------

_CLOUD_CNAME_SUFFIXES = [
    's3.amazonaws.com', 'cloudfront.net', 'azurewebsites.net', 'azurefd.net',
    'blob.core.windows.net', 'github.io', 'netlify.app', 'vercel.app',
    'pages.dev', 'fly.dev', 'herokuapp.com', 'fastly.net',
]

# ---------------------------------------------------------------------------
# Runner 1: Passive Recon — Shodan InternetDB + DNS + crt.sh
# ---------------------------------------------------------------------------

def run_recon_passive(domain: str, on_text: Callable[[str], None]) -> None:
    """Passive recon: Shodan InternetDB + DNS records (DoH) + crt.sh cert history."""
    on_text(f'\n[PASSIVE RECON] Starting passive reconnaissance for: {domain}\n')
    on_text('=' * 60 + '\n')

    futures_map: dict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        # DNS lookups
        futures_map['dns_a']   = pool.submit(_doh_query, domain, 'A')
        futures_map['dns_mx']  = pool.submit(_doh_query, domain, 'MX')
        futures_map['dns_txt'] = pool.submit(_doh_query, domain, 'TXT')
        futures_map['dns_ns']  = pool.submit(_doh_query, domain, 'NS')
        # Shodan IP resolve (pre-step)
        futures_map['ip']      = pool.submit(_resolve_ip, domain)
        # crt.sh cert history
        futures_map['certs']   = pool.submit(
            _get_json, f'https://crt.sh/?q={urllib.parse.quote(domain)}&output=json'
        )

    # -- DNS results --
    on_text('\n[INFO] DNS Records\n')
    on_text('-' * 40 + '\n')

    a_records = futures_map['dns_a'].result() if not futures_map['dns_a'].exception() else []
    mx_records = futures_map['dns_mx'].result() if not futures_map['dns_mx'].exception() else []
    txt_records = futures_map['dns_txt'].result() if not futures_map['dns_txt'].exception() else []
    ns_records = futures_map['dns_ns'].result() if not futures_map['dns_ns'].exception() else []

    if a_records:
        on_text(f'A records: {", ".join(a_records)}\n')
    else:
        on_text('[LOW] No A records resolved — domain may be inactive or behind CDN\n')

    if ns_records:
        on_text(f'NS records: {", ".join(ns_records)}\n')

    if mx_records:
        on_text(f'MX records: {", ".join(mx_records)}\n')
    else:
        on_text('[LOW] No MX records found — mail may not be configured\n')

    if txt_records:
        on_text('TXT records:\n')
        for txt in txt_records:
            on_text(f'  {txt}\n')

    # -- Shodan InternetDB --
    on_text('\n[INFO] Shodan InternetDB Lookup\n')
    on_text('-' * 40 + '\n')

    resolved_ip = futures_map['ip'].result() if not futures_map['ip'].exception() else None

    if resolved_ip:
        on_text(f'Resolved IP: {resolved_ip}\n')
        try:
            shodan_data = _get_json(f'https://internetdb.shodan.io/{resolved_ip}')
            ports = shodan_data.get('ports', [])
            cpes  = shodan_data.get('cpes', [])
            cves  = shodan_data.get('vulns', [])
            tags  = shodan_data.get('tags', [])
            hostnames = shodan_data.get('hostnames', [])

            if ports:
                on_text(f'Open ports: {", ".join(str(p) for p in ports)}\n')
                # Flag well-known sensitive ports
                risky = {p: name for p, name in {
                    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
                    445: 'SMB', 1433: 'MSSQL', 1521: 'Oracle DB',
                    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
                    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
                    8443: 'HTTPS-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB',
                }.items() if p in ports}
                if risky:
                    for port, svc in risky.items():
                        sev = '[HIGH]' if port in (6379, 9200, 27017, 5432, 3306, 1433, 3389, 445) else '[MEDIUM]'
                        on_text(f'{sev} open port {port} {svc} exposed on {resolved_ip}\n')
            else:
                on_text('[INFO] No open ports found in Shodan InternetDB\n')

            if tags:
                on_text(f'Tags: {", ".join(tags)}\n')
            if hostnames:
                on_text(f'Hostnames: {", ".join(hostnames)}\n')
            if cpes:
                on_text('CPEs detected:\n')
                for cpe in cpes:
                    on_text(f'  [INFO] {cpe}\n')
            if cves:
                on_text(f'[HIGH] Shodan reports {len(cves)} CVE(s) for {resolved_ip}:\n')
                for cve in cves:
                    on_text(f'  [HIGH] {cve}\n')
            else:
                on_text('[INFO] No CVEs reported by Shodan InternetDB\n')
        except Exception as exc:
            on_text(f'[INFO] Shodan InternetDB lookup failed: {exc}\n')
    else:
        on_text('[LOW] Could not resolve IP for Shodan lookup\n')

    # -- crt.sh certificate history --
    on_text('\n[INFO] Certificate History (crt.sh)\n')
    on_text('-' * 40 + '\n')

    try:
        certs = futures_map['certs'].result()
        if isinstance(certs, list) and certs:
            issuers = set()
            names = set()
            earliest = None
            latest = None
            for cert in certs:
                issuer = cert.get('issuer_name', '')
                name   = cert.get('name_value', '')
                logged = cert.get('entry_timestamp', '')
                if issuer:
                    issuers.add(issuer.split('O=')[-1].split(',')[0].strip())
                if name:
                    for n in name.split('\n'):
                        names.add(n.strip().lower())
                if logged:
                    if earliest is None or logged < earliest:
                        earliest = logged
                    if latest is None or logged > latest:
                        latest = logged

            on_text(f'Total certificates logged: {len(certs)}\n')
            if earliest:
                on_text(f'First seen: {earliest[:10]}  |  Latest: {latest[:10]}\n')
            if issuers:
                on_text(f'Certificate Authorities: {", ".join(sorted(issuers)[:5])}\n')
            # List unique alt names (may reveal subdomains)
            subs = sorted({n for n in names if domain in n and n != domain})
            if subs:
                on_text(f'[INFO] {len(subs)} additional name(s) in cert history:\n')
                for s in subs[:20]:
                    on_text(f'  {s}\n')
        else:
            on_text('[INFO] No certificate history found on crt.sh\n')
    except Exception as exc:
        on_text(f'[INFO] crt.sh cert lookup failed: {exc}\n')

    on_text('\n[INFO] Passive recon complete\n')


# ---------------------------------------------------------------------------
# Runner 2: Breach & Credential Check — HIBP + SPF/DMARC
# ---------------------------------------------------------------------------

def run_breach(domain: str, on_text: Callable[[str], None]) -> None:
    """Breach & credential check: HIBP all-breaches + keyed endpoint + SPF/DMARC DNS."""
    on_text(f'\n[BREACH CHECK] Starting breach & credential checks for: {domain}\n')
    on_text('=' * 60 + '\n')

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        fut_breaches = pool.submit(_get_json, 'https://haveibeenpwned.com/api/v3/breaches')
        fut_spf      = pool.submit(_doh_query, domain, 'TXT')
        fut_dmarc    = pool.submit(_doh_query, f'_dmarc.{domain}', 'TXT')

        hibp_key = os.environ.get('HIBP_API_KEY', '')
        fut_keyed = None
        if hibp_key:
            fut_keyed = pool.submit(
                _get_json,
                f'https://haveibeenpwned.com/api/v3/breacheddomain/{urllib.parse.quote(domain)}',
                {'hibp-api-key': hibp_key},
            )

    # -- HIBP all-breaches filter --
    on_text('\n[INFO] HIBP Breach Database Check (public endpoint)\n')
    on_text('-' * 40 + '\n')
    try:
        all_breaches = fut_breaches.result()
        if isinstance(all_breaches, list):
            matched = [b for b in all_breaches
                       if (b.get('Domain') or '').lower() == domain.lower()]
            if matched:
                on_text(f'[HIGH] Domain "{domain}" appears in {len(matched)} known breach(es):\n')
                for b in matched:
                    pwncount = b.get('PwnCount', 0)
                    date     = b.get('BreachDate', 'unknown')
                    classes  = ', '.join(b.get('DataClasses', []))
                    name     = b.get('Name', 'unknown')
                    on_text(f'  [HIGH] Breach: {name}  |  Date: {date}  |  Pwned: {pwncount:,}\n')
                    on_text(f'         Data classes: {classes}\n')
            else:
                on_text(f'[INFO] Domain "{domain}" not found in HIBP breach database\n')
                on_text(f'       Total breaches in HIBP: {len(all_breaches)}\n')
        else:
            on_text('[INFO] Unexpected HIBP response format\n')
    except Exception as exc:
        on_text(f'[INFO] HIBP all-breaches lookup failed: {exc}\n')

    # -- HIBP keyed endpoint --
    if fut_keyed is not None:
        on_text('\n[INFO] HIBP Subscriber Breach Details (keyed endpoint)\n')
        on_text('-' * 40 + '\n')
        try:
            keyed_result = fut_keyed.result()
            if isinstance(keyed_result, list) and keyed_result:
                on_text(f'[HIGH] HIBP keyed endpoint confirms {len(keyed_result)} breach(es) for {domain}\n')
                for b in keyed_result:
                    on_text(f'  - {b}\n')
            elif keyed_result == [] or keyed_result is None:
                on_text(f'[INFO] HIBP keyed: no breach records for {domain}\n')
            else:
                on_text(f'[INFO] HIBP keyed response: {str(keyed_result)[:200]}\n')
        except Exception as exc:
            status_code = getattr(getattr(exc, 'code', None), 'value', None) or getattr(exc, 'code', None)
            if status_code == 404:
                on_text(f'[INFO] HIBP keyed: no breach data for {domain}\n')
            else:
                on_text(f'[INFO] HIBP keyed endpoint error: {exc}\n')

    # -- SPF check --
    on_text('\n[INFO] Email Security — SPF / DMARC Analysis\n')
    on_text('-' * 40 + '\n')
    try:
        txt_records = fut_spf.result()
        spf_records = [r for r in txt_records if 'v=spf1' in r.lower()]
        if spf_records:
            for spf in spf_records:
                on_text(f'[INFO] SPF record found: {spf}\n')
                if '+all' in spf:
                    on_text('[HIGH] SPF uses "+all" — allows any server to send mail as this domain (email spoofing risk)\n')
                elif '~all' in spf:
                    on_text('[MEDIUM] SPF uses "~all" (softfail) — consider "-all" for strict enforcement\n')
                elif '-all' in spf:
                    on_text('[INFO] SPF uses "-all" — strict enforcement, good configuration\n')
                elif '?all' in spf:
                    on_text('[MEDIUM] SPF uses "?all" (neutral) — no enforcement, missing SPF enforcement\n')
        else:
            on_text('[HIGH] missing SPF record — domain vulnerable to email spoofing\n')
    except Exception as exc:
        on_text(f'[INFO] SPF lookup failed: {exc}\n')

    # -- DMARC check --
    try:
        dmarc_records = fut_dmarc.result()
        dmarc_found = [r for r in dmarc_records if 'v=dmarc1' in r.lower()]
        if dmarc_found:
            for dmarc in dmarc_found:
                on_text(f'[INFO] DMARC record found: {dmarc}\n')
                if 'p=none' in dmarc.lower():
                    on_text('[MEDIUM] DMARC policy is "none" — monitoring only, no enforcement\n')
                elif 'p=quarantine' in dmarc.lower():
                    on_text('[INFO] DMARC policy is "quarantine" — suspicious mail goes to spam\n')
                elif 'p=reject' in dmarc.lower():
                    on_text('[INFO] DMARC policy is "reject" — strict enforcement, good configuration\n')
        else:
            on_text('[HIGH] missing DMARC record — phishing/spoofing protection not configured\n')
    except Exception as exc:
        on_text(f'[INFO] DMARC lookup failed: {exc}\n')

    on_text('\n[INFO] Breach & credential check complete\n')


# ---------------------------------------------------------------------------
# Runner 3: Subdomain Enumeration — crt.sh + HackerTarget + dangling DNS
# ---------------------------------------------------------------------------

def run_subdomain(domain: str, on_text: Callable[[str], None]) -> None:
    """Subdomain enumeration via crt.sh, HackerTarget hostsearch, dangling DNS detection."""
    on_text(f'\n[SUBDOMAIN ENUM] Starting subdomain enumeration for: {domain}\n')
    on_text('=' * 60 + '\n')

    all_subdomains: set[str] = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        fut_crt = pool.submit(
            _get_json,
            f'https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json',
        )
        fut_ht = pool.submit(
            _get_text,
            f'https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}',
        )

    # -- crt.sh subdomains --
    on_text('\n[INFO] crt.sh Subdomain Enumeration\n')
    on_text('-' * 40 + '\n')
    try:
        crt_data = fut_crt.result()
        if isinstance(crt_data, list):
            for entry in crt_data:
                name_val = entry.get('name_value', '')
                for n in name_val.split('\n'):
                    n = n.strip().lower().lstrip('*.')
                    if n.endswith(f'.{domain}') or n == domain:
                        all_subdomains.add(n)
            crt_subs = sorted(all_subdomains)
            on_text(f'Found {len(crt_subs)} unique name(s) via crt.sh:\n')
            for s in crt_subs[:50]:
                on_text(f'  [INFO] {s}\n')
            if len(crt_subs) > 50:
                on_text(f'  ... and {len(crt_subs) - 50} more\n')
        else:
            on_text('[INFO] No crt.sh data returned\n')
    except Exception as exc:
        on_text(f'[INFO] crt.sh subdomain lookup failed: {exc}\n')

    # -- HackerTarget hostsearch --
    on_text('\n[INFO] HackerTarget Hostsearch\n')
    on_text('-' * 40 + '\n')
    ht_subdomains: set[str] = set()
    try:
        ht_text = fut_ht.result()
        lines = ht_text.strip().splitlines()
        if lines and not lines[0].startswith('error'):
            for line in lines:
                parts = line.split(',')
                if len(parts) >= 2:
                    sub = parts[0].strip().lower()
                    ip  = parts[1].strip()
                    ht_subdomains.add(sub)
                    all_subdomains.add(sub)
                    on_text(f'  [INFO] {sub}  ->  {ip}\n')
            on_text(f'HackerTarget found {len(ht_subdomains)} subdomain(s)\n')
        else:
            on_text(f'[INFO] HackerTarget: {ht_text[:200]}\n')
    except Exception as exc:
        on_text(f'[INFO] HackerTarget hostsearch failed: {exc}\n')

    # -- Dangling DNS detection --
    on_text('\n[INFO] Dangling DNS / Subdomain Takeover Detection\n')
    on_text('-' * 40 + '\n')

    candidates = sorted(all_subdomains)[:30]  # cap to avoid excessive requests
    dangling_found = 0

    def _check_dangling(sub: str):
        results = []
        try:
            cnames = _doh_query(sub, 'CNAME')
            for cname in cnames:
                cname_lower = cname.lower()
                for suffix in _CLOUD_CNAME_SUFFIXES:
                    if cname_lower.endswith(suffix):
                        # Check if the target resolves
                        a_records = _doh_query(cname, 'A')
                        if not a_records:
                            results.append(
                                f'[HIGH] Potential subdomain takeover: {sub} -> CNAME {cname} '
                                f'(cloud target does not resolve — dangling DNS)\n'
                            )
                        else:
                            results.append(
                                f'[INFO] {sub} -> CNAME {cname} (resolves OK)\n'
                            )
        except Exception:
            pass
        return results

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        dangling_futures = {pool.submit(_check_dangling, sub): sub for sub in candidates}
        for fut in concurrent.futures.as_completed(dangling_futures):
            try:
                msgs = fut.result()
                for msg in msgs:
                    on_text(msg)
                    if '[HIGH]' in msg:
                        dangling_found += 1
            except Exception:
                pass

    if dangling_found == 0:
        on_text('[INFO] No dangling DNS / subdomain takeover candidates detected\n')

    on_text(f'\n[INFO] Total unique subdomains discovered: {len(all_subdomains)}\n')
    on_text('[INFO] Subdomain enumeration complete\n')


# ---------------------------------------------------------------------------
# Runner 4: Tech Stack Detection — URLScan + header fingerprinting + HTML patterns
# ---------------------------------------------------------------------------

def run_tech_detect(domain: str, on_text: Callable[[str], None]) -> None:
    """Tech stack detection via URLScan.io search, response header analysis, HTML patterns."""
    on_text(f'\n[TECH DETECT] Starting technology stack detection for: {domain}\n')
    on_text('=' * 60 + '\n')

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        fut_urlscan = pool.submit(
            _get_json,
            f'https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(domain)}&size=5',
        )
        fut_site = pool.submit(
            _get_response,
            f'https://{domain}',
        )

    # -- URLScan results --
    on_text('\n[INFO] URLScan.io Intelligence\n')
    on_text('-' * 40 + '\n')
    try:
        urlscan_data = fut_urlscan.result()
        results = urlscan_data.get('results', [])
        if results:
            on_text(f'Found {len(results)} URLScan result(s) for {domain}\n')
            for r in results:
                page   = r.get('page', {})
                stats  = r.get('stats', {})
                task   = r.get('task', {})
                url    = page.get('url', '')
                ip     = page.get('ip', '')
                country = page.get('country', '')
                server = page.get('server', '')
                title  = page.get('title', '')
                tags   = task.get('tags', [])
                uniq_ips  = stats.get('uniqIPs', '')
                uniq_doms = stats.get('uniqDomains', '')

                if url:
                    on_text(f'\n  Scan URL: {url}\n')
                if ip:
                    on_text(f'  IP: {ip}  Country: {country}\n')
                if server:
                    on_text(f'  [INFO] Server header: {server}\n')
                if title:
                    on_text(f'  Page title: {title}\n')
                if uniq_ips:
                    on_text(f'  Unique IPs contacted: {uniq_ips}\n')
                if uniq_doms:
                    on_text(f'  Unique domains contacted: {uniq_doms}\n')
                if tags:
                    on_text(f'  Tags: {", ".join(tags)}\n')
        else:
            on_text(f'[INFO] No URLScan results found for {domain}\n')
    except Exception as exc:
        on_text(f'[INFO] URLScan lookup failed: {exc}\n')

    # -- Header + HTML fingerprinting --
    on_text('\n[INFO] Response Header & HTML Fingerprinting\n')
    on_text('-' * 40 + '\n')

    site_exc = fut_site.exception()
    if site_exc:
        on_text(f'[INFO] Could not fetch site (https://{domain}): {site_exc}\n')
        # Try HTTP fallback
        try:
            html_body, resp_headers = _get_response(f'http://{domain}')
        except Exception as exc2:
            on_text(f'[INFO] HTTP fallback also failed: {exc2}\n')
            on_text('[INFO] Tech detection complete (no page content available)\n')
            return
    else:
        html_body, resp_headers = fut_site.result()

    # Build combined text for pattern matching (headers + HTML)
    headers_text = '\n'.join(f'{k}: {v}' for k, v in resp_headers.items())
    combined = html_body + '\n' + headers_text

    # Identify interesting security headers
    sec_headers = {
        'strict-transport-security': ('HSTS', '[INFO]'),
        'content-security-policy': ('CSP', '[INFO]'),
        'x-frame-options': ('X-Frame-Options', '[INFO]'),
        'x-content-type-options': ('X-Content-Type-Options', '[INFO]'),
        'referrer-policy': ('Referrer-Policy', '[INFO]'),
        'permissions-policy': ('Permissions-Policy', '[INFO]'),
    }
    missing_sec = []
    for hdr_key, (hdr_name, sev) in sec_headers.items():
        found = any(k.lower() == hdr_key for k in resp_headers)
        if found:
            val = next(v for k, v in resp_headers.items() if k.lower() == hdr_key)
            on_text(f'{sev} {hdr_name}: {val[:120]}\n')
        else:
            missing_sec.append(hdr_name)

    if missing_sec:
        on_text(f'[MEDIUM] Missing security headers: {", ".join(missing_sec)}\n')

    # Version-leaking headers
    for hdr_key in ('server', 'x-powered-by', 'x-aspnet-version', 'x-generator'):
        val = next((v for k, v in resp_headers.items() if k.lower() == hdr_key), None)
        if val:
            on_text(f'[MEDIUM] Version disclosure via {hdr_key} header: {val}\n')

    # Tech pattern matching
    on_text('\n[INFO] Wappalyzer-style Technology Detection\n')
    detected = []
    for tech_name, patterns in _TECH_PATTERNS:
        for pat in patterns:
            if pat.lower() in combined.lower():
                detected.append(tech_name)
                break

    if detected:
        on_text(f'[INFO] Detected technologies: {", ".join(detected)}\n')
        for tech in detected:
            on_text(f'  [INFO] {tech}\n')
    else:
        on_text('[INFO] No specific technologies identified from pattern matching\n')

    on_text('\n[INFO] Tech detection complete\n')


# ---------------------------------------------------------------------------
# Runner 5: Supply Chain / JS Audit — HTML script extraction + Retire.js-style check
# ---------------------------------------------------------------------------

def run_supply_chain(domain: str, on_text: Callable[[str], None]) -> None:
    """Supply chain audit: fetch page, extract script src URLs, check against full Retire.js DB."""
    on_text(f'\n[SUPPLY CHAIN] Starting supply chain / JS library audit for: {domain}\n')
    on_text('=' * 60 + '\n')

    # Load Retire.js DB (cached locally, refreshed every 24 h)
    on_text('\n[INFO] Loading Retire.js vulnerability database...\n')
    db, db_source = _load_retirejs_db()
    on_text(f'[INFO] DB source: {db_source}\n')
    if db:
        on_text(f'[INFO] Database covers {len(db)} JS libraries\n')

    # Fetch the page
    on_text(f'\n[INFO] Fetching {domain} to extract script tags...\n')
    html_body = ''
    try:
        html_body, _ = _get_response(f'https://{domain}')
    except Exception as exc:
        on_text(f'[INFO] HTTPS fetch failed ({exc}), trying HTTP...\n')
        try:
            html_body, _ = _get_response(f'http://{domain}')
        except Exception as exc2:
            on_text(f'[HIGH] Cannot fetch page content: {exc2}\n')
            on_text('[INFO] Supply chain audit aborted — page unreachable\n')
            return

    # Extract all <script src="..."> URLs
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_body, re.IGNORECASE)
    on_text(f'\n[INFO] Found {len(script_srcs)} script tag(s) on {domain}\n')
    on_text('-' * 40 + '\n')

    if not script_srcs:
        on_text('[INFO] No external script sources found — page may use inline JS only\n')
        on_text('[INFO] Supply chain audit complete\n')
        return

    for src in script_srcs:
        on_text(f'  {src}\n')

    # Match against full Retire.js DB
    on_text('\n[INFO] Matching scripts against Retire.js vulnerability database\n')
    on_text('-' * 40 + '\n')

    if not db:
        on_text('[MEDIUM] Retire.js DB unavailable — falling back to offline mode\n')
        on_text('[INFO] Re-run when internet is available for full database check\n')
    else:
        on_text('[INFO] Pass 1: URL/filename pattern matching...\n')
        on_text('[INFO] Pass 2: Fetching script content for libraries without versioned filenames '
                '(Lodash, Underscore, etc.) — up to 12 scripts, 4KB each...\n')
        findings = _check_scripts_against_retirejs(script_srcs, db, fetch_content=True)

        if findings:
            critical = [f for f in findings if f['severity'] == 'CRITICAL']
            high     = [f for f in findings if f['severity'] == 'HIGH']
            on_text(f'[HIGH] Found {len(findings)} vulnerable library match(es) '
                    f'({len(critical)} CRITICAL, {len(high)} HIGH)\n\n')

            for f in findings:
                cve_str = ' | CVEs: ' + ', '.join(f['cves']) if f['cves'] else ''
                above_str = f' (>= {f["at_or_above"]})' if f.get('at_or_above') else ''
                on_text(f'[{f["severity"]}] {f["lib"]} v{f["version"]} — {f["summary"]}{cve_str}\n')
                on_text(f'  Vulnerable: v{f["version"]}{above_str} < v{f["below"]}\n')
                on_text(f'  Source URL: {f["url"]}\n\n')
        else:
            on_text('[INFO] No known-vulnerable library versions detected in script URLs\n')
            on_text('       Libraries may be present but versions were not parseable from URLs.\n')
            on_text('       Consider also running Retire.js locally: npm install -g retire && retire --path .\n')

    # Also flag any scripts loaded from unknown third-party origins
    on_text('\n[INFO] Third-Party Script Origin Analysis\n')
    on_text('-' * 40 + '\n')
    known_cdns = [
        'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'ajax.googleapis.com',
        'code.jquery.com', 'stackpath.bootstrapcdn.com', 'unpkg.com',
        'maxcdn.bootstrapcdn.com', 'cdn.bootcss.com',
    ]
    third_party: list[str] = []
    for src in script_srcs:
        src_lower = src.lower()
        if src_lower.startswith('http') and domain.lower() not in src_lower:
            third_party.append(src)

    if third_party:
        on_text(f'[MEDIUM] {len(third_party)} script(s) loaded from third-party origins:\n')
        for src in third_party:
            origin = urllib.parse.urlparse(src).netloc
            cdn_flag = ' (known CDN)' if any(c in origin.lower() for c in known_cdns) else ' [MEDIUM] unknown third-party origin'
            on_text(f'  {origin}{cdn_flag}\n')
    else:
        on_text('[INFO] All scripts appear to be same-origin or relative paths\n')

    on_text('\n[INFO] Supply chain / JS audit complete\n')


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

PASSIVE_RUNNERS: dict[str, Callable] = {
    'recon-passive': run_recon_passive,
    'breach':        run_breach,
    'subdomain':     run_subdomain,
    'tech-detect':   run_tech_detect,
    'supply-chain':  run_supply_chain,
}
