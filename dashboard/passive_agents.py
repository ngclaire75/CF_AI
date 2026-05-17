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
import urllib.request
import urllib.parse
import concurrent.futures
from typing import Callable

_TIMEOUT = 12  # seconds per HTTP call

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
# Supply-chain vuln DB
# ---------------------------------------------------------------------------

# (library_name, url_pattern_regex, version_capture_group, vuln_versions_below,
#  cve, severity, description)
_VULN_LIBS = [
    ('jQuery',       r'jquery[.-]([\d.]+)(?:\.min)?\.js',           '1', '3.5.0', 'CVE-2020-11022', 'MEDIUM',   'XSS via HTML parsing in jQuery < 3.5.0'),
    ('jQuery',       r'jquery[.-]([\d.]+)(?:\.min)?\.js',           '1', '1.9.0', 'CVE-2012-6708',  'MEDIUM',   'XSS in jQuery selector engine < 1.9.0'),
    ('Bootstrap',    r'bootstrap[.-]([\d.]+)(?:\.min)?\.js',        '1', '3.4.1', 'CVE-2018-14040', 'MEDIUM',   'XSS in data-* attributes in Bootstrap < 3.4.1'),
    ('Bootstrap',    r'bootstrap[.-]([\d.]+)(?:\.min)?\.js',        '1', '4.3.1', 'CVE-2019-8331',  'MEDIUM',   'XSS tooltip/popover in Bootstrap < 4.3.1'),
    ('Angular',      r'angular(?:js)?[.-]([\d.]+)(?:\.min)?\.js',   '1', '1.8.3', 'CVE-2023-26117', 'HIGH',     'ReDoS in Angular < 1.8.3'),
    ('Angular',      r'angular(?:js)?[.-]([\d.]+)(?:\.min)?\.js',   '1', '1.6.0', 'CVE-2016-6272',  'HIGH',     'XSS in AngularJS < 1.6.0'),
    ('Lodash',       r'lodash[.-]([\d.]+)(?:\.min)?\.js',           '1', '4.17.21', 'CVE-2021-23337', 'HIGH',   'Command injection in lodash < 4.17.21'),
    ('Lodash',       r'lodash[.-]([\d.]+)(?:\.min)?\.js',           '1', '4.17.12', 'CVE-2019-10744', 'CRITICAL', 'Prototype pollution in lodash < 4.17.12'),
    ('Moment.js',    r'moment[.-]([\d.]+)(?:\.min)?\.js',           '1', '2.29.4', 'CVE-2022-31129', 'HIGH',    'ReDoS in Moment.js < 2.29.4'),
    ('Underscore',   r'underscore[.-]([\d.]+)(?:\.min)?\.js',       '1', '1.13.0', 'CVE-2021-23358', 'HIGH',    'Arbitrary code exec in Underscore < 1.13.0'),
    ('Handlebars',   r'handlebars[.-]([\d.]+)(?:\.min)?\.js',       '1', '4.7.7',  'CVE-2021-23369', 'CRITICAL', 'RCE via template in Handlebars < 4.7.7'),
    ('Vue.js',       r'vue[.-]([\d.]+)(?:\.min)?\.js',              '1', '2.7.0',  'CVE-2023-49210', 'MEDIUM',  'XSS in Vue.js < 2.7.0'),
    ('Axios',        r'axios[.-]([\d.]+)(?:\.min)?\.js',            '1', '0.21.1', 'CVE-2020-28168', 'MEDIUM',  'SSRF in Axios < 0.21.1'),
    ('DOMPurify',    r'dompurify[.-]([\d.]+)(?:\.min)?\.js',        '1', '2.4.0',  'CVE-2022-25148', 'HIGH',    'XSS bypass in DOMPurify < 2.4.0'),
    ('Prototype.js', r'prototype[.-]([\d.]+)(?:\.min)?\.js',        '1', '1.7.3',  'CVE-2008-7220',  'HIGH',    'XSS in Prototype.js < 1.7.3'),
    ('MooTools',     r'mootools[.-]([\d.]+)(?:\.min)?\.js',         '1', '1.6.0',  'CVE-2021-20251', 'MEDIUM',  'Prototype pollution in MooTools'),
    ('three.js',     r'three[.-]([\d.]+)(?:\.min)?\.js',            '1', '0.125.0', 'CVE-2020-28461', 'MEDIUM', 'ReDoS in three.js < 0.125.0'),
    ('clipboard.js', r'clipboard[.-]([\d.]+)(?:\.min)?\.js',        '1', '2.0.7',  'CVE-2020-6710',  'MEDIUM',  'XSS in clipboard.js < 2.0.7'),
    ('highlight.js', r'highlight[.-]([\d.]+)(?:\.min)?\.js',        '1', '10.4.1', 'CVE-2020-26237', 'HIGH',    'ReDoS in highlight.js < 10.4.1'),
    ('marked',       r'marked[.-]([\d.]+)(?:\.min)?\.js',           '1', '2.0.0',  'CVE-2021-21306', 'HIGH',    'XSS in marked < 2.0.0'),
    ('remarkable',   r'remarkable[.-]([\d.]+)(?:\.min)?\.js',       '1', '2.0.0',  'CVE-2021-23386', 'MEDIUM',  'ReDoS in remarkable < 2.0.0'),
    ('showdown',     r'showdown[.-]([\d.]+)(?:\.min)?\.js',         '1', '1.9.1',  'CVE-2018-17052', 'MEDIUM',  'XSS in showdown < 1.9.1'),
    ('dojo',         r'dojo[./]([\d.]+)(?:/dojo)?(?:\.min)?\.js',   '1', '1.17.0', 'CVE-2018-15494', 'CRITICAL', 'XSS in dojo < 1.17.0'),
    ('ExtJS',        r'ext-all[.-]([\d.]+)(?:\.min)?\.js',          '1', '6.6.0',  'CVE-2020-8911',  'HIGH',    'Prototype pollution in ExtJS'),
    ('CKEditor',     r'ckeditor[.-]([\d.]+)(?:\.min)?\.js',         '1', '4.18.0', 'CVE-2022-24728', 'MEDIUM',  'XSS in CKEditor < 4.18.0'),
    ('TinyMCE',      r'tinymce[.-]([\d.]+)(?:\.min)?\.js',          '1', '5.10.0', 'CVE-2021-44701', 'MEDIUM',  'XSS in TinyMCE < 5.10.0'),
    ('CodeMirror',   r'codemirror[.-]([\d.]+)(?:\.min)?\.js',       '1', '5.65.0', 'CVE-2022-24713', 'MEDIUM',  'ReDoS in CodeMirror < 5.65.0'),
    ('Swagger UI',   r'swagger-ui[.-]([\d.]+)(?:\.min)?\.js',       '1', '4.1.3',  'CVE-2021-46708', 'MEDIUM',  'XSS in Swagger UI < 4.1.3'),
    ('Font Awesome', r'font-awesome[./]([\d.]+)',                    '1', '5.0.0',  '',               'INFO',    'Font Awesome < 5.0.0 (legacy, update recommended)'),
]

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
    """Supply chain audit: fetch page, extract script src URLs, match against known-vuln DB."""
    on_text(f'\n[SUPPLY CHAIN] Starting supply chain / JS library audit for: {domain}\n')
    on_text('=' * 60 + '\n')

    # Fetch the page
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
    on_text(f'\n[INFO] Found {len(script_srcs)} external script(s) on {domain}\n')
    on_text('-' * 40 + '\n')

    if not script_srcs:
        on_text('[INFO] No external script sources found — either inline scripts or no JS\n')
        on_text('[INFO] Supply chain audit complete\n')
        return

    for src in script_srcs:
        on_text(f'  Script: {src}\n')

    # Match against vuln library DB
    on_text('\n[INFO] Matching against known-vulnerable library database\n')
    on_text('-' * 40 + '\n')

    findings: list[tuple[str, str, str, str, str, str, str]] = []  # (src, lib, version, vuln_below, cve, sev, desc)
    clean_srcs: list[str] = []

    for src in script_srcs:
        # Normalize: strip query strings for matching
        src_clean = src.split('?')[0].split('#')[0]
        # Use the last path component for matching
        filename = src_clean.rsplit('/', 1)[-1]
        # Also try full path for patterns like dojo/1.16.0/dojo.js
        match_str = src_clean.lower()

        for lib_name, pattern, _grp, vuln_below, cve, severity, desc in _VULN_LIBS:
            try:
                m = re.search(pattern, match_str, re.IGNORECASE)
                if m:
                    detected_ver = m.group(int(_grp))
                    if vuln_below and _version_below(detected_ver, vuln_below):
                        findings.append((src, lib_name, detected_ver, vuln_below, cve, severity, desc))
            except Exception:
                pass

        clean_srcs.append(src_clean)

    # Report findings grouped by severity
    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    findings.sort(key=lambda f: sev_order.get(f[5], 5))

    if findings:
        on_text(f'[HIGH] Found {len(findings)} vulnerable JS librar(y/ies):\n\n')
        for src, lib, ver, vuln_below, cve, severity, desc in findings:
            cve_str = f' ({cve})' if cve else ''
            on_text(f'[{severity}] {lib} v{ver} — {desc}{cve_str}\n')
            on_text(f'  Source: {src}\n')
            on_text(f'  Vulnerable below: {vuln_below}  |  Severity: {severity}\n\n')
    else:
        on_text('[INFO] No known-vulnerable library versions detected\n')
        on_text('       (Libraries may still be present but versions were not parseable)\n')

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
