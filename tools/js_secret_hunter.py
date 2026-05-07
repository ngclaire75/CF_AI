"""CF_AI tool: JavaScript file discovery and secret hunting."""
from __future__ import annotations
import re
import subprocess
import json
from sdk.agents import function_tool

_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'

# ── Secret patterns ────────────────────────────────────────────────────────────
PATTERNS: dict[str, str] = {
    'AWS_ACCESS_KEY':    r'AKIA[0-9A-Z]{16}',
    'AWS_SECRET':        r'(?i)aws.{0,20}(?:secret|key).{0,20}["\']([A-Za-z0-9/+]{40})["\']',
    'GOOGLE_API_KEY':    r'AIza[0-9A-Za-z\-_]{35}',
    'GITHUB_TOKEN':      r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
    'STRIPE_KEY':        r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}',
    'SLACK_TOKEN':       r'xox[baprs]-[0-9A-Za-z\-]{10,}',
    'SENDGRID_KEY':      r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
    'TWILIO_KEY':        r'SK[a-f0-9]{32}',
    'JWT_TOKEN':         r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    'PRIVATE_KEY':       r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    'DB_CONN_STRING':    r'(?i)(?:mongodb|mysql|postgresql|redis|jdbc|mssql)://[^\s"\'<>{}\[\]]{8,}',
    'API_KEY_GENERIC':   r'(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?key|secret[_\-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
    'OAUTH_SECRET':      r'(?i)(?:client[_\-]?secret|oauth[_\-]?secret|consumer[_\-]?secret)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
    'PASSWORD_IN_CODE':  r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
    'INTERNAL_ENDPOINT': r'(?:https?://(?:localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^\s"\'<>]*|/(?:api/internal|admin|dashboard|config|debug|swagger|actuator)/[^\s"\'<>]*)',
    'FIREBASE_URL':      r'https://[a-zA-Z0-9\-]+\.firebaseio\.com',
    'EMAIL_ADDRESS':     r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    'PRIVATE_IP':        r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b',
    'BASIC_AUTH_URL':    r'https?://[^:@\s]+:[^@\s]+@[^\s"\'<>]+',
}

# Noise patterns to suppress (common false positives)
_NOISE = re.compile(r'(?:example\.com|localhost|yourdomain|placeholder|dummy|test@|foo@|bar@|user@)', re.I)


def _fetch(url: str, timeout: int = 15, wayback: bool = False) -> str:
    if wayback:
        url = f'https://web.archive.org/web/2/{url}'
        ua = 'curl/7.88'
    else:
        ua = _UA
    try:
        r = subprocess.run(
            ['curl', '-L', '-4', '-sk', '--max-time', str(timeout),
             '--connect-timeout', '8', '-A', ua,
             '-H', 'Accept: */*',
             '-H', 'Referer: https://www.google.com/',
             '-c', '/tmp/cf_cookies.txt', '-b', '/tmp/cf_cookies.txt', url],
            capture_output=True, text=True, timeout=timeout + 5
        )
        return r.stdout
    except Exception:
        return ''


def _cf_scraper_fetch(url: str) -> str:
    """Cloudscraper fallback for CF-protected sites."""
    script = (
        "import cloudscraper,sys; "
        f"s=cloudscraper.create_scraper(); "
        f"r=s.get('{url}',timeout=15,verify=False); "
        "print(r.text[:80000])"
    )
    try:
        r = subprocess.run(['python3', '-c', script], capture_output=True, text=True, timeout=20)
        return r.stdout if r.returncode == 0 else ''
    except Exception:
        return ''


def _extract_js_urls(html: str, base_url: str) -> list[str]:
    m = re.match(r'(https?://[^/]+)', base_url)
    origin = m.group(1) if m else base_url.rstrip('/')
    scheme = 'https' if base_url.startswith('https') else 'http'
    refs = re.findall(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html)
    refs += re.findall(r'"([^"]*\.js(?:\?[^"]*)?)"', html)
    urls: set[str] = set()
    for ref in refs:
        if ref.startswith('http'):
            urls.add(ref.split('?')[0])
        elif ref.startswith('//'):
            urls.add(scheme + ':' + ref.split('?')[0])
        elif ref.startswith('/'):
            urls.add(origin + ref.split('?')[0])
        elif ref and not ref.startswith('#') and not ref.startswith('data:'):
            urls.add(origin + '/' + ref.split('?')[0])
    return [u for u in list(urls)[:25] if not re.search(r'\.min\.js$', u) or len(urls) <= 5]


def _hunt_secrets(content: str, file_url: str) -> list[dict]:
    findings: list[dict] = []
    for name, pattern in PATTERNS.items():
        matches = re.findall(pattern, content)
        for m in matches[:5]:
            val = m if isinstance(m, str) else (m[0] if m else '')
            val = val.strip()
            if not val or _NOISE.search(val):
                continue
            findings.append({'type': name, 'value': val[:200], 'file': file_url})
    return findings


@function_tool
def hunt_js_secrets(
    domain: str,
    virustotal_api_key: str = '',
    use_wayback: bool = False,
) -> str:
    """Discover JavaScript files from a target domain and hunt for secrets.

    Automatically:
    - Extracts JS URLs from the live page HTML
    - Falls back to Wayback Machine when the live site is blocked or returns no JS
    - Optionally queries VirusTotal for additional JS URLs (requires API key)
    - Scans each JS file for: API keys (AWS/Google/GitHub/Stripe/Slack/Twilio),
      DB connection strings, JWT tokens, OAuth secrets, internal endpoints,
      passwords in source code, email addresses, private IPs

    Args:
        domain: Target domain, e.g. example.com
        virustotal_api_key: VirusTotal API key for extended JS URL discovery
        use_wayback: Force Wayback Machine mode (use when site is IP-filtered)

    Returns:
        Discovery log + all secrets found with file locations
    """
    out: list[str] = []
    base = f'https://{domain}/'

    # ── 1. Fetch live page ─────────────────────────────────────────────────────
    html = _fetch(base, timeout=15)
    if not html:
        out.append('[BYPASS] Live fetch failed — trying cloudscraper...')
        html = _cf_scraper_fetch(base)
    js_urls = _extract_js_urls(html, base) if html else []
    out.append(f'[LIVE] {len(js_urls)} JS files found on live site')

    # ── 2. Auto-fallback to Wayback when no JS or forced ──────────────────────
    if not js_urls or use_wayback:
        out.append('[WAYBACK] Fetching archived copy from Wayback Machine...')
        wb_html = _fetch(base, timeout=20, wayback=True)
        wb_js = _extract_js_urls(wb_html, base) if wb_html else []
        added = [u for u in wb_js if u not in js_urls]
        js_urls += added
        out.append(f'[WAYBACK] Added {len(added)} JS files from archive (total: {len(js_urls)})')

    # ── 3. VirusTotal JS URL enrichment ───────────────────────────────────────
    if virustotal_api_key:
        try:
            vt_raw = subprocess.run(
                ['curl', '-4', '-sk', '--max-time', '15',
                 '-H', f'x-apikey: {virustotal_api_key}',
                 f'https://www.virustotal.com/api/v3/domains/{domain}/urls?limit=40'],
                capture_output=True, text=True, timeout=20
            ).stdout
            vt = json.loads(vt_raw)
            vt_added = 0
            for item in vt.get('data', []):
                url = item.get('attributes', {}).get('url', '')
                if ('.js' in url) and url not in js_urls:
                    js_urls.append(url)
                    vt_added += 1
            out.append(f'[VIRUSTOTAL] Added {vt_added} JS URLs from VirusTotal scan')
        except Exception as exc:
            out.append(f'[VIRUSTOTAL] Error: {exc}')

    if not js_urls:
        out.append('[RESULT] No JS files found — site may require JS rendering (SPA) or is fully blocked')
        return '\n'.join(out)

    out.append(f'\n[SCANNING] {len(js_urls)} JS files...')

    # ── 4. Fetch + scan each JS file ──────────────────────────────────────────
    all_findings: list[dict] = []
    for url in js_urls[:20]:
        content = _fetch(url, timeout=12)
        if not content:
            content = _fetch(url, timeout=12, wayback=True)
        if content:
            hits = _hunt_secrets(content, url)
            all_findings.extend(hits)
            status = f'{len(hits)} HITS' if hits else 'clean'
            out.append(f'  [{status}] {url} ({len(content):,} bytes)')
        else:
            out.append(f'  [SKIP] {url} — not reachable')

    # ── 5. Results ────────────────────────────────────────────────────────────
    if all_findings:
        out.append(f'\n{"="*60}')
        out.append(f'SECRETS FOUND: {len(all_findings)} total')
        out.append('='*60)
        by_type: dict[str, list] = {}
        for f in all_findings:
            by_type.setdefault(f['type'], []).append(f)
        for t, items in by_type.items():
            out.append(f'\n[{t}] ({len(items)} occurrences)')
            for item in items[:3]:
                out.append(f'  Value : {item["value"][:120]}')
                out.append(f'  Source: {item["file"]}')
    else:
        out.append('\n[RESULT] No secrets found in scanned JS files')

    return '\n'.join(out)
