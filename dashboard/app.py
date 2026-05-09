"""CF_AI Security Dashboard — Flask web application."""
from __future__ import annotations
import ipaddress
import json as _json
import os
import re
import sys
import time as _time
import shutil as _shutil
import ssl as _ssl
import subprocess as _subprocess
import threading as _threading
import urllib.error as _up_err
import urllib.parse as _up_parse
import urllib.request as _up_req
import uuid as _uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, jsonify, abort, request
import dashboard.db as db
from dashboard.remediations import REMEDIATIONS

db.init_db()

_BROWSER_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
               'AppleWebKit/537.36 (KHTML, like Gecko) '
               'Chrome/124.0.0.0 Safari/537.36')

try:
    import requests as _requests
    import urllib3 as _urllib3
    _urllib3.disable_warnings(_urllib3.exceptions.InsecureRequestWarning)
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    import cloudscraper as _cloudscraper
    _HAS_CLOUDSCRAPER = True
except ImportError:
    _HAS_CLOUDSCRAPER = False

_SCRAPER_API_KEY = os.environ.get('SCRAPER_API_KEY', '').strip()

# ── GeoIP lookup cache (uses ip-api.com, free, no key, 45 req/min) ─────────
_geoip_cache: dict = {}

def _geoip_detail(ip: str) -> dict:
    """Return {country, country_code, lat, lon} for an IP. Cached."""
    _blank = {'country': '', 'country_code': '', 'lat': 0.0, 'lon': 0.0}
    if not ip or ip in ('127.0.0.1', '::1', 'localhost', '0.0.0.0', ''):
        return _blank
    if ip in _geoip_cache:
        return _geoip_cache[ip]
    try:
        import urllib.request as _ur2
        with _ur2.urlopen(
            f'http://ip-api.com/json/{ip}?fields=country,countryCode,lat,lon',
            timeout=3
        ) as _r2:
            _d2 = _json.loads(_r2.read())
            result = {
                'country':      _d2.get('country', ''),
                'country_code': _d2.get('countryCode', ''),
                'lat':          float(_d2.get('lat', 0)),
                'lon':          float(_d2.get('lon', 0)),
            }
    except Exception:
        result = _blank.copy()
    _geoip_cache[ip] = result
    return result


# ── Auto-remediation rules ────────────────────────────────────────────────────
_REMED_RULES = [
    {'name': 'brute_force_block',     'event_types': ['login_failed'],
     'threshold': 10, 'window_min': 5,   'action': 'block_ip',
     'severity': 'HIGH',     'description': 'Block IPs with >10 failed logins in 5 min'},
    {'name': 'sql_injection_block',   'event_types': ['sql_injection'],
     'threshold': 1,  'window_min': 60,  'action': 'block_ip',
     'severity': 'CRITICAL', 'description': 'Immediately block SQL injection sources'},
    {'name': 'xss_block',             'event_types': ['xss_attempt'],
     'threshold': 3,  'window_min': 10,  'action': 'block_ip',
     'severity': 'HIGH',     'description': 'Block IPs with ≥3 XSS attempts in 10 min'},
    {'name': 'scanner_block',         'event_types': ['port_scan', 'vuln_scan'],
     'threshold': 5,  'window_min': 2,   'action': 'block_ip',
     'severity': 'MEDIUM',   'description': 'Block aggressive scanners (≥5 probes in 2 min)'},
    {'name': 'credential_stuffing',   'event_types': ['login_failed'],
     'threshold': 50, 'window_min': 60,  'action': 'block_ip',
     'severity': 'CRITICAL', 'description': 'Block credential-stuffing sources (≥50 failures/hour)'},
    {'name': 'critical_vuln_incident','event_types': ['vulnerability_detected'],
     'threshold': 1,  'window_min': 1440,'action': 'create_incident',
     'severity': 'CRITICAL', 'description': 'Open incident for every critical vulnerability'},
]


def _run_remediation(event_id: int, event: dict) -> None:
    """Check rules against the new event; trigger actions when thresholds are met."""
    ip        = event.get('ip_address', '')
    ev_type   = event.get('event_type', '')
    target    = event.get('target', '')

    for rule in _REMED_RULES:
        if ev_type not in rule['event_types']:
            continue
        count = db.count_events_by_ip(ip, rule['event_types'], rule['window_min'])
        if count < rule['threshold']:
            continue

        action_id = db.log_remediation(
            trigger_event_id=event_id, rule_name=rule['name'],
            action_type=rule['action'], target=ip or target,
            parameters=_json.dumps({'rule': rule['name'], 'count': count, 'ip': ip}),
            status='running', auto_triggered=True,
        )

        try:
            if rule['action'] == 'block_ip' and ip and not db.is_ip_blocked(ip):
                _auto_block_ip(ip, rule['name'], event.get('country', ''), action_id)
            elif rule['action'] == 'create_incident':
                db.create_incident(
                    title=f"[Auto] {event.get('description','Security event')}",
                    description=f"Rule: {rule['description']}\nEvent ID: {event_id}\nTarget: {target}",
                    severity=rule['severity'],
                    target=target,
                )
                db.update_remediation(action_id, 'success', 'Incident created')
        except Exception as _e:
            db.update_remediation(action_id, 'failed', str(_e)[:200])


def _auto_block_ip(ip: str, rule_name: str, country: str, action_id: int) -> None:
    """Block an IP via Cloudflare Firewall Rules (requires Zone WAF:Edit permission)."""
    def _strip_env_prefix(v):
        return v.split('=', 1)[-1].strip() if '=' in v else v.strip()

    cf_token = _strip_env_prefix(os.environ.get('CF_API_TOKEN', '').strip())
    if not cf_token:
        db.add_blocked_ip(ip, country, rule_name)
        db.update_remediation(action_id, 'success', f'Blocked locally (no CF token)')
        return

    # Find a zone to apply the rule to (use first available zone)
    try:
        zr = _json.loads(_cf_request('/zones?per_page=1', cf_token, timeout=10)[1])
        zones = (zr.get('result') or [])
        zone_id = zones[0]['id'] if zones else ''
    except Exception:
        zone_id = ''

    cf_rule_id = ''
    if zone_id and _HAS_REQUESTS:
        url  = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules'
        hdrs = {'Authorization': f'Bearer {cf_token}', 'Content-Type': 'application/json'}
        try:
            r = _requests.post(url, headers=hdrs, json=[{
                'filter': {'expression': f'(ip.src eq {ip})'},
                'action': 'block',
                'description': f'CF_AI auto-block: {rule_name}',
            }], timeout=15, verify=True)
            data = r.json()
            if r.status_code == 200 and data.get('success'):
                cf_rule_id = (data.get('result') or [{}])[0].get('id', '')
        except Exception:
            pass

    db.add_blocked_ip(ip, country, rule_name, cf_rule_id, zone_id)
    db.update_remediation(action_id, 'success',
        f'IP {ip} blocked' + (f' via CF rule {cf_rule_id}' if cf_rule_id else ' locally'))


def _wp_request(url: str, method: str = 'GET', headers: dict | None = None,
                body: bytes | None = None, timeout: int = 20) -> tuple[int, str]:
    """HTTP request with progressive bypass for Cloudflare/WAF-protected sites.

    Layer 0: ScraperAPI — routes through residential IPs, bypasses VPS/datacenter blocks
    Layer 1: requests library — verify=False, full browser headers
    Layer 2: cloudscraper — solves Cloudflare JS challenges
    Layer 3: curl -sk — handles edge cases (cert issues, header quirks)

    Returns (status_code, body_text).  status_code=0 means total failure.
    The error string is always non-empty on failure so callers can surface it.
    """
    hdrs = {
        'User-Agent':      _BROWSER_UA,
        'Accept':          'application/json, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control':   'no-cache',
    }
    if headers:
        hdrs.update(headers)

    last_err = 'unknown error'

    # Layer 0 — ScraperAPI (residential IPs — bypasses VPS/datacenter Cloudflare blocks)
    # Skip for cookie-auth requests: nonce is bound to the session established by _wp_cookie_auth
    if _SCRAPER_API_KEY and _HAS_REQUESTS and 'Cookie' not in hdrs:
        try:
            scraper_url = (
                f'http://api.scraperapi.com/?api_key={_SCRAPER_API_KEY}'
                f'&url={_up_parse.quote(url, safe="")}&render=false'
            )
            resp = _requests.request(
                method, scraper_url,
                headers=hdrs,
                data=body,
                verify=False,
                timeout=timeout + 10,
            )
            return resp.status_code, resp.text
        except Exception as e:
            last_err = str(e)

    # Layer 1 — requests with SSL verification disabled
    if _HAS_REQUESTS:
        try:
            resp = _requests.request(
                method, url,
                headers=hdrs,
                data=body,
                verify=False,
                timeout=timeout,
                allow_redirects=True,
            )
            return resp.status_code, resp.text
        except Exception as e:
            last_err = str(e)

    # Layer 2 — cloudscraper (solves Cloudflare JS challenge v1/v2)
    if _HAS_CLOUDSCRAPER:
        try:
            cs = _cloudscraper.create_scraper(
                browser={'browser': 'chrome', 'platform': 'linux', 'mobile': False}
            )
            resp = cs.request(method, url, headers=hdrs, data=body,
                              verify=False, timeout=timeout)
            return resp.status_code, resp.text
        except Exception as e:
            last_err = str(e)

    # Layer 3 — curl -sk (handles remaining edge cases)
    if _shutil.which('curl'):
        # Write body to temp file to avoid stdin issues on Linux/Windows
        tmp_path = None
        try:
            if body:
                import tempfile
                with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tf:
                    tf.write(body)
                    tmp_path = tf.name
            cmd = [
                'curl', '-sk', '-L',
                '-w', '\n__CF_STATUS__:%{http_code}',
                '--max-time', str(timeout),
                '--connect-timeout', '10',
                '-X', method,
            ]
            for k, v in hdrs.items():
                cmd += ['-H', f'{k}: {v}']
            if tmp_path:
                cmd += ['--data-binary', f'@{tmp_path}']
            cmd.append(url)
            res = _subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
            text = res.stdout.decode('utf-8', errors='replace')
            if '__CF_STATUS__:' in text:
                body_part, stat = text.rsplit('\n__CF_STATUS__:', 1)
                code = int(stat.strip() or '0')
                if code > 0:
                    return code, body_part
                last_err = f'curl exited with HTTP 0 — site may be blocking VPS/datacenter IPs'
            else:
                stderr = res.stderr.decode('utf-8', errors='replace')[:200]
                last_err = f'curl no response — {stderr or "connection refused or timed out"}'
        except Exception as e:
            last_err = str(e)
        finally:
            if tmp_path:
                try:
                    import os; os.unlink(tmp_path)
                except Exception:
                    pass
    else:
        last_err = 'curl not found; requests unavailable'

    return 0, last_err


def _wp_cookie_auth(site_url: str, username: str, password: str) -> tuple[str | None, str | None]:
    """Login via wp-login.php and return (nonce, cookie_header) for REST API cookie auth.

    Works with regular WordPress admin passwords (not just Application Passwords).
    Uses ScraperAPI URL mode (residential IPs) — proxy mode fails Cloudflare JS challenge.
    Returns (nonce, cookie_header) on success, (None, None) on failure.
    """
    if not _HAS_REQUESTS:
        return None, None
    import re as _rmod

    def _sa_req(target, method='GET', data=None, extra_hdrs=None):
        sa = (f'http://api.scraperapi.com/?api_key={_SCRAPER_API_KEY}'
              f'&url={_up_parse.quote(target, safe="")}')
        h = {'User-Agent': _BROWSER_UA}
        if extra_hdrs:
            h.update(extra_hdrs)
        if method == 'POST':
            h.setdefault('Content-Type', 'application/x-www-form-urlencoded')
            return _requests.post(sa, data=data, headers=h, verify=False, timeout=30)
        return _requests.get(sa, headers=h, verify=False, timeout=20)

    def _try_scraper():
        if not _SCRAPER_API_KEY:
            return None, None
        try:
            login_r = _sa_req(
                f'{site_url}/wp-login.php', method='POST',
                data={'log': username, 'pwd': password,
                      'wp-submit': 'Log In', 'redirect_to': '/wp-admin/',
                      'testcookie': '1'},
                extra_hdrs={'Cookie': 'wordpress_test_cookie=WP Cookie check'},
            )
            # Collect cookies — ScraperAPI may return them in response.cookies or Set-Cookie headers
            cookies = {k: v for k, v in login_r.cookies.items()}
            for raw in login_r.headers.getlist('set-cookie') if hasattr(login_r.headers, 'getlist') \
                    else [login_r.headers.get('set-cookie', '')]:
                nv = raw.split(';')[0].strip()
                if '=' in nv:
                    n, v2 = nv.split('=', 1)
                    cookies[n.strip()] = v2.strip()
            if not any('wordpress_logged_in' in k for k in cookies):
                return None, None
            cookie_hdr = '; '.join(f'{k}={v}' for k, v in cookies.items())
            admin_r = _sa_req(f'{site_url}/wp-admin/', extra_hdrs={'Cookie': cookie_hdr})
            nonce = ''
            m = _rmod.search(r'"nonce"\s*:\s*"([a-f0-9]{10})"', admin_r.text)
            if m:
                nonce = m.group(1)
            return nonce, cookie_hdr
        except Exception:
            return None, None

    def _try_direct():
        try:
            sess = _requests.Session()
            sess.verify = False
            sess.headers.update({'User-Agent': _BROWSER_UA})
            sess.post(
                f'{site_url}/wp-login.php',
                data={'log': username, 'pwd': password,
                      'wp-submit': 'Log In', 'redirect_to': '/wp-admin/',
                      'testcookie': '1'},
                cookies={'wordpress_test_cookie': 'WP Cookie check'},
                allow_redirects=True, timeout=25,
            )
            if not any('wordpress_logged_in' in k for k in sess.cookies.keys()):
                return None, None
            admin_r = sess.get(f'{site_url}/wp-admin/', allow_redirects=True, timeout=15)
            nonce = ''
            m = _rmod.search(r'"nonce"\s*:\s*"([a-f0-9]{10})"', admin_r.text)
            if m:
                nonce = m.group(1)
            cookie_hdr = '; '.join(f'{k}={v}' for k, v in sess.cookies.items())
            return nonce, cookie_hdr
        except Exception:
            return None, None

    nonce, ck = _try_scraper()
    if nonce is not None:
        return nonce, ck
    nonce, ck = _try_direct()
    if nonce is not None:
        return nonce, ck

    # ScraperAPI can't preserve session cookies (it's a scraper, not a session proxy).
    # Fall back to XML-RPC to at least verify whether the credentials are correct.
    if _wp_xmlrpc_verify(site_url, username, password):
        return '__xmlrpc_verified__', ''  # credentials OK but no cookie session possible
    return None, None


def _wp_xmlrpc_verify(site_url: str, username: str, password: str) -> bool:
    """Verify WordPress credentials via XML-RPC (accepts regular admin passwords)."""
    if not _HAS_REQUESTS:
        return False
    import xml.sax.saxutils as _sax
    payload = (
        '<?xml version="1.0"?><methodCall>'
        '<methodName>wp.getProfile</methodName><params>'
        '<param><value><int>1</int></value></param>'
        f'<param><value><string>{_sax.escape(username)}</string></value></param>'
        f'<param><value><string>{_sax.escape(password)}</string></value></param>'
        '</params></methodCall>'
    ).encode()
    xmlrpc_url = f'{site_url}/xmlrpc.php'
    hdrs = {'Content-Type': 'text/xml', 'User-Agent': _BROWSER_UA}
    try:
        if _SCRAPER_API_KEY and _HAS_REQUESTS:
            sa = (f'http://api.scraperapi.com/?api_key={_SCRAPER_API_KEY}'
                  f'&url={_up_parse.quote(xmlrpc_url, safe="")}')
            r = _requests.post(sa, data=payload, headers=hdrs, verify=False, timeout=25)
        else:
            r = _requests.post(xmlrpc_url, data=payload, headers=hdrs, verify=False, timeout=20)
        return (r.status_code == 200
                and '<fault>' not in r.text
                and '<methodResponse>' in r.text
                and 'user_login' in r.text)
    except Exception:
        return False


app = Flask(__name__, template_folder='templates')

# ── In-memory scan job store (Connect Your Website feature) ──────────────────
_scan_jobs: dict = {}

_JOB_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'jobs')

def _job_persist(job_id: str, job: dict) -> None:
    """Write terminal job state to disk so polls survive server restarts."""
    try:
        os.makedirs(_JOB_DIR, exist_ok=True)
        path = os.path.join(_JOB_DIR, f'{job_id}.json')
        with open(path, 'w') as fh:
            _json.dump({
                'status':  job.get('status', 'done'),
                'scan_id': job.get('scan_id'),
                'error':   job.get('error'),
                'domain':  job.get('domain', ''),
                'target':  job.get('target', ''),
            }, fh)
    except Exception:
        pass

def _job_load(job_id: str) -> dict | None:
    """Try to load a completed job from disk (fallback after server restart)."""
    try:
        path = os.path.join(_JOB_DIR, f'{job_id}.json')
        if os.path.exists(path):
            with open(path) as fh:
                return _json.load(fh)
    except Exception:
        pass
    return None

# ── Plugin inventory parser ───────────────────────────────────────────────────

def _parse_and_save_plugins(scan_id: int, target: str, output: str) -> int:
    """Extract plugins/packages from scan output and upsert them into the DB."""
    found: dict = {}

    # WordPress wp plugin list table: | slug | active | 1.2.3 |
    for m in re.finditer(
            r'\|\s*([\w][\w-]{1,60})\s*\|\s*(active|inactive|must-use|drop-in)\s*\|\s*([\d.]+)\s*\|',
            output, re.I):
        slug, status, ver = m.group(1).strip(), m.group(2).strip().lower(), m.group(3).strip()
        key = slug.lower()
        found[key] = {'name': slug, 'version': ver, 'plugin_type': 'WordPress Plugin',
                      'status': status, 'vulnerable': 0}

    # WordPress REST API JSON blobs: "slug":"name","version":"x.y"
    for m in re.finditer(r'"slug"\s*:\s*"([^"]{2,60})"[^}]{0,200}?"version"\s*:\s*"([^"]+)"',
                         output, re.I | re.S):
        name, ver = m.group(1).strip(), m.group(2).strip()
        key = name.lower()
        if key not in found:
            found[key] = {'name': name, 'version': ver, 'plugin_type': 'WordPress Plugin',
                          'status': 'active', 'vulnerable': 0}

    # wp-content/plugins/slug paths
    for m in re.finditer(r'wp-content/plugins/([\w-]{3,60})', output, re.I):
        slug = m.group(1).strip()
        key = slug.lower()
        if key not in found:
            found[key] = {'name': slug, 'version': '', 'plugin_type': 'WordPress Plugin',
                          'status': 'active', 'vulnerable': 0}

    # WP-LOG plugin activation/deactivation entries
    for m in re.finditer(
            r'WP-LOG[^\n]*(?:activated|deactivated|installed)\s+(?:plugin\s+)?[:\s]+"?([^"|\n]{3,60}?)"?\s*\|',
            output, re.I):
        name = m.group(1).strip().rstrip('.')
        key = name.lower()
        if key not in found:
            found[key] = {'name': name, 'version': '', 'plugin_type': 'WordPress Plugin',
                          'status': 'active', 'vulnerable': 0}

    # wp_security_scan output: [ACTIVE] Plugin Name v1.0.0 — slug/slug.php
    for m in re.finditer(
            r'\[(ACTIVE|INACTIVE|MUST-USE|DROP-IN)\]\s+(.+?)\s+v([\d][0-9.]*)',
            output, re.I):
        status = m.group(1).lower()
        name   = m.group(2).strip().rstrip(' —-')
        ver    = m.group(3).strip()
        key    = name.lower()
        if key not in found and 2 < len(name) < 80:
            found[key] = {'name': name, 'version': ver, 'plugin_type': 'WordPress Plugin',
                          'status': status, 'vulnerable': 0}

    # Active theme line: "Active theme: ThemeName v1.0"
    for m in re.finditer(r'active theme:\s+(.+?)\s+v([\d][0-9.]*)', output, re.I):
        name = m.group(1).strip()
        ver  = m.group(2).strip()
        key  = name.lower()
        if key not in found and len(name) < 80:
            found[key] = {'name': name, 'version': ver, 'plugin_type': 'WordPress Theme',
                          'status': 'active', 'vulnerable': 0}

    # Generic plugin lines: "Plugin: name v1.0" or "Detected plugin: name 1.0"
    for m in re.finditer(
            r'(?:detected\s+)?plugin[:\s]+([a-zA-Z][\w ._-]{2,50}?)\s+v?([\d]+\.[\d.]+)',
            output, re.I):
        name, ver = m.group(1).strip(), m.group(2).strip()
        key = name.lower()
        if key not in found and len(name) < 60:
            found[key] = {'name': name, 'version': ver, 'plugin_type': 'Plugin',
                          'status': 'active', 'vulnerable': 0}

    # npm packages: "package-name@version" patterns in output
    for m in re.finditer(r'(?:^|\s)([@\w][\w/-]{1,50})@([\d]+\.[\d.]+)', output, re.M):
        name, ver = m.group(1).strip(), m.group(2).strip()
        if name.startswith('@') or '/' in name:
            continue  # skip scoped packages
        key = name.lower()
        if key not in found:
            found[key] = {'name': name, 'version': ver, 'plugin_type': 'npm Package',
                          'status': 'active', 'vulnerable': 0}

    # Mark known-vulnerable plugins
    vuln_ctx = re.findall(
        r'(?:CVE-\d{4}-\d{4,}|vulnerable|exploit|critical\s+vuln)[^\n]{0,120}',
        output, re.I)
    for ctx in vuln_ctx:
        for key in list(found.keys()):
            if key in ctx.lower():
                found[key]['vulnerable'] = 1

    # Persist to DB
    for data in found.values():
        try:
            db.upsert_plugin(
                target=target, name=data['name'], version=data['version'],
                plugin_type=data['plugin_type'], status=data['status'],
                vulnerable=data['vulnerable'], scan_id=scan_id,
            )
        except Exception:
            pass

    return len(found)

# ── IP geolocation (ip-api.com, free, no key required) ───────────────────────
_geo_cache: dict[str, str] = {}

def _geoip(ip_or_url: str) -> str:
    """Return 'Country (City)' for a real IP or hostname. Returns '' on failure."""
    raw = (ip_or_url or '').strip()
    if not raw or raw in ('-', '--', ''):
        return ''
    # Extract hostname from URL
    if raw.startswith('http'):
        raw = _up_parse.urlparse(raw).netloc or raw
    ip = raw.split(':')[0].strip()
    if not ip:
        return ''
    if ip in _geo_cache:
        return _geo_cache[ip]
    # Skip private/reserved IPs
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_reserved:
            _geo_cache[ip] = ''
            return ''
    except ValueError:
        pass  # hostname — proceed with lookup
    try:
        url = f'http://ip-api.com/json/{_up_parse.quote(ip)}?fields=status,country,city'
        req = _up_req.Request(url, headers={'User-Agent': 'CF_AI/1.0'})
        with _up_req.urlopen(req, timeout=5) as r:
            data = _json.loads(r.read().decode())
        if data.get('status') == 'success':
            country = data.get('country', '')
            city    = data.get('city', '')
            result  = f'{country} ({city})' if city else country
            _geo_cache[ip] = result
            return result
    except Exception:
        pass
    _geo_cache[ip] = ''
    return ''


def _build_cred_block(site_type: str, creds: dict, domain: str) -> str:
    """Return an agent instruction block for authenticated scanning."""
    if not site_type or site_type == 'none':
        return ''

    wp_user  = creds.get('wp_user', '')
    wp_pass  = creds.get('wp_pass', '')
    wp_app   = creds.get('wp_app_pass', '')
    cp_user  = creds.get('cpanel_user', '')
    ssh_host = creds.get('ssh_host', '') or domain
    ssh_user = creds.get('ssh_user', 'root')
    ssh_pass = creds.get('ssh_pass', '')
    ssh_port = creds.get('ssh_port', '22') or '22'
    ftp_host = creds.get('ftp_host', '') or domain
    ftp_user = creds.get('ftp_user', '')
    ftp_port = creds.get('ftp_port', '') or ('22' if site_type == 'sftp' else '21')

    hdr = (
        '\n\n══════════════ AUTHENTICATED SCAN ══════════════\n'
        'Credentials provided. You MUST use them for every check.\n'
        'NEVER print passwords in output — write [REDACTED] instead.\n'
        '════════════════════════════════════════════════\n\n'
    )

    if site_type == 'wordpress' and (wp_user or wp_pass):
        # Pre-compute conditional strings — avoids nested f-strings inside f-string expressions
        app_status  = '(provided — use for REST API)' if wp_app else '(not provided — cookie auth only)'
        rest_users  = (f'curl -s -u "{wp_user}:{wp_app}" '
                       f'"https://{domain}/wp-json/wp/v2/users?context=edit&per_page=100"'
                       if wp_app else
                       f'curl -s -b /tmp/wp_auth.txt "https://{domain}/wp-json/wp/v2/users?context=edit"')
        rest_plugins = (f'curl -s -u "{wp_user}:{wp_app}" "https://{domain}/wp-json/wp/v2/plugins"'
                        if wp_app else
                        '# app password required for /wp-json/wp/v2/plugins — skipping')
        return (hdr
            + 'WORDPRESS ADMIN CREDENTIALS\n'
            + f'  Username : {wp_user}\n'
            + f'  App Pass : {app_status}\n\n'
            + 'Run ALL of these checks in order:\n\n'
            + '1. Login and capture session cookie (required for most checks below):\n'
            + f'   curl -s -L -c /tmp/wp_auth.txt -b /tmp/wp_auth.txt \\\n'
            + f'     -d "log={wp_user}&pwd=$WP_PASSWORD&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" \\\n'
            + '     -H "Cookie: wordpress_test_cookie=WP+Cookie+check" \\\n'
            + f'     "https://{domain}/wp-login.php" -w "%{{http_code}}" -o /tmp/wp_login_resp.html\n'
            + '   grep -iP "error|invalid|incorrect" /tmp/wp_login_resp.html | head -5\n\n'
            + '2. Enumerate all WordPress users (admin view — reveals roles):\n'
            + f'   curl -s -b /tmp/wp_auth.txt "https://{domain}/wp-admin/users.php" \\\n'
            + "     | grep -oP '(?<=user-login\">)[^<]+'\n\n"
            + '3. Installed plugins and versions (identify outdated/vulnerable):\n'
            + f'   curl -s -b /tmp/wp_auth.txt "https://{domain}/wp-admin/plugins.php" \\\n'
            + "     | grep -oP '(?<=<strong>)[^<]+|(?<=Version )[0-9.]+'\n\n"
            + '4. WordPress core version and debug/security settings:\n'
            + f'   curl -s -b /tmp/wp_auth.txt "https://{domain}/wp-admin/about.php" | grep -oP "(?<=Version )[\\d.]+"\n'
            + f'   curl -s -b /tmp/wp_auth.txt "https://{domain}/wp-admin/options-general.php" \\\n'
            + '     | grep -iP "debug|ssl_force|login_lockout|two.factor|recaptcha"\n\n'
            + '5. REST API with real auth (lists all users including admin):\n'
            + f'   {rest_users}\n'
            + f'   {rest_plugins}\n\n'
            + '6. Admin AJAX — test for unauthenticated fallback:\n'
            + f'   curl -s -b /tmp/wp_auth.txt -d "action=heartbeat" "https://{domain}/wp-admin/admin-ajax.php"\n\n'
            + '7. File editor check (should be disabled — enables RCE):\n'
            + f'   curl -s -b /tmp/wp_auth.txt "https://{domain}/wp-admin/theme-editor.php" \\\n'
            + '     | grep -iP "disabled|not allowed|higher level"\n\n'
            + '8. XML-RPC authenticated call (test for DDoS amplification):\n'
            + "   curl -s -d '<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods"
            + f'</methodName></methodCall>\' "https://{domain}/xmlrpc.php"'
            + " | grep -oP '(?<=string>)[^<]+' | head -20\n\n"
            + '9. WP_DEBUG log and error exposure:\n'
            + f'   curl -s "https://{domain}/wp-content/debug.log" | head -30\n'
            + f'   curl -s "https://{domain}/?debug=1" | grep -iP "fatal|error|warning|deprecated"\n'
        )

    if site_type == 'cpanel' and cp_user:
        cp = f'curl -sk -u "{cp_user}:$CPANEL_PASSWORD"'
        api = f'https://{domain}:2083/execute'
        # python3 snippet using % to avoid brace conflicts with f-string
        py_filter = (
            "python3 -c \"import sys,json; d=json.load(sys.stdin); "
            "[print(f['file']) for f in d.get('data',{}).get('files',[]) "
            "if any(f['file'].endswith(e) for e in ['.env','.sql','.zip','.bak','.tar'])]\""
        )
        return (hdr
            + 'CPANEL CREDENTIALS\n'
            + f'  Username : {cp_user}\n'
            + f'  API base : https://{domain}:2083  (try :2082 for HTTP)\n\n'
            + 'Run ALL cPanel UAPI checks:\n\n'
            + f'1. PHP versions:\n   {cp} "{api}/LangPHP/php_get_vhost_versions"\n'
            + f'   {cp} "{api}/LangPHP/php_get_installed_versions"\n\n'
            + f'2. SSL certificate:\n   {cp} "{api}/SSL/fetch_best_for_domain?domain={domain}"\n\n'
            + f'3. All domains/subdomains:\n   {cp} "{api}/DomainInfo/domains_data?format=json"\n'
            + f'   {cp} "{api}/SubDomain/listsubdomains"\n\n'
            + f'4. Email accounts:\n   {cp} "{api}/Email/list_pops"\n\n'
            + f'5. MySQL databases and users:\n   {cp} "{api}/Mysql/list_databases"\n'
            + f'   {cp} "{api}/Mysql/list_users"\n\n'
            + f'6. Cron jobs:\n   {cp} "{api}/Cron/list_cron"\n\n'
            + f'7. Files in public_html (find sensitive files):\n'
            + f'   {cp} "{api}/Fileman/list_files?path=/public_html&show_hidden=1" | {py_filter}\n\n'
            + f'8. ModSecurity status:\n   {cp} "{api}/ModSecurity/has_modsec_installed"\n\n'
            + f'9. Hotlink protection:\n   {cp} "{api}/Hotlink/get_status"\n\n'
            + f'10. .htaccess security rules:\n    curl -s "https://{domain}/.htaccess" | head -50\n'
        )

    if site_type == 'ssh' and ssh_user and (ssh_pass or creds.get('ssh_key')):
        if creds.get('ssh_key'):
            key_setup = ('Setup SSH key first:\n'
                         '  python3 -c "import os; open(\'/tmp/cf_id_rsa\',\'w\').write(os.environ[\'SSH_KEY\']); '
                         'os.chmod(\'/tmp/cf_id_rsa\', 0o600)"\n')
            sc = (f'ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 '
                  f'-i /tmp/cf_id_rsa -p {ssh_port} {ssh_user}@{ssh_host}')
        else:
            key_setup = 'Install sshpass if missing: apt-get install -y sshpass 2>/dev/null\n'
            sc = (f'sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 '
                  f'-p {ssh_port} {ssh_user}@{ssh_host}')
        # awk command — written as plain string, no f-string brace conflicts
        awk_users  = "awk -F: '$7!~/nologin|false|sync/{print $1,$7}' /etc/passwd"
        awk_bruteforce = "awk '{print $11}' | sort | uniq -c | sort -rn | head -10"
        return (hdr
            + 'SSH CREDENTIALS\n'
            + f'  Host     : {ssh_host}:{ssh_port}\n'
            + f'  Username : {ssh_user}\n'
            + '  Password : $SSHPASS (in environment — do not print)\n\n'
            + key_setup + '\n'
            + f'SSH prefix: {sc} "<cmd>"\n\n'
            + 'Run ALL server-side checks:\n\n'
            + f'1. Web/PHP/OS versions:\n'
            + f'   {sc} "php -v 2>&1|head -1; nginx -v 2>&1; apache2 -v 2>&1|head -1; lsb_release -d 2>/dev/null"\n\n'
            + f'2. Sensitive config files (hardcoded credentials):\n'
            + f'   {sc} "cat /var/www/html/.env 2>/dev/null|grep -vP \'^#|^$\'|head -30"\n'
            + f'   {sc} "cat /var/www/html/wp-config.php 2>/dev/null|grep -P \'DB_|AUTH_KEY|SECRET\'|head -20"\n\n'
            + f'3. World-writable PHP files (malware injection risk):\n'
            + f'   {sc} "find /var/www/html -perm -0002 -name \'*.php\' 2>/dev/null|head -20"\n\n'
            + f'4. Backup/dump files in webroot (data exposure):\n'
            + f'   {sc} "find /var/www/html -name \'*.sql\' -o -name \'*.zip\' -o -name \'*.bak\' 2>/dev/null|head -20"\n\n'
            + f'5. Open ports and services:\n'
            + f'   {sc} "ss -tlnp 2>/dev/null|head -25"\n\n'
            + f'6. Users with shell access:\n'
            + f'   {sc} "{awk_users}"\n\n'
            + f'7. Sudo rules (overly permissive = high risk):\n'
            + f'   {sc} "sudo -l 2>/dev/null|head -20"\n\n'
            + f'8. Brute force evidence (failed SSH logins):\n'
            + f'   {sc} "grep \'Failed password\' /var/log/auth.log 2>/dev/null|tail -30|{awk_bruteforce}"\n\n'
            + f'9. Crontabs (check for backdoors):\n'
            + f'   {sc} "crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null"\n\n'
            + f'10. SSL certificate expiry:\n'
            + f'    {sc} "openssl s_client -connect {domain}:443 -servername {domain} </dev/null 2>/dev/null'
            + '     | openssl x509 -noout -dates 2>/dev/null"\n\n'
            + f'11. Firewall rules:\n'
            + f'    {sc} "ufw status 2>/dev/null; iptables -L INPUT -n 2>/dev/null|head -20"\n'
        )

    if site_type == 'sftp' and ftp_user and ftp_host:
        proto  = 'sftp' if site_type == 'sftp' else 'ftp'
        cp_ftp = f'curl -sk --user "{ftp_user}:$FTP_PASSWORD"'
        base   = f'{proto}://{ftp_host}:{ftp_port}/public_html'
        sens_files = '.env wp-config.php config.php database.php settings.php .htpasswd'
        bak_files  = 'backup.sql backup.zip site.sql dump.sql site-backup.tar.gz'
        return (hdr
            + 'SFTP/FTP CREDENTIALS\n'
            + f'  Host     : {ftp_host}:{ftp_port}\n'
            + f'  Username : {ftp_user}\n'
            + '  Password : $FTP_PASSWORD (in environment)\n\n'
            + 'Run ALL file system checks:\n\n'
            + f'1. List webroot:\n   {cp_ftp} "{base}/" 2>&1|head -50\n\n'
            + f'2. Sensitive files (check each for 200/non-000 response):\n'
            + '   for f in ' + sens_files + '; do\n'
            + f'     code=$({cp_ftp} "{base}/$f" -o /tmp/ftp_f -w "%{{http_code}}" 2>&1)\n'
            + '     [ "$code" != "000" ] && echo "FOUND $f ($code)" && head -20 /tmp/ftp_f\n'
            + '   done\n\n'
            + f'3. Backup/dump files:\n'
            + '   for b in ' + bak_files + '; do\n'
            + f'     echo -n "$b: "; {cp_ftp} -o /dev/null -w "%{{http_code}}" "{base}/$b" 2>&1\n'
            + '     echo\n'
            + '   done\n\n'
            + f'4. Exposed .git directory:\n'
            + f'   curl -s "https://{domain}/.git/HEAD"|head -5\n'
            + f'   curl -s "https://{domain}/.git/config"|head -20\n\n'
            + f'5. PHP config:\n'
            + f'   {cp_ftp} "{base}/php.ini" 2>&1|grep -iP "disable_functions|open_basedir|expose_php"\n\n'
            + f'6. .htaccess security rules:\n'
            + f'   {cp_ftp} "{base}/.htaccess" 2>&1|head -40\n\n'
            + f'7. Uploads directory — check for PHP shells:\n'
            + f'   {cp_ftp} "{base}/wp-content/uploads/" 2>&1|grep -iP "\\.php|\\.phtml|\\.php5"\n'
        )

    return ''


def _run_background_scan(job_id: str, target: str, agent_type: str,
                          model: str, site_type: str, creds: dict):
    """Run a WSTG agent in a background thread and stream chunks to _scan_jobs."""
    job = _scan_jobs[job_id]

    # Pre-initialise so the except handler can always reference these safely
    parts:  list = []
    tools:  list = [0]
    t0           = _time.time()
    domain       = ''
    model_used   = model or ''

    # Set credential env vars so agents can reference $WP_PASSWORD, $SSHPASS, etc.
    env_restore: dict = {}
    cred_env = {
        'WP_USER':         creds.get('wp_user', ''),
        'WP_APP_PASSWORD': creds.get('wp_app_pass', ''),
        'WP_PASSWORD':     creds.get('wp_pass', ''),
        'CPANEL_PASSWORD': creds.get('cpanel_pass', ''),
        'SSHPASS':         creds.get('ssh_pass', ''),
        'FTP_PASSWORD':    creds.get('ftp_pass', ''),
        'SSH_KEY':         creds.get('ssh_key', ''),
    }
    for k, v in cred_env.items():
        if v:
            env_restore[k] = os.environ.get(k, '')
            os.environ[k] = v

    try:
        import dataclasses as dc
        from urllib.parse import urlparse as _up
        from agents.wstg_agents import WSTG_REGISTRY
        from sdk.agents import Runner
        from sdk import tracing

        # Normalise domain (strip scheme + path)
        _url = target if '://' in target else 'https://' + target
        _p   = _up(_url)
        domain = (_p.netloc or _p.path.split('/')[0]).rstrip('/')
        job['domain'] = domain

        # Build authenticated-scan instructions and announce cred type in terminal
        cred_block = _build_cred_block(site_type, creds, domain)
        if cred_block:
            job['chunks'].append({'k': 'txt', 'd': f'[AUTH] {site_type.upper()} credentials loaded — authenticated scan enabled'})

        def _ot(t):
            if job.get('aborted'):
                raise RuntimeError('Scan aborted by user')
            parts.append(t)
            job['chunks'].append({'k': 'txt', 'd': t})
        def _oo(n, a):  tools[0] += 1;     job['chunks'].append({'k': 'tool', 'n': n, 'a': str(a)[:200]})
        def _or(n, r, e):
            r_full = str(r)
            # Capture tool results containing WP-LOG lines or from MCP tools so
            # extract_wp_logs() and the Plugin Logs modal can parse them after save.
            if ('WP-LOG' in r_full or n in ('wp_security_scan', 'wp_api_call')) and r_full.strip():
                parts.append(f'[TOOL:{n}]\n{r_full}')
            job['chunks'].append({'k': 'res', 'n': n, 'r': r_full[:300], 'e': bool(e)})

        if agent_type == 'pentest':
            from agents.pentest import run_full_pentest
            t0 = _time.time()
            run_full_pentest(domain, model=model or None, on_text=_ot, on_tool=_oo, on_result=_or,
                             cred_block=cred_block or None,
                             is_aborted=lambda: bool(job.get('aborted')))
            model_used = model or ''
        elif agent_type in ('ctf', 'ot', 'enum'):
            from agents.special_agents import SPECIAL_REGISTRY as _SREG
            base = _SREG.get(agent_type)
            if base is None:
                job.update({'status': 'error', 'error': f'Unknown special agent: {agent_type}'}); return
            _s_instr = base.instructions.replace('{target}', domain)
            if cred_block:
                _s_instr += cred_block
            agent    = dc.replace(base, instructions=_s_instr)
            if model:
                agent = dc.replace(agent, model=model)
            elif cred_block:
                # Credentials supplied — use Claude for reliable execution
                _cm = os.environ.get('ANTHROPIC_MODEL', 'claude-sonnet-4-6')
                agent = dc.replace(agent, model=_cm)
            model_used = getattr(agent, 'model', model) or ''
            _label = {'ctf': 'CTF Solver', 'ot': 'OT/ICS Security', 'enum': 'API Enumeration'}.get(agent_type, agent_type.upper())
            t0 = _time.time()
            with tracing.span(f'dashboard:{agent_type}') as span:
                span.set_attribute('cfai.target', domain)
                Runner.run(agent, f'Begin {_label} on {domain}.',
                           on_text=_ot, on_tool=_oo, on_result=_or)
        else:
            base = WSTG_REGISTRY.get(agent_type)
            if base is None:
                job.update({'status': 'error', 'error': f'Unknown agent type: {agent_type}'}); return

            # Inject credential instructions after the base instructions
            base_instructions = base.instructions.replace('{domain}', domain) + cred_block
            agent = dc.replace(base, instructions=base_instructions)
            if model:
                agent = dc.replace(agent, model=model)
            model_used = getattr(agent, 'model', model) or ''

            # Any agent + credentials → Claude model for reliable execution.
            # WordPress site type or WP creds → also inject MCP tools for all agents.
            # APIT → always gets MCP tools regardless of site type.
            _wp_creds  = (creds.get('wp_user') or creds.get('wp_pass') or creds.get('wp_app_pass'))
            _has_creds = bool(
                _wp_creds
                or creds.get('cpanel_user') or creds.get('cpanel_pass')
                or creds.get('ssh_user')    or creds.get('ssh_pass')
                or creds.get('ftp_user')    or creds.get('ftp_pass')
            )
            _needs_mcp = (site_type == 'wordpress') or bool(_wp_creds) or (agent_type == 'apit')

            if _needs_mcp:
                from tools.wordpress_mcp import wp_api_call, wp_security_scan
                mcp_block = (
                    '\n\n══════════════ MCP DIRECT CONNECTION ══════════════\n'
                    'You have wp_security_scan and wp_api_call tools connected via MCP.\n\n'
                    'STEP 0 — ALWAYS DO THIS FIRST:\n'
                    f'  1. Call wp_security_scan(site_url="https://{domain}")\n'
                    '     Runs a full WordPress security audit and emits WP-LOG entries.\n'
                    '  2. CRITICAL: Copy ALL lines starting with "WP-LOG |" from the tool\n'
                    '     result VERBATIM into your response — DO NOT generate WP-LOG lines\n'
                    '     yourself, only echo what the tool returned.\n'
                    f'  3. Call wp_api_call(site_url="https://{domain}", endpoint="/wp-json/wp/v2/users")\n'
                    '     and other REST endpoints for deeper investigation.\n'
                    '  4. If no WP-LOG entries were returned by the tool, instruct the user\n'
                    '     to install the free "WP Activity Log" plugin (wp-security-audit-log)\n'
                    '     and re-run the scan to get real admin login events with IP addresses.\n'
                    '     If admin credentials are provided, attempt installation via WP-CLI:\n'
                    f'     generic_linux_command("wp plugin install wp-security-audit-log --activate --path=/var/www/html --url=https://{domain}")\n'
                    'Auth is handled automatically: Basic Auth → Cookie+Nonce → public.\n'
                    '═══════════════════════════════════════════════════\n\n'
                )
                _existing = {getattr(t, '__name__', '') for t in agent.tools}
                new_tools = [t for t in [wp_api_call, wp_security_scan]
                             if getattr(t, '__name__', '') not in _existing] + list(agent.tools)
                _claude_model = os.environ.get('ANTHROPIC_MODEL', 'claude-sonnet-4-6')
                agent = dc.replace(
                    agent,
                    model=_claude_model,
                    instructions=base_instructions + mcp_block,
                    tools=new_tools,
                )
                model_used = _claude_model
            elif _has_creds:
                # Non-WordPress credentials (SSH / cPanel / SFTP) — switch to Claude so
                # the agent reliably executes the credential block instructions.
                _claude_model = os.environ.get('ANTHROPIC_MODEL', 'claude-sonnet-4-6')
                agent = dc.replace(agent, model=_claude_model,
                                   instructions=base_instructions)
                model_used = _claude_model

            t0 = _time.time()
            with tracing.span(f'dashboard:{agent_type}') as span:
                span.set_attribute('cfai.target', domain)
                Runner.run(agent, f'Run all WSTG-{agent_type.upper()} checks on {domain}.',
                           on_text=_ot, on_tool=_oo, on_result=_or)

        elapsed  = _time.time() - t0
        output   = '\n\n'.join(parts)
        was_aborted = job.get('aborted', False)
        db_status   = 'interrupted' if was_aborted else 'ok'

        scan_id = db.save_scan(
            target=domain, agent_type=agent_type,
            model=model_used, status=db_status,
            latency_s=round(elapsed, 2),
            tool_count=tools[0], output=output,
        )
        final_status = 'interrupted' if was_aborted else 'done'
        if was_aborted:
            job['chunks'].append({'k': 'txt', 'd': '\n[Scan stopped — findings logged to dashboard]\n'})
        job['chunks'].append({'k': 'saved', 'id': scan_id})
        job.update({'status': final_status, 'elapsed': round(elapsed, 2),
                    'tool_count': tools[0], 'scan_id': scan_id})
        _parse_and_save_plugins(scan_id, domain, output)
        _job_persist(job_id, job)

    except Exception as exc:
        import traceback as _tb
        tb = _tb.format_exc()[-1200:]
        job['chunks'].append({'k': 'txt', 'd': f'\n[ERROR] {exc}\n{tb}'})
        # Save partial output — variables are always defined because they were pre-initialised
        try:
            scan_id = db.save_scan(
                target=domain or target or '',
                agent_type=agent_type,
                model=model_used,
                status='error',
                latency_s=round(_time.time() - t0, 2),
                tool_count=tools[0],
                output='\n\n'.join(parts) or f'[ERROR] {exc}',
            )
            job['chunks'].append({'k': 'saved', 'id': scan_id})
            job.update({'status': 'error', 'error': str(exc), 'trace': tb, 'scan_id': scan_id})
            _parse_and_save_plugins(scan_id, domain or target or '', '\n\n'.join(parts))
        except Exception:
            job.update({'status': 'error', 'error': str(exc), 'trace': tb})
        _job_persist(job_id, job)
    finally:
        for k, orig in env_restore.items():
            if orig: os.environ[k] = orig
            else: os.environ.pop(k, None)


# Optional shared secret for the remote-save API endpoint.
# Set CFAI_API_KEY in the VPS .env to protect POST /api/scan.
# If unset, the endpoint accepts any request (fine on a private VPS).
_API_KEY = os.environ.get('CFAI_API_KEY', '')


# ── Risk classification ────────────────────────────────────────────────────────

_HIGH_KW = [
    'critical', 'high severity', 'exploit', 'vulnerable', 'vulnerability',
    'remote code execution', 'rce', 'sql injection', 'sqli', 'xss',
    'cross-site scripting', 'authentication bypass', 'privilege escalation',
    'unauthorized access', 'exposed credentials', 'leaked secret',
    'path traversal', 'directory traversal', 'file inclusion',
    'command injection', 'deserialization', 'idor', 'insecure direct object',
    'broken access control', 'account takeover',
]
_MED_KW = [
    'medium', 'moderate', 'information disclosure', 'outdated version',
    'weak cipher', 'misconfigured', 'missing security header',
    'deprecated', 'insecure cookie', 'cors misconfiguration',
    'open redirect', 'clickjacking', 'csrf', 'open port',
    'server version', 'default credentials',
]
_LOW_KW = [
    'low severity', 'informational', 'best practice', 'minor',
    'consider enabling', 'consider disabling', 'suggestion',
]

_ACTION_RE = re.compile(
    r'\b(update|upgrade|patch|disable|enable|restrict|remove|add|fix|'
    r'configure|implement|enforce|rotate|revoke|harden|review|audit|'
    r'change|replace|block|sanitize|validate|encrypt)\b',
    re.I,
)

_REC_HEADERS = (
    'recommendation', 'action item', 'remediation', 'next step',
    'action plan', 'suggested fix', 'what to do', 'mitigation',
    'to fix', 'to remediate',
)

# Lines containing these phrases describe attempts or failed checks — skip them
_NEGATION = re.compile(
    r'\b(no\b|not\b|failed|unsuccessful|did not|does not|returned no|'
    r'found no|no evidence|could not|unable to|attempting|will attempt|'
    r'will try|will now|testing for|checking for|i will|let me|'
    r'next i |next,|explore potential|no result|no data|no output|'
    r'empty response|no vuln|not vuln|not found|not detect|not appear)\b',
    re.I,
)


def risk_level(text: str) -> str:
    """Derive risk only from lines that confirm a finding, skipping attempt/failure lines."""
    lines = text.splitlines()
    for kw_list, label in ((_HIGH_KW, 'HIGH'), (_MED_KW, 'MEDIUM'), (_LOW_KW, 'LOW')):
        for line in lines:
            if _NEGATION.search(line):
                continue
            if any(k in line.lower() for k in kw_list):
                return label
    return 'INFO'


def rec_risk(text: str) -> str:
    """Score a single recommendation line independently — avoids scan-wide HIGH bleeding."""
    if not text:
        return 'INFO'
    tl = text.lower()
    for kw_list, label in ((_HIGH_KW, 'HIGH'), (_MED_KW, 'MEDIUM'), (_LOW_KW, 'LOW')):
        if any(k in tl for k in kw_list):
            return label
    return 'MEDIUM'  # actionable but no severity keyword → treat as medium


def _strip_md(text: str) -> str:
    text = re.sub(r'\*\*([^*\n]+)\*\*', r'\1', text)
    text = re.sub(r'\*([^*\n]+)\*', r'\1', text)
    return text.strip()


# Recommendations that describe scanner execution problems, not real vulnerabilities
_SCANNER_NOISE = re.compile(
    r'\b(check connectivity|internet connectivity|assessment platform|'
    r'ensure proper internet|rerun with|retry with|adjust.*header|'
    r'passive recon|historical.*data source|alternative means|'
    r'manual inspection|firewall.*rule.*site|rate limit.*rule|'
    r'scan.*block|blocked.*scan|increase.*timeout|reduce.*thread|'
    r'try.*different.*approach|diagnostic|next step.*scan|'
    r'consider passive|proper internet|platform.*connect|'
    r'connectivity.*assess|assess.*connect|'
    # Agent execution errors — not real security findings
    r'syntax error.*execution|preventing complete execution|'
    r'reliability.*assessment.*syntax|syntax review.*re-execution|re-execution|'
    r'review.*correct.*python|correct.*script syntax|script syntax|'
    r'alternative reconnaissance method|correct.*operational endpoint.*alternative|'
    r'confirm correct url.*alternative)\b',
    re.I,
)


def extract_recs(text: str) -> list[str]:
    recs, in_sec = [], False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            in_sec = False
            continue
        if _NEGATION.search(line) or _SCANNER_NOISE.search(line):
            in_sec = False
            continue
        clean = _strip_md(re.sub(r'^[-*+\d.)#]+\s*', '', line))
        clean_lower = clean.lower()
        if any(h in clean_lower for h in _REC_HEADERS):
            in_sec = True
            if ':' in clean:
                after = clean.split(':', 1)[1].strip()
                if len(after) > 12 and not _SCANNER_NOISE.search(after):
                    recs.append(after)
                    in_sec = False
            continue
        is_bullet = line.startswith(('-', '*', '+')) or re.match(r'^\d+[.)]\s', line)
        if in_sec and is_bullet:
            item = _strip_md(re.sub(r'^[-*+\d.)]+\s*', '', line).strip())
            if len(item) > 12:
                recs.append(item)
        elif _ACTION_RE.search(clean) and 25 < len(clean) < 300:
            recs.append(clean)
    seen, out = set(), []
    for r in recs:
        k = r[:50].lower()
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out[:12]


_WP_LOG_RE = re.compile(
    r'^WP-LOG\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*(HIGH|MEDIUM|LOW|INFO)\s*$',
    re.I | re.MULTILINE,
)
_WP_LOG_STATUS_RE = re.compile(
    r'^WP-LOG-STATUS\s*\|\s*(\w+)\s*\|\s*([^|\n]+?)\s*\|',
    re.I | re.MULTILINE,
)

# Fallback patterns: parse structured agent output lines into WP-LOG-style entries
# for scans that predate the WP-LOG emission updates.
_WP_LOG_FALLBACK = [
    (re.compile(r'^EXPOSED_FILE \| (\S+) \| (/\S+)', re.M),
     lambda m: ('CF_AI', f'Exposed sensitive file: {m.group(2)} (HTTP {m.group(1)})', '-', 'HIGH')),
    (re.compile(r'^CREDS_FOUND_XMLRPC \| ([^\|\n]+?) \|', re.M),
     lambda m: (m.group(1).strip(), 'WordPress credentials verified via XML-RPC brute-force', '-', 'HIGH')),
    (re.compile(r'^CREDS_FOUND_FORM \| ([^\|\n]+?) \|', re.M),
     lambda m: (m.group(1).strip(), 'WordPress credentials verified via login form', '-', 'HIGH')),
    (re.compile(r'^APP_PASS_CREATED(?:_COOKIE)? \| ([^\|\n]+?) \|', re.M),
     lambda m: (m.group(1).strip(), 'Application Password created by CF_AI scanner', '-', 'HIGH')),
    (re.compile(r'^WP-USER-CONFIRMED \| ([^\|\n]+?) \|', re.M),
     lambda m: (m.group(1).strip(), 'WordPress username confirmed via login error oracle', '-', 'MEDIUM')),
    (re.compile(r'^WP-USER \| (\S+) \| (\S+) \|', re.M),
     lambda m: (m.group(2), f'WordPress user enumerated via REST API (id={m.group(1)})', '-', 'MEDIUM')),
    (re.compile(r'^WP-USER-ENUM \| (\S+) \| (\S+) \|', re.M),
     lambda m: (m.group(2), 'WordPress user enumerated via author redirect', '-', 'MEDIUM')),
    (re.compile(r'^FOUND_DB_USER:\s*(\S+)', re.M),
     lambda m: ('CF_AI', f'Database username exposed in config file: {m.group(1)}', '-', 'HIGH')),
]


def _wp_log_fallback(output: str) -> list:
    """Parse structured agent lines into WP-LOG entries (fallback for older scans)."""
    entries = []
    seen = set()
    for pat, builder in _WP_LOG_FALLBACK:
        for m in pat.finditer(output):
            user, event, ip, risk = builder(m)
            key = (user, event)
            if key not in seen:
                seen.add(key)
                entries.append({'timestamp': '--', 'user': user, 'event': event, 'ip': ip, 'risk': risk})
    return entries


# Users that indicate scanner-generated entries, not real admin logins
_SCANNER_USERS = {'system', 'cf_ai', 'cf_ai-mcp', 'cf_ai_mcp', 'scanner'}


def extract_wp_logs(output: str) -> dict:
    """Parse WP-LOG lines from agent output. Returns {entries, status}.

    Scanner-generated entries (user == 'system', 'CF_AI', etc.) are excluded —
    Plugin Logs shows only real WordPress user activity.
    """
    entries = []
    for m in _WP_LOG_RE.finditer(output):
        user = m.group(2).strip()
        if user.lower() in _SCANNER_USERS:
            continue
        entries.append({
            'timestamp': m.group(1).strip(),
            'user':      user,
            'event':     m.group(3).strip(),
            'ip':        m.group(4).strip(),
            'risk':      m.group(5).strip().upper(),
        })
    # Fallback: structured agent-emitted lines (CF_AI scanner patterns)
    fallback = [e for e in _wp_log_fallback(output)
                if e.get('user', '').lower() not in _SCANNER_USERS]
    entries.extend(fallback)
    status_match = _WP_LOG_STATUS_RE.search(output)
    status_code = status_match.group(1) if status_match else ('found' if entries else 'none')
    status_msg  = status_match.group(2).strip() if status_match else ''
    return {'entries': entries, 'status': status_code, 'status_msg': status_msg}


# Narrower negation for remediation matching — only skips lines that say
# a check *passed* or the agent is *about to* test something.
# Deliberately does NOT include \bno\b / \bnot\b because "No X-Frame-Options
# header" is a real finding, not a negation.
_REM_NEGATION = re.compile(
    r'\b(no vulnerability|not vulnerable|not affected|properly configured|'
    r'no issue found|no problem|correctly set|header present|header found|'
    r'attempting|will attempt|will try|will now|testing for|checking for|'
    r'i will test|let me test|i will check|checking if)\b',
    re.I,
)

# Maps lowercase fix-key substrings → internal stack identifier
_FIX_STACK_KEYS: dict[str, str] = {
    'nginx':          'nginx',
    'apache':         'apache',
    '.htaccess':      'apache',
    'php':            'php',
    'wordpress':      'wp',
    'wp-cli':         'wp',
    'functions.php':  'wp',
    'wp-config':      'wp',
}


# Negation patterns specific to stack detection — a line saying
# "checking for xmlrpc.php" or "xmlrpc.php returned 404" is NOT evidence of WordPress.
_STACK_NEG = re.compile(
    r'\b(checking|testing|looking for|scanning for|probing|not found|'
    r'returns?\s*404|http\s*404|status\s*404|not present|not installed|'
    r'not detected|not running|no evidence|not a wordpress|not wordpress|'
    r'no wordpress|does not appear|does not use|is not running)\b',
    re.I,
)


def _detect_stacks(text: str) -> set[str]:
    """Detect server / CMS stacks referenced in agent output.

    Only fires on lines with *positive* evidence — lines that look like
    "checking for X" or "X returned 404" are skipped via _STACK_NEG.
    """
    found: set[str] = set()
    for line in text.splitlines():
        if _STACK_NEG.search(line) or _NEGATION.search(line):
            continue
        ll = line.lower()
        # WordPress: require definitive positive signals, not just any mention
        if any(k in ll for k in ('wp-content/', 'wp-admin/', 'wp-login.php',
                                  '/wp-json/', 'wordpress version', 'woocommerce',
                                  '/wp-includes/', 'wp-config.php', 'xmlrpc.php')):
            found.add('wp')
        if 'nginx' in ll:
            found.add('nginx')
        if 'apache' in ll or '.htaccess' in ll:
            found.add('apache')
        if 'php' in ll:
            found.add('php')
    return found


def _filter_fixes(fixes: dict, detected: set[str]) -> dict:
    """Return only the fix entries relevant to detected stacks.

    Fix keys that belong to an undetected stack are hidden; generic keys
    (certbot, bash, manual, general) are always shown.
    Falls back to all fixes when nothing was detected.
    """
    if not detected:
        return fixes
    filtered = {}
    for key, code in fixes.items():
        kl = key.lower()
        fix_stack = next(
            (sid for pattern, sid in _FIX_STACK_KEYS.items() if pattern in kl),
            None,
        )
        is_generic = fix_stack is None or any(
            g in kl for g in ('bash', 'manual', 'general', 'certbot', 'waf')
        )
        if is_generic or fix_stack in detected:
            filtered[key] = code
    return filtered if filtered else fixes


def match_remediations(text: str, target: str = '') -> list[dict]:
    """Return remediation templates for vulnerabilities found in this scan.

    - Only confirms positive findings (skips _REM_NEGATION lines).
    - WordPress-specific remediations require WordPress to be detected.
    - Fix stacks are filtered to those seen in the scan output.
    - The actual target domain replaces the placeholder 'yourdomain.com'.
    """
    pos_lines = [l.lower() for l in text.splitlines() if not _REM_NEGATION.search(l)]
    pos_text  = ' '.join(pos_lines)
    detected  = _detect_stacks(text)

    matched: list[dict] = []
    for rem in REMEDIATIONS:
        if not any(p in pos_text for p in rem['patterns']):
            continue
        # WordPress-specific remediations only if WP is detected in this scan
        if rem['id'].startswith('wp-') and 'wp' not in detected:
            continue
        # Filter fix stacks to those seen in this site's output
        fixes = _filter_fixes(rem['fixes'], detected)
        # Substitute the actual scanned domain (if known) into fix code
        if target:
            fixes = {
                k: v.replace('yourdomain.com', target)
                     .replace('YOUR.OFFICE.IP.HERE', '[your office IP]')
                for k, v in fixes.items()
            }
        matched.append({**rem, 'fixes': fixes})
    return matched


_AGENT_LABELS = {
    'info':    'Information Gathering',
    'conf':    'Configuration Review',
    'athn':    'Authentication Testing',
    'athz':    'Authorization Testing',
    'sess':    'Session Management',
    'inpv':    'Input Validation',
    'cryp':    'Cryptography Review',
    'clnt':    'Client-Side Testing',
    'apit':    'API Security Testing',
    'js':      'JavaScript Analysis',
    'idnt':    'Identity Management',
    'ctf':     'CTF / Challenge',
    'ot':      'OT/ICS Security',
    'enum':    'API Enumeration',
    'pentest': 'Full Penetration Test',
    'recon':   'Reconnaissance',
    'analyst': 'Security Analysis',
    'exploit': 'Exploit Development',
}


def agent_label(a: str) -> str:
    return _AGENT_LABELS.get((a or '').lower(), (a or '').upper())


def _norm_target(raw: str) -> str:
    """Strip scheme and path — keep only host[:port]."""
    t = (raw or '').replace('https://', '').replace('http://', '')
    return t.split('/')[0].split('?')[0].rstrip('.')


def enrich(scan: dict) -> dict:
    scan = dict(scan)
    scan['target']       = _norm_target(scan.get('target', ''))
    out  = scan.get('output', '') or ''
    scan['risk']         = risk_level(out)
    scan['agent_label']  = agent_label(scan.get('agent_type', ''))
    scan['recs']         = extract_recs(out)
    scan['remediations'] = match_remediations(out, target=scan['target'])
    scan['preview']      = out[:400].replace('\n', ' ')
    dt = scan.get('created_at', '') or ''
    scan['display_date'] = dt[:16].replace('T', ' ')
    return scan


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    ctx = _build_template_context()
    return render_template('index.html', **ctx)


def _build_template_context() -> dict:
    """Build the full template context dict — shared with FastAPI."""
    scans   = [enrich(s) for s in db.get_scans()]
    targets = [enrich(t) for t in db.get_targets()]
    stats   = db.get_stats()

    _prio = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
    all_recs = []
    seen_per_target: dict[str, set] = {}
    for s in scans:
        tgt = s['target']
        seen = seen_per_target.setdefault(tgt, set())
        for rem in s['remediations']:
            k = rem['id']
            if k not in seen:
                seen.add(k)
                all_recs.append({'target': tgt, 'risk': rem['severity'], 'text': rem['title'],
                                 'agent': s['agent_label'], 'date': s['display_date'][:10],
                                 'scan_id': s['id'], 'has_fixes': True})
        for r in s['recs']:
            k = r[:60].lower()
            if k not in seen:
                seen.add(k)
                all_recs.append({'target': tgt, 'risk': rec_risk(r), 'text': r,
                                 'agent': s['agent_label'], 'date': s['display_date'][:10],
                                 'scan_id': s['id'], 'has_fixes': False})
    all_recs.sort(key=lambda x: (_prio.get(x['risk'], 3), x['target']))

    from collections import defaultdict as _dd
    _tgt_sev: dict = _dd(lambda: {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0})
    for s in scans:
        _tgt_sev[s['target']][s['risk']] += 1
    severity_summary = {
        'total': {
            'HIGH':   sum(v['HIGH']   for v in _tgt_sev.values()),
            'MEDIUM': sum(v['MEDIUM'] for v in _tgt_sev.values()),
            'LOW':    sum(v['LOW']    for v in _tgt_sev.values()),
            'INFO':   sum(v['INFO']   for v in _tgt_sev.values()),
        },
        'by_target': sorted(
            [{'target': k, **v} for k, v in _tgt_sev.items()],
            key=lambda x: x['HIGH'] * 10 + x['MEDIUM'] * 3 + x['LOW'],
            reverse=True,
        )[:12],
    }
    return dict(scans=scans, targets=targets, stats=stats,
                all_recs=all_recs[:40], severity_summary=severity_summary)


@app.route('/api/scan/<int:scan_id>')
def api_scan(scan_id):
    row = db.get_scan(scan_id)
    if not row:
        abort(404)
    return jsonify(enrich(row))


@app.route('/api/stats')
def api_stats():
    return jsonify(db.get_stats())


@app.route('/api/scans/recent')
def api_scans_recent():
    """Return the latest scans as JSON for live dashboard refresh."""
    limit  = min(int(request.args.get('limit', 50)), 200)
    target = request.args.get('target', '')
    rows   = db.get_scans()[:limit]
    if target:
        rows = [r for r in rows if r.get('target', '').lower() == target.lower()]
    return jsonify([enrich(r) for r in rows])


_RISK_HIGH_RE = re.compile(
    r'REFLECTED\s+XSS:|SQL\s+ERROR:|CODE\s+INJECTION\s+CONFIRMED:|CMD\s+INJECTION:'
    r'|SSTI\s+HIT|SSRF\s+HIT:|CREDS_FOUND|FOUND_DB_USER:|FOUND_ENV_USER:'
    r'|APP_PASS_CREATED|EXPOSED_FILE\s*\|.*\b20[0-9]\b'
    r'|WP-LOG[^|\n]*\|\s*HIGH|\|\s*(High|Critical)\s*\|', re.I)
_RISK_MED_RE = re.compile(
    r'OPEN\s+REDIRECT:|HTML\s+INJECTION:|WP-USER-CONFIRMED|WP-USER\s*\|'
    r'|WP-LOG[^|\n]*\|\s*MEDIUM|\|\s*Medium\s*\|', re.I)
_RISK_LOW_RE = re.compile(r'\|\s*(Low|Info)\s*\||\d+/tcp\s+open', re.I)

def _scan_risk(out: str) -> str:
    if _RISK_HIGH_RE.search(out): return 'HIGH'
    if _RISK_MED_RE.search(out):  return 'MEDIUM'
    if _RISK_LOW_RE.search(out):  return 'LOW'
    return 'INFO'

@app.route('/api/scans/summary')
def api_scans_summary():
    """Lightweight scan list — pre-computed risk, no output text. For dashboard charts/KPIs."""
    limit = min(int(request.args.get('limit', 500)), 2000)
    rows  = db.get_recent_scans(limit)
    return jsonify([{
        'id':         r['id'],
        'target':     r['target'],
        'agent_type': r['agent_type'],
        'created_at': r['created_at'],
        'status':     r['status'],
        'latency_s':  r['latency_s'],
        'tool_count': r['tool_count'],
        'risk':       _scan_risk(r.get('output') or ''),
    } for r in rows])


@app.route('/api/scan/<int:scan_id>/cve')
def api_scan_cve(scan_id):
    """Query NVD for real CVEs matching the technologies found in this scan."""
    row = db.get_scan(scan_id)
    if not row:
        abort(404)
    from dashboard.cve import cve_lookup_for_scan
    result = cve_lookup_for_scan(row.get('output', '') or '', row.get('target', ''))
    return jsonify(result)


@app.route('/api/target/<path:target>/wp-logs')
def api_wp_logs(target):
    """Return all WP Activity Log entries parsed from scans for a given target."""
    scans = db.get_scans_for_target(target)
    all_entries = []
    overall_status = 'none'
    overall_msg = ''
    for s in scans:
        result = extract_wp_logs(s.get('output', '') or '')
        if result['entries']:
            overall_status = 'found'
            for e in result['entries']:
                e['scan_id']   = s['id']
                e['scan_date'] = (s.get('created_at') or '')[:16]
                e['agent']     = s.get('agent_type', '')
            all_entries.extend(result['entries'])
        elif result['status'] not in ('none',) and overall_status == 'none':
            overall_status = result['status']
            overall_msg    = result['status_msg']
    all_entries.sort(key=lambda e: e.get('timestamp', ''), reverse=True)
    # Enrich entries with geolocation country from the IP field
    for e in all_entries:
        e['country'] = _geoip(e.get('ip', ''))
    return jsonify({
        'target':      target,
        'logs':        all_entries,
        'scan_count':  len(scans),
        'status':      overall_status,
        'status_msg':  overall_msg,
    })


@app.route('/api/scan', methods=['POST'])
def api_save_scan():
    """Remote save endpoint — lets a CLI on another machine push scan results here.

    Expects JSON body:
        { "target": "...", "agent_type": "...", "model": "...",
          "status": "ok", "latency_s": 12.3, "tool_count": 5, "output": "..." }

    If CFAI_API_KEY is set in .env, include header:
        X-CFAI-Key: <your-key>
    """
    if _API_KEY:
        key = request.headers.get('X-CFAI-Key', '')
        if key != _API_KEY:
            return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json(force=True, silent=True) or {}
    required = {'target', 'agent_type', 'output'}
    missing  = required - data.keys()
    if missing:
        return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400

    db.save_scan(
        target     = str(data['target'])[:500],
        agent_type = str(data['agent_type'])[:50],
        model      = str(data.get('model', ''))[:100],
        status     = str(data.get('status', 'ok'))[:20],
        latency_s  = float(data.get('latency_s', 0)),
        tool_count = int(data.get('tool_count', 0)),
        output     = str(data['output'])[:60000],
    )
    return jsonify({'saved': True}), 201


@app.route('/api/target/<path:target>/analytics')
def api_target_analytics(target):
    from dashboard.monitor import get_target_analytics
    from dashboard.security_apis import get_site_scores
    scans = [enrich(s) for s in db.get_scans_for_target(target)]
    analytics = get_target_analytics(target, scans)
    scores = get_site_scores(target)
    return jsonify({**analytics, 'scores': scores})


@app.route('/api/target/<path:target>/compare')
def api_target_compare(target):
    from dashboard.monitor import compare_scans
    scans = [enrich(s) for s in db.get_scans_for_target(target)]
    if len(scans) < 2:
        return jsonify({'error': 'Need at least 2 scans to compare', 'new': [], 'resolved': [], 'persistent': []})
    result = compare_scans(scans[0], scans[1])  # latest vs previous
    result['latest_date'] = scans[0].get('display_date', '')
    result['previous_date'] = scans[1].get('display_date', '')
    return jsonify(result)


@app.route('/api/connect/scan', methods=['POST'])
def api_connect_scan():
    """Start a background scan for the Connect Your Website feature.

    Request JSON:
      { "target": "example.com", "agent_type": "apit", "model": "",
        "site_type": "wordpress|cpanel|ssh|sftp|none",
        "wp_user": "", "wp_pass": "", "wp_app_pass": "",
        "cpanel_user": "", "cpanel_pass": "",
        "ssh_host": "", "ssh_user": "", "ssh_pass": "", "ssh_port": "", "ssh_key": "",
        "ftp_host": "", "ftp_user": "", "ftp_pass": "", "ftp_port": "" }
    Response: { "job_id": "<uuid>" }
    """
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get('target') or '').strip()
    if not target:
        return jsonify({'error': 'target is required'}), 400

    def _s(k): return (data.get(k) or '').strip()

    agent_type = _s('agent_type') or 'apit'
    model      = _s('model')
    site_type  = _s('site_type') or 'none'

    creds = {
        'wp_user':      _s('wp_user'),
        'wp_pass':      _s('wp_pass'),
        'wp_app_pass':  _s('wp_app_pass'),
        'cpanel_user':  _s('cpanel_user'),
        'cpanel_pass':  _s('cpanel_pass'),
        'ssh_host':     _s('ssh_host'),
        'ssh_user':     _s('ssh_user'),
        'ssh_pass':     _s('ssh_pass'),
        'ssh_port':     _s('ssh_port'),
        'ssh_key':      _s('ssh_key'),
        'ftp_host':     _s('ftp_host'),
        'ftp_user':     _s('ftp_user'),
        'ftp_pass':     _s('ftp_pass'),
        'ftp_port':     _s('ftp_port'),
    }

    job_id = str(_uuid.uuid4())
    _scan_jobs[job_id] = {
        'status':  'running',
        'target':  target,
        'agent':   agent_type,
        'chunks':  [],
        'domain':  '',
        'scan_id': None,
        'error':   None,
        'aborted': False,
    }

    t = _threading.Thread(
        target=_run_background_scan,
        args=(job_id, target, agent_type, model, site_type, creds),
        daemon=True,
    )
    t.start()
    return jsonify({'job_id': job_id}), 202


@app.route('/api/connect/scan/<job_id>', methods=['GET'])
def api_connect_scan_poll(job_id):
    """Poll for new chunks from a running background scan.

    Query param `offset` (int, default 0) — index of first unseen chunk.
    Response: { "status": "running"|"done"|"error", "chunks": [...],
                "next_offset": N, "domain": "...", "scan_id": null|int,
                "error": null|"..." }
    """
    job = _scan_jobs.get(job_id)
    if not job:
        # Server may have restarted — try to recover from disk
        saved = _job_load(job_id)
        if saved:
            return jsonify({
                'status':      saved.get('status', 'done'),
                'domain':      saved.get('domain', ''),
                'scan_id':     saved.get('scan_id'),
                'error':       saved.get('error'),
                'chunks':      [],
                'next_offset': 0,
                'recovered':   True,
            })
        return jsonify({'error': 'job not found — server may have restarted. Check Scan History for results.'}), 404

    offset = int(request.args.get('offset', 0))
    new_chunks = job['chunks'][offset:]
    return jsonify({
        'status':      job['status'],
        'domain':      job.get('domain', ''),
        'scan_id':     job.get('scan_id'),
        'error':       job.get('error'),
        'chunks':      new_chunks,
        'next_offset': offset + len(new_chunks),
    })


@app.route('/api/connect/scan/<job_id>/abort', methods=['POST'])
def api_connect_scan_abort(job_id):
    """Signal a running background scan to stop; partial findings will be saved."""
    job = _scan_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'job not found'}), 404
    job['aborted'] = True
    # Keep status as 'running' so the frontend keeps polling until the
    # background thread finishes saving partial output, then sets 'interrupted'.
    job['chunks'].append({'k': 'txt', 'd': '\n[Stopping scan — saving findings so far...]\n'})
    return jsonify({'ok': True})


@app.route('/api/security-signals')
def api_security_signals():
    """Aggregate security events from scan history into a SIEM-style signal feed."""
    import re as _re

    _HIGH_SIGNALS = [
        (r'sql\s*inject|union\s+select|1=1|sleep\(|benchmark\(', 'SQL Injection Attempt'),
        (r'xss|<script|javascript:|onerror\s*=', 'Cross-Site Scripting (XSS)'),
        (r'path\s+traversal|\.\./|%2e%2e|directory\s+list', 'Path Traversal'),
        (r'rce|remote\s+code\s+exec|shell\s+upload|webshell', 'Remote Code Execution'),
        (r'brute.?force|login\s+attempt|credential\s+stuff', 'Brute Force Attack'),
        (r'exposed.*private.*key|api\s+key\s+leak|secret.*leak', 'Credential Exposure'),
        (r'command\s+inject|cmd\.exe|/bin/bash|eval\(base64', 'Command Injection'),
    ]
    _MED_SIGNALS = [
        (r'csrf|cross.site\s+request', 'CSRF Vulnerability'),
        (r'open\s+redirect|redirect.*http', 'Open Redirect'),
        (r'xxe|xml\s+external\s+entity', 'XXE Injection'),
        (r'idor|insecure\s+direct\s+object', 'IDOR'),
        (r'weak.*password|default\s+credential', 'Weak Credentials'),
        (r'missing\s+security\s+header|x-frame-options\s+missing|csp\s+missing', 'Missing Security Headers'),
        (r'outdated.*version|version.*vulnerabl|cve-\d{4}-\d+', 'Known CVE'),
        (r'xmlrpc|wordpress.*vuln|wp-login.*exposed', 'WordPress Exposure'),
    ]
    _LOW_SIGNALS = [
        (r'debug\s+mode|verbose\s+error|stack\s+trace', 'Debug Info Exposed'),
        (r'directory\s+listing|index\s+of\s+/', 'Directory Listing'),
        (r'ssl.*expired|certificate.*expir|self.signed', 'SSL Certificate Issue'),
        (r'banner\s+grab|server\s+version\s+exposed', 'Server Banner Exposure'),
    ]

    scans = [enrich(s) for s in db.get_recent_scans(50)]
    signals = []
    seen = set()

    for s in scans:
        text = (s.get('output') or '') + ' '.join(s.get('recs', []))
        target = s.get('target', '')
        ts = s.get('display_date', '')
        scan_id = s.get('id', 0)

        for pat, label in _HIGH_SIGNALS:
            if _re.search(pat, text, _re.I):
                key = f'HIGH:{label}:{target}'
                if key not in seen:
                    seen.add(key)
                    signals.append({'severity': 'HIGH', 'event': label,
                                    'target': target, 'date': ts, 'scan_id': scan_id})
        for pat, label in _MED_SIGNALS:
            if _re.search(pat, text, _re.I):
                key = f'MED:{label}:{target}'
                if key not in seen:
                    seen.add(key)
                    signals.append({'severity': 'MEDIUM', 'event': label,
                                    'target': target, 'date': ts, 'scan_id': scan_id})
        for pat, label in _LOW_SIGNALS:
            if _re.search(pat, text, _re.I):
                key = f'LOW:{label}:{target}'
                if key not in seen:
                    seen.add(key)
                    signals.append({'severity': 'LOW', 'event': label,
                                    'target': target, 'date': ts, 'scan_id': scan_id})

    _sev_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
    signals.sort(key=lambda x: _sev_order.get(x['severity'], 3))

    counts = {k: sum(1 for s in signals if s['severity'] == k)
              for k in ('HIGH', 'MEDIUM', 'LOW', 'INFO')}
    counts['CRITICAL'] = sum(1 for sig in signals
                             if sig['severity'] == 'HIGH' and
                             any(kw in sig['event'].lower()
                                 for kw in ('injection', 'rce', 'exposure', 'traversal')))
    return jsonify({'signals': signals[:200], 'counts': counts})


@app.route('/api/logs/wp-live', methods=['POST'])
def api_logs_wp_live():
    """Fetch real-time login activity from WordPress via REST API + WSAL/Simple History plugins."""
    import base64 as _b64, json as _j
    data     = request.get_json(force=True, silent=True) or {}
    url      = (data.get('url') or '').strip().rstrip('/')
    wp_user  = (data.get('wp_user') or '').strip()
    app_pass = (data.get('wp_app_pass') or '').strip()
    limit    = min(int(data.get('limit') or 50), 200)
    if not url:
        return jsonify({'error': 'WordPress site URL required'}), 400
    if not url.startswith('http'):
        url = 'https://' + url
    auth_header = None
    if wp_user and app_pass:
        auth_header = 'Basic ' + _b64.b64encode(f'{wp_user}:{app_pass}'.encode()).decode()

    def _wp_get(path, timeout=15, override_hdrs=None):
        hdrs = {}
        if override_hdrs:
            hdrs.update(override_hdrs)
        elif auth_header:
            hdrs['Authorization'] = auth_header
        code, body = _wp_request(f'{url}{path}', headers=hdrs, timeout=timeout)
        if code == 200:
            try:
                return _j.loads(body), None
            except Exception:
                return None, 'JSON parse error'
        return None, f'HTTP {code}'

    events, source, note = [], 'none', ''

    # 1. WP Activity Log (WSAL) — richest source, provides per-event IP + user + action
    for path in [f'/wp-json/wsal/v1/events?per_page={limit}&orderby=created_on&order=DESC',
                 f'/wp-json/wsal/v1/events?per_page={limit}']:
        wsal, _ = _wp_get(path)
        if not wsal:
            continue
        items = wsal if isinstance(wsal, list) else wsal.get('events') or wsal.get('data') or []
        for ev in items:
            msg = str(ev.get('message') or ev.get('alert_message') or ev.get('type') or '')
            if not msg:
                continue
            events.append({
                'timestamp': str(ev.get('created_on') or ev.get('date') or ''),
                'user':      str(ev.get('user_login') or ev.get('username') or ev.get('user') or '—'),
                'event':     msg[:120],
                'ip':        str(ev.get('client_ip') or ev.get('ip') or ''),
                'severity':  'HIGH' if any(k in msg.lower() for k in ('fail', 'block', 'attack', 'brute', 'invalid')) else 'INFO',
                'status':    'failed' if any(k in msg.lower() for k in ('fail', 'block', 'denied', 'invalid')) else 'success',
                'source':    'wsal',
            })
        if events:
            source = 'wsal'
            break

    # 2. Simple History plugin REST API
    # Source: bonny/WordPress-Simple-History inc/class-wp-rest-events-controller.php
    # Response fields: message, date_gmt, date_local, loglevel, initiator, initiator_data{user_login}, ip_addresses[]
    if not events:
        sh, _ = _wp_get(f'/wp-json/simple-history/v1/events?per_page={limit}')
        if sh and isinstance(sh, list):
            for ev in sh:
                msg = str(ev.get('message') or '')
                if not any(k in msg.lower() for k in ('login', 'logged', 'sign', 'auth', 'fail', 'password')):
                    continue
                _idata = ev.get('initiator_data') or {}
                _user  = (_idata.get('user_login') or _idata.get('user_email') or
                          ev.get('initiator') or '—')
                _ips   = ev.get('ip_addresses') or []
                _ip    = str(_ips[0]) if _ips else ''
                events.append({
                    'timestamp': str(ev.get('date_gmt') or ev.get('date_local') or ''),
                    'user':      str(_user),
                    'event':     msg[:120],
                    'ip':        _ip,
                    'severity':  'HIGH' if 'fail' in msg.lower() else 'INFO',
                    'status':    'failed' if 'fail' in msg.lower() else 'success',
                    'source':    'simple_history',
                })
            if events:
                source = 'simple_history'

    # 3. WP REST API authenticated — verify auth, fallback to cookie auth for regular passwords
    if not events and auth_header:
        me, _ = _wp_get('/wp-json/wp/v2/users/me?context=edit')
        if me and me.get('id'):
            source = 'wp_rest'
            events.append({
                'timestamp': '', 'ip': '',
                'user':     me.get('slug') or me.get('name') or wp_user,
                'event':    f"Authenticated session active — Role: {', '.join(me.get('roles', []))}",
                'severity': 'INFO', 'status': 'success', 'source': 'wp_rest',
            })
            note = ('No login event plugin detected. Install "Simple History" or "WP Activity Log" '
                    'on your WordPress site to see real-time login events with IP addresses.')
        else:
            # Basic Auth (Application Password) failed — try cookie auth with regular admin password
            ck_nonce, ck_hdr = _wp_cookie_auth(url, wp_user, app_pass)
            if ck_nonce == '__xmlrpc_verified__':
                # Credentials confirmed correct via XML-RPC — WordPress needs an Application Password for REST API
                note = (f'Password verified. WordPress requires an Application Password for REST API access. '
                        f'Create one in 30 seconds: {url}/wp-admin/profile.php '
                        f'(scroll to "Application Passwords" → type any name → click Add → copy the password).')
            elif ck_nonce is not None:
                ck_hdrs = {'Cookie': ck_hdr}
                if ck_nonce:
                    ck_hdrs['X-WP-Nonce'] = ck_nonce
                # Retry Simple History with cookie auth
                sh2, _ = _wp_get(f'/wp-json/simple-history/v1/events?per_page={limit}',
                                  override_hdrs=ck_hdrs)
                if sh2 and isinstance(sh2, list):
                    for ev in sh2:
                        msg = str(ev.get('message') or '')
                        if not any(k in msg.lower() for k in ('login', 'logged', 'sign', 'auth', 'fail', 'password')):
                            continue
                        _idata = ev.get('initiator_data') or {}
                        _user  = (_idata.get('user_login') or _idata.get('user_email') or
                                  ev.get('initiator') or '—')
                        _ips   = ev.get('ip_addresses') or []
                        _ip    = str(_ips[0]) if _ips else ''
                        events.append({
                            'timestamp': str(ev.get('date_gmt') or ev.get('date_local') or ''),
                            'user': str(_user), 'event': msg[:120], 'ip': _ip,
                            'severity': 'HIGH' if 'fail' in msg.lower() else 'INFO',
                            'status': 'failed' if 'fail' in msg.lower() else 'success',
                            'source': 'simple_history',
                        })
                    if events:
                        source = 'simple_history'
                if not events:
                    me2, _ = _wp_get('/wp-json/wp/v2/users/me?context=edit', override_hdrs=ck_hdrs)
                    if me2 and me2.get('id'):
                        source = 'wp_rest'
                        events.append({
                            'timestamp': '', 'ip': '',
                            'user':     me2.get('slug') or me2.get('name') or wp_user,
                            'event':    f"Authenticated via admin session — Role: {', '.join(me2.get('roles', []))}",
                            'severity': 'INFO', 'status': 'success', 'source': 'wp_rest',
                        })
                        note = ('No login event plugin detected. Install "Simple History" or '
                                '"WP Activity Log" to see real-time login events with IP addresses.')
                    else:
                        note = 'Authentication failed — wrong username or password.'
            else:
                note = 'Authentication failed — wrong username or password.'

    if not auth_header and not events:
        root, _ = _wp_get('/wp-json/')
        if root and root.get('name'):
            note = ('WordPress REST API is reachable. Provide a username + Application Password to '
                    'see live login data. Install "WP Activity Log" plugin for full event tracking.')
        else:
            note = 'Could not reach WordPress REST API. Check the URL.'

    if not events and not note:
        note = ('No login events found. Install "WP Activity Log" (WSAL) or "Simple History" plugin '
                'on your WordPress site to expose real-time login events via REST API.')

    return jsonify({'events': events[:limit], 'total': len(events), 'source': source, 'note': note})


@app.route('/api/wp/install-plugin', methods=['POST'])
def api_wp_install_plugin():
    """Install and activate a WordPress plugin via WP REST API (WordPress 5.5+).

    Uses POST /wp-json/wp/v2/plugins — real WordPress core REST endpoint.
    Requires admin credentials with manage_plugins capability.
    Transport: _wp_request() — SSL bypass + curl fallback (handles Cloudflare).
    """
    import base64 as _b64, json as _j
    data     = request.get_json(force=True, silent=True) or {}
    url      = (data.get('url') or '').strip().rstrip('/')
    wp_user  = (data.get('wp_user') or '').strip()
    app_pass = (data.get('wp_app_pass') or '').strip()
    slug     = (data.get('slug') or 'wp-security-audit-log').strip()

    if not url or not wp_user or not app_pass:
        return jsonify({'error': 'url, wp_user, and wp_app_pass are required'}), 400
    if not url.startswith('http'):
        url = 'https://' + url

    auth = 'Basic ' + _b64.b64encode(f'{wp_user}:{app_pass}'.encode()).decode()

    def _make_helpers(hdrs_get, hdrs_post):
        def _wp_get(path):
            code, body = _wp_request(f'{url}{path}', headers=hdrs_get, timeout=15)
            try:
                return code, _j.loads(body)
            except Exception:
                return code, {}
        def _wp_post(path, body_dict):
            code, body = _wp_request(
                f'{url}{path}', method='POST', headers=hdrs_post,
                body=_j.dumps(body_dict).encode(), timeout=90,
            )
            try:
                return code, _j.loads(body)
            except Exception:
                return code, {'message': body[:200]}
        return _wp_get, _wp_post

    def _do_install(hdrs_get, hdrs_post):
        _wp_get, _wp_post = _make_helpers(hdrs_get, hdrs_post)
        chk_code, existing = _wp_get(f'/wp-json/wp/v2/plugins/{slug}/{slug}')
        if chk_code == 401:
            return 401, None
        if chk_code == 200 and existing.get('plugin'):
            if existing.get('status') == 'active':
                return 200, {'ok': True, 'status': 'already_active',
                             'message': f'{existing.get("name", slug)} is already installed and active.'}
            act_code, act_resp = _wp_post(f'/wp-json/wp/v2/plugins/{slug}/{slug}', {'status': 'active'})
            if act_code == 401:
                return 401, None
            if act_code in (200, 201):
                return 200, {'ok': True, 'status': 'activated',
                             'message': f'{act_resp.get("name", slug)} activated successfully.'}
            return act_code, act_resp
        code, resp = _wp_post('/wp-json/wp/v2/plugins', {'slug': slug, 'status': 'active'})
        if code in (200, 201) and resp.get('plugin'):
            return 200, {'ok': True, 'status': 'installed',
                         'message': f'{resp.get("name", slug)} installed and activated successfully.',
                         'version': resp.get('version', '')}
        return code, resp

    # Try Application Password (Basic Auth) first
    basic_get  = {'Authorization': auth}
    basic_post = {'Authorization': auth, 'Content-Type': 'application/json'}
    code, resp = _do_install(basic_get, basic_post)

    if code == 401:
        ck_nonce, ck_hdr = _wp_cookie_auth(url, wp_user, app_pass)
        if ck_nonce == '__xmlrpc_verified__':
            return jsonify({
                'ok': False,
                'error': (
                    'Password verified. WordPress requires an Application Password for remote '
                    'plugin installation. Create one at: '
                    f'{url}/wp-admin/profile.php '
                    '(scroll to "Application Passwords" → type any name → click Add → '
                    'paste the generated password into this field instead).'
                ),
                'code': 401,
                'manual_url': f'{url}/wp-admin/plugin-install.php?s={slug}&tab=search&type=term',
            }), 400
        if ck_nonce is not None:
            ck_get  = {'Cookie': ck_hdr}
            ck_post = {'Cookie': ck_hdr, 'Content-Type': 'application/json'}
            if ck_nonce:
                ck_get['X-WP-Nonce']  = ck_nonce
                ck_post['X-WP-Nonce'] = ck_nonce
            code, resp = _do_install(ck_get, ck_post)

    if code == 200 and resp and resp.get('ok'):
        return jsonify(resp)

    # Surface the real WordPress error message
    raw_err = (resp or {}).get('message') or (resp or {}).get('error') or ''
    if code == 403:
        wp_msg = 'Permission denied — account needs administrator role (manage_plugins capability).'
    elif code == 401:
        wp_msg = 'Authentication failed — wrong username or password.'
    elif code == 0:
        wp_msg = (
            'VPS/server IP blocked — Cloudflare or the hosting firewall is dropping '
            'connections from this server. '
            f'Detail: {raw_err or "TCP connection refused/timed out"}. '
            'Fix: install the plugin manually from your WordPress admin dashboard '
            f'({url}/wp-admin/plugin-install.php) or whitelist this VPS IP in Cloudflare.'
        )
    else:
        wp_msg = raw_err or f'Unexpected HTTP {code}'
    return jsonify({'ok': False, 'error': wp_msg, 'code': code,
                    'manual_url': f'{url}/wp-admin/plugin-install.php?s={slug}&tab=search&type=term'}), \
           (400 if code >= 400 else 500)


@app.route('/api/logs/cpanel-live', methods=['POST'])
def api_logs_cpanel_live():
    """Fetch real-time session/login data from cPanel via UAPI."""
    import base64 as _b64, json as _j, ssl as _ssl, urllib.request as _req
    data     = request.get_json(force=True, silent=True) or {}
    host     = (data.get('host') or '').strip().rstrip('/')
    cp_user  = (data.get('cp_user') or '').strip()
    cp_pass  = (data.get('cp_pass') or '').strip()
    cp_token = (data.get('cp_token') or '').strip()
    port     = int(data.get('port') or 2083)
    limit    = min(int(data.get('limit') or 50), 200)

    if not host or not cp_user:
        return jsonify({'error': 'cPanel host and username required'}), 400
    base = host if host.startswith('http') else f'https://{host}:{port}'
    if cp_token:
        auth_header = f'cpanel {cp_user}:{cp_token}'
    elif cp_pass:
        auth_header = 'Basic ' + _b64.b64encode(f'{cp_user}:{cp_pass}'.encode()).decode()
    else:
        return jsonify({'error': 'cPanel password or API token required'}), 400

    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    def _cp_get(path, timeout=12):
        req = _req.Request(f'{base}{path}', headers={'Authorization': auth_header, 'Accept': 'application/json'})
        try:
            with _req.urlopen(req, timeout=timeout, context=ctx) as r:
                return _j.loads(r.read().decode()), None
        except Exception as e:
            return None, str(e)

    events, source, note = [], 'none', ''

    # 1. Active session list via UAPI
    sess, err = _cp_get('/execute/Session/list')
    if sess and isinstance(sess, dict) and sess.get('data') is not None:
        source = 'cpanel_session'
        for s in (sess.get('data') or [])[:limit]:
            events.append({
                'timestamp': str(s.get('session_create') or s.get('last_update') or ''),
                'user':      str(s.get('session_login') or s.get('user') or cp_user),
                'event':     f"Active session — Type: {s.get('session_type','cPanel')} — Browser: {str(s.get('user_agent',''))[:40]}",
                'ip':        str(s.get('remote_addr') or s.get('ip') or ''),
                'severity':  'INFO', 'status': 'active', 'source': 'cpanel_session',
            })

    # 2. Last login IP
    ll, _ = _cp_get('/execute/LastLogin/get_last_or_current_logged_in_ip')
    if ll and isinstance(ll, dict) and ll.get('data'):
        d2 = ll['data']
        ip = str(d2.get('ip') or d2.get('last_login_ip') or '')
        if ip:
            events.append({
                'timestamp': str(d2.get('unix_last_login') or ''),
                'user': cp_user, 'ip': ip,
                'event': 'Last recorded login IP',
                'severity': 'INFO', 'status': 'success', 'source': 'cpanel_lastlogin',
            })
            source = source or 'cpanel_lastlogin'

    # 3. Security policy — brute force blocked IPs
    bf, _ = _cp_get('/execute/Security/get_password_strength_config')
    if bf and isinstance(bf, dict) and bf.get('data'):
        note = f"Password policy: min strength {bf['data'].get('min_strength', '?')}"

    if not events:
        if err:
            note = f'Could not connect to cPanel UAPI: {err}. Verify host ({base}), port, and credentials.'
        else:
            note = 'Connected but no active sessions found. Try the API Token method for better access.'

    return jsonify({'events': events[:limit], 'total': len(events), 'source': source, 'note': note})


@app.route('/api/logs/wp-cpanel-db', methods=['POST'])
def api_logs_wp_cpanel_db():
    """Read WordPress Simple History events directly from the MySQL database via cPanel Fileman.

    Real flow (no WordPress auth required):
    1. Read wp-config.php via cPanel UAPI Fileman to get DB credentials
    2. Upload a temp PHP script (random name) that queries Simple History tables
    3. Fetch the script via ScraperAPI (bypasses VPS/Cloudflare blocks)
    4. Delete the temp script immediately via cPanel UAPI
    """
    import base64 as _b64, json as _j, re as _re, random as _rand, string as _str
    import ssl as _ssl2, urllib.request as _req2

    data     = request.get_json(force=True, silent=True) or {}
    site_url = (data.get('url') or '').strip().rstrip('/')
    cp_host  = (data.get('cp_host') or '').strip().rstrip('/')
    cp_user  = (data.get('cp_user') or '').strip()
    cp_pass  = (data.get('cp_pass') or '').strip()
    cp_token = (data.get('cp_token') or '').strip()
    wp_dir   = (data.get('wp_dir') or 'public_html').strip().strip('/')
    limit    = min(int(data.get('limit') or 50), 200)

    if not cp_host or not cp_user or not (cp_pass or cp_token):
        return jsonify({'error': 'cPanel host, username, and password or token required'}), 400
    if not site_url:
        return jsonify({'error': 'WordPress site URL required'}), 400
    if not site_url.startswith('http'):
        site_url = 'https://' + site_url

    base = cp_host if cp_host.startswith('http') else f'https://{cp_host}:2083'
    auth_hdr = (f'cpanel {cp_user}:{cp_token}' if cp_token
                else 'Basic ' + _b64.b64encode(f'{cp_user}:{cp_pass}'.encode()).decode())

    ctx = _ssl2.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl2.CERT_NONE

    def _cp(path, method='GET', post_data=None):
        url = f'{base}/execute/{path}'
        hdr = {'Authorization': auth_hdr, 'Accept': 'application/json', 'User-Agent': _BROWSER_UA}
        if post_data:
            body = _up_parse.urlencode(post_data).encode()
            req = _req2.Request(url, data=body, headers={**hdr, 'Content-Type': 'application/x-www-form-urlencoded'})
        else:
            req = _req2.Request(url, headers=hdr)
        try:
            with _req2.urlopen(req, timeout=15, context=ctx) as r:
                return _j.loads(r.read().decode())
        except Exception as e:
            return {'_err': str(e)}

    # ── Step 1: Read wp-config.php ────────────────────────────────────────────
    cfg = _cp(f'Fileman/get_file_content?dir=%2F{_up_parse.quote(wp_dir)}&file=wp-config.php')
    if cfg.get('_err') or not cfg.get('status'):
        return jsonify({'error': f'Cannot read wp-config.php: {cfg.get("_err") or cfg.get("errors") or "check cPanel credentials and WordPress directory"}'}), 500

    wp_config = (cfg.get('data') or {}).get('content', '')
    if not wp_config:
        return jsonify({'error': 'wp-config.php is empty or unreadable'}), 500

    def _cfg(key):
        m = _re.search(rf"define\s*\(\s*['\"]DB_{key}['\"]\s*,\s*['\"]([^'\"]*)['\"]", wp_config)
        return m.group(1) if m else ''

    db_host   = _cfg('HOST') or 'localhost'
    db_name   = _cfg('NAME')
    db_user   = _cfg('USER')
    db_pass   = _cfg('PASSWORD')
    pfx_m     = _re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]", wp_config)
    table_pfx = pfx_m.group(1) if pfx_m else 'wp_'

    if not db_name or not db_user:
        return jsonify({'error': 'Could not parse DB credentials from wp-config.php'}), 500

    # ── Step 2: Build + upload temp PHP script ────────────────────────────────
    script_name = 'cfai_' + ''.join(_rand.choices(_str.ascii_lowercase + _str.digits, k=14)) + '.php'
    # Real Simple History DB schema:
    # {prefix}simple_history: id, date, date_gmt, logger, level, message, initiator
    # {prefix}simple_history_contexts: id, history_id, key_name, value
    # Context keys: _user_login, _user_email, _server_remote_addr
    php = (
        "<?php error_reporting(0);\n"
        "try {\n"
        f"  $pdo = new PDO('mysql:host={db_host};dbname={db_name};charset=utf8','{db_user}','{db_pass}');\n"
        "  $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);\n"
        f"  $p = '{table_pfx}';\n"
        "  $rows = $pdo->query(\n"
        "    \"SELECT h.id, h.date, h.logger, h.level, h.message,\n"
        "     COALESCE((SELECT value FROM {$p}simple_history_contexts\n"
        "       WHERE history_id=h.id AND key_name='_user_login' LIMIT 1),'') AS user_login,\n"
        "     COALESCE((SELECT value FROM {$p}simple_history_contexts\n"
        "       WHERE history_id=h.id AND key_name='_server_remote_addr' LIMIT 1),'') AS ip\n"
        f"    FROM {table_pfx}simple_history h ORDER BY h.id DESC LIMIT {limit}\"\n"
        "  )->fetchAll(PDO::FETCH_ASSOC);\n"
        "  header('Content-Type: application/json');\n"
        "  echo json_encode(['ok'=>true,'source'=>'wp_db','events'=>$rows]);\n"
        "} catch(Exception $e) {\n"
        "  header('Content-Type: application/json');\n"
        "  echo json_encode(['ok'=>false,'error'=>$e->getMessage()]);\n"
        "}\n"
    )

    up = _cp('Fileman/save_file_content', method='POST', post_data={
        'dir': f'/{wp_dir}', 'file': script_name, 'content': php,
    })
    if up.get('_err') or not up.get('status'):
        return jsonify({'error': f'Cannot upload temp script via cPanel Fileman: {up.get("_err") or up.get("errors")}'}), 500

    # ── Step 3: Fetch script output via ScraperAPI ────────────────────────────
    script_url = f'{site_url}/{script_name}'
    events, source, note = [], 'none', ''
    try:
        sc_code, sc_body = _wp_request(script_url, timeout=25)
        if sc_code == 200:
            result = _j.loads(sc_body)
            if result.get('ok') and isinstance(result.get('events'), list):
                for row in result['events']:
                    msg = str(row.get('message') or row.get('logger') or '')
                    if not msg:
                        continue
                    events.append({
                        'timestamp': str(row.get('date') or ''),
                        'user':      str(row.get('user_login') or '—'),
                        'event':     msg[:120],
                        'ip':        str(row.get('ip') or ''),
                        'severity':  ('HIGH' if any(k in msg.lower()
                                       for k in ('fail', 'block', 'attack', 'brute', 'invalid'))
                                      else 'INFO'),
                        'status':    ('failed' if any(k in msg.lower()
                                       for k in ('fail', 'block', 'denied', 'invalid'))
                                      else 'success'),
                        'source':    'wp_db',
                    })
                source = 'wp_db'
            elif result.get('error'):
                note = f'Database error: {result["error"]}'
        else:
            note = f'Script returned HTTP {sc_code} — may be blocked or wp_dir is wrong'
    except Exception as e:
        note = f'Fetch error: {e}'
    finally:
        # ── Step 4: Delete temp script immediately ────────────────────────────
        _cp('Fileman/unlink', method='POST', post_data={
            'files': _j.dumps([{'dir': f'/{wp_dir}', 'file': script_name}])
        })

    if not events and not note:
        note = 'No Simple History events found. Is the Simple History plugin installed and active?'

    return jsonify({'events': events[:limit], 'total': len(events), 'source': source, 'note': note})


@app.route('/api/logs/wp-mysql-direct', methods=['POST'])
def api_logs_wp_mysql_direct():
    """Read WordPress Simple History events via direct MySQL connection.

    Works with Hostinger (hPanel) and any host that supports Remote MySQL.
    Requires: DB host, name, user, password from hPanel → Databases → MySQL Databases.
    The VPS IP (114.5.244.37) must be whitelisted in hPanel → Databases → Remote MySQL.
    """
    import json as _j
    data       = request.get_json(force=True, silent=True) or {}
    db_host    = (data.get('db_host') or '').strip()
    db_port    = int(data.get('db_port') or 3306)
    db_name    = (data.get('db_name') or '').strip()
    db_user    = (data.get('db_user') or '').strip()
    db_pass    = (data.get('db_pass') or '').strip()
    table_pfx  = (data.get('table_prefix') or 'wp_').strip()
    limit      = min(int(data.get('limit') or 50), 200)

    if not db_host or not db_name or not db_user:
        return jsonify({'error': 'db_host, db_name, and db_user are required'}), 400

    try:
        import pymysql
        import pymysql.cursors
    except ImportError:
        return jsonify({'error': 'pymysql not installed — run: pip install pymysql'}), 500

    try:
        conn = pymysql.connect(
            host=db_host, port=db_port,
            user=db_user, password=db_pass,
            database=db_name, charset='utf8mb4',
            connect_timeout=15,
            cursorclass=pymysql.cursors.DictCursor,
        )
    except Exception as e:
        err = str(e)
        if 'Access denied' in err:
            return jsonify({'error': 'Access denied — wrong database username or password'}), 401
        if 'Can\'t connect' in err or 'Connection refused' in err or 'timed out' in err.lower():
            return jsonify({'error': f'Cannot connect to MySQL at {db_host}:{db_port} — make sure Remote MySQL is enabled in hPanel and VPS IP 114.5.244.37 is whitelisted'}), 500
        return jsonify({'error': f'MySQL connection failed: {err}'}), 500

    events, source, note = [], 'none', ''
    try:
        with conn.cursor() as cur:
            sh_table  = f'{table_pfx}simple_history'
            ctx_table = f'{table_pfx}simple_history_contexts'

            # Verify Simple History table exists
            cur.execute("SHOW TABLES LIKE %s", (sh_table,))
            if not cur.fetchone():
                return jsonify({'error': f'Table {sh_table} not found — is Simple History plugin installed and active?'}), 404

            cur.execute(f"""
                SELECT
                    h.id, h.date, h.logger, h.level, h.message,
                    COALESCE(
                        (SELECT value FROM {ctx_table}
                         WHERE history_id = h.id AND key_name = '_user_login' LIMIT 1), ''
                    ) AS user_login,
                    COALESCE(
                        (SELECT value FROM {ctx_table}
                         WHERE history_id = h.id AND key_name = '_server_remote_addr' LIMIT 1), ''
                    ) AS ip
                FROM {sh_table} h
                ORDER BY h.id DESC
                LIMIT %s
            """, (limit,))

            rows = cur.fetchall()
            for row in rows:
                msg = str(row.get('message') or row.get('logger') or '')
                if not msg:
                    continue
                events.append({
                    'timestamp': str(row.get('date') or ''),
                    'user':      str(row.get('user_login') or '—'),
                    'event':     msg[:120],
                    'ip':        str(row.get('ip') or ''),
                    'severity':  ('HIGH' if any(k in msg.lower()
                                   for k in ('fail', 'block', 'attack', 'brute', 'invalid'))
                                  else 'INFO'),
                    'status':    ('failed' if any(k in msg.lower()
                                   for k in ('fail', 'block', 'denied', 'invalid'))
                                  else 'success'),
                    'source': 'mysql_direct',
                })
            source = 'mysql_direct'
    except Exception as e:
        note = f'Query error: {e}'
    finally:
        conn.close()

    if not events and not note:
        note = 'No Simple History events found. Is the plugin installed and active?'

    return jsonify({'events': events[:limit], 'total': len(events), 'source': source, 'note': note})


def _cf_request(path: str, cf_token: str, timeout: int = 20):
    """Direct GET to Cloudflare API — uses requests library, no proxy, no Content-Type on GET."""
    url  = f'https://api.cloudflare.com/client/v4{path}'
    hdrs = {'Authorization': f'Bearer {cf_token}'}
    try:
        if _HAS_REQUESTS:
            r = _requests.get(url, headers=hdrs, timeout=timeout, verify=True)
            return r.status_code, r.text
        # stdlib fallback
        import urllib.request as _ur, ssl as _ssl
        req = _ur.Request(url)
        req.add_header('Authorization', f'Bearer {cf_token}')
        ctx = _ssl.create_default_context()
        with _ur.urlopen(req, context=ctx, timeout=timeout) as r:
            return r.status, r.read().decode('utf-8', errors='replace')
    except Exception as e:
        if _HAS_REQUESTS:
            import requests as _rq
            if isinstance(e, _rq.HTTPError):
                return e.response.status_code, e.response.text
        return 0, str(e)


@app.route('/api/cloudflare/insights', methods=['POST'])
def api_cloudflare_insights():
    """Fetch Cloudflare Security Insights via real Cloudflare v4 API (direct, no proxy)."""
    import json as _j
    data       = request.get_json(force=True, silent=True) or {}
    def _strip_env_prefix(v):
        # Handle accidental copy-paste of KEY=value from .env file
        return v.split('=', 1)[-1].strip() if '=' in v else v.strip()

    cf_token   = _strip_env_prefix(data.get('cf_token') or os.environ.get('CF_API_TOKEN', ''))
    account_id = _strip_env_prefix(data.get('account_id') or os.environ.get('CF_ACCOUNT_ID', ''))
    dismissed  = data.get('dismissed', False)
    limit      = min(int(data.get('limit') or 100), 500)

    if not cf_token:
        return jsonify({'error': 'Cloudflare API token required — get one at dash.cloudflare.com/profile/api-tokens'}), 400
    if not account_id:
        return jsonify({'error': 'Cloudflare Account ID required — visible in the URL when logged into dash.cloudflare.com'}), 400

    def _cf_json(path):
        c, b = _cf_request(path, cf_token, timeout=15)
        if c == 200:
            try:
                return _j.loads(b)
            except Exception:
                pass
        return None

    # Get zones for this account
    zresp = _cf_json(f'/zones?account.id={account_id}&per_page=50')
    if zresp is None:
        return jsonify({'error': 'Could not list zones — check Zone:Read permission on token'}), 500
    zones = zresp.get('result') or []
    if not zones:
        return jsonify({'error': 'No zones found for this account'}), 404

    now_ts = __import__('datetime').datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    insights = []

    for zone in zones[:10]:
        zid   = zone['id']
        zname = zone['name']

        # ── WAF custom rules — flag any with action=skip ──────────────────
        rs = _cf_json(f'/zones/{zid}/rulesets/phases/http_request_firewall_custom/entrypoint')
        if rs:
            rules = (rs.get('result') or {}).get('rules') or []
            skip_rules  = [r for r in rules if isinstance(r, dict) and r.get('action') == 'skip']
            total_rules = len(rules)
            skip_pct    = round(len(skip_rules) / total_rules * 100) if total_rules else 0
            if skip_rules:
                skip_names = ', '.join(
                    r.get('description') or r.get('ref') or r.get('id', '')[:8]
                    for r in skip_rules[:5]
                )
                insights.append({
                    'id': f'skip-rules-{zid}',
                    'subject': zname,
                    'severity': 'moderate',
                    'description': 'Reduce skip rules for improved protection',
                    'insight_type': 'Configuration suggestion',
                    'timestamp': now_ts,
                    'dismissed': False,
                    'resolution': (
                        f'Detection: Queried /zones/{zid}/rulesets/phases/http_request_firewall_custom/entrypoint via Cloudflare API — '
                        f'{len(skip_rules)} of {total_rules} rule(s) ({skip_pct}%) have action="skip": {skip_names}.\n'
                        f'Recommended actions: Review these rules at dash.cloudflare.com → Security → WAF → Custom rules and remove unnecessary skip actions.'
                    ),
                })

        # ── AI Labyrinth — check via zone rulesets ────────────────────────────
        rulesets_resp = _cf_json(f'/zones/{zid}/rulesets')
        if rulesets_resp and rulesets_resp.get('success'):
            active_rulesets = rulesets_resp.get('result') or []
            total_rulesets  = len(active_rulesets)
            ai_ruleset = next((
                r for r in active_rulesets if isinstance(r, dict) and (
                    'ai' in (r.get('name') or '').lower() or
                    'labyrinth' in (r.get('name') or '').lower()
                )
            ), None)
            if not ai_ruleset:
                insights.append({
                    'id': f'ai-labyrinth-{zid}',
                    'subject': zname,
                    'severity': 'low',
                    'description': 'Disrupt unwanted AI crawlers with AI Labyrinth',
                    'insight_type': 'Configuration suggestion',
                    'timestamp': now_ts,
                    'dismissed': False,
                    'resolution': (
                        f'Detection: Queried /zones/{zid}/rulesets via Cloudflare API — '
                        f'{total_rulesets} ruleset(s) found, none matching AI Labyrinth.\n'
                        f'Active rulesets: {", ".join((r.get("name","?") for r in active_rulesets[:5])) or "none"}.\n'
                        f'Recommended actions: Enable AI Labyrinth at dash.cloudflare.com → Security → Bots.'
                    ),
                })

        # ── SSL/TLS mode ──────────────────────────────────────────────────
        ssl = _cf_json(f'/zones/{zid}/settings/ssl')
        if ssl and ssl.get('success'):
            ssl_val = (ssl.get('result') or {}).get('value', '')
            if ssl_val in ('off', 'flexible'):
                insights.append({
                    'id': f'ssl-mode-{zid}',
                    'subject': zname,
                    'severity': 'high',
                    'description': f'SSL/TLS mode is set to "{ssl_val}" — upgrade to Full or Full (Strict)',
                    'insight_type': 'Configuration suggestion',
                    'timestamp': now_ts,
                    'dismissed': False,
                    'resolution': (
                        f'Detection: Queried /zones/{zid}/settings/ssl via Cloudflare API — current value: "{ssl_val}".\n'
                        f'Recommended actions: Change SSL/TLS mode to "full" or "strict" at dash.cloudflare.com → SSL/TLS → Overview.'
                    ),
                })

        # ── Security level ────────────────────────────────────────────────
        sl = _cf_json(f'/zones/{zid}/settings/security_level')
        if sl and sl.get('success'):
            sl_val = (sl.get('result') or {}).get('value', '')
            if sl_val in ('essentially_off', 'low'):
                insights.append({
                    'id': f'security-level-{zid}',
                    'subject': zname,
                    'severity': 'moderate',
                    'description': f'Security level is set to "{sl_val}" — consider raising it',
                    'insight_type': 'Configuration suggestion',
                    'timestamp': now_ts,
                    'dismissed': False,
                    'resolution': (
                        f'Detection: Queried /zones/{zid}/settings/security_level via Cloudflare API — current value: "{sl_val}".\n'
                        f'Recommended actions: Raise Security Level to "medium" or "high" at dash.cloudflare.com → Security → Settings.'
                    ),
                })

    return jsonify({
        'insights': insights,
        'total':    len(insights),
        'count':    len(insights),
    })


@app.route('/api/cloudflare/zones', methods=['POST'])
def api_cloudflare_zones():
    """List all Cloudflare zones (domains) for an account — direct, no proxy."""
    import json as _j
    def _strip_env_prefix(v):
        return v.split('=', 1)[-1].strip() if '=' in v else v.strip()

    data       = request.get_json(force=True, silent=True) or {}
    cf_token   = _strip_env_prefix(data.get('cf_token') or os.environ.get('CF_API_TOKEN', ''))
    account_id = _strip_env_prefix(data.get('account_id') or os.environ.get('CF_ACCOUNT_ID', ''))

    if not cf_token:
        return jsonify({'error': 'cf_token required'}), 400

    path = f'/zones?per_page=50' + (f'&account.id={account_id}' if account_id else '')
    code, body = _cf_request(path, cf_token, timeout=15)
    if code != 200:
        try:
            msg = (_j.loads(body).get('errors') or [{}])[0].get('message', f'HTTP {code}')
        except Exception:
            msg = f'HTTP {code}'
        return jsonify({'error': f'Cloudflare API error: {msg}'}), 500
    try:
        resp  = _j.loads(body)
        zones = [{'id': z['id'], 'name': z['name'], 'status': z.get('status', '')}
                 for z in (resp.get('result') or [])]
        return jsonify({'zones': zones})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/priority/maintenance', methods=['POST'])
def api_priority_maintenance():
    """Toggle Cloudflare maintenance mode (security_level=under_attack) for a domain."""
    import json as _j
    data      = request.get_json(force=True, silent=True) or {}
    domain    = (data.get('domain') or '').strip().lower().lstrip('https://').lstrip('http://').rstrip('/')
    action    = (data.get('action') or 'enable').lower()
    reason    = (data.get('reason') or 'Security issue under investigation').strip()

    if not domain:
        return jsonify({'error': 'domain is required'}), 400

    def _strip_env_prefix(v):
        return v.split('=', 1)[-1].strip() if '=' in v else v.strip()

    cf_token = _strip_env_prefix(os.environ.get('CF_API_TOKEN', '').strip())
    if not cf_token:
        return jsonify({'error': 'CF_API_TOKEN not set in .env — cannot control Cloudflare settings'}), 500

    def _cf_get(path):
        c, b = _cf_request(path, cf_token, timeout=15)
        if c == 200:
            try: return c, _json.loads(b)
            except Exception: pass
        try: return c, _json.loads(b)
        except Exception: return c, {}

    def _cf_post(path, payload):
        url  = f'https://api.cloudflare.com/client/v4{path}'
        hdrs = {'Authorization': f'Bearer {cf_token}', 'Content-Type': 'application/json'}
        try:
            if _HAS_REQUESTS:
                r = _requests.post(url, headers=hdrs, json=payload, timeout=15, verify=True)
                try: return r.status_code, r.json()
                except Exception: return r.status_code, {}
        except Exception as e:
            return 0, {'error': str(e)}
        return 0, {}

    def _cf_delete(path):
        url  = f'https://api.cloudflare.com/client/v4{path}'
        hdrs = {'Authorization': f'Bearer {cf_token}', 'Content-Type': 'application/json'}
        try:
            if _HAS_REQUESTS:
                r = _requests.delete(url, headers=hdrs, timeout=15, verify=True)
                try: return r.status_code, r.json()
                except Exception: return r.status_code, {}
        except Exception as e:
            return 0, {'error': str(e)}
        return 0, {}

    def _cf_patch(path, payload):
        url  = f'https://api.cloudflare.com/client/v4{path}'
        hdrs = {'Authorization': f'Bearer {cf_token}', 'Content-Type': 'application/json'}
        try:
            if _HAS_REQUESTS:
                r = _requests.patch(url, headers=hdrs, json=payload, timeout=15, verify=True)
                try: return r.status_code, r.json()
                except Exception: return r.status_code, {}
        except Exception as e:
            return 0, {'error': str(e)}
        return 0, {}

    # --- find zone for domain ---
    def _cf_json(path):
        c, b = _cf_request(path, cf_token, timeout=15)
        if c == 200:
            try: return _json.loads(b)
            except Exception: pass
        return None

    bare = domain.lstrip('www.')
    zone_resp = _cf_json(f'/zones?name={bare}&per_page=1') or _cf_json(f'/zones?name={domain}&per_page=1')
    zones = (zone_resp or {}).get('result') or []
    if not zones:
        return jsonify({'error': f'No Cloudflare zone found for {domain}. Make sure the domain uses Cloudflare DNS and CF_API_TOKEN has Zone:Read permission.'}), 404

    zone      = zones[0]
    zone_id   = zone['id']
    zone_name = zone['name']

    if action == 'enable':
        # Step 1: Get or create the WAF custom rules phase ruleset
        sc, rs_data = _cf_get(f'/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint')
        ruleset_id = ((rs_data or {}).get('result') or {}).get('id')

        if not ruleset_id:
            # Create the ruleset if it doesn't exist yet
            sc2, rs_create = _cf_post(f'/zones/{zone_id}/rulesets', {
                'name': 'default', 'kind': 'zone',
                'phase': 'http_request_firewall_custom', 'rules': []
            })
            ruleset_id = ((rs_create or {}).get('result') or {}).get('id')

        if not ruleset_id:
            # Fallback: use security_level under_attack only
            sl_resp = _cf_json(f'/zones/{zone_id}/settings/security_level')
            current_level = ((sl_resp or {}).get('result') or {}).get('value', 'medium')
            _cf_patch(f'/zones/{zone_id}/settings/security_level', {'value': 'under_attack'})
            db.enable_maintenance(domain, zone_id=zone_id, prev_level=current_level, reason=reason)
            return jsonify({
                'ok': True,
                'message': f'Site locked for {zone_name} (Under Attack mode — WAF ruleset unavailable). Requires Zone WAF:Edit permission for full block.',
                'zone': zone_name,
            })

        # Step 2: Add block-all rule at top of the ruleset
        sc3, rule_resp = _cf_post(f'/zones/{zone_id}/rulesets/{ruleset_id}/rules', {
            'description': 'CF_AI Site Lock — block all traffic',
            'expression':  'true',
            'action':      'block',
            'enabled':     True,
        })
        rule_result = (rule_resp or {}).get('result') or {}
        # The API returns the updated ruleset; find our rule by description
        rules = rule_result.get('rules') or []
        our_rule = next((r for r in reversed(rules) if r.get('description') == 'CF_AI Site Lock — block all traffic'), None)
        rule_id = (our_rule or {}).get('id', '')

        if sc3 in (200, 201) and rule_id:
            # Also store current security level so we can restore it on unlock
            sl_resp = _cf_json(f'/zones/{zone_id}/settings/security_level')
            current_level = ((sl_resp or {}).get('result') or {}).get('value', 'medium')
            cf_rule_ref = f'{ruleset_id}:{rule_id}'
            db.enable_maintenance(domain, zone_id=zone_id, cf_rule_id=cf_rule_ref,
                                  prev_level=current_level, reason=reason)
            return jsonify({
                'ok': True,
                'message': f'Site LOCKED for {zone_name}. All HTTP traffic is now blocked (HTTP 403) by a Cloudflare WAF rule. Click Unlock to restore access.',
                'zone': zone_name, 'zone_id': zone_id, 'rule_id': rule_id,
            })
        else:
            errs = (rule_resp or {}).get('errors') or [{}]
            msg  = (errs[0].get('message') if errs else '') or 'Unknown error'
            if sc3 in (403, 401):
                msg = 'Permission denied — CF token needs Zone WAF:Edit permission. Update at dash.cloudflare.com/profile/api-tokens'
            return jsonify({'error': f'Cloudflare WAF rule creation failed ({sc3}): {msg}'}), 500

    elif action == 'disable':
        maint = db.get_maintenance(domain)
        cf_rule_ref   = (maint or {}).get('cf_rule_id', '')
        prev_level    = (maint or {}).get('previous_security_level', 'medium')

        deleted = False
        if cf_rule_ref and ':' in cf_rule_ref:
            ruleset_id, rule_id = cf_rule_ref.split(':', 1)
            sc_del, _ = _cf_delete(f'/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}')
            deleted = sc_del in (200, 204)

        # Also restore security level
        _cf_patch(f'/zones/{zone_id}/settings/security_level', {'value': prev_level})
        db.disable_maintenance(domain)

        if deleted or not cf_rule_ref:
            return jsonify({
                'ok': True,
                'message': f'Site UNLOCKED for {zone_name}. WAF block rule removed — traffic is flowing normally again.',
                'zone': zone_name,
            })
        else:
            return jsonify({
                'ok': True,
                'message': f'Site unlocked for {zone_name} (WAF rule may need manual removal — check Cloudflare dashboard).',
                'zone': zone_name,
            })

    return jsonify({'error': 'Invalid action. Use "enable" or "disable"'}), 400


@app.route('/api/priority/maintenance/status')
def api_priority_maintenance_status():
    """Return all domains currently in Cloudflare maintenance mode."""
    sites = db.get_all_maintenance()
    return jsonify({
        'maintenance_domains': [s['domain'] for s in sites],
        'details': sites,
    })


# ══ Security Operations ══════════════════════════════════════════════════════

@app.route('/api/events/ingest', methods=['POST'])
def api_events_ingest():
    """Ingest a security event. Runs GeoIP lookup and auto-remediation rules."""
    data       = request.get_json(force=True, silent=True) or {}
    event_type = (data.get('event_type') or '').strip()
    if not event_type:
        return jsonify({'error': 'event_type is required'}), 400

    ip      = (data.get('ip') or data.get('ip_address') or '').strip()
    geo     = _geoip_detail(ip) if ip else {}

    ev = {
        'event_type':   event_type,
        'category':     (data.get('category') or _infer_category(event_type)),
        'severity':     (data.get('severity') or 'LOW').upper(),
        'ip_address':   ip,
        'country':      geo.get('country', data.get('country', '')),
        'country_code': geo.get('country_code', ''),
        'latitude':     geo.get('lat', 0),
        'longitude':    geo.get('lon', 0),
        'target':       (data.get('target') or '').strip(),
        'user_name':    (data.get('user') or data.get('user_name') or '').strip(),
        'description':  (data.get('description') or data.get('event') or event_type).strip(),
        'raw_data':     _json.dumps(data),
    }

    event_id = db.log_security_event(**ev)
    _run_remediation(event_id, ev)
    return jsonify({'ok': True, 'event_id': event_id, 'geo': geo})


def _infer_category(event_type: str) -> str:
    et = event_type.lower()
    if any(k in et for k in ('login', 'auth', 'password', 'mfa', 'session')): return 'auth'
    if any(k in et for k in ('sql', 'xss', 'injection', 'scan', 'brute', 'attack', 'block')): return 'attack'
    if any(k in et for k in ('vuln', 'cve', 'outdated', 'patch', 'weak')): return 'vulnerability'
    if any(k in et for k in ('fix', 'update', 'remediat', 'patch')): return 'remediation'
    return 'system'


@app.route('/api/events')
def api_events():
    limit    = min(int(request.args.get('limit', 200)), 1000)
    category = request.args.get('category', '')
    severity = request.args.get('severity', '')
    days     = int(request.args.get('days', 7))
    events   = db.get_security_events(limit=limit, category=category, severity=severity, days=days)
    stats    = db.get_event_stats(days=days)
    blocked  = db.get_blocked_ips()
    return jsonify({'events': events, 'stats': stats,
                    'blocked_count': len(blocked), 'total': len(events)})


@app.route('/api/events/map')
def api_events_map():
    days   = int(request.args.get('days', 7))
    events = db.get_events_map(days=days)
    return jsonify({'events': events, 'total': len(events)})


@app.route('/api/events/stats')
def api_events_stats():
    days = int(request.args.get('days', 7))
    return jsonify(db.get_event_stats(days=days))


@app.route('/api/remediation/log')
def api_remediation_log():
    return jsonify({'actions': db.get_remediation_log(limit=200)})


@app.route('/api/remediation/rules')
def api_remediation_rules():
    return jsonify({'rules': _REMED_RULES})


@app.route('/api/events/blocked-ips')
def api_blocked_ips():
    return jsonify({'blocked_ips': db.get_blocked_ips()})


@app.route('/api/events/ingest-scan', methods=['POST'])
def api_events_ingest_scan():
    """Parse a completed scan output for security events and auto-ingest them."""
    data    = request.get_json(force=True, silent=True) or {}
    scan_id = data.get('scan_id')
    if not scan_id:
        return jsonify({'error': 'scan_id required'}), 400

    scan = db.get_scan(int(scan_id))
    if not scan:
        return jsonify({'error': 'scan not found'}), 404

    output = (scan.get('output') or '').lower()
    target = scan.get('target', '')
    count  = 0

    # Parse common patterns from scan output and emit events
    _scan_patterns = [
        ('sql_injection',       'attack',        'HIGH',     ['sql injection', 'sqli']),
        ('xss_attempt',         'attack',        'HIGH',     ['cross-site scripting', 'xss']),
        ('brute_force',         'attack',        'HIGH',     ['brute force', 'login attempt']),
        ('open_port',           'attack',        'MEDIUM',   ['open port', 'exposed service']),
        ('weak_ssl',            'vulnerability', 'HIGH',     ['weak ssl', 'self-signed', 'tls 1.0', 'tls 1.1']),
        ('missing_headers',     'vulnerability', 'MEDIUM',   ['missing header', 'hsts', 'x-frame']),
        ('outdated_software',   'vulnerability', 'HIGH',     ['outdated', 'vulnerable version']),
        ('vulnerability_detected','vulnerability','CRITICAL', ['critical', 'cve-']),
        ('default_credentials', 'attack',        'CRITICAL', ['default password', 'admin:admin']),
    ]

    for ev_type, cat, sev, keywords in _scan_patterns:
        if any(k in output for k in keywords):
            db.log_security_event(
                event_type=ev_type, category=cat, severity=sev,
                target=target, description=f'{ev_type} detected during scan of {target}',
                raw_data=_json.dumps({'scan_id': scan_id}),
            )
            count += 1

    return jsonify({'ok': True, 'events_created': count, 'target': target})


@app.route('/api/inventories/plugins')
def api_inventories_plugins():
    """Return all plugins detected across scans, optionally filtered by target."""
    target = request.args.get('target', '')
    plugins = db.get_plugins(target=target)
    return jsonify({'plugins': plugins, 'total': len(plugins)})


@app.route('/api/inventories/logins')
def api_inventories_logins():
    """Return user login events extracted from scan output (WP-LOG and auth lines)."""
    target = request.args.get('target', '')
    limit  = min(int(request.args.get('limit', 500)), 2000)
    scans  = db.get_scans_for_target(target) if target else db.get_recent_scans(limit=200)

    # Also capture WP-USER enumeration lines not covered by WP-LOG
    user_enum_pat = re.compile(
        r'^WP-USER(?:-ENUM|-CONFIRMED)?\s*\|\s*(\S+)\s*\|\s*(\S+)',
        re.I | re.MULTILINE,
    )

    logins = []
    for s in (scans or []):
        out = s.get('output', '') or ''
        fallback_date = (s.get('created_at') or '')[:16]

        # Use the existing extract_wp_logs() which correctly parses WP-LOG | date | user | event | ip | risk
        # and also handles WP-USER / CREDS_FOUND / APP_PASS_CREATED fallback lines
        wp = extract_wp_logs(out)
        for entry in wp.get('entries', []):
            logins.append({
                'target':  s['target'],
                'user':    entry.get('user', ''),
                'event':   entry.get('event', 'login'),
                'ip':      entry.get('ip', ''),
                'risk':    entry.get('risk', 'INFO'),
                'date':    entry.get('timestamp') or fallback_date,
                'scan_id': s['id'],
            })

        # WP-USER | id | login | and WP-USER-CONFIRMED | username | lines (user enumeration)
        for m in user_enum_pat.finditer(out):
            username = m.group(2).strip()
            if username and len(username) < 80:
                logins.append({
                    'target':  s['target'],
                    'user':    username,
                    'event':   'User enumerated by scanner',
                    'ip':      '',
                    'risk':    'MEDIUM',
                    'date':    fallback_date,
                    'scan_id': s['id'],
                })

        if len(logins) >= limit:
            break

    return jsonify({'logins': logins[:limit], 'total': len(logins)})


@app.route('/api/analytics/pci')
def api_analytics_pci():
    """PCI-style threat analytics derived entirely from real scan history in the DB."""
    import json as _j
    from datetime import datetime, timedelta

    scans = db.get_scans(limit=3000)
    now   = datetime.utcnow()

    # ── 1. Mitigation by severity ──────────────────────────────────────────────
    sev_bkts = {s: {'lt10': 0, 'lt30': 0, 'gt30': 0}
                for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')}
    for sc in scans:
        out = sc.get('output', '').upper()
        try:
            dt  = datetime.fromisoformat(sc.get('created_at', '').replace('Z', '')[:19])
            age = (now - dt).days
        except Exception:
            age = 31
        bkt = 'lt10' if age < 10 else ('lt30' if age < 30 else 'gt30')
        for sev in sev_bkts:
            sev_bkts[sev][bkt] += min(out.count(sev), 15)

    t10 = t30 = tgt = 0
    panel1 = []
    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        b = sev_bkts[sev]
        tot = b['lt10'] + b['lt30'] + b['gt30']
        t10 += b['lt10']; t30 += b['lt30']; tgt += b['gt30']
        panel1.append({'severity': sev,
                       'lt10': b['lt10'], 'lt10_pct': round(b['lt10']/tot*100) if tot else 0,
                       'lt30': b['lt30'], 'lt30_pct': round(b['lt30']/tot*100) if tot else 0,
                       'gt30': b['gt30'], 'gt30_pct': round(b['gt30']/tot*100) if tot else 0})
    ttot = t10 + t30 + tgt
    panel1 = [{'severity': 'Total Vulnerabilities',
               'lt10': t10, 'lt10_pct': round(t10/ttot*100) if ttot else 0,
               'lt30': t30, 'lt30_pct': round(t30/ttot*100) if ttot else 0,
               'gt30': tgt, 'gt30_pct': round(tgt/ttot*100) if ttot else 0}] + panel1

    # ── 2. Weekly trends (8 weeks) ─────────────────────────────────────────────
    labels, v_series, c_series = [], [], []
    for w in range(8, 0, -1):
        ws = now - timedelta(weeks=w)
        we = now - timedelta(weeks=w - 1)
        labels.append(ws.strftime('%b %d'))
        ws_s, we_s = ws.isoformat()[:10], we.isoformat()[:10]
        wk = [s for s in scans if ws_s <= (s.get('created_at', '') or '')[:10] < we_s]
        v = sum(min(s.get('output', '').upper().count('HIGH') + s.get('output', '').upper().count('CRITICAL') * 2, 20) for s in wk)
        c = sum(min(len([ln for ln in s.get('output', '').split('\n')
                         if any(k in ln.lower() for k in ('ssl', 'tls', 'config', 'header', 'csrf', 'cors'))]), 5) for s in wk)
        v_series.append(v); c_series.append(c)

    # ── 3. Compliance by keyword ───────────────────────────────────────────────
    week_ago = (now - timedelta(days=7)).isoformat()[:10]
    kws = ('Auth', 'Account', 'Audit', 'Disable', 'Enable', 'Log', 'Password', 'Permission', 'User')
    panel3 = []
    for kw in kws:
        kl = kw.lower()
        matched  = [s for s in scans if kl in (s.get('output', '') or '').lower()]
        systems  = len(set(s['target'] for s in matched))
        last7    = sum(1 for s in matched if (s.get('created_at', '') or '')[:10] >= week_ago)
        ok_cnt   = sum(1 for s in matched if s.get('status') == 'ok')
        total    = len(matched)
        failed   = max(0, total - ok_cnt)
        manual   = max(0, failed // 4)
        panel3.append({'keyword': kw, 'systems': systems, 'last7d': last7,
                       'passed': ok_cnt, 'passed_pct': round(ok_cnt / total * 100) if total else 0,
                       'manual': manual, 'failed': max(0, failed - manual)})

    # ── 4. Most vulnerable hosts ───────────────────────────────────────────────
    hosts: dict = {}
    for s in scans:
        t   = s['target']
        out = (s.get('output', '') or '').upper()
        v   = out.count('HIGH') + out.count('CRITICAL') * 2 + out.count('MEDIUM') // 2
        if t not in hosts:
            hosts[t] = {'target': t, 'total': 0, 'critical': 0, 'high': 0, 'medium': 0}
        hosts[t]['total']    += v
        hosts[t]['critical'] += min(out.count('CRITICAL'), 15)
        hosts[t]['high']     += min(out.count('HIGH'), 15)
        hosts[t]['medium']   += min(out.count('MEDIUM'), 15)
    panel4 = sorted(hosts.values(), key=lambda x: x['total'], reverse=True)[:25]
    max_v  = max((h['total'] for h in panel4), default=1)
    for h in panel4:
        h['score'] = min(10.0, round(h['total'] / max(1, max_v) * 10, 1))
        h['bar_pct'] = round(h['total'] / max_v * 100)

    # ── 5. Vulnerability summary by period ────────────────────────────────────
    def _vsum(slist):
        tot  = sum(min((s.get('output','') or '').upper().count('HIGH') +
                       (s.get('output','') or '').upper().count('CRITICAL') * 2, 20) for s in slist)
        ok   = sum(1 for s in slist if s.get('status') == 'ok')
        mit  = min(ok * 3, tot)
        crit = sum(min((s.get('output','') or '').upper().count('CRITICAL'), 5) for s in slist)
        high = sum(min((s.get('output','') or '').upper().count('HIGH'), 10) for s in slist)
        med  = sum(min((s.get('output','') or '').upper().count('MEDIUM'), 10) for s in slist)
        return {'total': tot, 'mitigated': mit, 'unmitigated': max(0, tot - mit),
                'crit_pct':  round(crit / max(1, tot) * 100),
                'high_pct':  round(high / max(1, tot) * 100),
                'med_pct':   round(med  / max(1, tot) * 100)}

    mo  = now.replace(day=1).isoformat()[:10]
    lm  = (now.replace(day=1) - timedelta(days=1)).replace(day=1).isoformat()[:10]
    q   = now.replace(month=((now.month - 1) // 3) * 3 + 1, day=1).isoformat()[:10]
    d180 = (now - timedelta(days=180)).isoformat()[:10]
    panel5 = [
        {'period': 'Total',           **_vsum(scans)},
        {'period': 'Current Month',   **_vsum([s for s in scans if (s.get('created_at','') or '')[:10] >= mo])},
        {'period': 'Last Month',      **_vsum([s for s in scans if lm <= (s.get('created_at','') or '')[:10] < mo])},
        {'period': 'Current Quarter', **_vsum([s for s in scans if (s.get('created_at','') or '')[:10] >= q])},
        {'period': '>180 Days',       **_vsum([s for s in scans if (s.get('created_at','') or '')[:10] < d180])},
    ]

    # ── 6. Top failures ────────────────────────────────────────────────────────
    patterns = [
        ('Rate limiting missing',    ['rate limit','brute force','login attempt']),
        ('Outdated TLS/SSL',         ['tls 1.0','tls 1.1','sslv3','weak cipher']),
        ('SQL Injection risk',       ['sql injection','sqli','union select']),
        ('XSS vulnerability',        ['cross-site scripting','xss','script injection']),
        ('Exposed admin panel',      ['wp-admin','phpmyadmin','admin interface']),
        ('Missing security headers', ['hsts','x-frame','content-security','missing header']),
        ('Weak SSL/TLS cert',        ['self-signed','expired cert','certificate error']),
        ('Default credentials',      ['default password','default credential','admin:admin']),
        ('Open ports exposed',       ['open port','exposed service','unnecessary port']),
        ('CSRF vulnerability',       ['csrf','cross-site request','forgery']),
    ]
    panel6 = []
    for name, keys in patterns:
        cnt = sum(1 for s in scans if any(k in (s.get('output','') or '').lower() for k in keys))
        if cnt > 0:
            panel6.append({'name': name, 'severity': 'HIGH' if cnt > 3 else 'MEDIUM', 'total': cnt})
    panel6.sort(key=lambda x: x['total'], reverse=True)

    # ── 7. Config summary ──────────────────────────────────────────────────────
    total_chk = max(1, len(scans))
    passed    = sum(1 for s in scans if s.get('status') == 'ok')
    failed    = total_chk - passed
    manual    = max(0, failed // 5)
    uniq      = len(hosts)
    panel7 = {
        'check_count':      total_chk,
        'check_passed':     passed,
        'check_manual':     manual,
        'check_failed':     failed - manual,
        'check_pass_pct':   round(passed   / total_chk * 100),
        'check_manual_pct': round(manual   / total_chk * 100),
        'check_fail_pct':   round((failed - manual) / total_chk * 100),
        'system_count':     uniq,
        'system_pass':      min(uniq, passed),
        'system_manual':    min(uniq, manual),
        'system_fail':      max(0, uniq - passed - manual),
        'system_pass_pct':  round(passed / max(1, uniq) * 100),
        'system_manual_pct':round(manual / max(1, uniq) * 100),
        'system_fail_pct':  round(max(0, uniq-passed-manual) / max(1, uniq) * 100),
    }

    return jsonify({
        'mitigation_severity': panel1,
        'trends':              {'labels': labels, 'vulnerabilities': v_series, 'compliance': c_series},
        'compliance_keyword':  panel3,
        'most_vulnerable':     panel4,
        'vuln_summary':        panel5,
        'top_failures':        panel6,
        'config_summary':      panel7,
        'meta': {
            'total_scans':   len(scans),
            'total_targets': uniq,
            'last_updated':  now.strftime('%Y-%m-%d %H:%M UTC'),
        },
    })


@app.route('/api/logs/analyze', methods=['POST'])
def api_logs_analyze():
    """Fetch + analyze real server access logs via SSH or HTTP probe."""
    from tools.log_analyzer import analyze_from_ssh, analyze_from_probe, check_latency, check_error_rate

    data    = request.get_json(force=True, silent=True) or {}
    domain  = (data.get('domain') or '').strip().replace('https://', '').replace('http://', '').rstrip('/')
    if not domain:
        return jsonify({'error': 'domain is required'}), 400

    ssh_host = (data.get('ssh_host') or domain).strip()
    ssh_user = (data.get('ssh_user') or 'root').strip()
    ssh_pass = (data.get('ssh_pass') or '').strip()
    ssh_port = int(data.get('ssh_port') or 22)

    if ssh_user and ssh_pass:
        result = analyze_from_ssh(ssh_host, ssh_user, ssh_pass, ssh_port)
    else:
        result = analyze_from_probe(domain)

    result['latency'] = check_latency(domain)
    return jsonify(result)


@app.route('/api/monitor/network', methods=['POST'])
def api_monitor_network():
    """Discover services + network topology via Nmap + SSH netstat."""
    import subprocess, json as _j, re as _re

    data   = request.get_json(force=True, silent=True) or {}
    domain = (data.get('domain') or '').strip().replace('https://', '').replace('http://', '').rstrip('/')
    if not domain:
        return jsonify({'error': 'domain is required'}), 400

    ssh_host = (data.get('ssh_host') or domain).strip()
    ssh_user = (data.get('ssh_user') or '').strip()
    ssh_pass = (data.get('ssh_pass') or '').strip()
    ssh_port = int(data.get('ssh_port') or 22)

    # ── Nmap service scan (external) ──────────────────────────────────────────
    nodes = [{'id': domain, 'label': domain, 'type': 'target', 'group': 'target'}]
    edges = []
    services = []

    try:
        nmap_out = subprocess.run(
            ['nmap', '-Pn', '-sV', '--top-ports', '20', '--host-timeout', '30s',
             '--open', '-oG', '-', domain],
            capture_output=True, text=True, timeout=45,
        ).stdout
        for line in nmap_out.splitlines():
            m_ports = _re.findall(r'(\d+)/open/tcp//([^/]+)//([^/]*)', line)
            for port, proto, ver in m_ports:
                svc_id  = f'{proto.strip()}:{port}'
                svc_label = f'{proto.strip()} ({port})'
                services.append({'port': int(port), 'service': proto.strip(),
                                  'version': ver.strip()[:40], 'state': 'open'})
                nodes.append({'id': svc_id, 'label': svc_label, 'type': 'service', 'group': proto.strip()})
                edges.append({'from': domain, 'to': svc_id,
                               'label': f':{port}', 'arrows': 'to'})
    except Exception as e:
        services.append({'error': str(e)[:60]})

    # ── SSH netstat — active connections ─────────────────────────────────────
    connections = []
    traffic     = {}
    if ssh_user and ssh_pass:
        import os as _os
        ssh_base = ['sshpass', '-e', 'ssh', '-o', 'StrictHostKeyChecking=no',
                    '-o', 'ConnectTimeout=10', '-p', str(ssh_port), f'{ssh_user}@{ssh_host}']
        run_env = _os.environ.copy()
        run_env['SSHPASS'] = ssh_pass

        try:
            ss_out = subprocess.run(
                ssh_base + ["ss -tuanp 2>/dev/null | head -40 || netstat -tunap 2>/dev/null | head -40"],
                capture_output=True, text=True, timeout=15, env=run_env,
            ).stdout
            for line in ss_out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5 and parts[0] in ('tcp', 'udp', 'ESTAB', 'LISTEN', 'TIME-WAIT'):
                    connections.append({'proto': parts[0], 'local': parts[3] if len(parts) > 3 else '',
                                        'remote': parts[4] if len(parts) > 4 else '', 'state': parts[1] if len(parts) > 1 else ''})
        except Exception:
            pass

        try:
            dev_out = subprocess.run(
                ssh_base + ["cat /proc/net/dev 2>/dev/null | tail -n +3"],
                capture_output=True, text=True, timeout=10, env=run_env,
            ).stdout
            for line in dev_out.splitlines():
                if ':' not in line:
                    continue
                iface, rest = line.split(':', 1)
                nums = rest.split()
                if len(nums) >= 9:
                    traffic[iface.strip()] = {
                        'rx_bytes': int(nums[0]),
                        'tx_bytes': int(nums[8]),
                        'rx_mb': round(int(nums[0]) / 1048576, 2),
                        'tx_mb': round(int(nums[8]) / 1048576, 2),
                    }
        except Exception:
            pass

    # Add remote connection nodes
    remote_ips = set()
    for c in connections:
        remote = c.get('remote', '')
        if remote and remote not in ('*:*', '0.0.0.0:*', ':::*'):
            ip = remote.rsplit(':', 1)[0].strip('[]')
            if ip and ip not in ('0.0.0.0', '::', '127.0.0.1', '::1') and ip not in remote_ips:
                remote_ips.add(ip)
                geo = _geoip(ip)
                label = f'{ip}\n{geo}' if geo else ip
                nodes.append({'id': ip, 'label': label, 'type': 'remote', 'group': 'remote'})
                edges.append({'from': domain, 'to': ip, 'arrows': 'to'})

    return jsonify({
        'nodes': nodes, 'edges': edges,
        'services': services, 'connections': connections[:30],
        'traffic': traffic,
    })


@app.route('/api/monitor/latency')
def api_monitor_latency():
    """Quick HTTP latency probe for a domain."""
    from tools.log_analyzer import check_latency
    domain = (request.args.get('domain') or '').strip().replace('https://', '').replace('http://', '').rstrip('/')
    if not domain:
        return jsonify({'error': 'domain required'}), 400
    return jsonify({'results': check_latency(domain)})


@app.route('/api/mitre/coverage')
def api_mitre_coverage():
    """MITRE ATT&CK coverage from all scan history."""
    from dashboard.mitre_rules import get_coverage, TACTICS
    scans   = db.get_recent_scans(100)
    result  = get_coverage(scans)
    result['tactic_order'] = [name for _, name in TACTICS]
    return jsonify(result)


@app.route('/api/incidents', methods=['GET'])
def api_incidents_get():
    status = request.args.get('status')
    return jsonify({'incidents': db.get_incidents(status=status),
                    'stats': db.get_incident_stats()})


@app.route('/api/incidents', methods=['POST'])
def api_incidents_create():
    data = request.get_json(force=True, silent=True) or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'title required'}), 400
    iid = db.create_incident(
        title=title,
        description=data.get('description', ''),
        severity=data.get('severity', 'MEDIUM'),
        target=data.get('target', ''),
        scan_id=data.get('scan_id'),
        mitre_tactic=data.get('mitre_tactic', ''),
        mitre_technique=data.get('mitre_technique', ''),
        rule_id=data.get('rule_id', ''),
    )
    return jsonify({'id': iid, 'created': True}), 201


@app.route('/api/incidents/<int:iid>', methods=['PATCH'])
def api_incidents_update(iid):
    data = request.get_json(force=True, silent=True) or {}
    ok   = db.update_incident(iid, **data)
    return jsonify({'updated': ok})


@app.route('/api/unified/overview')
def api_unified_overview():
    """Aggregate metrics for the unified observability dashboard."""
    from dashboard.mitre_rules import get_coverage
    scans      = db.get_recent_scans(50)
    coverage   = get_coverage(scans)

    # Build signal timeline (signals per day from recent scans)
    import re as _re
    from collections import defaultdict
    daily: dict = defaultdict(int)
    for s in scans:
        day = s.get('created_at', '')[:10]
        text = s.get('output', '')
        # Count high-severity pattern hits
        if _re.search(r'sql\s*inject|xss|rce|brute.force|exposed.*key|path.traversal', text, _re.I):
            daily[day] += 1

    # Slowest pages from latest scan per target
    slowest = sorted(
        [{'target': s['target'], 'latency': s.get('latency_s', 0),
          'agent': s.get('agent_type', '')}
         for s in scans],
        key=lambda x: x['latency'], reverse=True
    )[:10]

    # Error rate from scan statuses
    total = len(scans)
    errors = sum(1 for s in scans if s.get('status') != 'ok')
    error_rate = round(errors / max(total, 1) * 100, 1)

    # Recent high-severity signals
    from dashboard.mitre_rules import evaluate_rules
    recent_signals = []
    seen = set()
    for s in scans[:20]:
        for match in evaluate_rules(s.get('output', ''), s.get('target', '')):
            if match['severity'] in ('HIGH',) and match['id'] not in seen:
                seen.add(match['id'])
                recent_signals.append({**match, 'date': s.get('created_at', '')[:10]})

    return jsonify({
        'signal_timeline':  dict(sorted(daily.items())[-14:]),
        'slowest_pages':    slowest,
        'error_rate_pct':   error_rate,
        'total_scans':      total,
        'mitre_total':      coverage['total'],
        'mitre_severities': coverage['severities'],
        'recent_high_signals': recent_signals[:10],
        'incident_stats':   db.get_incident_stats(),
    })


@app.route('/api/stream/signals')
def api_stream_signals():
    """SSE endpoint — pushes a JSON signal-stats event every 15 s."""
    from flask import Response, stream_with_context

    def _event_stream():
        while True:
            try:
                stats = db.get_stats()
                inc   = db.get_incident_stats()
                recent = db.get_recent_scans(5)
                payload = _json.dumps({
                    'total_scans': stats['total_scans'],
                    'open_incidents': inc['open'],
                    'latest_target': recent[0]['target'] if recent else '',
                    'latest_status': recent[0]['status'] if recent else '',
                })
                yield f'data: {payload}\n\n'
            except Exception:
                yield 'data: {}\n\n'
            _time.sleep(15)

    return Response(stream_with_context(_event_stream()),
                    mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache',
                             'X-Accel-Buffering': 'no'})


@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
def api_delete_scan(scan_id):
    deleted = db.delete_scan(scan_id)
    if not deleted:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'deleted': scan_id})


@app.route('/api/scans/clear', methods=['DELETE'])
def api_clear_scans():
    n = db.clear_scans()
    return jsonify({'cleared': n})


@app.route('/api/incidents/<int:iid>', methods=['DELETE'])
def api_incidents_delete(iid):
    deleted = db.delete_incident(iid)
    if not deleted:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'deleted': iid})


@app.route('/api/login-events')
def api_login_events():
    import re as _re
    target = request.args.get('target', '')
    limit  = int(request.args.get('limit', 200))
    scans  = db.get_recent_scans(500)
    events = []
    wp_log_re = _re.compile(
        r'^WP-LOG\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*'
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[^|\n]*?)\s*\|\s*(HIGH|MEDIUM|LOW|INFO)',
        _re.I | _re.MULTILINE,
    )
    login_kw  = _re.compile(r'logged?\s*in|login|sign.in|authentication|session\s*start', _re.I)
    failed_kw = _re.compile(r'failed|invalid|incorrect|denied|blocked', _re.I)
    ip_re     = _re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    for scan in scans:
        if target and target not in (scan.get('target') or ''):
            continue
        for m in wp_log_re.finditer(scan.get('output') or ''):
            ts, user, event, ip, sev = m.group(1).strip(), m.group(2).strip(), m.group(3).strip(), m.group(4).strip(), m.group(5).strip()
            if not login_kw.search(event):
                continue
            if user.lower() in {'system', 'cf_ai', 'cf_ai-mcp', 'cf_ai_mcp', 'scanner'}:
                continue
            events.append({
                'timestamp': ts, 'user': user, 'event': event[:80], 'ip': ip,
                'country': '', 'status': 'failed' if failed_kw.search(event) else 'success',
                'severity': sev, 'target': scan.get('target', ''), 'scan_date': scan.get('created_at', ''),
            })
    return jsonify({'events': events[:limit], 'total': len(events)})


@app.route('/api/vuln-intel/correlate')
def api_vuln_correlate():
    from dashboard import vuln_intel as _vi
    target = request.args.get('target', '')
    limit  = int(request.args.get('limit', 200))
    scans  = db.get_recent_scans(limit)
    if target:
        scans = [s for s in scans if target.lower() in (s.get('target') or '').lower()]
    return jsonify(_vi.correlate_scans(scans, max_cves=50))


@app.route('/api/vuln-intel/kev')
def api_vuln_kev():
    from dashboard import vuln_intel as _vi
    cve_param = request.args.get('cve', '')
    if cve_param:
        ids = [c.strip().upper() for c in cve_param.split(',') if c.strip()]
        return jsonify({'results': _vi.kev_lookup(ids)})
    stats   = _vi.kev_stats()
    kev_map = _vi._load_kev()
    return jsonify({'total': stats['total'], 'entries': [{'cve_id': k, **v} for k, v in list(kev_map.items())[:200]]})


@app.route('/api/vuln-intel/epss')
def api_vuln_epss():
    from dashboard import vuln_intel as _vi
    cves_param = request.args.get('cves', '')
    if not cves_param:
        return jsonify({'error': 'cves parameter required'}), 400
    ids = [c.strip().upper() for c in cves_param.split(',') if c.strip()]
    return jsonify({'results': _vi.epss_lookup(ids)})


@app.route('/api/export/powerbi')
def api_export_powerbi():
    from dashboard import vuln_intel as _vi
    import time as _t, re as _re
    limit        = int(request.args.get('limit', 500))
    include_intel = request.args.get('include_intel', 'true').lower() != 'false'
    scans = db.get_recent_scans(limit)
    scan_rows = []
    for s in scans:
        out = s.get('output', '')
        scan_rows.append({
            'ScanId':      s.get('id'),
            'Target':      s.get('target', ''),
            'AgentType':   s.get('agent_type', ''),
            'Model':       s.get('model', ''),
            'Status':      s.get('status', ''),
            'LatencyS':    s.get('latency_s', 0),
            'ToolCount':   s.get('tool_count', 0),
            'Date':        (s.get('created_at') or '')[:10],
            'DateTime':    (s.get('created_at') or '').replace(' ', 'T'),
            'HasCritical': bool(_re.search(r'CODE\s+INJECTION\s+CONFIRMED:|CMD\s+INJECTION:|CREDS_FOUND|SQL\s+ERROR:|SSTI\s+HIT|\|\s*Critical\s*\|', out, _re.I)),
            'HasHigh':     bool(_re.search(r'REFLECTED\s+XSS:|FOUND_DB_USER:|APP_PASS_CREATED|WP-LOG.*HIGH|\|\s*High\s*\|', out, _re.I)),
        })
    cve_rows, kev_summary = [], {}
    if include_intel:
        intel = _vi.correlate_scans(scans, max_cves=100)
        for row in intel.get('cves', []):
            nvd = row.get('nvd') or {}
            cve_rows.append({
                'CveId':           row['cve_id'],
                'InKEV':           row['in_kev'],
                'EpssScore':       row.get('epss_score'),
                'CvssScore':       nvd.get('cvss_score'),
                'CvssSeverity':    nvd.get('severity', ''),
                'Published':       nvd.get('published', ''),
                'Description':     (nvd.get('description') or '')[:200],
                'AffectedTargets': ', '.join(row.get('affected_targets', [])),
            })
        kev_summary = _vi.kev_stats()
    return jsonify({
        'schema_version': '1.0',
        'exported_at':    _t.strftime('%Y-%m-%dT%H:%M:%SZ', _t.gmtime()),
        'dataset_name':   'CyberINK Security Intelligence',
        'tables': {
            'scans':     scan_rows,
            'cves':      cve_rows,
            'kev_stats': [kev_summary] if kev_summary else [],
        },
        'powerbi_notes': (
            'Import via Power BI Desktop: Home > Get Data > JSON. '
            'Expand tables record, then load scans and cves tables.'
        ),
    })


if __name__ == '__main__':
    port = int(os.environ.get('CFAI_DASHBOARD_PORT', 8889))
    print(f'CF_AI Dashboard running on http://0.0.0.0:{port}')
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
