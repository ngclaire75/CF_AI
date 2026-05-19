"""
CyberINK — Functional Test Suite
Tests every major page and API endpoint for real responses, no fake data, no hardcoded logic.
No dependencies required — stdlib only.

Usage:
  python functional_test.py <base_url> <admin_username> <admin_password>

Example:
  python functional_test.py https://inktelligence.online admin MyPassword123
"""

import sys
import json
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar

# ── Args ──────────────────────────────────────────────────────────────────────
if len(sys.argv) < 4:
    print('Usage: python functional_test.py <base_url> <admin_user> <admin_password>')
    sys.exit(1)

BASE    = sys.argv[1].rstrip('/')
USER    = sys.argv[2]
PASSWD  = sys.argv[3]
TIMEOUT = 12

PASS = '\033[92m[PASS]\033[0m'
FAIL = '\033[91m[FAIL]\033[0m'
WARN = '\033[93m[WARN]\033[0m'
INFO = '\033[94m[INFO]\033[0m'
SKIP = '\033[90m[SKIP]\033[0m'

results = []

def rec(level, name, detail):
    results.append((level, name, detail))

# ── Fake data patterns to detect ─────────────────────────────────────────────
FAKE_PATTERNS = [
    'lorem ipsum', 'dummy data', 'test@test.com',
    'fake data', 'sample data', 'todo:', 'fixme:', 'hardcoded',
    'coming soon', 'not implemented',
]

def has_fake_data(text):
    t = text.lower()
    return next((p for p in FAKE_PATTERNS if p in t), None)

# ── HTTP session ──────────────────────────────────────────────────────────────
jar    = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
opener.addheaders = [('User-Agent', 'CyberINK-FuncTest/1.0')]

def _req(method, path, data=None, json_body=None):
    url  = BASE + path
    body = None
    hdrs = {}
    if json_body is not None:
        body = json.dumps(json_body).encode()
        hdrs['Content-Type'] = 'application/json'
    elif data is not None:
        body = urllib.parse.urlencode(data).encode()
        hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        resp = opener.open(req, timeout=TIMEOUT)
        raw  = resp.read().decode('utf-8', errors='ignore')
        return resp.status, dict(resp.headers), raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode('utf-8', errors='ignore')
        return e.code, dict(e.headers), raw
    except urllib.error.URLError as e:
        return 0, {}, str(e)

def get(path):   return _req('GET',  path)
def post(path, data=None, json_body=None):
    return _req('POST', path, data=data, json_body=json_body)

def parse_json(raw):
    try:    return json.loads(raw)
    except: return None

# ── Login ─────────────────────────────────────────────────────────────────────
def login():
    status, _, body = post('/login', data={'username': USER, 'password': PASSWD})
    logged_in = status in (200, 302) and 'error' not in body.lower()[:200]
    if not logged_in:
        print('{} Login failed for user "{}". Check credentials.'.format(FAIL, USER))
        sys.exit(1)
    rec('PASS', 'Login', 'Authenticated as "{}"'.format(USER))

# ── Helpers ───────────────────────────────────────────────────────────────────
def check_page(name, path, expect_status=200, check_json=False,
               required_keys=None, no_fake=True, min_items=None):
    status, headers, body = get(path)
    if status == 0:
        rec('FAIL', name, 'Connection error — {}'.format(body))
        return None

    if status != expect_status:
        rec('FAIL', name, 'Expected HTTP {}, got {} — {}'.format(
            expect_status, status, body[:120]))
        return None

    if no_fake:
        hit = has_fake_data(body)
        if hit:
            rec('WARN', name, 'Possible fake/placeholder data detected: "{}"'.format(hit))

    if check_json:
        d = parse_json(body)
        if d is None:
            rec('FAIL', name, 'Expected JSON response, got: {}'.format(body[:120]))
            return None
        if required_keys:
            missing = [k for k in required_keys if k not in d]
            if missing:
                rec('FAIL', name, 'JSON missing keys: {}'.format(missing))
                return d
        if min_items is not None:
            # d could be a list or a dict with a list value
            items = d if isinstance(d, list) else next(
                (v for v in d.values() if isinstance(v, list)), None)
            if items is not None and len(items) < min_items:
                rec('WARN', name,
                    'Response has {} items (expected >= {})'.format(len(items), min_items))
                return d
        rec('PASS', name, 'HTTP {} — valid JSON{}'.format(
            status, ', keys: {}'.format(list(d.keys())[:6]) if isinstance(d, dict) else ''))
        return d

    rec('PASS', name, 'HTTP {} — OK'.format(status))
    return body

def check_post(name, path, payload, expect_key='ok', expect_status=200, json_body=True):
    status, _, body = post(path, json_body=payload if json_body else None,
                           data=payload if not json_body else None)
    if status == 0:
        rec('FAIL', name, 'Connection error')
        return None
    d = parse_json(body)
    if status not in (200, 201):
        rec('WARN', name, 'HTTP {} — {}'.format(status, body[:120]))
        return d
    if d and expect_key and not d.get(expect_key):
        rec('WARN', name, 'Response missing "{}": {}'.format(expect_key, body[:120]))
        return d
    rec('PASS', name, 'HTTP {} — {}'.format(status, body[:80]))
    return d

# ── Test groups ───────────────────────────────────────────────────────────────

def test_public_pages():
    print('\n{}  Public pages'.format(INFO))
    check_page('GET /login',   '/login',   expect_status=200, no_fake=False)
    check_page('GET /signup',  '/signup',  expect_status=200, no_fake=False)
    check_page('GET /favicon', '/favicon.ico', expect_status=200, no_fake=False)

def test_main_dashboard():
    print('\n{}  Main dashboard'.format(INFO))
    check_page('GET /', '/', expect_status=200, no_fake=True)
    check_page('GET /api/stats', '/api/stats',
               check_json=True, required_keys=['total_scans'])
    check_page('GET /api/scans/recent', '/api/scans/recent',
               check_json=True)
    check_page('GET /api/scans/summary', '/api/scans/summary',
               check_json=True)
    check_page('GET /api/unified/overview', '/api/unified/overview',
               check_json=True)

def test_security_signals():
    print('\n{}  Security signals & events'.format(INFO))
    check_page('GET /api/security-signals', '/api/security-signals',
               check_json=True)
    check_page('GET /api/events', '/api/events',
               check_json=True)
    check_page('GET /api/events/stats', '/api/events/stats',
               check_json=True)
    check_page('GET /api/events/map', '/api/events/map',
               check_json=True)
    check_page('GET /api/events/blocked-ips', '/api/events/blocked-ips',
               check_json=True)

def test_incidents():
    print('\n{}  Incidents'.format(INFO))
    d = check_page('GET /api/incidents', '/api/incidents',
                   check_json=True)
    if d and isinstance(d, list) and len(d) > 0:
        inc = d[0]
        missing = [k for k in ('id','title','status') if k not in inc]
        if missing:
            rec('WARN', 'Incident record shape', 'Missing fields: {}'.format(missing))
        else:
            rec('PASS', 'Incident record shape', 'Fields present: id, title, status')

def test_log_explorer():
    print('\n{}  Log explorer'.format(INFO))
    check_page('GET /api/syslog', '/api/syslog', check_json=True)
    check_page('GET /api/syslog/config', '/api/syslog/config', check_json=True)
    check_page('GET /api/login-events', '/api/login-events', check_json=True)

def test_network():
    print('\n{}  Network monitor'.format(INFO))
    check_page('GET /api/geoip', '/api/geoip', check_json=True)

def test_inventories():
    print('\n{}  Inventories'.format(INFO))
    check_page('GET /api/inventories/plugins', '/api/inventories/plugins',
               check_json=True)
    check_page('GET /api/inventories/logins', '/api/inventories/logins',
               check_json=True)

def test_grc():
    print('\n{}  GRC'.format(INFO))
    check_page('GET /api/grc2/stats',    '/api/grc2/stats',    check_json=True)
    check_page('GET /api/grc2/risks',    '/api/grc2/risks',    check_json=True)
    check_page('GET /api/grc2/controls', '/api/grc2/controls', check_json=True)
    check_page('GET /api/grc2/tests',    '/api/grc2/tests',    check_json=True)
    check_page('GET /api/grc2/audits',   '/api/grc2/audits',   check_json=True)
    check_page('GET /api/grc2/evidence', '/api/grc2/evidence', check_json=True)
    check_page('GET /api/grc2/users',    '/api/grc2/users',    check_json=True)

def test_pentest():
    print('\n{}  Pentest'.format(INFO))
    d = check_page('GET /api/pentest/engagements', '/api/pentest/engagements',
                   check_json=True)
    if d and isinstance(d, list) and len(d) > 0:
        eid = d[0].get('id')
        if eid:
            check_page('GET pentest findings',
                       '/api/pentest/engagements/{}/findings'.format(eid),
                       check_json=True)
            check_page('GET pentest checklist',
                       '/api/pentest/engagements/{}/checklist'.format(eid),
                       check_json=True)
            check_page('GET pentest scope',
                       '/api/pentest/engagements/{}/scope'.format(eid),
                       check_json=True)

def test_appointments():
    print('\n{}  Appointments'.format(INFO))
    d = check_page('GET /api/appointments', '/api/appointments',
                   check_json=True, required_keys=['appointments'])
    check_page('GET /api/my-appointments', '/api/my-appointments',
               check_json=True)
    if d:
        appts = d.get('appointments', [])
        rec('INFO', 'Appointments count', '{} appointment(s) in system'.format(len(appts)))

def test_credits_usage():
    print('\n{}  Credits & usage'.format(INFO))
    check_page('GET /api/usage', '/api/usage', check_json=True)
    check_page('GET /api/admin/credit-requests', '/api/admin/credit-requests',
               check_json=True)

def test_payment():
    print('\n{}  Payment & subscriptions'.format(INFO))
    check_page('GET /api/payment/status', '/api/payment/status', check_json=True)
    check_page('GET /api/admin/invoices', '/api/admin/invoices', check_json=True)

def test_user_management():
    print('\n{}  User management'.format(INFO))
    d = check_page('GET /api/admin/users', '/api/admin/users',
                   check_json=True, required_keys=['users'])
    if d:
        users = d.get('users', [])
        rec('INFO', 'User count', '{} user account(s) in system'.format(len(users)))
        # users may be a list of dicts or a dict keyed by username
        items = users.items() if isinstance(users, dict) else (
            (u.get('username', str(i)), u) for i, u in enumerate(users)
        )
        fake_found = False
        for uname, udata in items:
            fake = has_fake_data(str(udata))
            if fake:
                rec('WARN', 'User data: {}'.format(uname),
                    'Possible fake data pattern: "{}"'.format(fake))
                fake_found = True
        if not fake_found:
            rec('PASS', 'User records', 'All user records checked — no fake data detected')

def test_files():
    print('\n{}  File manager'.format(INFO))
    check_page('GET /api/files', '/api/files', check_json=True)

def test_sca_dca():
    print('\n{}  SCA / DCA'.format(INFO))
    check_page('GET /api/sca/check',     '/api/sca/check',     check_json=True)
    check_page('GET /api/dca/scanners',  '/api/dca/scanners',  check_json=True)

def test_remediation():
    print('\n{}  Remediation'.format(INFO))
    check_page('GET /api/remediation/log',   '/api/remediation/log',   check_json=True)
    check_page('GET /api/remediation/rules', '/api/remediation/rules', check_json=True)

def test_vuln_intel():
    print('\n{}  Vulnerability intelligence'.format(INFO))
    check_page('GET /api/vuln-intel/kev', '/api/vuln-intel/kev', check_json=True)
    # EPSS requires a cves param — test with a known CVE
    check_page('GET /api/vuln-intel/epss',
               '/api/vuln-intel/epss?cves=CVE-2021-44228', check_json=True)

def test_mitre():
    print('\n{}  MITRE coverage'.format(INFO))
    check_page('GET /api/mitre/coverage', '/api/mitre/coverage', check_json=True)

def test_analytics():
    print('\n{}  Analytics'.format(INFO))
    check_page('GET /api/analytics/pci', '/api/analytics/pci', check_json=True)

def test_gsc():
    print('\n{}  Google Search Console'.format(INFO))
    check_page('GET /api/gsc/config', '/api/gsc/config', check_json=True)

def test_creds():
    print('\n{}  Saved credentials'.format(INFO))
    check_page('GET /api/creds/load', '/api/creds/load', check_json=True)

def test_unauthenticated_blocks():
    print('\n{}  Unauthenticated access blocks (logout first)'.format(INFO))
    # Logout then verify protected endpoints still block
    get('/logout')
    protected = [
        '/api/stats', '/api/incidents', '/api/admin/users',
        '/api/appointments', '/api/grc2/risks', '/api/usage',
        '/api/files', '/api/pentest/engagements',
    ]
    for path in protected:
        status, _, _ = get(path)
        if status in (401, 403, 302):
            rec('PASS', 'Logout blocks: {}'.format(path),
                'Returns HTTP {} after logout'.format(status))
        else:
            rec('FAIL', 'Logout blocks: {}'.format(path),
                'Returned HTTP {} after logout — session not cleared'.format(status))

# ── Runner ────────────────────────────────────────────────────────────────────

GROUPS = [
    test_public_pages,
    test_main_dashboard,
    test_security_signals,
    test_incidents,
    test_log_explorer,
    test_network,
    test_inventories,
    test_grc,
    test_pentest,
    test_appointments,
    test_credits_usage,
    test_payment,
    test_user_management,
    test_files,
    test_sca_dca,
    test_remediation,
    test_vuln_intel,
    test_mitre,
    test_analytics,
    test_gsc,
    test_creds,
    test_unauthenticated_blocks,
]

def main():
    print('\n' + '=' * 60)
    print('  CyberINK — Functional Test Suite')
    print('  Target : {}'.format(BASE))
    print('  User   : {}'.format(USER))
    print('=' * 60)

    login()

    for fn in GROUPS:
        try:
            fn()
        except Exception as e:
            rec('FAIL', fn.__name__, 'Group raised exception: {}'.format(e))

    pass_n = sum(1 for r in results if r[0] == 'PASS')
    warn_n = sum(1 for r in results if r[0] == 'WARN')
    fail_n = sum(1 for r in results if r[0] == 'FAIL')
    info_n = sum(1 for r in results if r[0] == 'INFO')

    print('\n' + '-' * 60)
    print('  Full Results')
    print('-' * 60)
    for level, name, detail in results:
        tag = (PASS if level == 'PASS' else
               WARN if level == 'WARN' else
               INFO if level == 'INFO' else FAIL)
        print('{} [{}] {}'.format(tag, name, detail))

    print('\n' + '-' * 60)
    print('  Results: {} passed  |  {} warnings  |  {} failures  |  {} info'.format(
        pass_n, warn_n, fail_n, info_n))
    print('-' * 60 + '\n')
    sys.exit(1 if fail_n > 0 else 0)

if __name__ == '__main__':
    main()
