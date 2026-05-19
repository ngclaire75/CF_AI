"""
CyberINK — Dynamic Code Analysis Test
No dependencies required. Just run: python dynamic_analysis_test.py [base_url]
Default base_url: http://localhost:8889
The app must be running before executing this script.
"""

import sys
import time
import json
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar

BASE_URL = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else 'http://localhost:8889'
TIMEOUT  = 8

PASS = '\033[92m[PASS]\033[0m'
FAIL = '\033[91m[FAIL]\033[0m'
WARN = '\033[93m[WARN]\033[0m'
INFO = '\033[94m[INFO]\033[0m'

results = []

def rec(level, name, detail):
    results.append((level, name, detail))

def chk(condition, level, name, pass_msg, fail_msg):
    if condition:
        rec('PASS' if level != 'WARN' else 'PASS', name, pass_msg)
    else:
        rec(level, name, fail_msg)

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _opener(jar=None):
    handlers = [urllib.request.HTTPCookieProcessor(jar or http.cookiejar.CookieJar())]
    o = urllib.request.build_opener(*handlers)
    o.addheaders = [('User-Agent', 'CyberINK-DynTest/1.0')]
    return o

def _get(path, opener=None):
    op = opener or _opener()
    req = urllib.request.Request(BASE_URL + path)
    try:
        resp = op.open(req, timeout=TIMEOUT)
        return resp.status, dict(resp.headers), resp.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode('utf-8', errors='ignore')
    except urllib.error.URLError as e:
        raise ConnectionError(str(e))

def _post(path, data, opener=None):
    op = opener or _opener()
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(BASE_URL + path, data=body,
                                  headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        resp = op.open(req, timeout=TIMEOUT)
        return resp.status, dict(resp.headers), resp.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode('utf-8', errors='ignore')
    except urllib.error.URLError as e:
        raise ConnectionError(str(e))

def _post_json(path, payload, opener=None):
    op = opener or _opener()
    body = json.dumps(payload).encode()
    req = urllib.request.Request(BASE_URL + path, data=body,
                                  headers={'Content-Type': 'application/json'})
    try:
        resp = op.open(req, timeout=TIMEOUT)
        return resp.status, dict(resp.headers), resp.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode('utf-8', errors='ignore')
    except urllib.error.URLError as e:
        raise ConnectionError(str(e))

# ── 1. Availability ───────────────────────────────────────────────────────────

def test_app_reachable():
    try:
        status, _, _ = _get('/')
        rec('PASS' if status in (200, 302, 301) else 'WARN', 'App Reachable',
            'App is up (HTTP {})'.format(status))
    except ConnectionError:
        rec('FAIL', 'App Reachable', 'Cannot connect to {} — is the app running?'.format(BASE_URL))
        print('{} Cannot connect to {}. Start the app first.'.format(FAIL, BASE_URL))
        sys.exit(1)

# ── 2. Security Headers ───────────────────────────────────────────────────────

def test_security_headers():
    status, headers, _ = _get('/')
    lower_headers = {k.lower(): v for k, v in headers.items()}

    desired = [
        ('x-content-type-options',   'nosniff',          'WARN'),
        ('x-frame-options',          'DENY or SAMEORIGIN','WARN'),
        ('x-xss-protection',         '1; mode=block',     'WARN'),
        ('strict-transport-security','max-age=...',        'WARN'),
        ('content-security-policy',  'present',           'WARN'),
    ]
    for header, expected, level in desired:
        present = header in lower_headers
        chk(present, level, 'Header: {}'.format(header),
            '{}: {}'.format(header, lower_headers.get(header, '')),
            '{} not set (expected: {})'.format(header, expected))

    srv = lower_headers.get('server', '')
    chk('werkzeug' not in srv.lower() and 'python' not in srv.lower(), 'WARN',
        'Server Header',
        'Server header hides framework ({})'.format(srv or 'not set'),
        'Server header reveals framework: {}'.format(srv))

# ── 3. Authentication Enforcement ─────────────────────────────────────────────

def test_auth_enforcement():
    protected = [
        '/api/users',
        '/api/admin/users',
        '/api/admin/credit-requests',
        '/api/appointments',
        '/api/credits/balance',
    ]
    for path in protected:
        status, _, _ = _get(path)
        chk(status in (401, 403, 302), 'FAIL', 'Auth: {}'.format(path),
            '{} blocks unauthenticated access (HTTP {})'.format(path, status),
            '{} returned HTTP {} — may be accessible without login'.format(path, status))

# ── 4. Admin Endpoint Isolation ───────────────────────────────────────────────

def test_admin_isolation():
    jar = http.cookiejar.CookieJar()
    op  = _opener(jar)
    # login as non-existent user (will fail, but session is now established)
    try:
        _post('/login', {'username': 'hacker_probe', 'password': 'wrongpass'}, opener=op)
    except Exception:
        pass
    for path in ['/api/admin/users', '/api/admin/credit-requests']:
        status, _, _ = _get(path, opener=op)
        chk(status in (401, 403, 302), 'FAIL', 'Admin Isolation: {}'.format(path),
            '{} blocks non-admin session (HTTP {})'.format(path, status),
            '{} returned HTTP {} for non-admin'.format(path, status))

# ── 5. Login Error Behaviour ──────────────────────────────────────────────────

def test_login_errors():
    status, _, body = _post('/login', {'username': 'nobody_test', 'password': 'wrongpassword'})
    chk(status in (200, 302), 'PASS', 'Login Bad Credentials',
        'Login returns HTTP {} for bad credentials (no 500)'.format(status),
        'Login returned unexpected HTTP {}'.format(status))

    body_lower = body.lower()
    chk('traceback' not in body_lower and 'werkzeug' not in body_lower,
        'FAIL', 'Login Error Leakage',
        'Login error does not expose stack trace',
        'Login error page may contain stack trace or debug info')

    chk(any(w in body_lower for w in ('invalid', 'incorrect', 'wrong', 'error', 'failed')),
        'WARN', 'Login Error Message',
        'Login shows user-facing error message',
        'No error message found in login response')

# ── 6. Signup Input Validation ────────────────────────────────────────────────

def test_signup_validation():
    status, _, body = _post('/signup', {'username': 'sc_probe_1', 'password': '123', 'confirm': '123'})
    body_lower = body.lower()
    chk(any(w in body_lower for w in ('short', 'minimum', 'error', 'least')) or status == 400,
        'WARN', 'Signup: Short Password',
        'Signup rejects short passwords',
        'Signup may accept passwords shorter than minimum length')

    status2, _, body2 = _post('/signup', {'username': 'sc_probe_2',
                                          'password': 'validpassword1',
                                          'confirm':  'differentpassword'})
    chk(any(w in body2.lower() for w in ('match', 'error', 'confirm')) or status2 == 400,
        'WARN', 'Signup: Password Match',
        'Signup rejects mismatched passwords',
        'Signup may not validate password confirmation')

# ── 7. Error Page Info Leak ───────────────────────────────────────────────────

def test_error_pages():
    status, _, body = _get('/route-that-does-not-exist-xyzabc')
    chk(status == 404, 'PASS', '404 Status',
        '404 handler returns correct status code',
        'Expected 404, got {}'.format(status))
    body_lower = body.lower()
    chk('traceback' not in body_lower and 'werkzeug' not in body_lower,
        'FAIL', '404 Info Leak',
        '404 page does not expose stack trace',
        '404 page may expose stack trace or debug info')

# ── 8. Cookie Security ────────────────────────────────────────────────────────

def test_cookie_flags():
    status, headers, _ = _get('/')
    set_cookie = headers.get('Set-Cookie', '')
    if set_cookie:
        chk('httponly' in set_cookie.lower(), 'WARN', 'Cookie HttpOnly',
            'HttpOnly present in Set-Cookie header',
            'HttpOnly missing from Set-Cookie — JS can access session cookie')
        chk('samesite' in set_cookie.lower(), 'WARN', 'Cookie SameSite',
            'SameSite present in Set-Cookie header',
            'SameSite missing from Set-Cookie — CSRF risk')
    else:
        rec('INFO', 'Cookie Flags', 'No Set-Cookie on GET / — check after a login attempt')

# ── 9. Rate Limiting ──────────────────────────────────────────────────────────

def test_rate_limiting():
    start = time.time()
    statuses = []
    for i in range(10):
        try:
            status, _, _ = _post('/login', {'username': 'ratelimit_probe_{}'.format(i),
                                            'password': 'wrongpass'})
            statuses.append(status)
        except Exception:
            pass
    elapsed = time.time() - start
    chk(429 in statuses or elapsed > 3.0, 'WARN', 'Rate Limiting',
        'Possible rate limiting detected ({:.1f}s for 10 requests{})'.format(
            elapsed, ' or 429 seen' if 429 in statuses else ''),
        'No rate limiting — 10 login attempts in {:.1f}s, codes: {}'.format(
            elapsed, sorted(set(statuses))))

# ── 10. Sensitive Path Exposure ───────────────────────────────────────────────

def test_sensitive_paths():
    sensitive = [
        '/.env',
        '/data/users.json',
        '/static/../.env',
        '/config',
    ]
    for path in sensitive:
        try:
            status, _, body = _get(path)
            chk(status in (302, 401, 403, 404), 'WARN',
                'Sensitive Path: {}'.format(path),
                '{} not exposed (HTTP {})'.format(path, status),
                '{} returned HTTP {} — may be publicly accessible'.format(path, status))
        except Exception:
            rec('INFO', 'Sensitive Path: {}'.format(path), 'Request failed / path not reachable')

    status, _, _ = _get('/robots.txt')
    rec('INFO', 'robots.txt', 'HTTP {} — {}'.format(
        status, 'present' if status == 200 else 'not found'))

# ── Runner ────────────────────────────────────────────────────────────────────

TESTS = [
    ('App Reachable',          test_app_reachable),
    ('Security Headers',       test_security_headers),
    ('Auth Enforcement',       test_auth_enforcement),
    ('Admin Isolation',        test_admin_isolation),
    ('Login Error Behaviour',  test_login_errors),
    ('Signup Validation',      test_signup_validation),
    ('Error Page Info Leak',   test_error_pages),
    ('Cookie Security',        test_cookie_flags),
    ('Rate Limiting',          test_rate_limiting),
    ('Sensitive Path Exposure',test_sensitive_paths),
]

def main():
    print('\n' + '=' * 60)
    print('  CyberINK — Dynamic Code Analysis')
    print('  Target: {}'.format(BASE_URL))
    print('=' * 60 + '\n')

    for name, fn in TESTS:
        print('{} Running: {}'.format(INFO, name))
        try:
            fn()
        except Exception as e:
            rec('FAIL', name, 'Test raised exception: {}'.format(e))

    pass_n = sum(1 for r in results if r[0] == 'PASS')
    warn_n = sum(1 for r in results if r[0] == 'WARN')
    fail_n = sum(1 for r in results if r[0] == 'FAIL')
    info_n = sum(1 for r in results if r[0] == 'INFO')

    print('\n' + '-' * 60)
    print('  Full Results')
    print('-' * 60)
    for level, name, detail in results:
        tag = PASS if level == 'PASS' else (WARN if level == 'WARN' else (INFO if level == 'INFO' else FAIL))
        print('{} [{}] {}'.format(tag, name, detail))

    print('\n' + '-' * 60)
    print('  Results: {} passed  |  {} warnings  |  {} failures  |  {} info'.format(
        pass_n, warn_n, fail_n, info_n))
    print('-' * 60 + '\n')
    sys.exit(1 if fail_n > 0 else 0)

if __name__ == '__main__':
    main()
