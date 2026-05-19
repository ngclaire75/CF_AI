"""
CyberINK — Agent Tool Test Suite
Directly exercises every tool used by the agents with real inputs and real execution.
No LLM calls — no API credits spent.

Usage:
  python tool_test.py                          # basic tests, no network
  python tool_test.py --net                    # + network tests (curl, JS hunt, latency)
  python tool_test.py --net --nuclei           # + nuclei scan against test target
  python tool_test.py --net --target example.com  # custom target for network tests

Run on the server (Linux) for full tool coverage. Windows runs a reduced set.
"""
from __future__ import annotations
import sys
import os
import re
import platform
import tempfile
import json

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

RUN_NET    = '--net'    in sys.argv
RUN_NUCLEI = '--nuclei' in sys.argv
TARGET     = next((sys.argv[i+1] for i, a in enumerate(sys.argv)
                   if a == '--target' and i+1 < len(sys.argv)), 'example.com')
IS_WINDOWS = platform.system() == 'Windows'

PASS = '\033[92m[PASS]\033[0m'
FAIL = '\033[91m[FAIL]\033[0m'
WARN = '\033[93m[WARN]\033[0m'
INFO = '\033[94m[INFO]\033[0m'
SKIP = '\033[90m[SKIP]\033[0m'

results = []

def rec(level, name, detail):
    results.append((level, name, detail))

def tag(l):
    return (PASS if l=='PASS' else WARN if l=='WARN' else
            SKIP if l=='SKIP' else INFO if l=='INFO' else FAIL)

def section(title):
    print('\n{}  {}'.format(INFO, title))


# ══════════════════════════════════════════════════════════════════════════════
# 1. generic_linux_command
# ══════════════════════════════════════════════════════════════════════════════

def test_generic_linux_command():
    section('Tool: generic_linux_command')
    try:
        from tools.generic_linux_command import generic_linux_command, _patch_curl, _patch_windows_compat
        rec('PASS', 'import generic_linux_command', 'Module loaded')
    except Exception as e:
        rec('FAIL', 'import generic_linux_command', str(e))
        return

    # ── echo ──────────────────────────────────────────────────────────────────
    out = generic_linux_command('echo hello_cfai')
    rec('PASS' if 'hello_cfai' in out else 'FAIL',
        'echo command', 'Output: {}'.format(out[:80]))

    # ── python version ────────────────────────────────────────────────────────
    cmd = 'python --version 2>&1 || python3 --version 2>&1'
    out = generic_linux_command(cmd)
    rec('PASS' if 'python' in out.lower() or 'Python' in out else 'WARN',
        'python version check', 'Output: {}'.format(out[:80]))

    # ── multiline / pipe ──────────────────────────────────────────────────────
    out = generic_linux_command('echo line1 && echo line2')
    rec('PASS' if 'line1' in out and 'line2' in out else 'FAIL',
        'multi-command &&', 'Output: {}'.format(out[:80]))

    # ── env var access ────────────────────────────────────────────────────────
    out = generic_linux_command('echo $HOME || echo %USERPROFILE%')
    rec('PASS' if out.strip() else 'WARN',
        'env var access', 'Output: {}'.format(out[:60]))

    # ── timeout behaviour ─────────────────────────────────────────────────────
    # sleep 2 should complete within TOOL_TIMEOUT
    out = generic_linux_command('sleep 1 && echo slept_ok')
    rec('PASS' if 'slept_ok' in out else 'WARN',
        'sleep + output', 'Output: {}'.format(out[:80]))

    # ── large output truncation ───────────────────────────────────────────────
    out = generic_linux_command('python3 -c "print(chr(65)*300)" 2>/dev/null || python -c "print(chr(65)*300)"')
    rec('PASS' if len(out) > 50 else 'WARN',
        'large output handling', '{} chars returned'.format(len(out)))

    # ── non-existent command graceful failure ─────────────────────────────────
    out = generic_linux_command('__nonexistent_cmd_cfai_test__ 2>&1 || echo cmd_not_found')
    rec('PASS' if out.strip() else 'WARN',
        'graceful command failure', 'Output: {}'.format(out[:80]))

    # ── _patch_curl ───────────────────────────────────────────────────────────
    patched = _patch_curl('curl https://example.com')
    rec('PASS' if '--connect-timeout' in patched and '-4' in patched else 'FAIL',
        '_patch_curl: speed flags injected',
        'Patched: {}'.format(patched[:120]))

    # no double-injection
    patched2 = _patch_curl(patched)
    count = patched2.count('--connect-timeout')
    rec('PASS' if count == 1 else 'WARN',
        '_patch_curl: no double-injection',
        '--connect-timeout appears {} time(s)'.format(count))

    # respects existing --max-time
    patched3 = _patch_curl('curl --max-time 60 https://example.com')
    rec('PASS' if '--max-time 20' not in patched3 and '--connect-timeout' in patched3 else 'WARN',
        '_patch_curl: respects existing --max-time',
        'Patched: {}'.format(patched3[:120]))

    # does NOT patch curl inside Python string literals
    patched4 = _patch_curl("subprocess.run(['curl', 'https://example.com'])")
    rec('PASS' if '-4' not in patched4 else 'FAIL',
        '_patch_curl: does not modify curl inside quotes',
        'Patched: {}'.format(patched4[:120]))

    # ── _patch_windows_compat ─────────────────────────────────────────────────
    if IS_WINDOWS:
        patched_w = _patch_windows_compat('python3 -c "print(1)"')
        rec('PASS' if 'python ' in patched_w or patched_w.startswith('python ') else 'WARN',
            '_patch_windows_compat: python3 → python', 'Patched: {}'.format(patched_w[:80]))


# ══════════════════════════════════════════════════════════════════════════════
# 2. read_file / write_file
# ══════════════════════════════════════════════════════════════════════════════

def test_file_tools():
    section('Tool: read_file / write_file')
    try:
        from tools.generic_linux_command import read_file, write_file
        rec('PASS', 'import read_file / write_file', 'Imported successfully')
    except Exception as e:
        rec('FAIL', 'import read_file / write_file', str(e))
        return

    tmp = os.path.join(tempfile.gettempdir(), 'cfai_tool_test.txt')
    content = 'cfai_write_test_content_12345'

    # ── write_file ────────────────────────────────────────────────────────────
    result = write_file(tmp, content)
    rec('PASS' if 'Written' in result and os.path.exists(tmp) else 'FAIL',
        'write_file: creates file', 'Result: {}'.format(result[:80]))

    # ── write_file: correct byte count ───────────────────────────────────────
    rec('PASS' if str(len(content)) in result else 'WARN',
        'write_file: reports correct byte count',
        'Expected {} bytes in result: {}'.format(len(content), result[:60]))

    # ── read_file: reads back correctly ──────────────────────────────────────
    read_back = read_file(tmp)
    rec('PASS' if read_back == content else 'FAIL',
        'read_file: reads back written content',
        'Content match: {}'.format(read_back == content))

    # ── read_file: truncation at 6000 chars ──────────────────────────────────
    big = 'X' * 7000
    write_file(tmp, big)
    read_big = read_file(tmp)
    rec('PASS' if 'truncated' in read_big and len(read_big) < 7000 else 'WARN',
        'read_file: truncates large files',
        '{} chars, truncated={}'.format(len(read_big), 'truncated' in read_big))

    # ── read_file: non-existent file ──────────────────────────────────────────
    bad = read_file('/nonexistent/path/cfai_test_missing.txt')
    rec('PASS' if 'error' in bad.lower() else 'FAIL',
        'read_file: graceful error on missing file',
        'Response: {}'.format(bad[:80]))

    # ── write_file: creates parent dirs ──────────────────────────────────────
    nested = os.path.join(tempfile.gettempdir(), 'cfai_test_nested', 'sub', 'file.txt')
    r = write_file(nested, 'nested_content')
    rec('PASS' if os.path.exists(nested) else 'FAIL',
        'write_file: creates parent directories',
        'Result: {}'.format(r[:60]))

    # ── cleanup ───────────────────────────────────────────────────────────────
    for f in [tmp, nested]:
        try: os.remove(f)
        except: pass


# ══════════════════════════════════════════════════════════════════════════════
# 3. log_analyzer
# ══════════════════════════════════════════════════════════════════════════════

SAMPLE_LOG = """\
192.168.1.1 - - [10/May/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
10.0.0.5 - - [10/May/2026:10:00:02 +0000] "GET /wp-login.php HTTP/1.1" 200 512 "-" "sqlmap/1.7"
10.0.0.5 - - [10/May/2026:10:00:03 +0000] "GET /wp-login.php HTTP/1.1" 200 512 "-" "sqlmap/1.7"
10.0.0.5 - - [10/May/2026:10:00:04 +0000] "GET /wp-login.php HTTP/1.1" 200 512 "-" "sqlmap/1.7"
10.0.0.5 - - [10/May/2026:10:00:05 +0000] "GET /wp-login.php HTTP/1.1" 401 128 "-" "sqlmap/1.7"
10.0.0.5 - - [10/May/2026:10:00:06 +0000] "GET /wp-login.php HTTP/1.1" 401 128 "-" "sqlmap/1.7"
203.0.113.9 - - [10/May/2026:10:00:07 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/7.88"
203.0.113.9 - - [10/May/2026:10:00:08 +0000] "GET /.git/HEAD HTTP/1.1" 404 0 "-" "curl/7.88"
172.16.0.2 - - [10/May/2026:10:00:09 +0000] "GET /page?id=1+UNION+SELECT+1,2,3-- HTTP/1.1" 200 2048 "-" "Mozilla/5.0"
192.168.1.100 - - [10/May/2026:10:00:10 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 403 0 "-" "python-requests/2.28"
192.168.1.1 - - [10/May/2026:10:00:11 +0000] "GET /page HTTP/1.1" 500 0 "-" "Mozilla/5.0"
192.168.1.1 - - [10/May/2026:10:00:12 +0000] "GET /other HTTP/1.1" 404 0 "-" "Mozilla/5.0"
"""

def test_log_analyzer():
    section('Tool: log_analyzer (parse, detect, stats, timeline)')
    try:
        from tools.log_analyzer import (
            parse_log_lines, detect_patterns, get_field_stats,
            build_timeline, check_error_rate
        )
        rec('PASS', 'import log_analyzer', 'All functions imported')
    except Exception as e:
        rec('FAIL', 'import log_analyzer', str(e))
        return

    # ── parse_log_lines ───────────────────────────────────────────────────────
    records = parse_log_lines(SAMPLE_LOG)
    rec('PASS' if len(records) == 12 else 'FAIL',
        'parse_log_lines: record count',
        'Parsed {} / 12 expected records'.format(len(records)))

    expected_fields = {'ip', 'ts', 'method', 'path', 'status'}
    sample = records[0] if records else {}
    missing = expected_fields - set(sample.keys())
    rec('PASS' if not missing else 'FAIL',
        'parse_log_lines: record shape',
        'All fields present' if not missing else 'Missing: {}'.format(missing))

    rec('PASS' if records[0]['ip'] == '192.168.1.1' else 'FAIL',
        'parse_log_lines: IP parsed correctly',
        'First IP: {}'.format(records[0].get('ip')))

    rec('PASS' if records[0]['status'] == 200 else 'FAIL',
        'parse_log_lines: status parsed as int',
        'Type={}, value={}'.format(type(records[0].get('status')).__name__, records[0].get('status')))

    # ── detect_patterns ───────────────────────────────────────────────────────
    patterns = detect_patterns(records)
    types = {p['type'] for p in patterns}
    rec('PASS' if patterns else 'FAIL',
        'detect_patterns: returns findings',
        '{} finding(s): {}'.format(len(patterns), sorted(types)))

    rec('PASS' if 'SCANNER_DETECTED' in types else 'FAIL',
        'detect_patterns: detects scanner UA (sqlmap)',
        'Types found: {}'.format(sorted(types)))

    rec('PASS' if 'BRUTE_FORCE' in types else 'FAIL',
        'detect_patterns: detects brute force (5x wp-login)',
        'Types found: {}'.format(sorted(types)))

    rec('PASS' if 'SQL_INJECTION' in types else 'FAIL',
        'detect_patterns: detects SQL injection in path',
        'Types found: {}'.format(sorted(types)))

    rec('PASS' if 'PATH_TRAVERSAL' in types else 'FAIL',
        'detect_patterns: detects path traversal (../etc/passwd)',
        'Types found: {}'.format(sorted(types)))

    rec('PASS' if 'SENSITIVE_FILE_PROBE' in types else 'FAIL',
        'detect_patterns: detects sensitive file probe (.env/.git)',
        'Types found: {}'.format(sorted(types)))

    # all findings have required fields
    for p in patterns:
        missing_f = {f for f in ('type','severity','ip','detail') if f not in p}
        if missing_f:
            rec('FAIL', 'detect_patterns: finding shape',
                'Finding missing fields: {}'.format(missing_f))
            break
    else:
        rec('PASS', 'detect_patterns: all findings have required fields',
            'Fields: type, severity, ip, detail — all present')

    # ── get_field_stats ───────────────────────────────────────────────────────
    stats = get_field_stats(records)
    required_keys = {'total_requests','error_rate_pct','status_codes',
                     'http_methods','top_ips','top_paths','unique_ips','unique_paths'}
    missing_keys = required_keys - set(stats.keys())
    rec('PASS' if not missing_keys else 'FAIL',
        'get_field_stats: all keys present',
        'All keys present' if not missing_keys else 'Missing: {}'.format(missing_keys))

    rec('PASS' if stats.get('total_requests') == 12 else 'FAIL',
        'get_field_stats: correct total_requests',
        'Got: {}'.format(stats.get('total_requests')))

    rec('PASS' if isinstance(stats.get('error_rate_pct'), float) else 'FAIL',
        'get_field_stats: error_rate_pct is float',
        'Value: {} ({})'.format(stats.get('error_rate_pct'),
                                type(stats.get('error_rate_pct')).__name__))

    # ── build_timeline ────────────────────────────────────────────────────────
    timeline = build_timeline(records, buckets=5)
    rec('PASS' if isinstance(timeline, list) else 'FAIL',
        'build_timeline: returns list',
        '{} bucket(s)'.format(len(timeline)))

    if timeline:
        tl_fields = {'t','total','errors'}
        missing_tf = tl_fields - set(timeline[0].keys())
        rec('PASS' if not missing_tf else 'FAIL',
            'build_timeline: bucket shape',
            'Fields OK' if not missing_tf else 'Missing: {}'.format(missing_tf))

    # ── check_error_rate ─────────────────────────────────────────────────────
    err = check_error_rate(records)
    rec('PASS' if 'surge' in err and 'rate_pct' in err else 'FAIL',
        'check_error_rate: correct shape',
        'Keys: {}'.format(list(err.keys())))

    # ── empty input safety ────────────────────────────────────────────────────
    rec('PASS' if parse_log_lines('') == [] else 'FAIL',
        'parse_log_lines: empty input returns []', '')
    rec('PASS' if detect_patterns([]) == [] else 'FAIL',
        'detect_patterns: empty input returns []', '')
    rec('PASS' if get_field_stats([]) == {} else 'FAIL',
        'get_field_stats: empty input returns {}', '')
    rec('PASS' if build_timeline([]) == [] else 'FAIL',
        'build_timeline: empty input returns []', '')


# ══════════════════════════════════════════════════════════════════════════════
# 4. js_secret_hunter (pattern engine)
# ══════════════════════════════════════════════════════════════════════════════

def test_js_secret_hunter():
    section('Tool: js_secret_hunter (pattern engine)')
    try:
        from tools.js_secret_hunter import hunt_js_secrets, _hunt_secrets, _extract_js_urls, PATTERNS
        rec('PASS', 'import js_secret_hunter', 'Module + functions imported')
    except Exception as e:
        rec('FAIL', 'import js_secret_hunter', str(e))
        return

    # ── PATTERNS dict ─────────────────────────────────────────────────────────
    expected_patterns = ['AWS_ACCESS_KEY','GOOGLE_API_KEY','GITHUB_TOKEN','STRIPE_KEY',
                         'JWT_TOKEN','PRIVATE_KEY','DB_CONN_STRING','API_KEY_GENERIC',
                         'PASSWORD_IN_CODE','INTERNAL_ENDPOINT']
    missing_p = [p for p in expected_patterns if p not in PATTERNS]
    rec('PASS' if not missing_p else 'FAIL',
        'PATTERNS: all key patterns defined',
        'All {} patterns present'.format(len(PATTERNS)) if not missing_p
        else 'Missing: {}'.format(missing_p))

    # All patterns compile as valid regex
    bad_regex = []
    for name, pat in PATTERNS.items():
        try: re.compile(pat)
        except re.error as e: bad_regex.append('{}: {}'.format(name, e))
    rec('PASS' if not bad_regex else 'FAIL',
        'PATTERNS: all regexes valid',
        'All {} compile OK'.format(len(PATTERNS)) if not bad_regex
        else 'Invalid: {}'.format(bad_regex))

    # ── _hunt_secrets: detects AWS key ────────────────────────────────────────
    fake_aws = 'var key = "AKIAIOSFODNN7EXAMPLE"; // AWS access key'
    hits = _hunt_secrets(fake_aws, 'test.js')
    rec('PASS' if any(h['type'] == 'AWS_ACCESS_KEY' for h in hits) else 'FAIL',
        '_hunt_secrets: detects AWS access key',
        'Hits: {}'.format([h['type'] for h in hits]))

    # ── _hunt_secrets: detects JWT ────────────────────────────────────────────
    fake_jwt = 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'
    hits = _hunt_secrets(fake_jwt, 'test.js')
    rec('PASS' if any(h['type'] == 'JWT_TOKEN' for h in hits) else 'FAIL',
        '_hunt_secrets: detects JWT token',
        'Hits: {}'.format([h['type'] for h in hits]))

    # ── _hunt_secrets: detects DB connection string ───────────────────────────
    # Must not use example.com / localhost — those are in the _NOISE filter
    fake_db = 'db = "mongodb://admin:s3cr3t@prod-cluster.company.io:27017/appdb"'
    hits = _hunt_secrets(fake_db, 'test.js')
    rec('PASS' if any(h['type'] == 'DB_CONN_STRING' for h in hits) else 'FAIL',
        '_hunt_secrets: detects DB connection string',
        'Hits: {}'.format([h['type'] for h in hits]))

    # ── _hunt_secrets: noise suppression ─────────────────────────────────────
    noisy = 'var email = "test@example.com"; placeholder = "dummy"'
    hits = _hunt_secrets(noisy, 'test.js')
    real_hits = [h for h in hits if h['value'] not in ('test@example.com',)]
    # example.com / placeholder should be filtered by _NOISE
    rec('PASS' if not any('example.com' in h.get('value','') for h in hits) else 'WARN',
        '_hunt_secrets: noise suppression (example.com filtered)',
        'Hits after noise filter: {}'.format([h['type']+':'+h['value'][:30] for h in hits]))

    # ── _extract_js_urls ──────────────────────────────────────────────────────
    html = '''<html><head>
    <script src="/static/app.js"></script>
    <script src="https://cdn.example.com/lib.js"></script>
    <script src="//cdn2.example.com/other.js"></script>
    </head></html>'''
    urls = _extract_js_urls(html, 'https://mysite.com/')
    rec('PASS' if len(urls) >= 2 else 'WARN',
        '_extract_js_urls: extracts JS URLs from HTML',
        'Found {} URLs: {}'.format(len(urls), urls[:3]))

    # Absolute path resolved correctly
    rec('PASS' if any('mysite.com/static/app.js' in u for u in urls) else 'WARN',
        '_extract_js_urls: resolves relative /path to full URL',
        'URLs: {}'.format(urls))

    # function_tool spec
    rec('PASS' if hasattr(hunt_js_secrets, '_ant_tool_spec') else 'FAIL',
        'hunt_js_secrets: has _ant_tool_spec', '')
    rec('PASS' if hasattr(hunt_js_secrets, '_oai_tool_spec') else 'FAIL',
        'hunt_js_secrets: has _oai_tool_spec', '')


# ══════════════════════════════════════════════════════════════════════════════
# 5. nuclei_scan (availability + spec)
# ══════════════════════════════════════════════════════════════════════════════

def test_nuclei_scan():
    section('Tool: nuclei_scan')
    try:
        from tools.nuclei_scan import nuclei_scan, _TEMPLATE_MAP, _SEV_MARKER
        rec('PASS', 'import nuclei_scan', 'Module imported')
    except Exception as e:
        rec('FAIL', 'import nuclei_scan', str(e))
        return

    # Spec
    rec('PASS' if hasattr(nuclei_scan, '_ant_tool_spec') else 'FAIL',
        'nuclei_scan: has _ant_tool_spec', '')
    rec('PASS' if hasattr(nuclei_scan, '_oai_tool_spec') else 'FAIL',
        'nuclei_scan: has _oai_tool_spec', '')

    # Template map complete
    expected_tmpl = ['cves','vulnerabilities','misconfiguration','exposures',
                     'default-logins','takeovers','technologies','wordpress']
    missing_t = [t for t in expected_tmpl if t not in _TEMPLATE_MAP]
    rec('PASS' if not missing_t else 'FAIL',
        'nuclei_scan: _TEMPLATE_MAP complete',
        'All 8 templates present' if not missing_t
        else 'Missing: {}'.format(missing_t))

    # Severity markers
    expected_sev = ['critical','high','medium','low','info']
    missing_s = [s for s in expected_sev if s not in _SEV_MARKER]
    rec('PASS' if not missing_s else 'FAIL',
        'nuclei_scan: _SEV_MARKER complete',
        'All 5 severity markers present' if not missing_s
        else 'Missing: {}'.format(missing_s))

    # Binary availability
    import shutil
    nuclei_bin = shutil.which('nuclei')
    if not nuclei_bin:
        rec('WARN', 'nuclei binary', 'Not installed — nuclei_scan will return install instructions')
        rec('INFO', 'nuclei install',
            'apt-get install nuclei  OR  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest')
    else:
        rec('PASS', 'nuclei binary', 'Found at {}'.format(nuclei_bin))
        # Version check
        from tools.generic_linux_command import generic_linux_command
        ver = generic_linux_command('nuclei -version 2>&1 | head -3')
        rec('PASS' if 'nuclei' in ver.lower() or 'version' in ver.lower() else 'WARN',
            'nuclei version', ver[:80])

    if RUN_NUCLEI and nuclei_bin:
        # Safe public test target — testphp.vulnweb.com is Acunetix's dedicated test site
        rec('INFO', 'nuclei live scan',
            'Scanning testphp.vulnweb.com (Acunetix test site) — this may take ~2 min')
        out = nuclei_scan(
            target='http://testphp.vulnweb.com',
            templates='technologies,misconfiguration',
            severity='medium,high,critical',
        )
        rec('PASS' if '[NUCLEI]' in out else 'FAIL',
            'nuclei live scan result', out[:300])
    elif RUN_NUCLEI and not nuclei_bin:
        rec('SKIP', 'nuclei live scan', 'Skipped — nuclei not installed')


# ══════════════════════════════════════════════════════════════════════════════
# 6. Network tools (requires --net flag)
# ══════════════════════════════════════════════════════════════════════════════

def test_network_tools():
    if not RUN_NET:
        rec('SKIP', 'Network tool tests', 'Pass --net to run (requires internet access)')
        return

    section('Tool: network (curl, latency, probe)')
    from tools.generic_linux_command import generic_linux_command

    # ── curl availability ─────────────────────────────────────────────────────
    import shutil
    curl_bin = shutil.which('curl')
    rec('PASS' if curl_bin else 'WARN',
        'curl binary', 'Found at {}'.format(curl_bin) if curl_bin else 'Not found — curl tests may fail')

    # ── curl basic fetch ──────────────────────────────────────────────────────
    out = generic_linux_command('curl -s -o /dev/null -w "%{http_code}" https://example.com 2>&1')
    code = out.strip()[:3]
    rec('PASS' if code in ('200','301','302') else 'WARN',
        'curl: fetch example.com',
        'HTTP {}'.format(code))

    # ── curl speed flags applied ──────────────────────────────────────────────
    out2 = generic_linux_command('curl -v https://example.com 2>&1 | head -5')
    rec('PASS' if out2.strip() else 'WARN',
        'curl -v: returns headers',
        'Output: {}'.format(out2[:80]))

    # ── dig / nslookup ────────────────────────────────────────────────────────
    out3 = generic_linux_command('dig +short example.com 2>/dev/null || nslookup example.com 2>&1 | tail -4')
    rec('PASS' if out3.strip() else 'WARN',
        'DNS lookup (dig/nslookup)',
        'Output: {}'.format(out3[:80]))

    # ── check_latency ─────────────────────────────────────────────────────────
    try:
        from tools.log_analyzer import check_latency
        latency = check_latency(TARGET, paths=['/', '/robots.txt'])
        rec('PASS' if latency and all('latency_ms' in r for r in latency) else 'WARN',
            'check_latency: returns timing data',
            'Results: {}'.format(['{path}={latency_ms}ms'.format(**r) for r in latency]))

        for r in latency:
            if r.get('latency_ms', -1) > 0:
                rec('PASS', 'check_latency: {}'.format(r['path']),
                    '{}ms — status {}'.format(r['latency_ms'], r.get('status')))
            else:
                rec('WARN', 'check_latency: {}'.format(r['path']),
                    'No response (status {})'.format(r.get('status')))
    except Exception as e:
        rec('FAIL', 'check_latency', str(e))

    # ── analyze_from_probe ────────────────────────────────────────────────────
    try:
        from tools.log_analyzer import analyze_from_probe
        rec('INFO', 'analyze_from_probe', 'Probing {} — scanning 10 paths...'.format(TARGET))
        result = analyze_from_probe(TARGET)
        probe_results = result.get('probe_results', [])
        rec('PASS' if probe_results else 'FAIL',
            'analyze_from_probe: returns probe results',
            '{} path(s) probed'.format(len(probe_results)))

        for p in probe_results:
            status  = p.get('status', 0)
            sev     = p.get('severity', 'INFO')
            finding = p.get('finding', '')
            t = PASS if sev == 'OK' else (WARN if sev in ('MEDIUM','INFO') else FAIL)
            label = '{} {} [{}]'.format(p['method'], p['path'], sev)
            detail = 'HTTP {} {}'.format(status, '— '+finding if finding else '')
            print('{} [probe: {}] {}'.format(t, label, detail))
    except Exception as e:
        rec('FAIL', 'analyze_from_probe', str(e))

    # ── hunt_js_secrets (live fetch) ──────────────────────────────────────────
    try:
        from tools.js_secret_hunter import hunt_js_secrets
        rec('INFO', 'hunt_js_secrets live', 'Scanning JS files on {}...'.format(TARGET))
        out = hunt_js_secrets(TARGET)
        rec('PASS' if '[LIVE]' in out or '[WAYBACK]' in out or '[RESULT]' in out else 'WARN',
            'hunt_js_secrets: live scan runs end-to-end',
            out[:300])
    except Exception as e:
        rec('FAIL', 'hunt_js_secrets live', str(e))


# ══════════════════════════════════════════════════════════════════════════════
# 7. WordPress MCP tools (optional)
# ══════════════════════════════════════════════════════════════════════════════

def test_wordpress_tools():
    section('Tool: wordpress_mcp (optional)')
    try:
        from tools.wordpress_mcp import wp_api_call, wp_security_scan
        rec('PASS', 'import wordpress_mcp', 'Module loaded')
        for fn in [wp_api_call, wp_security_scan]:
            has_ant = hasattr(fn, '_ant_tool_spec') or getattr(fn, '_is_mcp_tool', False)
            rec('PASS' if has_ant else 'WARN',
                '{}: spec present'.format(fn.__name__),
                'Has ANT spec or _is_mcp_tool flag')
    except ImportError as e:
        rec('WARN', 'import wordpress_mcp',
            'Optional module not available: {} — WP tools disabled'.format(str(e)[:80]))
    except Exception as e:
        rec('FAIL', 'import wordpress_mcp', str(e))


# ══════════════════════════════════════════════════════════════════════════════
# RUNNER
# ══════════════════════════════════════════════════════════════════════════════

GROUPS = [
    test_generic_linux_command,
    test_file_tools,
    test_log_analyzer,
    test_js_secret_hunter,
    test_nuclei_scan,
    test_network_tools,
    test_wordpress_tools,
]

def main():
    print('\n' + '='*60)
    print('  CyberINK — Agent Tool Test Suite')
    print('  Platform : {}'.format(platform.system()))
    print('  Net tests: {}'.format('YES (--net)' if RUN_NET else 'NO  (pass --net to enable)'))
    print('  Nuclei   : {}'.format('YES (--nuclei)' if RUN_NUCLEI else 'NO  (pass --nuclei to enable)'))
    if RUN_NET:
        print('  Target   : {}'.format(TARGET))
    print('='*60)

    for fn in GROUPS:
        try:
            fn()
        except Exception as e:
            rec('FAIL', fn.__name__, 'Group raised exception: {}'.format(e))

    pass_n = sum(1 for r in results if r[0]=='PASS')
    warn_n = sum(1 for r in results if r[0]=='WARN')
    fail_n = sum(1 for r in results if r[0]=='FAIL')
    skip_n = sum(1 for r in results if r[0]=='SKIP')
    info_n = sum(1 for r in results if r[0]=='INFO')

    print('\n' + '-'*60)
    print('  Full Results')
    print('-'*60)
    for level, name, detail in results:
        print('{} [{}]{}'.format(tag(level), name,
                                  ' — '+detail if detail else ''))

    print('\n' + '-'*60)
    print('  Results: {} passed  |  {} warnings  |  {} failures  |  {} skipped  |  {} info'.format(
        pass_n, warn_n, fail_n, skip_n, info_n))
    print('-'*60 + '\n')
    sys.exit(1 if fail_n > 0 else 0)

if __name__ == '__main__':
    main()
