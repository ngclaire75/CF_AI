"""
CyberINK — Static Code Analysis Test
No dependencies required. Just run: python static_analysis_test.py
Scans source files for security issues without running the app.
"""

import os
import re
import sys

# ── Config ────────────────────────────────────────────────────────────────────
ROOT      = os.path.dirname(os.path.abspath(__file__))
SCAN_DIRS = [os.path.join(ROOT, 'dashboard')]
SCAN_EXTS = {'.py', '.html', '.js'}

PASS = '\033[92m[PASS]\033[0m'
FAIL = '\033[91m[FAIL]\033[0m'
WARN = '\033[93m[WARN]\033[0m'
INFO = '\033[94m[INFO]\033[0m'

findings = []

def record(level, check, detail, file_=None, line=None):
    loc = ' ({}:{})'.format(os.path.relpath(file_, ROOT), line) if file_ else ''
    findings.append((level, check, detail + loc))

def collect_files():
    out = []
    for d in SCAN_DIRS:
        for root, _, files in os.walk(d):
            for f in files:
                if os.path.splitext(f)[1] in SCAN_EXTS:
                    out.append(os.path.join(root, f))
    return out

def read_lines(path):
    try:
        with open(path, encoding='utf-8', errors='ignore') as fh:
            return fh.readlines()
    except OSError:
        return []

# ── Checks ────────────────────────────────────────────────────────────────────

def check_hardcoded_secrets(files):
    patterns = [
        (r'sk-ant-api[0-9A-Za-z\-]+',           'Anthropic API key literal'),
        (r'AIza[0-9A-Za-z\-_]{35}',              'Google API key literal'),
        (r'(?i)password\s*=\s*["\'][^"\']{4,}',  'Hardcoded password assignment'),
        (r'(?i)secret_key\s*=\s*["\'][^"\']{4,}','Hardcoded Flask secret key'),
        (r'(?i)smtp_pass\w*\s*=\s*["\'][^"\']{4,}','Hardcoded SMTP password'),
    ]
    for path in files:
        if not path.endswith('.py'):
            continue
        for i, line in enumerate(read_lines(path), 1):
            if line.strip().startswith('#'):
                continue
            for pattern, label in patterns:
                if re.search(pattern, line):
                    record('FAIL', 'Hardcoded Secret', label, path, i)

def check_dangerous_functions(files):
    patterns = [
        (r'\beval\s*\(',                    'eval() — code execution risk'),
        (r'\bexec\s*\(',                    'exec() — code execution risk'),
        (r'\bos\.system\s*\(',             'os.system() — command injection risk'),
        (r'subprocess.*shell\s*=\s*True',  'subprocess shell=True — injection risk'),
        (r'pickle\.loads?\s*\(',           'pickle.load() — deserialization risk'),
        (r'yaml\.load\s*\([^,)]+\)',       'yaml.load() without Loader — use yaml.safe_load'),
    ]
    for path in files:
        if not path.endswith('.py'):
            continue
        for i, line in enumerate(read_lines(path), 1):
            if line.strip().startswith('#'):
                continue
            for pattern, label in patterns:
                if re.search(pattern, line):
                    record('FAIL', 'Dangerous Function', label, path, i)

def check_debug_mode(files):
    for path in files:
        if not path.endswith('.py'):
            continue
        for i, line in enumerate(read_lines(path), 1):
            if re.search(r'app\.run\(.*debug\s*=\s*True', line):
                record('FAIL', 'Debug Mode', 'Flask debug=True in production', path, i)

def check_secret_key_strength(files):
    for path in files:
        if not path.endswith('.py'):
            continue
        for i, line in enumerate(read_lines(path), 1):
            m = re.search(r'SECRET_KEY["\']?\s*[=:]\s*["\']([^"\']+)["\']', line)
            if m:
                key = m.group(1)
                if len(key) < 24:
                    record('FAIL', 'Weak Secret Key',
                           'SECRET_KEY too short ({} chars, need >=24)'.format(len(key)), path, i)
                else:
                    record('PASS', 'Secret Key Length',
                           'SECRET_KEY length OK ({} chars)'.format(len(key)))

def check_sql_injection(files):
    patterns = [
        r'execute\s*\(\s*[f"\'].*%[s\d]',
        r'execute\s*\(\s*f["\']',
        r'execute\s*\(\s*"[^"]*"\s*%',
        r'execute\s*\(\s*\'[^\']*\'\s*%',
    ]
    for path in files:
        if not path.endswith('.py'):
            continue
        for i, line in enumerate(read_lines(path), 1):
            if line.strip().startswith('#'):
                continue
            for pattern in patterns:
                if re.search(pattern, line):
                    record('FAIL', 'SQL Injection', 'String-formatted SQL query', path, i)

def check_xss_jinja(files):
    for path in files:
        if not path.endswith('.html'):
            continue
        for i, line in enumerate(read_lines(path), 1):
            if re.search(r'\{\{.*\|\s*safe', line):
                record('WARN', 'XSS Risk', 'Jinja2 |safe filter — ensure value is sanitised', path, i)

def check_open_redirect(files):
    for path in files:
        if not path.endswith('.py'):
            continue
        for i, line in enumerate(read_lines(path), 1):
            if re.search(r'redirect\s*\(.*request\.(args|form|values|json)', line):
                record('WARN', 'Open Redirect', 'redirect() with user-supplied URL', path, i)

def check_path_traversal(files):
    for path in files:
        if not path.endswith('.py'):
            continue
        for i, line in enumerate(read_lines(path), 1):
            if re.search(r'open\s*\(.*request\.(args|form|values|json)', line):
                record('FAIL', 'Path Traversal', 'open() with user-supplied path', path, i)

def check_cookie_flags(files):
    found_secure   = False
    found_httponly = False
    for path in files:
        if not path.endswith('.py'):
            continue
        full = ''.join(read_lines(path))
        if 'SESSION_COOKIE_SECURE' in full and 'True' in full:
            found_secure = True
        if 'SESSION_COOKIE_HTTPONLY' in full and 'True' in full:
            found_httponly = True
    record('PASS' if found_secure   else 'WARN', 'Cookie Secure Flag',
           'SESSION_COOKIE_SECURE = True found' if found_secure
           else 'SESSION_COOKIE_SECURE not set — cookies sent over HTTP')
    record('PASS' if found_httponly else 'WARN', 'Cookie HttpOnly Flag',
           'SESSION_COOKIE_HTTPONLY = True found' if found_httponly
           else 'SESSION_COOKIE_HTTPONLY not set — JS can read session cookie')

def check_env_usage(files):
    uses_env = any(
        'os.environ' in ''.join(read_lines(p)) or 'load_dotenv' in ''.join(read_lines(p))
        for p in files if p.endswith('.py')
    )
    record('PASS' if uses_env else 'WARN', 'Env Config',
           'Secrets loaded from environment / .env' if uses_env
           else 'No os.environ / dotenv usage detected — are secrets hardcoded?')

def check_gitignore(files):
    gi_path = os.path.join(ROOT, '.gitignore')
    if not os.path.exists(gi_path):
        record('FAIL', '.gitignore', '.gitignore not found')
        return
    with open(gi_path) as fh:
        gi = fh.read()
    for item in ['.env', 'data/']:
        if item in gi:
            record('PASS', '.gitignore', '{} excluded from git'.format(item))
        else:
            record('FAIL', '.gitignore', '{} NOT in .gitignore — risk of committing secrets'.format(item))

def check_admin_auth(files):
    for path in files:
        if not path.endswith('.py'):
            continue
        lines = read_lines(path)
        for i, line in enumerate(lines):
            if re.search(r'@app\.route\(.*/admin', line):
                block = ''.join(lines[i:i+8])
                if 'role' not in block and "'admin'" not in block:
                    record('WARN', 'Admin Auth',
                           'Admin route may be missing role check', path, i + 1)

# ── Runner ────────────────────────────────────────────────────────────────────

def main():
    print('\n' + '=' * 60)
    print('  CyberINK — Static Code Analysis')
    print('=' * 60)

    all_files = collect_files()
    print('{} Scanning {} files\n'.format(INFO, len(all_files)))

    check_hardcoded_secrets(all_files)
    check_dangerous_functions(all_files)
    check_debug_mode(all_files)
    check_secret_key_strength(all_files)
    check_sql_injection(all_files)
    check_xss_jinja(all_files)
    check_open_redirect(all_files)
    check_path_traversal(all_files)
    check_cookie_flags(all_files)
    check_env_usage(all_files)
    check_gitignore(all_files)
    check_admin_auth(all_files)

    pass_n = sum(1 for f in findings if f[0] == 'PASS')
    warn_n = sum(1 for f in findings if f[0] == 'WARN')
    fail_n = sum(1 for f in findings if f[0] == 'FAIL')

    for level, check, detail in findings:
        tag = PASS if level == 'PASS' else (WARN if level == 'WARN' else FAIL)
        print('{} [{}] {}'.format(tag, check, detail))

    print('\n' + '-' * 60)
    print('  Results: {} passed  |  {} warnings  |  {} failures'.format(pass_n, warn_n, fail_n))
    print('-' * 60 + '\n')
    sys.exit(1 if fail_n > 0 else 0)

if __name__ == '__main__':
    main()
