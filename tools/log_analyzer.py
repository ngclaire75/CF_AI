"""CF_AI — Web server access log fetcher, parser, and anomaly detector.

Fetches real access logs from connected servers (SSH) or probes observable
HTTP behaviour when only a URL is available.  Never returns hardcoded data —
every result is derived from the actual target.
"""
from __future__ import annotations
import re
import json
import time
import urllib.request
import urllib.parse
import urllib.error
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional

# ── Log-line regex (Combined Log Format — Apache / Nginx / Caddy) ─────────────
_CLF_RE = re.compile(
    r'(?P<ip>\S+)\s+'           # client IP
    r'\S+\s+\S+\s+'             # ident / auth (usually -)
    r'\[(?P<time>[^\]]+)\]\s+'  # [timestamp]
    r'"(?P<method>[A-Z]+)\s+'   # "METHOD
    r'(?P<path>\S+)\s+'         # /path
    r'HTTP/\S+"\s+'             # HTTP/version"
    r'(?P<status>\d{3})\s+'     # status code
    r'(?P<bytes>\S+)'           # bytes (may be -)
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?',  # optional referer + UA
)

# ── Timestamp formats seen in access logs ─────────────────────────────────────
_TS_FORMATS = [
    '%d/%b/%Y:%H:%M:%S %z',   # Apache default
    '%d/%b/%Y:%H:%M:%S',
]

# ── Malicious pattern signatures ──────────────────────────────────────────────
_SQLI_RE  = re.compile(r"(union\s+select|select\s+.+from|'\s*or\s+'|--\s*$|1=1|sleep\(|benchmark\(|information_schema)", re.I)
_XSS_RE   = re.compile(r"(<script|javascript:|on(load|error|click|mouseover)\s*=|alert\s*\()", re.I)
_TRAV_RE  = re.compile(r"\.\./|%2e%2e|%252e|\.\.%2f", re.I)
_SHELL_RE = re.compile(r"(cmd\.exe|/bin/(bash|sh)|wget\s+http|curl\s+http|eval\(base64)", re.I)
_SCAN_UA  = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|ffuf|wfuzz|acunetix|nessus|openvas|qualys|rapid7|metasploit|python-requests|go-http-client/1\.1$)", re.I)
_BRUTE_PATHS = {'/wp-login.php', '/admin', '/login', '/signin', '/administrator', '/wp-admin/admin-ajax.php'}
_PROBE_PATHS = re.compile(r'/(\.env|\.git|config\.php|phpinfo\.php|wp-config\.php|admin\.php|shell\.php|\.htaccess|backup|\.bak|\.sql)', re.I)


def _parse_ts(raw: str) -> Optional[datetime]:
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    return None


def parse_log_lines(raw: str) -> list[dict]:
    """Parse Combined Log Format lines into structured dicts."""
    records = []
    for line in raw.splitlines():
        m = _CLF_RE.match(line.strip())
        if not m:
            continue
        ts = _parse_ts(m.group('time'))
        records.append({
            'ip':     m.group('ip'),
            'ts':     ts.isoformat() if ts else m.group('time'),
            'ts_obj': ts,
            'method': m.group('method'),
            'path':   m.group('path'),
            'status': int(m.group('status')),
            'bytes':  m.group('bytes'),
            'ua':     (m.group('ua') or '').strip(),
        })
    return records


def detect_patterns(records: list[dict]) -> list[dict]:
    """Detect anomalies in parsed log records.  Returns list of finding dicts."""
    findings = []
    if not records:
        return findings

    # Group by IP for rate-based checks
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_ip[r['ip']].append(r)

    for ip, reqs in by_ip.items():
        if ip in ('127.0.0.1', '::1', '-'):
            continue

        # Brute-force: many requests to login paths
        brute = [r for r in reqs if r['path'].split('?')[0] in _BRUTE_PATHS]
        if len(brute) >= 5:
            findings.append({
                'type':     'BRUTE_FORCE',
                'severity': 'HIGH',
                'ip':       ip,
                'count':    len(brute),
                'detail':   f'{len(brute)} login attempts from {ip}',
                'paths':    list({r["path"] for r in brute})[:5],
            })

        # Vulnerability scanner UA
        scan_reqs = [r for r in reqs if _SCAN_UA.search(r.get('ua', ''))]
        if scan_reqs:
            findings.append({
                'type':     'SCANNER_DETECTED',
                'severity': 'HIGH',
                'ip':       ip,
                'count':    len(scan_reqs),
                'detail':   f'Scanner UA detected from {ip}: {scan_reqs[0]["ua"][:80]}',
                'paths':    [],
            })

        # High request rate (>100 reqs in any 60-second window)
        if len(reqs) > 100:
            ts_list = sorted([r['ts_obj'] for r in reqs if r['ts_obj']])
            if ts_list:
                for i in range(len(ts_list)):
                    window = [t for t in ts_list[i:] if (t - ts_list[i]).total_seconds() <= 60]
                    if len(window) >= 100:
                        findings.append({
                            'type':     'HIGH_REQUEST_RATE',
                            'severity': 'MEDIUM',
                            'ip':       ip,
                            'count':    len(window),
                            'detail':   f'{len(window)} requests in 60s from {ip}',
                            'paths':    [],
                        })
                        break

        # Injection attempts in paths
        inj = [r for r in reqs if _SQLI_RE.search(r['path']) or _XSS_RE.search(r['path'])]
        if inj:
            for r in inj[:3]:
                sev = 'HIGH' if _SQLI_RE.search(r['path']) else 'MEDIUM'
                kind = 'SQL_INJECTION' if _SQLI_RE.search(r['path']) else 'XSS_ATTEMPT'
                findings.append({
                    'type': kind, 'severity': sev, 'ip': ip, 'count': 1,
                    'detail': f'{kind} attempt: {r["path"][:120]}', 'paths': [r['path']],
                })

        # Path traversal
        trav = [r for r in reqs if _TRAV_RE.search(r['path'])]
        if trav:
            findings.append({
                'type': 'PATH_TRAVERSAL', 'severity': 'HIGH', 'ip': ip,
                'count': len(trav),
                'detail': f'Path traversal from {ip}: {trav[0]["path"][:80]}',
                'paths': [r['path'] for r in trav[:3]],
            })

        # Sensitive file probes (.env, .git, backups)
        probes = [r for r in reqs if _PROBE_PATHS.search(r['path'])]
        if probes:
            findings.append({
                'type': 'SENSITIVE_FILE_PROBE', 'severity': 'MEDIUM', 'ip': ip,
                'count': len(probes),
                'detail': f'Sensitive file probes from {ip}',
                'paths': list({r['path'] for r in probes})[:5],
            })

        # Shell/command injection in URIs
        shell = [r for r in reqs if _SHELL_RE.search(r['path'])]
        if shell:
            findings.append({
                'type': 'COMMAND_INJECTION', 'severity': 'HIGH', 'ip': ip,
                'count': len(shell),
                'detail': f'Command injection attempt from {ip}: {shell[0]["path"][:80]}',
                'paths': [r['path'] for r in shell[:3]],
            })

    return findings


def get_field_stats(records: list[dict]) -> dict:
    """Compute field-level statistics from parsed log records."""
    if not records:
        return {}

    status_counts  = Counter(r['status'] for r in records)
    method_counts  = Counter(r['method'] for r in records)
    ip_counts      = Counter(r['ip'] for r in records)
    path_counts    = Counter(r['path'].split('?')[0] for r in records)
    ua_counts      = Counter(r['ua'][:60] for r in records if r['ua'])

    error_rate = round(
        sum(v for k, v in status_counts.items() if k >= 400) / max(len(records), 1) * 100, 1
    )

    return {
        'total_requests': len(records),
        'error_rate_pct': error_rate,
        'status_codes':   dict(status_counts.most_common(10)),
        'http_methods':   dict(method_counts.most_common()),
        'top_ips':        dict(ip_counts.most_common(10)),
        'top_paths':      dict(path_counts.most_common(10)),
        'top_uas':        dict(ua_counts.most_common(5)),
        'unique_ips':     len(ip_counts),
        'unique_paths':   len(path_counts),
    }


def build_timeline(records: list[dict], buckets: int = 20) -> list[dict]:
    """Build a time-bucketed request/error timeline."""
    ts_list = [r for r in records if r.get('ts_obj')]
    if not ts_list:
        return []

    ts_list.sort(key=lambda r: r['ts_obj'])
    t_min = ts_list[0]['ts_obj']
    t_max = ts_list[-1]['ts_obj']
    total_secs = max((t_max - t_min).total_seconds(), 1)
    bucket_secs = total_secs / buckets

    timeline = []
    for i in range(buckets):
        t_start = t_min.timestamp() + i * bucket_secs
        t_end   = t_start + bucket_secs
        bucket_recs = [r for r in ts_list
                       if t_start <= r['ts_obj'].timestamp() < t_end]
        if not bucket_recs and i < buckets - 1:
            continue
        errors  = sum(1 for r in bucket_recs if r['status'] >= 400)
        label   = datetime.fromtimestamp(t_start, tz=timezone.utc).strftime('%H:%M')
        timeline.append({'t': label, 'total': len(bucket_recs), 'errors': errors})

    return timeline


# ── Threat intelligence (free APIs, no key required) ─────────────────────────

_threat_cache: dict[str, dict] = {}
_threat_cache_ts: dict[str, float] = {}
_THREAT_TTL = 3600  # 1 hour


def _urlhaus_check(ip_or_host: str) -> dict:
    """Check an IP/host against URLhaus (abuse.ch) — free, no key."""
    try:
        data = urllib.parse.urlencode({'host': ip_or_host}).encode()
        req  = urllib.request.Request(
            'https://urlhaus-api.abuse.ch/v1/host/',
            data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        with urllib.request.urlopen(req, timeout=6) as r:
            j = json.loads(r.read().decode())
        if j.get('query_status') == 'is_host':
            urls = j.get('urls', [])
            active = [u for u in urls if u.get('url_status') == 'online']
            return {
                'listed':      True,
                'threat':      'malware_distribution',
                'url_count':   len(urls),
                'active_urls': len(active),
                'source':      'URLhaus',
            }
        return {'listed': False}
    except Exception:
        return {}


def _vt_ip_check(ip: str) -> dict:
    """VirusTotal IP lookup (uses VT_KEY env var if set)."""
    import os
    key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if not key:
        return {}
    try:
        req = urllib.request.Request(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
            headers={'x-apikey': key},
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            j = json.loads(r.read().decode())
        stats = j.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        if malicious or suspicious:
            return {
                'listed':     True,
                'malicious':  malicious,
                'suspicious': suspicious,
                'source':     'VirusTotal',
            }
        return {'listed': False}
    except Exception:
        return {}


def enrich_ips(ips: list[str]) -> dict[str, dict]:
    """Threat-intel lookup for a list of IPs — parallel, cached."""
    result: dict[str, dict] = {}
    now = time.time()
    to_fetch = []
    for ip in ips:
        if ip in _threat_cache and now - _threat_cache_ts.get(ip, 0) < _THREAT_TTL:
            result[ip] = _threat_cache[ip]
        else:
            to_fetch.append(ip)

    def _check(ip):
        # URLhaus first (no key), VT second (key required)
        uh = _urlhaus_check(ip)
        if uh.get('listed'):
            return ip, uh
        vt = _vt_ip_check(ip)
        if vt.get('listed'):
            return ip, vt
        return ip, {'listed': False}

    if to_fetch:
        with ThreadPoolExecutor(max_workers=min(len(to_fetch), 8)) as pool:
            for ip, info in pool.map(_check, to_fetch):
                _threat_cache[ip] = info
                _threat_cache_ts[ip] = now
                result[ip] = info

    return result


# ── SSH log fetcher ───────────────────────────────────────────────────────────

def _ssh_fetch_logs(host: str, user: str, password: str, port: int = 22,
                    lines: int = 2000) -> tuple[str, str]:
    """Try to fetch Nginx/Apache access logs via SSH.

    Returns (log_content, log_path_used).  Returns ('', '') on failure.
    """
    import subprocess, shlex

    # Common log paths in priority order
    paths = [
        '/var/log/nginx/access.log',
        '/var/log/nginx/*.log',
        '/var/log/apache2/access.log',
        '/var/log/apache2/other_vhosts_access.log',
        '/var/log/httpd/access_log',
        '/var/log/httpd/access.log',
    ]

    # Build SSH command using sshpass if password given, ssh-key otherwise
    ssh_base = [
        'sshpass', '-e',
        'ssh', '-o', 'StrictHostKeyChecking=no',
        '-o', f'ConnectTimeout=10',
        '-p', str(port),
        f'{user}@{host}',
    ]
    env = {'SSHPASS': password} if password else None

    for path in paths:
        cmd = ssh_base + [f'tail -n {lines} {path} 2>/dev/null | head -n {lines}']
        try:
            import os
            run_env = os.environ.copy()
            if env:
                run_env.update(env)
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20, env=run_env)
            content = r.stdout.strip()
            if content and _CLF_RE.search(content):
                return content, path
        except Exception:
            continue
    return '', ''


def analyze_from_ssh(host: str, user: str, password: str, port: int = 22) -> dict:
    """Full log analysis pipeline using SSH to fetch real logs."""
    raw, log_path = _ssh_fetch_logs(host, user, password, port)
    if not raw:
        return {'error': 'Could not fetch logs via SSH — check credentials and log path permissions',
                'records': 0, 'log_path': ''}

    records   = parse_log_lines(raw)
    patterns  = detect_patterns(records)
    stats     = get_field_stats(records)
    timeline  = build_timeline(records)

    # Threat intel for top 20 external IPs
    top_ips = [ip for ip, _ in Counter(r['ip'] for r in records).most_common(20)
               if ip not in ('127.0.0.1', '::1', '-')]
    threat_info = enrich_ips(top_ips)

    # Mark findings with threat intel
    for f in patterns:
        ti = threat_info.get(f.get('ip', ''), {})
        if ti.get('listed'):
            f['threat_intel'] = ti
            f['severity'] = 'HIGH'

    return {
        'log_path':    log_path,
        'records':     len(records),
        'timeline':    timeline,
        'patterns':    patterns,
        'stats':       stats,
        'threat_info': {ip: v for ip, v in threat_info.items() if v.get('listed')},
        'sample_lines': raw.splitlines()[-20:],  # last 20 log lines for display
    }


def analyze_from_probe(domain: str) -> dict:
    """Observable HTTP behaviour analysis (no SSH) — probes the site directly."""
    import os

    results = {
        'log_path':   'N/A (HTTP probes — no SSH access)',
        'records':    0,
        'timeline':   [],
        'patterns':   [],
        'stats':      {},
        'threat_info': {},
        'probe_results': [],
    }

    probes = [
        ('GET', '/',              'Homepage'),
        ('GET', '/wp-login.php',  'WP login page'),
        ('GET', '/xmlrpc.php',    'XML-RPC endpoint'),
        ('GET', '/.env',          'ENV file exposure'),
        ('GET', '/.git/HEAD',     'Git HEAD exposure'),
        ('GET', '/wp-config.php', 'WP config exposure'),
        ('GET', '/admin',         'Admin panel'),
        ('GET', '/phpmyadmin',    'phpMyAdmin'),
        ('GET', '/readme.html',   'WP readme'),
        ('OPTIONS', '/',          'OPTIONS method'),
    ]

    ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    probe_results = []

    def _probe(method, path, label):
        url = f'https://{domain}{path}'
        try:
            req = urllib.request.Request(url, method=method,
                                         headers={'User-Agent': ua})
            with urllib.request.urlopen(req, timeout=8) as r:
                status = r.status
                hdrs   = dict(r.headers)
        except urllib.error.HTTPError as e:
            status = e.code
            hdrs   = dict(e.headers) if e.headers else {}
        except Exception as e:
            return {'label': label, 'path': path, 'method': method,
                    'status': 0, 'error': str(e)[:60]}

        finding = None
        sev     = 'INFO'
        if status == 200 and path in ('/.env', '/.git/HEAD', '/wp-config.php'):
            finding = f'CRITICAL: {label} is publicly accessible!'
            sev = 'HIGH'
        elif status == 200 and path in ('/xmlrpc.php', '/phpmyadmin'):
            finding = f'{label} is accessible (potential attack surface)'
            sev = 'MEDIUM'
        elif method == 'OPTIONS':
            allowed = hdrs.get('Allow', hdrs.get('allow', ''))
            if allowed:
                finding = f'Allowed HTTP methods: {allowed}'
                sev = 'INFO' if 'PUT' not in allowed and 'DELETE' not in allowed else 'MEDIUM'

        entry = {'label': label, 'path': path, 'method': method,
                 'status': status, 'severity': sev}
        if finding:
            entry['finding'] = finding
        return entry

    with ThreadPoolExecutor(max_workers=len(probes)) as pool:
        futures = {pool.submit(_probe, m, p, l): (m, p, l) for m, p, l in probes}
        for fut in as_completed(futures):
            probe_results.append(fut.result())

    probe_results.sort(key=lambda x: {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}.get(x.get('severity', 'INFO'), 3))
    results['probe_results'] = probe_results
    results['records'] = len([p for p in probe_results if p.get('status', 0) > 0])

    return results


# ── APM / Monitoring — latency, system metrics, auth anomalies ────────────────

_LATENCY_PATHS = ['/', '/robots.txt', '/favicon.ico', '/sitemap.xml']


def check_latency(domain: str, paths: list[str] = None) -> list[dict]:
    """Probe HTTP response times for APM latency monitoring."""
    ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    targets = paths or _LATENCY_PATHS

    def _measure(path):
        url = f'https://{domain}{path}'
        try:
            t0  = time.time()
            req = urllib.request.Request(url, headers={'User-Agent': ua})
            with urllib.request.urlopen(req, timeout=10) as r:
                status = r.status
            ms = round((time.time() - t0) * 1000, 1)
            spike = ms > 2000
            return {'path': path, 'status': status, 'latency_ms': ms,
                    'spike': spike, 'severity': 'HIGH' if ms > 3000 else 'MEDIUM' if spike else 'OK'}
        except urllib.error.HTTPError as e:
            ms = round((time.time() - t0) * 1000, 1)
            return {'path': path, 'status': e.code, 'latency_ms': ms, 'spike': False, 'severity': 'OK'}
        except Exception as e:
            return {'path': path, 'status': 0, 'latency_ms': -1, 'spike': False,
                    'severity': 'ERROR', 'error': str(e)[:60]}

    with ThreadPoolExecutor(max_workers=len(targets)) as pool:
        results = list(pool.map(_measure, targets))

    return results


def check_system_metrics(host: str, user: str, password: str,
                         port: int = 22) -> dict:
    """Fetch CPU, memory, disk, load, and recent auth events via SSH."""
    import subprocess, os

    commands = {
        'cpu_load':     "uptime | awk -F'load average:' '{print $2}' | tr -d ' '",
        'memory':       "free -m | awk 'NR==2{printf \"{\\\"total\\\":%s,\\\"used\\\":%s,\\\"free\\\":%s}\", $2, $3, $4}'",
        'disk':         "df -h / | tail -1 | awk '{printf \"{\\\"size\\\":\\\"%s\\\",\\\"used\\\":\\\"%s\\\",\\\"avail\\\":\\\"%s\\\",\\\"pct\\\":\\\"%s\\\"}\", $2, $3, $4, $5}'",
        'top_procs':    "ps aux --sort=-%cpu | awk 'NR>1 && NR<=6 {printf \"%s %.1f%% CPU %.1f%% MEM\\n\", $11, $3, $4}'",
        'auth_fails':   "grep -iE 'failed|invalid|refused' /var/log/auth.log 2>/dev/null | tail -20 || journalctl -u sshd --no-pager -n 20 2>/dev/null | grep -iE 'failed|invalid'",
        'open_ports':   "ss -tlnp 2>/dev/null | awk 'NR>1{print $4, $6}' | head -20",
        'error_log':    "tail -20 /var/log/nginx/error.log 2>/dev/null || tail -20 /var/log/apache2/error.log 2>/dev/null || echo '(no error log found)'",
    }

    ssh_base = ['sshpass', '-e', 'ssh', '-o', 'StrictHostKeyChecking=no',
                '-o', 'ConnectTimeout=10', '-p', str(port), f'{user}@{host}']
    run_env = os.environ.copy()
    if password:
        run_env['SSHPASS'] = password

    results = {}
    for key, cmd in commands.items():
        try:
            full_cmd = ssh_base + [cmd]
            r = subprocess.run(full_cmd, capture_output=True, text=True,
                               timeout=15, env=run_env)
            results[key] = r.stdout.strip() or r.stderr.strip()[:100]
        except Exception as e:
            results[key] = f'error: {e}'

    # Parse auth failures into structured anomaly list
    auth_raw = results.get('auth_fails', '')
    auth_anomalies = []
    for line in auth_raw.splitlines():
        if any(kw in line.lower() for kw in ('failed', 'invalid', 'refused')):
            auth_anomalies.append({'event': line.strip()[:120], 'type': 'AUTH_FAILURE'})
    results['auth_anomalies'] = auth_anomalies[:15]
    results['auth_anomaly_count'] = len(auth_anomalies)

    # Parse memory JSON safely
    try:
        import json as _j
        mem = _j.loads(results.get('memory', '{}'))
        pct = round(mem.get('used', 0) / max(mem.get('total', 1), 1) * 100, 1)
        results['memory_parsed'] = {**mem, 'used_pct': pct,
                                    'spike': pct > 85}
    except Exception:
        results['memory_parsed'] = {}

    return results


def check_error_rate(records: list[dict], window_minutes: int = 60) -> dict:
    """Detect error surges in recent log window vs historical baseline."""
    if not records:
        return {'surge': False, 'rate_pct': 0.0, 'recent_errors': 0, 'baseline_pct': 0.0}

    now_ts = max((r['ts_obj'].timestamp() for r in records if r.get('ts_obj')), default=0)
    window_secs = window_minutes * 60
    recent  = [r for r in records if r.get('ts_obj') and now_ts - r['ts_obj'].timestamp() <= window_secs]
    older   = [r for r in records if r.get('ts_obj') and now_ts - r['ts_obj'].timestamp() > window_secs]

    recent_errors   = sum(1 for r in recent if r['status'] >= 400)
    recent_rate     = round(recent_errors / max(len(recent), 1) * 100, 1)
    baseline_errors = sum(1 for r in older if r['status'] >= 400)
    baseline_rate   = round(baseline_errors / max(len(older), 1) * 100, 1)

    surge = recent_rate > baseline_rate * 2 and recent_errors >= 5

    return {
        'surge':          surge,
        'rate_pct':       recent_rate,
        'baseline_pct':   baseline_rate,
        'recent_errors':  recent_errors,
        'recent_total':   len(recent),
        'severity':       'HIGH' if surge and recent_rate > 20 else 'MEDIUM' if surge else 'OK',
    }
