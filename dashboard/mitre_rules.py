"""CF_AI — MITRE ATT&CK detection rules engine.

Maps scan findings to MITRE ATT&CK tactics and techniques.
Rules are evaluated against scan output text — no hardcoded results.
"""
from __future__ import annotations
import re
from typing import Optional

# ── MITRE ATT&CK Tactic ordering ──────────────────────────────────────────────
TACTICS = [
    ('TA0043', 'Reconnaissance'),
    ('TA0001', 'Initial Access'),
    ('TA0002', 'Execution'),
    ('TA0003', 'Persistence'),
    ('TA0004', 'Privilege Escalation'),
    ('TA0005', 'Defense Evasion'),
    ('TA0006', 'Credential Access'),
    ('TA0007', 'Discovery'),
    ('TA0008', 'Lateral Movement'),
    ('TA0009', 'Collection'),
    ('TA0011', 'Command and Control'),
    ('TA0010', 'Exfiltration'),
    ('TA0040', 'Impact'),
]

TACTIC_IDS = {name: tid for tid, name in TACTICS}

# ── Detection rules — each rule matches one or more MITRE techniques ──────────
DETECTION_RULES: list[dict] = [
    # ── Reconnaissance ─────────────────────────────────────────────────────
    # Patterns match ACTUAL findings in agent output, not test descriptions.
    # Agents emit specific markers when something is confirmed (e.g. "REFLECTED XSS:", "SQL ERROR:").
    {
        'id': 'CF-R001', 'severity': 'LOW',
        'title': 'Open Ports Discovered',
        'tactic': 'Reconnaissance', 'tactic_id': 'TA0043',
        'technique': 'T1595', 'technique_name': 'Active Scanning',
        'patterns': [r'\d+/tcp\s+open', r'\d+/udp\s+open', r'open\s+port\s+\d+.*found', r'Shodan.*ports.*\[\d'],
        'desc': 'Target has open network ports discovered via active port scan.',
        'source': 'Recon Scout',
    },
    {
        'id': 'CF-R002', 'severity': 'INFO',
        'title': 'Subdomains / OSINT Data Found',
        'tactic': 'Reconnaissance', 'tactic_id': 'TA0043',
        'technique': 'T1596', 'technique_name': 'Search Open Technical Databases',
        'patterns': [r'\[crt\.sh\]\s+\S+\.\S+', r'\[certspotter\]\s+\S+\.\S+', r'\[jldc\.me\]', r'Shodan\s+hostnames:.*\['],
        'desc': 'Subdomains or OSINT data found in public databases (crt.sh, certspotter, Shodan).',
        'source': 'Recon Scout',
    },
    # ── Initial Access ─────────────────────────────────────────────────────
    {
        'id': 'CF-I001', 'severity': 'HIGH',
        'title': 'Injection Vulnerability Confirmed',
        'tactic': 'Initial Access', 'tactic_id': 'TA0001',
        'technique': 'T1190', 'technique_name': 'Exploit Public-Facing Application',
        'patterns': [r'SQL\s+ERROR:', r'CODE\s+INJECTION\s+CONFIRMED:', r'CMD\s+INJECTION:', r'SSTI\s+HIT', r'SSRF\s+HIT:'],
        'desc': 'Active injection vulnerability confirmed: SQL injection, command injection, SSTI, or SSRF.',
        'source': 'Injection Hunter',
    },
    {
        'id': 'CF-I002', 'severity': 'HIGH',
        'title': 'Credentials or API Keys Exposed',
        'tactic': 'Initial Access', 'tactic_id': 'TA0001',
        'technique': 'T1078', 'technique_name': 'Valid Accounts',
        'patterns': [r'CREDS_FOUND', r'FOUND_DB_USER:', r'FOUND_ENV_USER:', r'APP_PASS_CREATED', r'EXPOSED_FILE\s*\|.*\b20[0-9]\b'],
        'desc': 'Valid credentials or API keys found exposed in publicly accessible files.',
        'source': 'JS Intelligence Agent',
    },
    {
        'id': 'CF-I003', 'severity': 'MEDIUM',
        'title': 'WordPress Login Page Exposed',
        'tactic': 'Initial Access', 'tactic_id': 'TA0001',
        'technique': 'T1566', 'technique_name': 'Phishing',
        'patterns': [r'200\s+/wp-login\.php', r'wp-login\.php.*HTTP.*200', r'200\s+/wp-admin'],
        'desc': 'WordPress admin login page is publicly accessible.',
        'source': 'Auth Prober',
    },
    # ── Execution ──────────────────────────────────────────────────────────
    {
        'id': 'CF-E001', 'severity': 'HIGH',
        'title': 'Command / Code Injection Confirmed',
        'tactic': 'Execution', 'tactic_id': 'TA0002',
        'technique': 'T1059', 'technique_name': 'Command and Scripting Interpreter',
        'patterns': [r'CMD\s+INJECTION:', r'CODE\s+INJECTION\s+CONFIRMED:', r'uid=0\(root\)', r'uid=\d+\(\w+\).*gid='],
        'desc': 'Server-side command or code execution confirmed via injection.',
        'source': 'Injection Hunter',
    },
    {
        'id': 'CF-E002', 'severity': 'HIGH',
        'title': 'Server-Side Template Injection (SSTI) Confirmed',
        'tactic': 'Execution', 'tactic_id': 'TA0002',
        'technique': 'T1059.007', 'technique_name': 'JavaScript / Template Injection',
        'patterns': [r'SSTI\s+HIT\s*\(7\*7=49\)'],
        'desc': 'Template engine injection confirmed (7*7=49 evaluated server-side).',
        'source': 'Injection Hunter',
    },
    # ── Persistence ────────────────────────────────────────────────────────
    {
        'id': 'CF-P001', 'severity': 'HIGH',
        'title': 'Sensitive File or Shell Accessible',
        'tactic': 'Persistence', 'tactic_id': 'TA0003',
        'technique': 'T1505.003', 'technique_name': 'Web Shell',
        'patterns': [r'EXPOSED_FILE\s*\|.*\.php.*\b20[0-9]\b', r'EXPOSED_FILE\s*\|.*/wp-config'],
        'desc': 'A sensitive file (config, backup, or potential shell) was found accessible.',
        'source': 'Config Auditor',
    },
    {
        'id': 'CF-P002', 'severity': 'MEDIUM',
        'title': 'Admin Panel Accessible',
        'tactic': 'Persistence', 'tactic_id': 'TA0003',
        'technique': 'T1098', 'technique_name': 'Account Manipulation',
        'patterns': [r'200\s+/admin\b', r'200\s+/wp-admin\b', r'200\s+/phpmyadmin', r'API-ENDPOINT:.*200.*/admin'],
        'desc': 'Administrative panel accessible without confirmed authentication block.',
        'source': 'Config Auditor',
    },
    # ── Privilege Escalation ───────────────────────────────────────────────
    {
        'id': 'CF-PE001', 'severity': 'HIGH',
        'title': 'IDOR / Access Control Bypass Found',
        'tactic': 'Privilege Escalation', 'tactic_id': 'TA0004',
        'technique': 'T1548', 'technique_name': 'Abuse Elevation Control Mechanism',
        'patterns': [r'200\s+/api/(user|order|account|invoice)/\d+', r'HIT\s+PATH\s+TRAVERSAL'],
        'desc': 'Insecure direct object reference or path traversal allows unauthorized resource access.',
        'source': 'Access Control Tester',
    },
    {
        'id': 'CF-PE002', 'severity': 'HIGH',
        'title': 'WordPress Credentials Verified',
        'tactic': 'Privilege Escalation', 'tactic_id': 'TA0004',
        'technique': 'T1548.004', 'technique_name': 'Elevated Execution with Prompt',
        'patterns': [r'CREDS_FOUND_XMLRPC', r'CREDS_FOUND_FORM'],
        'desc': 'WordPress credentials confirmed via XML-RPC or login form.',
        'source': 'API Security Tester',
    },
    # ── Defense Evasion ────────────────────────────────────────────────────
    {
        'id': 'CF-DE001', 'severity': 'MEDIUM',
        'title': 'Security Headers Missing',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005',
        'technique': 'T1562', 'technique_name': 'Impair Defenses',
        'patterns': [r'\|\s*Medium\s*\|.*[Hh]eader', r'\|\s*Low\s*\|.*[Hh]eader', r'WP-LOG.*missing.*header'],
        'desc': 'Agent final report indicates missing security headers.',
        'source': 'Config Auditor',
    },
    {
        'id': 'CF-DE002', 'severity': 'LOW',
        'title': 'Debug Log Publicly Accessible',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005',
        'technique': 'T1070', 'technique_name': 'Indicator Removal',
        'patterns': [r'WP-LOG.*Debug log is publicly accessible', r'EXPOSED_FILE\s*\|.*debug\.log'],
        'desc': 'WordPress or application debug log is publicly accessible.',
        'source': 'Config Auditor',
    },
    # ── Credential Access ──────────────────────────────────────────────────
    {
        'id': 'CF-CA001', 'severity': 'HIGH',
        'title': 'Valid Credentials Found',
        'tactic': 'Credential Access', 'tactic_id': 'TA0006',
        'technique': 'T1110', 'technique_name': 'Brute Force',
        'patterns': [r'CREDS_FOUND_XMLRPC', r'CREDS_FOUND_FORM', r'WP-LOG.*credentials.*verified'],
        'desc': 'Valid credentials were confirmed via brute-force or exposed file.',
        'source': 'Auth Prober',
    },
    {
        'id': 'CF-CA002', 'severity': 'HIGH',
        'title': 'Config File with Credentials Exposed',
        'tactic': 'Credential Access', 'tactic_id': 'TA0006',
        'technique': 'T1552', 'technique_name': 'Unsecured Credentials',
        'patterns': [r'FOUND_DB_USER:', r'FOUND_ENV_USER:', r'FOUND_DB_PASS:', r'FOUND_ENV_PASS:'],
        'desc': 'Database or application credentials found in exposed configuration files.',
        'source': 'JS Intelligence Agent',
    },
    {
        'id': 'CF-CA003', 'severity': 'HIGH',
        'title': 'Application Password Auto-Created',
        'tactic': 'Credential Access', 'tactic_id': 'TA0006',
        'technique': 'T1078', 'technique_name': 'Valid Accounts',
        'patterns': [r'APP_PASS_CREATED'],
        'desc': 'Scanner auto-created a WordPress Application Password — credentials were verified.',
        'source': 'Auth Prober',
    },
    # ── Discovery ──────────────────────────────────────────────────────────
    {
        'id': 'CF-D001', 'severity': 'MEDIUM',
        'title': 'WordPress Users Enumerated',
        'tactic': 'Discovery', 'tactic_id': 'TA0007',
        'technique': 'T1087', 'technique_name': 'Account Discovery',
        'patterns': [r'WP-USER\s*\|', r'WP-USER-CONFIRMED', r'WP-USER-ENUM'],
        'desc': 'WordPress usernames enumerated via REST API or author redirect.',
        'source': 'Identity Mapper',
    },
    {
        'id': 'CF-D002', 'severity': 'LOW',
        'title': 'Sensitive File Discovered',
        'tactic': 'Discovery', 'tactic_id': 'TA0007',
        'technique': 'T1083', 'technique_name': 'File and Directory Discovery',
        'patterns': [r'EXPOSED_FILE\s*\|', r'EXPOSED:\s+/\.git', r'EXPOSED:\s+/\.env', r'EXPOSED:\s+.*backup'],
        'desc': 'Sensitive files or directories found accessible via probing.',
        'source': 'Config Auditor',
    },
    # ── Collection ─────────────────────────────────────────────────────────
    {
        'id': 'CF-C001', 'severity': 'HIGH',
        'title': 'XSS Vulnerability Confirmed',
        'tactic': 'Collection', 'tactic_id': 'TA0009',
        'technique': 'T1185', 'technique_name': 'Browser Session Hijacking',
        'patterns': [r'REFLECTED\s+XSS:', r'STORED\s+XSS:', r'HTML\s+INJECTION:'],
        'desc': 'XSS or HTML injection confirmed, enabling session token theft.',
        'source': 'Injection Hunter',
    },
    {
        'id': 'CF-C002', 'severity': 'MEDIUM',
        'title': 'WordPress Activity Logs Retrieved',
        'tactic': 'Collection', 'tactic_id': 'TA0009',
        'technique': 'T1213', 'technique_name': 'Data from Information Repositories',
        'patterns': [r'WP-LOG\s*\|.*\|\s*(HIGH|MEDIUM)', r'\[PHASE2\].*auth\s+SUCCEEDED'],
        'desc': 'WordPress activity log data successfully retrieved.',
        'source': 'API Security Tester',
    },
    # ── Command and Control ────────────────────────────────────────────────
    {
        'id': 'CF-CC001', 'severity': 'HIGH',
        'title': 'SSRF Confirmed',
        'tactic': 'Command and Control', 'tactic_id': 'TA0011',
        'technique': 'T1219', 'technique_name': 'Remote Access Software',
        'patterns': [r'SSRF\s+HIT:', r'ami-id|instance-id.*metadata'],
        'desc': 'Server-Side Request Forgery confirmed — internal metadata accessible.',
        'source': 'API Security Tester',
    },
    # ── Exfiltration ───────────────────────────────────────────────────────
    {
        'id': 'CF-EX001', 'severity': 'HIGH',
        'title': 'Database / Backup File Accessible',
        'tactic': 'Exfiltration', 'tactic_id': 'TA0010',
        'technique': 'T1048', 'technique_name': 'Exfiltration Over Alternative Protocol',
        'patterns': [r'EXPOSED_FILE\s*\|.*\.(sql|bak|dump|backup)\b', r'200\s+/backup\.sql', r'200\s+/database\.sql'],
        'desc': 'Database dump or backup file found publicly accessible.',
        'source': 'API Security Tester',
    },
    # ── Impact ─────────────────────────────────────────────────────────────
    {
        'id': 'CF-IM001', 'severity': 'HIGH',
        'title': 'Weak TLS / SSL Detected',
        'tactic': 'Impact', 'tactic_id': 'TA0040',
        'technique': 'T1486', 'technique_name': 'Data Encrypted for Impact',
        'patterns': [r'WEAK.*TLS|SSL.*2\.0|TLS.*1\.0.*WEAK|RC4|DES.*cipher|NULL\s+cipher|EXPORT.*cipher'],
        'desc': 'Weak cryptographic protocol or cipher suite detected by SSL scan.',
        'source': 'Crypto Inspector',
    },
    {
        'id': 'CF-IM002', 'severity': 'MEDIUM',
        'title': 'Open Redirect Confirmed',
        'tactic': 'Impact', 'tactic_id': 'TA0040',
        'technique': 'T1499', 'technique_name': 'Endpoint Denial of Service',
        'patterns': [r'OPEN\s+REDIRECT:'],
        'desc': 'Open redirect vulnerability confirmed — attacker can redirect users externally.',
        'source': 'Client-Side Analyst',
    },
]

# Pre-compile all patterns for performance
for _rule in DETECTION_RULES:
    _rule['_compiled'] = [re.compile(p, re.I) for p in _rule['patterns']]


def evaluate_rules(text: str, target: str = '') -> list[dict]:
    """Run all detection rules against scan text. Returns list of matched rules."""
    if not text:
        return []
    matched = []
    for rule in DETECTION_RULES:
        if any(pat.search(text) for pat in rule['_compiled']):
            matched.append({
                'id':               rule['id'],
                'severity':         rule['severity'],
                'title':            rule['title'],
                'tactic':           rule['tactic'],
                'tactic_id':        rule['tactic_id'],
                'technique':        rule['technique'],
                'technique_name':   rule['technique_name'],
                'desc':             rule['desc'],
                'source':           rule['source'],
                'target':           target,
            })
    return matched


def get_coverage(scan_results: list[dict]) -> dict:
    """Compute MITRE ATT&CK coverage from a list of scan result dicts.

    Returns {tactic_name: {count, rules_matched: [...]}} and overall totals.
    """
    all_matches: list[dict] = []
    seen_ids: set[str] = set()

    for s in scan_results:
        text = s.get('output', '')
        target = s.get('target', '')
        for match in evaluate_rules(text, target):
            key = f"{match['id']}:{target}"
            if key not in seen_ids:
                seen_ids.add(key)
                all_matches.append(match)

    tactic_map: dict[str, list[dict]] = {name: [] for _, name in TACTICS}
    for m in all_matches:
        if m['tactic'] in tactic_map:
            tactic_map[m['tactic']].append(m)

    coverage = {}
    for tid, tname in TACTICS:
        rules = tactic_map.get(tname, [])
        coverage[tname] = {
            'tactic_id': tid,
            'count':     len(rules),
            'rules':     rules,
        }

    sev_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for m in all_matches:
        sev_counts[m['severity']] = sev_counts.get(m['severity'], 0) + 1

    return {
        'tactics':    coverage,
        'total':      len(all_matches),
        'severities': sev_counts,
        'all_matches': all_matches,
    }
