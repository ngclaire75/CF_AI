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
    {
        'id': 'CF-R001', 'severity': 'LOW',
        'title': 'Active DNS & Port Scanning Detected',
        'tactic': 'Reconnaissance', 'tactic_id': 'TA0043',
        'technique': 'T1595', 'technique_name': 'Active Scanning',
        'patterns': [r'nmap|port\s*scan|open\s*port|service\s*version|fingerprint'],
        'desc': 'Target shows evidence of active reconnaissance including port scans and service enumeration.',
        'source': 'Recon Scout',
    },
    {
        'id': 'CF-R002', 'severity': 'INFO',
        'title': 'OSINT & Certificate Transparency Data Available',
        'tactic': 'Reconnaissance', 'tactic_id': 'TA0043',
        'technique': 'T1596', 'technique_name': 'Search Open Technical Databases',
        'patterns': [r'crt\.sh|shodan|certificate\s*transparency|wayback|archive\.org'],
        'desc': 'Domain information is indexed in public databases (crt.sh, Shodan, Wayback Machine).',
        'source': 'Recon Scout',
    },
    # ── Initial Access ─────────────────────────────────────────────────────
    {
        'id': 'CF-I001', 'severity': 'HIGH',
        'title': 'Exploit Public-Facing Application',
        'tactic': 'Initial Access', 'tactic_id': 'TA0001',
        'technique': 'T1190', 'technique_name': 'Exploit Public-Facing Application',
        'patterns': [r'sql\s*inject|union\s+select|rce|remote\s*code\s*exec|shell\s*upload|arbitrary\s*file|deserialization'],
        'desc': 'Vulnerability detected that could allow exploitation of the public-facing application.',
        'source': 'Injection Hunter',
    },
    {
        'id': 'CF-I002', 'severity': 'MEDIUM',
        'title': 'Valid Account Credential Exposure',
        'tactic': 'Initial Access', 'tactic_id': 'TA0001',
        'technique': 'T1078', 'technique_name': 'Valid Accounts',
        'patterns': [r'exposed.*credential|leaked.*password|api.*key.*exposed|\.env.*accessible|config.*password'],
        'desc': 'Valid credentials or API keys found exposed publicly.',
        'source': 'JS Intelligence Agent',
    },
    {
        'id': 'CF-I003', 'severity': 'MEDIUM',
        'title': 'Phishing-Ready Login Page',
        'tactic': 'Initial Access', 'tactic_id': 'TA0001',
        'technique': 'T1566', 'technique_name': 'Phishing',
        'patterns': [r'wp-login\.php.*exposed|login\s*form.*no\s*mfa|missing.*two.factor|no\s*captcha.*login'],
        'desc': 'Login page lacks anti-phishing controls (MFA, CAPTCHA, or rate limiting).',
        'source': 'Auth Prober',
    },
    # ── Execution ──────────────────────────────────────────────────────────
    {
        'id': 'CF-E001', 'severity': 'HIGH',
        'title': 'Command Injection / Server-Side Code Execution',
        'tactic': 'Execution', 'tactic_id': 'TA0002',
        'technique': 'T1059', 'technique_name': 'Command and Scripting Interpreter',
        'patterns': [r'command\s*inject|eval\s*\(|exec\s*\(|system\s*\(|passthru|shell_exec|/bin/bash|cmd\.exe'],
        'desc': 'Input vector accepts shell commands or server-side code execution is possible.',
        'source': 'Injection Hunter',
    },
    {
        'id': 'CF-E002', 'severity': 'HIGH',
        'title': 'Server-Side Template Injection (SSTI)',
        'tactic': 'Execution', 'tactic_id': 'TA0002',
        'technique': 'T1059.007', 'technique_name': 'JavaScript / Template Injection',
        'patterns': [r'ssti|template\s*inject|\{\{.*7\*7\}\}|\$\{7\*7\}|template.*render.*user'],
        'desc': 'Template engine injection detected, allowing arbitrary code execution.',
        'source': 'Injection Hunter',
    },
    # ── Persistence ────────────────────────────────────────────────────────
    {
        'id': 'CF-P001', 'severity': 'HIGH',
        'title': 'Web Shell or Backdoor Accessible',
        'tactic': 'Persistence', 'tactic_id': 'TA0003',
        'technique': 'T1505.003', 'technique_name': 'Web Shell',
        'patterns': [r'webshell|shell\.php|cmd\.php|c99\.php|r57\.php|b374k|backdoor.*accessible'],
        'desc': 'A web shell or backdoor file was found accessible on the server.',
        'source': 'Config Auditor',
    },
    {
        'id': 'CF-P002', 'severity': 'MEDIUM',
        'title': 'Exposed Admin Panel Without Protection',
        'tactic': 'Persistence', 'tactic_id': 'TA0003',
        'technique': 'T1098', 'technique_name': 'Account Manipulation',
        'patterns': [r'admin\s*panel.*accessible|wp-admin.*no.*auth|phpmyadmin.*exposed|/admin.*200'],
        'desc': 'Administrative panel accessible without adequate protection.',
        'source': 'Config Auditor',
    },
    # ── Privilege Escalation ───────────────────────────────────────────────
    {
        'id': 'CF-PE001', 'severity': 'HIGH',
        'title': 'Privilege Escalation via IDOR',
        'tactic': 'Privilege Escalation', 'tactic_id': 'TA0004',
        'technique': 'T1548', 'technique_name': 'Abuse Elevation Control Mechanism',
        'patterns': [r'idor|insecure.*direct.*object|horizontal.*privilege|vertical.*privilege|bola|bfla'],
        'desc': 'Insecure direct object reference allows accessing resources belonging to other users.',
        'source': 'Access Control Tester',
    },
    {
        'id': 'CF-PE002', 'severity': 'HIGH',
        'title': 'File Editor Enabled (WordPress RCE)',
        'tactic': 'Privilege Escalation', 'tactic_id': 'TA0004',
        'technique': 'T1548.004', 'technique_name': 'Elevated Execution with Prompt',
        'patterns': [r'file.editor.*enabled|theme.editor.*accessible|wp.*file.*edit.*not.disabled'],
        'desc': 'WordPress file editor is enabled, allowing admin-to-RCE escalation.',
        'source': 'API Security Tester',
    },
    # ── Defense Evasion ────────────────────────────────────────────────────
    {
        'id': 'CF-DE001', 'severity': 'MEDIUM',
        'title': 'Security Headers Missing (WAF Bypass)',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005',
        'technique': 'T1562', 'technique_name': 'Impair Defenses',
        'patterns': [r'x-frame-options.*missing|csp.*missing|content-security-policy.*not\s*set|hsts.*missing'],
        'desc': 'Critical security headers are absent, weakening browser-level defenses.',
        'source': 'Config Auditor',
    },
    {
        'id': 'CF-DE002', 'severity': 'INFO',
        'title': 'Debug Mode / Verbose Errors Exposed',
        'tactic': 'Defense Evasion', 'tactic_id': 'TA0005',
        'technique': 'T1070', 'technique_name': 'Indicator Removal',
        'patterns': [r'debug.*mode.*on|wp_debug.*true|stack\s*trace.*exposed|verbose.*error.*production'],
        'desc': 'Debug mode or verbose error messages are exposed in production.',
        'source': 'Config Auditor',
    },
    # ── Credential Access ──────────────────────────────────────────────────
    {
        'id': 'CF-CA001', 'severity': 'HIGH',
        'title': 'Brute Force Attack Surface',
        'tactic': 'Credential Access', 'tactic_id': 'TA0006',
        'technique': 'T1110', 'technique_name': 'Brute Force',
        'patterns': [r'brute.force|no.*lockout|rate.*limit.*missing.*login|login.*unlimited.*attempt'],
        'desc': 'Login endpoint has no rate limiting or lockout, enabling brute-force attacks.',
        'source': 'Auth Prober',
    },
    {
        'id': 'CF-CA002', 'severity': 'HIGH',
        'title': 'Unsecured Credentials in Repository / Config',
        'tactic': 'Credential Access', 'tactic_id': 'TA0006',
        'technique': 'T1552', 'technique_name': 'Unsecured Credentials',
        'patterns': [r'\.env.*exposed|api[_\s]key.*found|secret.*key.*exposed|password.*in.*config|credentials.*leaked'],
        'desc': 'Credentials or secrets found in publicly accessible configuration files.',
        'source': 'JS Intelligence Agent',
    },
    {
        'id': 'CF-CA003', 'severity': 'HIGH',
        'title': 'Login Attempt Using Leaked Key',
        'tactic': 'Credential Access', 'tactic_id': 'TA0006',
        'technique': 'T1078', 'technique_name': 'Valid Accounts',
        'patterns': [r'leaked.*key.*valid|valid.*credential.*found|successful.*auth.*unexpected|login.*success.*scan'],
        'desc': 'Leaked credentials appear to be valid for the target system.',
        'source': 'Auth Prober',
    },
    # ── Discovery ──────────────────────────────────────────────────────────
    {
        'id': 'CF-D001', 'severity': 'MEDIUM',
        'title': 'User Enumeration Possible',
        'tactic': 'Discovery', 'tactic_id': 'TA0007',
        'technique': 'T1087', 'technique_name': 'Account Discovery',
        'patterns': [r'user.*enum|username.*enum|wp-json.*users.*exposed|different.*error.*valid.*user'],
        'desc': 'Application reveals whether a username is valid through different error messages.',
        'source': 'Identity Mapper',
    },
    {
        'id': 'CF-D002', 'severity': 'LOW',
        'title': 'Sensitive File / Directory Discovery',
        'tactic': 'Discovery', 'tactic_id': 'TA0007',
        'technique': 'T1083', 'technique_name': 'File and Directory Discovery',
        'patterns': [r'\.git.*exposed|backup.*accessible|directory.*listing|sensitive.*file.*found|\.sql.*accessible'],
        'desc': 'Sensitive files or directory listings are publicly accessible.',
        'source': 'Config Auditor',
    },
    # ── Collection ─────────────────────────────────────────────────────────
    {
        'id': 'CF-C001', 'severity': 'HIGH',
        'title': 'Cross-Site Scripting (Session Hijacking)',
        'tactic': 'Collection', 'tactic_id': 'TA0009',
        'technique': 'T1185', 'technique_name': 'Browser Session Hijacking',
        'patterns': [r'xss.*confirmed|reflected.*xss|stored.*xss|dom.*xss|cross.site.*script'],
        'desc': 'XSS vulnerability confirmed, enabling session token theft and data collection.',
        'source': 'Injection Hunter',
    },
    {
        'id': 'CF-C002', 'severity': 'MEDIUM',
        'title': 'Sensitive Data in API Response',
        'tactic': 'Collection', 'tactic_id': 'TA0009',
        'technique': 'T1213', 'technique_name': 'Data from Information Repositories',
        'patterns': [r'pii.*exposed|email.*leaked.*api|user.*data.*unauthenticated|password.*hash.*api'],
        'desc': 'API endpoint returns sensitive user data without proper authentication.',
        'source': 'API Security Tester',
    },
    # ── Command and Control ────────────────────────────────────────────────
    {
        'id': 'CF-CC001', 'severity': 'HIGH',
        'title': 'XML-RPC / SSRF Enabled for C2',
        'tactic': 'Command and Control', 'tactic_id': 'TA0011',
        'technique': 'T1219', 'technique_name': 'Remote Access Software',
        'patterns': [r'xmlrpc.*enabled|ssrf|server.side.*request.*forgery|open.*redirect.*external'],
        'desc': 'XML-RPC or SSRF vectors available that could be used for command-and-control.',
        'source': 'API Security Tester',
    },
    # ── Exfiltration ───────────────────────────────────────────────────────
    {
        'id': 'CF-EX001', 'severity': 'HIGH',
        'title': 'Unrestricted File Download / Export',
        'tactic': 'Exfiltration', 'tactic_id': 'TA0010',
        'technique': 'T1048', 'technique_name': 'Exfiltration Over Alternative Protocol',
        'patterns': [r'unrestricted.*download|export.*no.*auth|csv.*export.*unauthenticated|database.*dump.*accessible'],
        'desc': 'Data export or file download endpoints accessible without authentication.',
        'source': 'API Security Tester',
    },
    # ── Impact ─────────────────────────────────────────────────────────────
    {
        'id': 'CF-IM001', 'severity': 'HIGH',
        'title': 'Weak Cryptography / Data at Risk',
        'tactic': 'Impact', 'tactic_id': 'TA0040',
        'technique': 'T1486', 'technique_name': 'Data Encrypted for Impact',
        'patterns': [r'md5.*password|sha1.*password|weak.*cipher|ssl.*2\.0|ssl.*3\.0|tls.*1\.0.*weak|rc4|des\b'],
        'desc': 'Weak cryptographic algorithms in use, putting stored data at risk.',
        'source': 'Crypto Inspector',
    },
    {
        'id': 'CF-IM002', 'severity': 'MEDIUM',
        'title': 'Denial of Service Surface (Rate Limiting)',
        'tactic': 'Impact', 'tactic_id': 'TA0040',
        'technique': 'T1499', 'technique_name': 'Endpoint Denial of Service',
        'patterns': [r'no.*rate.*limit|rate.limit.*missing|xmlrpc.*amplif|dos.*vulnerabl'],
        'desc': 'Endpoints lack rate limiting, making them susceptible to denial of service attacks.',
        'source': 'Auth Prober',
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
