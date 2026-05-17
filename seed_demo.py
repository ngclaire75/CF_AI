"""
Seed script: creates demo/demo123 account and populates fake data.
Run once: python seed_demo.py
Safe to re-run (skips if demo user already exists, replaces fake data).
Does NOT touch real user accounts or real scan data.
"""
import sys, os, json, sqlite3, random, datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'dashboard'))

from werkzeug.security import generate_password_hash

# ── Paths ─────────────────────────────────────────────────────────────────────
USERS_FILE = os.path.join(os.path.dirname(__file__), 'data', 'users.json')
DB_PATH    = os.environ.get('CFAI_DB_PATH',
             os.path.join(os.path.dirname(__file__), 'data', 'cfai_scans.db'))

os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)

# ── 1. Create demo user ───────────────────────────────────────────────────────
with open(USERS_FILE) as f:
    users = json.load(f)

if 'demo' not in users:
    users['demo'] = {
        'password': generate_password_hash('demo123'),
        'role': 'user',
        'email': 'demo@inktelligence.online',
        'verified': True,
        'verification_token': None,
        'plan': 'pro',
        'allowed_pages': [
            'dashboard','chatbot','gsc','filescan','threatanalytics',
            'incidents','priority','syslog','pluginlogs','logexplorer',
            'network','targets','history','sca','dca','grc',
        ],
    }
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)
    print('Created demo user (demo / demo123)')
else:
    # Update plan + allowed_pages in case they drifted
    users['demo']['plan'] = 'pro'
    users['demo']['allowed_pages'] = [
        'dashboard','chatbot','gsc','filescan','threatanalytics',
        'incidents','priority','syslog','pluginlogs','logexplorer',
        'network','targets','history','sca','dca','grc',
    ]
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)
    print('demo user already exists — updated plan/pages')

# ── 2. Seed SQLite fake data ──────────────────────────────────────────────────
con = sqlite3.connect(DB_PATH)
con.row_factory = sqlite3.Row

def ts(days_ago=0, hours=0):
    dt = datetime.datetime.utcnow() - datetime.timedelta(days=days_ago, hours=hours)
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def date_str(days_ago=0):
    return (datetime.date.today() - datetime.timedelta(days=days_ago)).isoformat()

DEMO = 'demo'
TARGETS = [
    'https://inktelligence.online',
    'https://api.inktelligence.online',
    'https://blog.inktelligence.online',
    'https://admin.inktelligence.online',
    'https://shop.inktelligence.online',
]

# ── 2a. Scans ─────────────────────────────────────────────────────────────────
# Clear existing demo scans first
con.execute("DELETE FROM scans WHERE username=?", (DEMO,))

scan_rows = []
risks   = ['HIGH','HIGH','MEDIUM','MEDIUM','MEDIUM','LOW','LOW','LOW','INFO']
outputs = [
    "SSL/TLS: TLSv1.0 enabled — weak protocol\nHTTP: Missing X-Frame-Options header\nOpen port 8080 detected",
    "Outdated WordPress plugin: WooCommerce 6.1 (CVE-2023-2986)\nDirectory listing enabled on /uploads/",
    "HTTP: Strict-Transport-Security header missing\nReferrer-Policy not set\nX-Content-Type-Options missing",
    "Default credentials found on admin panel\nWeak password policy detected\nNo rate limiting on login",
    "DNS: No SPF record configured\nDMARC policy missing\nDNS zone transfer allowed",
    "Open port 3306 (MySQL) exposed to internet\nSSH on port 22 with password auth enabled",
    "Content-Security-Policy not configured\nCookies missing Secure and HttpOnly flags",
    "Outdated jQuery 1.11 (CVE-2019-11358)\nAngular version disclosure in HTTP headers",
    "X-Powered-By header reveals PHP/7.4\nServer: Apache/2.4.41 disclosed in headers",
]
findings_counts = [3,2,3,4,2,2,2,2,2]

# Determine columns available in scans table
cols_info = con.execute("PRAGMA table_info(scans)").fetchall()
col_names = [c['name'] for c in cols_info]

for i, target in enumerate(TARGETS):
    for j in range(random.randint(3,6)):
        days = random.randint(0, 30)
        risk_val = random.choice(risks)
        out_idx = (i + j) % len(outputs)
        created = ts(days, random.randint(0,23))
        row_data = {
            'created_at':     created,
            'updated_at':     created,
            'target':         target,
            'risk':           risk_val,
            'output':         outputs[out_idx],
            'status':         'completed',
            'findings_count': findings_counts[out_idx % len(findings_counts)],
            'username':       DEMO,
            'scan_type':      'nmap+nikto',
            'agent_type':     'nmap+nikto',
            'score':          random.randint(10, 90),
            'agent_id':       '',
            'error':          '',
            'notes':          '',
        }
        # Only insert columns that actually exist in this DB
        insert_cols = [c for c in row_data if c in col_names]
        vals = [row_data[c] for c in insert_cols]
        placeholders = ','.join(['?']*len(insert_cols))
        con.execute(f"INSERT INTO scans ({','.join(insert_cols)}) VALUES ({placeholders})", vals)
        scan_rows.append(row_data)

con.commit()
print(f'Inserted {len(scan_rows)} demo scans across {len(TARGETS)} targets')

# ── 2b. Incidents ─────────────────────────────────────────────────────────────
try:
    con.execute("DELETE FROM incidents WHERE username=?", (DEMO,))
    inc_cols = [c['name'] for c in con.execute("PRAGMA table_info(incidents)").fetchall()]
    incidents = [
        ('Brute Force Login Attempt', 'high',    'open',          'inktelligence.online', 'Multiple failed login attempts from 192.168.1.x'),
        ('Outdated Plugin Exploited',  'critical','investigating', 'shop.inktelligence.online', 'WooCommerce CVE-2023-2986 exploitation attempt detected'),
        ('SSL Certificate Expiring',   'medium',  'open',          'api.inktelligence.online', 'SSL cert expires in 14 days — renewal required'),
        ('Suspicious File Upload',     'high',    'resolved',      'blog.inktelligence.online', 'PHP webshell upload attempt blocked by WAF'),
        ('DDoS Attack Mitigated',      'critical','resolved',      'inktelligence.online', 'Layer 7 DDoS attack mitigated via Cloudflare — 50k req/s'),
        ('Exposed Admin Panel',        'medium',  'open',          'admin.inktelligence.online', 'Admin panel accessible without VPN restriction'),
        ('Data Exfiltration Attempt',  'high',    'investigating', 'api.inktelligence.online', 'Unusual outbound traffic spike to unknown IP'),
        ('SQL Injection Attempt',      'high',    'resolved',      'shop.inktelligence.online', 'SQLi payload detected and blocked in checkout endpoint'),
    ]
    for i, (title, sev, status, target, desc) in enumerate(incidents):
        row = {'created_at': ts(i*3+1), 'updated_at': ts(i*3),
               'title': title, 'severity': sev, 'status': status,
               'target': target, 'description': desc, 'username': DEMO}
        icols = [c for c in row if c in inc_cols]
        con.execute(
            f"INSERT INTO incidents ({','.join(icols)}) VALUES ({','.join(['?']*len(icols))})",
            [row[c] for c in icols]
        )
    con.commit()
    print(f'Inserted {len(incidents)} demo incidents')
except Exception as e:
    print(f'Incidents skipped: {e}')

# ── 2c. GRC Controls ──────────────────────────────────────────────────────────
try:
    con.execute("DELETE FROM grc_controls WHERE username=?", (DEMO,))
    controls = [
        ('ISO-A.5.1',  'Information Security Policy',        'ISO 27001', 'Policy',          'implemented', 'Security Team',    date_str(5),   'Custom',   'SOC 2 CC 1.1'),
        ('ISO-A.6.1',  'Information Security Roles',         'ISO 27001', 'Organization',    'implemented', 'CISO',             date_str(10),  'Custom',   'SOC 2 CC 1.2'),
        ('ISO-A.8.1',  'Asset Management & Inventory',       'ISO 27001', 'Asset Mgmt',      'in_progress', 'IT Team',          date_str(-15), 'Custom',   'NIST PR.AC-1'),
        ('ISO-A.9.1',  'Access Control Policy',              'ISO 27001', 'Access Control',  'implemented', 'IT Admin',         date_str(2),   'Vanta',    'SOC 2 CC 6.1'),
        ('ISO-A.10.1', 'Cryptographic Controls',             'ISO 27001', 'Cryptography',    'implemented', 'Dev Team',         date_str(30),  'Custom',   'SOC 2 CC 6.7'),
        ('ISO-A.12.1', 'Operational Security Procedures',    'ISO 27001', 'Operations',      'in_progress', 'DevOps',           date_str(-5),  'Custom',   'NIST PR.IP-1'),
        ('ISO-A.14.2', 'Secure Development Policy',          'ISO 27001', 'Development',     'not_started', 'Dev Team',         date_str(-20), 'Custom',   'SOC 2 CC 8.1'),
        ('NIST-PR.1',  'Protect: Identity Management',       'NIST CSF',  'Identity',        'implemented', 'IT Admin',         date_str(7),   'Vanta',    'ISO A.9.1'),
        ('NIST-DE.1',  'Detect: Anomaly Detection',          'NIST CSF',  'Detection',       'in_progress', 'Security Team',    date_str(-10), 'Custom',   'ISO A.16.1'),
        ('SOC2-CC6.1', 'Logical & Physical Access Controls', 'SOC 2',     'Access Control',  'implemented', 'CISO',             date_str(15),  'Vanta',    'ISO A.9.2'),
        ('SOC2-CC7.1', 'System Monitoring',                  'SOC 2',     'Monitoring',      'implemented', 'DevOps',           date_str(12),  'Vanta',    'NIST DE.CM-1'),
        ('SOC2-CC8.1', 'Change Management',                  'SOC 2',     'Change Mgmt',     'not_started', 'Dev Team',         date_str(-30), 'Custom',   'ISO A.14.2'),
        ('CIS-1.1',    'Inventory of Enterprise Assets',     'CIS Controls','Asset Mgmt',    'implemented', 'IT Team',          date_str(20),  'Custom',   'NIST ID.AM-1'),
        ('CIS-4.1',    'Secure Config of Enterprise Assets', 'CIS Controls','Configuration', 'in_progress', 'DevOps',           date_str(-8),  'Custom',   'NIST PR.IP-1'),
        ('CIS-6.1',    'Access Control Management',          'CIS Controls','Access Control', 'implemented','IT Admin',          date_str(5),   'Custom',   'SOC 2 CC 6.1'),
    ]
    for cid, title, fw, cat, status, owner, due, source, fwmap in controls:
        con.execute(
            "INSERT INTO grc_controls (created_at, updated_at, control_id, title, framework, framework_mapping, source, category, status, owner, due_date, username) VALUES (datetime('now'),datetime('now'),?,?,?,?,?,?,?,?,?,?)",
            (cid, title, fw, fwmap, source, cat, status, owner, due, DEMO)
        )
    con.commit()
    print(f'Inserted {len(controls)} demo controls')
except Exception as e:
    print(f'Controls skipped: {e}')

# ── 2d. GRC Risks ─────────────────────────────────────────────────────────────
try:
    con.execute("DELETE FROM grc_risks WHERE username=?", (DEMO,))
    risks_data = [
        ('SQL Injection on Checkout API',          'Technical',    5, 5, 'mitigate',  'open',         'approved',  2,  'Dev Team',     date_str(-10)),
        ('Brute Force on Admin Login',             'Technical',    4, 4, 'mitigate',  'in_treatment', 'approved',  3,  'IT Admin',     date_str(-5)),
        ('Third-party Plugin Vulnerability',       'Third-party',  4, 5, 'mitigate',  'open',         'pending',   5,  'Dev Team',     date_str(-20)),
        ('Data Breach via Misconfigured S3',       'Cloud',        3, 5, 'mitigate',  'in_treatment', 'approved',  4,  'DevOps',       date_str(-15)),
        ('Phishing Attack on Employees',           'Human',        4, 3, 'mitigate',  'open',         'pending',   6,  'HR Team',      date_str(-30)),
        ('Insider Threat — Data Exfiltration',     'Insider',      2, 5, 'accept',    'open',         'approved',  3,  'CISO',         date_str(-7)),
        ('DDoS Attack on Main Site',               'Infrastructure',5,4, 'transfer',  'in_treatment', 'approved',  2,  'DevOps',       date_str(-3)),
        ('Expired SSL Certificate',                'Compliance',   3, 3, 'mitigate',  'closed',       'approved',  1,  'IT Admin',     date_str(5)),
        ('Weak Password Policy',                   'Policy',       4, 4, 'mitigate',  'open',         'pending',   4,  'Security Team',date_str(-25)),
        ('Unpatched OS Vulnerabilities',           'Technical',    3, 4, 'mitigate',  'in_treatment', 'pending',   4,  'DevOps',       date_str(-12)),
        ('Regulatory Non-compliance (GDPR)',       'Compliance',   2, 4, 'avoid',     'open',         'approved',  2,  'Legal',        date_str(-40)),
        ('Supply Chain Software Risk',             'Third-party',  2, 3, 'transfer',  'open',         'pending',   3,  'Dev Team',     date_str(-50)),
    ]
    for title, cat, like, impact, treatment, status, risk_status, residual, owner, due in risks_data:
        con.execute(
            "INSERT INTO grc_risks (created_at,updated_at,title,category,likelihood,impact,score,treatment,status,risk_status,residual_risk,owner,due_date,username) VALUES (datetime('now'),datetime('now'),?,?,?,?,?,?,?,?,?,?,?,?)",
            (title, cat, like, impact, like*impact, treatment, status, risk_status, residual, owner, due, DEMO)
        )
    con.commit()
    print(f'Inserted {len(risks_data)} demo risks')
except Exception as e:
    print(f'Risks skipped: {e}')

# ── 2e. GRC Tests ─────────────────────────────────────────────────────────────
try:
    con.execute("DELETE FROM grc_tests WHERE username=?", (DEMO,))
    tests = [
        ('Password Complexity Check',       'HR',          'automated', 'pass',         date_str(2),  'HR Team'),
        ('MFA Enrollment Verification',     'HR',          'manual',    'pass',         date_str(5),  'HR Team'),
        ('Security Awareness Training',     'HR',          'manual',    'in_progress',  date_str(-7), 'HR Team'),
        ('Firewall Rule Review',            'IT',          'manual',    'pass',         date_str(3),  'IT Admin'),
        ('Vulnerability Scan — Production', 'IT',          'automated', 'pass',         date_str(1),  'DevOps'),
        ('Patch Management Audit',          'IT',          'manual',    'fail',         date_str(-5), 'IT Admin'),
        ('Endpoint Protection Check',       'IT',          'automated', 'pass',         date_str(4),  'IT Admin'),
        ('Acceptable Use Policy Review',    'Policy',      'manual',    'pass',         date_str(10), 'CISO'),
        ('Data Classification Audit',       'Policy',      'manual',    'not_started',  date_str(-15),'Legal'),
        ('Incident Response Plan Test',     'Policy',      'manual',    'in_progress',  date_str(-3), 'Security Team'),
        ('SAST — Code Repository Scan',     'Engineering', 'automated', 'pass',         date_str(2),  'Dev Team'),
        ('DAST — Web Application Scan',     'Engineering', 'automated', 'fail',         date_str(-2), 'Dev Team'),
        ('Dependency Vulnerability Scan',   'Engineering', 'automated', 'pass',         date_str(1),  'Dev Team'),
        ('Secrets Detection in CI/CD',      'Engineering', 'automated', 'pass',         date_str(3),  'DevOps'),
        ('Risk Register Review',            'Risks',       'manual',    'pass',         date_str(7),  'CISO'),
        ('Third-party Risk Assessment',     'Risks',       'manual',    'in_progress',  date_str(-10),'Security Team'),
        ('Business Continuity Test',        'Custom',      'manual',    'not_started',  date_str(-20),'CISO'),
        ('Penetration Test — Annual',       'Custom',      'manual',    'pass',         date_str(30), 'Security Team'),
    ]
    for name, test_cat, cat, status, last_run, owner in tests:
        con.execute(
            "INSERT INTO grc_tests (created_at,updated_at,name,test_category,category,status,last_run,owner,username) VALUES (datetime('now'),datetime('now'),?,?,?,?,?,?,?)",
            (name, test_cat, cat, status, last_run, owner, DEMO)
        )
    con.commit()
    print(f'Inserted {len(tests)} demo tests')
except Exception as e:
    print(f'Tests skipped: {e}')

# ── 2f. GRC Audits ────────────────────────────────────────────────────────────
try:
    con.execute("DELETE FROM grc_audits WHERE username=?", (DEMO,))
    audits = [
        ('ISO 27001 Annual Audit 2025',   'Ernst & Young LLP',  'external', 'complete',    'ISO 27001 Annex A',          date_str(60),  date_str(30),  'All controls passed. Minor findings in A.12.1.'),
        ('SOC 2 Type II Readiness',       'Deloitte Advisory',  'external', 'in_progress', 'SOC 2 Trust Criteria',       date_str(10),  date_str(-30), 'CC6 and CC7 fieldwork in progress.'),
        ('GDPR Compliance Review',        'Internal Audit',     'internal', 'planned',     'GDPR Articles 13-22',        date_str(-15), date_str(-45), ''),
        ('Penetration Test — H1 2025',    'Offensive Security', 'external', 'complete',    'Web Application & API',      date_str(90),  date_str(75),  '3 high, 5 medium findings. All remediated.'),
        ('PCI DSS Gap Assessment',        'Internal Audit',     'internal', 'planned',     'PCI DSS v4.0 Requirements',  date_str(-30), date_str(-60), ''),
    ]
    for name, auditor, atype, status, scope, start, end, findings in audits:
        con.execute(
            "INSERT INTO grc_audits (created_at,updated_at,name,auditor,audit_type,status,scope,start_date,end_date,findings,username) VALUES (datetime('now'),datetime('now'),?,?,?,?,?,?,?,?,?)",
            (name, auditor, atype, status, scope, start, end, findings, DEMO)
        )
    con.commit()
    print(f'Inserted {len(audits)} demo audits')
    # Get audit IDs for evidence linking
    audit_ids = [r[0] for r in con.execute("SELECT id FROM grc_audits WHERE username=? ORDER BY id", (DEMO,)).fetchall()]
except Exception as e:
    print(f'Audits skipped: {e}')
    audit_ids = []

# ── 2g. GRC Evidence ──────────────────────────────────────────────────────────
try:
    con.execute("DELETE FROM grc_evidence WHERE username=?", (DEMO,))
    ev_list = [
        ('Access Control Policy Document',    'Document',    'accepted',        'ISO-A.9.1',  'Security Team',  'access_control_policy_v3.pdf'),
        ('MFA Enrollment Screenshot',         'Screenshot',  'accepted',        'ISO-A.9.1',  'IT Admin',       'mfa_enrollment_jan2025.png'),
        ('Firewall Configuration Export',     'Configuration','ready',          'ISO-A.13.1', 'IT Admin',       'fw_config_export.txt'),
        ('Penetration Test Report 2024',      'Report',      'accepted',        'CIS-4.1',    'Security Team',  'pentest_report_2024.pdf'),
        ('Employee Security Training Log',    'Log',         'accepted',        'ISO-A.6.1',  'HR Team',        'training_log_q1_2025.xlsx'),
        ('Vulnerability Scan Results',        'Report',      'ready',           'NIST-DE.1',  'DevOps',         'vuln_scan_march2025.pdf'),
        ('Incident Response Procedure',       'Document',    'accepted',        'ISO-A.16.1', 'Security Team',  'ir_procedure_v2.pdf'),
        ('Data Encryption Policy',            'Document',    'accepted',        'ISO-A.10.1', 'Dev Team',       'encryption_policy.pdf'),
        ('Backup & Recovery Test Results',    'Test Result', 'flagged',         'ISO-A.12.3', 'DevOps',         'backup_test_q4_2024.pdf'),
        ('Third-party Vendor Assessment',     'Assessment',  'not_ready',       'ISO-A.15.1', 'Legal',          ''),
        ('Asset Inventory Spreadsheet',       'Document',    'ready',           'CIS-1.1',    'IT Team',        'asset_inventory_2025.xlsx'),
        ('Change Management Log',             'Log',         'not_ready',       'SOC2-CC8.1', 'Dev Team',       ''),
        ('Cloud Security Config Review',      'Configuration','ready',          'NIST-PR.1',  'DevOps',         'cloud_config_review.pdf'),
        ('GDPR Data Processing Register',     'Document',    'not_applicable',  'ISO-A.18.1', 'Legal',          'gdpr_register.pdf'),
        ('Security Awareness Training Cert',  'Certificate', 'accepted',        'ISO-A.6.1',  'HR Team',        'training_cert_2025.pdf'),
    ]
    for i, (title, ev_type, ev_status, ctrl_id, collected_by, file_name) in enumerate(ev_list):
        aid = audit_ids[i % len(audit_ids)] if audit_ids else None
        con.execute(
            "INSERT INTO grc_evidence (created_at,updated_at,title,evidence_type,evidence_status,control_id,collected_by,file_name,audit_id,username) VALUES (datetime('now'),datetime('now'),?,?,?,?,?,?,?,?)",
            (title, ev_type, ev_status, ctrl_id, collected_by, file_name, aid, DEMO)
        )
    con.commit()
    print(f'Inserted {len(ev_list)} demo evidence items')
except Exception as e:
    print(f'Evidence skipped: {e}')

con.close()
print('\nDemo seed complete.')
print('Login at https://inktelligence.online  →  username: demo  password: demo123')
