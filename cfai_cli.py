#!/usr/bin/env python3
"""
cfai — CF_AI Autonomous Penetration Testing AI — Terminal Client
Version: 6.0

Install on Kali VPS:
    chmod +x /opt/CF_AI/cfai_cli.py
    ln -sf /opt/CF_AI/cfai_cli.py /usr/local/bin/cfai

Usage:
    cfai                           # interactive REPL
    cfai "full pentest on 10.0.0.1"  # one-shot
    cfai -s http://vps:8888        # remote server
    cfai -t 10.0.0.1               # set default target
"""

import sys
import os
import json
import re
import time
import threading
import argparse
import textwrap
import itertools
import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    print("\033[0;31m[!] requests not installed — run: pip3 install requests\033[0m")
    sys.exit(1)

try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False

# ── ANSI colour palette (green-matrix theme) ─────────────────────────────────
G0  = "\033[38;5;46m"    # bright matrix green
G1  = "\033[0;32m"       # standard green
G2  = "\033[2;32m"       # dim green
G3  = "\033[38;5;22m"    # dark green
C   = "\033[0;36m"       # cyan
Y   = "\033[1;33m"       # yellow
R   = "\033[0;31m"       # red
M   = "\033[0;35m"       # magenta
W   = "\033[1;37m"       # white bold
DIM = "\033[2m"
UL  = "\033[4m"
BOLD= "\033[1m"
NC  = "\033[0m"

# Severity colours
SEV = {
    "critical": "\033[38;5;196m",
    "high":     "\033[0;31m",
    "medium":   "\033[1;33m",
    "low":      "\033[0;34m",
    "info":     "\033[0;36m",
}

BANNER = f"""{G0}
 ██████╗███████╗      █████╗ ██╗
██╔════╝██╔════╝     ██╔══██╗██║
██║     █████╗       ███████║██║
██║     ██╔══╝       ██╔══██║██║
╚██████╗██║          ██║  ██║██║
 ╚═════╝╚═╝          ╚═╝  ╚═╝╚═╝{NC}"""

TAGLINE = f" {G2}Autonomous Penetration Testing AI  ·  v6.0{NC}"

DIVIDER  = G2 + "─" * 72 + NC
DIVIDER2 = G3 + "═" * 72 + NC

# ── Default server discovery ─────────────────────────────────────────────────
def _default_server() -> str:
    if "CFAI_SERVER" in os.environ:
        return os.environ["CFAI_SERVER"]
    for path in ("/opt/CF_AI/.env", os.path.expanduser("~/.cfai")):
        if os.path.exists(path):
            for line in Path(path).read_text().splitlines():
                if line.startswith("CFAI_PORT="):
                    port = line.split("=", 1)[1].strip()
                    host = "localhost"
                    return f"http://{host}:{port}"
    return "http://localhost:8888"

# ── Session state ─────────────────────────────────────────────────────────────
class Session:
    def __init__(self, server: str):
        self.server       = server.rstrip("/")
        self.target       = None
        self.creds        = {}       # {username, password, totp_secret}
        self.last_output  = ""
        self.cmd_count    = 0
        self.findings     = []       # accumulated confirmed PoCs
        self.connected    = False
        self.start_time   = time.time()

    def elapsed(self) -> str:
        s = int(time.time() - self.start_time)
        return f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"

    def status_line(self) -> str:
        conn  = f"{G1}●{NC} Connected" if self.connected else f"{R}●{NC} Offline"
        tgt   = f"{G0}{self.target}{NC}" if self.target else f"{DIM}none{NC}"
        cmds  = f"{DIM}{self.cmd_count} cmds{NC}"
        uptime= f"{DIM}{self.elapsed()}{NC}"
        return f"  {conn}  │  Target: {tgt}  │  {cmds}  │  {uptime}"

# ── HTTP helpers ──────────────────────────────────────────────────────────────
def api_chat(session: Session, message: str, timeout: int = 300) -> str:
    try:
        r = requests.post(
            f"{session.server}/api/chat",
            json={"message": message},
            timeout=timeout,
        )
        r.raise_for_status()
        data = r.json()
        resp = data.get("response", "(no response)")
        session.cmd_count += 1
        session.last_output = resp
        # Collect any confirmed PoCs from the response
        for line in resp.splitlines():
            if "poc:" in line.lower() or "curl -s" in line.lower():
                session.findings.append(line.strip())
        return resp
    except requests.ConnectionError:
        session.connected = False
        return (f"{R}[!] Cannot connect to CF_AI at {session.server}{NC}\n"
                f"    Start the server: bash /opt/CF_AI/run.sh\n"
                f"    Or: cfai -s http://host:port")
    except requests.Timeout:
        return f"{Y}[!] Request timed out (>{timeout}s). The scan may still be running on the server.{NC}"
    except Exception as e:
        return f"{R}[!] {e}{NC}"


def api_health(session: Session) -> dict:
    try:
        r = requests.get(f"{session.server}/health", timeout=6)
        session.connected = True
        return r.json()
    except Exception:
        session.connected = False
        return {}


def api_wordpress_report(session: Session, payload: dict, timeout: int = 600) -> dict:
    try:
        r = requests.post(f"{session.server}/api/wordpress/report",
                          json=payload, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"success": False, "error": str(e)}

# ── Spinner ───────────────────────────────────────────────────────────────────
class Spinner:
    FRAMES = ["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"]

    def __init__(self, label: str = "Running"):
        self.label = label
        self._stop = threading.Event()
        self._thread = None

    def __enter__(self):
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        sys.stdout.write("\r" + " " * (len(self.label) + 12) + "\r")
        sys.stdout.flush()

    def _spin(self):
        for f in itertools.cycle(self.FRAMES):
            if self._stop.is_set():
                break
            sys.stdout.write(f"\r  {G0}{f}{NC}  {DIM}{self.label}...{NC} ")
            sys.stdout.flush()
            time.sleep(0.09)

# ── Output formatter ──────────────────────────────────────────────────────────
def fmt(text: str) -> str:
    """Apply green-matrix colour coding to AI response text."""
    lines = []
    in_code = False
    for line in text.splitlines():
        stripped = line.strip()

        # Code fence toggle
        if stripped.startswith("```"):
            in_code = not in_code
            lines.append(G3 + line + NC)
            continue

        if in_code:
            # Highlight severity tags and PoC markers
            line = line.replace("[CRITICAL]", f"{SEV['critical']}[CRITICAL]{NC}")
            line = line.replace("[HIGH]",     f"{SEV['high']}[HIGH]{NC}")
            line = line.replace("[MEDIUM]",   f"{SEV['medium']}[MEDIUM]{NC}")
            line = line.replace("[LOW]",      f"{SEV['low']}[LOW]{NC}")
            line = line.replace("[INFO]",     f"{SEV['info']}[INFO]{NC}")
            line = line.replace("[+]",  f"{G1}[+]{NC}")
            line = line.replace("[-]",  f"{R}[-]{NC}")
            line = line.replace("[!]",  f"{Y}[!]{NC}")
            line = line.replace("[*]",  f"{C}[*]{NC}")
            line = line.replace("PoC:",     f"{G0}PoC:{NC}")
            line = line.replace("Finding:", f"{G0}Finding:{NC}")
            line = line.replace("[AUTO-ADAPT]", f"{M}[AUTO-ADAPT]{NC}")
            line = line.replace("CONFIRMED EXPLOITABLE", f"{G0}CONFIRMED EXPLOITABLE{NC}")
            # Dim pure separator lines
            if set(line.strip()) <= set("─═╔╗╚╝║"):
                line = G3 + line + NC
            lines.append(line)
        else:
            # Bold **text** and inline `code`
            line = re.sub(r'\*\*(.+?)\*\*', BOLD + r'\1' + NC, line)
            line = re.sub(r'`([^`]+)`',     C    + r'\1' + NC, line)
            # Headers: lines starting with #
            if stripped.startswith("##"):
                line = G1 + BOLD + line + NC
            elif stripped.startswith("#"):
                line = G0 + BOLD + line + NC
            lines.append(line)

    return "\n".join(lines)


def box(title: str, body: str, width: int = 72) -> str:
    """Render a green-bordered box."""
    inner = width - 4
    top   = G1 + "┌─ " + G0 + BOLD + title + NC + G1 + " " + "─" * max(0, inner - len(title) - 2) + "┐" + NC
    mid   = "\n".join(G1 + "│ " + NC + l.ljust(inner)[:inner] + G1 + " │" + NC
                      for l in body.splitlines())
    bot   = G1 + "└" + "─" * (width - 2) + "┘" + NC
    return f"{top}\n{mid}\n{bot}"

# ── Help text ─────────────────────────────────────────────────────────────────
HELP_SECTIONS = {
    "recon": [
        ("scan <target>",              "Nmap port + service scan"),
        ("subdomains <domain>",        "Subdomain enumeration (subfinder + amass)"),
        ("osint <domain>",             "OSINT recon (theHarvester + Shodan + VT)"),
        ("shodan <ip/query>",          "Shodan host lookup / search"),
        ("virustotal <ip/domain>",     "VirusTotal reputation check"),
        ("hackerone",                  "List HackerOne bug bounty programs"),
    ],
    "web": [
        ("web <url>",                  "Full web security scan (gobuster+nikto+nuclei)"),
        ("dirs <url>",                 "Directory/file brute-force (gobuster/ffuf)"),
        ("sqli <url>",                 "SQL injection (sqlmap)"),
        ("xss <url>",                  "XSS scan (dalfox)"),
        ("wordpress <url>",            "WordPress security scan"),
        ("wp report <url>",            "Full WordPress PDF-style report"),
    ],
    "api": [
        ("api <url>",                  "OWASP API Top 10 — full test suite"),
        ("graphql <url>",              "GraphQL introspection + security checks"),
        ("jwt <token>",                "JWT decode, alg:none, brute-force"),
        ("rest <url>",                 "REST API audit (BOLA, auth, injection, SSRF)"),
    ],
    "pentest": [
        ("pentest <target>",           "FULLY AUTONOMOUS 4-phase pentest + PoC report"),
        ("exploit <service/CVE>",      "Searchsploit + Metasploit module lookup"),
        ("msf <module> <target>",      "Run Metasploit module via resource script"),
        ("payload <type> <lhost:port>","Generate msfvenom payload"),
        ("brute <service> <target>",   "Credential brute-force (hydra/medusa)"),
        ("crack <hash>",               "Hash cracking (hashcat/john)"),
    ],
    "forensics": [
        ("forensics <file>",           "Auto-detect tool by file extension"),
        ("binwalk <file>",             "Firmware analysis"),
        ("exiftool <file>",            "Metadata extraction"),
        ("steghide <file>",            "Steganography detection"),
        ("zsteg <file>",               "PNG/BMP steg (zsteg)"),
        ("vol <memdump>",              "Memory forensics (Volatility3)"),
    ],
    "cloud": [
        ("cloud aws",                  "AWS audit (prowler)"),
        ("trivy <image>",              "Container image CVE scan"),
        ("checkov <dir>",              "IaC misconfiguration scan"),
    ],
    "session": [
        ("set target <host>",          "Set default target for all scans"),
        ("set creds <user>:<pass>",    "Set credentials (used by sqlmap/hydra etc.)"),
        ("set totp <secret>",          "Set TOTP/2FA secret for auth flows"),
        ("set server <url>",           "Change CF_AI server"),
        ("status",                     "Server health + tool availability"),
        ("findings",                   "Show all confirmed PoCs from this session"),
        ("save [filename]",            "Save last output to file"),
        ("clear",                      "Clear screen"),
        ("exit",                       "Quit"),
    ],
}

def print_help():
    print(f"\n{DIVIDER2}")
    print(f"  {G0}CF_AI Command Reference{NC}")
    print(DIVIDER2)
    icons = {"recon": "🔍", "web": "🌐", "api": "🔌", "pentest": "💥",
             "forensics": "🔬", "cloud": "☁️", "session": "⚙️"}
    for section, cmds in HELP_SECTIONS.items():
        print(f"\n  {G1}{BOLD}{section.upper()}{NC}")
        for cmd, desc in cmds:
            print(f"    {G0}{cmd:<38}{NC} {DIM}{desc}{NC}")
    print(f"\n{DIVIDER2}")
    print(f"  {DIM}Any other input is forwarded directly to the AI as natural language.{NC}")
    print(f"  {DIM}Examples:{NC}")
    print(f"    {C}run nmap and sqlmap on 10.0.0.1{NC}")
    print(f"    {C}use exploit/multi/handler lhost 10.0.0.1 lport 4444{NC}")
    print(f"    {C}touch /root/hash.txt && echo 'abc123' > /root/hash.txt{NC}")
    print(f"    {C}full pentest on 10.0.0.1{NC}")
    print(f"{DIVIDER2}\n")

# ── Command shortcuts → natural language ─────────────────────────────────────
def expand_shortcut(msg: str, session: Session) -> str:
    """Expand CLI shortcuts to the natural language the server understands."""
    w  = msg.strip().split()
    lo = msg.strip().lower()

    # Use default target if the command has no explicit target
    def _t(pos: int = 1) -> str:
        if len(w) > pos:
            return " ".join(w[pos:])
        return session.target or ""

    # RECON
    if lo.startswith("scan ") and len(w) >= 2:
        return f"scan {_t(1)}"
    if lo.startswith(("subdomains ", "subdomain ")):
        return f"find subdomains for {_t(1)}"
    if lo.startswith("osint "):
        return f"subdomain and osint tools: amass subfinder dnsenum theharvester on {_t(1)}"
    if lo.startswith("shodan "):
        return f"shodan lookup {_t(1)}"
    if lo.startswith("virustotal "):
        return f"virustotal check {_t(1)}"

    # WEB
    if lo.startswith("web "):
        return f"run gobuster nikto nuclei on {_t(1)}"
    if lo.startswith(("dirs ", "dir ")):
        return f"enumerate directories on {_t(1)}"
    if lo.startswith("sqli "):
        return f"run sqlmap on {_t(1)}"
    if lo.startswith("xss "):
        return f"run dalfox on {_t(1)}"
    if lo.startswith("wordpress "):
        return f"scan wordpress {_t(1)}"
    if lo.startswith("wp report "):
        # Handled separately
        return msg

    # API SECURITY
    if lo.startswith("api "):
        return f"api security test: graphql jwt rest api endpoint discovery on {_t(1)}"
    if lo.startswith("graphql "):
        return f"graphql security check {_t(1)}"
    if lo.startswith("jwt "):
        return f"jwt analyze {_t(1)}"
    if lo.startswith("rest "):
        return f"rest api audit {_t(1)}"

    # AUTONOMOUS PENTEST
    if re.match(r'^pentest\s+', lo):
        return f"full pentest on {_t(1)}"

    # EXPLOITATION
    if lo.startswith("exploit "):
        return f"searchsploit {_t(1)}"
    if re.match(r'^msf\s+', lo):
        return f"use exploit/{_t(1)}"
    if lo.startswith("payload "):
        parts = _t(1).split()
        ptype = parts[0] if parts else "linux/x64/shell_reverse_tcp"
        lhp   = parts[1] if len(parts) > 1 else "10.0.0.1:4444"
        lhost, _, lport = lhp.partition(":")
        return (f"msfvenom -p {ptype} LHOST={lhost} LPORT={lport or '4444'}"
                f" -f elf -o /root/payload.elf")

    # BRUTE / CRACK
    if lo.startswith(("brute ", "bruteforce ")):
        rest = _t(1)
        u = session.creds.get("username", "admin")
        p = session.creds.get("password", "")
        wl = "/usr/share/wordlists/rockyou.txt"
        if p:
            return f"run hydra on {rest} use username '{u}' password '{p}'"
        return f"run hydra -l {u} -P {wl} on {rest}"
    if lo.startswith("crack "):
        h = _t(1)
        return f"hashcat -a 0 -m 0 {h} /usr/share/wordlists/rockyou.txt --force"

    # FORENSICS
    if lo.startswith("forensics "):
        return f"forensics on {_t(1)}"
    if lo.startswith("binwalk "):
        return f"binwalk {_t(1)}"
    if lo.startswith("exiftool "):
        return f"exiftool {_t(1)}"
    if lo.startswith("steghide "):
        return f"steghide info {_t(1)}"
    if lo.startswith("zsteg "):
        return f"zsteg {_t(1)}"
    if lo.startswith("vol "):
        return f"volatility memory analysis on {_t(1)}"

    # CLOUD
    if lo.startswith("cloud aws"):
        return "prowler aws"
    if lo.startswith("trivy "):
        return f"trivy image {_t(1)}"
    if lo.startswith("checkov "):
        return f"checkov -d {_t(1)}"

    return msg  # pass through as-is


# ── Special local commands (handled without server call) ─────────────────────
def handle_local(msg: str, session: Session) -> bool:
    """Handle local commands. Returns True if handled, False to forward to server."""
    lo = msg.strip().lower()
    w  = msg.strip().split()

    if lo in ("exit", "quit", "q", ":q"):
        print_goodbye(session)
        sys.exit(0)

    if lo in ("help", "?", "-h", "--help"):
        print_help()
        return True

    if lo in ("clear", "cls"):
        os.system("clear")
        return True

    if lo in ("status", "health"):
        print_status(session)
        return True

    if lo == "findings":
        print_findings(session)
        return True

    if lo.startswith("set target ") and len(w) >= 3:
        session.target = w[2]
        print(f"  {G1}[+]{NC} Target set to {G0}{session.target}{NC}")
        return True

    if lo.startswith("set server ") and len(w) >= 3:
        session.server = w[2].rstrip("/")
        print(f"  {G1}[+]{NC} Server set to {G0}{session.server}{NC}")
        return True

    if lo.startswith("set creds ") and len(w) >= 3:
        raw = w[2]
        if ":" in raw:
            u, _, p = raw.partition(":")
            session.creds["username"] = u
            session.creds["password"] = p
            print(f"  {G1}[+]{NC} Credentials: {G0}{u}:{DIM}{'*'*len(p)}{NC}")
        else:
            session.creds["username"] = raw
            print(f"  {G1}[+]{NC} Username set to {G0}{raw}{NC}")
        return True

    if lo.startswith("set totp ") and len(w) >= 3:
        session.creds["totp_secret"] = w[2]
        print(f"  {G1}[+]{NC} TOTP secret stored for 2FA flows")
        return True

    if lo.startswith("save"):
        fname = w[1] if len(w) > 1 else f"cfai_output_{int(time.time())}.txt"
        if session.last_output:
            Path(fname).write_text(session.last_output)
            print(f"  {G1}[+]{NC} Saved to {G0}{fname}{NC}")
        else:
            print(f"  {Y}[!]{NC} Nothing to save yet")
        return True

    if lo == "history":
        if HAS_READLINE:
            n = readline.get_current_history_length()
            for i in range(max(0, n - 20), n):
                print(f"  {DIM}{i:4}  {readline.get_history_item(i+1)}{NC}")
        return True

    return False  # not a local command


# ── Status display ────────────────────────────────────────────────────────────
def print_status(session: Session):
    h = api_health(session)
    print(f"\n{DIVIDER}")
    if h:
        session.connected = True
        print(f"  {G1}[+]{NC} Server   : {G0}{session.server}{NC}")
        print(f"  {G1}[+]{NC} Status   : {G1}{h.get('status', 'online')}{NC}")
        print(f"  {G1}[+]{NC} Version  : {DIM}{h.get('version', '?')}{NC}")
        if "tools" in h:
            tools = h["tools"]
            if isinstance(tools, dict):
                avail = sum(1 for v in tools.values() if v)
                total = len(tools)
                bar_len = 40
                filled = int(bar_len * avail / max(total, 1))
                bar = G1 + "█" * filled + G3 + "░" * (bar_len - filled) + NC
                print(f"  {G1}[+]{NC} Tools    : [{bar}] {G0}{avail}/{total}{NC}")
            else:
                print(f"  {G1}[+]{NC} Tools    : {G0}{tools}{NC}")
        if "uptime" in h:
            print(f"  {G1}[+]{NC} Uptime   : {DIM}{h['uptime']}{NC}")
    else:
        print(f"  {R}[-]{NC} Server {session.server} is {R}offline{NC}")
        print(f"       Run: {C}bash /opt/CF_AI/run.sh{NC}")
    print(f"  {G1}[+]{NC} Session  : {DIM}{session.elapsed()} · {session.cmd_count} commands{NC}")
    if session.target:
        print(f"  {G1}[+]{NC} Target   : {G0}{session.target}{NC}")
    print(DIVIDER + "\n")


def print_findings(session: Session):
    if not session.findings:
        print(f"\n  {DIM}No confirmed PoCs collected in this session.{NC}\n")
        return
    print(f"\n{DIVIDER}")
    print(f"  {G0}Confirmed PoCs — this session ({len(session.findings)}){NC}")
    print(DIVIDER)
    for i, f in enumerate(session.findings, 1):
        print(f"  {G1}{i:2}.{NC} {f}")
    print(DIVIDER + "\n")


def print_goodbye(session: Session):
    print(f"\n{G3}  Session ended · {session.cmd_count} commands · {session.elapsed()}{NC}")
    print(f"{G3}  Goodbye.{NC}\n")


# ── WordPress report via dedicated endpoint ───────────────────────────────────
def run_wp_report(session: Session, args: list):
    if not args:
        print(f"  {Y}[!]{NC} Usage: {C}wp report <url> [company] [assessor]{NC}")
        return
    url     = args[0]
    company = args[1] if len(args) > 1 else "Security Assessment"
    assessor= args[2] if len(args) > 2 else "CF_AI Automated Scanner"
    payload = {
        "site_url":      url,
        "company_name":  company,
        "assessor_name": assessor,
        "report_date":   datetime.date.today().isoformat(),
        "assessment_scope": "WordPress Security Assessment",
    }
    print(f"\n  {G0}[*]{NC} Generating WordPress security report for {G0}{url}{NC}")
    print(f"  {DIM}This may take 3-5 minutes (wpscan + nikto + nuclei)...{NC}\n")
    with Spinner("Scanning"):
        result = api_wordpress_report(session, payload, timeout=600)
    if result.get("success"):
        report_text = result.get("report", "")
        print(fmt(f"```\n{report_text}\n```"))
        fname = f"wp_report_{url.replace('http://', '').replace('https://', '').replace('/', '_')}_{int(time.time())}.txt"
        Path(fname).write_text(report_text)
        print(f"\n  {G1}[+]{NC} Report saved to {G0}{fname}{NC}")
        session.last_output = report_text
    else:
        print(f"  {R}[-]{NC} Report failed: {result.get('error', 'unknown error')}")


# ── 2FA / TOTP helper message ─────────────────────────────────────────────────
def _inject_totp(msg: str, session: Session) -> str:
    """If a TOTP secret is set in session, inject it into the message."""
    totp = session.creds.get("totp_secret")
    if totp and "totp" not in msg.lower() and "2fa" not in msg.lower():
        msg += f" totp secret '{totp}'"
    u = session.creds.get("username")
    p = session.creds.get("password")
    if u and "username" not in msg.lower() and "user " not in msg.lower():
        msg += f" username '{u}'"
    if p and "password" not in msg.lower():
        msg += f" password '{p}'"
    return msg


# ── Prompt builder ────────────────────────────────────────────────────────────
def prompt(session: Session) -> str:
    tgt = f"{G2}:{G0}{session.target}{NC}" if session.target else ""
    conn_dot = G1 + "●" + NC if session.connected else R + "●" + NC
    return f"{conn_dot} {G1}cfai{tgt}{NC} {G3}❯{NC} "


# ── Tab completion ────────────────────────────────────────────────────────────
_COMPLETIONS = sorted([
    "pentest", "scan", "subdomains", "osint", "shodan", "virustotal",
    "hackerone", "web", "dirs", "sqli", "xss", "wordpress", "wp report",
    "api", "graphql", "jwt", "rest", "exploit", "msf", "payload",
    "brute", "crack", "forensics", "binwalk", "exiftool", "steghide",
    "zsteg", "vol", "cloud", "trivy", "checkov", "set target", "set creds",
    "set totp", "set server", "status", "findings", "save", "clear",
    "history", "help", "exit",
    # direct tools
    "nmap", "gobuster", "ffuf", "nuclei", "nikto", "sqlmap", "dalfox",
    "wpscan", "hydra", "hashcat", "john", "medusa", "amass", "subfinder",
    "searchsploit", "msfvenom", "msfconsole", "gdb", "r2", "radare2",
    "binwalk", "exiftool", "steghide", "volatility", "trivy", "checkov",
    # linux
    "ls", "cat", "mkdir", "touch", "chmod", "find", "grep", "ps",
    "curl", "wget", "ping", "systemctl", "service", "apt-get",
])

def _complete(text, state):
    options = [c for c in _COMPLETIONS if c.startswith(text)]
    return options[state] if state < len(options) else None

if HAS_READLINE:
    readline.set_completer(_complete)
    readline.parse_and_bind("tab: complete")


# ── Main interactive REPL ─────────────────────────────────────────────────────
def interactive(session: Session):
    # Check connectivity
    h = api_health(session)
    if h:
        session.connected = True

    # Banner
    print(BANNER)
    print(TAGLINE)
    print()
    print(session.status_line())
    print()
    print(f"  {DIM}Type {C}help{NC}{DIM} for the full command reference · {C}exit{NC}{DIM} to quit{NC}")
    print()

    # Readline history
    history_file = Path.home() / ".cfai_history"
    if HAS_READLINE:
        try:
            readline.read_history_file(history_file)
        except FileNotFoundError:
            pass
        readline.set_history_length(2000)

    while True:
        try:
            raw = input(prompt(session)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            print_goodbye(session)
            break

        if not raw:
            continue

        lo = raw.lower()

        # ── wp report: special path ───────────────────────────────────────
        if lo.startswith("wp report "):
            run_wp_report(session, raw.split()[2:])
            continue

        # ── Local commands ────────────────────────────────────────────────
        if handle_local(raw, session):
            continue

        # ── Inject session creds / TOTP into message ──────────────────────
        expanded = expand_shortcut(raw, session)
        if session.target and expanded == raw:
            # Append target to bare keywords that need one
            _needs_target = ("scan", "web", "api", "pentest", "dirs", "sqli",
                             "xss", "brute", "subdomain", "osint")
            if lo in _needs_target and session.target:
                expanded = f"{expanded} {session.target}"
        expanded = _inject_totp(expanded, session)

        # ── Send to server ────────────────────────────────────────────────
        # Estimate timeout from command complexity
        timeout = 60
        heavy = ("pentest", "full pentest", "autonomous", "api security",
                 "wpscan", "wordpress", "nuclei", "sqlmap", "hydra", "hashcat",
                 "amass", "msfconsole", "msfvenom", "brute", "crack")
        if any(h in lo for h in heavy):
            timeout = 600

        label = f"Running {lo[:40]}..." if len(lo) > 12 else "Running..."
        with Spinner(label):
            response = api_chat(session, expanded, timeout=timeout)

        print(fmt(response))
        print()

    if HAS_READLINE:
        readline.write_history_file(history_file)


# ── One-shot mode ─────────────────────────────────────────────────────────────
def oneshot(session: Session, message: str, timeout: int):
    expanded = expand_shortcut(message, session)
    expanded = _inject_totp(expanded, session)
    with Spinner(message[:50]):
        response = api_chat(session, expanded, timeout=timeout)
    print(fmt(response))


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="cfai",
        description="CF_AI — Autonomous Penetration Testing AI CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          cfai                                    # interactive REPL
          cfai "full pentest on 10.0.0.1"         # autonomous pentest
          cfai pentest 192.168.1.1                # shortcut
          cfai api http://target.com/api/v1       # OWASP API Top 10
          cfai -t 10.0.0.1                        # set default target, then REPL
          cfai -s http://vps:8888                 # remote CF_AI server
          cfai -t 10.0.0.1 scan                   # scan default target
        """),
    )
    parser.add_argument("-s", "--server",  default=_default_server(),
                        help="CF_AI server URL (default: http://localhost:8888)")
    parser.add_argument("-t", "--target",  default=None,
                        help="Default target host/IP/URL")
    parser.add_argument("-u", "--username",default=None, help="Default username")
    parser.add_argument("-p", "--password",default=None, help="Default password")
    parser.add_argument("--totp",          default=None, help="TOTP/2FA secret")
    parser.add_argument("--timeout",  type=int, default=300,
                        help="Request timeout seconds (default: 300)")
    parser.add_argument("message", nargs="*",
                        help="Command to run (omit for interactive REPL)")
    args = parser.parse_args()

    session = Session(args.server)
    if args.target:   session.target = args.target
    if args.username: session.creds["username"] = args.username
    if args.password: session.creds["password"] = args.password
    if args.totp:     session.creds["totp_secret"] = args.totp

    if args.message:
        oneshot(session, " ".join(args.message), args.timeout)
    else:
        interactive(session)


if __name__ == "__main__":
    main()
