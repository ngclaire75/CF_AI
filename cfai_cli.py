#!/usr/bin/env python3
"""
cfai — CF_AI command-line client for Kali Linux
Usage:
  cfai                        interactive REPL
  cfai "scan 10.0.0.1"        one-shot command
  cfai -s http://vps:8888     connect to remote server

Install on VPS:
  chmod +x /opt/CF_AI/cfai_cli.py
  ln -sf /opt/CF_AI/cfai_cli.py /usr/local/bin/cfai
"""

import sys
import os
import json
import textwrap
import argparse

try:
    import requests
except ImportError:
    print("[!] requests not installed — run: pip3 install requests")
    sys.exit(1)

try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False

# ── ANSI colours ─────────────────────────────────────────────────────────────
R   = "\033[0;31m"   # red
G   = "\033[0;32m"   # green
Y   = "\033[1;33m"   # yellow
C   = "\033[0;36m"   # cyan
B   = "\033[0;34m"   # blue
M   = "\033[0;35m"   # magenta
W   = "\033[1;37m"   # white bold
DIM = "\033[2m"
NC  = "\033[0m"
BOLD = "\033[1m"

BANNER = f"""{G}
  ██████╗███████╗     █████╗ ██╗
 ██╔════╝██╔════╝    ██╔══██╗██║
 ██║     █████╗      ███████║██║
 ██║     ██╔══╝      ██╔══██║██║
 ╚██████╗██║         ██║  ██║██║
  ╚═════╝╚═╝         ╚═╝  ╚═╝╚═╝{NC}
 {DIM}Penetration Testing AI — CLI Client{NC}
"""

HELP_TEXT = f"""
{W}Commands:{NC}
  Any natural language or direct tool command is forwarded to the AI.

{W}Examples:{NC}
  {C}scan 10.0.0.1{NC}                          — port scan
  {C}full pentest on 10.0.0.1{NC}               — autonomous full pentest
  {C}run nmap and nikto on target.com{NC}        — parallel multi-tool
  {C}sqlmap -u http://target.com/page?id=1{NC}   — direct tool command
  {C}ls /root{NC}                                — linux shell command
  {C}touch /root/hash.txt{NC}                    — create file
  {C}mkdir /root/work{NC}                        — create directory
  {C}use exploit/multi/handler lhost 10.0.0.1{NC} — metasploit module
  {C}msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf{NC}
  {C}shodan lookup 8.8.8.8{NC}                   — shodan intel
  {C}virustotal check google.com{NC}             — virustotal
  {C}forensics memory.dmp{NC}                    — auto forensics
  {C}api security test http://target.com/api{NC} — OWASP API Top 10

{W}Special:{NC}
  {C}help{NC}       — this help text
  {C}status{NC}     — server health check
  {C}clear{NC}      — clear screen
  {C}exit{NC}       — quit
"""


def _server_default() -> str:
    env = os.environ.get("CFAI_SERVER")
    if env:
        return env
    # Try reading from .env
    for path in ("/opt/CF_AI/.env", os.path.expanduser("~/.cfai")):
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    if line.startswith("CFAI_PORT="):
                        port = line.strip().split("=", 1)[1]
                        return f"http://localhost:{port}"
    return "http://localhost:8888"


def chat(message: str, server: str, timeout: int = 300) -> str:
    try:
        r = requests.post(
            f"{server}/api/chat",
            json={"message": message},
            timeout=timeout,
        )
        r.raise_for_status()
        data = r.json()
        return data.get("response", "(empty response)")
    except requests.ConnectionError:
        return (f"{R}[!] Cannot connect to CF_AI at {server}{NC}\n"
                f"    Start the server: bash /opt/CF_AI/run.sh\n"
                f"    Or set CFAI_SERVER=http://host:port")
    except requests.Timeout:
        return f"{Y}[!] Request timed out after {timeout}s{NC}"
    except Exception as e:
        return f"{R}[!] Error: {e}{NC}"


def health_check(server: str) -> str:
    try:
        r = requests.get(f"{server}/health", timeout=5)
        d = r.json()
        lines = [f"{G}[+] Server online{NC} — {server}"]
        if "version" in d:
            lines.append(f"    Version : {d['version']}")
        if "tools" in d:
            lines.append(f"    Tools   : {d['tools']}")
        if "uptime" in d:
            lines.append(f"    Uptime  : {d['uptime']}")
        return "\n".join(lines)
    except Exception as e:
        return f"{R}[-] Server unreachable: {e}{NC}"


def _format_response(text: str) -> str:
    """Apply basic colour to response text for terminal display."""
    lines = []
    in_code = False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            in_code = not in_code
            lines.append(DIM + line + NC)
            continue
        if in_code:
            # Colour key patterns in code blocks
            line = line.replace("[+]", f"{G}[+]{NC}")
            line = line.replace("[-]", f"{R}[-]{NC}")
            line = line.replace("[!]", f"{Y}[!]{NC}")
            line = line.replace("[CRITICAL]", f"{R}[CRITICAL]{NC}")
            line = line.replace("[HIGH]", f"{R}[HIGH]{NC}")
            line = line.replace("[MEDIUM]", f"{Y}[MEDIUM]{NC}")
            line = line.replace("[LOW]", f"{B}[LOW]{NC}")
            line = line.replace("[INFO]", f"{C}[INFO]{NC}")
            lines.append(line)
        else:
            # Bold **text**
            import re
            line = re.sub(r'\*\*(.+?)\*\*', BOLD + r'\1' + NC, line)
            line = re.sub(r'`([^`]+)`', C + r'\1' + NC, line)
            lines.append(line)
    return "\n".join(lines)


def _spinner_start():
    import threading, itertools, time
    stop = threading.Event()
    frames = ["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"]

    def spin():
        for f in itertools.cycle(frames):
            if stop.is_set():
                break
            sys.stdout.write(f"\r{C}{f}{NC} Running... ")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * 30 + "\r")
        sys.stdout.flush()

    t = threading.Thread(target=spin, daemon=True)
    t.start()
    return stop


def interactive(server: str):
    print(BANNER)
    print(f"  {DIM}Server: {server}{NC}")
    print(f"  {DIM}Type 'help' for commands, 'exit' to quit{NC}\n")

    # Readline history
    history_file = os.path.expanduser("~/.cfai_history")
    if HAS_READLINE:
        try:
            readline.read_history_file(history_file)
        except FileNotFoundError:
            pass
        readline.set_history_length(1000)

    while True:
        try:
            msg = input(f"{G}cfai{NC} {DIM}❯{NC} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{DIM}Goodbye.{NC}")
            break

        if not msg:
            continue
        if msg.lower() in ("exit", "quit", "q", ":q"):
            print(f"{DIM}Goodbye.{NC}")
            break
        if msg.lower() in ("help", "?"):
            print(HELP_TEXT)
            continue
        if msg.lower() in ("clear", "cls"):
            os.system("clear")
            continue
        if msg.lower() in ("status", "health"):
            print(health_check(server))
            continue

        stop = _spinner_start()
        response = chat(msg, server)
        stop.set()
        print(_format_response(response))
        print()

    if HAS_READLINE:
        readline.write_history_file(history_file)


def main():
    parser = argparse.ArgumentParser(
        prog="cfai",
        description="CF_AI — Penetration Testing AI CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Examples:
          cfai                                  # interactive REPL
          cfai "scan 10.0.0.1"                  # one-shot command
          cfai full pentest on 192.168.1.1      # autonomous pentest
          cfai -s http://192.168.1.100:8888     # remote server
        """),
    )
    parser.add_argument("-s", "--server", default=_server_default(),
                        help="CF_AI server URL (default: http://localhost:8888)")
    parser.add_argument("-t", "--timeout", type=int, default=300,
                        help="Request timeout in seconds (default: 300)")
    parser.add_argument("message", nargs="*", help="Command to send (omit for interactive mode)")
    args = parser.parse_args()

    server = args.server.rstrip("/")

    if args.message:
        # One-shot mode
        msg = " ".join(args.message)
        stop = _spinner_start()
        response = chat(msg, server, args.timeout)
        stop.set()
        print(_format_response(response))
    else:
        # Interactive REPL
        interactive(server)


if __name__ == "__main__":
    main()
