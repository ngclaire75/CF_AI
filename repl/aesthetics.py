"""CF_AI REPL aesthetics — grey palette, banner, output formatting."""
import sys
import time
import threading
import contextlib

# ── Palette (grey / neutral) ─────────────────────────────────────────────────
R      = '\033[0m'       # reset
DIM    = '\033[2m'       # dim grey
GREY   = '\033[90m'      # dark grey
LGREY  = '\033[37m'      # light grey
WHITE  = '\033[97m'      # bright white
BOLD   = '\033[1m'
OK     = '\033[92m'      # green  — success only
WARN   = '\033[93m'      # yellow — warnings
ERR    = '\033[91m'      # red    — errors
CYAN   = '\033[96m'      # cyan   — tool output / agent speech
BLUE   = '\033[34m'      # blue   — tool names
PURPLE = '\033[35m'      # purple — AI reasoning


def _c(color: str, s: str) -> str:
    if not sys.stdout.isatty():
        return s
    return f'{color}{s}{R}'


def ok(s: str)     -> str: return _c(OK,     s)
def err(s: str)    -> str: return _c(ERR,    s)
def warn(s: str)   -> str: return _c(WARN,   s)
def info(s: str)   -> str: return _c(GREY,   s)
def dim(s: str)    -> str: return _c(DIM,    s)
def white(s: str)  -> str: return _c(WHITE,  s)
def bold(s: str)   -> str: return _c(BOLD,   s)
def tool(s: str)   -> str: return _c(BLUE,   s)
def agent(s: str)  -> str: return _c(CYAN,   s)
def think(s: str)  -> str: return _c(PURPLE, s)


BANNER = f"""{GREY}
  ╔══════════════════════════════════════════════════════╗
  ║  {WHITE}CF_AI{GREY}  —  Autonomous Cybersecurity Agent v2.0     ║
  ║  {DIM}Penetration Testing  •  Bug Bounty  •  CTF{GREY}         ║
  ╚══════════════════════════════════════════════════════╝{R}
"""

HELP_TEXT = f"""{GREY}
  {WHITE}Agent commands:{R}
  {LGREY}  agent [role] <target>   {DIM}Spawn AI pentest agent  (roles: pentest ctf recon exploit analyst){R}
  {LGREY}  recon <target>          {DIM}Passive + active reconnaissance{R}
  {LGREY}  chat <message>          {DIM}Single AI message (no tools){R}

  {WHITE}Examples:{R}
  {LGREY}  agent pentest https://example.com{R}
  {LGREY}  agent ctf Find the flag in the web app at 10.0.0.1{R}
  {LGREY}  recon example.com{R}
  {LGREY}  nmap -sV 10.0.0.1          {DIM}(any shell command runs directly){R}
  {LGREY}  curl -I https://example.com{R}

  {WHITE}REPL:{R}
  {LGREY}  model [name]            {DIM}Show/set AI model (gpt-4o, claude-sonnet-4-6, llama3.2…){R}
  {LGREY}  history                 {DIM}Show command history{R}
  {LGREY}  clear                   {DIM}Clear screen{R}
  {LGREY}  exit                    {DIM}Quit{R}

  {GREY}  Unrecognized input is executed as a local shell command.{R}
  {GREY}  During agent runs, press Ctrl+C for Human-In-The-Loop (HITL).{R}
"""


def banner() -> str:
    return BANNER


def prompt(model: str = '') -> str:
    tag = f'{DIM}[{model}]{R} ' if model else ''
    return f'{GREY}cf_ai{R}{tag}{GREY} »{R} '


def print_output(text: str, prefix: str = ''):
    lines = text.strip().splitlines()
    for line in lines:
        print(f'  {GREY}{prefix}{R}{LGREY}{line}{R}')


def print_tool_call(name: str, args: dict):
    args_str = '  '.join(f'{k}={repr(v)[:60]}' for k, v in args.items())
    print(f'  {BLUE}⚙ {name}{R}  {DIM}{args_str}{R}')


def print_tool_result(name: str, result: str, elapsed: float = 0.0):
    lines = result.strip().splitlines()[:30]
    elapsed_str = f'  {DIM}({elapsed:.1f}s){R}' if elapsed else ''
    print(f'  {DIM}└ {name}{R}{elapsed_str}')
    for line in lines:
        print(f'    {LGREY}{line}{R}')
    if len(result.strip().splitlines()) > 30:
        skipped = len(result.strip().splitlines()) - 30
        print(f'    {DIM}… {skipped} more lines{R}')


def print_agent_text(text: str):
    for line in text.strip().splitlines():
        print(f'  {CYAN}{line}{R}')


def print_finding(f: dict, index: int = 0):
    sev = f.get('severity', 'info').upper()
    colors = {'CRITICAL': ERR, 'HIGH': f'\033[91m', 'MEDIUM': WARN,
              'LOW': LGREY, 'INFO': DIM}
    sc = colors.get(sev, DIM)
    print(f'  {DIM}[{index:02d}]{R} {sc}{sev:8}{R}  {WHITE}{f.get("title","")}{R}')
    print(f'       {DIM}{f.get("site_url","")}  id={f.get("id","")}{R}')
    if f.get('description'):
        print(f'       {LGREY}{f["description"][:120]}{R}')


def print_site(s: dict):
    worst = s.get('worst_severity', 'none')
    sc_map = {'critical': ERR, 'high': '\033[91m', 'medium': WARN,
              'low': LGREY, 'none': DIM}
    sc    = sc_map.get(worst, DIM)
    crit  = s.get('findings_critical', 0)
    high  = s.get('findings_high', 0)
    print(f'  {sc}●{R}  {WHITE}{s.get("url",""):45}{R}  '
          f'{DIM}id={s.get("id",""):8}  platform={s.get("platform","?"):10}  '
          f'C={crit} H={high}{R}')


# ── Spinner ──────────────────────────────────────────────────────────────────

class Spinner:
    _FRAMES = ('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏')

    def __init__(self, label: str = ''):
        self._label  = label
        self._thread: threading.Thread | None = None
        self._stop   = threading.Event()

    def __enter__(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        if self._thread:
            self._thread.join()
        sys.stdout.write('\r\033[K')
        sys.stdout.flush()

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = self._FRAMES[i % len(self._FRAMES)]
            sys.stdout.write(f'\r  {GREY}{frame}  {DIM}{self._label}{R}')
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
