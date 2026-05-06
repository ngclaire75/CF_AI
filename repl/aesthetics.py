"""CF_AI REPL aesthetics."""
import sys
import time
import threading

# ── Palette ───────────────────────────────────────────────────────────────────
R      = '\033[0m'
DIM    = '\033[2m'
GREY   = '\033[90m'
LGREY  = '\033[37m'
WHITE  = '\033[97m'
BOLD   = '\033[1m'
OK     = '\033[92m'
WARN   = '\033[93m'
ERR    = '\033[91m'
CYAN   = '\033[96m'
BLUE   = '\033[94m'
PURPLE = '\033[35m'


def _c(color: str, s: str) -> str:
    if not sys.stdout.isatty():
        return s
    return f'{color}{s}{R}'

def ok(s: str)    -> str: return _c(OK,     s)
def err(s: str)   -> str: return _c(ERR,    s)
def warn(s: str)  -> str: return _c(WARN,   s)
def dim(s: str)   -> str: return _c(DIM,    s)
def white(s: str) -> str: return _c(WHITE,  s)


# ── Banner ────────────────────────────────────────────────────────────────────

def banner() -> str:
    W = 58
    line = f'{GREY}{"─" * W}{R}'
    return (
        f'\n{line}\n'
        f'  {WHITE}CF_AI{R}  {GREY}·{R}  {LGREY}Autonomous Cybersecurity Agent{R}  {GREY}·{R}  {DIM}v2.0{R}\n'
        f'  {DIM}Pentest  ·  Bug Bounty  ·  CTF  ·  WSTG v4.2{R}\n'
        f'{line}\n'
    )


# ── Prompt ────────────────────────────────────────────────────────────────────

def prompt(model: str = '') -> str:
    m = f'{DIM}({model}){R} ' if model else ''
    return f'{m}{CYAN}❯{R}  '


# ── Help ──────────────────────────────────────────────────────────────────────

HELP_TEXT = f"""
  {WHITE}Commands{R}
  {LGREY}  agent [role] <target>{R}   {DIM}AI pentest agent  (roles: pentest ctf recon exploit analyst){R}
  {LGREY}  recon <target>{R}          {DIM}Passive + active reconnaissance{R}
  {LGREY}  chat <message>{R}          {DIM}Single AI message (no tools){R}
  {LGREY}  model [name]{R}            {DIM}Show/set model  (gpt-4o · gpt-4o-mini · o1){R}
  {LGREY}  history{R}                 {DIM}Command history{R}
  {LGREY}  clear · exit{R}            {DIM}Clear screen / quit{R}

  {WHITE}Examples{R}
  {LGREY}  agent pentest https://target.com{R}
  {LGREY}  agent ctf Find the flag at 10.0.0.1{R}
  {LGREY}  recon target.com{R}
  {LGREY}  nmap -sV 10.0.0.1{R}          {DIM}(any shell command runs directly){R}

  {GREY}  Ctrl+C during agent → Human-In-The-Loop (HITL) pause{R}
"""


# ── Tool output ───────────────────────────────────────────────────────────────

_SEP = f'{GREY}{"─" * 58}{R}'


def print_tool_call(name: str, args: dict):
    cmd = (args.get('command') or args.get('path') or
           '  '.join(f'{k}={repr(v)[:50]}' for k, v in args.items()))
    print(f'\n{_SEP}')
    print(f'  {BLUE}$ {cmd[:120]}{R}')
    print(_SEP)


def print_tool_result(name: str, result: str, elapsed: float = 0.0):
    lines = result.strip().splitlines()
    shown = lines[:50]
    for line in shown:
        print(f'  {LGREY}{line}{R}')
    skipped = len(lines) - 50
    if skipped > 0:
        print(f'  {DIM}… {skipped} more lines{R}')
    timing = f'{GREY}[{elapsed:.1f}s]{R}' if elapsed else ''
    print(f'{_SEP} {timing}\n')


def print_agent_text(text: str):
    for line in text.strip().splitlines():
        print(f'  {CYAN}{line}{R}')


# ── Finding / site display ────────────────────────────────────────────────────

def print_finding(f: dict, index: int = 0):
    sev = f.get('severity', 'info').upper()
    sc  = {'CRITICAL': ERR, 'HIGH': ERR, 'MEDIUM': WARN,
           'LOW': LGREY, 'INFO': DIM}.get(sev, DIM)
    print(f'  {DIM}[{index:02d}]{R} {sc}{sev:8}{R}  {WHITE}{f.get("title","")}{R}')
    if f.get('description'):
        print(f'       {LGREY}{f["description"][:120]}{R}')


def print_site(s: dict):
    sc = {'critical': ERR, 'high': ERR, 'medium': WARN,
          'low': LGREY, 'none': DIM}.get(s.get('worst_severity','none'), DIM)
    print(f'  {sc}●{R}  {WHITE}{s.get("url",""):45}{R}  {DIM}id={s.get("id","")}{R}')


# ── Spinner ───────────────────────────────────────────────────────────────────

class Spinner:
    _F = ('⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏')

    def __init__(self, label: str = ''):
        self._label  = label
        self._thread = None
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
            sys.stdout.write(f'\r  {GREY}{self._F[i % len(self._F)]}  {DIM}{self._label}{R}')
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
