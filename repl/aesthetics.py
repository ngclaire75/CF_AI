"""CF_AI REPL aesthetics — dark green banner, boxed tool output."""
from __future__ import annotations
import re
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
GREEN  = '\033[32m'   # dark green for banner

_ANSI = re.compile(r'\033\[[0-9;]*m')


def _tty() -> bool:
    return sys.stdout.isatty()

def _utf8() -> bool:
    enc = getattr(sys.stdout, 'encoding', '') or ''
    return 'utf' in enc.lower()

def _c(color: str, s: str) -> str:
    return f'{color}{s}{R}' if _tty() else s

def ok(s: str)    -> str: return _c(OK,    s)
def err(s: str)   -> str: return _c(ERR,   s)
def warn(s: str)  -> str: return _c(WARN,  s)
def dim(s: str)   -> str: return _c(DIM,   s)
def white(s: str) -> str: return _c(WHITE, s)
def green(s: str) -> str: return _c(GREEN, s)

def _vlen(s: str) -> int:
    """Visual length — strips ANSI escape codes before measuring."""
    return len(_ANSI.sub('', s))


# ── Banner ────────────────────────────────────────────────────────────────────
#
#  CF+AI in dark-green block letters (36 visible chars wide, 6 lines tall).
#  Each row:  C(8) + sep(1) + F(8) + cross(7) + A(8) + sep(1) + I(3) = 36
#
_ART = (
    ' ██████╗ ███████╗   ╋    █████╗  ██╗',
    '██╔════╝ ██╔════╝   │   ██╔══██╗ ██║',
    '██║      █████╗   ──┼── ███████║ ██║',
    '██║      ██╔══╝     │   ██╔══██║ ██║',
    '╚██████╗ ██║        ╋   ██║  ██║ ██║',
    ' ╚═════╝ ╚═╝            ╚═╝  ╚═╝ ╚═╝',
)

_BW = 62  # banner separator width


def banner() -> str:
    G = GREEN if _tty() else ''
    g = GREY  if _tty() else ''
    w = WHITE if _tty() else ''
    d = DIM   if _tty() else ''
    r = R     if _tty() else ''
    sep = f'{g}{"─" * _BW}{r}'
    art = '\n'.join(f'  {G}{ln}{r}' for ln in _ART)
    return (
        f'\n{sep}\n'
        f'{art}\n\n'
        f'  {w}Autonomous Cybersecurity Agent{r}  {g}·{r}  {d}WSTG v4.2  ·  v2.0{r}\n'
        f'  {d}Pentest  ·  Bug Bounty  ·  CTF  ·  Red Team{r}\n'
        f'{sep}\n'
    )


# ── Prompt ────────────────────────────────────────────────────────────────────

def prompt(model: str = '') -> str:
    if not _tty():
        return '> '
    m = f'{DIM}({model}){R} ' if model else ''
    return f'{m}{GREEN}❯{R}  '


# ── Help table ────────────────────────────────────────────────────────────────

def help_text() -> str:
    G  = GREY  if _tty() else ''
    w  = WHITE if _tty() else ''
    c  = CYAN  if _tty() else ''
    d  = DIM   if _tty() else ''
    g  = GREEN if _tty() else ''
    r  = R     if _tty() else ''

    W   = 68   # inner box content width
    lw  = 24   # command column width (fits all: "agent info  <target>" = 21 chars)
    rw  = W - lw - 6  # desc column (2+lw+2+rw+2 = W) → 38 chars

    def _top():
        return f'{G}  ╔{"═" * W}╗{r}'

    def _bot():
        return f'{G}  ╚{"═" * W}╝{r}'

    def _sep():
        return f'{G}  ╠{"═" * W}╣{r}'

    def _blank():
        return f'{G}  ║{" " * W}║{r}'

    def _hdiv():
        inner = '  ' + '─' * (W - 4) + '  '
        return f'{G}  ║{r}{d}{inner}{r}{G}║{r}'

    def _section(txt: str):
        vis = 4 + len(txt)          # "  ▸ " + txt
        pad = ' ' * max(0, W - vis)
        return f'{G}  ║{r}  {g}▸ {txt}{r}{pad}{G}║{r}'

    def _header(txt: str):
        vis = 2 + len(txt)
        pad = ' ' * max(0, W - vis)
        return f'{G}  ║{r}  {w}{BOLD if _tty() else ""}{txt}{r}{pad}{G}║{r}'

    def _row(cmd: str, desc: str):
        l  = cmd[:lw].ljust(lw)
        ri = desc[:rw].ljust(rw)
        return f'{G}  ║{r}  {c}{l}{r}  {d}{ri}{r}  {G}║{r}'

    def _tip(txt: str):
        vis = 2 + len(txt)
        pad = ' ' * max(0, W - vis)
        return f'{G}  ║{r}  {d}{txt}{r}{pad}{G}║{r}'

    lines = [
        '',
        _top(),
        _blank(),
        _header('CF+AI  Command Reference'),
        _blank(),
        _sep(),
        _blank(),
        _section('WSTG Specialized Agents'),
        _hdiv(),
        _row('agent info  <target>', 'Information Gathering      [WSTG-INFO]'),
        _row('agent conf  <target>', 'Configuration & Deployment [WSTG-CONF]'),
        _row('agent idnt  <target>', 'Identity Management        [WSTG-IDNT]'),
        _row('agent athn  <target>', 'Authentication Testing     [WSTG-ATHN]'),
        _row('agent athz  <target>', 'Authorization Testing      [WSTG-ATHZ]'),
        _row('agent sess  <target>', 'Session Management         [WSTG-SESS]'),
        _row('agent inpv  <target>', 'Input Validation           [WSTG-INPV]'),
        _row('agent cryp  <target>', 'Cryptography Testing       [WSTG-CRYP]'),
        _row('agent clnt  <target>', 'Client-Side Testing        [WSTG-CLNT]'),
        _row('agent apit  <target>', 'API Security Testing       [WSTG-APIT]'),
        _blank(),
        _sep(),
        _blank(),
        _section('Specialized Agents'),
        _hdiv(),
        _row('agent ctf  <target|url>', 'CTF solver — web/crypto/RE/OT/forensics'),
        _row('agent ot   <target|ip>', 'OT/ICS — Modbus DNP3 SCADA PLC HMI'),
        _row('agent enum <target|url>', 'API enum — IDOR rate-limit anti-bot'),
        _blank(),
        _sep(),
        _blank(),
        _section('Full Penetration Test'),
        _hdiv(),
        _row('agent pentest <url>', 'Run all 10 WSTG agents sequentially'),
        _row('recon <target>', 'Passive + active reconnaissance'),
        _row('chat <message>', 'Single-turn AI chat  (no tools)'),
        _blank(),
        _sep(),
        _blank(),
        _section('Utility'),
        _hdiv(),
        _row('model [name]', 'Show / set active AI model'),
        _row('history', 'View last 50 commands'),
        _row('help', 'Show this command table'),
        _row('clear', 'Clear terminal screen'),
        _row('exit / quit', 'Exit CF_AI'),
        _row('<shell command>', 'Execute any shell command directly'),
        _blank(),
        _sep(),
        _blank(),
        _tip('Ctrl+C during agent run → Human-In-The-Loop (HITL) pause'),
        _tip('Example:  agent pentest https://target.com'),
        _tip('Example:  agent athn https://app.example.com'),
        _blank(),
        _bot(),
        '',
    ]
    return '\n'.join(lines)


# ── Tool output — boxed ───────────────────────────────────────────────────────

_TBW = 64  # tool box inner width (excludes the │ border char itself)


def _box_top(label: str) -> str:
    G = GREY  if _tty() else ''
    B = BLUE  if _tty() else ''
    r = R     if _tty() else ''
    n     = f' ▶  {label} '
    fill  = max(0, _TBW - len(n))
    return f'\n{G}╭─{B}{n}{G}{"─" * fill}╮{r}'


def _box_cmd(cmd: str) -> str:
    G = GREY  if _tty() else ''
    B = BLUE  if _tty() else ''
    r = R     if _tty() else ''
    return f'{G}│{r}  {B}$ {cmd[:_TBW - 4]}{r}'


def _box_line(text: str) -> str:
    G = GREY  if _tty() else ''
    L = LGREY if _tty() else ''
    r = R     if _tty() else ''
    return f'{G}│{r}  {L}{text[:_TBW - 2]}{r}'


def _box_bot(elapsed: float = 0.0) -> str:
    G = GREY if _tty() else ''
    d = DIM  if _tty() else ''
    r = R    if _tty() else ''
    if elapsed:
        t    = f' {elapsed:.1f}s '
        fill = max(0, _TBW - len(t))
        return f'{G}╰{"─" * fill}{d}{t}{r}{G}╯{r}\n'
    return f'{G}╰{"─" * _TBW}╯{r}\n'


def print_tool_call(name: str, args: dict):
    """Print opening box with tool name and command."""
    cmd = (
        args.get('command') or
        args.get('path') or
        '  '.join(f'{k}={repr(v)[:30]}' for k, v in list(args.items())[:3])
    )
    print(_box_top(name))
    print(_box_cmd(cmd))
    G = GREY if _tty() else ''
    r = R    if _tty() else ''
    print(f'{G}│{r}')


def print_tool_result(name: str, result: str, elapsed: float = 0.0):
    """Print result lines and close the box."""
    G = GREY if _tty() else ''
    d = DIM  if _tty() else ''
    r = R    if _tty() else ''

    lines   = result.strip().splitlines()
    shown   = lines[:60]
    skipped = len(lines) - 60

    for line in shown:
        print(_box_line(line))

    if skipped > 0:
        print(f'{G}│{r}  {d}… {skipped} more lines{r}')

    print(f'{G}│{r}')
    print(_box_bot(elapsed), end='')


# ── Agent text ────────────────────────────────────────────────────────────────

def print_agent_text(text: str):
    C = CYAN if _tty() else ''
    r = R    if _tty() else ''
    for line in text.strip().splitlines():
        print(f'  {C}▷  {line}{r}')


# ── Finding / site display ────────────────────────────────────────────────────

def print_finding(f: dict, index: int = 0):
    sev = f.get('severity', 'info').upper()
    sc  = {'CRITICAL': ERR, 'HIGH': ERR, 'MEDIUM': WARN,
           'LOW': LGREY, 'INFO': DIM}.get(sev, DIM)
    print(f'  {DIM}[{index:02d}]{R} {sc}{sev:8}{R}  {WHITE}{f.get("title", "")}{R}')
    if f.get('description'):
        print(f'       {LGREY}{f["description"][:120]}{R}')


def print_site(s: dict):
    sc = {'critical': ERR, 'high': ERR, 'medium': WARN,
          'low': LGREY, 'none': DIM}.get(s.get('worst_severity', 'none'), DIM)
    print(f'  {sc}●{R}  {WHITE}{s.get("url", ""):45}{R}  {DIM}id={s.get("id", "")}{R}')


# ── Spinner ───────────────────────────────────────────────────────────────────

class Spinner:
    _F = ('⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏')

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
            sys.stdout.write(
                f'\r  {GREY}{self._F[i % len(self._F)]}  {DIM}{self._label}{R}'
            )
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
