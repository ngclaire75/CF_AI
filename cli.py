#!/usr/bin/env python3
"""CF_AI CLI v2.0 — Autonomous Cybersecurity Agent REPL.

Entry point for the command-line interface. Implements the CAI architecture:
  - ReACT agent loop (Reasoning + Action)
  - Human-In-The-Loop (HITL) via Ctrl+C
  - Grey ANSI theme
  - All commands execute real tools; results recorded to dashboard

Usage:
    python3 cli.py                   # Interactive REPL
    python3 cli.py -m gpt-4o         # Start with a specific model
    python3 cli.py -e "scan 192.0.2.1"  # Execute one command and exit
"""
from __future__ import annotations
import os
import sys
import readline
import argparse
import traceback
import signal
import textwrap

# ── Bootstrap: load .env before anything else ────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from util import load_env, server_url
    load_env()
except Exception:
    pass

from repl import aesthetics as A
import repl.commands as C
from internal.endpoints import get_client
from internal.audit import get_audit


# ── REPL state ────────────────────────────────────────────────────────────────

class CFAI_REPL:
    HISTORY_FILE = os.path.expanduser('~/.cfai_history')
    MODEL_DEFAULT = os.environ.get('CAI_MODEL', 'claude-sonnet-4-6')

    def __init__(self, model: str = ''):
        self.model   = model or self.MODEL_DEFAULT
        self.running = True
        self._setup_readline()

    # ── Readline ──────────────────────────────────────────────────────────────

    def _setup_readline(self):
        try:
            readline.set_history_length(1000)
            if os.path.exists(self.HISTORY_FILE):
                readline.read_history_file(self.HISTORY_FILE)
            readline.parse_and_bind('tab: complete')
            readline.set_completer(self._completer)
        except Exception:
            pass

    def _save_history(self):
        try:
            readline.write_history_file(self.HISTORY_FILE)
        except Exception:
            pass

    _KEYWORDS = [
        'run', 'scan', 'recon', 'agent', 'chat', 'sites', 'site add',
        'site rm', 'findings', 'fix', 'stats', 'jobs', 'metrics',
        'model', 'history', 'clear', 'help', 'exit', 'quit',
        # roles
        'pentest', 'ctf', 'exploit', 'analyst',
        # common tools
        'nmap', 'nikto', 'nuclei', 'gobuster', 'wpscan', 'sqlmap',
        'subfinder', 'amass', 'wafw00f', 'whatweb', 'hydra', 'john',
        'hashcat', 'ffuf', 'dirb', 'curl', 'wget', 'dig',
    ]

    def _completer(self, text: str, state: int) -> str | None:
        opts = [k for k in self._KEYWORDS if k.startswith(text)]
        return opts[state] if state < len(opts) else None

    # ── Prompt ────────────────────────────────────────────────────────────────

    def _prompt(self) -> str:
        short = self.model.replace('claude-', '').replace('gpt-', '')
        return A.prompt(short)

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def dispatch(self, line: str):
        line = line.strip()
        if not line:
            return

        # Tokenise
        parts = line.split(maxsplit=1)
        verb  = parts[0].lower()
        args  = parts[1] if len(parts) > 1 else ''

        # ── Built-in commands ─────────────────────────────────────────────
        if verb in ('exit', 'quit', 'q'):
            self.running = False
            return

        if verb == 'clear':
            os.system('clear')
            return

        if verb == 'help':
            print(A.HELP_TEXT)
            return

        if verb == 'history':
            C.cmd_history(args)
            return

        if verb == 'model':
            self.model = C.cmd_model(args, set_cb=lambda m: setattr(self, 'model', m)) or self.model
            return

        if verb == 'stats':
            C.cmd_stats(args)
            return

        if verb == 'jobs':
            C.cmd_jobs(args)
            return

        if verb == 'metrics':
            C.cmd_metrics(args)
            return

        # ── Sites ─────────────────────────────────────────────────────────
        if verb == 'sites':
            C.cmd_sites(args)
            return

        if verb == 'site':
            sub_parts = args.split(maxsplit=1)
            sub  = sub_parts[0].lower() if sub_parts else ''
            rest = sub_parts[1] if len(sub_parts) > 1 else ''
            if sub == 'add':
                C.cmd_site_add(rest)
            elif sub in ('rm', 'remove', 'del', 'delete'):
                C.cmd_site_rm(rest)
            else:
                _print_usage('site add <url> | site rm <id>')
            return

        # ── Scan ──────────────────────────────────────────────────────────
        if verb == 'scan':
            C.cmd_scan(args)
            return

        # ── Findings ──────────────────────────────────────────────────────
        if verb == 'findings':
            C.cmd_findings(args)
            return

        if verb == 'fix':
            C.cmd_fix(args)
            return

        # ── AI ────────────────────────────────────────────────────────────
        if verb == 'agent':
            C.cmd_agent(args, model=self.model)
            return

        if verb == 'chat':
            C.cmd_chat(args, model=self.model)
            return

        if verb == 'recon':
            C.cmd_recon(args, model=self.model)
            return

        # ── Shell shorthand ───────────────────────────────────────────────
        if verb == 'run' or line.startswith('$ '):
            cmd = args if verb == 'run' else line[2:]
            C.cmd_run(cmd)
            return

        # ── Fallback: run as shell command ────────────────────────────────
        C.cmd_shell(line)

    # ── Main loop ─────────────────────────────────────────────────────────────

    def start(self):
        print(A.banner())

        # Dashboard connectivity check
        try:
            if get_client().ping():
                print(f'  {A.ok("●")}  Dashboard connected at {server_url()}\n')
            else:
                print(f'  {A.warn("●")}  Dashboard not reachable — start cfai_server.py first\n')
        except Exception:
            print(f'  {A.warn("●")}  Dashboard offline\n')

        print(f'  {A.dim("Model: " + self.model + "   Type help for commands.")}\n')

        while self.running:
            try:
                line = input(self._prompt())
            except KeyboardInterrupt:
                print()
                continue
            except EOFError:
                break

            if not line.strip():
                continue

            try:
                self.dispatch(line)
            except KeyboardInterrupt:
                print(f'\n  {A.warn("Interrupted.")}')
            except Exception as exc:
                print(f'  {A.err("Error:")} {exc}')
                if os.environ.get('DEBUG_MODE') == '1':
                    traceback.print_exc()

        self._save_history()
        print(f'\n  {A.dim("Goodbye.")}\n')


def _print_usage(msg: str):
    print(f'  {A.dim("Usage: " + msg)}')


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='cfai',
        description='CF_AI — Autonomous Cybersecurity Agent CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              python3 cli.py
              python3 cli.py -m gpt-4o
              python3 cli.py -e "scan https://example.com"
        '''),
    )
    parser.add_argument('-m', '--model',   default='', help='AI model to use')
    parser.add_argument('-e', '--exec',    default='', help='Execute one command and exit')
    parser.add_argument('-s', '--server',  default='', help='Dashboard server URL (default: localhost:8888)')
    args = parser.parse_args()

    if args.server:
        os.environ['CFAI_SERVER'] = args.server

    repl = CFAI_REPL(model=args.model)

    if args.exec:
        repl.dispatch(args.exec)
    else:
        repl.start()


if __name__ == '__main__':
    main()
