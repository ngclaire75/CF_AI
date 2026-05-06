#!/usr/bin/env python3
"""CF_AI CLI — Autonomous Cybersecurity Agent REPL.

Usage:
    python3 cli.py                      # Interactive REPL
    python3 cli.py -m gpt-4o            # Start with a specific model
    python3 cli.py -e "agent pentest https://example.com"
"""
from __future__ import annotations
import os
import sys
import readline
import argparse
import traceback
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from util import load_env
    load_env()
except Exception:
    pass

from repl import aesthetics as A
import repl.commands as C

# ── Phoenix / OTel tracing (opt-in via CFAI_TRACING=1) ───────────────────────
try:
    from sdk.tracing import setup as _tracing_setup, phoenix_url as _phoenix_url
    _tracing_active = _tracing_setup()
except Exception:
    _tracing_active = False
    _phoenix_url    = lambda: ''


# ── REPL ──────────────────────────────────────────────────────────────────────

class CFAI_REPL:
    HISTORY_FILE  = os.path.expanduser('~/.cfai_history')
    MODEL_DEFAULT = os.environ.get('CAI_MODEL', 'gpt-4o')

    def __init__(self, model: str = ''):
        self.model   = model or self.MODEL_DEFAULT
        self.running = True
        self._setup_readline()

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
        'agent', 'recon', 'chat', 'model', 'history', 'clear', 'help', 'exit', 'quit',
        'pentest', 'ctf', 'exploit', 'analyst',
        'nmap', 'nikto', 'nuclei', 'gobuster', 'wpscan', 'sqlmap',
        'subfinder', 'amass', 'wafw00f', 'whatweb', 'hydra', 'ffuf',
        'curl', 'wget', 'dig', 'whois',
    ]

    def _completer(self, text: str, state: int) -> str | None:
        opts = [k for k in self._KEYWORDS if k.startswith(text)]
        return opts[state] if state < len(opts) else None

    def _prompt(self) -> str:
        short = self.model.replace('claude-', '').replace('gpt-', '')
        return A.prompt(short)

    def dispatch(self, line: str):
        line = line.strip()
        if not line:
            return

        parts = line.split(maxsplit=1)
        verb  = parts[0].lower()
        args  = parts[1] if len(parts) > 1 else ''

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

        if verb == 'agent':
            C.cmd_agent(args, model=self.model)
            return

        if verb == 'chat':
            C.cmd_chat(args, model=self.model)
            return

        if verb == 'recon':
            C.cmd_recon(args, model=self.model)
            return

        # Anything else → run as local shell command
        C.cmd_shell(line)

    def start(self):
        print(A.banner())
        if _tracing_active:
            print(f'  {A.ok("●")}  Phoenix tracing active → {_phoenix_url()}\n')
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
              python3 cli.py -e "agent pentest https://example.com"
              python3 cli.py -e "recon target.com"
        '''),
    )
    parser.add_argument('-m', '--model', default='', help='AI model (gpt-4o, claude-sonnet-4-6, llama3.2, …)')
    parser.add_argument('-e', '--exec',  default='', help='Execute one command and exit')
    args = parser.parse_args()

    repl = CFAI_REPL(model=args.model)

    if args.exec:
        repl.dispatch(args.exec)
    else:
        repl.start()


if __name__ == '__main__':
    main()
