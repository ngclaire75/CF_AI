#!/usr/bin/env python3
"""cfai — CF_AI CLI entry point.

This file is the installed binary (linked to /usr/local/bin/cfai).
The actual implementation lives in cli.py following the CAI architecture.

Usage:
    cfai                            # interactive REPL
    cfai -m gpt-4o                  # start with GPT-4o model
    cfai -e "scan https://target.com"  # execute one command and exit
    cfai -s http://vps:8888         # connect to remote dashboard

Install on Kali VPS:
    chmod +x /opt/CF_AI/cfai_cli.py
    ln -sf /opt/CF_AI/cfai_cli.py /usr/local/bin/cfai
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli import main

if __name__ == '__main__':
    main()
