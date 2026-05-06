#!/usr/bin/env python3
"""cfai — CF_AI CLI entry point.

Install on Kali VPS:
    chmod +x /opt/CF_AI/cfai_cli.py
    ln -sf /opt/CF_AI/cfai_cli.py /usr/local/bin/cfai

Usage:
    cfai                              # interactive REPL
    cfai -m gpt-4o                    # start with specific model
    cfai -e "agent pentest https://target.com"
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli import main

if __name__ == '__main__':
    main()
