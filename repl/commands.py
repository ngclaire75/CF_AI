"""CF_AI REPL command handlers — standalone CLI, no dashboard required."""
from __future__ import annotations
import os
import time
import subprocess
from collections import deque
from datetime import datetime

from repl import aesthetics as A
from util import parse_target, truncate, format_duration


# ── Local history (in-memory ring buffer) ────────────────────────────────────

_history: deque = deque(maxlen=500)


def _record(cmd_type: str, command: str, output: str = ''):
    _history.append({
        'timestamp': datetime.utcnow().isoformat(),
        'type':      cmd_type,
        'command':   command,
        'output':    output[:500],
    })


# ── Helpers ───────────────────────────────────────────────────────────────────

def _print_err(msg: str):
    print(f'  {A.err("✗")}  {msg}')

def _print_ok(msg: str):
    print(f'  {A.ok("✓")}  {msg}')

def _print_warn(msg: str):
    print(f'  {A.warn("!")}  {msg}')


# ── Shell execution ───────────────────────────────────────────────────────────

def cmd_shell(line: str) -> str:
    """Execute a shell command locally."""
    t0 = time.time()
    try:
        proc = subprocess.Popen(
            line, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True,
            env={**os.environ, 'TERM': 'dumb'},
        )
        lines = []
        for ln in proc.stdout:
            print(f'  {A.LGREY}{ln.rstrip()}{A.R}')
            lines.append(ln.rstrip())
        proc.wait()
        output = '\n'.join(lines)
    except Exception as exc:
        output = f'[error: {exc}]'
        _print_err(output)

    elapsed = time.time() - t0
    _record('shell', line, output)
    return output


# ── Agent / Chat ──────────────────────────────────────────────────────────────

def cmd_agent(args: str, model: str = ''):
    """Spawn a ReACT agent with all security tools."""
    from sdk.agents import Agent, Runner
    from tools.generic_linux_command import (generic_linux_command,
                                              read_file, write_file)
    from prompts.security import get as get_prompt

    tokens = args.strip().split(maxsplit=1)
    roles  = ('pentest', 'ctf', 'recon', 'exploit', 'analyst')
    if tokens and tokens[0] in roles:
        role    = tokens[0]
        message = tokens[1] if len(tokens) > 1 else ''
    else:
        role    = 'pentest'
        message = args.strip()

    # Extract target URL/domain from the message so the prompt can substitute it
    target = ''
    for word in message.split():
        if '.' in word and not word.startswith('-'):
            target = word.rstrip('/')
            break

    if not message:
        message = f'Run all WSTG checks on {target}.' if target else 'Begin reconnaissance and report your findings.'

    eff_model = model or os.environ.get('CAI_MODEL', 'gpt-4o')
    system    = get_prompt(role, target=target)

    print(f'\n  {A.dim(f"Agent: {role}  model: {eff_model}")}\n'
          f'  {A.dim("Press Ctrl+C at any time for Human-In-The-Loop (HITL)")}\n')

    agent = Agent(
        name=f'CF_AI-{role}',
        instructions=system,
        tools=[generic_linux_command, read_file, write_file],
        model=eff_model,
        max_turns=50,
    )

    t0 = time.time()
    _record('agent', f'agent {role} {message[:100]}')

    try:
        Runner.run(
            agent, message,
            on_text   = lambda t: A.print_agent_text(t),
            on_tool   = lambda n, a: A.print_tool_call(n, a),
            on_result = lambda n, r, e: A.print_tool_result(n, r, e),
        )
    except KeyboardInterrupt:
        print(f'\n  {A.warn("[HITL] Agent interrupted.")}')

    elapsed = time.time() - t0
    if elapsed > 0.5:
        print(f'\n  {A.dim(f"Session finished in {format_duration(elapsed)}")}')


def cmd_recon(args: str, model: str = ''):
    """Spawn recon agent for passive + active reconnaissance."""
    target = args.strip()
    if not target:
        _print_err('Usage: recon <target>')
        return
    cmd_agent(f'recon {target}', model=model)


def cmd_chat(args: str, model: str = ''):
    """Single-turn AI chat (no tools)."""
    from sdk.agents import Agent, Runner
    from prompts.security import get as get_prompt

    if not args.strip():
        _print_err('Usage: chat <message>')
        return

    eff_model = model or os.environ.get('CAI_MODEL', 'gpt-4o')
    agent = Agent(
        name='CF_AI-chat',
        instructions=get_prompt('analyst'),
        tools=[],
        model=eff_model,
        max_turns=1,
    )

    try:
        Runner.run(
            agent, args.strip(),
            on_text=lambda t: A.print_agent_text(t),
        )
    except KeyboardInterrupt:
        pass

    _record('chat', args.strip())


# ── History ───────────────────────────────────────────────────────────────────

def cmd_history(_: str):
    records = list(_history)[-50:]
    if not records:
        print(f'  {A.dim("No history yet.")}')
        return
    print(f'\n  {A.white("Command history:")}\n')
    for r in records:
        ts  = r.get('timestamp', '')[:16]
        cmd = truncate(r.get('command', ''), 80)
        print(f'  {A.DIM}{ts}{A.R}  {A.LGREY}{cmd}{A.R}')
    print()


# ── Model ─────────────────────────────────────────────────────────────────────

def cmd_model(args: str, set_cb=None) -> str:
    """Show or set the active AI model."""
    known = ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'o1', 'o3-mini']
    if not args.strip():
        current = os.environ.get('CAI_MODEL', 'gpt-4o')
        print(f'\n  {A.white("Active model:")} {A.CYAN}{current}{A.R}')
        print(f'  {A.dim("Available:")}\n')
        for m in known:
            tick = A.ok('✓') if m == current else A.dim('○')
            print(f'    {tick}  {A.LGREY}{m}{A.R}')
        print()
        return current
    model = args.strip()
    os.environ['CAI_MODEL'] = model
    _print_ok(f'Model set to {model}')
    if set_cb:
        set_cb(model)
    return model
