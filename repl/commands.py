"""CF_AI REPL command handlers — standalone CLI, no dashboard required."""
from __future__ import annotations
import dataclasses
import json
import os
import time
import urllib.request
import urllib.error
import subprocess
from collections import deque
from datetime import datetime

from repl import aesthetics as A
from util import truncate, format_duration

# WSTG categories that can be passed directly to `agent`
WSTG_CATEGORIES = {
    'info', 'js', 'conf', 'idnt', 'athn', 'athz',
    'sess', 'inpv', 'cryp', 'clnt', 'apit',
}
SPECIAL_CATEGORIES = {'ctf', 'ot', 'enum'}


# ── Scan saver: local DB or remote VPS dashboard ─────────────────────────────

def _save_scan(*, target, agent_type, model='', status='ok',
               latency_s=0.0, tool_count=0, output=''):
    """Save scan result locally or POST to remote VPS dashboard.

    If CFAI_DASHBOARD_URL is set in .env (e.g. http://YOUR_VPS_IP:8889),
    the result is POSTed to the VPS over HTTP.  Otherwise it writes to the
    local SQLite database (same machine as the dashboard).
    """
    dashboard_url = os.environ.get('CFAI_DASHBOARD_URL', '').rstrip('/')
    if dashboard_url:
        payload = json.dumps({
            'target':     target,
            'agent_type': agent_type,
            'model':      model,
            'status':     status,
            'latency_s':  round(float(latency_s), 2),
            'tool_count': int(tool_count),
            'output':     str(output)[:60000],
        }).encode('utf-8')
        headers = {'Content-Type': 'application/json'}
        api_key = os.environ.get('CFAI_API_KEY', '')
        if api_key:
            headers['X-CFAI-Key'] = api_key
        req = urllib.request.Request(
            f'{dashboard_url}/api/scan',
            data=payload,
            headers=headers,
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except Exception as e:
            print(f'  [dashboard] Remote save failed: {e}')
    else:
        try:
            from dashboard.db import save_scan
            save_scan(target=target, agent_type=agent_type, model=model,
                      status=status, latency_s=latency_s,
                      tool_count=tool_count, output=output)
        except Exception:
            pass


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

    _record('shell', line, output)
    return output


# ── WSTG agent runner ─────────────────────────────────────────────────────────

def _run_wstg(category: str, target: str, model: str = ''):
    """Run a single WSTG category agent against target."""
    import dataclasses as dc
    from agents.wstg_agents import WSTG_REGISTRY
    from sdk.agents import Runner
    from sdk import tracing

    domain = target.replace('https://', '').replace('http://', '').rstrip('/')
    if not domain:
        _print_err(f'Usage: agent {category} <target>')
        return

    base  = WSTG_REGISTRY.get(category)
    if base is None:
        _print_err(f'Unknown WSTG category: {category}')
        return

    agent = dc.replace(base, instructions=base.instructions.replace('{domain}', domain))
    if model:
        agent = dc.replace(agent, model=model)

    cat = category.upper()
    print(f'\n  {A.dim(f"WSTG-{cat} agent  ·  target: {domain}  ·  model: {agent.model}")}\n'
          f'  {A.dim("Press Ctrl+C at any time for Human-In-The-Loop (HITL)")}\n')

    _record('agent', f'agent {category} {domain}')
    t0 = time.time()

    _parts, _tools, _status = [], [0], ['ok']
    def _on_text(t):    _parts.append(t); A.print_agent_text(t)
    def _on_tool(n, a): _tools[0] += 1;  A.print_tool_call(n, a)

    with tracing.span(f'agent:WSTG-{cat}') as span:
        span.set_attribute('cfai.category', category)
        span.set_attribute('cfai.target', domain)
        try:
            Runner.run(
                agent,
                f'Run all WSTG-{cat} checks on {domain}.',
                on_text=_on_text,
                on_tool=_on_tool,
                on_result=lambda n, r, e: A.print_tool_result(n, r, e),
            )
        except KeyboardInterrupt:
            _status[0] = 'interrupted'
            print(f'\n  {A.warn("[HITL] Agent interrupted.")}')

    elapsed = time.time() - t0
    if elapsed > 0.5:
        print(f'\n  {A.dim(f"Session finished in {format_duration(elapsed)}")}')

    _save_scan(target=domain, agent_type=category, model=agent.model,
               status=_status[0], latency_s=elapsed,
               tool_count=_tools[0], output='\n\n'.join(_parts))


# ── Special agent runner (ctf / ot) ──────────────────────────────────────────

def _run_special(category: str, target: str, model: str = ''):
    """Run CTF or OT/ICS agent against target."""
    import dataclasses as dc
    from agents.special_agents import SPECIAL_REGISTRY
    from sdk.agents import Runner
    from sdk import tracing

    if not target:
        _print_err(f'Usage: agent {category} <target|challenge-url>')
        return

    base  = SPECIAL_REGISTRY.get(category)
    if base is None:
        _print_err(f'Unknown special category: {category}')
        return

    # Substitute {target} in instructions
    instructions = base.instructions.replace('{target}', target)
    agent = dc.replace(base, instructions=instructions)
    if model:
        agent = dc.replace(agent, model=model)

    label = {
        'ctf':  'CTF Solver',
        'ot':   'OT/ICS Security',
        'enum': 'API Enumeration / IDOR',
    }.get(category, category.upper())
    print(f'\n  {A.dim(f"{label} agent  ·  target: {target}  ·  model: {agent.model}")}\n'
          f'  {A.dim("Press Ctrl+C at any time for Human-In-The-Loop (HITL)")}\n')

    _record('agent', f'agent {category} {target}')
    t0 = time.time()

    _parts, _tools, _status = [], [0], ['ok']
    def _on_text(t):    _parts.append(t); A.print_agent_text(t)
    def _on_tool(n, a): _tools[0] += 1;  A.print_tool_call(n, a)

    with tracing.span(f'agent:{category}') as span:
        span.set_attribute('cfai.category', category)
        span.set_attribute('cfai.target', target)
        try:
            Runner.run(
                agent,
                f'Begin {label} on {target}.',
                on_text=_on_text,
                on_tool=_on_tool,
                on_result=lambda n, r, e: A.print_tool_result(n, r, e),
            )
        except KeyboardInterrupt:
            _status[0] = 'interrupted'
            print(f'\n  {A.warn("[HITL] Agent interrupted.")}')

    elapsed = time.time() - t0
    if elapsed > 0.5:
        print(f'\n  {A.dim(f"Session finished in {format_duration(elapsed)}")}')

    _save_scan(target=target, agent_type=category, model=agent.model,
               status=_status[0], latency_s=elapsed,
               tool_count=_tools[0], output='\n\n'.join(_parts))


# ── Agent / Chat ──────────────────────────────────────────────────────────────

def cmd_agent(args: str, model: str = ''):
    """Route to WSTG agent, full pentest, or generic AI agent."""
    tokens = args.strip().split(maxsplit=1)
    if not tokens:
        _print_err('Usage: agent <category|pentest> <target>')
        return

    verb    = tokens[0].lower()
    rest    = tokens[1].strip() if len(tokens) > 1 else ''

    # ── Single WSTG category ──────────────────────────────────────────────────
    if verb in WSTG_CATEGORIES:
        _run_wstg(verb, rest, model=model)
        return

    # ── Special agents (ctf / ot) ─────────────────────────────────────────────
    if verb in SPECIAL_CATEGORIES:
        _run_special(verb, rest, model=model)
        return

    # ── Full pentest (all 10 agents) ──────────────────────────────────────────
    if verb == 'pentest':
        target = rest
        if not target:
            _print_err('Usage: agent pentest <url>')
            return
        from agents.pentest import run_full_pentest
        _eff = model or os.environ.get('CAI_MODEL', 'gpt-4o')
        print(f'\n  {A.dim(f"Full WSTG pentest  ·  target: {target}  ·  model: {_eff}")}\n'
              f'  {A.dim("Running all 10 WSTG agents sequentially — Ctrl+C skips current agent")}\n')
        _record('agent', f'agent pentest {target}')
        try:
            run_full_pentest(
                target,
                model=model,
                on_text=lambda t: A.print_agent_text(t),
                on_tool=lambda n, a: A.print_tool_call(n, a),
                on_result=lambda n, r, e: A.print_tool_result(n, r, e),
            )
        except KeyboardInterrupt:
            print(f'\n  {A.warn("[HITL] Pentest aborted.")}')
        return

    # ── Legacy role-based agent (ctf / recon / exploit / analyst) ────────────
    roles = ('ctf', 'recon', 'exploit', 'analyst')
    if verb in roles:
        role    = verb
        message = rest
    else:
        role    = 'pentest'
        message = args.strip()

    target = ''
    for word in message.split():
        if '.' in word and not word.startswith('-'):
            target = word.rstrip('/')
            break

    if not message:
        message = f'Begin reconnaissance on {target}.' if target else 'Begin reconnaissance and report findings.'

    from sdk.agents import Agent, Runner
    from tools.generic_linux_command import generic_linux_command, read_file, write_file
    from prompts.security import get as get_prompt

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

    _record('agent', f'agent {role} {message[:100]}')
    t0 = time.time()

    _parts, _tools, _status = [], [0], ['ok']
    def _on_text(t):    _parts.append(t); A.print_agent_text(t)
    def _on_tool(n, a): _tools[0] += 1;  A.print_tool_call(n, a)

    try:
        Runner.run(
            agent, message,
            on_text=_on_text,
            on_tool=_on_tool,
            on_result=lambda n, r, e: A.print_tool_result(n, r, e),
        )
    except KeyboardInterrupt:
        _status[0] = 'interrupted'
        print(f'\n  {A.warn("[HITL] Agent interrupted.")}')

    elapsed = time.time() - t0
    if elapsed > 0.5:
        print(f'\n  {A.dim(f"Session finished in {format_duration(elapsed)}")}')

    _save_scan(target=target or message[:80], agent_type=role, model=eff_model,
               status=_status[0], latency_s=elapsed,
               tool_count=_tools[0], output='\n\n'.join(_parts))


def cmd_recon(args: str, model: str = ''):
    """Spawn recon agent for passive + active reconnaissance."""
    target = args.strip()
    if not target:
        _print_err('Usage: recon <target>')
        return
    _run_wstg('info', target, model=model)


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
