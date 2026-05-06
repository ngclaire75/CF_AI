"""CF_AI REPL command handlers."""
from __future__ import annotations
import os
import time
import shlex
import subprocess
from typing import Optional

from repl import aesthetics as A
from internal.endpoints import get_client
from internal.audit import get_audit
from util import parse_target, truncate, format_duration


# ── Helpers ───────────────────────────────────────────────────────────────────

def _client():
    return get_client()

def _audit():
    return get_audit()

def _print_err(msg: str):
    print(f'  {A.err("✗")}  {msg}')

def _print_ok(msg: str):
    print(f'  {A.ok("✓")}  {msg}')

def _print_warn(msg: str):
    print(f'  {A.warn("!")}  {msg}')


# ── run / shell execution ─────────────────────────────────────────────────────

def cmd_run(args: str, *, record: bool = True) -> str:
    """Execute a shell command via the dashboard server (recorded + logged)."""
    command = args.strip()
    if not command:
        _print_err('Usage: run <command>')
        return ''

    t0 = time.time()
    with A.Spinner(command[:60]):
        result = _client().execute(command, use_cache=False)
    elapsed = time.time() - t0

    if result.get('blocked'):
        _print_err(f'Blocked: {result.get("error","injection protection")}')
        return ''

    output = (result.get('output') or result.get('result') or
              result.get('stdout', '') + result.get('stderr', '')).strip()
    error  = result.get('error', '')

    if output:
        A.print_output(output)
    elif error:
        _print_err(error)

    if record:
        _audit().record('command', command, output, duration=elapsed)

    return output


def cmd_shell(line: str) -> str:
    """Fallback: execute unrecognized input as a shell command directly."""
    t0 = time.time()
    try:
        proc = subprocess.Popen(
            line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd='/root',
            env={**os.environ, 'TERM': 'dumb'},
        )
        lines  = []
        for l in proc.stdout:
            print(f'  {A.LGREY}{l.rstrip()}{A.R}')
            lines.append(l.rstrip())
        proc.wait()
        output = '\n'.join(lines)
    except Exception as exc:
        output = f'[error: {exc}]'
        _print_err(output)

    elapsed = time.time() - t0
    _audit().record('command', line, output, duration=elapsed)
    return output


# ── Sites ─────────────────────────────────────────────────────────────────────

def cmd_sites(_: str):
    with A.Spinner('Loading sites…'):
        sites = _client().sites()
    if not sites:
        print(f'  {A.dim("No sites connected. Use: site add <url>")}')
        return
    print(f'\n  {A.white(f"{len(sites)} connected site(s):")}\n')
    for s in sites:
        A.print_site(s)
    print()


def cmd_site_add(args: str):
    parts = args.split(maxsplit=1)
    if not parts:
        _print_err('Usage: site add <url> [name]')
        return
    url  = parts[0]
    name = parts[1] if len(parts) > 1 else ''
    with A.Spinner(f'Connecting {url}…'):
        r = _client().add_site(url, name=name)
    if r.get('error'):
        _print_err(r['error'])
    else:
        site = r.get('site', {})
        _print_ok(f'Site added: {site.get("url")}  id={site.get("id")}  platform={site.get("platform")}')
        _audit().record('site_add', f'site add {url}')


def cmd_site_rm(args: str):
    site_id = args.strip()
    if not site_id:
        _print_err('Usage: site rm <site_id>')
        return
    r = _client().remove_site(site_id)
    if r.get('error'):
        _print_err(r['error'])
    else:
        _print_ok(f'Site {site_id} removed')
        _audit().record('site_rm', f'site rm {site_id}')


# ── Scan ──────────────────────────────────────────────────────────────────────

def cmd_scan(args: str):
    target = args.strip()
    if not target:
        _print_err('Usage: scan <site_id|url>')
        return

    # Check if it's a URL rather than an ID — add site first
    site_id = target
    if '.' in target or target.startswith('http'):
        url, _ = parse_target(target)
        with A.Spinner(f'Connecting {url}…'):
            r = _client().add_site(url)
        if r.get('error') and 'already' not in r.get('error', ''):
            _print_err(r['error'])
            return
        site_id = r.get('site', {}).get('id', target)

    with A.Spinner(f'Starting scan {site_id}…'):
        r = _client().start_scan(site_id)
    if r.get('error'):
        _print_err(r['error'])
        return

    scan_id = r.get('scan_id', '')
    _print_ok(f'Scan started  scan_id={scan_id}')
    print(f'  {A.dim("Monitor in dashboard → Sites → click site → Live Logs")}')
    _audit().record('scan', f'scan {target}', site_id=site_id)

    # Poll status
    print(f'  {A.dim("Polling status…")}')
    for _ in range(60):
        time.sleep(5)
        status = _client().scan_status(site_id)
        phase    = status.get('phase', '')
        progress = status.get('progress', 0)
        print(f'  {A.GREY}[{progress:3d}%]{A.R}  {A.dim(phase)}', end='\r')
        if status.get('status') in ('complete', 'error'):
            print()
            if status.get('status') == 'complete':
                _print_ok(f'Scan complete — run "findings {site_id}" to review')
            else:
                _print_err(f'Scan error: {status.get("phase","")}')
            break
    else:
        print()
        print(f'  {A.dim("Still running — use dashboard to monitor")}')


# ── Findings ──────────────────────────────────────────────────────────────────

def cmd_findings(args: str):
    site_id = args.strip()
    with A.Spinner('Loading findings…'):
        findings = _client().findings(site_id)
    if not findings:
        print(f'  {A.dim("No findings." + (" For site " + site_id if site_id else ""))}')
        return
    findings.sort(key=lambda f: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(
        f.get('severity', 'info'), 5))
    print(f'\n  {A.white(f"{len(findings)} finding(s):")}\n')
    for i, f in enumerate(findings):
        A.print_finding(f, i)
    print()


def cmd_fix(args: str):
    finding_id = args.strip()
    if not finding_id:
        _print_err('Usage: fix <finding_id>')
        return
    with A.Spinner(f'Applying fix for {finding_id}…'):
        r = _client().apply_fix(finding_id)
    if r.get('blocked'):
        _print_err(f'Fix blocked by guardrails: {r.get("block_reason","")}')
    elif r.get('success'):
        _print_ok('Fix applied successfully')
        if r.get('output'):
            A.print_output(r['output'])
    else:
        _print_err(r.get('error') or r.get('output') or 'Fix failed')
    _audit().record('fix', f'fix {finding_id}')


# ── Stats / Jobs / Metrics ────────────────────────────────────────────────────

def cmd_stats(_: str):
    with A.Spinner('Loading stats…'):
        s = _client().stats()
    print(f'\n  {A.white("Dashboard stats:")}\n')
    print(f'  {A.LGREY}Sites:    {A.WHITE}{s.get("sites",0)}{A.R}')
    print(f'  {A.LGREY}Critical: {A.ERR}{s.get("critical",0)}{A.R}')
    print(f'  {A.LGREY}High:     {A.WARN}{s.get("high",0)}{A.R}')
    print(f'  {A.LGREY}Findings: {A.LGREY}{s.get("findings",0)}{A.R}')
    print(f'  {A.LGREY}Scans:    {A.LGREY}{s.get("scans",0)} running{A.R}')
    print(f'  {A.LGREY}Fixes:    {A.LGREY}{s.get("fixes",0)} pending{A.R}')
    print()


def cmd_jobs(_: str):
    with A.Spinner('Loading jobs…'):
        jobs = _client().jobs()
    if not jobs:
        print(f'  {A.dim("No jobs in queue.")}')
        return
    print(f'\n  {A.white(f"{len(jobs)} job(s):")}\n')
    for j in jobs:
        status = j.get('status', '')
        sc = {'running': A.CYAN, 'done': A.OK, 'failed': A.ERR,
              'pending': A.DIM, 'cancelled': A.GREY}.get(status, A.LGREY)
        print(f'  {sc}{status:10}{A.R}  {A.DIM}{j.get("id",""):8}{A.R}  '
              f'{A.LGREY}{j.get("type",""):8}{A.R}  {A.DIM}{j.get("site_id","")}{A.R}')
    print()


def cmd_metrics(_: str):
    with A.Spinner('Loading metrics…'):
        m = _client().metrics()
    print(f'\n  {A.white("Telemetry counters:")}\n')
    for k, v in m.items():
        print(f'  {A.LGREY}{k:25}{A.WHITE}{v}{A.R}')
    print()


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
        message = tokens[1] if len(tokens) > 1 else 'Begin reconnaissance and report your findings.'
    else:
        role    = 'pentest'
        message = args.strip() or 'Begin reconnaissance and report your findings.'

    eff_model = model or os.environ.get('CAI_MODEL', 'claude-sonnet-4-6')
    system    = get_prompt(role)

    print(f'\n  {A.dim(f"Agent: {role}  model: {eff_model}")}\n'
          f'  {A.dim("Press Ctrl+C at any time for Human-In-The-Loop (HITL)")}\n')

    agent = Agent(
        name=f'CF_AI-{role}',
        instructions=system,
        tools=[generic_linux_command, read_file, write_file],
        model=eff_model,
    )

    t0 = time.time()
    _audit().record('agent', f'agent {role} {message[:100]}')

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
    print(f'\n  {A.dim(f"Session finished in {format_duration(elapsed)}")}')


def cmd_chat(args: str, model: str = ''):
    """Single AI message via dashboard chat endpoint."""
    if not args.strip():
        _print_err('Usage: chat <message>')
        return
    with A.Spinner('Thinking…'):
        r = _client().chat(args.strip())
    resp = r.get('response') or r.get('message') or r.get('output', '')
    if resp:
        A.print_agent_text(resp)
    elif r.get('error'):
        _print_err(r['error'])
    _audit().record('chat', args.strip(), resp)


# ── Recon ─────────────────────────────────────────────────────────────────────

def cmd_recon(args: str, model: str = ''):
    """Spawn recon agent for passive + active reconnaissance."""
    target = args.strip()
    if not target:
        _print_err('Usage: recon <target>')
        return
    cmd_agent(f'recon Perform comprehensive reconnaissance on {target}', model=model)


# ── History ───────────────────────────────────────────────────────────────────

def cmd_history(_: str):
    records = _audit().history(50)
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
    known = [
        'claude-opus-4-7', 'claude-sonnet-4-6', 'claude-haiku-4-5',
        'gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'o1', 'o3-mini',
    ]
    if not args.strip():
        current = os.environ.get('CAI_MODEL', 'claude-sonnet-4-6')
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
