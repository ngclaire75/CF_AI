"""CF_AI Security Dashboard — Flask web application."""
from __future__ import annotations
import os
import re
import sys
import time as _time
import threading as _threading
import uuid as _uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, jsonify, abort, request
import dashboard.db as db
from dashboard.remediations import REMEDIATIONS

db.init_db()

app = Flask(__name__, template_folder='templates')

# ── In-memory scan job store (Connect Your Website feature) ──────────────────
_scan_jobs: dict = {}


def _run_background_scan(job_id: str, target: str, agent_type: str,
                          model: str, wp_user: str, wp_app_pass: str, wp_pass: str):
    """Run a WSTG agent in a background thread and stream chunks to _scan_jobs."""
    job = _scan_jobs[job_id]

    # Temporarily set WP credential env vars for this scan
    env_restore: dict = {}
    for k, v in [('WP_USER', wp_user), ('WP_APP_PASSWORD', wp_app_pass), ('WP_PASSWORD', wp_pass)]:
        if v:
            env_restore[k] = os.environ.get(k, '')
            os.environ[k] = v

    try:
        import dataclasses as dc
        from urllib.parse import urlparse as _up
        from agents.wstg_agents import WSTG_REGISTRY
        from sdk.agents import Runner
        from sdk import tracing

        # Normalise domain (strip scheme + path)
        _url = target if '://' in target else 'https://' + target
        _p   = _up(_url)
        domain = (_p.netloc or _p.path.split('/')[0]).rstrip('/')
        job['domain'] = domain

        if agent_type == 'pentest':
            from agents.pentest import run_full_pentest
            t0 = _time.time()
            parts: list = []
            tools: list = [0]
            def _ot(t):  parts.append(t);  job['chunks'].append({'k': 'txt', 'd': t})
            def _oo(n,a): tools[0]+=1;      job['chunks'].append({'k': 'tool', 'n': n, 'a': str(a)[:200]})
            def _or(n,r,e): job['chunks'].append({'k': 'res', 'n': n, 'r': str(r)[:300], 'e': bool(e)})
            run_full_pentest(domain, model=model or None, on_text=_ot, on_tool=_oo, on_result=_or)
            elapsed = _time.time() - t0
            output  = '\n\n'.join(parts)
        else:
            base = WSTG_REGISTRY.get(agent_type)
            if base is None:
                job.update({'status': 'error', 'error': f'Unknown agent type: {agent_type}'}); return

            agent = dc.replace(base, instructions=base.instructions.replace('{domain}', domain))
            if model:
                agent = dc.replace(agent, model=model)

            t0 = _time.time()
            parts, tools = [], [0]
            def _ot(t):   parts.append(t);  job['chunks'].append({'k': 'txt', 'd': t})
            def _oo(n, a): tools[0] += 1;    job['chunks'].append({'k': 'tool', 'n': n, 'a': str(a)[:200]})
            def _or(n,r,e): job['chunks'].append({'k': 'res', 'n': n, 'r': str(r)[:300], 'e': bool(e)})

            with tracing.span(f'dashboard:{agent_type}') as span:
                span.set_attribute('cfai.target', domain)
                Runner.run(agent, f'Run all WSTG-{agent_type.upper()} checks on {domain}.',
                           on_text=_ot, on_tool=_oo, on_result=_or)

            elapsed = _time.time() - t0
            output  = '\n\n'.join(parts)

        scan_id = db.save_scan(
            target=domain, agent_type=agent_type,
            model=getattr(agent, 'model', model) if agent_type != 'pentest' else model,
            status='ok', latency_s=round(elapsed, 2),
            tool_count=tools[0], output=output,
        )
        job.update({'status': 'done', 'elapsed': round(elapsed, 2),
                    'tool_count': tools[0], 'scan_id': scan_id})

    except Exception as exc:
        import traceback as _tb
        job.update({'status': 'error', 'error': str(exc),
                    'trace': _tb.format_exc()[-800:]})
    finally:
        for k, orig in env_restore.items():
            if orig: os.environ[k] = orig
            else: os.environ.pop(k, None)


# Optional shared secret for the remote-save API endpoint.
# Set CFAI_API_KEY in the VPS .env to protect POST /api/scan.
# If unset, the endpoint accepts any request (fine on a private VPS).
_API_KEY = os.environ.get('CFAI_API_KEY', '')


# ── Risk classification ────────────────────────────────────────────────────────

_HIGH_KW = [
    'critical', 'high severity', 'exploit', 'vulnerable', 'vulnerability',
    'remote code execution', 'rce', 'sql injection', 'sqli', 'xss',
    'cross-site scripting', 'authentication bypass', 'privilege escalation',
    'unauthorized access', 'exposed credentials', 'leaked secret',
    'path traversal', 'directory traversal', 'file inclusion',
    'command injection', 'deserialization', 'idor', 'insecure direct object',
    'broken access control', 'account takeover',
]
_MED_KW = [
    'medium', 'moderate', 'information disclosure', 'outdated version',
    'weak cipher', 'misconfigured', 'missing security header',
    'deprecated', 'insecure cookie', 'cors misconfiguration',
    'open redirect', 'clickjacking', 'csrf', 'open port',
    'server version', 'default credentials',
]
_LOW_KW = [
    'low severity', 'informational', 'best practice', 'minor',
    'consider enabling', 'consider disabling', 'suggestion',
]

_ACTION_RE = re.compile(
    r'\b(update|upgrade|patch|disable|enable|restrict|remove|add|fix|'
    r'configure|implement|enforce|rotate|revoke|harden|review|audit|'
    r'change|replace|block|sanitize|validate|encrypt)\b',
    re.I,
)

_REC_HEADERS = (
    'recommendation', 'action item', 'remediation', 'next step',
    'action plan', 'suggested fix', 'what to do', 'mitigation',
    'to fix', 'to remediate',
)

# Lines containing these phrases describe attempts or failed checks — skip them
_NEGATION = re.compile(
    r'\b(no\b|not\b|failed|unsuccessful|did not|does not|returned no|'
    r'found no|no evidence|could not|unable to|attempting|will attempt|'
    r'will try|will now|testing for|checking for|i will|let me|'
    r'next i |next,|explore potential|no result|no data|no output|'
    r'empty response|no vuln|not vuln|not found|not detect|not appear)\b',
    re.I,
)


def risk_level(text: str) -> str:
    """Derive risk only from lines that confirm a finding, skipping attempt/failure lines."""
    lines = text.splitlines()
    for kw_list, label in ((_HIGH_KW, 'HIGH'), (_MED_KW, 'MEDIUM'), (_LOW_KW, 'LOW')):
        for line in lines:
            if _NEGATION.search(line):
                continue
            if any(k in line.lower() for k in kw_list):
                return label
    return 'INFO'


def _strip_md(text: str) -> str:
    text = re.sub(r'\*\*([^*\n]+)\*\*', r'\1', text)
    text = re.sub(r'\*([^*\n]+)\*', r'\1', text)
    return text.strip()


# Recommendations that describe scanner execution problems, not real vulnerabilities
_SCANNER_NOISE = re.compile(
    r'\b(check connectivity|internet connectivity|assessment platform|'
    r'ensure proper internet|rerun with|retry with|adjust.*header|'
    r'passive recon|historical.*data source|alternative means|'
    r'manual inspection|firewall.*rule.*site|rate limit.*rule|'
    r'scan.*block|blocked.*scan|increase.*timeout|reduce.*thread|'
    r'try.*different.*approach|diagnostic|next step.*scan|'
    r'consider passive|proper internet|platform.*connect|'
    r'connectivity.*assess|assess.*connect)\b',
    re.I,
)


def extract_recs(text: str) -> list[str]:
    recs, in_sec = [], False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            in_sec = False
            continue
        if _NEGATION.search(line) or _SCANNER_NOISE.search(line):
            in_sec = False
            continue
        clean = _strip_md(re.sub(r'^[-*+\d.)#]+\s*', '', line))
        clean_lower = clean.lower()
        if any(h in clean_lower for h in _REC_HEADERS):
            in_sec = True
            if ':' in clean:
                after = clean.split(':', 1)[1].strip()
                if len(after) > 12 and not _SCANNER_NOISE.search(after):
                    recs.append(after)
                    in_sec = False
            continue
        is_bullet = line.startswith(('-', '*', '+')) or re.match(r'^\d+[.)]\s', line)
        if in_sec and is_bullet:
            item = _strip_md(re.sub(r'^[-*+\d.)]+\s*', '', line).strip())
            if len(item) > 12:
                recs.append(item)
        elif _ACTION_RE.search(clean) and 25 < len(clean) < 300:
            recs.append(clean)
    seen, out = set(), []
    for r in recs:
        k = r[:50].lower()
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out[:12]


_WP_LOG_RE = re.compile(
    r'^WP-LOG\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*([^|\n]+?)\s*\|\s*(HIGH|MEDIUM|LOW|INFO)\s*$',
    re.I | re.MULTILINE,
)
_WP_LOG_STATUS_RE = re.compile(
    r'^WP-LOG-STATUS\s*\|\s*(\w+)\s*\|\s*([^|\n]+?)\s*\|',
    re.I | re.MULTILINE,
)


def extract_wp_logs(output: str) -> dict:
    """Parse WP-LOG lines from agent output. Returns {entries, status}."""
    entries = []
    for m in _WP_LOG_RE.finditer(output):
        entries.append({
            'timestamp': m.group(1).strip(),
            'user':      m.group(2).strip(),
            'event':     m.group(3).strip(),
            'ip':        m.group(4).strip(),
            'risk':      m.group(5).strip().upper(),
        })
    status_match = _WP_LOG_STATUS_RE.search(output)
    status_code = status_match.group(1) if status_match else ('found' if entries else 'none')
    status_msg  = status_match.group(2).strip() if status_match else ''
    return {'entries': entries, 'status': status_code, 'status_msg': status_msg}


# Narrower negation for remediation matching — only skips lines that say
# a check *passed* or the agent is *about to* test something.
# Deliberately does NOT include \bno\b / \bnot\b because "No X-Frame-Options
# header" is a real finding, not a negation.
_REM_NEGATION = re.compile(
    r'\b(no vulnerability|not vulnerable|not affected|properly configured|'
    r'no issue found|no problem|correctly set|header present|header found|'
    r'attempting|will attempt|will try|will now|testing for|checking for|'
    r'i will test|let me test|i will check|checking if)\b',
    re.I,
)

# Maps lowercase fix-key substrings → internal stack identifier
_FIX_STACK_KEYS: dict[str, str] = {
    'nginx':          'nginx',
    'apache':         'apache',
    '.htaccess':      'apache',
    'php':            'php',
    'wordpress':      'wp',
    'wp-cli':         'wp',
    'functions.php':  'wp',
    'wp-config':      'wp',
}


def _detect_stacks(text: str) -> set[str]:
    """Detect server / CMS stacks referenced in agent output."""
    tl = text.lower()
    found: set[str] = set()
    if any(k in tl for k in ('wordpress', 'wp-content', 'wp-admin', 'wp-login',
                              'xmlrpc.php', '/wp-', 'woocommerce')):
        found.add('wp')
    if 'nginx' in tl:
        found.add('nginx')
    if 'apache' in tl or '.htaccess' in tl:
        found.add('apache')
    if 'php' in tl:
        found.add('php')
    return found


def _filter_fixes(fixes: dict, detected: set[str]) -> dict:
    """Return only the fix entries relevant to detected stacks.

    Fix keys that belong to an undetected stack are hidden; generic keys
    (certbot, bash, manual, general) are always shown.
    Falls back to all fixes when nothing was detected.
    """
    if not detected:
        return fixes
    filtered = {}
    for key, code in fixes.items():
        kl = key.lower()
        fix_stack = next(
            (sid for pattern, sid in _FIX_STACK_KEYS.items() if pattern in kl),
            None,
        )
        is_generic = fix_stack is None or any(
            g in kl for g in ('bash', 'manual', 'general', 'certbot', 'waf')
        )
        if is_generic or fix_stack in detected:
            filtered[key] = code
    return filtered if filtered else fixes


def match_remediations(text: str, target: str = '') -> list[dict]:
    """Return remediation templates for vulnerabilities found in this scan.

    - Only confirms positive findings (skips _REM_NEGATION lines).
    - WordPress-specific remediations require WordPress to be detected.
    - Fix stacks are filtered to those seen in the scan output.
    - The actual target domain replaces the placeholder 'yourdomain.com'.
    """
    pos_lines = [l.lower() for l in text.splitlines() if not _REM_NEGATION.search(l)]
    pos_text  = ' '.join(pos_lines)
    detected  = _detect_stacks(text)

    matched: list[dict] = []
    for rem in REMEDIATIONS:
        if not any(p in pos_text for p in rem['patterns']):
            continue
        # WordPress-specific remediations only if WP is detected in this scan
        if rem['id'].startswith('wp-') and 'wp' not in detected:
            continue
        # Filter fix stacks to those seen in this site's output
        fixes = _filter_fixes(rem['fixes'], detected)
        # Substitute the actual scanned domain (if known) into fix code
        if target:
            fixes = {
                k: v.replace('yourdomain.com', target)
                     .replace('YOUR.OFFICE.IP.HERE', '[your office IP]')
                for k, v in fixes.items()
            }
        matched.append({**rem, 'fixes': fixes})
    return matched


_AGENT_LABELS = {
    'info':    'Information Gathering',
    'conf':    'Configuration Review',
    'athn':    'Authentication Testing',
    'athz':    'Authorization Testing',
    'sess':    'Session Management',
    'inpv':    'Input Validation',
    'cryp':    'Cryptography Review',
    'clnt':    'Client-Side Testing',
    'apit':    'API Security Testing',
    'js':      'JavaScript Analysis',
    'idnt':    'Identity Management',
    'ctf':     'CTF / Challenge',
    'ot':      'OT/ICS Security',
    'enum':    'API Enumeration',
    'pentest': 'Full Penetration Test',
    'recon':   'Reconnaissance',
    'analyst': 'Security Analysis',
    'exploit': 'Exploit Development',
}


def agent_label(a: str) -> str:
    return _AGENT_LABELS.get((a or '').lower(), (a or '').upper())


def _norm_target(raw: str) -> str:
    """Strip scheme and path — keep only host[:port]."""
    t = (raw or '').replace('https://', '').replace('http://', '')
    return t.split('/')[0].split('?')[0].rstrip('.')


def enrich(scan: dict) -> dict:
    scan = dict(scan)
    scan['target']       = _norm_target(scan.get('target', ''))
    out  = scan.get('output', '') or ''
    scan['risk']         = risk_level(out)
    scan['agent_label']  = agent_label(scan.get('agent_type', ''))
    scan['recs']         = extract_recs(out)
    scan['remediations'] = match_remediations(out, target=scan['target'])
    scan['preview']      = out[:400].replace('\n', ' ')
    dt = scan.get('created_at', '') or ''
    scan['display_date'] = dt[:16].replace('T', ' ')
    return scan


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    scans   = [enrich(s) for s in db.get_scans()]
    targets = [enrich(t) for t in db.get_targets()]
    stats   = db.get_stats()

    _prio = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
    all_recs = []
    seen_text: set[str] = set()

    for s in scans:
        # Primary: structured remediation templates (have exact fix code)
        for rem in s['remediations']:
            k = rem['title'][:50].lower()
            if k not in seen_text:
                seen_text.add(k)
                all_recs.append({
                    'target':    s['target'],
                    'risk':      rem['severity'],
                    'text':      rem['title'],
                    'agent':     s['agent_label'],
                    'date':      s['display_date'][:10],
                    'scan_id':   s['id'],
                    'has_fixes': True,
                })
        # Secondary: free-text extracted recommendations
        for r in s['recs']:
            k = r[:50].lower()
            if k not in seen_text:
                seen_text.add(k)
                all_recs.append({
                    'target':    s['target'],
                    'risk':      s['risk'],
                    'text':      r,
                    'agent':     s['agent_label'],
                    'date':      s['display_date'][:10],
                    'scan_id':   s['id'],
                    'has_fixes': False,
                })

    all_recs.sort(key=lambda x: _prio.get(x['risk'], 3))

    return render_template('index.html',
                           scans=scans,
                           targets=targets,
                           stats=stats,
                           all_recs=all_recs[:40])


@app.route('/api/scan/<int:scan_id>')
def api_scan(scan_id):
    row = db.get_scan(scan_id)
    if not row:
        abort(404)
    return jsonify(enrich(row))


@app.route('/api/stats')
def api_stats():
    return jsonify(db.get_stats())


@app.route('/api/scan/<int:scan_id>/cve')
def api_scan_cve(scan_id):
    """Query NVD for real CVEs matching the technologies found in this scan."""
    row = db.get_scan(scan_id)
    if not row:
        abort(404)
    from dashboard.cve import cve_lookup_for_scan
    result = cve_lookup_for_scan(row.get('output', '') or '', row.get('target', ''))
    return jsonify(result)


@app.route('/api/target/<path:target>/wp-logs')
def api_wp_logs(target):
    """Return all WP Activity Log entries parsed from scans for a given target."""
    scans = db.get_scans_for_target(target)
    all_entries = []
    overall_status = 'none'
    overall_msg = ''
    for s in scans:
        result = extract_wp_logs(s.get('output', '') or '')
        if result['entries']:
            overall_status = 'found'
            for e in result['entries']:
                e['scan_id']   = s['id']
                e['scan_date'] = (s.get('created_at') or '')[:16]
                e['agent']     = s.get('agent_type', '')
            all_entries.extend(result['entries'])
        elif result['status'] not in ('none',) and overall_status == 'none':
            overall_status = result['status']
            overall_msg    = result['status_msg']
    all_entries.sort(key=lambda e: e.get('timestamp', ''), reverse=True)
    return jsonify({
        'target':      target,
        'logs':        all_entries,
        'scan_count':  len(scans),
        'status':      overall_status,
        'status_msg':  overall_msg,
    })


@app.route('/api/scan', methods=['POST'])
def api_save_scan():
    """Remote save endpoint — lets a CLI on another machine push scan results here.

    Expects JSON body:
        { "target": "...", "agent_type": "...", "model": "...",
          "status": "ok", "latency_s": 12.3, "tool_count": 5, "output": "..." }

    If CFAI_API_KEY is set in .env, include header:
        X-CFAI-Key: <your-key>
    """
    if _API_KEY:
        key = request.headers.get('X-CFAI-Key', '')
        if key != _API_KEY:
            return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json(force=True, silent=True) or {}
    required = {'target', 'agent_type', 'output'}
    missing  = required - data.keys()
    if missing:
        return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400

    db.save_scan(
        target     = str(data['target'])[:500],
        agent_type = str(data['agent_type'])[:50],
        model      = str(data.get('model', ''))[:100],
        status     = str(data.get('status', 'ok'))[:20],
        latency_s  = float(data.get('latency_s', 0)),
        tool_count = int(data.get('tool_count', 0)),
        output     = str(data['output'])[:60000],
    )
    return jsonify({'saved': True}), 201


@app.route('/api/connect/scan', methods=['POST'])
def api_connect_scan():
    """Start a background scan for the Connect Your Website feature.

    Request JSON: { "target": "example.com", "agent_type": "apit",
                    "model": "", "wp_user": "", "wp_app_pass": "", "wp_pass": "" }
    Response:     { "job_id": "<uuid>" }
    """
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get('target') or '').strip()
    if not target:
        return jsonify({'error': 'target is required'}), 400

    agent_type = (data.get('agent_type') or 'apit').strip().lower()
    model      = (data.get('model') or '').strip()
    wp_user    = (data.get('wp_user') or '').strip()
    wp_app_pass = (data.get('wp_app_pass') or '').strip()
    wp_pass    = (data.get('wp_pass') or '').strip()

    job_id = str(_uuid.uuid4())
    _scan_jobs[job_id] = {
        'status':   'running',
        'target':   target,
        'agent':    agent_type,
        'chunks':   [],
        'offset':   0,
        'domain':   '',
        'scan_id':  None,
        'error':    None,
    }

    t = _threading.Thread(
        target=_run_background_scan,
        args=(job_id, target, agent_type, model, wp_user, wp_app_pass, wp_pass),
        daemon=True,
    )
    t.start()
    return jsonify({'job_id': job_id}), 202


@app.route('/api/connect/scan/<job_id>', methods=['GET'])
def api_connect_scan_poll(job_id):
    """Poll for new chunks from a running background scan.

    Query param `offset` (int, default 0) — index of first unseen chunk.
    Response: { "status": "running"|"done"|"error", "chunks": [...],
                "next_offset": N, "domain": "...", "scan_id": null|int,
                "error": null|"..." }
    """
    job = _scan_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'job not found'}), 404

    offset = int(request.args.get('offset', 0))
    new_chunks = job['chunks'][offset:]
    return jsonify({
        'status':      job['status'],
        'domain':      job.get('domain', ''),
        'scan_id':     job.get('scan_id'),
        'error':       job.get('error'),
        'chunks':      new_chunks,
        'next_offset': offset + len(new_chunks),
    })


if __name__ == '__main__':
    port = int(os.environ.get('CFAI_DASHBOARD_PORT', 8889))
    print(f'CF_AI Dashboard running on http://0.0.0.0:{port}')
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
