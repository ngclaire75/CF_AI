"""CF_AI Security Dashboard — Flask web application."""
from __future__ import annotations
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, jsonify, abort
import dashboard.db as db

db.init_db()

app = Flask(__name__, template_folder='templates')


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


def risk_level(text: str) -> str:
    t = text.lower()
    if any(k in t for k in _HIGH_KW):
        return 'HIGH'
    if any(k in t for k in _MED_KW):
        return 'MEDIUM'
    if any(k in t for k in _LOW_KW):
        return 'LOW'
    return 'INFO'


def _strip_md(text: str) -> str:
    """Strip markdown bold/italic markers from text."""
    text = re.sub(r'\*\*([^*\n]+)\*\*', r'\1', text)
    text = re.sub(r'\*([^*\n]+)\*', r'\1', text)
    return text.strip()


def extract_recs(text: str) -> list[str]:
    """Extract actionable recommendations from agent findings text."""
    recs, in_sec = [], False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            in_sec = False
            continue
        # Strip markdown markers so **Recommendation:** is detected
        clean = _strip_md(re.sub(r'^[-*+\d.)#]+\s*', '', line))
        clean_lower = clean.lower()
        if any(h in clean_lower for h in _REC_HEADERS):
            in_sec = True
            if ':' in clean:
                after = clean.split(':', 1)[1].strip()
                if len(after) > 12:
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
    # deduplicate
    seen, out = set(), []
    for r in recs:
        k = r[:50].lower()
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out[:12]


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


def enrich(scan: dict) -> dict:
    scan = dict(scan)
    out  = scan.get('output', '') or ''
    scan['risk']        = risk_level(out)
    scan['agent_label'] = agent_label(scan.get('agent_type', ''))
    scan['recs']        = extract_recs(out)
    scan['preview']     = out[:400].replace('\n', ' ')
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
    for s in scans:
        for r in s['recs']:
            all_recs.append({
                'target':  s['target'],
                'risk':    s['risk'],
                'text':    r,
                'agent':   s['agent_label'],
                'date':    s['display_date'][:10],
                'scan_id': s['id'],
            })
    all_recs.sort(key=lambda x: _prio.get(x['risk'], 3))
    seen, deduped = set(), []
    for r in all_recs:
        k = r['text'][:50].lower()
        if k not in seen:
            seen.add(k)
            deduped.append(r)

    return render_template('index.html',
                           scans=scans,
                           targets=targets,
                           stats=stats,
                           all_recs=deduped[:40])


@app.route('/api/scan/<int:scan_id>')
def api_scan(scan_id):
    row = db.get_scan(scan_id)
    if not row:
        abort(404)
    return jsonify(enrich(row))


@app.route('/api/stats')
def api_stats():
    return jsonify(db.get_stats())


if __name__ == '__main__':
    port = int(os.environ.get('CFAI_DASHBOARD_PORT', 8889))
    print(f'CF_AI Dashboard running on http://0.0.0.0:{port}')
    app.run(host='0.0.0.0', port=port, debug=False)
