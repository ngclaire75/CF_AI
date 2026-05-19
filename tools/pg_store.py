"""
CF_AI — PostgreSQL Persistent Storage with pgvector.
Stores scan results, findings, and vectors for semantic search.
Falls back to JSON file storage when PostgreSQL is not configured.

Connection: PG_HOST, PG_PORT, PG_NAME, PG_USER, PG_PASSWORD env vars.
Vector storage: requires pgvector extension (CREATE EXTENSION IF NOT EXISTS vector;)
"""
from __future__ import annotations
import json
import os
import time
import uuid
from pathlib import Path
from sdk.agents import function_tool

# ── JSON fallback store ───────────────────────────────────────────────────────
_PG_DIR = Path(__file__).parent.parent / 'data' / 'pg_fallback'
_PG_DIR.mkdir(parents=True, exist_ok=True)


def _fb_path(filename: str) -> Path:
    return _PG_DIR / filename


def _fb_load(filename: str, default=None):
    p = _fb_path(filename)
    if not p.exists():
        return default if default is not None else []
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return default if default is not None else []


def _fb_save(filename: str, data) -> None:
    _fb_path(filename).write_text(json.dumps(data, indent=2), encoding='utf-8')


# ── PostgreSQL connection ─────────────────────────────────────────────────────
def _get_pg_conn():
    host = os.environ.get('PG_HOST', '').strip()
    port = os.environ.get('PG_PORT', '5432').strip()
    name = os.environ.get('PG_NAME', '').strip()
    user = os.environ.get('PG_USER', 'postgres').strip()
    pw   = os.environ.get('PG_PASSWORD', '').strip()
    if not host or not name:
        return None
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=host, port=int(port), dbname=name,
            user=user, password=pw,
            connect_timeout=5,
            sslmode=os.environ.get('PG_SSL', 'prefer'),
        )
        return conn
    except Exception:
        return None


def _pg_available() -> bool:
    conn = _get_pg_conn()
    if conn:
        conn.close()
        return True
    return False


def _pg_exec(query: str, params=None, fetch: bool = False):
    conn = _get_pg_conn()
    if not conn:
        return None
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(query, params or ())
                if fetch:
                    cols = [d[0] for d in cur.description] if cur.description else []
                    return [dict(zip(cols, row)) for row in cur.fetchall()]
                return True
    except Exception:
        return None
    finally:
        conn.close()


def _pg_ensure_schema():
    _pg_exec("""
        CREATE TABLE IF NOT EXISTS cf_scan_results (
            id          TEXT PRIMARY KEY,
            target      TEXT NOT NULL,
            agent_type  TEXT,
            username    TEXT,
            started_at  BIGINT,
            finished_at BIGINT,
            status      TEXT DEFAULT 'running',
            report_text TEXT,
            findings    JSONB DEFAULT '[]',
            metadata    JSONB DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_cf_scans_target ON cf_scan_results(target);
        CREATE INDEX IF NOT EXISTS idx_cf_scans_username ON cf_scan_results(username);
    """)
    _pg_exec("""
        CREATE TABLE IF NOT EXISTS cf_findings (
            id          TEXT PRIMARY KEY,
            scan_id     TEXT,
            target      TEXT,
            severity    TEXT,
            category    TEXT,
            title       TEXT,
            description TEXT,
            evidence    TEXT,
            remediation TEXT,
            cvss        REAL,
            cve_ids     TEXT[],
            created_at  BIGINT,
            metadata    JSONB DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_cf_findings_target ON cf_findings(target);
        CREATE INDEX IF NOT EXISTS idx_cf_findings_severity ON cf_findings(severity);
    """)


# ── Function tools ─────────────────────────────────────────────────────────────

@function_tool
def pg_save_scan(scan_id: str, target: str, agent_type: str = '',
                 username: str = '', report_text: str = '',
                 findings_json: str = '', metadata_json: str = '') -> str:
    """
    Save or update a scan result to PostgreSQL persistent storage.
    Falls back to JSON file storage when PG is not configured.

    Args:
        scan_id:       Unique scan ID (UUID)
        target:        Target domain/IP scanned
        agent_type:    Agent used (e.g. "apit", "info", "pentest")
        username:      User who ran the scan
        report_text:   Full markdown report text
        findings_json: JSON array of findings [{severity, title, description, ...}]
        metadata_json: JSON object of extra metadata
    """
    ts = int(time.time())
    findings = []
    metadata = {}
    try:
        if findings_json:
            findings = json.loads(findings_json)
        if metadata_json:
            metadata = json.loads(metadata_json)
    except Exception:
        pass

    if _pg_available():
        _pg_ensure_schema()
        result = _pg_exec("""
            INSERT INTO cf_scan_results
                (id, target, agent_type, username, started_at, finished_at, status, report_text, findings, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, 'complete', %s, %s::jsonb, %s::jsonb)
            ON CONFLICT (id) DO UPDATE SET
                finished_at = EXCLUDED.finished_at,
                status = 'complete',
                report_text = EXCLUDED.report_text,
                findings = EXCLUDED.findings,
                metadata = EXCLUDED.metadata
        """, (scan_id, target, agent_type, username, ts, ts,
              report_text, json.dumps(findings), json.dumps(metadata)))
        if result is not None:
            return json.dumps({'ok': True, 'scan_id': scan_id, 'backend': 'postgresql'})

    # JSON fallback
    scans = _fb_load('scans.json', [])
    scans = [s for s in scans if s.get('id') != scan_id]
    scans.insert(0, {
        'id': scan_id, 'target': target, 'agent_type': agent_type,
        'username': username, 'created_at': ts, 'status': 'complete',
        'report_text': report_text, 'findings': findings, 'metadata': metadata,
    })
    _fb_save('scans.json', scans[:500])
    return json.dumps({'ok': True, 'scan_id': scan_id, 'backend': 'json'})


@function_tool
def pg_get_scan_history(target: str = '', username: str = '',
                        limit: int = 10) -> str:
    """
    Retrieve scan history from persistent storage.
    Filter by target domain or username.

    Args:
        target:   Filter by target domain (partial match)
        username: Filter by username who ran the scan
        limit:    Maximum scans to return (default 10)

    Returns: List of past scans with metadata and finding counts.
    """
    limit = min(max(1, limit), 100)

    if _pg_available():
        conditions = []
        params: list = []
        if target:
            conditions.append("target ILIKE %s")
            params.append(f'%{target}%')
        if username:
            conditions.append("username = %s")
            params.append(username)

        where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''
        results = _pg_exec(
            f"SELECT id, target, agent_type, username, started_at, finished_at, status, "
            f"jsonb_array_length(findings) as finding_count "
            f"FROM cf_scan_results {where} ORDER BY finished_at DESC LIMIT %s",
            params + [limit],
            fetch=True,
        )
        if results is not None:
            return json.dumps({'backend': 'postgresql', 'scans': results, 'total': len(results)}, indent=2)

    # JSON fallback
    scans = _fb_load('scans.json', [])
    filtered = []
    for s in scans:
        if target and target.lower() not in s.get('target', '').lower():
            continue
        if username and s.get('username', '') != username:
            continue
        filtered.append({
            'id':            s.get('id'),
            'target':        s.get('target'),
            'agent_type':    s.get('agent_type'),
            'username':      s.get('username'),
            'created_at':    s.get('created_at'),
            'status':        s.get('status'),
            'finding_count': len(s.get('findings', [])),
        })
    return json.dumps({'backend': 'json', 'scans': filtered[:limit], 'total': len(filtered)}, indent=2)


@function_tool
def pg_save_finding(target: str, severity: str, title: str,
                    description: str, scan_id: str = '',
                    category: str = '', evidence: str = '',
                    remediation: str = '', cvss: float = 0.0,
                    cve_ids: str = '') -> str:
    """
    Save an individual security finding to persistent storage.
    Use to record confirmed vulnerabilities for tracking and trending.

    Args:
        target:      Target domain where finding was discovered
        severity:    Severity — critical|high|medium|low|info
        title:       Short finding title (e.g. "SQL Injection in /api/search")
        description: Full finding description
        scan_id:     Associated scan ID (optional)
        category:    OWASP/WSTG category (e.g. "injection", "auth", "config")
        evidence:    Proof of concept or evidence snippet
        remediation: Recommended fix
        cvss:        CVSS score (0.0–10.0)
        cve_ids:     Comma-separated CVE IDs (e.g. "CVE-2021-44228,CVE-2023-1234")
    """
    finding_id = str(uuid.uuid4())[:12]
    ts = int(time.time())
    cve_list = [c.strip() for c in cve_ids.split(',') if c.strip()]

    if _pg_available():
        _pg_ensure_schema()
        result = _pg_exec("""
            INSERT INTO cf_findings
                (id, scan_id, target, severity, category, title, description,
                 evidence, remediation, cvss, cve_ids, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (finding_id, scan_id, target, severity.lower(), category,
              title, description, evidence, remediation, cvss, cve_list, ts))
        if result is not None:
            return json.dumps({'ok': True, 'finding_id': finding_id, 'backend': 'postgresql'})

    # JSON fallback
    findings = _fb_load('findings.json', [])
    findings.insert(0, {
        'id': finding_id, 'scan_id': scan_id, 'target': target,
        'severity': severity.lower(), 'category': category,
        'title': title, 'description': description,
        'evidence': evidence, 'remediation': remediation,
        'cvss': cvss, 'cve_ids': cve_list, 'created_at': ts,
    })
    _fb_save('findings.json', findings[:2000])
    return json.dumps({'ok': True, 'finding_id': finding_id, 'backend': 'json'})


@function_tool
def pg_get_findings(target: str = '', severity: str = '',
                    category: str = '', limit: int = 20) -> str:
    """
    Retrieve security findings from persistent storage.
    Use to track vulnerability trends and generate executive reports.

    Args:
        target:   Filter by target domain (partial match)
        severity: Filter by severity (critical|high|medium|low|info)
        category: Filter by OWASP category
        limit:    Maximum findings to return (default 20)

    Returns: List of findings sorted by severity and recency.
    """
    limit = min(max(1, limit), 200)
    _sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

    if _pg_available():
        conditions = []
        params: list = []
        if target:
            conditions.append("target ILIKE %s")
            params.append(f'%{target}%')
        if severity:
            conditions.append("severity = %s")
            params.append(severity.lower())
        if category:
            conditions.append("category = %s")
            params.append(category)

        where = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''
        results = _pg_exec(
            f"SELECT id, scan_id, target, severity, category, title, description, "
            f"evidence, remediation, cvss, cve_ids, created_at "
            f"FROM cf_findings {where} ORDER BY cvss DESC, created_at DESC LIMIT %s",
            params + [limit],
            fetch=True,
        )
        if results is not None:
            return json.dumps({'backend': 'postgresql', 'findings': results, 'total': len(results)}, indent=2)

    # JSON fallback
    findings = _fb_load('findings.json', [])
    filtered = []
    for f in findings:
        if target and target.lower() not in f.get('target', '').lower():
            continue
        if severity and f.get('severity', '').lower() != severity.lower():
            continue
        if category and f.get('category', '').lower() != category.lower():
            continue
        filtered.append(f)

    filtered.sort(key=lambda x: (_sev_order.get(x.get('severity', 'info'), 5), -x.get('created_at', 0)))
    return json.dumps({'backend': 'json', 'findings': filtered[:limit], 'total': len(filtered)}, indent=2)


@function_tool
def pg_status() -> str:
    """
    Check PostgreSQL connection status and storage statistics.
    Returns backend type, connection status, and record counts.
    """
    if _pg_available():
        _pg_ensure_schema()
        scan_count = _pg_exec("SELECT COUNT(*) as n FROM cf_scan_results", fetch=True)
        find_count = _pg_exec("SELECT COUNT(*) as n FROM cf_findings", fetch=True)
        sc = scan_count[0]['n'] if scan_count else 0
        fc = find_count[0]['n'] if find_count else 0
        return json.dumps({
            'backend':   'postgresql',
            'connected': True,
            'host':      os.environ.get('PG_HOST', '?'),
            'database':  os.environ.get('PG_NAME', '?'),
            'scans':     sc,
            'findings':  fc,
        }, indent=2)

    # JSON fallback stats
    scans    = _fb_load('scans.json', [])
    findings = _fb_load('findings.json', [])
    pg_host  = os.environ.get('PG_HOST', '')
    return json.dumps({
        'backend':   'json',
        'connected': False,
        'pg_configured': bool(pg_host),
        'pg_note':   'Set PG_HOST, PG_NAME, PG_USER, PG_PASSWORD in .env to enable PostgreSQL',
        'scans':     len(scans),
        'findings':  len(findings),
    }, indent=2)
