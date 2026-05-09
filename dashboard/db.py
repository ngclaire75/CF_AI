"""CF_AI Dashboard — SQLite data store for agent scan results."""
import sqlite3
import os
from pathlib import Path

DB_PATH = os.environ.get(
    'CFAI_DB_PATH',
    str(Path(__file__).parent.parent / 'data' / 'cfai_scans.db')
)


def _connect():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with _connect() as con:
        con.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                target      TEXT    NOT NULL,
                agent_type  TEXT    NOT NULL,
                model       TEXT    DEFAULT '',
                status      TEXT    DEFAULT 'ok',
                latency_s   REAL    DEFAULT 0,
                tool_count  INTEGER DEFAULT 0,
                output      TEXT    DEFAULT ''
            )
        ''')
        con.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at      TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
                title           TEXT NOT NULL,
                description     TEXT DEFAULT '',
                severity        TEXT DEFAULT 'MEDIUM',
                status          TEXT DEFAULT 'open',
                target          TEXT DEFAULT '',
                scan_id         INTEGER DEFAULT NULL,
                mitre_tactic    TEXT DEFAULT '',
                mitre_technique TEXT DEFAULT '',
                rule_id         TEXT DEFAULT '',
                notes           TEXT DEFAULT ''
            )
        ''')
        con.execute('''
            CREATE TABLE IF NOT EXISTS maintenance_sites (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                domain                  TEXT NOT NULL,
                zone_id                 TEXT DEFAULT '',
                method                  TEXT DEFAULT 'cloudflare',
                cf_rule_id              TEXT DEFAULT '',
                previous_security_level TEXT DEFAULT 'medium',
                enabled_at              TEXT DEFAULT (datetime('now')),
                reason                  TEXT DEFAULT ''
            )
        ''')
        con.commit()


def save_scan(*, target, agent_type, model='', status='ok',
              latency_s=0.0, tool_count=0, output='') -> int:
    with _connect() as con:
        cur = con.execute(
            'INSERT INTO scans (target, agent_type, model, status, latency_s, tool_count, output) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (target, agent_type, model, status,
             round(float(latency_s), 2), int(tool_count), str(output)[:60000])
        )
        con.commit()
        return cur.lastrowid


def get_scans(limit=500):
    with _connect() as con:
        rows = con.execute(
            'SELECT * FROM scans ORDER BY created_at DESC LIMIT ?', (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id):
    with _connect() as con:
        row = con.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    return dict(row) if row else None


def get_stats():
    with _connect() as con:
        total   = con.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
        targets = con.execute('SELECT COUNT(DISTINCT target) FROM scans').fetchone()[0]
        avg_lat = con.execute('SELECT AVG(latency_s) FROM scans').fetchone()[0] or 0
        ok_cnt  = con.execute("SELECT COUNT(*) FROM scans WHERE status = 'ok'").fetchone()[0]
    return {
        'total_scans':    total,
        'unique_targets': targets,
        'avg_latency':    round(avg_lat, 1),
        'success_rate':   round(ok_cnt / total * 100, 1) if total else 0,
    }


def get_targets():
    """Return the most recent scan per unique target."""
    with _connect() as con:
        rows = con.execute('''
            SELECT s.* FROM scans s
            INNER JOIN (
                SELECT target, MAX(created_at) AS latest
                FROM scans GROUP BY target
            ) g ON s.target = g.target AND s.created_at = g.latest
            ORDER BY s.created_at DESC
        ''').fetchall()
    return [dict(r) for r in rows]


def get_scans_for_target(target: str) -> list:
    with _connect() as con:
        rows = con.execute(
            'SELECT * FROM scans WHERE target = ? ORDER BY created_at DESC LIMIT 50',
            (target,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_recent_scans(limit: int = 50) -> list:
    with _connect() as con:
        rows = con.execute(
            'SELECT * FROM scans ORDER BY created_at DESC LIMIT ?', (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ── Incident management ───────────────────────────────────────────────────────

def get_incidents(status: str = None, limit: int = 100) -> list:
    with _connect() as con:
        if status:
            rows = con.execute(
                'SELECT * FROM incidents WHERE status=? ORDER BY created_at DESC LIMIT ?',
                (status, limit)
            ).fetchall()
        else:
            rows = con.execute(
                'SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?', (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


def create_incident(*, title: str, description: str = '', severity: str = 'MEDIUM',
                    target: str = '', scan_id: int = None, mitre_tactic: str = '',
                    mitre_technique: str = '', rule_id: str = '') -> int:
    with _connect() as con:
        cur = con.execute(
            '''INSERT INTO incidents (title, description, severity, target, scan_id,
               mitre_tactic, mitre_technique, rule_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (title, description, severity, target, scan_id,
             mitre_tactic, mitre_technique, rule_id)
        )
        con.commit()
        return cur.lastrowid


def update_incident(incident_id: int, **kwargs) -> bool:
    allowed = {'status', 'notes', 'severity', 'title', 'description'}
    fields  = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return False
    fields['updated_at'] = 'datetime(\'now\')'
    set_clause = ', '.join(
        f'{k} = datetime(\'now\')' if k == 'updated_at' else f'{k} = ?'
        for k in fields
    )
    vals = [v for k, v in fields.items() if k != 'updated_at']
    vals.append(incident_id)
    with _connect() as con:
        con.execute(f'UPDATE incidents SET {set_clause} WHERE id = ?', vals)
        con.commit()
    return True


def delete_scan(scan_id: int) -> bool:
    with _connect() as con:
        cur = con.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        con.commit()
        return cur.rowcount > 0


def clear_scans() -> int:
    with _connect() as con:
        cur = con.execute('DELETE FROM scans')
        con.commit()
        return cur.rowcount


def delete_incident(incident_id: int) -> bool:
    with _connect() as con:
        cur = con.execute('DELETE FROM incidents WHERE id = ?', (incident_id,))
        con.commit()
        return cur.rowcount > 0


def get_incident_stats() -> dict:
    with _connect() as con:
        total    = con.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]
        open_c   = con.execute("SELECT COUNT(*) FROM incidents WHERE status='open'").fetchone()[0]
        inv_c    = con.execute("SELECT COUNT(*) FROM incidents WHERE status='investigating'").fetchone()[0]
        res_c    = con.execute("SELECT COUNT(*) FROM incidents WHERE status='resolved'").fetchone()[0]
    return {'total': total, 'open': open_c, 'investigating': inv_c, 'resolved': res_c}


# ── Maintenance mode ──────────────────────────────────────────────────────────

def get_maintenance(domain: str) -> dict | None:
    with _connect() as con:
        row = con.execute(
            'SELECT * FROM maintenance_sites WHERE domain = ?', (domain.lower(),)
        ).fetchone()
    return dict(row) if row else None


def enable_maintenance(domain: str, zone_id: str = '', method: str = 'cloudflare',
                       cf_rule_id: str = '', prev_level: str = 'medium', reason: str = '') -> int:
    with _connect() as con:
        con.execute('DELETE FROM maintenance_sites WHERE domain = ?', (domain.lower(),))
        cur = con.execute(
            '''INSERT INTO maintenance_sites
               (domain, zone_id, method, cf_rule_id, previous_security_level, reason)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (domain.lower(), zone_id, method, cf_rule_id, prev_level, reason)
        )
        con.commit()
        return cur.lastrowid


def disable_maintenance(domain: str) -> None:
    with _connect() as con:
        con.execute('DELETE FROM maintenance_sites WHERE domain = ?', (domain.lower(),))
        con.commit()


def get_all_maintenance() -> list:
    with _connect() as con:
        rows = con.execute('SELECT * FROM maintenance_sites').fetchall()
    return [dict(r) for r in rows]
