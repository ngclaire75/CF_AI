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
        con.execute('''CREATE TABLE IF NOT EXISTS security_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at   TEXT NOT NULL DEFAULT (datetime('now')),
            event_type   TEXT NOT NULL,
            category     TEXT DEFAULT '',
            severity     TEXT DEFAULT 'LOW',
            ip_address   TEXT DEFAULT '',
            country      TEXT DEFAULT '',
            country_code TEXT DEFAULT '',
            latitude     REAL DEFAULT 0,
            longitude    REAL DEFAULT 0,
            target       TEXT DEFAULT '',
            user_name    TEXT DEFAULT '',
            description  TEXT DEFAULT '',
            raw_data     TEXT DEFAULT '',
            remediated   INTEGER DEFAULT 0,
            remediation_id INTEGER DEFAULT NULL
        )''')
        con.execute('''CREATE TABLE IF NOT EXISTS remediation_actions (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at       TEXT NOT NULL DEFAULT (datetime('now')),
            trigger_event_id INTEGER DEFAULT NULL,
            rule_name        TEXT NOT NULL DEFAULT '',
            action_type      TEXT NOT NULL,
            target           TEXT DEFAULT '',
            parameters       TEXT DEFAULT '',
            status           TEXT DEFAULT 'pending',
            result           TEXT DEFAULT '',
            auto_triggered   INTEGER DEFAULT 1
        )''')
        con.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at   TEXT NOT NULL DEFAULT (datetime('now')),
            ip_address   TEXT NOT NULL,
            country      TEXT DEFAULT '',
            block_reason TEXT DEFAULT '',
            cf_rule_id   TEXT DEFAULT '',
            zone_id      TEXT DEFAULT '',
            expires_at   TEXT DEFAULT '',
            status       TEXT DEFAULT 'active'
        )''')
        con.execute('''CREATE TABLE IF NOT EXISTS plugins (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
            target      TEXT NOT NULL,
            name        TEXT NOT NULL,
            version     TEXT DEFAULT '',
            plugin_type TEXT DEFAULT 'Plugin',
            status      TEXT DEFAULT 'active',
            vulnerable  INTEGER DEFAULT 0,
            scan_id     INTEGER DEFAULT NULL
        )''')
        con.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_plugins_target_name ON plugins(target, name)')
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


# ── Security Events ───────────────────────────────────────────────────────────

def log_security_event(*, event_type: str, category: str = '', severity: str = 'LOW',
                       ip_address: str = '', country: str = '', country_code: str = '',
                       latitude: float = 0, longitude: float = 0, target: str = '',
                       user_name: str = '', description: str = '', raw_data: str = '') -> int:
    with _connect() as con:
        cur = con.execute(
            '''INSERT INTO security_events
               (event_type, category, severity, ip_address, country, country_code,
                latitude, longitude, target, user_name, description, raw_data)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
            (event_type, category, severity, ip_address, country, country_code,
             float(latitude), float(longitude), target, user_name, description, str(raw_data)[:4000])
        )
        con.commit()
        return cur.lastrowid


def get_security_events(limit: int = 200, category: str = '', severity: str = '',
                        days: int = 7) -> list:
    with _connect() as con:
        wheres = ["created_at >= datetime('now', ?)"]
        params: list = [f'-{days} days']
        if category:
            wheres.append('category = ?'); params.append(category)
        if severity:
            wheres.append('severity = ?'); params.append(severity)
        rows = con.execute(
            f'SELECT * FROM security_events WHERE {" AND ".join(wheres)} ORDER BY created_at DESC LIMIT ?',
            params + [limit]
        ).fetchall()
    return [dict(r) for r in rows]


def get_events_map(days: int = 7) -> list:
    """Return events that have valid geo coords for the world map."""
    with _connect() as con:
        rows = con.execute(
            '''SELECT id, created_at, event_type, category, severity,
                      ip_address, country, country_code, latitude, longitude,
                      target, description
               FROM security_events
               WHERE created_at >= datetime('now', ?)
                 AND latitude != 0 AND longitude != 0
               ORDER BY created_at DESC LIMIT 500''',
            (f'-{days} days',)
        ).fetchall()
    return [dict(r) for r in rows]


def count_events_by_ip(ip: str, event_types: list, window_minutes: int) -> int:
    placeholders = ','.join('?' * len(event_types))
    with _connect() as con:
        row = con.execute(
            f'''SELECT COUNT(*) FROM security_events
                WHERE ip_address = ?
                  AND event_type IN ({placeholders})
                  AND created_at >= datetime('now', ?)''',
            [ip] + event_types + [f'-{window_minutes} minutes']
        ).fetchone()
    return row[0] if row else 0


def get_event_stats(days: int = 7) -> dict:
    with _connect() as con:
        total  = con.execute("SELECT COUNT(*) FROM security_events WHERE created_at >= datetime('now', ?)", (f'-{days} days',)).fetchone()[0]
        crit   = con.execute("SELECT COUNT(*) FROM security_events WHERE severity='CRITICAL' AND created_at >= datetime('now', ?)", (f'-{days} days',)).fetchone()[0]
        high   = con.execute("SELECT COUNT(*) FROM security_events WHERE severity='HIGH' AND created_at >= datetime('now', ?)", (f'-{days} days',)).fetchone()[0]
        by_cat = con.execute("SELECT category, COUNT(*) FROM security_events WHERE created_at >= datetime('now', ?) GROUP BY category", (f'-{days} days',)).fetchall()
        by_country = con.execute("SELECT country, COUNT(*) FROM security_events WHERE created_at >= datetime('now', ?) AND country != '' GROUP BY country ORDER BY COUNT(*) DESC LIMIT 10", (f'-{days} days',)).fetchall()
    return {
        'total': total, 'critical': crit, 'high': high,
        'by_category': [dict(zip(['category','count'], r)) for r in by_cat],
        'top_countries': [dict(zip(['country','count'], r)) for r in by_country],
    }


# ── Remediation Actions ───────────────────────────────────────────────────────

def log_remediation(*, trigger_event_id: int = None, rule_name: str = '',
                    action_type: str, target: str = '', parameters: str = '',
                    status: str = 'pending', result: str = '',
                    auto_triggered: bool = True) -> int:
    with _connect() as con:
        cur = con.execute(
            '''INSERT INTO remediation_actions
               (trigger_event_id, rule_name, action_type, target, parameters,
                status, result, auto_triggered)
               VALUES (?,?,?,?,?,?,?,?)''',
            (trigger_event_id, rule_name, action_type, target,
             parameters, status, result, 1 if auto_triggered else 0)
        )
        con.commit()
        return cur.lastrowid


def update_remediation(action_id: int, status: str, result: str = '') -> None:
    with _connect() as con:
        con.execute('UPDATE remediation_actions SET status=?, result=? WHERE id=?',
                    (status, result, action_id))
        con.commit()


def get_remediation_log(limit: int = 100) -> list:
    with _connect() as con:
        rows = con.execute(
            'SELECT * FROM remediation_actions ORDER BY created_at DESC LIMIT ?', (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ── Blocked IPs ───────────────────────────────────────────────────────────────

def add_blocked_ip(ip: str, country: str = '', reason: str = '',
                   cf_rule_id: str = '', zone_id: str = '') -> int:
    with _connect() as con:
        con.execute('DELETE FROM blocked_ips WHERE ip_address = ?', (ip,))
        cur = con.execute(
            'INSERT INTO blocked_ips (ip_address, country, block_reason, cf_rule_id, zone_id) VALUES (?,?,?,?,?)',
            (ip, country, reason, cf_rule_id, zone_id)
        )
        con.commit()
        return cur.lastrowid


def get_blocked_ips(status: str = 'active') -> list:
    with _connect() as con:
        rows = con.execute(
            'SELECT * FROM blocked_ips WHERE status=? ORDER BY created_at DESC LIMIT 500', (status,)
        ).fetchall()
    return [dict(r) for r in rows]


def is_ip_blocked(ip: str) -> bool:
    with _connect() as con:
        row = con.execute(
            "SELECT id FROM blocked_ips WHERE ip_address=? AND status='active'", (ip,)
        ).fetchone()
    return row is not None


# ── Plugin Inventory ──────────────────────────────────────────────────────────

def upsert_plugin(*, target: str, name: str, version: str = '',
                  plugin_type: str = 'Plugin', status: str = 'active',
                  vulnerable: int = 0, scan_id: int = None) -> int:
    with _connect() as con:
        con.execute(
            '''INSERT INTO plugins (target, name, version, plugin_type, status, vulnerable, scan_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(target, name) DO UPDATE SET
                 version     = excluded.version,
                 plugin_type = excluded.plugin_type,
                 status      = excluded.status,
                 vulnerable  = excluded.vulnerable,
                 scan_id     = excluded.scan_id,
                 updated_at  = datetime('now')''',
            (target, name, version, plugin_type, status, vulnerable, scan_id)
        )
        con.commit()
        row = con.execute('SELECT id FROM plugins WHERE target=? AND name=?', (target, name)).fetchone()
    return row[0] if row else 0


def get_plugins(target: str = '', limit: int = 1000) -> list:
    with _connect() as con:
        if target:
            rows = con.execute(
                'SELECT * FROM plugins WHERE target=? ORDER BY updated_at DESC LIMIT ?',
                (target, limit)
            ).fetchall()
        else:
            rows = con.execute(
                'SELECT * FROM plugins ORDER BY updated_at DESC LIMIT ?', (limit,)
            ).fetchall()
    return [dict(r) for r in rows]
