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
                output      TEXT    DEFAULT '',
                username    TEXT    DEFAULT ''
            )
        ''')
        # Migrate existing DBs — add username column if missing
        try:
            con.execute('ALTER TABLE scans ADD COLUMN username TEXT DEFAULT ""')
            con.commit()
        except Exception:
            pass
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
            scan_id     INTEGER DEFAULT NULL,
            username    TEXT DEFAULT ''
        )''')
        con.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_plugins_target_name ON plugins(target, name)')
        # Migrate existing DBs — add username column to plugins if missing
        try:
            con.execute('ALTER TABLE plugins ADD COLUMN username TEXT DEFAULT ""')
            con.commit()
        except Exception:
            pass

        # ── System Logs (Splunk HEC + Windows Event Logs) ─────────────────────
        con.execute('''
            CREATE TABLE IF NOT EXISTS syslog (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL DEFAULT (datetime('now')),
                source_type TEXT DEFAULT 'generic',
                host        TEXT DEFAULT '',
                source      TEXT DEFAULT '',
                sourcetype  TEXT DEFAULT '',
                level       TEXT DEFAULT 'INFO',
                event_id    TEXT DEFAULT '',
                channel     TEXT DEFAULT '',
                message     TEXT DEFAULT '',
                raw         TEXT DEFAULT ''
            )
        ''')
        con.execute('CREATE INDEX IF NOT EXISTS idx_syslog_received ON syslog(received_at)')
        con.execute('CREATE INDEX IF NOT EXISTS idx_syslog_level ON syslog(level)')
        con.execute('CREATE INDEX IF NOT EXISTS idx_syslog_source_type ON syslog(source_type)')

        # ── Pentest Engagements ───────────────────────────────────────────────
        con.execute('''
            CREATE TABLE IF NOT EXISTS engagements (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                name        TEXT NOT NULL,
                client      TEXT DEFAULT '',
                scope_urls  TEXT DEFAULT '[]',
                scope_ips   TEXT DEFAULT '[]',
                auth_config TEXT DEFAULT '{}',
                urgency     TEXT DEFAULT 'normal',
                deadline    TEXT DEFAULT '',
                status      TEXT DEFAULT 'pending',
                notes       TEXT DEFAULT '',
                username    TEXT DEFAULT ''
            )
        ''')
        try:
            con.execute('ALTER TABLE scans ADD COLUMN engagement_id INTEGER DEFAULT NULL')
            con.commit()
        except Exception:
            pass

        # ── Subscriptions (Midtrans payment tracking) ─────────────────────────
        con.execute('''
            CREATE TABLE IF NOT EXISTS subscriptions (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at       TEXT NOT NULL DEFAULT (datetime('now')),
                username         TEXT NOT NULL,
                email            TEXT DEFAULT '',
                order_id         TEXT UNIQUE NOT NULL,
                transaction_id   TEXT DEFAULT '',
                plan_type        TEXT DEFAULT 'monthly',
                amount           INTEGER DEFAULT 0,
                currency         TEXT DEFAULT 'IDR',
                status           TEXT DEFAULT 'pending',
                payment_type     TEXT DEFAULT '',
                bank             TEXT DEFAULT '',
                va_number        TEXT DEFAULT '',
                subscribed_at    TEXT DEFAULT '',
                expires_at       TEXT DEFAULT '',
                cancelled_at     TEXT DEFAULT '',
                snap_token       TEXT DEFAULT '',
                raw_notification TEXT DEFAULT ''
            )
        ''')
        con.execute('CREATE INDEX IF NOT EXISTS idx_sub_username  ON subscriptions(username)')
        con.execute('CREATE INDEX IF NOT EXISTS idx_sub_status    ON subscriptions(status)')
        con.execute('CREATE INDEX IF NOT EXISTS idx_sub_order_id  ON subscriptions(order_id)')

        # ── GRC Risk Management ───────────────────────────────────────────────
        con.execute('''
            CREATE TABLE IF NOT EXISTS grc_risks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
                title       TEXT NOT NULL,
                description TEXT DEFAULT '',
                category    TEXT DEFAULT '',
                likelihood  INTEGER DEFAULT 3,
                impact      INTEGER DEFAULT 3,
                score       INTEGER DEFAULT 9,
                status      TEXT DEFAULT 'open',
                treatment   TEXT DEFAULT 'mitigate',
                owner       TEXT DEFAULT '',
                due_date    TEXT DEFAULT '',
                notes       TEXT DEFAULT '',
                username    TEXT DEFAULT ''
            )
        ''')
        con.execute('''
            CREATE TABLE IF NOT EXISTS grc_controls (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
                control_id  TEXT NOT NULL DEFAULT '',
                title       TEXT NOT NULL,
                description TEXT DEFAULT '',
                framework   TEXT DEFAULT 'ISO 27001',
                category    TEXT DEFAULT '',
                status      TEXT DEFAULT 'not_started',
                owner       TEXT DEFAULT '',
                due_date    TEXT DEFAULT '',
                evidence    TEXT DEFAULT '',
                notes       TEXT DEFAULT '',
                username    TEXT DEFAULT ''
            )
        ''')
        con.execute('''
            CREATE TABLE IF NOT EXISTS grc_tests (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at   TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
                name         TEXT NOT NULL,
                description  TEXT DEFAULT '',
                category     TEXT DEFAULT 'manual',
                control_ref  TEXT DEFAULT '',
                status       TEXT DEFAULT 'not_started',
                last_run     TEXT DEFAULT '',
                result_notes TEXT DEFAULT '',
                owner        TEXT DEFAULT '',
                username     TEXT DEFAULT ''
            )
        ''')
        con.execute('''
            CREATE TABLE IF NOT EXISTS grc_audits (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
                name        TEXT NOT NULL,
                description TEXT DEFAULT '',
                auditor     TEXT DEFAULT '',
                scope       TEXT DEFAULT '',
                status      TEXT DEFAULT 'planned',
                start_date  TEXT DEFAULT '',
                end_date    TEXT DEFAULT '',
                findings    TEXT DEFAULT '',
                notes       TEXT DEFAULT '',
                username    TEXT DEFAULT ''
            )
        ''')
        con.execute('''
            CREATE TABLE IF NOT EXISTS grc_evidence (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at   TEXT NOT NULL DEFAULT (datetime('now')),
                audit_id     INTEGER DEFAULT NULL,
                control_id   TEXT DEFAULT '',
                title        TEXT NOT NULL,
                description  TEXT DEFAULT '',
                file_name    TEXT DEFAULT '',
                collected_by TEXT DEFAULT '',
                username     TEXT DEFAULT ''
            )
        ''')
        con.commit()


# ── Subscription CRUD ─────────────────────────────────────────────────────────

def create_subscription(*, username: str, email: str, order_id: str,
                        plan_type: str, amount: int, snap_token: str = '') -> int:
    with _connect() as con:
        cur = con.execute(
            '''INSERT INTO subscriptions (username, email, order_id, plan_type, amount, snap_token)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (username, email, order_id, plan_type, amount, snap_token)
        )
        con.commit()
        return cur.lastrowid


def update_subscription_status(order_id: str, status: str, *,
                                transaction_id: str = '', payment_type: str = '',
                                bank: str = '', va_number: str = '',
                                subscribed_at: str = '', expires_at: str = '',
                                raw_notification: str = '') -> None:
    with _connect() as con:
        con.execute(
            '''UPDATE subscriptions SET
               status=?, transaction_id=?, payment_type=?, bank=?, va_number=?,
               subscribed_at = CASE WHEN ? != '' THEN ? ELSE subscribed_at END,
               expires_at    = CASE WHEN ? != '' THEN ? ELSE expires_at END,
               raw_notification = CASE WHEN ? != '' THEN ? ELSE raw_notification END
               WHERE order_id=?''',
            (status, transaction_id, payment_type, bank, va_number,
             subscribed_at, subscribed_at, expires_at, expires_at,
             raw_notification, raw_notification, order_id)
        )
        con.commit()


def cancel_subscription(order_id: str, cancelled_at: str) -> None:
    with _connect() as con:
        con.execute(
            "UPDATE subscriptions SET status='cancelled', cancelled_at=? WHERE order_id=?",
            (cancelled_at, order_id)
        )
        con.commit()


def get_subscription_by_order_id(order_id: str):
    with _connect() as con:
        row = con.execute('SELECT * FROM subscriptions WHERE order_id=?', (order_id,)).fetchone()
        return dict(row) if row else None


def get_user_active_subscription(username: str):
    with _connect() as con:
        row = con.execute(
            "SELECT * FROM subscriptions WHERE username=? AND status='active' "
            "ORDER BY subscribed_at DESC LIMIT 1",
            (username,)
        ).fetchone()
        return dict(row) if row else None


def get_user_subscriptions(username: str) -> list:
    with _connect() as con:
        rows = con.execute(
            'SELECT * FROM subscriptions WHERE username=? ORDER BY created_at DESC',
            (username,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_subscriptions(status: str = None, plan_type: str = None,
                          search: str = None, limit: int = 100, offset: int = 0) -> list:
    with _connect() as con:
        q = 'SELECT * FROM subscriptions WHERE 1=1'
        params: list = []
        if status:
            q += ' AND status=?'
            params.append(status)
        if plan_type:
            q += ' AND plan_type=?'
            params.append(plan_type)
        if search:
            q += ' AND (username LIKE ? OR email LIKE ? OR order_id LIKE ?)'
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
        q += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        return [dict(r) for r in con.execute(q, params).fetchall()]


def count_all_subscriptions(status: str = None, plan_type: str = None,
                             search: str = None) -> int:
    with _connect() as con:
        q = 'SELECT COUNT(*) FROM subscriptions WHERE 1=1'
        params: list = []
        if status:
            q += ' AND status=?'
            params.append(status)
        if plan_type:
            q += ' AND plan_type=?'
            params.append(plan_type)
        if search:
            q += ' AND (username LIKE ? OR email LIKE ? OR order_id LIKE ?)'
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
        return con.execute(q, params).fetchone()[0]


def get_subscription_stats() -> dict:
    with _connect() as con:
        def _count(where, params=()):
            return con.execute(f'SELECT COUNT(*) FROM subscriptions WHERE {where}', params).fetchone()[0]
        def _sum(where, params=()):
            return con.execute(f'SELECT COALESCE(SUM(amount),0) FROM subscriptions WHERE {where}', params).fetchone()[0]
        return {
            'active':               _count("status='active'"),
            'monthly':              _count("status='active' AND plan_type='monthly'"),
            'annual':               _count("status='active' AND plan_type='annual'"),
            'pending':              _count("status='pending'"),
            'cancelled':            _count("status='cancelled'"),
            'expired':              _count("status='expired'"),
            'failed':               _count("status='failed'"),
            'revenue_active':       _sum("status='active'"),
            'revenue_all_time':     _sum("status IN ('active','expired','cancelled')"),
        }


def expire_stale_subscriptions() -> list:
    """Mark active subscriptions past their expires_at as expired. Returns affected rows."""
    import datetime as _dt
    now = _dt.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    with _connect() as con:
        rows = con.execute(
            "SELECT * FROM subscriptions WHERE status='active' AND expires_at!='' AND expires_at<=?",
            (now,)
        ).fetchall()
        if rows:
            con.execute(
                "UPDATE subscriptions SET status='expired' WHERE status='active' AND expires_at!='' AND expires_at<=?",
                (now,)
            )
            con.commit()
        return [dict(r) for r in rows]


# ── Engagement CRUD ───────────────────────────────────────────────────────────

def create_engagement(*, name, client='', scope_urls=None, scope_ips=None,
                      auth_config=None, urgency='normal', deadline='',
                      notes='', username='') -> int:
    import json
    with _connect() as con:
        cur = con.execute(
            'INSERT INTO engagements (name,client,scope_urls,scope_ips,auth_config,urgency,deadline,notes,username) '
            'VALUES (?,?,?,?,?,?,?,?,?)',
            (name, client,
             json.dumps(scope_urls or []),
             json.dumps(scope_ips   or []),
             json.dumps(auth_config or {}),
             urgency, deadline, notes, username)
        )
        con.commit()
        return cur.lastrowid


def get_engagements(username=None):
    import json
    with _connect() as con:
        if username:
            rows = con.execute(
                'SELECT * FROM engagements WHERE username=? ORDER BY created_at DESC', (username,)
            ).fetchall()
        else:
            rows = con.execute('SELECT * FROM engagements ORDER BY created_at DESC').fetchall()
    out = []
    for r in rows:
        d = dict(r)
        for f in ('scope_urls', 'scope_ips', 'auth_config'):
            try: d[f] = json.loads(d[f])
            except Exception: d[f] = [] if f != 'auth_config' else {}
        out.append(d)
    return out


def get_engagement(eid) -> dict | None:
    import json
    with _connect() as con:
        row = con.execute('SELECT * FROM engagements WHERE id=?', (eid,)).fetchone()
    if not row:
        return None
    d = dict(row)
    for f in ('scope_urls', 'scope_ips', 'auth_config'):
        try: d[f] = json.loads(d[f])
        except Exception: d[f] = [] if f != 'auth_config' else {}
    return d


def update_engagement_status(eid, status):
    with _connect() as con:
        con.execute('UPDATE engagements SET status=? WHERE id=?', (status, eid))
        con.commit()


def delete_engagement(eid):
    with _connect() as con:
        con.execute('UPDATE scans SET engagement_id=NULL WHERE engagement_id=?', (eid,))
        con.execute('DELETE FROM engagements WHERE id=?', (eid,))
        con.commit()


def get_engagement_scans(eid):
    with _connect() as con:
        rows = con.execute(
            'SELECT * FROM scans WHERE engagement_id=? ORDER BY created_at DESC', (eid,)
        ).fetchall()
    return [dict(r) for r in rows]


def save_scan(*, target, agent_type, model='', status='ok',
              latency_s=0.0, tool_count=0, output='', username='') -> int:
    with _connect() as con:
        cur = con.execute(
            'INSERT INTO scans (target, agent_type, model, status, latency_s, tool_count, output, username) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (target, agent_type, model, status,
             round(float(latency_s), 2), int(tool_count), str(output)[:60000], username)
        )
        con.commit()
        return cur.lastrowid


def get_scans(limit=500, username=None):
    with _connect() as con:
        if username:
            rows = con.execute(
                'SELECT * FROM scans WHERE username=? ORDER BY created_at DESC LIMIT ?',
                (username, limit)
            ).fetchall()
        else:
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


def get_targets(username=None):
    """Return the most recent scan per unique target, scoped to user if given."""
    with _connect() as con:
        if username:
            rows = con.execute('''
                SELECT s.* FROM scans s
                INNER JOIN (
                    SELECT target, MAX(created_at) AS latest
                    FROM scans WHERE username=? GROUP BY target
                ) g ON s.target = g.target AND s.created_at = g.latest
                WHERE s.username=?
                ORDER BY s.created_at DESC
            ''', (username, username)).fetchall()
        else:
            rows = con.execute('''
                SELECT s.* FROM scans s
                INNER JOIN (
                    SELECT target, MAX(created_at) AS latest
                    FROM scans GROUP BY target
                ) g ON s.target = g.target AND s.created_at = g.latest
                ORDER BY s.created_at DESC
            ''').fetchall()
    return [dict(r) for r in rows]


def get_scans_for_target(target: str, username=None) -> list:
    with _connect() as con:
        if username:
            rows = con.execute(
                'SELECT * FROM scans WHERE target=? AND username=? ORDER BY created_at DESC LIMIT 50',
                (target, username)
            ).fetchall()
        else:
            rows = con.execute(
                'SELECT * FROM scans WHERE target=? ORDER BY created_at DESC LIMIT 50',
                (target,)
            ).fetchall()
    return [dict(r) for r in rows]


def get_recent_scans(limit: int = 50, username=None) -> list:
    with _connect() as con:
        if username:
            rows = con.execute(
                'SELECT * FROM scans WHERE username=? ORDER BY created_at DESC LIMIT ?',
                (username, limit)
            ).fetchall()
        else:
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
                  vulnerable: int = 0, scan_id: int = None, username: str = '') -> int:
    with _connect() as con:
        con.execute(
            '''INSERT INTO plugins (target, name, version, plugin_type, status, vulnerable, scan_id, username)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(target, name) DO UPDATE SET
                 version     = excluded.version,
                 plugin_type = excluded.plugin_type,
                 status      = excluded.status,
                 vulnerable  = excluded.vulnerable,
                 scan_id     = excluded.scan_id,
                 username    = excluded.username,
                 updated_at  = datetime('now')''',
            (target, name, version, plugin_type, status, vulnerable, scan_id, username)
        )
        con.commit()
        row = con.execute('SELECT id FROM plugins WHERE target=? AND name=?', (target, name)).fetchone()
    return row[0] if row else 0


# ── Pentest Findings & Checklist ──────────────────────────────────────────────

def _ensure_pt_tables():
    with _connect() as con:
        con.execute('''
            CREATE TABLE IF NOT EXISTS pt_findings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at    TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
                engagement_id INTEGER NOT NULL,
                phase         TEXT DEFAULT '',
                severity      TEXT DEFAULT 'informational',
                title         TEXT NOT NULL,
                asset         TEXT DEFAULT '',
                description   TEXT DEFAULT '',
                steps         TEXT DEFAULT '',
                evidence      TEXT DEFAULT '',
                cvss_score    REAL DEFAULT 0,
                cve           TEXT DEFAULT '',
                cwe           TEXT DEFAULT '',
                remediation   TEXT DEFAULT '',
                status        TEXT DEFAULT 'open'
            )
        ''')
        con.execute('''
            CREATE TABLE IF NOT EXISTS pt_checklist (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                section       TEXT NOT NULL,
                item          TEXT NOT NULL,
                checked       INTEGER DEFAULT 0,
                UNIQUE(engagement_id, section, item)
            )
        ''')
        try:
            con.execute('ALTER TABLE engagements ADD COLUMN scope_doc TEXT DEFAULT ""')
            con.commit()
        except Exception:
            pass
        try:
            con.execute('ALTER TABLE engagements ADD COLUMN roe_doc TEXT DEFAULT ""')
            con.commit()
        except Exception:
            pass
        con.commit()


def get_pt_findings(engagement_id: int) -> list:
    _ensure_pt_tables()
    with _connect() as con:
        rows = con.execute(
            'SELECT * FROM pt_findings WHERE engagement_id=? ORDER BY severity DESC, created_at DESC',
            (engagement_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def add_pt_finding(*, engagement_id: int, phase: str = '', severity: str = 'informational',
                   title: str, asset: str = '', description: str = '', steps: str = '',
                   evidence: str = '', cvss_score: float = 0, cve: str = '', cwe: str = '',
                   remediation: str = '', status: str = 'open') -> int:
    _ensure_pt_tables()
    with _connect() as con:
        cur = con.execute(
            '''INSERT INTO pt_findings
               (engagement_id, phase, severity, title, asset, description, steps,
                evidence, cvss_score, cve, cwe, remediation, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (engagement_id, phase, severity, title, asset, description, steps,
             evidence, float(cvss_score), cve, cwe, remediation, status)
        )
        con.commit()
        return cur.lastrowid


def update_pt_finding(finding_id: int, **kwargs) -> bool:
    allowed = {'phase', 'severity', 'title', 'asset', 'description', 'steps',
               'evidence', 'cvss_score', 'cve', 'cwe', 'remediation', 'status'}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return False
    set_clause = ', '.join(f'{k} = ?' for k in fields)
    set_clause += ', updated_at = datetime(\'now\')'
    vals = list(fields.values()) + [finding_id]
    with _connect() as con:
        con.execute(f'UPDATE pt_findings SET {set_clause} WHERE id = ?', vals)
        con.commit()
    return True


def delete_pt_finding(finding_id: int) -> bool:
    with _connect() as con:
        cur = con.execute('DELETE FROM pt_findings WHERE id = ?', (finding_id,))
        con.commit()
        return cur.rowcount > 0


def get_pt_checklist(engagement_id: int) -> list:
    _ensure_pt_tables()
    with _connect() as con:
        rows = con.execute(
            'SELECT * FROM pt_checklist WHERE engagement_id=? ORDER BY section, item',
            (engagement_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def set_pt_checklist_item(engagement_id: int, section: str, item: str, checked: bool) -> None:
    _ensure_pt_tables()
    with _connect() as con:
        con.execute(
            '''INSERT INTO pt_checklist (engagement_id, section, item, checked)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(engagement_id, section, item) DO UPDATE SET checked = excluded.checked''',
            (engagement_id, section, item, 1 if checked else 0)
        )
        con.commit()


def get_engagement_scope(eid: int) -> dict:
    _ensure_pt_tables()
    with _connect() as con:
        row = con.execute(
            'SELECT scope_doc, roe_doc FROM engagements WHERE id=?', (eid,)
        ).fetchone()
    if not row:
        return {'scope_doc': '', 'roe_doc': ''}
    return {'scope_doc': row['scope_doc'] or '', 'roe_doc': row['roe_doc'] or ''}


def save_engagement_scope(eid: int, scope_doc: str = None, roe_doc: str = None) -> None:
    _ensure_pt_tables()
    with _connect() as con:
        if scope_doc is not None and roe_doc is not None:
            con.execute('UPDATE engagements SET scope_doc=?, roe_doc=? WHERE id=?',
                        (scope_doc, roe_doc, eid))
        elif scope_doc is not None:
            con.execute('UPDATE engagements SET scope_doc=? WHERE id=?', (scope_doc, eid))
        elif roe_doc is not None:
            con.execute('UPDATE engagements SET roe_doc=? WHERE id=?', (roe_doc, eid))
        con.commit()


# ── System Log functions ──────────────────────────────────────────────────────

def log_syslog(*, source_type: str = 'generic', host: str = '', source: str = '',
               sourcetype: str = '', level: str = 'INFO', event_id: str = '',
               channel: str = '', message: str = '', raw: str = '') -> int:
    with _connect() as con:
        cur = con.execute(
            '''INSERT INTO syslog (source_type, host, source, sourcetype, level,
               event_id, channel, message, raw)
               VALUES (?,?,?,?,?,?,?,?,?)''',
            (source_type, host, source, sourcetype, level.upper(),
             event_id, channel, message, raw)
        )
        con.commit()
        return cur.lastrowid


def get_syslog(limit: int = 500, source_type: str = '', level: str = '',
               channel: str = '', search: str = '', hours: int = 24) -> list:
    clauses, params = ['received_at >= datetime("now", ? || " hours")'], [f'-{hours}']
    if source_type:
        clauses.append('source_type = ?'); params.append(source_type)
    if level:
        clauses.append('level = ?'); params.append(level.upper())
    if channel:
        clauses.append('channel = ?'); params.append(channel)
    if search:
        clauses.append('(message LIKE ? OR host LIKE ? OR source LIKE ?)')
        s = f'%{search}%'; params += [s, s, s]
    where = ' AND '.join(clauses)
    with _connect() as con:
        rows = con.execute(
            f'SELECT * FROM syslog WHERE {where} ORDER BY received_at DESC LIMIT ?',
            params + [limit]
        ).fetchall()
    return [dict(r) for r in rows]


def get_syslog_stats(hours: int = 24) -> dict:
    with _connect() as con:
        total = con.execute(
            'SELECT COUNT(*) FROM syslog WHERE received_at >= datetime("now", ? || " hours")',
            (f'-{hours}',)
        ).fetchone()[0]
        by_level = con.execute(
            '''SELECT level, COUNT(*) as cnt FROM syslog
               WHERE received_at >= datetime("now", ? || " hours")
               GROUP BY level''',
            (f'-{hours}',)
        ).fetchall()
        by_source = con.execute(
            '''SELECT source_type, COUNT(*) as cnt FROM syslog
               WHERE received_at >= datetime("now", ? || " hours")
               GROUP BY source_type ORDER BY cnt DESC LIMIT 10''',
            (f'-{hours}',)
        ).fetchall()
        by_host = con.execute(
            '''SELECT host, COUNT(*) as cnt FROM syslog
               WHERE received_at >= datetime("now", ? || " hours") AND host != ""
               GROUP BY host ORDER BY cnt DESC LIMIT 10''',
            (f'-{hours}',)
        ).fetchall()
    return {
        'total': total,
        'by_level': {r['level']: r['cnt'] for r in by_level},
        'by_source': [dict(r) for r in by_source],
        'by_host': [dict(r) for r in by_host],
    }


def clear_syslog() -> int:
    with _connect() as con:
        cur = con.execute('DELETE FROM syslog')
        con.commit()
        return cur.rowcount


def get_plugins(target: str = '', limit: int = 1000, username=None) -> list:
    with _connect() as con:
        if target and username:
            rows = con.execute(
                'SELECT * FROM plugins WHERE target=? AND username=? ORDER BY updated_at DESC LIMIT ?',
                (target, username, limit)
            ).fetchall()
        elif target:
            rows = con.execute(
                'SELECT * FROM plugins WHERE target=? ORDER BY updated_at DESC LIMIT ?',
                (target, limit)
            ).fetchall()
        elif username:
            rows = con.execute(
                'SELECT * FROM plugins WHERE username=? ORDER BY updated_at DESC LIMIT ?',
                (username, limit)
            ).fetchall()
        else:
            rows = con.execute(
                'SELECT * FROM plugins ORDER BY updated_at DESC LIMIT ?', (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


# ── GRC CRUD ──────────────────────────────────────────────────────────────────

def grc_list_risks(q='', status='', treatment='') -> list:
    with _connect() as con:
        sql = 'SELECT * FROM grc_risks WHERE 1=1'
        params: list = []
        if q:
            sql += ' AND (title LIKE ? OR category LIKE ? OR owner LIKE ?)'
            params += [f'%{q}%', f'%{q}%', f'%{q}%']
        if status:
            sql += ' AND status=?'; params.append(status)
        if treatment:
            sql += ' AND treatment=?'; params.append(treatment)
        sql += ' ORDER BY score DESC, created_at DESC'
        return [dict(r) for r in con.execute(sql, params).fetchall()]


def grc_create_risk(data: dict) -> int:
    cols = ['title','description','category','likelihood','impact','score',
            'status','treatment','owner','due_date','notes','username']
    with _connect() as con:
        cur = con.execute(
            f'INSERT INTO grc_risks ({",".join(cols)}) VALUES ({",".join("?"*len(cols))})',
            [data.get(c, '') for c in cols]
        )
        con.commit()
        return cur.lastrowid


def grc_update_risk(rid: int, data: dict) -> bool:
    cols = ['title','description','category','likelihood','impact','score',
            'status','treatment','owner','due_date','notes']
    with _connect() as con:
        sets = ', '.join(f'{c}=?' for c in cols) + ", updated_at=datetime('now')"
        con.execute(f'UPDATE grc_risks SET {sets} WHERE id=?',
                    [data.get(c, '') for c in cols] + [rid])
        con.commit()
    return True


def grc_delete_risk(rid: int) -> bool:
    with _connect() as con:
        con.execute('DELETE FROM grc_risks WHERE id=?', (rid,))
        con.commit()
    return True


def grc_list_controls(q='', framework='', status='') -> list:
    with _connect() as con:
        sql = 'SELECT * FROM grc_controls WHERE 1=1'
        params: list = []
        if q:
            sql += ' AND (control_id LIKE ? OR title LIKE ? OR category LIKE ? OR owner LIKE ?)'
            params += [f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%']
        if framework:
            sql += ' AND framework=?'; params.append(framework)
        if status:
            sql += ' AND status=?'; params.append(status)
        sql += ' ORDER BY framework, control_id'
        return [dict(r) for r in con.execute(sql, params).fetchall()]


def grc_create_control(data: dict) -> int:
    cols = ['control_id','title','description','framework','category',
            'status','owner','due_date','evidence','notes','username']
    with _connect() as con:
        cur = con.execute(
            f'INSERT INTO grc_controls ({",".join(cols)}) VALUES ({",".join("?"*len(cols))})',
            [data.get(c, '') for c in cols]
        )
        con.commit()
        return cur.lastrowid


def grc_update_control(cid: int, data: dict) -> bool:
    cols = ['control_id','title','description','framework','category',
            'status','owner','due_date','evidence','notes']
    with _connect() as con:
        sets = ', '.join(f'{c}=?' for c in cols) + ", updated_at=datetime('now')"
        con.execute(f'UPDATE grc_controls SET {sets} WHERE id=?',
                    [data.get(c, '') for c in cols] + [cid])
        con.commit()
    return True


def grc_delete_control(cid: int) -> bool:
    with _connect() as con:
        con.execute('DELETE FROM grc_controls WHERE id=?', (cid,))
        con.commit()
    return True


def grc_list_tests(q='', category='', status='') -> list:
    with _connect() as con:
        sql = 'SELECT * FROM grc_tests WHERE 1=1'
        params: list = []
        if q:
            sql += ' AND (name LIKE ? OR control_ref LIKE ? OR owner LIKE ?)'
            params += [f'%{q}%', f'%{q}%', f'%{q}%']
        if category:
            sql += ' AND category=?'; params.append(category)
        if status:
            sql += ' AND status=?'; params.append(status)
        sql += ' ORDER BY created_at DESC'
        return [dict(r) for r in con.execute(sql, params).fetchall()]


def grc_create_test(data: dict) -> int:
    cols = ['name','description','category','control_ref','status',
            'last_run','result_notes','owner','username']
    with _connect() as con:
        cur = con.execute(
            f'INSERT INTO grc_tests ({",".join(cols)}) VALUES ({",".join("?"*len(cols))})',
            [data.get(c, '') for c in cols]
        )
        con.commit()
        return cur.lastrowid


def grc_update_test(tid: int, data: dict) -> bool:
    cols = ['name','description','category','control_ref','status',
            'last_run','result_notes','owner']
    with _connect() as con:
        sets = ', '.join(f'{c}=?' for c in cols) + ", updated_at=datetime('now')"
        con.execute(f'UPDATE grc_tests SET {sets} WHERE id=?',
                    [data.get(c, '') for c in cols] + [tid])
        con.commit()
    return True


def grc_delete_test(tid: int) -> bool:
    with _connect() as con:
        con.execute('DELETE FROM grc_tests WHERE id=?', (tid,))
        con.commit()
    return True


def grc_list_audits() -> list:
    with _connect() as con:
        return [dict(r) for r in
                con.execute('SELECT * FROM grc_audits ORDER BY created_at DESC').fetchall()]


def grc_create_audit(data: dict) -> int:
    cols = ['name','description','auditor','scope','status',
            'start_date','end_date','findings','notes','username']
    with _connect() as con:
        cur = con.execute(
            f'INSERT INTO grc_audits ({",".join(cols)}) VALUES ({",".join("?"*len(cols))})',
            [data.get(c, '') for c in cols]
        )
        con.commit()
        return cur.lastrowid


def grc_update_audit(aid: int, data: dict) -> bool:
    cols = ['name','description','auditor','scope','status',
            'start_date','end_date','findings','notes']
    with _connect() as con:
        sets = ', '.join(f'{c}=?' for c in cols) + ", updated_at=datetime('now')"
        con.execute(f'UPDATE grc_audits SET {sets} WHERE id=?',
                    [data.get(c, '') for c in cols] + [aid])
        con.commit()
    return True


def grc_delete_audit(aid: int) -> bool:
    with _connect() as con:
        con.execute('DELETE FROM grc_audits WHERE id=?', (aid,))
        con.commit()
    return True


def grc_list_evidence() -> list:
    with _connect() as con:
        rows = con.execute('''
            SELECT e.*, a.name as audit_name
            FROM grc_evidence e
            LEFT JOIN grc_audits a ON a.id = e.audit_id
            ORDER BY e.created_at DESC
        ''').fetchall()
        return [dict(r) for r in rows]


def grc_create_evidence(data: dict) -> int:
    cols = ['audit_id','control_id','title','description','file_name','collected_by','username']
    with _connect() as con:
        cur = con.execute(
            f'INSERT INTO grc_evidence ({",".join(cols)}) VALUES ({",".join("?"*len(cols))})',
            [data.get(c) or None if c == 'audit_id' else data.get(c, '') for c in cols]
        )
        con.commit()
        return cur.lastrowid


def grc_delete_evidence(eid: int) -> bool:
    with _connect() as con:
        con.execute('DELETE FROM grc_evidence WHERE id=?', (eid,))
        con.commit()
    return True


def grc_stats() -> dict:
    with _connect() as con:
        def cnt(sql, *p):
            return con.execute(sql, p).fetchone()[0]
        return {
            'controls_total':       cnt('SELECT COUNT(*) FROM grc_controls'),
            'controls_implemented': cnt("SELECT COUNT(*) FROM grc_controls WHERE status='implemented'"),
            'controls_in_progress': cnt("SELECT COUNT(*) FROM grc_controls WHERE status='in_progress'"),
            'controls_not_started': cnt("SELECT COUNT(*) FROM grc_controls WHERE status='not_started'"),
            'risks_total':          cnt('SELECT COUNT(*) FROM grc_risks'),
            'risks_high':           cnt('SELECT COUNT(*) FROM grc_risks WHERE score>=15'),
            'risks_medium':         cnt('SELECT COUNT(*) FROM grc_risks WHERE score>=8 AND score<15'),
            'risks_low':            cnt('SELECT COUNT(*) FROM grc_risks WHERE score<8'),
            'tests_total':          cnt('SELECT COUNT(*) FROM grc_tests'),
            'tests_pass':           cnt("SELECT COUNT(*) FROM grc_tests WHERE status='pass'"),
            'tests_fail':           cnt("SELECT COUNT(*) FROM grc_tests WHERE status='fail'"),
            'tests_not_started':    cnt("SELECT COUNT(*) FROM grc_tests WHERE status='not_started'"),
            'audits_total':         cnt('SELECT COUNT(*) FROM grc_audits'),
            'audits_complete':      cnt("SELECT COUNT(*) FROM grc_audits WHERE status='complete'"),
            'audits_in_progress':   cnt("SELECT COUNT(*) FROM grc_audits WHERE status='in_progress'"),
            'audits_planned':       cnt("SELECT COUNT(*) FROM grc_audits WHERE status='planned'"),
        }
