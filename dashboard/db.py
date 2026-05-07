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
        con.commit()


def save_scan(*, target, agent_type, model='', status='ok',
              latency_s=0.0, tool_count=0, output=''):
    with _connect() as con:
        con.execute(
            'INSERT INTO scans (target, agent_type, model, status, latency_s, tool_count, output) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (target, agent_type, model, status,
             round(float(latency_s), 2), int(tool_count), str(output)[:60000])
        )
        con.commit()


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
