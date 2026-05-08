"""Security monitoring — MTTR/MTTD, fix detection, vulnerability comparison."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _parse_date(dt_str: str) -> datetime | None:
    """Parse an ISO-style date string into a datetime, returning None on failure."""
    if not dt_str:
        return None
    # Pairs of (expected-output-length, format-string)
    _FMTS = [
        (19, '%Y-%m-%dT%H:%M:%S'),
        (19, '%Y-%m-%d %H:%M:%S'),
        (16, '%Y-%m-%dT%H:%M'),
        (16, '%Y-%m-%d %H:%M'),
        (10, '%Y-%m-%d'),
    ]
    for slen, fmt in _FMTS:
        try:
            return datetime.strptime(dt_str[:slen], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _rem_id(rem: dict) -> str:
    """Return a stable identifier for a remediation item."""
    return str(rem.get('id') or rem.get('title', '') or '')[:120]


def _rec_key(rec: str) -> str:
    """Return a normalised key for a free-text recommendation."""
    return str(rec or '')[:60].lower().strip()


def compare_scans(scan_new: dict, scan_old: dict) -> dict:
    """Compare two enriched scans and return new/resolved/persistent findings.

    Compares both structured remediation IDs and free-text recs.

    Returns:
        {
          "new":        list of finding dicts  (in scan_new, not in scan_old)
          "resolved":   list of finding dicts  (in scan_old, not in scan_new)
          "persistent": list of finding dicts  (in both scans)
        }
    """
    def _build_finding(rem: dict) -> dict:
        return {
            'id':       _rem_id(rem),
            'title':    rem.get('title', ''),
            'severity': rem.get('severity', rem.get('risk', 'INFO')),
        }

    def _rec_finding(rec: str) -> dict:
        return {'id': _rec_key(rec), 'title': rec, 'severity': 'INFO'}

    # --- structured remediations ---
    new_ids_rem  = {_rem_id(r) for r in (scan_new.get('remediations') or []) if _rem_id(r)}
    old_ids_rem  = {_rem_id(r) for r in (scan_old.get('remediations') or []) if _rem_id(r)}
    by_id_new    = {_rem_id(r): r for r in (scan_new.get('remediations') or [])}
    by_id_old    = {_rem_id(r): r for r in (scan_old.get('remediations') or [])}

    # --- free-text recs ---
    new_recs     = {_rec_key(r): r for r in (scan_new.get('recs') or []) if r}
    old_recs     = {_rec_key(r): r for r in (scan_old.get('recs') or []) if r}

    added_rem    = new_ids_rem - old_ids_rem
    removed_rem  = old_ids_rem - new_ids_rem
    both_rem     = new_ids_rem & old_ids_rem

    added_rec    = set(new_recs) - set(old_recs)
    removed_rec  = set(old_recs) - set(new_recs)
    both_rec     = set(new_recs) & set(old_recs)

    new_findings        = [_build_finding(by_id_new[i]) for i in added_rem]
    new_findings       += [_rec_finding(new_recs[k]) for k in added_rec]
    resolved_findings   = [_build_finding(by_id_old[i]) for i in removed_rem]
    resolved_findings  += [_rec_finding(old_recs[k]) for k in removed_rec]
    persistent_findings = [_build_finding(by_id_new[i]) for i in both_rem]
    persistent_findings += [_rec_finding(new_recs[k]) for k in both_rec]

    return {
        'new':        new_findings,
        'resolved':   resolved_findings,
        'persistent': persistent_findings,
    }


def get_target_analytics(target: str, scans: list[dict]) -> dict:
    """Compute analytics for one target given its enriched scans (any order).

    Returns:
        {
          "trend":              list of {date, HIGH, MEDIUM, LOW, INFO} oldest first
          "mttr_days":          float | None
          "mttd_days":          float | None
          "new_since_last":     list of finding dicts
          "resolved_since_last":list of finding dicts
          "risk_trend":         "improving" | "degrading" | "stable"
        }
    """
    if not scans:
        return {
            'trend': [], 'mttr_days': None, 'mttd_days': None,
            'new_since_last': [], 'resolved_since_last': [], 'risk_trend': 'stable',
        }

    # Sort oldest-first for trend / MTTR
    def _scan_dt(s: dict) -> datetime:
        dt = _parse_date(s.get('display_date') or s.get('created_at') or '')
        return dt or datetime(2000, 1, 1, tzinfo=timezone.utc)

    sorted_scans = sorted(scans, key=_scan_dt)

    # ── Trend ────────────────────────────────────────────────────────────────
    trend: list[dict] = []
    _sev_map = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for s in sorted_scans:
        risk = (s.get('risk') or 'INFO').upper()
        bucket: dict[str, Any] = {'date': s.get('display_date') or s.get('created_at') or ''}
        bucket.update({k: 0 for k in _sev_map})
        bucket[risk] = bucket.get(risk, 0) + 1
        trend.append(bucket)

    # ── MTTR ─────────────────────────────────────────────────────────────────
    # Track when each finding ID first appeared and when it last disappeared.
    # "disappeared" = in scan N but not in scan N+1.
    first_seen: dict[str, datetime] = {}
    last_seen:  dict[str, datetime] = {}

    for s in sorted_scans:
        dt = _scan_dt(s)
        ids: set[str] = set()
        for rem in (s.get('remediations') or []):
            fid = _rem_id(rem)
            if fid:
                ids.add(fid)
                if fid not in first_seen:
                    first_seen[fid] = dt
                last_seen[fid] = dt
        for rec in (s.get('recs') or []):
            fid = _rec_key(rec)
            if fid:
                ids.add(fid)
                if fid not in first_seen:
                    first_seen[fid] = dt
                last_seen[fid] = dt

    # A finding is "resolved" if its last_seen < the most recent scan date.
    latest_dt = _scan_dt(sorted_scans[-1])
    resolved_durations: list[float] = []
    for fid, ls in last_seen.items():
        if ls < latest_dt:
            fs = first_seen.get(fid, ls)
            delta = (ls - fs).total_seconds() / 86400.0
            resolved_durations.append(max(delta, 0.0))

    mttr_days: float | None = None
    if resolved_durations:
        mttr_days = round(sum(resolved_durations) / len(resolved_durations), 1)

    # ── MTTD (scan cadence) ───────────────────────────────────────────────────
    mttd_days: float | None = None
    if len(sorted_scans) >= 2:
        dts = [_scan_dt(s) for s in sorted_scans]
        intervals = [(dts[i+1] - dts[i]).total_seconds() / 86400.0 for i in range(len(dts)-1)]
        valid = [x for x in intervals if x >= 0]
        if valid:
            mttd_days = round(sum(valid) / len(valid), 1)

    # ── New / resolved since last scan ───────────────────────────────────────
    new_since_last:      list[dict] = []
    resolved_since_last: list[dict] = []

    if len(sorted_scans) >= 2:
        # sorted_scans[-1] is latest, sorted_scans[-2] is previous
        compared = compare_scans(sorted_scans[-1], sorted_scans[-2])
        new_since_last      = compared['new']
        resolved_since_last = compared['resolved']

    # ── Risk trend ───────────────────────────────────────────────────────────
    risk_trend = 'stable'
    if len(trend) >= 2:
        _prio = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        def _score(entry: dict) -> int:
            return (entry.get('HIGH', 0) * 3 + entry.get('MEDIUM', 0) * 2
                    + entry.get('LOW', 0) * 1)
        first_half = trend[:len(trend)//2] if len(trend) > 2 else [trend[0]]
        second_half = trend[len(trend)//2:] if len(trend) > 2 else [trend[-1]]
        avg_first  = sum(_score(e) for e in first_half)  / max(len(first_half), 1)
        avg_second = sum(_score(e) for e in second_half) / max(len(second_half), 1)
        if avg_second < avg_first * 0.85:
            risk_trend = 'improving'
        elif avg_second > avg_first * 1.15:
            risk_trend = 'degrading'

    return {
        'trend':               trend,
        'mttr_days':           mttr_days,
        'mttd_days':           mttd_days,
        'new_since_last':      new_since_last,
        'resolved_since_last': resolved_since_last,
        'risk_trend':          risk_trend,
    }
