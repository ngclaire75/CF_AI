"""Free third-party security API integrations — no API key required."""
from __future__ import annotations

import time
import urllib.request as _req
import urllib.parse as _up
import json as _json
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Module-level caches (domain -> (timestamp, result)) ──────────────────────
_obs_cache:  dict[str, tuple[float, dict]] = {}
_ssl_cache:  dict[str, tuple[float, dict]] = {}
_shd_cache:  dict[str, tuple[float, dict]] = {}

_CACHE_TTL = 3600  # 1 hour

_HEADERS = {
    'User-Agent': 'CF_AI-SecurityDashboard/1.0',
    'Accept': 'application/json',
}


def _cached(cache: dict, key: str) -> dict | None:
    entry = cache.get(key)
    if entry and (time.time() - entry[0]) < _CACHE_TTL:
        return entry[1]
    return None


def mozilla_observatory(domain: str) -> dict:
    """Call Mozilla Observatory for an HTTP security grade.

    POSTs to trigger a scan, then GETs the result.
    Returns {grade, score, tests: {test_name: {pass, score_modifier, result}}}.
    Returns {} on any failure.
    """
    domain = (domain or '').strip().lower()
    if not domain:
        return {}
    cached = _cached(_obs_cache, domain)
    if cached is not None:
        return cached
    try:
        encoded = _up.quote(domain, safe='')
        base_url = f'https://http-observatory.security.mozilla.org/api/v1/analyze?host={encoded}&rescan=false'

        # POST to initiate scan
        post_req = _req.Request(
            base_url,
            data=b'',
            method='POST',
            headers=_HEADERS,
        )
        with _req.urlopen(post_req, timeout=15) as resp:
            raw = _json.loads(resp.read().decode('utf-8', errors='replace'))

        # If not finished, do a single GET poll after a brief moment
        if raw.get('state', '') not in ('FINISHED', 'FAILED', 'ABORTED'):
            time.sleep(2)
            get_req = _req.Request(base_url, headers=_HEADERS)
            with _req.urlopen(get_req, timeout=15) as resp2:
                raw = _json.loads(resp2.read().decode('utf-8', errors='replace'))

        grade = raw.get('grade', '')
        score = raw.get('score')
        tests_raw = raw.get('tests', {}) or {}
        tests: dict = {}
        for name, info in tests_raw.items():
            tests[name] = {
                'pass':           bool(info.get('pass')),
                'score_modifier': info.get('score_modifier', 0),
                'result':         info.get('result', ''),
            }
        result = {'grade': grade, 'score': score, 'tests': tests}
        _obs_cache[domain] = (time.time(), result)
        return result
    except Exception:
        return {}


def ssl_labs_grade(domain: str) -> dict:
    """Fetch a cached SSL Labs grade for the domain (non-blocking, 24h cache ok).

    Returns {grade, hasWarnings, status}.
    Returns {grade: 'pending', status} if not ready, {} on failure.
    """
    domain = (domain or '').strip().lower()
    if not domain:
        return {}
    cached = _cached(_ssl_cache, domain)
    if cached is not None:
        return cached
    try:
        encoded = _up.quote(domain, safe='')
        url = (
            f'https://api.ssllabs.com/api/v3/analyze'
            f'?host={encoded}&fromCache=on&maxAge=24'
        )
        get_req = _req.Request(url, headers=_HEADERS)
        with _req.urlopen(get_req, timeout=20) as resp:
            raw = _json.loads(resp.read().decode('utf-8', errors='replace'))

        status = raw.get('status', '')
        if status != 'READY':
            result: dict = {'grade': 'pending', 'status': status}
            # Don't cache a pending result so next call may succeed
            return result

        endpoints = raw.get('endpoints') or []
        grade      = ''
        has_warnings = False
        for ep in endpoints:
            ep_grade = ep.get('grade', '')
            if ep_grade and (not grade or ep_grade > grade):
                grade = ep_grade
            if ep.get('hasWarnings'):
                has_warnings = True
        result = {'grade': grade, 'hasWarnings': has_warnings, 'status': status}
        _ssl_cache[domain] = (time.time(), result)
        return result
    except Exception:
        return {}


def securityheaders_check(domain: str) -> dict:
    """Fetch SecurityHeaders.com grade by reading the X-Grade response header.

    Returns {grade} (e.g. 'A+', 'B', 'F'), or {} on failure.
    """
    domain = (domain or '').strip().lower()
    if not domain:
        return {}
    cached = _cached(_shd_cache, domain)
    if cached is not None:
        return cached
    try:
        encoded = _up.quote(domain, safe='')
        url = f'https://securityheaders.com/?q=https://{encoded}&followRedirects=on'
        req = _req.Request(url, headers=dict(_HEADERS, Accept='text/html'))
        # We want the redirect response headers, so disable auto-redirect following
        import urllib.error as _uerr
        grade = ''
        try:
            with _req.urlopen(req, timeout=15) as resp:
                grade = resp.headers.get('X-Grade', '')
        except _uerr.HTTPError as e:
            grade = e.headers.get('X-Grade', '') if e.headers else ''

        result: dict = {'grade': grade} if grade else {}
        if result:
            _shd_cache[domain] = (time.time(), result)
        return result
    except Exception:
        return {}


def get_site_scores(domain: str) -> dict:
    """Fetch all three external security scores in parallel.

    Returns {observatory: {...}, ssl_labs: {...}, security_headers: {...}}.
    """
    domain = (domain or '').strip().lower()
    if not domain:
        return {'observatory': {}, 'ssl_labs': {}, 'security_headers': {}}

    tasks = {
        'observatory':      lambda: mozilla_observatory(domain),
        'ssl_labs':         lambda: ssl_labs_grade(domain),
        'security_headers': lambda: securityheaders_check(domain),
    }
    results: dict = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(fn): key for key, fn in tasks.items()}
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                results[key] = fut.result()
            except Exception:
                results[key] = {}

    return {
        'observatory':      results.get('observatory', {}),
        'ssl_labs':         results.get('ssl_labs', {}),
        'security_headers': results.get('security_headers', {}),
    }
