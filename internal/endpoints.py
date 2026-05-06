"""CF_AI Dashboard API client — wraps all cfai_server.py REST endpoints."""
import json
import logging
from typing import Optional
import urllib.request
import urllib.error

from util import server_url

log = logging.getLogger('cfai.endpoints')

_BASE = None


def _base() -> str:
    global _BASE
    if _BASE is None:
        _BASE = server_url()
    return _BASE


def _post(path: str, data: dict, timeout: int = 30) -> dict:
    url     = _base() + path
    payload = json.dumps(data).encode()
    req     = urllib.request.Request(url, data=payload,
                                     headers={'Content-Type': 'application/json'},
                                     method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors='replace')
        try:
            return json.loads(body)
        except Exception:
            return {'error': f'HTTP {e.code}: {body[:200]}'}
    except Exception as exc:
        return {'error': str(exc)}


def _get(path: str, timeout: int = 15) -> dict:
    url = _base() + path
    req = urllib.request.Request(url, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {'error': f'HTTP {e.code}'}
    except Exception as exc:
        return {'error': str(exc)}


def _delete(path: str, timeout: int = 10) -> dict:
    url = _base() + path
    req = urllib.request.Request(url, method='DELETE')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        return {'error': str(exc)}


class DashboardClient:
    """Thin client for the CF_AI REST API."""

    # ── Command execution ──────────────────────────────────────────────────

    def execute(self, command: str, use_cache: bool = False) -> dict:
        return _post('/api/command', {'command': command, 'use_cache': use_cache},
                     timeout=120)

    def chat(self, message: str) -> dict:
        return _post('/api/chat', {'message': message}, timeout=60)

    # ── Sites ──────────────────────────────────────────────────────────────

    def sites(self) -> list:
        return _get('/api/sites').get('sites', [])

    def add_site(self, url: str, name: str = '', platform: str = 'auto',
                 scan_freq: str = 'weekly') -> dict:
        return _post('/api/sites', {
            'url': url, 'name': name or None,
            'platform': platform, 'scan_freq': scan_freq,
        })

    def remove_site(self, site_id: str) -> dict:
        return _delete(f'/api/sites/{site_id}')

    def start_scan(self, site_id: str) -> dict:
        return _post(f'/api/sites/{site_id}/scan', {})

    def scan_status(self, site_id: str) -> dict:
        return _get(f'/api/sites/{site_id}/scan/status')

    def site_report(self, site_id: str) -> dict:
        return _post(f'/api/sites/{site_id}/report', {})

    # ── Findings ──────────────────────────────────────────────────────────

    def findings(self, site_id: str = '') -> list:
        all_f = _get('/api/findings').get('findings', [])
        if site_id:
            all_f = [f for f in all_f if f.get('site_id') == site_id]
        return all_f

    def apply_fix(self, finding_id: str) -> dict:
        return _post('/api/autofix', {'finding_id': finding_id})

    # ── AI / Stats ─────────────────────────────────────────────────────────

    def ai_analyze(self, ctx: dict) -> str:
        return _post('/api/ai/analyze', ctx).get('analysis', '')

    def stats(self) -> dict:
        return _get('/api/stats')

    def jobs(self) -> list:
        return _get('/api/jobs').get('jobs', [])

    def metrics(self) -> dict:
        return _get('/api/metrics')

    # ── Audit record ───────────────────────────────────────────────────────

    def ping(self) -> bool:
        try:
            r = _get('/health', timeout=3)
            return 'error' not in r
        except Exception:
            return False


_client: Optional[DashboardClient] = None


def get_client() -> DashboardClient:
    global _client
    if _client is None:
        _client = DashboardClient()
    return _client
