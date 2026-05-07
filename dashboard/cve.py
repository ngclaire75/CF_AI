"""CF_AI — Real CVE lookup via the NVD API v2 (nvd.nist.gov).

Extracts technology fingerprints and explicit CVE IDs from agent scan
output, then queries the National Vulnerability Database for real,
confirmed CVE records.  No mock data — every result comes from NVD.

Rate limit (no API key): 5 requests per 30-second rolling window.
We stay well within that by capping total queries per scan at 5.
"""
from __future__ import annotations
import re
import json
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional

# ── Technology version extraction patterns ────────────────────────────────────

_TECH_PATTERNS: list[tuple[str, str]] = [
    (r'\bApache[/ ]([\d]+\.[\d]+(?:\.[\d]+)?)\b',         'Apache HTTP Server'),
    (r'\bnginx[/ ]([\d]+\.[\d]+(?:\.[\d]+)?)\b',           'nginx'),
    (r'\bPHP[/ ]([\d]+\.[\d]+(?:\.[\d]+)?)\b',             'PHP'),
    (r'\bWordPress[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',      'WordPress'),
    (r'\bDrupal[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',         'Drupal'),
    (r'\bJoomla[! ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',         'Joomla'),
    (r'\bOpenSSL[/ ]([\d]+\.[\d]+(?:[a-z]|\.[a-z0-9]+)?)\b', 'OpenSSL'),
    (r'\bjQuery[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',         'jQuery'),
    (r'\bMySQL[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',          'MySQL'),
    (r'\bPostgreSQL[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',     'PostgreSQL'),
    (r'\bTomcat[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',         'Apache Tomcat'),
    (r'\bIIS[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',            'Microsoft IIS'),
    (r'\bOpenSSH[_ /]?([\d]+\.[\d]+(?:p[\d]+)?)\b',        'OpenSSH'),
    (r'\bproftpd[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',        'ProFTPd'),
    (r'\bvsftpd[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',         'vsftpd'),
    (r'\bLaravel[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',        'Laravel'),
    (r'\bSymfony[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',        'Symfony'),
    (r'\bNode\.js[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',       'Node.js'),
    (r'\bExpress[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',        'Express.js'),
    (r'\bRedis[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',          'Redis'),
    (r'\bMongoDB[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',        'MongoDB'),
    (r'\bElasticSearch[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',  'Elasticsearch'),
    (r'\bDjango[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',         'Django'),
    (r'\bFlask[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',          'Flask'),
    (r'\bSpring[/ ]?([\d]+\.[\d]+(?:\.[\d]+)?)\b',         'Spring Framework'),
]

_CVE_RE  = re.compile(r'\b(CVE-\d{4}-\d{4,7})\b', re.I)
NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
_DELAY   = 6.5   # seconds between NVD requests — keeps us under 5-req/30s limit
_TIMEOUT = 18    # seconds per HTTP request


# ── NVD fetch helpers ─────────────────────────────────────────────────────────

def _nvd_get(url: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={'User-Agent': 'CF_AI-SecurityDashboard/1.0 (educational security research)'},
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RuntimeError('NVD rate-limit reached — try again in 30 seconds')
        raise RuntimeError(f'NVD returned HTTP {e.code}')
    except Exception as e:
        raise RuntimeError(f'NVD request failed: {e}')


def _parse_item(item: dict) -> Optional[dict]:
    cve    = item.get('cve', {})
    cve_id = cve.get('id', '')
    if not cve_id:
        return None

    desc = next(
        (d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'),
        'No description available.',
    )

    metrics = cve.get('metrics', {})
    score, severity, vector = None, 'UNKNOWN', ''
    for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        if metrics.get(key):
            data     = metrics[key][0].get('cvssData', {})
            score    = data.get('baseScore')
            severity = (data.get('baseSeverity') or 'UNKNOWN').upper()
            vector   = data.get('vectorString', '')
            break

    refs      = [r['url'] for r in cve.get('references', [])[:3]]
    published = (cve.get('published') or '')[:10]

    return {
        'id':        cve_id,
        'desc':      desc[:700],
        'score':     score,
        'severity':  severity,
        'vector':    vector,
        'published': published,
        'refs':      refs,
        'source':    '',
        'tech_matched': '',
    }


# ── Public lookup functions ───────────────────────────────────────────────────

def _lookup_by_id(cve_id: str) -> Optional[dict]:
    try:
        url  = f'{NVD_BASE}?cveId={urllib.parse.quote(cve_id)}'
        data = _nvd_get(url)
        vs   = data.get('vulnerabilities', [])
        return _parse_item(vs[0]) if vs else None
    except Exception:
        return None


def _lookup_by_keyword(keyword: str, max_results: int = 3) -> list[dict]:
    try:
        url  = (f'{NVD_BASE}?keywordSearch={urllib.parse.quote(keyword)}'
                f'&resultsPerPage={max_results}')
        data = _nvd_get(url)
        out  = []
        for v in data.get('vulnerabilities', []):
            p = _parse_item(v)
            if p:
                out.append(p)
        out.sort(key=lambda x: (x['score'] or 0), reverse=True)
        return out[:max_results]
    except Exception:
        return []


# ── Extraction helpers ────────────────────────────────────────────────────────

def extract_cve_ids(text: str) -> list[str]:
    return list(dict.fromkeys(m.upper() for m in _CVE_RE.findall(text)))


def extract_tech(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen:  set[tuple[str, str]]  = set()
    for pat, product in _TECH_PATTERNS:
        for m in re.finditer(pat, text, re.I):
            key = (product.lower(), m.group(1))
            if key not in seen:
                seen.add(key)
                found.append((product, m.group(1)))
    return found


# ── Main entry point ──────────────────────────────────────────────────────────

def cve_lookup_for_scan(output: str, target: str) -> dict:
    """Analyse scan output and return real CVEs from NVD.

    Returns:
        {
          'tech': [{'product': str, 'version': str}, ...],
          'cves': [cve_dict, ...],
          'error': str | None,
        }
    """
    results:  list[dict] = []
    seen_ids: set[str]   = set()
    requests_made = 0
    MAX_REQUESTS  = 5   # hard cap to stay within NVD rate limit

    try:
        # Step 1 — look up explicit CVE IDs already mentioned in the scan output
        for cve_id in extract_cve_ids(output)[:3]:
            if requests_made >= MAX_REQUESTS:
                break
            if cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            if requests_made > 0:
                time.sleep(_DELAY)
            info = _lookup_by_id(cve_id)
            requests_made += 1
            if info:
                info['source'] = 'mentioned_in_output'
                results.append(info)

        # Step 2 — look up by detected technology versions
        tech = extract_tech(output)
        for product, version in tech[:3]:
            if requests_made >= MAX_REQUESTS:
                break
            if requests_made > 0:
                time.sleep(_DELAY)
            keyword = f'{product} {version}'
            matches = _lookup_by_keyword(keyword, max_results=2)
            requests_made += 1
            for m in matches:
                if m['id'] not in seen_ids:
                    seen_ids.add(m['id'])
                    m['source']       = 'tech_fingerprint'
                    m['tech_matched'] = f'{product} {version}'
                    results.append(m)

    except RuntimeError as e:
        return {'tech': [], 'cves': results, 'error': str(e)}
    except Exception as e:
        return {'tech': [], 'cves': results, 'error': f'Unexpected error: {e}'}

    # Sort: explicit mentions first, then by CVSS score descending
    results.sort(key=lambda x: (
        0 if x['source'] == 'mentioned_in_output' else 1,
        -(x['score'] or 0),
    ))

    tech_out = extract_tech(output)
    return {
        'tech':  [{'product': p, 'version': v} for p, v in tech_out],
        'cves':  results[:12],
        'error': None,
    }
