"""CF_AI tool: Nuclei vulnerability scanner integration."""
from __future__ import annotations
import json
import shutil
import subprocess
from sdk.agents import function_tool

_TEMPLATE_MAP: dict[str, str] = {
    'cves':             'cves/',
    'vulnerabilities':  'vulnerabilities/',
    'misconfiguration': 'misconfiguration/',
    'exposures':        'exposures/',
    'default-logins':   'default-logins/',
    'takeovers':        'takeovers/',
    'technologies':     'technologies/',
    'wordpress':        'technologies/wordpress/',
}

_SEV_MARKER: dict[str, str] = {
    'critical': '|Critical|',
    'high':     '|High|',
    'medium':   '|Medium|',
    'low':      '|Low|',
    'info':     '|Info|',
}

_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
_ORDER = ['critical', 'high', 'medium', 'low', 'info']


@function_tool
def nuclei_scan(
    target: str,
    templates: str = 'cves,vulnerabilities,misconfiguration,exposures',
    tags: str = '',
    severity: str = 'medium,high,critical',
    headers: str = '',
) -> str:
    """Run Nuclei against a target URL and return structured vulnerability findings.

    Nuclei is a purpose-built vulnerability scanner with 9,000+ verified templates
    covering CVEs, injection flaws, misconfigurations, exposed files, and default
    credentials. Always call this before manual curl payload testing — it is far
    more thorough for known CVE detection.

    Args:
        target:    Full URL to scan, e.g. https://example.com
        templates: Comma-separated template categories:
                   cves, vulnerabilities, misconfiguration, exposures,
                   default-logins, takeovers, technologies, wordpress
        tags:      Comma-separated tag filter, e.g. 'sqli,xss,rce,ssrf,wordpress'
                   When set, overrides the templates argument.
        severity:  Comma-separated severity filter: info,low,medium,high,critical
        headers:   Extra HTTP headers, one per line in 'Header: Value' format

    Returns:
        Structured findings report. |High| and |Critical| markers in the output
        are picked up by the CF_AI dashboard risk detection system automatically.
    """
    nuclei_bin = shutil.which('nuclei')
    if not nuclei_bin:
        return (
            '[NUCLEI] Not installed — skipping template scan.\n'
            'Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n'
            '  or: apt-get install nuclei   (Kali / ParrotOS)\n'
            '  or: brew install nuclei      (macOS)\n'
            'After install run once: nuclei -update-templates'
        )

    cmd = [
        nuclei_bin,
        '-u', target,
        '-j',           # JSONL output — one finding per line
        '-silent',      # suppress banner/progress bar
        '-no-color',
        '-timeout', '10',
        '-c', '25',     # 25 concurrent template goroutines
        '-rate-limit', '50',
        '-retries', '1',
        '-severity', severity,
    ]

    if tags:
        cmd += ['-tags', tags]
    else:
        for t in templates.split(','):
            t = t.strip()
            path = _TEMPLATE_MAP.get(t, t.rstrip('/') + '/')
            cmd += ['-t', path]

    if headers:
        for line in headers.strip().splitlines():
            line = line.strip()
            if line and ':' in line:
                cmd += ['-H', line]

    cmd += ['-H', f'User-Agent: {_UA}']

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return '[NUCLEI] Scan timed out after 5 minutes — target may be unresponsive.'
    except Exception as exc:
        return f'[NUCLEI] Error: {exc}'

    findings: list[dict] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue

        info      = d.get('info', {})
        sev       = (info.get('severity') or 'info').lower()
        tags_raw  = info.get('tags', [])
        cve_ids   = [
            t.upper()
            for t in (tags_raw if isinstance(tags_raw, list) else [])
            if t.lower().startswith('cve-')
        ]
        findings.append({
            'severity':    sev,
            'marker':      _SEV_MARKER.get(sev, '|Info|'),
            'template_id': d.get('template-id', ''),
            'name':        info.get('name', ''),
            'matched':     d.get('matched-at', ''),
            'description': (info.get('description') or '')[:200],
            'extracted':   d.get('extracted-results', []),
            'curl':        d.get('curl-command', '')[:300],
            'cves':        cve_ids,
        })

    if not findings:
        return (
            f'[NUCLEI] Scan complete — 0 findings\n'
            f'Target  : {target}\n'
            f'Filters : {tags or templates} | severity={severity}'
            + (f'\n[NUCLEI] stderr: {result.stderr.strip()[:300]}' if result.stderr.strip() else '')
        )

    by_sev: dict[str, list] = {s: [] for s in _ORDER}
    for f in findings:
        by_sev.setdefault(f['severity'], []).append(f)

    out: list[str] = [f'[NUCLEI] {len(findings)} finding(s) on {target}', '=' * 70]

    for sev in _ORDER:
        items = by_sev.get(sev, [])
        if not items:
            continue
        out.append(f'\n[{sev.upper()}] {len(items)} finding(s)')
        out.append('-' * 50)
        for f in items:
            cve_str = ' [' + ', '.join(f['cves']) + ']' if f['cves'] else ''
            out.append(f'{f["marker"]} {f["template_id"]}{cve_str}')
            out.append(f'  Name     : {f["name"]}')
            out.append(f'  URL      : {f["matched"]}')
            if f['description']:
                out.append(f'  Detail   : {f["description"]}')
            for ex in f['extracted'][:3]:
                out.append(f'  Extracted: {str(ex)[:200]}')
            if f['curl']:
                out.append(f'  Verify   : {f["curl"]}')
            out.append('')

    out.append('=' * 70)
    out.append('[NUCLEI] Done. Manually verify High/Critical findings before reporting.')
    return '\n'.join(out)
