"""CF_AI Scanner Agent — platform-aware scanning with parallel tool execution."""
import os
import re
import shlex
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from .claude_agent import analyze_scan_output
from .telemetry import traced

log = logging.getLogger('cfai.scanner')

SCAN_TIMEOUT = int(os.environ.get('CFAI_SCAN_TIMEOUT', '120'))


# ── Tool sets by platform ────────────────────────────────────────────────────

_BASE_TOOLS = [
    ('nmap',      '-sV -sC --open -T4 {host} -p 80,443,8080,8443,22,21,25,3306,5432,6379,27017'),
    ('whatweb',   '-a 3 --log-json=/tmp/whatweb_{safe}.json {url}'),
    ('wafw00f',   '{url}'),
    ('nikto',     '-h {url} -maxtime 60s -Format txt'),
    ('nuclei',    '-u {url} -severity medium,high,critical -silent -timeout 10 -rate-limit 20'),
    ('gobuster',  'dir -u {url} -w /usr/share/wordlists/dirb/common.txt -q --no-error -t 20'),
]

_WORDPRESS_TOOLS = [
    ('wpscan',    '--url {url} --enumerate u,p,t --disable-tls-checks --format cli-no-color'),
]

_DRUPAL_TOOLS = [
    ('droopescan', 'scan drupal -u {url}'),
]

_JOOMLA_TOOLS = [
    ('joomscan',  '-u {url}'),
]

_PLATFORM_TOOLS = {
    'wordpress': _WORDPRESS_TOOLS,
    'drupal':    _DRUPAL_TOOLS,
    'joomla':    _JOOMLA_TOOLS,
}

# ── Helpers ──────────────────────────────────────────────────────────────────

def _which(binary: str) -> bool:
    return subprocess.run(['which', binary], capture_output=True).returncode == 0


def _safe_name(url: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_-]', '_', url)[:40]


def _run_tool(binary: str, args_template: str, url: str, host: str) -> tuple[str, str]:
    """Run a single security tool; returns (tool_name, stdout_output)."""
    safe = _safe_name(url)
    args = args_template.format(url=url, host=host, safe=safe)
    cmd  = f'{binary} {args}'
    try:
        result = subprocess.run(
            shlex.split(cmd),
            capture_output=True, text=True,
            timeout=SCAN_TIMEOUT,
            env={**os.environ, 'TERM': 'dumb'},
        )
        return binary, (result.stdout + result.stderr).strip()
    except subprocess.TimeoutExpired:
        return binary, f'[timeout after {SCAN_TIMEOUT}s]'
    except FileNotFoundError:
        return binary, f'[not installed]'
    except Exception as exc:
        return binary, f'[error: {exc}]'


# ── Scanner Agent ─────────────────────────────────────────────────────────────

class ScannerAgent:
    """Runs a full scan against a site and returns structured findings."""

    MAX_WORKERS = 4

    @traced('scanner.run')
    def run(self, site: dict) -> list[dict]:
        url      = site.get('url', '').rstrip('/')
        platform = site.get('platform', 'unknown').lower()
        host     = re.sub(r'https?://', '', url).split('/')[0]

        tools = list(_BASE_TOOLS)
        tools += _PLATFORM_TOOLS.get(platform, [])

        # Filter to installed tools
        tools = [(b, a) for b, a in tools if _which(b)]
        if not tools:
            log.warning('No scan tools available for %s', url)
            return []

        raw_outputs: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as pool:
            futures = {pool.submit(_run_tool, b, a, url, host): b for b, a in tools}
            for future in as_completed(futures):
                tool_name, output = future.result()
                if output and '[not installed]' not in output:
                    raw_outputs[tool_name] = output
                    log.debug('%s completed (%d chars)', tool_name, len(output))

        findings: list[dict] = []
        for tool_name, output in raw_outputs.items():
            parsed = analyze_scan_output(tool_name, output, url)
            for f in parsed:
                f['tool']     = tool_name
                f['site_url'] = url
            findings.extend(parsed)

        # Deduplicate by title+site
        seen = set()
        unique = []
        for f in findings:
            key = (f.get('title', ''), f.get('site_url', ''))
            if key not in seen:
                seen.add(key)
                unique.append(f)

        log.info('Scan of %s complete: %d findings from %d tools',
                 url, len(unique), len(raw_outputs))
        return unique

    def quick_recon(self, site: dict) -> dict:
        """Fast single-tool recon (whatweb only) for platform detection."""
        url  = site.get('url', '')
        host = re.sub(r'https?://', '', url).split('/')[0]
        _, output = _run_tool('whatweb', '-a 1 {url}', url, host)
        return {'tool': 'whatweb', 'output': output, 'url': url}


_agent: Optional[ScannerAgent] = None


def get_scanner() -> ScannerAgent:
    global _agent
    if _agent is None:
        _agent = ScannerAgent()
    return _agent
