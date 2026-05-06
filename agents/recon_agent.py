"""CF_AI Recon Agent — passive + active reconnaissance and fingerprinting."""
import re
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from .telemetry import traced

log = logging.getLogger('cfai.recon')

RECON_TIMEOUT = 90


def _run(cmd: list[str], timeout: int = RECON_TIMEOUT) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=__import__('os').environ | {'TERM': 'dumb'})
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return '[timeout]'
    except FileNotFoundError:
        return '[not installed]'
    except Exception as exc:
        return f'[error: {exc}]'


def _which(binary: str) -> bool:
    return subprocess.run(['which', binary], capture_output=True).returncode == 0


class ReconAgent:
    """Runs passive and active recon against a target."""

    @traced('recon.run')
    def run(self, site: dict) -> dict:
        url  = site.get('url', '').rstrip('/')
        host = re.sub(r'https?://', '', url).split('/')[0]

        tasks = {
            'subdomains':    lambda: self._subdomains(host),
            'ports':         lambda: self._port_scan(host),
            'waf':           lambda: self._detect_waf(url),
            'tech':          lambda: self._detect_tech(url),
            'ssl':           lambda: self._ssl_info(host),
            'dns':           lambda: self._dns_info(host),
        }

        results: dict = {'url': url, 'host': host}
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(fn): name for name, fn in tasks.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as exc:
                    results[name] = {'error': str(exc)}

        results['summary'] = self._summarise(results)
        log.info('Recon complete for %s', url)
        return results

    # ── Passive ──────────────────────────────────────────────────────────────

    def _subdomains(self, host: str) -> dict:
        subs: list[str] = []

        if _which('subfinder'):
            out = _run(['subfinder', '-d', host, '-silent', '-timeout', '30'])
            subs.extend(l.strip() for l in out.splitlines() if l.strip() and '[' not in l)

        if _which('amass') and len(subs) < 5:
            out = _run(['amass', 'enum', '-passive', '-d', host, '-timeout', '30'], timeout=60)
            for line in out.splitlines():
                s = line.strip()
                if s and host in s and s not in subs:
                    subs.append(s)

        return {'count': len(subs), 'subdomains': subs[:50]}

    def _dns_info(self, host: str) -> dict:
        records: dict = {}
        for record_type in ('A', 'MX', 'NS', 'TXT'):
            out = _run(['dig', '+short', record_type, host])
            if out and '[' not in out:
                records[record_type] = [l for l in out.splitlines() if l]
        return records

    def _ssl_info(self, host: str) -> dict:
        out = _run(['openssl', 's_client', '-connect', f'{host}:443',
                    '-servername', host, '-brief'], timeout=15)
        info: dict = {}
        for line in out.splitlines():
            if 'subject' in line.lower():
                info['subject'] = line.split(':', 1)[-1].strip()
            if 'issuer' in line.lower():
                info['issuer'] = line.split(':', 1)[-1].strip()
            if 'expire' in line.lower():
                info['expiry'] = line.split(':', 1)[-1].strip()
        return info

    # ── Active ───────────────────────────────────────────────────────────────

    def _port_scan(self, host: str) -> dict:
        out = _run(['nmap', '-sV', '--open', '-T4', '-p',
                    '21,22,23,25,53,80,110,143,443,445,993,995,'
                    '1433,1521,3306,3389,5432,5900,6379,8080,8443,27017',
                    '--host-timeout', '60s', host])
        open_ports: list[dict] = []
        for line in out.splitlines():
            m = re.match(r'(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)', line)
            if m:
                open_ports.append({
                    'port':    int(m.group(1)),
                    'proto':   m.group(2),
                    'service': m.group(3),
                    'version': m.group(4).strip(),
                })
        return {'raw': out[:500], 'open_ports': open_ports}

    def _detect_waf(self, url: str) -> dict:
        if _which('wafw00f'):
            out = _run(['wafw00f', url, '-a'])
            detected: list[str] = []
            for line in out.splitlines():
                m = re.search(r'is behind (.+)', line, re.I)
                if m:
                    detected.append(m.group(1).strip())
            return {'detected': detected, 'raw': out[:300]}
        return {'detected': [], 'raw': '[wafw00f not installed]'}

    def _detect_tech(self, url: str) -> dict:
        if _which('whatweb'):
            out = _run(['whatweb', '-a', '3', '--log-brief=/dev/stderr', url])
            return {'raw': out[:500]}
        return {'raw': '[whatweb not installed]'}

    # ── Summary ──────────────────────────────────────────────────────────────

    def _summarise(self, results: dict) -> dict:
        ports  = results.get('ports', {}).get('open_ports', [])
        subs   = results.get('subdomains', {}).get('count', 0)
        waf    = results.get('waf', {}).get('detected', [])
        return {
            'open_port_count':  len(ports),
            'subdomain_count':  subs,
            'waf_detected':     bool(waf),
            'waf_names':        waf,
            'has_ssl':          bool(results.get('ssl')),
        }


_agent: Optional[ReconAgent] = None


def get_recon() -> ReconAgent:
    global _agent
    if _agent is None:
        _agent = ReconAgent()
    return _agent
