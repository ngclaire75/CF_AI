"""CF_AI tool: generic Linux command execution with real-time output."""
import os
import platform
import re
import subprocess
from sdk.agents import function_tool

TOOL_TIMEOUT = int(os.environ.get('CFAI_TOOL_TIMEOUT', '300'))
CWD          = os.environ.get('CFAI_CWD', '/root')

# ── Cross-platform bash resolution ──────────────────────────────────────────
def _find_bash() -> list:
    """Return the argv prefix to invoke bash -c on any platform."""
    if platform.system() != 'Windows':
        return ['/bin/bash', '-c']
    # Windows: prefer Git Bash, fallback to WSL
    for candidate in [
        r'C:\Program Files\Git\bin\bash.exe',
        r'C:\Program Files (x86)\Git\bin\bash.exe',
        r'C:\Windows\System32\bash.exe',   # WSL bash
    ]:
        if os.path.isfile(candidate):
            return [candidate, '-c']
    return None  # no bash found — fallback to cmd.exe

_BASH_ARGV = _find_bash()
_IS_WINDOWS = platform.system() == 'Windows'

_EXIT_EXPLAIN = {
    0:  'The server returned an empty response. '
        'Recovery options: '
        '(1) Add -v to see response headers — X-Debug-Token, X-Powered-By, Server often reveal framework/version. '
        '(2) Try debug headers: -H "X-Debug: 1" -H "X-Debug-Token: debug". '
        '(3) Fetch debug artifacts: /.env  /.git/HEAD  /phpinfo.php  /actuator/health  /server-status. '
        '(4) Append query params: ?debug=1  ?XDEBUG_SESSION_START=1  ?env=debug. '
        '(5) Use Accept: application/json to get a JSON error body. '
        '(6) Try OPTIONS method to enumerate allowed HTTP methods. '
        '(7) Add -L to follow redirects.',
    1:  'The command produced no output. '
        'Recovery options: '
        '(1) Check the tool is installed: which <tool>  or  apt-get install <tool>. '
        '(2) Run with --verbose or -v to see the actual error. '
        '(3) For curl: check URL quoting, try without -k, verify the endpoint with curl -I first. '
        '(4) Replace with a Python one-liner using subprocess + curl list args to avoid shell quoting issues. '
        '(5) Look for HTML comments: curl ... | grep -oP "<!--.*?-->". '
        '(6) Check for JS source maps: curl <page.js>.map.',
    6:  'DNS lookup failed — the domain does not resolve. Check for typos, or the VPS may have no internet access.',
    7:  'TCP connection refused — the port is closed or no service is listening on it.',
    28: 'Request timed out — the server is likely blocking this VPS IP (geo-block or cloud-provider filter). '
        'Skip retrying; pivot to passive sources: Shodan, Wayback Machine, crt.sh, or a staging subdomain.',
    35: 'SSL/TLS handshake failed — the certificate may be expired, SNI may be mismatched, or a WAF reset the connection. Try adding -k to skip certificate verification.',
    51: 'SSL peer certificate verification failed — the certificate is self-signed or the CN does not match. Add -k to proceed.',
    52: 'No data received — the server accepted the TCP connection but sent nothing back.',
    56: 'Network receive failure — the connection dropped mid-transfer. Retry once; if it persists the host is rate-limiting.',
    60: 'SSL certificate not trusted — add -k to skip certificate verification and retry.',
}

# Inject speed flags into every curl call:
#   -4                   force IPv4 (avoids ~120s IPv6 fallback on most VPS)
#   --connect-timeout 8  give up on TCP connect after 8s
#   --max-time 20        overall cap so a blocked host can't hang the agent forever
_CURL_SPEED_FLAGS = '-4 --connect-timeout 8 --max-time 20'
# Only match curl when it is NOT inside a Python string literal (preceded by ' or ").
# Without this, _patch_curl corrupts subprocess.run(['curl',...]) list args by merging
# flags into the first element: ['curl -4 --connect-timeout 8 ...'] → FileNotFoundError.
_CURL_RE = re.compile(r"""(?<!['"])\bcurl\b""")
_HAS_MAX_TIME = re.compile(r'--max-time\s')

def _patch_curl(cmd: str) -> str:
    """Prepend speed flags to every curl invocation in the command."""
    has_max = bool(_HAS_MAX_TIME.search(cmd))
    # If user already specified --max-time, respect it (omit our --max-time 20)
    flags = '-4 --connect-timeout 8' if has_max else _CURL_SPEED_FLAGS

    def _inject(m):
        pos = m.end()
        # Don't double-inject if -4 already present
        rest = cmd[pos:pos+5]
        if rest.lstrip().startswith('-4'):
            return m.group(0)
        return f'curl {flags}'
    return _CURL_RE.sub(_inject, cmd)


def _patch_windows_compat(cmd: str) -> str:
    """On Windows, substitute commands that don't exist for compatible equivalents."""
    if not _IS_WINDOWS:
        return cmd
    # Agents use python3 but Windows installs as python
    cmd = re.sub(r'\bpython3\b', 'python', cmd)
    return cmd


@function_tool
def generic_linux_command(command: str) -> str:
    """Execute any Linux shell command on the Kali VPS and return its output.

    Use this for: nmap, nikto, nuclei, gobuster, wpscan, sqlmap, hydra, john,
    hashcat, subfinder, amass, wafw00f, whatweb, ffuf, curl, wget, dig,
    file operations (ls, cat, mkdir, etc.), and any other shell command.

    Returns stdout + stderr combined. Truncated to 8000 chars if very long.
    """
    patched = _patch_curl(command)
    patched = _patch_windows_compat(patched)

    # Determine working directory — use temp dir on Windows since /root doesn't exist
    cwd = CWD
    if _IS_WINDOWS and not os.path.isdir(cwd):
        cwd = os.environ.get('TEMP', os.path.expanduser('~'))

    try:
        if _BASH_ARGV:
            # Unix or Windows with Git Bash / WSL — run through real bash
            result = subprocess.run(
                _BASH_ARGV + [patched],
                capture_output=True,
                text=True,
                timeout=TOOL_TIMEOUT,
                cwd=cwd,
                env={**os.environ, 'TERM': 'dumb', 'COLUMNS': '120'},
            )
        else:
            # Windows without bash — use cmd.exe (limited, but better than crashing)
            result = subprocess.run(
                patched,
                shell=True,
                capture_output=True,
                text=True,
                timeout=TOOL_TIMEOUT,
                cwd=cwd,
                env={**os.environ, 'TERM': 'dumb', 'COLUMNS': '120'},
            )
        output = (result.stdout + result.stderr).strip()
        if not output and result.returncode in _EXIT_EXPLAIN:
            return _EXIT_EXPLAIN[result.returncode]
        if len(output) > 8000:
            lines = output.splitlines()
            kept  = '\n'.join(lines[:80]) + f'\n… [{len(lines)-80} more lines truncated]'
            return kept
        if not output:
            return f'No output returned. The command completed but produced nothing — check the target or try a different approach.'
        if result.returncode in _EXIT_EXPLAIN and result.returncode not in (0, 1) and len(output) < 120:
            return output + f'\n{_EXIT_EXPLAIN[result.returncode]}'
        return output
    except subprocess.TimeoutExpired:
        return f'[timeout after {TOOL_TIMEOUT}s — try a shorter scan or add --timeout]'
    except Exception as exc:
        return f'[execution error: {exc}]'


@function_tool
def read_file(path: str) -> str:
    """Read a file from the filesystem and return its contents."""
    try:
        with open(path) as f:
            content = f.read()
        if len(content) > 6000:
            return content[:6000] + '\n… [truncated]'
        return content
    except Exception as exc:
        return f'[error reading {path}: {exc}]'


@function_tool
def write_file(path: str, content: str) -> str:
    """Write content to a file on the filesystem. Creates parent dirs if needed."""
    try:
        import pathlib
        pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)
        return f'Written {len(content)} bytes to {path}'
    except Exception as exc:
        return f'[error writing {path}: {exc}]'
