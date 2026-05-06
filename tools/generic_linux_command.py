"""CF_AI tool: generic Linux command execution with real-time output."""
import os
import re
import subprocess
from sdk.agents import function_tool

TOOL_TIMEOUT = int(os.environ.get('CFAI_TOOL_TIMEOUT', '300'))
CWD          = os.environ.get('CFAI_CWD', '/root')

# Inject speed flags into every curl call:
#   -4                   force IPv4 (avoids ~120s IPv6 fallback on most VPS)
#   --connect-timeout 8  give up on TCP connect after 8s
#   --max-time 20        overall cap so a blocked host can't hang the agent forever
_CURL_SPEED_FLAGS = '-4 --connect-timeout 8 --max-time 20'
_CURL_RE = re.compile(r'\bcurl\b')
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


@function_tool
def generic_linux_command(command: str) -> str:
    """Execute any Linux shell command on the Kali VPS and return its output.

    Use this for: nmap, nikto, nuclei, gobuster, wpscan, sqlmap, hydra, john,
    hashcat, subfinder, amass, wafw00f, whatweb, ffuf, curl, wget, dig,
    file operations (ls, cat, mkdir, etc.), and any other shell command.

    Returns stdout + stderr combined. Truncated to 8000 chars if very long.
    """
    patched = _patch_curl(command)
    try:
        result = subprocess.run(
            patched,
            shell=True,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            cwd=CWD,
            env={**os.environ, 'TERM': 'dumb', 'COLUMNS': '120'},
        )
        output = (result.stdout + result.stderr).strip()
        if len(output) > 8000:
            lines = output.splitlines()
            kept  = '\n'.join(lines[:80]) + f'\n… [{len(lines)-80} more lines truncated]'
            return kept
        return output or f'[exit code {result.returncode}, no output]'
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
