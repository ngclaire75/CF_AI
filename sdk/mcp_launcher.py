"""CF_AI MCP server lifecycle — start/stop the WordPress MCP server subprocess.

Used by sdk/agents.py to auto-start the FastMCP server when a Claude model
is running an agent that has MCP tools (_is_mcp_tool=True). Falls back
gracefully if the 'mcp' package is not installed or the server fails to start.
"""
from __future__ import annotations
import atexit
import logging
import os
import socket
import subprocess
import sys
import threading
import time

log  = logging.getLogger('cfai.mcp')
_lk  = threading.Lock()
_proc: subprocess.Popen | None = None
_port: int | None = None
_url:  str = ''


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _wait(port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.4):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def get_server_url() -> str:
    """Start the MCP server if not running. Returns server URL or '' on failure."""
    global _proc, _port, _url
    with _lk:
        # Already running?
        if _url and _proc and _proc.poll() is None:
            return _url

        # Require mcp package
        try:
            import mcp  # noqa: F401
        except ImportError:
            return ''

        script = os.path.normpath(
            os.path.join(os.path.dirname(__file__), '..', 'tools', 'wp_mcp_server.py')
        )
        if not os.path.isfile(script):
            return ''

        _port = _free_port()
        env   = {**os.environ, 'WP_MCP_PORT': str(_port)}
        _proc = subprocess.Popen(
            [sys.executable, script],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        atexit.register(stop)

        if _wait(_port):
            _url = f'http://127.0.0.1:{_port}/mcp'
            log.info('MCP server ready: %s', _url)
            return _url

        log.warning('MCP server did not become ready — using direct tool calls')
        try:
            _proc.terminate()
        except Exception:
            pass
        _proc = None
        return ''


def stop():
    global _proc, _url
    with _lk:
        if _proc:
            try:
                _proc.terminate()
            except Exception:
                pass
            _proc = None
            _url = ''
