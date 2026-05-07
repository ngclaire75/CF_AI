"""CF_AI WordPress MCP Server — proper Model Context Protocol implementation.

Exposes wp_security_scan and wp_api_call as MCP tools so any MCP client
(Claude Desktop, Claude Code, external integrations) can connect and run
WordPress security audits without needing Python function access.

Start standalone:
    python3 tools/wp_mcp_server.py

Server URL (streamable-http):
    http://127.0.0.1:${WP_MCP_PORT:-8765}/mcp

Environment credentials (inherited by the server process):
    WP_USER          — WordPress username
    WP_APP_PASSWORD  — Application Password (preferred)
    WP_PASSWORD      — Plain admin password (fallback)
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from mcp.server.fastmcp import FastMCP

_PORT = int(os.environ.get('WP_MCP_PORT', '8765'))

mcp = FastMCP(
    name='CF_AI WordPress Security',
    host='127.0.0.1',
    port=_PORT,
)


@mcp.tool()
def wp_security_scan(site_url: str) -> str:
    """Comprehensive WordPress security audit via MCP.

    Performs 13 checks: WP version, user enumeration, plugin/theme versions,
    XML-RPC, REST API exposure, debug.log, wp-config.php accessibility,
    wp-cron, SSL certificate, security headers, and sensitive file access.

    Credentials are read from WP_USER / WP_APP_PASSWORD / WP_PASSWORD env vars
    and used in an auth fallback chain: Basic Auth → Cookie+Nonce → public.

    Returns structured findings with WP-LOG entries (format:
    WP-LOG | timestamp | user | event | ip | SEVERITY) for plugin log tracking.
    IMPORTANT: Include all WP-LOG lines verbatim in your final response.
    """
    from tools.wordpress_mcp import wp_security_scan as _f
    return _f(site_url)


@mcp.tool()
def wp_api_call(site_url: str, endpoint: str) -> str:
    """Call any WordPress REST API endpoint via MCP.

    Auth fallback chain: Basic Auth (WP_USER + WP_APP_PASSWORD) →
    Cookie+Nonce (WP_USER + WP_PASSWORD) → unauthenticated public access.

    Credentials from WP_USER / WP_APP_PASSWORD / WP_PASSWORD env vars.
    endpoint must start with /wp-json/ e.g. /wp-json/wp/v2/users
    """
    from tools.wordpress_mcp import wp_api_call as _f
    return _f(site_url, endpoint)


if __name__ == '__main__':
    print(f'[CF_AI MCP] WordPress Security server → http://127.0.0.1:{_PORT}/mcp')
    print(f'[CF_AI MCP] Tools: wp_security_scan, wp_api_call')
    print(f'[CF_AI MCP] Credentials from env: WP_USER, WP_APP_PASSWORD, WP_PASSWORD')
    mcp.run(transport='streamable-http')
