"""
Shared helper: translate HTTP status codes and network errors into
plain English explanations suitable for security reports and agent output.
"""
from __future__ import annotations

_STATUS_MESSAGES: dict[int, str] = {
    200: 'accessible — the server returned the page successfully',
    201: 'resource created successfully',
    204: 'request accepted with no content returned',
    206: 'partial content returned by the server',
    301: 'permanently redirected to another location',
    302: 'temporarily redirected to another location',
    304: 'not modified — the cached version is current',
    400: 'bad request — the server did not understand the request syntax',
    401: 'authentication required — valid credentials must be provided to access this resource',
    403: 'access denied — the server understood the request but refused to fulfil it',
    404: 'not found — no resource exists at this path',
    405: 'method not allowed — the HTTP method used is not accepted here',
    408: 'request timed out — the server did not receive the complete request in time',
    409: 'conflict — the request could not be completed due to a state conflict',
    410: 'gone — the resource has been permanently removed from the server',
    412: 'precondition failed — one or more request headers did not match the server requirements',
    413: 'request too large — the server refused because the payload exceeded its limit',
    415: 'unsupported media type — the content format is not accepted by this endpoint',
    422: 'unprocessable content — the request was well-formed but contained semantic errors',
    429: 'rate limited — too many requests sent in a short time; the server is throttling access',
    500: 'internal server error — the server encountered an unexpected condition',
    501: 'not implemented — the server does not support the requested method',
    502: 'bad gateway — the server received an invalid response from an upstream service',
    503: 'service unavailable — the server is temporarily unable to handle the request',
    504: 'gateway timeout — the upstream server did not respond in time',
    520: 'unknown error from the origin server (Cloudflare reported an unexpected response)',
    521: 'origin server is unreachable (Cloudflare could not connect to the server)',
    522: 'connection timed out — Cloudflare could not establish a connection to the origin server',
    523: 'origin server is unreachable — Cloudflare cannot reach the host',
    524: 'response timeout — Cloudflare connected but the origin took too long to respond',
    526: 'invalid SSL certificate on the origin server',
}

_API_ERROR_HINTS: dict[str, str] = {
    'TAVILY_API_KEY':     'To enable AI-powered web search, add TAVILY_API_KEY to your .env file.',
    'PERPLEXITY_API_KEY': 'To enable Perplexity AI search, add PERPLEXITY_API_KEY to your .env file.',
    'GOOGLE_CSE_API_KEY': 'To enable Google Custom Search, add GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID to your .env file.',
    'TRAVERSAAL_API_KEY': 'To enable Traversaal search, add TRAVERSAAL_API_KEY to your .env file.',
    'GREYNOISE_API_KEY':  'A free GreyNoise API key is available at greynoise.io — add GREYNOISE_API_KEY to your .env for full access.',
    'NEO4J_URI':          'To enable the knowledge graph, add NEO4J_URI, NEO4J_USER, and NEO4J_PASSWORD to your .env file.',
    'PG_HOST':            'To enable PostgreSQL storage, add PG_HOST, PG_NAME, PG_USER, and PG_PASSWORD to your .env file.',
}


def http_explain(status: int, context: str = '') -> str:
    """Return a plain English explanation of an HTTP status code."""
    base = _STATUS_MESSAGES.get(status, f'an unexpected status was returned by the server')
    ctx  = f' ({context})' if context else ''
    return f'The server responded with status {status}: {base}{ctx}'


def http_label(status: int) -> str:
    """Return a short human-readable label for a status code, e.g. 'Accessible' or 'Not found'."""
    labels = {
        200: 'Accessible',
        201: 'Created',
        204: 'Empty response',
        301: 'Redirects permanently',
        302: 'Redirects temporarily',
        304: 'Cached',
        400: 'Bad request',
        401: 'Requires authentication',
        403: 'Access denied',
        404: 'Not found',
        405: 'Method not allowed',
        408: 'Timed out',
        410: 'Removed',
        429: 'Rate limited',
        500: 'Server error',
        502: 'Bad gateway',
        503: 'Service unavailable',
        504: 'Gateway timeout',
    }
    if status == 0:
        return 'Unreachable (no response)'
    label = labels.get(status, f'Status {status}')
    return label


def api_missing_key_msg(key_name: str, service: str) -> str:
    """Return a friendly message when an API key is not configured."""
    hint = _API_ERROR_HINTS.get(key_name, f'Add {key_name} to your .env file to enable this service.')
    return (
        f'The {service} search tool is not available because no API key has been configured. '
        f'{hint}'
    )


def network_error_msg(service: str, url: str = '') -> str:
    """Return a friendly message for a network-level error (status 0)."""
    loc = f' at {url}' if url else ''
    return (
        f'A network error occurred while contacting {service}{loc}. '
        f'The host may be unreachable, the connection timed out, or the request was blocked. '
        f'Check network connectivity and try again.'
    )


def api_error_msg(service: str, status: int, hint: str = '') -> str:
    """Return a friendly message for a non-200 API response."""
    explanation = _STATUS_MESSAGES.get(status, f'an unexpected error (code {status})')
    base = (
        f'The {service} API request was unsuccessful. '
        f'The server responded with: {explanation}.'
    )
    if hint:
        base += f' {hint}'
    return base
