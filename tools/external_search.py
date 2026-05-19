"""
CF_AI — External search system integrations.
Supports: Tavily, Perplexity, DuckDuckGo, Google CSE, Sploitus, Searxng, Shodan, GreyNoise.
API keys loaded from environment variables — never hardcoded.
"""
from __future__ import annotations
import json
import os
import re
import subprocess
import urllib.parse
from sdk.agents import function_tool
from tools._http_explain import api_missing_key_msg, api_error_msg, network_error_msg

_TO = 15
_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'


def _curl(url: str, method: str = 'GET', data: str = '', headers: list[str] | None = None,
          timeout: int = _TO) -> tuple[int, str]:
    """Return (status_code, body). status=0 on network error."""
    flags = ['-s', '-4', '-L', '--connect-timeout', '8', '--max-time', str(timeout),
             '-w', '\n__STATUS__%{http_code}', '-A', _UA]
    if method == 'POST':
        flags += ['-X', 'POST', '--data', data or '']
    for h in (headers or []):
        flags += ['-H', h]
    flags.append(url)
    try:
        r = subprocess.run(['curl'] + flags, capture_output=True, text=True, timeout=timeout + 5)
        body, _, status_str = r.stdout.rpartition('\n__STATUS__')
        return int(status_str.strip() or '0'), body.strip()
    except Exception:
        return 0, ''


def _clean(text: str, max_len: int = 0) -> str:
    """Remove non-printable/control characters and optionally truncate."""
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    if max_len and len(text) > max_len:
        text = text[:max_len]
    return text.strip()


# ──────────────────────────────────────────────────────────────────────────────
# TAVILY
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def search_tavily(query: str, search_depth: str = 'advanced', max_results: int = 5) -> str:
    """
    Search the web using Tavily AI search API (optimised for security research).
    Returns structured results with titles, URLs, and content snippets.
    Requires TAVILY_API_KEY environment variable.

    Args:
        query: Search query (e.g. "CVE-2024-1234 exploit", "nginx 1.18 vulnerabilities")
        search_depth: "basic" (fast) or "advanced" (deeper, recommended for security research)
        max_results: Number of results to return (1-10, default 5)
    """
    key = os.environ.get('TAVILY_API_KEY', '').strip()
    if not key:
        return json.dumps({
            'status': 'not_configured',
            'message': api_missing_key_msg('TAVILY_API_KEY', 'Tavily'),
            'results': [],
        }, indent=2)

    payload = json.dumps({
        'api_key': key,
        'query': query,
        'search_depth': search_depth,
        'max_results': min(max(1, max_results), 10),
        'include_answer': True,
        'include_raw_content': False,
    })
    status, body = _curl('https://api.tavily.com/search', method='POST', data=payload,
                         headers=['Content-Type: application/json'])
    if status == 0:
        return json.dumps({'status': 'network_error', 'message': network_error_msg('Tavily'), 'results': []}, indent=2)
    if status != 200:
        return json.dumps({
            'status': 'api_error',
            'message': api_error_msg('Tavily', status,
                'If your API key is valid, this may be a temporary outage. Try again shortly.'),
            'results': [],
        }, indent=2)
    try:
        data = json.loads(body)
        return json.dumps({
            'source':  'Tavily AI Search',
            'query':   query,
            'summary': _clean(data.get('answer', '')),
            'results': [
                {
                    'title':   _clean(r.get('title', '')),
                    'url':     r.get('url', ''),
                    'summary': _clean(r.get('content', '')),
                }
                for r in data.get('results', [])[:max_results]
            ],
        }, indent=2)
    except Exception as e:
        return json.dumps({
            'status': 'parse_error',
            'message': f'The Tavily response could not be parsed. Technical detail: {e}',
            'results': [],
        }, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# PERPLEXITY
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def search_perplexity(query: str, model: str = 'llama-3.1-sonar-large-128k-online') -> str:
    """
    Search using Perplexity AI (web-grounded LLM search, excellent for CVE analysis).
    Requires PERPLEXITY_API_KEY environment variable.

    Args:
        query: Search query or question about a vulnerability/technology
        model: Perplexity model (default: llama-3.1-sonar-large-128k-online)
    """
    key = os.environ.get('PERPLEXITY_API_KEY', '').strip()
    if not key:
        return json.dumps({
            'status': 'not_configured',
            'message': api_missing_key_msg('PERPLEXITY_API_KEY', 'Perplexity AI'),
            'answer': '',
        }, indent=2)

    payload = json.dumps({
        'model': model,
        'messages': [
            {'role': 'system', 'content': 'You are a cybersecurity research assistant. Provide precise, factual answers with sources.'},
            {'role': 'user', 'content': query},
        ],
        'max_tokens': 1024,
        'return_citations': True,
    })
    status, body = _curl('https://api.perplexity.ai/chat/completions', method='POST', data=payload,
                         headers=['Content-Type: application/json', f'Authorization: Bearer {key}'])
    if status == 0:
        return json.dumps({'status': 'network_error', 'message': network_error_msg('Perplexity AI'), 'answer': ''}, indent=2)
    if status != 200:
        hint = 'If you are receiving an authentication error, verify your PERPLEXITY_API_KEY is correct.' if status == 401 else ''
        return json.dumps({
            'status': 'api_error',
            'message': api_error_msg('Perplexity AI', status, hint),
            'answer': '',
        }, indent=2)
    try:
        data = json.loads(body)
        answer = _clean(data.get('choices', [{}])[0].get('message', {}).get('content', ''))
        citations = data.get('citations', [])
        return json.dumps({
            'source':    'Perplexity AI',
            'query':     query,
            'answer':    answer,
            'citations': citations[:10],
        }, indent=2)
    except Exception as e:
        return json.dumps({
            'status': 'parse_error',
            'message': f'The Perplexity response could not be parsed. Technical detail: {e}',
            'answer': '',
        }, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# DUCKDUCKGO (no key required)
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def search_duckduckgo(query: str, max_results: int = 8) -> str:
    """
    Search the web using DuckDuckGo Instant Answer API (no API key required).
    Good for quick CVE lookups, tool documentation, and general security queries.

    Args:
        query: Search query (e.g. "sqlmap options", "CVE-2023-44487 details")
        max_results: Number of related topics to return (default 8)
    """
    encoded = urllib.parse.quote(query)
    url = f'https://api.duckduckgo.com/?q={encoded}&format=json&no_redirect=1&no_html=1&skip_disambig=1'
    status, body = _curl(url)
    if status != 200 or not body:
        # Fallback: DuckDuckGo HTML scrape
        fallback_url = f'https://html.duckduckgo.com/html/?q={encoded}'
        _, body2 = _curl(fallback_url)
        titles = re.findall(r'class="result__title"[^>]*>.*?<a[^>]*>([^<]+)</a>', body2, re.S)
        urls   = re.findall(r'class="result__url"[^>]*>\s*([^\s<]+)', body2)
        results = [
            {'title': _clean(t), 'url': u.strip()}
            for t, u in zip(titles[:max_results], urls[:max_results])
        ]
        return json.dumps({'source': 'DuckDuckGo', 'query': query, 'results': results}, indent=2)
    try:
        data = json.loads(body)
        results = []
        if data.get('AbstractText'):
            results.append({
                'type':    'summary',
                'text':    _clean(data['AbstractText']),
                'url':     data.get('AbstractURL', ''),
            })
        for item in data.get('RelatedTopics', [])[:max_results]:
            if isinstance(item, dict) and item.get('Text'):
                results.append({
                    'type': 'related',
                    'text': _clean(item['Text']),
                    'url':  item.get('FirstURL', ''),
                })
        return json.dumps({
            'source':  'DuckDuckGo',
            'query':   query,
            'answer':  _clean(data.get('Answer', '')),
            'results': results,
        }, indent=2)
    except Exception as e:
        return json.dumps({
            'status':  'parse_error',
            'message': f'The DuckDuckGo response could not be parsed. Technical detail: {e}',
            'results': [],
        }, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# GOOGLE CUSTOM SEARCH
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def search_google(query: str, max_results: int = 5, site_filter: str = '') -> str:
    """
    Search using Google Custom Search API.
    Requires GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID environment variables.

    Args:
        query: Search query
        max_results: Number of results (1-10)
        site_filter: Optional site restriction (e.g. "site:github.com" or "site:exploit-db.com")
    """
    key = os.environ.get('GOOGLE_CSE_API_KEY', '').strip()
    cx  = os.environ.get('GOOGLE_CSE_ID', '').strip()
    if not key or not cx:
        return json.dumps({
            'status': 'not_configured',
            'message': api_missing_key_msg('GOOGLE_CSE_API_KEY', 'Google Custom Search'),
            'results': [],
        }, indent=2)

    q = f'{site_filter} {query}'.strip() if site_filter else query
    params = urllib.parse.urlencode({'key': key, 'cx': cx, 'q': q, 'num': min(max_results, 10)})
    status, body = _curl(f'https://www.googleapis.com/customsearch/v1?{params}')
    if status == 0:
        return json.dumps({'status': 'network_error', 'message': network_error_msg('Google Custom Search'), 'results': []}, indent=2)
    if status != 200:
        hint = 'Verify your GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID are correct and the Custom Search Engine is enabled.' if status == 403 else ''
        return json.dumps({
            'status': 'api_error',
            'message': api_error_msg('Google Custom Search', status, hint),
            'results': [],
        }, indent=2)
    try:
        data = json.loads(body)
        return json.dumps({
            'source':  'Google Custom Search',
            'query':   q,
            'total_results': data.get('searchInformation', {}).get('totalResults', 'unknown'),
            'results': [
                {
                    'title':   _clean(i.get('title', '')),
                    'url':     i.get('link', ''),
                    'summary': _clean(i.get('snippet', '')),
                }
                for i in data.get('items', [])[:max_results]
            ],
        }, indent=2)
    except Exception as e:
        return json.dumps({
            'status':  'parse_error',
            'message': f'The Google search response could not be parsed. Technical detail: {e}',
            'results': [],
        }, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# SPLOITUS (exploit search — no key required)
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def search_sploitus(query: str, max_results: int = 8) -> str:
    """
    Search Sploitus for public exploits and PoCs by CVE ID, software name, or keyword.
    No API key required. Aggregates ExploitDB, PacketStorm, GitHub PoCs.

    Args:
        query: CVE ID (e.g. "CVE-2021-44228") or software name (e.g. "Apache Log4j RCE")
        max_results: Number of results to return (default 8)
    """
    payload = json.dumps({'query': query, 'type': 'exploits', 'offset': 0, 'implant': False})
    status, body = _curl('https://sploitus.com/search', method='POST', data=payload,
                         headers=['Content-Type: application/json',
                                  'Origin: https://sploitus.com',
                                  'Referer: https://sploitus.com/'])
    if status == 0:
        return json.dumps({'status': 'network_error', 'message': network_error_msg('Sploitus'), 'results': []}, indent=2)
    if status != 200:
        return json.dumps({
            'status': 'api_error',
            'message': api_error_msg('Sploitus', status,
                'Sploitus may be temporarily rate-limiting requests. Wait a moment and try again.'),
            'results': [],
        }, indent=2)
    try:
        data = json.loads(body)
        exploits = data.get('exploits', [])[:max_results]
        return json.dumps({
            'source':        'Sploitus (ExploitDB, PacketStorm, GitHub PoCs)',
            'query':         query,
            'total_found':   data.get('total', 0),
            'results': [
                {
                    'title':       _clean(e.get('title', '')),
                    'type':        e.get('type', ''),
                    'source':      e.get('source', ''),
                    'url':         e.get('href', ''),
                    'published':   e.get('published', ''),
                    'cvss_score':  e.get('cvss', ''),
                    'cve_ids':     e.get('cve_list', []),
                }
                for e in exploits
            ],
        }, indent=2)
    except Exception as e:
        return json.dumps({
            'status':  'parse_error',
            'message': f'The Sploitus response could not be parsed. Technical detail: {e}',
            'results': [],
        }, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# SEARXNG (self-hosted or public instance, no key)
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def search_searxng(query: str, categories: str = 'general,it', max_results: int = 8) -> str:
    """
    Search via SearXNG — a privacy-respecting metasearch engine.
    Uses SEARXNG_URL env var (default: https://searx.be). No API key needed.

    Args:
        query: Search query
        categories: Comma-separated categories (general, it, news, science, files)
        max_results: Number of results to return
    """
    base_url = os.environ.get('SEARXNG_URL', 'https://searx.be').rstrip('/')
    params = urllib.parse.urlencode({
        'q': query, 'format': 'json',
        'categories': categories, 'safesearch': '0',
    })
    status, body = _curl(f'{base_url}/search?{params}')
    if status == 0:
        return json.dumps({
            'status':  'network_error',
            'message': (
                f'Could not reach the SearXNG instance at {base_url}. '
                'If you are using the default public instance, it may be temporarily unavailable. '
                'Set SEARXNG_URL in your .env file to point to a working SearXNG instance.'
            ),
            'results': [],
        }, indent=2)
    if status != 200:
        return json.dumps({
            'status': 'api_error',
            'message': api_error_msg(f'SearXNG at {base_url}', status,
                'Try setting SEARXNG_URL in your .env file to point to a different SearXNG instance.'),
            'results': [],
        }, indent=2)
    try:
        data = json.loads(body)
        results = data.get('results', [])[:max_results]
        return json.dumps({
            'source':  f'SearXNG ({base_url})',
            'query':   query,
            'results': [
                {
                    'title':   _clean(r.get('title', '')),
                    'url':     r.get('url', ''),
                    'summary': _clean(r.get('content', '')),
                }
                for r in results
            ],
        }, indent=2)
    except Exception as e:
        return json.dumps({
            'status':  'parse_error',
            'message': f'The SearXNG response could not be parsed. Technical detail: {e}',
            'results': [],
        }, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# TRAVERSAAL
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def search_traversaal(query: str) -> str:
    """
    Search using Traversaal AI search API (security-focused).
    Requires TRAVERSAAL_API_KEY environment variable.

    Args:
        query: Security research query or CVE lookup
    """
    key = os.environ.get('TRAVERSAAL_API_KEY', '').strip()
    if not key:
        return json.dumps({
            'status': 'not_configured',
            'message': api_missing_key_msg('TRAVERSAAL_API_KEY', 'Traversaal'),
            'answer': '',
        }, indent=2)

    payload = json.dumps({'queries': [query]})
    status, body = _curl('https://api-ares.traversaal.ai/live/predict', method='POST', data=payload,
                         headers=['Content-Type: application/json', f'x-api-key: {key}'])
    if status == 0:
        return json.dumps({'status': 'network_error', 'message': network_error_msg('Traversaal'), 'answer': ''}, indent=2)
    if status != 200:
        return json.dumps({
            'status': 'api_error',
            'message': api_error_msg('Traversaal', status),
            'answer': '',
        }, indent=2)
    try:
        data = json.loads(body)
        response_text = _clean(data.get('data', {}).get('response_text', '') or str(data))
        return json.dumps({
            'source':       'Traversaal AI Search',
            'query':        query,
            'answer':       response_text,
            'references':   data.get('data', {}).get('web_url', []),
        }, indent=2)
    except Exception as e:
        return json.dumps({
            'status':  'parse_error',
            'message': f'The Traversaal response could not be parsed. Technical detail: {e}',
            'answer': '',
        }, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# GREYNOISE (threat intelligence — no key for community)
# ──────────────────────────────────────────────────────────────────────────────

@function_tool
def search_greynoise(ip_or_query: str) -> str:
    """
    Query GreyNoise for IP reputation and internet noise classification.
    Community API (no key) or full API with GREYNOISE_API_KEY.

    Args:
        ip_or_query: IP address to look up or search query (e.g. "192.0.2.1", "log4j scanner")
    """
    key = os.environ.get('GREYNOISE_API_KEY', '').strip()
    hdrs = ['Content-Type: application/json']
    if key:
        hdrs.append(f'key: {key}')

    ip_re = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_re.match(ip_or_query.strip()):
        url = f'https://api.greynoise.io/v3/community/{ip_or_query.strip()}'
        status, body = _curl(url, headers=hdrs)
    else:
        payload = json.dumps({'query': ip_or_query, 'size': 10})
        url = 'https://api.greynoise.io/v2/experimental/gnql'
        status, body = _curl(url, method='POST', data=payload, headers=hdrs)

    if status == 0:
        return json.dumps({
            'status':  'network_error',
            'message': network_error_msg('GreyNoise', url),
        }, indent=2)
    if status == 429:
        return json.dumps({
            'status':  'rate_limited',
            'message': (
                'GreyNoise has temporarily rate-limited this request because too many queries '
                'were sent in a short period. Wait a few minutes before trying again. '
                'For higher rate limits, add a GREYNOISE_API_KEY to your .env file.'
            ),
        }, indent=2)
    if status == 404:
        return json.dumps({
            'status':  'not_found',
            'message': f'The IP address or query "{ip_or_query}" was not found in the GreyNoise database. '
                       'This IP has not been observed scanning the internet.',
            'ip': ip_or_query,
        }, indent=2)
    try:
        data = json.loads(body)
        return json.dumps({'source': 'GreyNoise Threat Intelligence', 'query': ip_or_query, 'data': data}, indent=2)
    except Exception as e:
        return json.dumps({
            'status':  'parse_error',
            'message': f'The GreyNoise response could not be parsed. Technical detail: {e}',
        }, indent=2)
