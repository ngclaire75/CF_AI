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

_TO = 15
_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'


def _curl(url: str, method: str = 'GET', data: str = '', headers: list[str] | None = None,
          timeout: int = _TO) -> tuple[int, str]:
    """Return (status_code, body). status=0 on error."""
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
        return json.dumps({'error': 'TAVILY_API_KEY not set in .env', 'results': []})

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
    if status != 200:
        return json.dumps({'error': f'Tavily HTTP {status}', 'body': body[:300]})
    try:
        data = json.loads(body)
        return json.dumps({
            'source': 'Tavily',
            'query': query,
            'answer': data.get('answer', ''),
            'results': [
                {'title': r.get('title', ''), 'url': r.get('url', ''), 'content': r.get('content', '')[:500]}
                for r in data.get('results', [])[:max_results]
            ],
        }, indent=2)
    except Exception as e:
        return json.dumps({'error': str(e), 'raw': body[:400]})


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
        return json.dumps({'error': 'PERPLEXITY_API_KEY not set in .env', 'answer': ''})

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
    if status != 200:
        return json.dumps({'error': f'Perplexity HTTP {status}', 'body': body[:300]})
    try:
        data = json.loads(body)
        answer = data.get('choices', [{}])[0].get('message', {}).get('content', '')
        citations = data.get('citations', [])
        return json.dumps({
            'source': 'Perplexity',
            'query': query,
            'answer': answer,
            'citations': citations[:10],
        }, indent=2)
    except Exception as e:
        return json.dumps({'error': str(e), 'raw': body[:400]})


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
        # Fallback: DuckDuckGo HTML search scrape
        fallback_url = f'https://html.duckduckgo.com/html/?q={encoded}'
        status2, body2 = _curl(fallback_url)
        titles = re.findall(r'class="result__title"[^>]*>.*?<a[^>]*>([^<]+)</a>', body2, re.S)
        urls   = re.findall(r'class="result__url"[^>]*>\s*([^\s<]+)', body2)
        results = [{'title': t.strip(), 'url': u.strip()} for t, u in zip(titles[:max_results], urls[:max_results])]
        return json.dumps({'source': 'DuckDuckGo (HTML)', 'query': query, 'results': results}, indent=2)
    try:
        data = json.loads(body)
        results = []
        if data.get('AbstractText'):
            results.append({'type': 'abstract', 'text': data['AbstractText'], 'url': data.get('AbstractURL', '')})
        for item in data.get('RelatedTopics', [])[:max_results]:
            if isinstance(item, dict) and item.get('Text'):
                results.append({'type': 'related', 'text': item['Text'], 'url': item.get('FirstURL', '')})
        return json.dumps({
            'source': 'DuckDuckGo',
            'query': query,
            'answer': data.get('Answer', ''),
            'results': results,
        }, indent=2)
    except Exception as e:
        return json.dumps({'error': str(e), 'raw': body[:300]})


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
        return json.dumps({'error': 'GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID not set in .env'})

    q = query
    if site_filter:
        q = f'{site_filter} {q}'
    params = urllib.parse.urlencode({'key': key, 'cx': cx, 'q': q, 'num': min(max_results, 10)})
    status, body = _curl(f'https://www.googleapis.com/customsearch/v1?{params}')
    if status != 200:
        return json.dumps({'error': f'Google CSE HTTP {status}', 'body': body[:200]})
    try:
        data = json.loads(body)
        return json.dumps({
            'source': 'Google Custom Search',
            'query': q,
            'total': data.get('searchInformation', {}).get('totalResults', '?'),
            'results': [
                {'title': i.get('title', ''), 'url': i.get('link', ''), 'snippet': i.get('snippet', '')}
                for i in data.get('items', [])[:max_results]
            ],
        }, indent=2)
    except Exception as e:
        return json.dumps({'error': str(e), 'raw': body[:300]})


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
    if status != 200 or not body:
        return json.dumps({'error': f'Sploitus HTTP {status} — may be rate-limited', 'query': query})
    try:
        data = json.loads(body)
        exploits = data.get('exploits', [])[:max_results]
        return json.dumps({
            'source': 'Sploitus',
            'query': query,
            'total': data.get('total', 0),
            'results': [
                {
                    'title':    e.get('title', ''),
                    'type':     e.get('type', ''),
                    'source':   e.get('source', ''),
                    'href':     e.get('href', ''),
                    'date':     e.get('published', ''),
                    'cvss':     e.get('cvss', ''),
                    'cve_list': e.get('cve_list', []),
                }
                for e in exploits
            ],
        }, indent=2)
    except Exception as e:
        return json.dumps({'error': str(e), 'raw': body[:300]})


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
        'q': query,
        'format': 'json',
        'categories': categories,
        'safesearch': '0',
    })
    status, body = _curl(f'{base_url}/search?{params}')
    if status != 200 or not body:
        return json.dumps({'error': f'SearXNG HTTP {status} — try setting SEARXNG_URL to a working instance'})
    try:
        data = json.loads(body)
        results = data.get('results', [])[:max_results]
        return json.dumps({
            'source': f'SearXNG ({base_url})',
            'query': query,
            'results': [
                {'title': r.get('title', ''), 'url': r.get('url', ''), 'content': r.get('content', '')[:300]}
                for r in results
            ],
        }, indent=2)
    except Exception as e:
        return json.dumps({'error': str(e), 'raw': body[:300]})


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
        return json.dumps({'error': 'TRAVERSAAL_API_KEY not set in .env'})

    payload = json.dumps({'queries': [query]})
    status, body = _curl('https://api-ares.traversaal.ai/live/predict', method='POST', data=payload,
                         headers=['Content-Type: application/json', f'x-api-key: {key}'])
    if status != 200:
        return json.dumps({'error': f'Traversaal HTTP {status}', 'body': body[:300]})
    try:
        data = json.loads(body)
        response_text = data.get('data', {}).get('response_text', '') or str(data)
        return json.dumps({
            'source': 'Traversaal',
            'query': query,
            'answer': response_text,
            'web_url': data.get('data', {}).get('web_url', []),
        }, indent=2)
    except Exception as e:
        return json.dumps({'error': str(e), 'raw': body[:300]})


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
    headers = ['Content-Type: application/json']
    if key:
        headers.append(f'key: {key}')

    # Determine if IP or text query
    ip_re = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_re.match(ip_or_query.strip()):
        url = f'https://api.greynoise.io/v3/community/{ip_or_query.strip()}'
        status, body = _curl(url, headers=headers)
    else:
        payload = json.dumps({'query': ip_or_query, 'size': 10})
        url = 'https://api.greynoise.io/v2/experimental/gnql'
        status, body = _curl(url, method='POST', data=payload, headers=headers)

    if status in (0, 429):
        return json.dumps({'error': 'GreyNoise rate-limited or unreachable', 'ip': ip_or_query})
    try:
        data = json.loads(body)
        return json.dumps({'source': 'GreyNoise', 'query': ip_or_query, 'data': data}, indent=2)
    except Exception as e:
        return json.dumps({'error': str(e), 'raw': body[:300]})
