"""
CF_AI — Web Intelligence: browser-based scraping and page analysis.
Provides screenshot-free web fetching with JavaScript rendering fallback,
form detection, link extraction, and content analysis for security research.
"""
from __future__ import annotations
import json
import re
import subprocess
import urllib.parse
from sdk.agents import function_tool
from tools._http_explain import http_label, network_error_msg

_UA  = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
_TO  = 20
_JAX = '-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Accept-Language: en-US,en;q=0.9"'


def _fetch(url: str, follow: bool = True, timeout: int = _TO,
           extra_headers: list[str] | None = None,
           post_data: str | None = None) -> tuple[int, dict, str]:
    """Fetch URL with curl. Returns (status, headers_dict, body)."""
    flags = ['-s', '-4', '--connect-timeout', '8', '--max-time', str(timeout),
             '-D', '-', '-A', _UA,
             '-H', 'Accept: text/html,application/xhtml+xml,*/*;q=0.8',
             '-H', 'Accept-Language: en-US,en;q=0.9',
             '-H', 'Referer: https://www.google.com/',
             '-c', '/tmp/cf_scraper_cookies.txt',
             '-b', '/tmp/cf_scraper_cookies.txt']
    if follow:
        flags.append('-L')
    if post_data is not None:
        flags += ['-X', 'POST', '--data', post_data]
    for h in (extra_headers or []):
        flags += ['-H', h]
    flags.append(url)
    try:
        r = subprocess.run(['curl'] + flags, capture_output=True, text=True, timeout=timeout + 5)
        raw = r.stdout
    except Exception:
        return 0, {}, ''

    parts   = raw.split('\r\n\r\n', 1)
    hdr_raw = parts[0] if parts else ''
    body    = parts[1] if len(parts) > 1 else ''

    status = 0
    for line in hdr_raw.splitlines():
        m = re.match(r'HTTP/[\d.]+ (\d{3})', line)
        if m:
            status = int(m.group(1))

    headers: dict[str, str] = {}
    for line in hdr_raw.splitlines()[1:]:
        if ':' in line:
            k, _, v = line.partition(':')
            headers[k.strip().lower()] = v.strip()

    return status, headers, body


def _strip_tags(html: str) -> str:
    """Remove HTML tags and collapse whitespace."""
    text = re.sub(r'<style[^>]*>.*?</style>', ' ', html, flags=re.S | re.I)
    text = re.sub(r'<script[^>]*>.*?</script>', ' ', text, flags=re.S | re.I)
    text = re.sub(r'<!--.*?-->', ' ', text, flags=re.S)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'&nbsp;', ' ', text)
    text = re.sub(r'&[a-z]+;', '', text, flags=re.I)
    return re.sub(r'\s+', ' ', text).strip()


@function_tool
def scrape_page(url: str, extract: str = 'all') -> str:
    """
    Fetch and analyse a web page for security research.
    Extracts: page title, meta tags, all links, forms, scripts, hidden fields,
    comments, technology hints, and readable text content.

    Args:
        url: Target URL to scrape
        extract: What to extract — 'all', 'links', 'forms', 'text', 'scripts', 'meta'

    Returns JSON with structured page analysis.
    """
    if not url.startswith('http'):
        url = 'https://' + url

    status, headers, body = _fetch(url)

    # Cloudflare bypass fallback
    if status in (403, 503, 0) or len(body) < 200:
        _, _, body2 = _fetch(url, extra_headers=[
            'User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)',
            'X-Forwarded-For: 66.249.66.1',
        ])
        if len(body2) > len(body):
            body = body2

    result: dict = {'url': url, 'status': http_label(status), 'content_type': headers.get('content-type', '')}

    if extract in ('all', 'meta'):
        # Title
        title_m = re.search(r'<title[^>]*>([^<]*)</title>', body, re.I)
        result['title'] = title_m.group(1).strip() if title_m else ''

        # Meta tags
        metas: list[dict] = []
        for m in re.finditer(r'<meta\s([^>]+)>', body, re.I | re.S):
            attrs = dict(re.findall(r'(\w+)=["\']([^"\']*)["\']', m.group(1)))
            if attrs:
                metas.append(attrs)
        result['meta'] = metas[:30]

        # Server / tech headers
        result['server']       = headers.get('server', '')
        result['x_powered_by'] = headers.get('x-powered-by', '')
        result['x_generator']  = headers.get('x-generator', '')

        # Generator meta
        gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.I)
        if gen:
            result['generator'] = gen.group(1)

    if extract in ('all', 'links'):
        # All href links
        hrefs = re.findall(r'href=["\']([^"\'#][^"\']*)["\']', body, re.I)
        links = []
        for h in hrefs:
            try:
                full = urllib.parse.urljoin(url, h)
                links.append(full)
            except Exception:
                pass
        result['links'] = sorted(set(links))[:100]

        # API / JS routes
        api_routes = re.findall(r'["\'](/api/[a-zA-Z0-9/_\-\.]+)["\']', body)
        result['api_routes'] = sorted(set(api_routes))[:50]

    if extract in ('all', 'forms'):
        # Forms — extract action, method, input names
        forms: list[dict] = []
        for form_m in re.finditer(r'<form([^>]*)>(.*?)</form>', body, re.S | re.I):
            form_attrs = form_m.group(1)
            form_body  = form_m.group(2)
            action = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.I)
            method = re.search(r'method=["\']([^"\']*)["\']', form_attrs, re.I)
            inputs = re.findall(r'<input[^>]+>', form_body, re.I)
            fields = []
            for inp in inputs:
                name  = re.search(r'name=["\']([^"\']+)["\']', inp, re.I)
                itype = re.search(r'type=["\']([^"\']+)["\']', inp, re.I)
                val   = re.search(r'value=["\']([^"\']*)["\']', inp, re.I)
                if name:
                    fields.append({
                        'name': name.group(1),
                        'type': itype.group(1) if itype else 'text',
                        'value': val.group(1) if val else '',
                    })
            forms.append({
                'action': action.group(1) if action else '',
                'method': (method.group(1) if method else 'GET').upper(),
                'fields': fields,
            })
        result['forms'] = forms[:20]

        # Hidden fields (security relevant)
        hidden = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', body, re.I)
        result['hidden_fields'] = [
            {'name': (re.search(r'name=["\']([^"\']*)["\']', h, re.I) or type('', (), {'group': lambda x,_: ''})()).group(1),
             'value': (re.search(r'value=["\']([^"\']*)["\']', h, re.I) or type('', (), {'group': lambda x,_: ''})()).group(1)}
            for h in hidden[:20]
        ]

    if extract in ('all', 'scripts'):
        # Inline scripts (first 500 chars each)
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.S | re.I)
        result['inline_scripts'] = [s.strip()[:500] for s in scripts[:10] if s.strip()]

        # External script sources
        ext_scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.I)
        result['script_sources'] = ext_scripts[:30]

        # Potential secrets in page source
        secret_patterns = [
            (r'(?i)(api[_-]?key|apikey)["\s:=]+["\']([A-Za-z0-9_\-]{16,})["\']',    'api_key'),
            (r'(?i)(secret[_-]?key|secretkey)["\s:=]+["\']([A-Za-z0-9_\-]{20,})["\']', 'secret_key'),
            (r'(?i)(token)["\s:=]+["\']([A-Za-z0-9_\-\.]{20,})["\']',                'token'),
            (r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',               'jwt'),
            (r'(?i)(password|passwd)["\s:=]+["\']([^"\']{6,})["\']',                  'password'),
            (r'AKIA[0-9A-Z]{16}',                                                      'aws_key'),
        ]
        found_secrets = []
        for pattern, label in secret_patterns:
            for m in re.finditer(pattern, body):
                found_secrets.append({'type': label, 'match': m.group(0)[:80]})
        result['potential_secrets'] = found_secrets[:20]

    if extract in ('all', 'text'):
        result['text_content'] = _strip_tags(body)[:3000]

    # HTML comments (often contain dev notes / paths / credentials)
    comments = re.findall(r'<!--(.*?)-->', body, re.S)
    result['html_comments'] = [c.strip()[:200] for c in comments if c.strip() and len(c.strip()) > 5][:20]

    result['body_length'] = len(body)
    return json.dumps(result, indent=2)


@function_tool
def crawl_site(base_url: str, max_pages: int = 15, stay_on_domain: bool = True) -> str:
    """
    Crawl a website and map its structure: pages, endpoints, forms, technologies.
    Useful for attack surface mapping before penetration testing.

    Args:
        base_url: Starting URL (e.g. https://example.com)
        max_pages: Maximum pages to crawl (default 15, max 50)
        stay_on_domain: Only follow links on the same domain (default True)

    Returns JSON with site map, discovered endpoints, forms, and tech stack.
    """
    if not base_url.startswith('http'):
        base_url = 'https://' + base_url

    parsed  = urllib.parse.urlparse(base_url)
    domain  = parsed.netloc
    visited: set[str] = set()
    queue   = [base_url]
    pages: list[dict] = []
    all_forms: list[dict] = []
    all_endpoints: set[str] = set()
    tech_hints: set[str] = set()
    max_pages = min(max_pages, 50)

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        status, headers, body = _fetch(url, timeout=12)
        if status == 0 or not body:
            continue

        ct = headers.get('content-type', '')
        if 'text/html' not in ct and 'application/xhtml' not in ct:
            continue

        # Detect technology
        server = headers.get('server', '').lower()
        powered = headers.get('x-powered-by', '').lower()
        for tech_sig, tech_name in [
            ('wordpress', 'WordPress'), ('wp-content', 'WordPress'),
            ('drupal', 'Drupal'), ('joomla', 'Joomla'),
            ('django', 'Django'), ('rails', 'Ruby on Rails'),
            ('express', 'Express'), ('laravel', 'Laravel'),
            ('php', 'PHP'), ('asp.net', 'ASP.NET'), ('nginx', 'nginx'),
            ('apache', 'Apache'), ('iis', 'IIS'), ('cloudflare', 'Cloudflare'),
        ]:
            if tech_sig in (server + powered + body.lower()[:2000]):
                tech_hints.add(tech_name)

        # Extract links
        hrefs = re.findall(r'href=["\']([^"\'#][^"\']*)["\']', body, re.I)
        for h in hrefs:
            try:
                full = urllib.parse.urljoin(url, h)
                fp   = urllib.parse.urlparse(full)
                if stay_on_domain and fp.netloc != domain:
                    continue
                if full not in visited and full not in queue:
                    # Skip assets
                    if not re.search(r'\.(css|js|png|jpg|gif|ico|svg|woff|ttf|pdf|zip)(\?|$)', full, re.I):
                        queue.append(full)
                # Track endpoints
                if fp.path and fp.path != '/':
                    all_endpoints.add(fp.path)
            except Exception:
                pass

        # API routes
        api_routes = re.findall(r'["\'](/api/[a-zA-Z0-9/_\-\.]+)["\']', body)
        for ar in api_routes:
            all_endpoints.add(ar)

        # Forms
        for form_m in re.finditer(r'<form([^>]*)>', body, re.I):
            action = re.search(r'action=["\']([^"\']*)["\']', form_m.group(1), re.I)
            method = re.search(r'method=["\']([^"\']*)["\']', form_m.group(1), re.I)
            all_forms.append({
                'page': url,
                'action': action.group(1) if action else '',
                'method': (method.group(1) if method else 'GET').upper(),
            })

        title_m = re.search(r'<title[^>]*>([^<]*)</title>', body, re.I)
        pages.append({
            'url':    url,
            'status': status,
            'title':  title_m.group(1).strip() if title_m else '',
            'size':   len(body),
        })

    return json.dumps({
        'base_url':         base_url,
        'pages_crawled':    len(pages),
        'pages':            pages,
        'endpoints':        sorted(all_endpoints)[:100],
        'forms_found':      all_forms[:30],
        'technologies':     sorted(tech_hints),
    }, indent=2)


@function_tool
def fetch_robots_and_sitemap(target: str) -> str:
    """
    Fetch and parse robots.txt and sitemap.xml for a target website.
    Reveals hidden paths, admin URLs, and site structure without active scanning.

    Args:
        target: Domain or URL (e.g. example.com or https://example.com)
    """
    if not target.startswith('http'):
        target = 'https://' + target
    base = target.rstrip('/')
    result: dict = {'target': base, 'robots': {}, 'sitemaps': []}

    # robots.txt
    st, _, body = _fetch(base + '/robots.txt')
    if st == 200 and body:
        disallowed = re.findall(r'(?i)Disallow:\s*(/[^\s]*)', body)
        allowed    = re.findall(r'(?i)Allow:\s*(/[^\s]*)', body)
        sitemaps   = re.findall(r'(?i)Sitemap:\s*(https?://[^\s]+)', body)
        result['robots'] = {
            'status':    st,
            'disallowed': disallowed[:50],
            'allowed':    allowed[:30],
            'sitemap_urls': sitemaps,
            'interesting': [p for p in disallowed if any(k in p.lower() for k in
                ['admin','backup','config','secret','private','internal','api','hidden','.git','wp-admin'])],
        }
        result['sitemaps'] = sitemaps

    # sitemap.xml
    for sitemap_url in ([base + '/sitemap.xml', base + '/sitemap_index.xml'] + result['sitemaps'])[:4]:
        st2, _, body2 = _fetch(sitemap_url, timeout=15)
        if st2 == 200 and body2:
            urls = re.findall(r'<loc>(https?://[^<]+)</loc>', body2)
            result.setdefault('sitemap_pages', []).extend(urls[:50])

    if result.get('sitemap_pages'):
        result['sitemap_pages'] = sorted(set(result['sitemap_pages']))[:100]

    return json.dumps(result, indent=2)
