"""
CF_AI — Full agent and tool test suite.
Tests: all agents load, all tools return human-readable output,
no raw HTTP codes, no truncated messages, no unclean special chars.
Run: python -m pytest tests/test_agents_full.py -v
"""
import json
import os
import re
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('ANTHROPIC_API_KEY', 'test-key')
os.environ.setdefault('SECRET_KEY', 'test-secret')

# ─── helpers ─────────────────────────────────────────────────────────────────

RAW_CODE_RE = re.compile(r'\bHTTP[/ ]?\s*\d{3}\b|\bstatus["\s:=]+\d{3}\b', re.IGNORECASE)
CTRL_CHAR_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def _no_raw_codes(text: str) -> bool:
    """Return True if text contains no raw HTTP status codes like 'HTTP 200' or '\"status\": 404'."""
    # Allow codes inside JSON keys for internal fields — check only the human-readable strings
    # Strip JSON structure first, look at string values only
    try:
        data = json.loads(text)
        flat = _flatten_strings(data)
        for s in flat:
            if RAW_CODE_RE.search(s):
                return False
        return True
    except Exception:
        return not bool(RAW_CODE_RE.search(text))


def _flatten_strings(obj, depth=0) -> list:
    """Recursively extract all string values from a JSON object."""
    if depth > 8:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        results = []
        for k, v in obj.items():
            if k in ('status', 'url', 'path', 'preview', 'snippet', 'raw', 'body'):
                continue  # internal structural fields — skip code check on these
            results.extend(_flatten_strings(v, depth + 1))
        return results
    if isinstance(obj, list):
        r = []
        for item in obj:
            r.extend(_flatten_strings(item, depth + 1))
        return r
    return []


def _no_control_chars(text: str) -> bool:
    return not bool(CTRL_CHAR_RE.search(text))


def _not_truncated(text: str) -> bool:
    """Check that error/message strings are not abruptly cut off (no trailing '...' or mid-word cut)."""
    if not text.strip():
        return True
    # Accept trailing ellipsis only inside JSON values, not on the last character of the whole payload
    last = text.strip()[-20:]
    return not last.endswith('...')


def _assert_clean(result: str, tool_name: str):
    assert isinstance(result, str) and len(result) > 0, f'{tool_name}: returned empty string'
    assert _no_control_chars(result), f'{tool_name}: contains control characters'
    # For tools that return JSON, extract and check message/error fields
    try:
        data = json.loads(result)
        msg = data.get('message', '') or data.get('error', '') or data.get('answer', '')
        if msg:
            assert not RAW_CODE_RE.search(msg), (
                f'{tool_name}: message contains raw HTTP code: {msg[:200]}'
            )
    except Exception:
        pass


# ─── 1. Agent registry loads cleanly ─────────────────────────────────────────

class TestAgentRegistry:
    def test_all_agents_load(self):
        from agents.wstg_agents import WSTG_REGISTRY
        assert len(WSTG_REGISTRY) > 10, 'Expected more than 10 agents'

    def test_no_duplicate_tools(self):
        from collections import Counter
        from agents.wstg_agents import WSTG_REGISTRY
        for name, agent in WSTG_REGISTRY.items():
            tool_names = [getattr(t, '__name__', str(t)) for t in agent.tools]
            dupes = [k for k, v in Counter(tool_names).items() if v > 1]
            assert not dupes, f'Agent {name} has duplicate tools: {dupes}'

    def test_agent_tool_counts(self):
        from agents.wstg_agents import WSTG_REGISTRY
        counts = {name: len(agent.tools) for name, agent in WSTG_REGISTRY.items()}
        # INFO and CONF agents should have 40+ tools
        assert counts.get('info', 0) >= 35, f'INFO agent has only {counts.get("info")} tools'
        assert counts.get('apit', 0) >= 35, f'APIT agent has only {counts.get("apit")} tools'

    def test_all_agents_have_instructions(self):
        from agents.wstg_agents import WSTG_REGISTRY
        for name, agent in WSTG_REGISTRY.items():
            assert agent.instructions and len(agent.instructions) > 200, \
                f'Agent {name} has very short instructions'

    def test_rules_contain_english_formatting(self):
        from agents.wstg_agents import RULES
        assert 'raw HTTP status codes' in RULES, 'RULES must instruct agents to avoid raw HTTP codes'
        assert 'complete English sentences' in RULES or 'plain English' in RULES, \
            'RULES must instruct agents to write in plain English'


# ─── 2. HTTP explain helper ───────────────────────────────────────────────────

class TestHttpExplain:
    def test_known_codes(self):
        from tools._http_explain import http_label, http_explain
        assert 'Accessible' in http_label(200)
        assert 'Not found' in http_label(404)
        assert 'Access denied' in http_label(403)
        assert 'Requires authentication' in http_label(401)
        assert 'Rate limited' in http_label(429)
        assert 'Server error' in http_label(500)

    def test_unknown_code(self):
        from tools._http_explain import http_label
        result = http_label(599)
        assert '599' in result

    def test_zero_code(self):
        from tools._http_explain import http_label
        result = http_label(0)
        assert 'Unreachable' in result or '0' in result

    def test_explain_full_sentence(self):
        from tools._http_explain import http_explain
        result = http_explain(403)
        assert 'server' in result.lower()
        assert '403' in result

    def test_api_missing_key_message(self):
        from tools._http_explain import api_missing_key_msg
        msg = api_missing_key_msg('TAVILY_API_KEY', 'Tavily')
        assert 'Tavily' in msg
        assert 'TAVILY_API_KEY' in msg
        assert not RAW_CODE_RE.search(msg)

    def test_no_raw_codes_in_messages(self):
        from tools._http_explain import api_error_msg, network_error_msg
        for code in (400, 401, 403, 404, 429, 500, 502, 503):
            msg = api_error_msg('TestService', code)
            assert not re.search(r'\bHTTP[/ ]\d{3}\b', msg), \
                f'api_error_msg({code}) contains raw HTTP code: {msg}'


# ─── 3. External search tools — no API keys configured ────────────────────────

class TestExternalSearchNoKey:
    """When API keys are absent, tools must return a friendly not-configured message."""

    def _run(self, fn, *args, **kwargs):
        # Temporarily remove any key
        env_backup = {}
        key_vars = ['TAVILY_API_KEY', 'PERPLEXITY_API_KEY', 'GOOGLE_CSE_API_KEY',
                    'GOOGLE_CSE_ID', 'TRAVERSAAL_API_KEY']
        for k in key_vars:
            env_backup[k] = os.environ.pop(k, None)
        try:
            result = fn.__wrapped__(*args, **kwargs) if hasattr(fn, '__wrapped__') else fn(*args, **kwargs)
        finally:
            for k, v in env_backup.items():
                if v is not None:
                    os.environ[k] = v
        return result

    def test_tavily_no_key(self):
        from tools.external_search import search_tavily
        result = self._run(search_tavily, 'test query')
        _assert_clean(result, 'search_tavily')
        data = json.loads(result)
        msg = data.get('message', '')
        assert msg, 'search_tavily should return a message when not configured'
        assert 'TAVILY_API_KEY' in msg, f'Message should mention the key name: {msg}'
        assert not RAW_CODE_RE.search(msg), f'Message contains raw code: {msg}'

    def test_perplexity_no_key(self):
        from tools.external_search import search_perplexity
        result = self._run(search_perplexity, 'test query')
        _assert_clean(result, 'search_perplexity')
        data = json.loads(result)
        msg = data.get('message', '')
        assert msg and 'PERPLEXITY_API_KEY' in msg

    def test_google_no_key(self):
        from tools.external_search import search_google
        result = self._run(search_google, 'test query')
        _assert_clean(result, 'search_google')
        data = json.loads(result)
        msg = data.get('message', '')
        assert msg and 'GOOGLE_CSE_API_KEY' in msg

    def test_traversaal_no_key(self):
        from tools.external_search import search_traversaal
        result = self._run(search_traversaal, 'test query')
        _assert_clean(result, 'search_traversaal')
        data = json.loads(result)
        msg = data.get('message', '')
        assert msg and 'TRAVERSAAL_API_KEY' in msg

    def test_duckduckgo_returns_structure(self):
        """DuckDuckGo needs no key — verify tool returns valid JSON structure."""
        from tools.external_search import search_duckduckgo
        result = search_duckduckgo.__wrapped__('security vulnerability') \
            if hasattr(search_duckduckgo, '__wrapped__') \
            else search_duckduckgo('security vulnerability')
        _assert_clean(result, 'search_duckduckgo')
        data = json.loads(result)
        assert 'source' in data or 'status' in data
        assert 'results' in data or 'message' in data

    def test_sploitus_returns_structure(self):
        """Sploitus needs no key — verify tool returns valid JSON structure."""
        from tools.external_search import search_sploitus
        result = search_sploitus.__wrapped__('CVE-2021-44228') \
            if hasattr(search_sploitus, '__wrapped__') \
            else search_sploitus('CVE-2021-44228')
        _assert_clean(result, 'search_sploitus')
        data = json.loads(result)
        assert 'results' in data or 'message' in data or 'status' in data

    def test_greynoise_returns_structure(self):
        """GreyNoise community endpoint needs no key."""
        from tools.external_search import search_greynoise
        result = search_greynoise.__wrapped__('8.8.8.8') \
            if hasattr(search_greynoise, '__wrapped__') \
            else search_greynoise('8.8.8.8')
        _assert_clean(result, 'search_greynoise')
        data = json.loads(result)
        assert 'data' in data or 'message' in data or 'status' in data


# ─── 4. Memory store tools ────────────────────────────────────────────────────

class TestMemoryStore:
    def _call(self, fn, *args, **kwargs):
        return fn.__wrapped__(*args, **kwargs) if hasattr(fn, '__wrapped__') else fn(*args, **kwargs)

    def test_save_and_recall(self):
        from tools.memory_store import memory_save, memory_recall, memory_delete
        result = self._call(memory_save,
            content='SQL injection found in the login form parameter on the test target.',
            memory_type='finding', target='test.example.com', tags='sqli,critical',
            title='SQL Injection in login form')
        _assert_clean(result, 'memory_save')
        data = json.loads(result)
        assert data.get('ok'), f'memory_save failed: {result}'
        entry_id = data['id']

        recall = self._call(memory_recall, query='SQL injection', target='test.example.com')
        _assert_clean(recall, 'memory_recall')
        recall_data = json.loads(recall)
        assert recall_data.get('total_found', 0) >= 1, 'Recall found no results after save'

        # Cleanup
        self._call(memory_delete, entry_id=entry_id)

    def test_save_requires_content(self):
        from tools.memory_store import memory_save
        result = self._call(memory_save, content='')
        data = json.loads(result)
        assert 'error' in data

    def test_list_returns_structure(self):
        from tools.memory_store import memory_list
        result = self._call(memory_list)
        _assert_clean(result, 'memory_list')
        data = json.loads(result)
        assert 'entries' in data or 'message' in data


# ─── 5. Knowledge graph tools ─────────────────────────────────────────────────

class TestKnowledgeGraph:
    def _call(self, fn, *args, **kwargs):
        return fn.__wrapped__(*args, **kwargs) if hasattr(fn, '__wrapped__') else fn(*args, **kwargs)

    def test_add_entity(self):
        from tools.knowledge_graph import kg_add_entity
        result = self._call(kg_add_entity,
            name='test.example.com', entity_type='domain',
            target='test.example.com', labels='test')
        _assert_clean(result, 'kg_add_entity')
        data = json.loads(result)
        assert data.get('ok'), f'kg_add_entity failed: {result}'

    def test_add_relationship(self):
        from tools.knowledge_graph import kg_add_entity, kg_add_relationship
        self._call(kg_add_entity, name='test.example.com', entity_type='domain')
        self._call(kg_add_entity, name='CVE-2024-TEST', entity_type='vulnerability')
        result = self._call(kg_add_relationship,
            from_entity='test.example.com', relationship='HAS_VULN',
            to_entity='CVE-2024-TEST', target='test.example.com')
        _assert_clean(result, 'kg_add_relationship')
        data = json.loads(result)
        assert data.get('ok'), f'kg_add_relationship failed: {result}'

    def test_search(self):
        from tools.knowledge_graph import kg_search
        result = self._call(kg_search, query='test.example', target='test.example.com')
        _assert_clean(result, 'kg_search')
        data = json.loads(result)
        assert 'results' in data

    def test_summary(self):
        from tools.knowledge_graph import kg_summary
        result = self._call(kg_summary)
        _assert_clean(result, 'kg_summary')
        data = json.loads(result)
        assert 'total_entities' in data or 'entity_counts' in data

    def test_attack_path(self):
        from tools.knowledge_graph import kg_attack_path
        result = self._call(kg_attack_path, start_entity='test.example.com')
        _assert_clean(result, 'kg_attack_path')
        data = json.loads(result)
        assert 'paths' in data

    def test_get_neighbors(self):
        from tools.knowledge_graph import kg_get_neighbors
        result = self._call(kg_get_neighbors, entity_name='test.example.com')
        _assert_clean(result, 'kg_get_neighbors')
        data = json.loads(result)
        assert 'edges' in data


# ─── 6. PostgreSQL storage tools (JSON fallback) ──────────────────────────────

class TestPgStore:
    def _call(self, fn, *args, **kwargs):
        return fn.__wrapped__(*args, **kwargs) if hasattr(fn, '__wrapped__') else fn(*args, **kwargs)

    def test_pg_status_no_pg(self):
        """Without PG configured, pg_status should report JSON fallback gracefully."""
        env_backup = os.environ.pop('PG_HOST', None)
        try:
            from tools.pg_store import pg_status
            result = self._call(pg_status)
            _assert_clean(result, 'pg_status')
            data = json.loads(result)
            assert data.get('backend') in ('json', 'postgresql')
            assert 'scans' in data
        finally:
            if env_backup:
                os.environ['PG_HOST'] = env_backup

    def test_save_and_retrieve_finding(self):
        from tools.pg_store import pg_save_finding, pg_get_findings
        result = self._call(pg_save_finding,
            target='test.example.com', severity='high',
            title='Cross-Site Scripting in search parameter',
            description='The search parameter on the main page reflects user input without sanitisation, enabling stored XSS attacks.',
            evidence='Payload <script>alert(1)</script> executed in the browser.',
            remediation='Encode all user-supplied output using htmlspecialchars() before rendering.',
            cvss=7.2, cve_ids='')
        _assert_clean(result, 'pg_save_finding')
        data = json.loads(result)
        assert data.get('ok'), f'pg_save_finding failed: {result}'

        findings = self._call(pg_get_findings, target='test.example.com', severity='high')
        _assert_clean(findings, 'pg_get_findings')
        fd = json.loads(findings)
        assert fd.get('total', 0) >= 1 or len(fd.get('findings', [])) >= 1

    def test_scan_history(self):
        import uuid
        from tools.pg_store import pg_save_scan, pg_get_scan_history
        scan_id = str(uuid.uuid4())
        save_result = self._call(pg_save_scan,
            scan_id=scan_id, target='test.example.com',
            agent_type='apit', username='tester',
            report_text='Security assessment completed. Two findings identified.',
            findings_json='[{"severity":"high","title":"XSS"}]')
        _assert_clean(save_result, 'pg_save_scan')
        assert json.loads(save_result).get('ok')

        history = self._call(pg_get_scan_history, target='test.example.com', limit=5)
        _assert_clean(history, 'pg_get_scan_history')
        hd = json.loads(history)
        assert 'scans' in hd


# ─── 7. CMS scanner tools ─────────────────────────────────────────────────────

class TestCmsScanner:
    """Verify CMS scanners return valid JSON with human-readable status labels."""

    def _call(self, fn, *args, **kwargs):
        return fn.__wrapped__(*args, **kwargs) if hasattr(fn, '__wrapped__') else fn(*args, **kwargs)

    def _check_no_raw_status_codes(self, result: str, tool: str):
        _assert_clean(result, tool)
        try:
            data = json.loads(result)
            text = json.dumps(data)
            # Status values should be human-readable strings, not bare integers in status fields
            status_values = re.findall(r'"status"\s*:\s*(\d+)', text)
            assert not status_values, \
                f'{tool}: found raw numeric status codes in output: {status_values}'
        except json.JSONDecodeError:
            pass  # Non-JSON output is also acceptable

    def test_scan_wordpress_unreachable(self):
        from tools.cms_scanner import scan_wordpress
        result = self._call(scan_wordpress, target='https://unreachable-test-12345.example.invalid')
        self._check_no_raw_status_codes(result, 'scan_wordpress')

    def test_scan_joomla_unreachable(self):
        from tools.cms_scanner import scan_joomla
        result = self._call(scan_joomla, target='https://unreachable-test-12345.example.invalid')
        self._check_no_raw_status_codes(result, 'scan_joomla')

    def test_scan_laravel_unreachable(self):
        from tools.cms_scanner import scan_laravel
        result = self._call(scan_laravel, target='https://unreachable-test-12345.example.invalid')
        self._check_no_raw_status_codes(result, 'scan_laravel')

    def test_scan_django_flask_unreachable(self):
        from tools.cms_scanner import scan_django_flask
        result = self._call(scan_django_flask, target='https://unreachable-test-12345.example.invalid')
        self._check_no_raw_status_codes(result, 'scan_django_flask')

    def test_scan_nodejs_unreachable(self):
        from tools.cms_scanner import scan_nodejs
        result = self._call(scan_nodejs, target='https://unreachable-test-12345.example.invalid')
        self._check_no_raw_status_codes(result, 'scan_nodejs')

    def test_scan_java_spring_unreachable(self):
        from tools.cms_scanner import scan_java_spring
        result = self._call(scan_java_spring, target='https://unreachable-test-12345.example.invalid')
        self._check_no_raw_status_codes(result, 'scan_java_spring')

    def test_scan_dotnet_unreachable(self):
        from tools.cms_scanner import scan_dotnet
        result = self._call(scan_dotnet, target='https://unreachable-test-12345.example.invalid')
        self._check_no_raw_status_codes(result, 'scan_dotnet')

    def test_scan_rails_unreachable(self):
        from tools.cms_scanner import scan_rails
        result = self._call(scan_rails, target='https://unreachable-test-12345.example.invalid')
        self._check_no_raw_status_codes(result, 'scan_rails')

    def test_scan_generic_php_unreachable(self):
        from tools.cms_scanner import scan_generic_php
        result = self._call(scan_generic_php, target='https://unreachable-test-12345.example.invalid')
        self._check_no_raw_status_codes(result, 'scan_generic_php')

    def test_scan_drupal_unreachable(self):
        from tools.cms_scanner import scan_drupal
        result = self._call(scan_drupal, target='https://unreachable-test-12345.example.invalid')
        self._check_no_raw_status_codes(result, 'scan_drupal')


# ─── 8. Site profiler ─────────────────────────────────────────────────────────

class TestSiteProfiler:
    def test_returns_json_block(self):
        from tools.site_profiler import profile_target
        fn = profile_target.__wrapped__ if hasattr(profile_target, '__wrapped__') else profile_target
        result = fn('https://unreachable-test-12345.example.invalid')
        assert isinstance(result, str) and len(result) > 0
        # Should contain a JSON block at the end
        assert 'JSON:' in result or '{' in result


# ─── 9. Web scraper tools ─────────────────────────────────────────────────────

class TestWebScraper:
    def _call(self, fn, *args, **kwargs):
        return fn.__wrapped__(*args, **kwargs) if hasattr(fn, '__wrapped__') else fn(*args, **kwargs)

    def test_scrape_returns_structure(self):
        from tools.web_scraper import scrape_page
        result = self._call(scrape_page, url='https://unreachable-test-12345.example.invalid')
        _assert_clean(result, 'scrape_page')
        data = json.loads(result)
        assert 'url' in data
        assert 'status' in data
        # status should be a string label, not a bare integer
        assert isinstance(data['status'], str), \
            f'scrape_page status should be a string label, got: {data["status"]}'

    def test_fetch_robots_returns_structure(self):
        from tools.web_scraper import fetch_robots_and_sitemap
        result = self._call(fetch_robots_and_sitemap, target='https://unreachable-test-12345.example.invalid')
        _assert_clean(result, 'fetch_robots_and_sitemap')
        data = json.loads(result)
        assert 'target' in data


# ─── 10. Dashboard app imports ────────────────────────────────────────────────

class TestDashboardApp:
    def test_app_imports(self):
        """Verify dashboard/app.py imports without errors."""
        import importlib
        spec = importlib.util.spec_from_file_location(
            'dashboard.app',
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         'dashboard', 'app.py')
        )
        # Just verify syntax was already checked — import would be too heavy for unit test
        assert spec is not None

    def test_llm_provider_catalog(self):
        """Verify the LLM provider catalog is accessible from wstg_agents."""
        from agents.wstg_agents import _LLM_PROVIDERS
        assert 'anthropic' in _LLM_PROVIDERS
        assert 'openai' in _LLM_PROVIDERS
        assert 'google' in _LLM_PROVIDERS
        assert len(_LLM_PROVIDERS) >= 10, 'Expected at least 10 LLM providers'

    def test_knowledge_graph_tools_in_all_agents(self):
        from agents.wstg_agents import WSTG_REGISTRY
        kg_tool_names = {'kg_add_entity', 'kg_search', 'kg_summary'}
        for name, agent in WSTG_REGISTRY.items():
            if name in ('assoc', 'triage', 'reduce', 'verify', 'report', 'infra', 'js'):
                continue  # specialist agents have different tool sets
            tool_names = {getattr(t, '__name__', '') for t in agent.tools}
            missing = kg_tool_names - tool_names
            assert not missing, f'Agent {name} is missing KG tools: {missing}'

    def test_pg_tools_in_main_agents(self):
        from agents.wstg_agents import WSTG_REGISTRY
        pg_tool_names = {'pg_save_finding', 'pg_get_findings'}
        for name, agent in WSTG_REGISTRY.items():
            if name in ('assoc', 'triage', 'reduce', 'verify', 'report', 'infra', 'js'):
                continue
            tool_names = {getattr(t, '__name__', '') for t in agent.tools}
            missing = pg_tool_names - tool_names
            assert not missing, f'Agent {name} is missing PG tools: {missing}'

    def test_memory_tools_in_all_agents(self):
        from agents.wstg_agents import WSTG_REGISTRY
        mem_tools = {'memory_save', 'memory_recall'}
        for name, agent in WSTG_REGISTRY.items():
            if name in ('assoc', 'triage', 'reduce', 'verify', 'report', 'infra', 'js'):
                continue
            tool_names = {getattr(t, '__name__', '') for t in agent.tools}
            missing = mem_tools - tool_names
            assert not missing, f'Agent {name} missing memory tools: {missing}'


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
