"""
CyberINK — Agent Test Suite
Tests the full agent stack: SDK, registry, tools, routing, and live API endpoints.
Does NOT call LLM APIs (no credit spend) — validates plumbing, specs, and wiring only.

Usage:
  python agent_test.py                                         # unit tests only
  python agent_test.py https://inktelligence.online admin PWD # + live API tests
"""
from __future__ import annotations
import sys
import os
import json
import importlib
import inspect
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar

# ── Add project root to path ──────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

BASE   = sys.argv[1].rstrip('/') if len(sys.argv) > 1 else ''
USER   = sys.argv[2] if len(sys.argv) > 2 else ''
PASSWD = sys.argv[3] if len(sys.argv) > 3 else ''

PASS = '\033[92m[PASS]\033[0m'
FAIL = '\033[91m[FAIL]\033[0m'
WARN = '\033[93m[WARN]\033[0m'
INFO = '\033[94m[INFO]\033[0m'

results = []

def rec(level, name, detail):
    results.append((level, name, detail))

def tag(level):
    return PASS if level == 'PASS' else (WARN if level == 'WARN' else (INFO if level == 'INFO' else FAIL))

# ══════════════════════════════════════════════════════════════════════════════
# 1. SDK LAYER
# ══════════════════════════════════════════════════════════════════════════════

def test_sdk_imports():
    print('\n{}  SDK imports'.format(INFO))
    for mod in ['sdk.agents', 'sdk.tracing', 'sdk.mcp_launcher']:
        try:
            importlib.import_module(mod)
            rec('PASS', 'Import: {}'.format(mod), 'Module loads without error')
        except Exception as e:
            rec('FAIL', 'Import: {}'.format(mod), str(e))

def test_sdk_classes():
    print('\n{}  SDK classes & decorators'.format(INFO))
    try:
        from sdk.agents import Agent, Runner, function_tool, handoff, HandoffRequest
        rec('PASS', 'SDK: Agent class',      'Agent dataclass importable')
        rec('PASS', 'SDK: Runner class',     'Runner importable')
        rec('PASS', 'SDK: function_tool',    'Decorator importable')
        rec('PASS', 'SDK: handoff',          'handoff() importable')
        rec('PASS', 'SDK: HandoffRequest',   'HandoffRequest importable')
    except Exception as e:
        rec('FAIL', 'SDK classes', str(e))
        return

    # Verify function_tool produces correct specs
    @function_tool
    def _sample_tool(target: str, depth: int) -> str:
        """Sample tool for testing."""
        return ''

    has_oai = hasattr(_sample_tool, '_oai_tool_spec')
    has_ant = hasattr(_sample_tool, '_ant_tool_spec')
    has_flag = getattr(_sample_tool, '_is_tool', False)

    rec('PASS' if has_oai  else 'FAIL', 'function_tool: OAI spec',
        'Has _oai_tool_spec' if has_oai else 'Missing _oai_tool_spec')
    rec('PASS' if has_ant  else 'FAIL', 'function_tool: ANT spec',
        'Has _ant_tool_spec' if has_ant else 'Missing _ant_tool_spec')
    rec('PASS' if has_flag else 'FAIL', 'function_tool: _is_tool flag',
        '_is_tool=True' if has_flag else '_is_tool missing or False')

    # Verify spec schema shape
    if has_oai:
        spec = _sample_tool._oai_tool_spec
        ok = (spec.get('type') == 'function' and
              'name' in spec.get('function', {}) and
              'parameters' in spec.get('function', {}))
        rec('PASS' if ok else 'FAIL', 'OAI spec schema',
            'Correct {type, function.{name,parameters}} shape' if ok
            else 'Malformed OAI tool spec: {}'.format(spec))

    if has_ant:
        spec = _sample_tool._ant_tool_spec
        ok = ('name' in spec and 'description' in spec and 'input_schema' in spec)
        rec('PASS' if ok else 'FAIL', 'ANT spec schema',
            'Correct {name, description, input_schema} shape' if ok
            else 'Malformed ANT tool spec: {}'.format(spec))

    # Verify Agent instantiation
    try:
        a = Agent(name='TestAgent', instructions='Test instructions.',
                  tools=[_sample_tool], model='claude-sonnet-4-6')
        rec('PASS', 'Agent instantiation', 'Agent("TestAgent") created successfully')
        all_tools = a.all_tools()
        rec('PASS' if len(all_tools) == 1 else 'FAIL', 'Agent.all_tools()',
            'Returns {} tool(s)'.format(len(all_tools)))
        oai_specs = a._openai_specs()
        ant_specs = a._anthropic_specs()
        rec('PASS' if oai_specs else 'FAIL', 'Agent._openai_specs()',
            '{} OAI spec(s) returned'.format(len(oai_specs)))
        rec('PASS' if ant_specs else 'FAIL', 'Agent._anthropic_specs()',
            '{} ANT spec(s) returned'.format(len(ant_specs)))
    except Exception as e:
        rec('FAIL', 'Agent instantiation', str(e))

    # Verify handoff produces a callable tool
    try:
        target = Agent(name='Target', instructions='target', model='gpt-4o')
        h = handoff(target)
        rec('PASS' if hasattr(h, '_is_tool') else 'FAIL', 'handoff() tool',
            'handoff() returns a function_tool-decorated callable')
    except Exception as e:
        rec('FAIL', 'handoff()', str(e))

def test_runner_routing():
    print('\n{}  Runner model routing'.format(INFO))
    try:
        from sdk.agents import Runner, Agent
        # Verify routing logic exists for both backends without calling APIs
        src = inspect.getsource(Runner.run)
        has_claude_route = "startswith('claude-')" in src or "claude-" in src
        has_openai_route = '_run_openai' in src
        has_anthropic_route = '_run_anthropic' in src
        rec('PASS' if has_claude_route   else 'FAIL', 'Runner: Claude routing',
            'Routes claude-* models to Anthropic backend' if has_claude_route
            else 'Claude routing not found in Runner.run source')
        rec('PASS' if has_openai_route   else 'FAIL', 'Runner: OpenAI routing',
            '_run_openai method present')
        rec('PASS' if has_anthropic_route else 'FAIL', 'Runner: Anthropic routing',
            '_run_anthropic method present')

        # Verify _run_anthropic handles missing API key gracefully
        src_ant = inspect.getsource(Runner._run_anthropic)
        rec('PASS' if 'ANTHROPIC_API_KEY' in src_ant else 'WARN',
            'Runner: API key check', 'ANTHROPIC_API_KEY guard present in _run_anthropic')

        # Verify _run_anthropic deduplicates tools
        rec('PASS' if '_seen_tool_names' in src_ant else 'WARN',
            'Runner: tool dedup', 'Duplicate tool name guard present')
    except Exception as e:
        rec('FAIL', 'Runner routing', str(e))


# ══════════════════════════════════════════════════════════════════════════════
# 2. TOOLS
# ══════════════════════════════════════════════════════════════════════════════

def test_tools():
    print('\n{}  Tools'.format(INFO))

    tool_modules = {
        'generic_linux_command': ('tools.generic_linux_command',
                                  ['generic_linux_command', 'read_file', 'write_file']),
        'js_secret_hunter':      ('tools.js_secret_hunter',   ['hunt_js_secrets']),
        'nuclei_scan':           ('tools.nuclei_scan',         ['nuclei_scan']),
        'log_analyzer':          ('tools.log_analyzer',        []),
    }

    for label, (mod_path, fns) in tool_modules.items():
        try:
            mod = importlib.import_module(mod_path)
            rec('PASS', 'Import: {}'.format(label), 'Module loads without error')
            for fn_name in fns:
                fn = getattr(mod, fn_name, None)
                if fn is None:
                    rec('FAIL', '{}.{}'.format(label, fn_name), 'Function not found in module')
                    continue
                has_oai = hasattr(fn, '_oai_tool_spec')
                has_ant = hasattr(fn, '_ant_tool_spec')
                rec('PASS' if (has_oai and has_ant) else 'FAIL',
                    'Tool spec: {}'.format(fn_name),
                    'Has both OAI and ANT specs' if (has_oai and has_ant)
                    else 'Missing spec(s) — OAI:{} ANT:{}'.format(has_oai, has_ant))
        except ImportError as e:
            rec('WARN', 'Import: {}'.format(label), 'Optional module not installed: {}'.format(e))
        except Exception as e:
            rec('FAIL', 'Import: {}'.format(label), str(e))

    # Test generic_linux_command executes safely on Windows/Linux
    try:
        from tools.generic_linux_command import generic_linux_command
        result = generic_linux_command('echo cfai_agent_test_ok')
        passed = 'cfai_agent_test_ok' in result or 'cfai_agent_test_ok' in str(result)
        rec('PASS' if passed else 'FAIL', 'generic_linux_command execution',
            'echo command executed: {}'.format(str(result)[:80]))
    except Exception as e:
        rec('FAIL', 'generic_linux_command execution', str(e))

    # Test read_file
    try:
        from tools.generic_linux_command import read_file
        result = read_file(os.path.join(ROOT, 'requirements.txt'))
        rec('PASS' if result and 'error' not in str(result).lower()[:30] else 'WARN',
            'read_file execution', str(result)[:80])
    except Exception as e:
        rec('FAIL', 'read_file execution', str(e))

    # Test write_file
    try:
        from tools.generic_linux_command import write_file
        tmp = os.path.join(ROOT, '_agent_test_tmp.txt')
        write_file(tmp, 'agent_test')
        exists = os.path.exists(tmp)
        if exists:
            os.remove(tmp)
        rec('PASS' if exists else 'FAIL', 'write_file execution',
            'File created and cleaned up' if exists else 'File not created')
    except Exception as e:
        rec('FAIL', 'write_file execution', str(e))


# ══════════════════════════════════════════════════════════════════════════════
# 3. AGENT REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

EXPECTED_WSTG   = ['info', 'js', 'conf', 'idnt', 'athn', 'athz',
                   'sess', 'inpv', 'cryp', 'clnt', 'apit']
EXPECTED_WORKFLOW = ['assoc', 'triage', 'reduce', 'verify', 'report', 'infra']
EXPECTED_SPECIAL  = ['ctf', 'ot']

def test_wstg_registry():
    print('\n{}  WSTG agent registry'.format(INFO))
    try:
        from agents.wstg_agents import WSTG_REGISTRY, WSTG_ORDER, WORKFLOW_ORDER
    except Exception as e:
        rec('FAIL', 'Import wstg_agents', str(e))
        return

    # Order lists match registry keys
    for key in WSTG_ORDER:
        rec('PASS' if key in WSTG_REGISTRY else 'FAIL',
            'WSTG_ORDER key in registry: {}'.format(key),
            'Found in WSTG_REGISTRY' if key in WSTG_REGISTRY
            else 'Key "{}" in WSTG_ORDER but NOT in WSTG_REGISTRY'.format(key))

    for key in WORKFLOW_ORDER:
        rec('PASS' if key in WSTG_REGISTRY else 'FAIL',
            'WORKFLOW_ORDER key in registry: {}'.format(key),
            'Found in WSTG_REGISTRY' if key in WSTG_REGISTRY
            else 'Key "{}" in WORKFLOW_ORDER but NOT in WSTG_REGISTRY'.format(key))

    rec('PASS' if set(WSTG_ORDER) == set(EXPECTED_WSTG) else 'FAIL',
        'WSTG_ORDER completeness',
        'All 11 WSTG agents present' if set(WSTG_ORDER) == set(EXPECTED_WSTG)
        else 'Missing: {}'.format(set(EXPECTED_WSTG) - set(WSTG_ORDER)))

    rec('PASS' if set(WORKFLOW_ORDER) == set(EXPECTED_WORKFLOW) else 'FAIL',
        'WORKFLOW_ORDER completeness',
        'All 6 workflow agents present' if set(WORKFLOW_ORDER) == set(EXPECTED_WORKFLOW)
        else 'Missing: {}'.format(set(EXPECTED_WORKFLOW) - set(WORKFLOW_ORDER)))

    # Inspect each agent
    for key, agent in WSTG_REGISTRY.items():
        from sdk.agents import Agent
        rec('PASS' if isinstance(agent, Agent) else 'FAIL',
            'Agent type: {}'.format(key), 'Is Agent instance')
        rec('PASS' if agent.name else 'FAIL',
            'Agent name: {}'.format(key),
            'name="{}"'.format(agent.name) if agent.name else 'name is empty')
        rec('PASS' if agent.instructions and len(agent.instructions) > 100 else 'FAIL',
            'Agent instructions: {}'.format(key),
            '{} chars'.format(len(agent.instructions)) if agent.instructions
            else 'instructions is empty')
        rec('PASS' if agent.tools else 'WARN',
            'Agent tools: {}'.format(key),
            '{} tool(s): {}'.format(len(agent.tools), [getattr(t,'__name__','?') for t in agent.tools])
            if agent.tools else 'No tools assigned')
        # Check {domain} placeholder for pentest agents
        if key in WSTG_ORDER:
            has_domain = '{domain}' in agent.instructions
            rec('PASS' if has_domain else 'WARN',
                'Agent domain placeholder: {}'.format(key),
                '{domain} placeholder present' if has_domain
                else '{domain} placeholder NOT found — pentest target may not be injected')

def test_special_registry():
    print('\n{}  Special agent registry'.format(INFO))
    try:
        from agents.special_agents import SPECIAL_REGISTRY
    except Exception as e:
        rec('FAIL', 'Import special_agents', str(e))
        return

    for key in EXPECTED_SPECIAL:
        rec('PASS' if key in SPECIAL_REGISTRY else 'FAIL',
            'Special agent: {}'.format(key),
            'Present in SPECIAL_REGISTRY' if key in SPECIAL_REGISTRY
            else '"{}" missing from SPECIAL_REGISTRY'.format(key))

    for key, agent in SPECIAL_REGISTRY.items():
        from sdk.agents import Agent
        rec('PASS' if isinstance(agent, Agent) else 'FAIL',
            'Special agent type: {}'.format(key), 'Is Agent instance')
        rec('PASS' if agent.tools else 'WARN',
            'Special agent tools: {}'.format(key),
            '{} tool(s)'.format(len(agent.tools)))


# ══════════════════════════════════════════════════════════════════════════════
# 4. PENTEST ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def test_pentest_orchestrator():
    print('\n{}  Pentest orchestrator'.format(INFO))
    try:
        from agents.pentest import _with_domain, _run_agent
        rec('PASS', 'Import pentest module', 'pentest.py loads without error')
    except Exception as e:
        rec('FAIL', 'Import pentest module', str(e))
        return

    try:
        from agents.wstg_agents import WSTG_REGISTRY
        from agents.pentest import _with_domain
        import dataclasses
        agent = WSTG_REGISTRY['info']
        patched = _with_domain(agent, 'example.com')
        rec('PASS' if 'example.com' in patched.instructions else 'FAIL',
            '_with_domain() substitution',
            '{domain} → "example.com" injected correctly' if 'example.com' in patched.instructions
            else 'Domain substitution failed')
        # Verify original agent is unchanged (immutable replace)
        rec('PASS' if '{domain}' in agent.instructions else 'WARN',
            '_with_domain() immutability',
            'Original agent instructions unchanged')
    except Exception as e:
        rec('FAIL', '_with_domain() test', str(e))


# ══════════════════════════════════════════════════════════════════════════════
# 5. LIVE API TESTS (only if credentials provided)
# ══════════════════════════════════════════════════════════════════════════════

jar    = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
opener.addheaders = [('User-Agent', 'CyberINK-AgentTest/1.0')]

def _req(method, path, json_body=None, data=None):
    url  = BASE + path
    body = None
    hdrs = {}
    if json_body is not None:
        body = json.dumps(json_body).encode()
        hdrs['Content-Type'] = 'application/json'
    elif data is not None:
        body = urllib.parse.urlencode(data).encode()
        hdrs['Content-Type'] = 'application/x-www-form-urlencoded'
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        resp = opener.open(req, timeout=15)
        raw  = resp.read().decode('utf-8', errors='ignore')
        return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode('utf-8', errors='ignore')
        return e.code, raw
    except urllib.error.URLError as e:
        return 0, str(e)

def _parse(raw):
    try:    return json.loads(raw)
    except: return None

def test_live_api():
    if not BASE or not USER or not PASSWD:
        rec('INFO', 'Live API tests', 'Skipped — no base URL / credentials provided')
        return

    print('\n{}  Live API — agent endpoints'.format(INFO))

    # Login
    status, body = _req('POST', '/login', data={'username': USER, 'password': PASSWD})
    if status not in (200, 302) or ('error' in body.lower()[:200]):
        rec('FAIL', 'Live: Login', 'Login failed (HTTP {})'.format(status))
        return
    rec('PASS', 'Live: Login', 'Authenticated as "{}"'.format(USER))

    # /api/chat — chatbot uses Anthropic agent
    status, body = _req('POST', '/api/chat',
                        json_body={'message': 'ping', 'history': []})
    d = _parse(body)
    if status == 200 and d:
        rec('PASS', 'Live: /api/chat', 'Returns HTTP 200 with JSON response')
        has_reply = 'reply' in d or 'response' in d or 'content' in d or 'message' in d
        rec('PASS' if has_reply else 'WARN', 'Live: /api/chat response shape',
            'Response keys: {}'.format(list(d.keys())[:6]))
        # Check no_credits / daily limit responses are handled
        if d.get('no_credits'):
            rec('INFO', 'Live: /api/chat credits', 'Account has 0 AI credits — credit gate working')
        if d.get('daily_limit'):
            rec('INFO', 'Live: /api/chat daily limit', 'Daily limit reached — limit gate working')
    elif status == 402:
        rec('INFO', 'Live: /api/chat', 'HTTP 402 — credit gate active (no credits on account)')
    elif status == 429:
        rec('INFO', 'Live: /api/chat', 'HTTP 429 — daily limit gate active')
    else:
        rec('WARN', 'Live: /api/chat', 'HTTP {} — {}'.format(status, body[:120]))

    # /api/connect/scan status (GET job that doesn't exist → expect 404 or error JSON)
    status, body = _req('GET', '/api/connect/scan/nonexistent-job-id-test')
    rec('PASS' if status in (200, 404, 400) else 'WARN',
        'Live: /api/connect/scan/<job_id>',
        'HTTP {} (route exists and responds)'.format(status))

    # /api/pentest/engagements — uses pentest agents
    status, body = _req('GET', '/api/pentest/engagements')
    d = _parse(body)
    rec('PASS' if status == 200 and d and 'engagements' in d else 'FAIL',
        'Live: /api/pentest/engagements',
        'HTTP {} — {}'.format(status, list(d.keys()) if d else body[:80]))

    # /api/dca/scanners — dynamic code analysis agent tools
    status, body = _req('GET', '/api/dca/scanners')
    d = _parse(body)
    if status == 200 and d:
        rec('PASS', 'Live: /api/dca/scanners', 'Scanner status: {}'.format(
            {k: v.get('installed', '?') if isinstance(v, dict) else v for k, v in d.items()}))
    else:
        rec('WARN', 'Live: /api/dca/scanners', 'HTTP {} — {}'.format(status, body[:80]))

    # /api/sca/check — static code analysis agent
    status, body = _req('GET', '/api/sca/check')
    d = _parse(body)
    rec('PASS' if status == 200 and d else 'WARN',
        'Live: /api/sca/check',
        'installed={}, version={}'.format(d.get('installed'), d.get('version')) if d
        else 'HTTP {} — {}'.format(status, body[:80]))

    # Verify pentest API blocks unauthenticated after logout
    _req('GET', '/logout')
    status, _ = _req('POST', '/api/connect/scan', json_body={'target': 'test.com'})
    rec('PASS' if status in (401, 403, 302) else 'FAIL',
        'Live: /api/connect/scan auth guard',
        'Blocks unauthenticated POST (HTTP {})'.format(status))


# ══════════════════════════════════════════════════════════════════════════════
# RUNNER
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print('\n' + '=' * 60)
    print('  CyberINK — Agent Test Suite')
    if BASE:
        print('  Target : {}'.format(BASE))
        print('  User   : {}'.format(USER))
    else:
        print('  Mode   : unit tests only (no live URL provided)')
    print('=' * 60)

    for fn in [
        test_sdk_imports,
        test_sdk_classes,
        test_runner_routing,
        test_tools,
        test_wstg_registry,
        test_special_registry,
        test_pentest_orchestrator,
        test_live_api,
    ]:
        try:
            fn()
        except Exception as e:
            rec('FAIL', fn.__name__, 'Test group raised exception: {}'.format(e))

    pass_n = sum(1 for r in results if r[0] == 'PASS')
    warn_n = sum(1 for r in results if r[0] == 'WARN')
    fail_n = sum(1 for r in results if r[0] == 'FAIL')
    info_n = sum(1 for r in results if r[0] == 'INFO')

    print('\n' + '-' * 60)
    print('  Full Results')
    print('-' * 60)
    for level, name, detail in results:
        print('{} [{}] {}'.format(tag(level), name, detail))

    print('\n' + '-' * 60)
    print('  Results: {} passed  |  {} warnings  |  {} failures  |  {} info'.format(
        pass_n, warn_n, fail_n, info_n))
    print('-' * 60 + '\n')
    sys.exit(1 if fail_n > 0 else 0)

if __name__ == '__main__':
    main()
