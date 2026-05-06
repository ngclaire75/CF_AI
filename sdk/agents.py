"""CF_AI Agent SDK — Agent, Runner, function_tool, handoff.

Implements the ReACT (Reasoning + Action) agent model using either
Anthropic Claude or OpenAI-compatible models (GPT-4o, local Ollama, etc.).
"""
from __future__ import annotations
import os
import time
import inspect
import logging
from dataclasses import dataclass, field
from typing import Callable, Any, Optional

log = logging.getLogger('cfai.sdk')

# ── Supported providers ───────────────────────────────────────────────────────
PROVIDERS = {
    'claude-opus-4-7':       'anthropic',
    'claude-sonnet-4-6':     'anthropic',
    'claude-haiku-4-5':      'anthropic',
    'gpt-4o':                'openai',
    'gpt-4o-mini':           'openai',
    'gpt-4-turbo':           'openai',
    'o1':                    'openai',
    'o3-mini':               'openai',
}

# Ollama models (runs locally — free, no API key needed)
OLLAMA_MODELS = {
    'llama3.2', 'llama3.1', 'llama3', 'llama2',
    'mistral', 'mistral-nemo', 'mixtral',
    'qwen2.5', 'qwen2.5:7b', 'qwen2.5:14b', 'qwen2.5:32b',
    'qwen2', 'qwen',
    'gemma2', 'gemma2:9b', 'gemma2:27b', 'gemma',
    'phi3', 'phi3:mini', 'phi4',
    'deepseek-r1', 'deepseek-r1:7b', 'deepseek-r1:14b',
    'codellama', 'codellama:13b',
    'dolphin-mistral', 'neural-chat',
    'llava', 'bakllava',
}

DEFAULT_MODEL = os.environ.get('CAI_MODEL', 'claude-sonnet-4-6')
OLLAMA_BASE   = os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434/v1')


def _provider(model: str) -> str:
    # Exact/prefix match against known providers
    for key, prov in PROVIDERS.items():
        if key in model:
            return prov
    if 'claude' in model.lower():
        return 'anthropic'
    if model.lower().startswith(('gpt-', 'o1', 'o3')):
        return 'openai'
    # Anything else → try Ollama
    return 'ollama'


# ── function_tool decorator ───────────────────────────────────────────────────

def function_tool(fn: Callable = None, *, description: str = None):
    """Decorate a function so it becomes a Claude/OpenAI tool.

    The function's type hints determine the schema. Supported hint types:
    str, int, float, bool — anything else maps to string.
    """
    def _wrap(f: Callable) -> Callable:
        doc    = (description or inspect.getdoc(f) or f.__name__).strip()
        sig    = inspect.signature(f)
        hints  = f.__annotations__
        props  = {}
        req    = []
        _type_map = {str: 'string', int: 'integer', float: 'number', bool: 'boolean'}

        for name, param in sig.parameters.items():
            if name in ('self', 'cls'):
                continue
            hint = hints.get(name, str)
            props[name] = {
                'type':        _type_map.get(hint, 'string'),
                'description': name,
            }
            if param.default is inspect.Parameter.empty:
                req.append(name)

        # Anthropic tool spec
        f._tool_spec = {
            'name': f.__name__,
            'description': doc,
            'input_schema': {
                'type': 'object',
                'properties': props,
                'required': req,
            },
        }
        # OpenAI tool spec
        f._oai_tool_spec = {
            'type': 'function',
            'function': {
                'name': f.__name__,
                'description': doc,
                'parameters': {
                    'type': 'object',
                    'properties': props,
                    'required': req,
                },
            },
        }
        f._is_tool = True
        return f

    return _wrap(fn) if fn is not None else _wrap


# ── Handoff ───────────────────────────────────────────────────────────────────

@dataclass
class HandoffRequest:
    target_agent: 'Agent'
    message: str


def handoff(target: 'Agent') -> Callable:
    """Create a handoff tool that transfers execution to another agent."""
    @function_tool(description=f'Hand off task to {target.name}: {target.description}')
    def _handoff(message: str) -> str:
        raise HandoffRequest(target, message)
    _handoff.__name__ = f'transfer_to_{target.name.lower().replace(" ", "_")}'
    _handoff._tool_spec['name']            = _handoff.__name__
    _handoff._oai_tool_spec['function']['name'] = _handoff.__name__
    return _handoff


# ── Agent dataclass ───────────────────────────────────────────────────────────

@dataclass
class Agent:
    name:         str
    instructions: str
    tools:        list         = field(default_factory=list)
    handoffs:     list         = field(default_factory=list)
    model:        str          = field(default_factory=lambda: DEFAULT_MODEL)
    description:  str          = ''
    max_turns:    int          = 20

    def all_tools(self) -> list:
        tools = list(self.tools)
        for h in self.handoffs:
            tools.append(handoff(h))
        return tools

    def _anthropic_specs(self) -> list:
        return [t._tool_spec for t in self.all_tools() if hasattr(t, '_tool_spec')]

    def _openai_specs(self) -> list:
        return [t._oai_tool_spec for t in self.all_tools() if hasattr(t, '_oai_tool_spec')]


# ── Runner ────────────────────────────────────────────────────────────────────

class Runner:
    """Executes an Agent with the ReACT loop until done, error, or HITL abort."""

    @classmethod
    def run(cls, agent: Agent, message: str,
            on_text:   Callable[[str], None]        = None,
            on_tool:   Callable[[str, dict], None]  = None,
            on_result: Callable[[str, str, float], None] = None,
            max_turns: int = None) -> str:
        """Run agent synchronously. Returns final text output.

        Ctrl+C during execution triggers HITL (Human-In-The-Loop) pause.
        """
        provider = _provider(agent.model)
        turns = max_turns or agent.max_turns
        if provider == 'anthropic':
            return cls._run_anthropic(agent, message, on_text, on_tool, on_result, turns)
        elif provider == 'ollama':
            return cls._run_ollama(agent, message, on_text, on_tool, on_result, turns)
        else:
            return cls._run_openai(agent, message, on_text, on_tool, on_result, turns)

    # ── Anthropic path ────────────────────────────────────────────────────

    @classmethod
    def _run_anthropic(cls, agent: Agent, message: str,
                       on_text, on_tool, on_result, max_turns) -> str:

        def _emit(msg: str):
            if on_text:
                on_text(msg)
            else:
                print(msg)

        try:
            import anthropic as _ant
        except ImportError:
            _emit('anthropic package not installed. Run: pip3 install --break-system-packages anthropic')
            return ''

        key = os.environ.get('ANTHROPIC_API_KEY', '')
        if not key:
            _emit('ANTHROPIC_API_KEY not set — add it to /opt/CF_AI/.env and restart')
            return ''

        client   = _ant.Anthropic(api_key=key)
        messages = [{'role': 'user', 'content': message}]
        tools    = agent._anthropic_specs()
        tool_map = {t.__name__: t for t in agent.all_tools() if callable(t)}
        turns    = 0
        final    = ''

        while turns < max_turns:
            turns += 1
            try:
                create_kwargs = dict(
                    model=agent.model,
                    max_tokens=4096,
                    system=agent.instructions,
                    messages=messages,
                )
                if tools:
                    create_kwargs['tools'] = tools
                resp = client.messages.create(**create_kwargs)
            except KeyboardInterrupt:
                final = _hitl_pause(messages)
                if final is None:
                    return '[Agent aborted by operator]'
                continue
            except Exception as exc:
                _emit(f'[API error: {exc}]')
                return ''

            # Extract and display text
            text_parts = [b.text for b in resp.content if b.type == 'text']
            if text_parts and on_text:
                for t in text_parts:
                    on_text(t)
            final = ' '.join(text_parts)

            if resp.stop_reason in ('end_turn', 'max_tokens'):
                break

            if resp.stop_reason == 'tool_use':
                tool_results = []
                for block in resp.content:
                    if block.type != 'tool_use':
                        continue
                    fn = tool_map.get(block.name)
                    if on_tool:
                        on_tool(block.name, block.input)
                    t0 = time.time()
                    try:
                        if fn:
                            result = fn(**block.input)
                        else:
                            result = f'[unknown tool: {block.name}]'
                    except HandoffRequest as hoff:
                        return cls.run(hoff.target_agent, hoff.message,
                                       on_text, on_tool, on_result, max_turns - turns)
                    except KeyboardInterrupt:
                        result = '[tool interrupted]'
                    except Exception as exc:
                        result = f'[tool error: {exc}]'
                    elapsed = time.time() - t0
                    if on_result:
                        on_result(block.name, str(result), elapsed)
                    tool_results.append({
                        'type': 'tool_result',
                        'tool_use_id': block.id,
                        'content': str(result)[:8000],
                    })

                messages.append({'role': 'assistant', 'content': resp.content})
                messages.append({'role': 'user',      'content': tool_results})

                # HITL check after tool batch
                try:
                    pass  # Ctrl+C is caught per-iteration above
                except KeyboardInterrupt:
                    instr = _hitl_pause(messages)
                    if instr is None:
                        return '[Agent aborted by operator]'

        return final

    # ── OpenAI path ───────────────────────────────────────────────────────

    @classmethod
    def _run_openai(cls, agent: Agent, message: str,
                    on_text, on_tool, on_result, max_turns) -> str:

        def _emit(msg: str):
            if on_text:
                on_text(msg)
            else:
                print(msg)

        try:
            from openai import OpenAI
        except ImportError:
            _emit('openai package not installed. Run: pip3 install --break-system-packages openai')
            return ''

        key = os.environ.get('OPENAI_API_KEY', '')
        if not key:
            _emit('OPENAI_API_KEY not set — add it to /opt/CF_AI/.env and restart')
            return ''

        client   = OpenAI(api_key=key)
        messages = [
            {'role': 'system',  'content': agent.instructions},
            {'role': 'user',    'content': message},
        ]
        tools    = agent._openai_specs()
        tool_map = {t.__name__: t for t in agent.all_tools() if callable(t)}
        turns    = 0
        final    = ''

        while turns < max_turns:
            turns += 1
            try:
                resp = client.chat.completions.create(
                    model=agent.model,
                    messages=messages,
                    tools=tools or None,
                    tool_choice='auto' if tools else None,
                )
            except KeyboardInterrupt:
                instr = _hitl_pause(messages)
                if instr is None:
                    return '[Agent aborted by operator]'
                continue
            except Exception as exc:
                _emit(f'[API error: {exc}]')
                return ''

            choice = resp.choices[0]
            msg    = choice.message
            text   = msg.content or ''
            if text and on_text:
                on_text(text)
            final = text

            if choice.finish_reason in ('stop', 'length') or not msg.tool_calls:
                break

            tool_results = []
            for tc in (msg.tool_calls or []):
                import json
                fn    = tool_map.get(tc.function.name)
                try:
                    args  = json.loads(tc.function.arguments or '{}')
                except Exception:
                    args  = {}
                if on_tool:
                    on_tool(tc.function.name, args)
                t0 = time.time()
                try:
                    result = fn(**args) if fn else f'[unknown tool: {tc.function.name}]'
                except HandoffRequest as hoff:
                    return cls.run(hoff.target_agent, hoff.message,
                                   on_text, on_tool, on_result, max_turns - turns)
                except Exception as exc:
                    result = f'[tool error: {exc}]'
                elapsed = time.time() - t0
                if on_result:
                    on_result(tc.function.name, str(result), elapsed)
                tool_results.append({
                    'role':         'tool',
                    'tool_call_id': tc.id,
                    'content':      str(result)[:8000],
                })

            messages.append(msg)
            messages.extend(tool_results)

        return final


    # ── Ollama path (local, free) ─────────────────────────────────────────

    @classmethod
    def _run_ollama(cls, agent: Agent, message: str,
                    on_text, on_tool, on_result, max_turns) -> str:

        def _emit(msg: str):
            if on_text:
                on_text(msg)
            else:
                print(msg)

        try:
            from openai import OpenAI
        except ImportError:
            _emit('openai package not installed. Run: pip3 install --break-system-packages openai')
            return ''

        base_url = OLLAMA_BASE
        try:
            client = OpenAI(base_url=base_url, api_key='ollama')
            # Quick connectivity check
            client.models.list()
        except Exception as exc:
            _emit(f'Ollama not reachable at {base_url} — is it running?\n'
                  f'  Start with: ollama serve\n'
                  f'  Install:    curl -fsSL https://ollama.ai/install.sh | sh\n'
                  f'  Pull model: ollama pull {agent.model}\n'
                  f'  Error: {exc}')
            return ''

        # Check model is available, pull if not
        try:
            available = [m.id for m in client.models.list().data]
            if agent.model not in available:
                _emit(f'Pulling {agent.model} — this may take a minute…')
                import subprocess
                subprocess.run(['ollama', 'pull', agent.model],
                               capture_output=False, timeout=300)
        except Exception:
            pass  # best-effort, proceed anyway

        messages  = [
            {'role': 'system', 'content': agent.instructions},
            {'role': 'user',   'content': message},
        ]
        tools    = agent._openai_specs()
        tool_map = {t.__name__: t for t in agent.all_tools() if callable(t)}
        turns    = 0
        final    = ''

        while turns < max_turns:
            turns += 1
            try:
                create_kwargs = dict(
                    model=agent.model,
                    messages=messages,
                )
                if tools:
                    create_kwargs['tools']       = tools
                    create_kwargs['tool_choice'] = 'auto'
                resp = client.chat.completions.create(**create_kwargs)
            except KeyboardInterrupt:
                instr = _hitl_pause(messages)
                if instr is None:
                    return '[Agent aborted by operator]'
                continue
            except Exception as exc:
                _emit(f'[Ollama error: {exc}]')
                return ''

            choice = resp.choices[0]
            msg    = choice.message
            text   = msg.content or ''
            if text and on_text:
                on_text(text)
            final = text

            if choice.finish_reason in ('stop', 'length') or not msg.tool_calls:
                break

            tool_results = []
            for tc in (msg.tool_calls or []):
                import json as _json
                fn = tool_map.get(tc.function.name)
                try:
                    args = _json.loads(tc.function.arguments or '{}')
                except Exception:
                    args = {}
                if on_tool:
                    on_tool(tc.function.name, args)
                t0 = time.time()
                try:
                    result = fn(**args) if fn else f'[unknown tool: {tc.function.name}]'
                except HandoffRequest as hoff:
                    return cls.run(hoff.target_agent, hoff.message,
                                   on_text, on_tool, on_result, max_turns - turns)
                except Exception as exc:
                    result = f'[tool error: {exc}]'
                elapsed = time.time() - t0
                if on_result:
                    on_result(tc.function.name, str(result), elapsed)
                tool_results.append({
                    'role':         'tool',
                    'tool_call_id': tc.id,
                    'content':      str(result)[:8000],
                })

            messages.append(msg)
            messages.extend(tool_results)

        return final


def _hitl_pause(messages: list) -> Optional[str]:
    """Human-In-The-Loop: pause agent, prompt operator. Returns instruction or None=abort."""
    from repl.aesthetics import WARN, DIM, R, GREY
    print(f'\n  {WARN}[HITL] Agent paused by operator.{R}')
    try:
        instr = input(f'  {GREY}Enter instruction (Enter=resume, "abort"=stop): {R}')
    except (EOFError, KeyboardInterrupt):
        return None
    if instr.strip().lower() == 'abort':
        return None
    if instr.strip():
        messages.append({'role': 'user', 'content': f'[Human operator]: {instr.strip()}'})
    return instr or ''
