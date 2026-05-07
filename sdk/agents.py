"""CF_AI Agent SDK — Agent, Runner, function_tool, handoff.

Routing:
  model starts with "claude-"  →  Anthropic API  (real MCP tool calling)
  all other models             →  OpenAI API     (GPT-4o, o1, etc.)
"""
from __future__ import annotations
import os
import time
import inspect
import json as _json
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

log = logging.getLogger('cfai.sdk')

DEFAULT_MODEL = os.environ.get('CAI_MODEL', 'gpt-4o')


# ── function_tool decorator ───────────────────────────────────────────────────

def function_tool(fn: Callable = None, *, description: str = None):
    """Decorate a function to expose it as a tool for both OpenAI and Anthropic."""
    def _wrap(f: Callable) -> Callable:
        doc   = (description or inspect.getdoc(f) or f.__name__).strip()
        sig   = inspect.signature(f)
        hints = f.__annotations__
        props: dict = {}
        req:   list = []
        _map  = {str: 'string', int: 'integer', float: 'number', bool: 'boolean'}

        for name, param in sig.parameters.items():
            if name in ('self', 'cls'):
                continue
            props[name] = {'type': _map.get(hints.get(name, str), 'string'), 'description': name}
            if param.default is inspect.Parameter.empty:
                req.append(name)

        # OpenAI tool spec
        f._oai_tool_spec = {
            'type': 'function',
            'function': {
                'name':        f.__name__,
                'description': doc,
                'parameters':  {'type': 'object', 'properties': props, 'required': req},
            },
        }
        # Anthropic tool spec
        f._ant_tool_spec = {
            'name':         f.__name__,
            'description':  doc,
            'input_schema': {'type': 'object', 'properties': props, 'required': req},
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
    _handoff._oai_tool_spec['function']['name'] = _handoff.__name__
    _handoff._ant_tool_spec['name']             = _handoff.__name__
    return _handoff


# ── Agent ─────────────────────────────────────────────────────────────────────

@dataclass
class Agent:
    name:         str
    instructions: str
    tools:        list = field(default_factory=list)
    handoffs:     list = field(default_factory=list)
    model:        str  = field(default_factory=lambda: DEFAULT_MODEL)
    description:  str  = ''
    max_turns:    int  = 50

    def all_tools(self) -> list:
        tools = list(self.tools)
        for h in self.handoffs:
            tools.append(handoff(h))
        return tools

    def _openai_specs(self) -> list:
        return [t._oai_tool_spec for t in self.all_tools() if hasattr(t, '_oai_tool_spec')]

    def _anthropic_specs(self) -> list:
        return [t._ant_tool_spec for t in self.all_tools() if hasattr(t, '_ant_tool_spec')]


# ── Runner ────────────────────────────────────────────────────────────────────

class Runner:
    """Executes an Agent. Routes to Anthropic (Claude) or OpenAI based on model name."""

    @classmethod
    def run(cls, agent: Agent, message: str,
            on_text:   Callable[[str], None]             = None,
            on_tool:   Callable[[str, dict], None]       = None,
            on_result: Callable[[str, str, float], None] = None,
            max_turns: int = None) -> str:

        from sdk.tracing import span as _span, set_ok as _ok, set_error as _err
        turns = max_turns or agent.max_turns

        with _span(f'agent:{agent.name}') as s:
            s.set_attribute('cfai.agent', agent.name)
            s.set_attribute('cfai.model', agent.model)
            s.set_attribute('cfai.max_turns', turns)
            s.set_attribute('openinference.span.kind', 'CHAIN')
            s.set_attribute('input.value', message[:2000])
            try:
                if agent.model.startswith('claude-'):
                    result = cls._run_anthropic(agent, message, on_text, on_tool, on_result, turns)
                else:
                    result = cls._run_openai(agent, message, on_text, on_tool, on_result, turns)
                s.set_attribute('output.value', str(result)[:2000])
                _ok(s)
                return result
            except Exception as exc:
                _err(s, exc)
                raise


    # ── Anthropic (Claude) backend ────────────────────────────────────────────

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
            _emit('anthropic package not installed — run: pip3 install anthropic')
            return ''

        key = os.environ.get('ANTHROPIC_API_KEY', '')
        if not key:
            _emit('ANTHROPIC_API_KEY not set — add it to .env and restart')
            return ''

        client    = _ant.Anthropic(api_key=key)
        messages  = [{'role': 'user', 'content': message}]
        all_fns   = agent.all_tools()
        _mcp_fns  = [t for t in all_fns if getattr(t, '_is_mcp_tool', False)]
        _reg_fns  = [t for t in all_fns if not getattr(t, '_is_mcp_tool', False)]

        # Try to start the MCP server for real MCP protocol connections
        _mcp_url = ''
        if _mcp_fns:
            try:
                from sdk import mcp_launcher
                _mcp_url = mcp_launcher.get_server_url()
            except Exception:
                pass

        # When MCP server running: regular tools go to API, MCP tools go to server
        # When no MCP server: all tools (including MCP functions) as regular Anthropic tools
        if _mcp_url:
            tools    = [t._ant_tool_spec for t in _reg_fns if hasattr(t, '_ant_tool_spec')]
            tool_map = {t.__name__: t for t in _reg_fns if callable(t)}
        else:
            tools    = agent._anthropic_specs()
            tool_map = {t.__name__: t for t in all_fns if callable(t)}

        turns = 0
        final = ''

        from sdk.tracing import span as _span, set_ok as _ok

        while turns < max_turns:
            turns += 1
            try:
                with _span(f'turn:{turns}') as ts:
                    ts.set_attribute('cfai.turn', turns)
                    ts.set_attribute('openinference.span.kind', 'LLM')
                    ts.set_attribute('llm.model_name', agent.model)
                    if _mcp_url:
                        try:
                            resp = client.beta.messages.create(
                                model=agent.model,
                                max_tokens=8096,
                                system=agent.instructions,
                                messages=messages,
                                tools=tools or _ant.NOT_GIVEN,
                                betas=['mcp-client-2025-04-04'],
                                mcp_servers=[{
                                    'type': 'url',
                                    'url':  _mcp_url,
                                    'name': 'cf-ai-wordpress',
                                }],
                            )
                        except Exception as mcp_exc:
                            _emit(f'[MCP] Server unavailable, using direct tool calls: {mcp_exc}')
                            _mcp_url = ''
                            tools    = agent._anthropic_specs()
                            tool_map = {t.__name__: t for t in all_fns if callable(t)}
                            resp = client.messages.create(
                                model=agent.model,
                                max_tokens=8096,
                                system=agent.instructions,
                                messages=messages,
                                tools=tools or _ant.NOT_GIVEN,
                            )
                    else:
                        resp = client.messages.create(
                            model=agent.model,
                            max_tokens=8096,
                            system=agent.instructions,
                            messages=messages,
                            tools=tools or _ant.NOT_GIVEN,
                        )
                    _ok(ts)
            except KeyboardInterrupt:
                instr = _hitl_pause(messages)
                if instr is None:
                    return '[Agent aborted by operator]'
                continue
            except Exception as exc:
                _emit(f'[API error: {exc}]')
                return ''

            # Collect text and tool-use blocks from response
            text_parts  = []
            tool_blocks = []
            for block in resp.content:
                if block.type == 'text' and block.text:
                    text_parts.append(block.text)
                elif block.type == 'tool_use':
                    tool_blocks.append(block)

            text = ''.join(text_parts)
            if text:
                if on_text:
                    on_text(text)
                final = text

            if resp.stop_reason == 'end_turn' or not tool_blocks:
                break

            # Append assistant turn (must include full content list)
            messages.append({
                'role':    'assistant',
                'content': [_block_to_dict(b) for b in resp.content],
            })

            # Execute tools and collect results
            tool_results = []
            for block in tool_blocks:
                fn   = tool_map.get(block.name)
                args = block.input or {}
                if on_tool:
                    on_tool(block.name, args)
                t0 = time.time()
                with _span(f'tool:{block.name}') as tool_s:
                    tool_s.set_attribute('cfai.tool', block.name)
                    tool_s.set_attribute('cfai.tool.args', str(args)[:300])
                    try:
                        result = fn(**args) if fn else f'[unknown tool: {block.name}]'
                    except HandoffRequest as hoff:
                        return cls.run(hoff.target_agent, hoff.message,
                                       on_text, on_tool, on_result, max_turns - turns)
                    except Exception as exc:
                        result = f'[tool error: {exc}]'
                    tool_s.set_attribute('cfai.tool.output_len', len(str(result)))
                elapsed = time.time() - t0
                if on_result:
                    on_result(block.name, str(result), elapsed)
                tool_results.append({
                    'type':        'tool_result',
                    'tool_use_id': block.id,
                    'content':     str(result)[:8000],
                })

            messages.append({'role': 'user', 'content': tool_results})

        return final


    # ── OpenAI (GPT-4o / o1) backend ─────────────────────────────────────────

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
            _emit('openai package not installed — run: pip3 install openai')
            return ''

        key = os.environ.get('OPENAI_API_KEY', '')
        if not key:
            _emit('OPENAI_API_KEY not set — add it to .env and restart')
            return ''

        client   = OpenAI(api_key=key)
        messages = [
            {'role': 'system', 'content': agent.instructions},
            {'role': 'user',   'content': message},
        ]
        tools    = agent._openai_specs()
        tool_map = {t.__name__: t for t in agent.all_tools() if callable(t)}
        turns    = 0
        final    = ''

        from sdk.tracing import span as _span, set_ok as _ok

        while turns < max_turns:
            turns += 1
            try:
                with _span(f'turn:{turns}') as ts:
                    ts.set_attribute('cfai.turn', turns)
                    ts.set_attribute('openinference.span.kind', 'LLM')
                    ts.set_attribute('llm.model_name', agent.model)
                    ts.set_attribute('llm.invocation_parameters',
                                     _json.dumps({'model': agent.model, 'tool_choice': 'auto' if tools else None}))
                    for i, m in enumerate(messages[-10:]):
                        role    = m.get('role', '')    if isinstance(m, dict) else (m.role or '')
                        content = m.get('content', '') if isinstance(m, dict) else (m.content or '')
                        ts.set_attribute(f'llm.input_messages.{i}.message.role', role)
                        ts.set_attribute(f'llm.input_messages.{i}.message.content', str(content)[:500])
                    resp = client.chat.completions.create(
                        model=agent.model,
                        messages=messages,
                        tools=tools or None,
                        tool_choice='auto' if tools else None,
                    )
                    out_msg = resp.choices[0].message
                    ts.set_attribute('llm.output_messages.0.message.role', 'assistant')
                    ts.set_attribute('llm.output_messages.0.message.content',
                                     str(out_msg.content or '')[:500])
                    ts.set_attribute('llm.token_count.prompt',
                                     getattr(getattr(resp, 'usage', None), 'prompt_tokens', 0))
                    ts.set_attribute('llm.token_count.completion',
                                     getattr(getattr(resp, 'usage', None), 'completion_tokens', 0))
                    _ok(ts)
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
                fn = tool_map.get(tc.function.name)
                try:
                    args = _json.loads(tc.function.arguments or '{}')
                except Exception:
                    args = {}
                if on_tool:
                    on_tool(tc.function.name, args)
                t0 = time.time()
                with _span(f'tool:{tc.function.name}') as tool_s:
                    tool_s.set_attribute('cfai.tool', tc.function.name)
                    tool_s.set_attribute('cfai.tool.args', str(args)[:300])
                    try:
                        result = fn(**args) if fn else f'[unknown tool: {tc.function.name}]'
                    except HandoffRequest as hoff:
                        return cls.run(hoff.target_agent, hoff.message,
                                       on_text, on_tool, on_result, max_turns - turns)
                    except Exception as exc:
                        result = f'[tool error: {exc}]'
                    tool_s.set_attribute('cfai.tool.output_len', len(str(result)))
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


# ── Helpers ───────────────────────────────────────────────────────────────────

def _block_to_dict(block) -> dict:
    """Convert an Anthropic content block object to a plain dict."""
    if block.type == 'text':
        return {'type': 'text', 'text': block.text}
    if block.type == 'tool_use':
        return {'type': 'tool_use', 'id': block.id, 'name': block.name, 'input': block.input}
    return {'type': block.type}


def _hitl_pause(messages: list) -> Optional[str]:
    from repl.aesthetics import WARN, DIM, R, GREY
    print(f'\n  {WARN}[HITL] Agent paused.{R}')
    try:
        instr = input(f'  {GREY}Enter instruction (Enter=resume, "abort"=stop): {R}')
    except (EOFError, KeyboardInterrupt):
        return None
    if instr.strip().lower() == 'abort':
        return None
    if instr.strip():
        messages.append({'role': 'user', 'content': f'[Operator]: {instr.strip()}'})
    return instr or ''
