"""CF_AI Agent SDK — Agent, Runner, function_tool, handoff.

Implements the ReACT (Reasoning + Action) agent model using OpenAI (GPT-4o, o1, etc.).
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
    """Decorate a function to expose it as an OpenAI tool."""
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

        f._oai_tool_spec = {
            'type': 'function',
            'function': {
                'name':        f.__name__,
                'description': doc,
                'parameters':  {'type': 'object', 'properties': props, 'required': req},
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
    _handoff._oai_tool_spec['function']['name'] = _handoff.__name__
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


# ── Runner ────────────────────────────────────────────────────────────────────

class Runner:
    """Executes an Agent with the ReACT loop until done, error, or HITL abort."""

    @classmethod
    def run(cls, agent: Agent, message: str,
            on_text:   Callable[[str], None]             = None,
            on_tool:   Callable[[str, dict], None]       = None,
            on_result: Callable[[str, str, float], None] = None,
            max_turns: int = None) -> str:
        """Run the agent. Returns final text output.

        Phoenix/OTel auto-instrumentation captures every ChatCompletion call
        when CFAI_TRACING=1 — no extra code needed here.
        Ctrl+C triggers Human-In-The-Loop pause.
        """
        from sdk.tracing import span as _span

        turns = max_turns or agent.max_turns

        from sdk.tracing import set_ok as _ok, set_error as _err
        with _span(f'agent:{agent.name}') as s:
            s.set_attribute('cfai.agent', agent.name)
            s.set_attribute('cfai.model', agent.model)
            s.set_attribute('cfai.max_turns', turns)
            s.set_attribute('openinference.span.kind', 'CHAIN')
            try:
                result = cls._run_openai(agent, message, on_text, on_tool, on_result, turns)
                _ok(s)
                return result
            except Exception as exc:
                _err(s, exc)
                raise

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
            _emit('openai package not installed — run: pip3 install --break-system-packages openai')
            return ''

        key = os.environ.get('OPENAI_API_KEY', '')
        if not key:
            _emit('OPENAI_API_KEY not set — add it to /opt/CF_AI/.env and restart')
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
                    # Log input messages for Phoenix ChatCompletion view
                    # messages can be dicts OR ChatCompletionMessage objects
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
                    # Log output
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


# ── HITL ─────────────────────────────────────────────────────────────────────

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
