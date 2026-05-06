"""CF_AI — Phoenix / OpenTelemetry AI observability.

Mirrors how aliasrobotics/CAI integrates tracing:
  - arize-phoenix provides the web UI (localhost:6006)
  - openinference instrumentors auto-patch the OpenAI/Anthropic clients
  - every ChatCompletion, tool call, and agent turn is traced automatically

Enable:
    CFAI_TRACING=1  in .env  (disabled by default)

Install on Kali VPS:
    pip3 install --break-system-packages \
        arize-phoenix \
        openinference-instrumentation-openai \
        openinference-instrumentation-anthropic \
        opentelemetry-sdk \
        opentelemetry-exporter-otlp-proto-http
"""
from __future__ import annotations
import os
import logging

log = logging.getLogger('cfai.tracing')

_tracer      = None
_enabled     = False
_phoenix_url = ''


def setup() -> bool:
    """Call once at startup. Returns True if tracing was activated."""
    global _tracer, _enabled, _phoenix_url

    if not os.environ.get('CFAI_TRACING'):
        return False

    # ── 1. Import required packages ───────────────────────────────────────
    try:
        import phoenix as px
        from opentelemetry import trace as otel_trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    except ImportError:
        log.warning(
            'Phoenix tracing packages not found.\n'
            '  pip3 install --break-system-packages \\\n'
            '      arize-phoenix openinference-instrumentation-openai \\\n'
            '      openinference-instrumentation-anthropic \\\n'
            '      opentelemetry-sdk opentelemetry-exporter-otlp-proto-http'
        )
        return False

    # ── 2. Launch Phoenix web UI ──────────────────────────────────────────
    try:
        session = px.launch_app()
        _phoenix_url = str(session.url)
    except Exception as exc:
        log.debug(f'Phoenix launch: {exc} — assuming already running at :6006')
        _phoenix_url = 'http://localhost:6006'

    # ── 3. Wire OTel provider → Phoenix OTLP endpoint ─────────────────────
    endpoint = _phoenix_url.rstrip('/') + '/v1/traces'
    provider = TracerProvider()
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
    )
    otel_trace.set_tracer_provider(provider)

    # ── 4. Auto-instrument AI provider SDKs ───────────────────────────────
    # This patches the OpenAI/Anthropic clients so every ChatCompletion call
    # is automatically captured in Phoenix — no manual span code needed.
    try:
        from openinference.instrumentation.openai import OpenAIInstrumentor
        OpenAIInstrumentor().instrument(tracer_provider=provider)
    except ImportError:
        pass  # openai not installed or instrumentor missing

    try:
        from openinference.instrumentation.anthropic import AnthropicInstrumentor
        AnthropicInstrumentor().instrument(tracer_provider=provider)
    except ImportError:
        pass

    # ── 5. Keep a named tracer for our own turn/tool spans ─────────────────
    _tracer  = otel_trace.get_tracer('cfai')
    _enabled = True
    return True


# ── Convenience helpers used by Runner ───────────────────────────────────────

def phoenix_url() -> str:
    return _phoenix_url


def span(name: str):
    """Return a live OTel span, or a no-op context manager when tracing is off."""
    if _tracer:
        return _tracer.start_as_current_span(name)
    return _NullSpan()


class _NullSpan:
    def __enter__(self):       return self
    def __exit__(self, *_):    pass
    def set_attribute(self, *_): pass
    def record_exception(self, *_): pass
