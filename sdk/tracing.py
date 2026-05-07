"""CF_AI — OpenTelemetry AI observability → Arize Phoenix UI.

Architecture (avoids compiling pandas from source on Python 3.13):
  - VPS: only needs opentelemetry-sdk + opentelemetry-exporter-otlp-proto-http
          + openinference instrumentors  (no pandas, no arize-phoenix)
  - Phoenix UI: run locally on your laptop (has pre-built pandas wheels)

VPS install:
    pip3 install --break-system-packages \
        opentelemetry-sdk \
        opentelemetry-exporter-otlp-proto-http \
        openinference-instrumentation-openai \
        openinference-instrumentation-anthropic

Local (Windows/Mac) — Phoenix server:
    pip install arize-phoenix
    python -m phoenix.server.main serve
    # opens http://localhost:6006

SSH tunnel (forward VPS traces → local Phoenix):
    ssh -R 6006:localhost:6006 root@<vps-ip>
    # VPS sends to localhost:6006 which tunnels to your laptop

Enable tracing:
    CFAI_TRACING=1                   # required
    CFAI_PHOENIX_URL=http://localhost:6006  # default, override if needed
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

    # ── 1. Import OTel packages (no phoenix/pandas needed on VPS) ─────────
    try:
        from opentelemetry import trace as otel_trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    except ImportError:
        log.warning(
            'OTel packages not found. Install on VPS:\n'
            '  pip3 install --break-system-packages \\\n'
            '      opentelemetry-sdk \\\n'
            '      opentelemetry-exporter-otlp-proto-http \\\n'
            '      openinference-instrumentation-openai \\\n'
            '      openinference-instrumentation-anthropic'
        )
        return False

    # ── 2. Resolve Phoenix URL (env var or default) ────────────────────────
    _phoenix_url = os.environ.get('CFAI_PHOENIX_URL', 'http://localhost:6006')

    # ── 3. Wire OTel provider → Phoenix OTLP endpoint ─────────────────────
    endpoint = _phoenix_url.rstrip('/') + '/v1/traces'
    provider = TracerProvider()
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
    )
    otel_trace.set_tracer_provider(provider)
    log.info(f'Tracing → {endpoint}')

    # ── 4. Auto-instrument AI provider SDKs ───────────────────────────────
    try:
        from openinference.instrumentation.openai import OpenAIInstrumentor
        OpenAIInstrumentor().instrument(tracer_provider=provider)
    except ImportError:
        pass

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


def set_ok(s):
    """Mark span as OK (successful completion)."""
    if not _enabled:
        return
    try:
        from opentelemetry.trace import StatusCode
        s.set_status(StatusCode.OK)
    except Exception:
        pass


def set_error(s, exc: Exception):
    """Mark span as ERROR with exception details."""
    if not _enabled:
        return
    try:
        from opentelemetry.trace import StatusCode
        s.set_status(StatusCode.ERROR, str(exc))
        s.record_exception(exc)
    except Exception:
        pass


class _NullSpan:
    def __enter__(self):              return self
    def __exit__(self, *_):           pass
    def set_attribute(self, *_):      pass
    def set_status(self, *_):         pass
    def record_exception(self, *_):   pass
