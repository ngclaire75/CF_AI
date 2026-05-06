"""CF_AI Telemetry — OpenTelemetry tracing with graceful degradation."""
import os
import time
import logging
import functools
from typing import Callable, Any

log = logging.getLogger('cfai.telemetry')

ENABLED       = os.environ.get('CFAI_TELEMETRY', '0') == '1'
PHOENIX_URL   = os.environ.get('PHOENIX_COLLECTOR_ENDPOINT', 'http://localhost:6006/v1/traces')
SERVICE_NAME  = os.environ.get('CFAI_SERVICE_NAME', 'cf-ai')

_tracer = None


def _init_tracer():
    """Attempt to initialise OpenTelemetry; returns None if unavailable."""
    global _tracer
    if _tracer is not None:
        return _tracer
    if not ENABLED:
        return None
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        resource = Resource.create({'service.name': SERVICE_NAME})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=PHOENIX_URL)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(SERVICE_NAME)
        log.info('OpenTelemetry tracer initialised → %s', PHOENIX_URL)
        return _tracer
    except ImportError:
        log.debug('opentelemetry-sdk not installed; telemetry disabled')
    except Exception as exc:
        log.debug('Telemetry init failed: %s', exc)
    return None


# ── Span context manager ─────────────────────────────────────────────────────

class Span:
    """Thin wrapper; no-ops when OTel is unavailable."""

    def __init__(self, name: str, attributes: dict | None = None):
        self._name       = name
        self._attributes = attributes or {}
        self._span       = None
        self._ctx        = None
        self._start      = 0.0

    def __enter__(self):
        self._start = time.time()
        tracer = _init_tracer()
        if tracer:
            try:
                self._ctx  = tracer.start_as_current_span(self._name)
                self._span = self._ctx.__enter__()
                for k, v in self._attributes.items():
                    self._span.set_attribute(k, str(v))
            except Exception:
                self._span = None
        return self

    def set_attribute(self, key: str, value: Any):
        if self._span:
            try:
                self._span.set_attribute(key, str(value))
            except Exception:
                pass

    def record_error(self, exc: Exception):
        if self._span:
            try:
                self._span.record_exception(exc)
                from opentelemetry.trace import StatusCode
                self._span.set_status(StatusCode.ERROR, str(exc))
            except Exception:
                pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.time() - self._start
        if self._ctx:
            try:
                self._ctx.__exit__(exc_type, exc_val, exc_tb)
            except Exception:
                pass
        if exc_type is None:
            log.debug('[trace] %s %.2fs', self._name, elapsed)
        else:
            log.debug('[trace] %s %.2fs ERROR=%s', self._name, elapsed, exc_val)
        return False  # do not suppress exceptions


# ── Decorator ────────────────────────────────────────────────────────────────

def traced(span_name: str, **extra_attrs):
    """Decorator that wraps a method in a telemetry span."""
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            attrs = dict(extra_attrs)
            # Capture first non-self arg as 'target' if it's a dict with 'url'
            for a in args[1:]:
                if isinstance(a, dict) and 'url' in a:
                    attrs['target'] = a['url']
                    break
            with Span(span_name, attrs):
                return fn(*args, **kwargs)
        return wrapper
    return decorator


# ── Metrics helpers (counters via log; real metrics need otel-metrics SDK) ───

class Counter:
    """Simple in-memory counter; logs periodically."""
    def __init__(self, name: str):
        self.name  = name
        self._val  = 0
        self._lock = __import__('threading').Lock()

    def inc(self, amount: int = 1):
        with self._lock:
            self._val += amount

    @property
    def value(self) -> int:
        return self._val


_counters: dict[str, Counter] = {}


def counter(name: str) -> Counter:
    if name not in _counters:
        _counters[name] = Counter(name)
    return _counters[name]


def all_metrics() -> dict:
    return {n: c.value for n, c in _counters.items()}


# Pre-defined counters
scans_started  = counter('scans_started')
scans_done     = counter('scans_done')
findings_found = counter('findings_found')
fixes_applied  = counter('fixes_applied')
fixes_blocked  = counter('fixes_blocked')
