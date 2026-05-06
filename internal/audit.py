"""CF_AI audit trail — records every CLI action to the dashboard log stream."""
import threading
from collections import deque
from datetime import datetime
from typing import Optional
from util import now_iso, truncate


class AuditRecord:
    def __init__(self, kind: str, command: str, output: str = '',
                 site_id: str = '', duration: float = 0.0):
        self.kind      = kind        # command | scan | agent | fix | chat
        self.command   = command
        self.output    = output
        self.site_id   = site_id
        self.duration  = duration
        self.timestamp = now_iso()

    def to_dict(self) -> dict:
        return {
            'kind':      self.kind,
            'command':   self.command,
            'output':    truncate(self.output, 500),
            'site_id':   self.site_id,
            'duration':  self.duration,
            'timestamp': self.timestamp,
        }


class AuditLog:
    """In-memory audit ring buffer + optional dashboard push."""

    MAX_ENTRIES = 500

    def __init__(self):
        self._buf:    deque             = deque(maxlen=self.MAX_ENTRIES)
        self._lock    = threading.Lock()
        self._client  = None  # lazy

    def _get_client(self):
        if self._client is None:
            try:
                from internal.endpoints import get_client
                self._client = get_client()
            except Exception:
                pass
        return self._client

    def record(self, kind: str, command: str, output: str = '',
               site_id: str = '', duration: float = 0.0) -> AuditRecord:
        rec = AuditRecord(kind, command, output, site_id, duration)
        with self._lock:
            self._buf.append(rec)
        # Fire-and-forget push to dashboard log queue
        self._push(rec)
        return rec

    def _push(self, rec: AuditRecord):
        client = self._get_client()
        if not client:
            return
        try:
            client.execute(f'# audit: {rec.command}', use_cache=False)
        except Exception:
            pass

    def history(self, n: int = 50) -> list:
        with self._lock:
            return [r.to_dict() for r in list(self._buf)[-n:]]

    def commands(self, n: int = 50) -> list:
        with self._lock:
            return [r.command for r in list(self._buf)[-n:]
                    if r.kind == 'command']


_log: Optional[AuditLog] = None


def get_audit() -> AuditLog:
    global _log
    if _log is None:
        _log = AuditLog()
    return _log
