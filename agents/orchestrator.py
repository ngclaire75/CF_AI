"""CF_AI Orchestrator — job queue, scan scheduling, retry logic."""
import json
import time
import uuid
import threading
import logging
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Callable, Any

log = logging.getLogger('cfai.orchestrator')


class JobStatus(str, Enum):
    PENDING   = 'pending'
    RUNNING   = 'running'
    DONE      = 'done'
    FAILED    = 'failed'
    CANCELLED = 'cancelled'


class JobType(str, Enum):
    SCAN     = 'scan'
    RECON    = 'recon'
    AUTOFIX  = 'autofix'
    AI       = 'ai'
    CUSTOM   = 'custom'


@dataclass
class Job:
    id:          str          = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type:        JobType      = JobType.CUSTOM
    site_id:     str          = ''
    params:      dict         = field(default_factory=dict)
    status:      JobStatus    = JobStatus.PENDING
    created_at:  float        = field(default_factory=time.time)
    started_at:  float        = 0.0
    finished_at: float        = 0.0
    retries:     int          = 0
    max_retries: int          = 2
    result:      Any          = None
    error:       str          = ''
    scheduled_for: float      = 0.0   # epoch; 0 = run immediately

    def to_dict(self) -> dict:
        d = asdict(self)
        d['type']   = self.type.value
        d['status'] = self.status.value
        return d


class Orchestrator:
    """Thread-safe job queue with scheduling and retry logic."""

    MAX_WORKERS   = 4
    SCHEDULE_TICK = 15   # seconds between schedule checks

    def __init__(self):
        self._jobs: dict[str, Job]     = {}
        self._queue: list[Job]         = []
        self._lock                     = threading.Lock()
        self._handlers: dict[JobType, Callable] = {}
        self._pool                     = ThreadPoolExecutor(max_workers=self.MAX_WORKERS,
                                                            thread_name_prefix='cfai-worker')
        self._futures: dict[str, Future] = {}
        self._running                  = False
        self._scheduler_thread: threading.Thread | None = None

    # ── Registration ────────────────────────────────────────────────────────

    def register(self, job_type: JobType, handler: Callable):
        """Bind a handler function to a job type."""
        self._handlers[job_type] = handler

    # ── Lifecycle ───────────────────────────────────────────────────────────

    def start(self):
        if self._running:
            return
        self._running = True
        self._scheduler_thread = threading.Thread(
            target=self._scheduler_loop, daemon=True, name='cfai-scheduler'
        )
        self._scheduler_thread.start()
        log.info('Orchestrator started')

    def stop(self):
        self._running = False
        self._pool.shutdown(wait=False)
        log.info('Orchestrator stopped')

    # ── Public API ───────────────────────────────────────────────────────────

    def submit(self, job_type: JobType, site_id: str = '', params: dict | None = None,
               delay_seconds: float = 0, max_retries: int = 2) -> Job:
        job = Job(
            type=job_type,
            site_id=site_id,
            params=params or {},
            max_retries=max_retries,
            scheduled_for=time.time() + delay_seconds if delay_seconds else 0,
        )
        with self._lock:
            self._jobs[job.id] = job
            self._queue.append(job)
        log.info('Submitted job %s type=%s site=%s', job.id, job_type, site_id)
        if not delay_seconds:
            self._dispatch_ready()
        return job

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.status not in (JobStatus.PENDING, JobStatus.RUNNING):
                return False
            job.status = JobStatus.CANCELLED
            future = self._futures.get(job_id)
            if future:
                future.cancel()
        return True

    def get_job(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def list_jobs(self, site_id: str = '', status: JobStatus | None = None) -> list[dict]:
        with self._lock:
            jobs = list(self._jobs.values())
        if site_id:
            jobs = [j for j in jobs if j.site_id == site_id]
        if status:
            jobs = [j for j in jobs if j.status == status]
        return [j.to_dict() for j in sorted(jobs, key=lambda j: j.created_at, reverse=True)]

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values() if j.status == JobStatus.RUNNING)

    # ── Scheduling ──────────────────────────────────────────────────────────

    def schedule_recurring(self, job_type: JobType, site_id: str,
                            params: dict, interval_hours: float = 24.0):
        """Submit a job and re-queue it after completion."""
        def _run_and_reschedule():
            job = self.submit(job_type, site_id=site_id, params=params)
            # Wait for completion
            deadline = time.time() + interval_hours * 3600 * 2
            while time.time() < deadline:
                j = self.get_job(job.id)
                if j and j.status in (JobStatus.DONE, JobStatus.FAILED, JobStatus.CANCELLED):
                    break
                time.sleep(30)
            # Schedule next run
            if self._running:
                self.submit(job_type, site_id=site_id, params=params,
                            delay_seconds=interval_hours * 3600)

        t = threading.Thread(target=_run_and_reschedule, daemon=True)
        t.start()

    # ── Internal ────────────────────────────────────────────────────────────

    def _scheduler_loop(self):
        while self._running:
            self._dispatch_ready()
            time.sleep(self.SCHEDULE_TICK)

    def _dispatch_ready(self):
        now = time.time()
        with self._lock:
            ready = [
                j for j in self._queue
                if j.status == JobStatus.PENDING
                and (j.scheduled_for == 0 or j.scheduled_for <= now)
            ]
        for job in ready:
            self._run_job(job)

    def _run_job(self, job: Job):
        handler = self._handlers.get(job.type)
        if not handler:
            with self._lock:
                job.status  = JobStatus.FAILED
                job.error   = f'No handler registered for job type {job.type}'
            return

        with self._lock:
            job.status     = JobStatus.RUNNING
            job.started_at = time.time()

        future = self._pool.submit(self._execute, job, handler)
        with self._lock:
            self._futures[job.id] = future

    def _execute(self, job: Job, handler: Callable):
        try:
            result = handler(job)
            with self._lock:
                job.status      = JobStatus.DONE
                job.result      = result
                job.finished_at = time.time()
            log.info('Job %s done in %.1fs', job.id, job.finished_at - job.started_at)
        except Exception as exc:
            log.warning('Job %s failed (attempt %d): %s', job.id, job.retries + 1, exc)
            with self._lock:
                job.retries += 1
                if job.retries <= job.max_retries:
                    job.status       = JobStatus.PENDING
                    job.scheduled_for = time.time() + 10 * job.retries  # back-off
                    job.error        = str(exc)
                else:
                    job.status      = JobStatus.FAILED
                    job.error       = str(exc)
                    job.finished_at = time.time()


# Module-level singleton
_orchestrator: Orchestrator | None = None


def get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
        _orchestrator.start()
    return _orchestrator
