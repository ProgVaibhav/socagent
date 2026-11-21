"""Asynchronous triage jobs (Chapter 13).

POST returns a job id immediately; the SOAR polls for the result. Jobs are
keyed by (alert_id, payload hash), so a retried request never triages the
same alert twice, and a semaphore caps concurrent model calls.
"""
from __future__ import annotations

import hashlib
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Job:
    id: str
    alert_id: str
    status: str = "queued"          # queued | running | done | failed
    result: dict[str, Any] | None = None
    error: str | None = None


@dataclass
class JobManager:
    run: Callable[[str, str], dict[str, Any]]   # (alert_id, payload) -> result dict
    max_workers: int = 4
    _jobs: dict[str, Job] = field(default_factory=dict)
    _by_key: dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self):
        self._pool = ThreadPoolExecutor(max_workers=self.max_workers)

    def submit(self, alert_id: str, payload: str) -> Job:
        key = alert_id + ":" + hashlib.sha256(payload.encode()).hexdigest()
        with self._lock:
            if key in self._by_key:                    # idempotent retry
                return self._jobs[self._by_key[key]]
            job = Job(id=uuid.uuid4().hex, alert_id=alert_id)
            self._jobs[job.id], self._by_key[key] = job, job.id
        self._pool.submit(self._work, job, payload)
        return job

    def _work(self, job: Job, payload: str) -> None:
        job.status = "running"
        try:
            job.result, job.status = self.run(job.alert_id, payload), "done"
        except Exception as e:                         # never leak internals to the caller
            job.status, job.error = "failed", type(e).__name__

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=True)
