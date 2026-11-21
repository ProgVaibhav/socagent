"""HTTP front end for asynchronous triage jobs (Chapter 13).

Fail-closed by design:
  * refuses to start without an API token, unless explicitly in local-only
    development mode AND bound to the loopback interface,
  * constant-time token comparison,
  * strict Content-Type, Content-Length and payload-schema validation,
  * per-client rate limiting,
  * errors never leak internals.
"""
from __future__ import annotations

import hmac
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .jobs import JobManager

MAX_BODY = 1_000_000                       # OWASP LLM06:2026 Unbounded Consumption
ALERT_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class ConfigError(RuntimeError):
    pass


class RateLimiter:
    """Token bucket per client address."""

    def __init__(self, rate_per_min: int = 60, burst: int = 20):
        self.rate, self.burst = rate_per_min / 60.0, burst
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            ok = tokens >= 1
            self._buckets[key] = (tokens - 1 if ok else tokens, now)
            return ok


def make_server(jobs: JobManager, token: str | None = None, host: str = "127.0.0.1", port: int = 8080,
                allow_insecure_local: bool = False, limiter: RateLimiter | None = None,
                tenant_tokens: dict[str, str] | None = None,
                default_tenant: str | None = None) -> ThreadingHTTPServer:
    """Authentication decides the tenant; the request body never does.

    Single-tenant: `token` (one credential), jobs run for `default_tenant`.
    Multi-tenant: `tenant_tokens` maps tenant id -> that tenant's own credential, issued to
    that customer's SOAR. The tenant is whichever credential matched. A body that carries a
    tenant field is rejected like any other unexpected field."""
    if token and tenant_tokens:
        raise ConfigError("use either token or tenant_tokens, not both")
    creds: dict[str, str | None] = dict(tenant_tokens or {})
    if token:
        creds = {default_tenant: token}       # tenant None = single-tenant deployment
    if not creds:
        if not (allow_insecure_local and host in LOOPBACK):
            raise ConfigError("TRIAGE_API_TOKEN is required. Unauthenticated mode is only allowed "
                              "with allow_insecure_local=True on a loopback address.")
    for tenant_id, t in creds.items():
        if not t or len(t) < 32:
            raise ConfigError(f"token for tenant '{tenant_id}' must be at least 32 characters")
    if len(set(creds.values())) != len(creds):
        raise ConfigError("every tenant needs its own token")
    limiter = limiter or RateLimiter()
    expected = {tenant_id: f"Bearer {t}".encode() for tenant_id, t in creds.items()}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # do not echo request lines (may contain ids) to stderr
            pass

        def _authenticate(self) -> tuple[bool, str | None]:
            """(authenticated, tenant). Compares against every credential so timing does not
            reveal which tenants exist."""
            if not expected:
                return True, default_tenant       # loopback dev mode only, enforced above
            got = (self.headers.get("Authorization") or "").encode()
            ok, tenant = False, None
            for tenant_id, cred in expected.items():
                if hmac.compare_digest(got, cred):
                    ok, tenant = True, tenant_id
            return ok, tenant

        def _guard(self) -> bool:
            if not limiter.allow(self.client_address[0]):
                self._send(429, {"error": "rate limited"})
                return False
            ok, self.tenant = self._authenticate()
            if not ok:
                self._send(401, {"error": "unauthorised"})
                return False
            return True

        def do_POST(self):
            if not self._guard():
                return
            if self.path != "/triage":
                return self._send(404, {"error": "not found"})
            if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
                return self._send(415, {"error": "Content-Type must be application/json"})
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self._send(411, {"error": "Content-Length required"})
            if length < 0:
                return self._send(400, {"error": "invalid Content-Length"})
            if length > MAX_BODY:
                return self._send(413, {"error": "payload too large"})
            try:
                body = json.loads(self.rfile.read(length))
            except ValueError:
                return self._send(400, {"error": "invalid JSON"})
            if (not isinstance(body, dict) or set(body) != {"alert_id", "raw_email"}
                    or not isinstance(body["alert_id"], str) or not ALERT_ID.match(body["alert_id"])
                    or not isinstance(body["raw_email"], str) or not body["raw_email"].strip()):
                return self._send(400, {"error": "expected exactly {alert_id, raw_email}"})
            job = jobs.submit(body["alert_id"], body["raw_email"], tenant=self.tenant)
            self._send(202, {"job_id": job.id, "status": job.status})

        def do_GET(self):
            if self.path == "/health":
                return self._send(200, {"ok": True})
            if not self._guard():
                return
            if not self.path.startswith("/jobs/"):
                return self._send(404, {"error": "not found"})
            job = jobs.get(self.path.rsplit("/", 1)[-1])
            if job is None or job.tenant != self.tenant:   # another tenant's job does not exist
                return self._send(404, {"error": "unknown job"})
            payload = {"job_id": job.id, "alert_id": job.alert_id, "status": job.status}
            if job.result:
                payload.update(job.result)
            if job.error:
                payload["error"] = "triage failed; route to manual triage"
            self._send(200, payload)

        def _send(self, code, payload):
            data = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

    return ThreadingHTTPServer((host, port), Handler)
