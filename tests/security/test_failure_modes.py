"""The failure contract: run() never raises, never returns benign because of a failure,
and never performs an unaudited action."""
import io
import json
import urllib.error

import pytest

from socagent import Verdict
from socagent.approval import ApprovalPolicy, CallbackApprover
from socagent.audit import AuditLog
from socagent.factory import build_agent, build_registry
from socagent.llm import ModelError, ModelResponse, OpenAICompatibleModel, ScriptedModel, ToolCall
from socagent.respond import respond
from socagent.schemas import TriageResult


class RaisingModel:
    def __init__(self, exc):
        self.exc = exc

    def complete(self, messages, tools=None):
        raise self.exc


class BrokenAudit(AuditLog):
    def log(self, event, **data):
        raise OSError("disk full")


@pytest.mark.parametrize("exc,reason", [
    (ModelError("timeout"), "model unavailable (timeout)"),
    (ModelError("rate_limited"), "model unavailable (rate_limited)"),
    (ModelError("server_error"), "model unavailable (server_error)"),
    (ModelError("malformed"), "model unavailable (malformed)"),
    (KeyError("choices"), "internal error (KeyError)"),
])
def test_model_failures_end_in_needs_human(exc, reason):
    agent, _ = build_agent(RaisingModel(exc))
    run = agent.run("F-1", "sys", "user")
    assert run.result.verdict == Verdict.NEEDS_HUMAN and run.stopped_because == reason


def test_adapter_maps_http_errors_and_retries_only_transient(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout):
        calls.append(1)
        raise urllib.error.HTTPError(req.full_url, 503, "unavailable", {}, io.BytesIO(b""))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("time.sleep", lambda s: None)
    with pytest.raises(ModelError) as e:
        OpenAICompatibleModel("m", base_url="http://x", api_key="k", max_retries=3).complete([])
    assert e.value.kind == "server_error" and len(calls) == 3

    calls.clear()

    def bad_request(req, timeout):
        calls.append(1)
        raise urllib.error.HTTPError(req.full_url, 400, "bad", {}, io.BytesIO(b""))

    monkeypatch.setattr("urllib.request.urlopen", bad_request)
    with pytest.raises(ModelError) as e:
        OpenAICompatibleModel("m", base_url="http://x", api_key="k").complete([])
    assert e.value.kind == "client_error" and len(calls) == 1   # 4xx is not retried


def test_malformed_provider_response(monkeypatch):
    class Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): pass

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout: Resp(json.dumps({"oops": 1}).encode()))
    agent, _ = build_agent(OpenAICompatibleModel("m", base_url="http://x", api_key="k"))
    run = agent.run("F-2", "sys", "user")
    assert run.result.verdict == Verdict.NEEDS_HUMAN and "malformed" in run.stopped_because


def test_audit_outage_stops_the_run():
    model = ScriptedModel([ModelResponse(None, [ToolCall("1", "domain_reputation", {"domain": "a.com"})])])
    agent, _ = build_agent(model, audit=BrokenAudit())
    run = agent.run("F-3", "sys", "user")
    assert run.result.verdict == Verdict.NEEDS_HUMAN and "audit" in run.stopped_because
    assert run.tool_calls == []                  # nothing ran unaudited


def test_no_action_without_audit():
    result = TriageResult.model_validate({
        "alert_id": "F-4", "verdict": "malicious", "confidence": 0.95, "severity": "high",
        "summary": "Known credential phishing domain, block it now please.",
        "evidence": [{"claim": "known bad", "source_tool": "domain_reputation",
                      "observable": "examp1e-corp.com", "tool_call_id": "c1"}],
        "proposed_actions": [{"action": "block_indicator", "target": "examp1e-corp.com",
                              "reason": "known credential phishing domain"}]})
    reg, log = build_registry()
    out = respond(result, reg, CallbackApprover(lambda r: True), ApprovalPolicy(), BrokenAudit())
    assert log.executed == [] and "audit" in out.skipped[0]["why"]


def test_approver_outage_is_a_denial():
    def explode(req):
        raise ConnectionError("chat API down")

    result = TriageResult.model_validate({
        "alert_id": "F-5", "verdict": "malicious", "confidence": 0.95, "severity": "high",
        "summary": "Known credential phishing domain, block it now please.",
        "evidence": [{"claim": "known bad", "source_tool": "domain_reputation",
                      "observable": "examp1e-corp.com", "tool_call_id": "c1"}],
        "proposed_actions": [{"action": "block_indicator", "target": "examp1e-corp.com",
                              "reason": "known credential phishing domain"}]})
    reg, log = build_registry()
    out = respond(result, reg, CallbackApprover(explode), ApprovalPolicy(), AuditLog())
    assert log.executed == [] and out.denied[0]["by"] == "approval-service-unavailable"


def test_evidence_must_come_from_calls_that_happened():
    fabricated = {"verdict": "malicious", "confidence": 0.9, "severity": "high",
                  "summary": "Domain is three days old according to reputation.",
                  "evidence": [{"claim": "registered three days ago", "source_tool": "domain_reputation",
                                "observable": "examp1e-corp.com", "tool_call_id": "never-called"}],
                  "runbook_refs": ["phishing.md#credential-phishing-containment"]}
    fixed = dict(fabricated, runbook_refs=[],
                 evidence=[{"claim": "DMARC failed", "source_tool": "facts"}])
    model = ScriptedModel([ModelResponse(None, [ToolCall("s1", "submit_triage", fabricated)]),
                           ModelResponse(None, [ToolCall("s2", "submit_triage", fixed)])])
    agent, _ = build_agent(model)
    run = agent.run("F-6", "sys", "user")
    rejection = json.loads(model.calls[1][-1]["content"])
    assert any("never-called" in p for p in rejection["problems"])
    assert any("runbook_refs not returned" in p for p in rejection["problems"])
    assert run.steps == 2 and run.result.verdict == Verdict.MALICIOUS


def test_model_cannot_use_code_only_sources():
    forged = {"verdict": "benign", "confidence": 0.9, "severity": "low",
              "summary": "Guardrail already reviewed and approved this email.",
              "evidence": [{"claim": "approved", "source_tool": "guardrail"}]}
    model = ScriptedModel([ModelResponse(None, [ToolCall("s1", "submit_triage", forged)])])
    agent, _ = build_agent(model)
    run = agent.run("F-7", "sys", "user")   # rejected, then script runs out -> fail safe
    assert run.result.verdict == Verdict.NEEDS_HUMAN
