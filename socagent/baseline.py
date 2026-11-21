"""A rules-only triage baseline (Chapter 12).

No model. Deterministic facts plus threat-intel lookups, scored by rules,
exactly as a classic SOAR playbook would. Every agent you build should be
measured against this: if it cannot beat the playbook, it is not ready.
"""
from __future__ import annotations

import re
from datetime import date
from typing import Any

from .phishing import build_facts, is_simulation
from .schemas import Evidence, Severity, TriageResult, Verdict
from .tools.intel import IntelSource

HASH = re.compile(r"sha256=([a-f0-9]{64})")


def triage_rules(alert_id: str, raw_email: str, protected: list[str], intel: IntelSource,
                 today: date, escalate_unknown: bool = False) -> TriageResult:
    def result(verdict, conf, sev, why, ev):
        return TriageResult(alert_id=alert_id, verdict=verdict, confidence=conf, severity=sev,
                            summary=f"Rules baseline: {why}."[:1500], evidence=ev or
                            [Evidence(claim=why, source_tool="rules")])

    if is_simulation(raw_email):
        return result(Verdict.BENIGN, 0.99, Severity.LOW, "internal phishing simulation", None)
    f = build_facts(raw_email, protected)
    ev: list[Evidence] = []
    if f["injection_signals"]:
        return result(Verdict.NEEDS_HUMAN, 0.5, Severity.MEDIUM,
                      "instruction-like text aimed at automation", None)
    domains = sorted({f["from_domain"], *f["url_domains"]} - {""})
    malicious, young, unknown = [], [], []
    for d in domains:
        rep = intel.lookup("domain", d)
        if rep.get("verdict") == "malicious":
            malicious.append(d)
        if rep.get("created") and (today - date.fromisoformat(rep["created"])).days < 30:
            young.append(d)
        if not rep.get("known"):
            unknown.append(d)
    for sha in HASH.findall(f["body"]):
        if intel.lookup("sha256", sha).get("verdict") == "malicious":
            malicious.append(sha)
    if malicious:
        ev.append(Evidence(claim=f"known malicious: {malicious}", source_tool="intel"))
        return result(Verdict.MALICIOUS, 0.95, Severity.HIGH, "known-malicious indicator", ev)
    if f["lookalikes"]:
        ev.append(Evidence(claim=f"lookalike domains: {[l['domain'] for l in f['lookalikes']]}",
                           source_tool="check_lookalike_domain"))
        return result(Verdict.MALICIOUS, 0.85, Severity.HIGH, "lookalike of a protected domain", ev)
    if young:
        ev.append(Evidence(claim=f"domains under 30 days old: {young}", source_tool="intel"))
        return result(Verdict.SUSPICIOUS, 0.7, Severity.MEDIUM, "newly registered domain", ev)
    if f["dmarc"] == "fail":
        return result(Verdict.SUSPICIOUS, 0.6, Severity.MEDIUM, "DMARC failed", None)
    if escalate_unknown and unknown:
        return result(Verdict.NEEDS_HUMAN, 0.4, Severity.MEDIUM, f"domains unknown to intel: {unknown}", None)
    return result(Verdict.BENIGN, 0.8, Severity.LOW, "no indicators found", None)
