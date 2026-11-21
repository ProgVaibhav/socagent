"""From verdict to response (Chapter 10).

Triage proposes. This module disposes. An action is only put to a human when
DETERMINISTIC conditions hold; model-reported confidence is recorded but is
never the gate on its own. Every action is audited BEFORE it runs: if the audit
trail cannot be written, the action does not happen.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Callable

from .approval import ApprovalPolicy, ApprovalRequest, Approver, normalise_target
from .audit import AuditLog
from .render import safe_md
from .schemas import TriageResult, Verdict
from .tools.registry import ToolRegistry

ARG_BUILDERS = {
    "isolate_host": lambda a: {"hostname": a.target, "reason": a.reason},
    "revoke_sessions": lambda a: {"username": a.target, "reason": a.reason},
    "block_indicator": lambda a: {"indicator": a.target, "kind": _kind(a.target), "reason": a.reason},
}
ACTIONABLE = {Verdict.MALICIOUS, Verdict.SUSPICIOUS}
# Shared infrastructure that must never be blocked on an agent's proposal (Chapter 10 case study).
NEVER_BLOCK = {"8.8.8.8", "1.1.1.1", "cloudfront.net", "akamaiedge.net", "googleapis.com",
               "office.com", "microsoft.com", "amazonaws.com"}


def _kind(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if value.startswith(("http://", "https://")):
        return "url"
    if len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower()):
        return "sha256"
    return "domain"


@dataclass
class ResponseOutcome:
    executed: list[dict[str, Any]] = field(default_factory=list)
    denied: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)


def supported_targets(result: TriageResult) -> set[str]:
    """Observables backed by tool evidence (provenance was verified by the agent loop)."""
    return {normalise_target(e.observable) for e in result.evidence
            if e.observable and e.source_tool not in ("guardrail", "reviewer", "agent")}


def gate(result: TriageResult, action, min_model_confidence: float) -> str | None:
    """Deterministic reasons NOT to put an action in front of a human. None = proceed."""
    target = normalise_target(action.target)
    if result.verdict not in ACTIONABLE:
        return f"verdict is {result.verdict.value}"
    if target not in supported_targets(result):
        return "target is not an observable in verified evidence"
    if any(target == n or target.endswith("." + n) for n in NEVER_BLOCK):
        return "target is shared infrastructure on the never-block list"
    if result.confidence < min_model_confidence:
        return f"model-reported confidence {result.confidence} below {min_model_confidence}"
    return None


Revalidator = Callable[[str, str], "str | None"]   # (action, target) -> reason to abort, or None


def dns_revalidator(resolve: Callable[[str], list[str]],
                    shared_networks: list[str]) -> Revalidator:
    """Re-check a domain or URL target immediately before acting.

    `resolve` returns the target's current IP addresses. If the name now points into
    shared infrastructure (a CDN, a cloud provider, your own ranges) or no longer resolves,
    an IP-level block would hit the wrong thing, so the action is not executed."""
    nets = [ipaddress.ip_network(n) for n in shared_networks]

    def check(action: str, target: str) -> str | None:
        if _kind(target) not in ("domain", "url"):
            return None
        host = normalise_target(target)
        try:
            ips = [ipaddress.ip_address(i) for i in resolve(host)]
        except Exception:
            return "target could not be re-resolved before execution"
        bad = [str(i) for i in ips if any(i in n for n in nets)]
        if bad:
            return f"target now resolves to shared or internal addresses {bad}"
        return None

    return check


def respond(result: TriageResult, registry: ToolRegistry, approver: Approver,
            policy: ApprovalPolicy, audit: AuditLog, min_model_confidence: float = 0.8,
            revalidate: Revalidator | None = None) -> ResponseOutcome:
    """`revalidate` runs AFTER approval and immediately BEFORE execution: the world can
    change between proposal and action (DNS, DHCP, asset reassignment)."""
    out = ResponseOutcome()
    for action in result.proposed_actions:
        tool = registry.get(action.action)
        if tool is None or action.action not in ARG_BUILDERS:
            out.skipped.append({"action": action.action, "why": "no executor"})
            continue
        why = gate(result, action, min_model_confidence)
        if why:
            out.skipped.append({"action": action.action, "target": action.target, "why": why})
            continue
        args = ARG_BUILDERS[action.action](action)
        try:
            if policy.needs_human(tool.permission, args):
                audit.log("approval_requested", tool=action.action, arguments=args)
                try:
                    decision = approver.decide(ApprovalRequest(action.action, args, tool.permission,
                                                               result.alert_id, rationale=action.reason))
                except Exception as e:  # approval service down: treat as denied
                    audit.log("approval_error", tool=action.action, error=type(e).__name__)
                    out.denied.append({"action": action.action, "target": action.target,
                                       "by": "approval-service-unavailable"})
                    continue
                audit.log("approval", tool=action.action, arguments=args,
                          approved=decision.approved, approver=decision.approver)
                if not decision.approved:
                    out.denied.append({"action": action.action, "target": action.target, "by": decision.approver})
                    continue
            if revalidate is not None:
                try:
                    stale = revalidate(action.action, action.target)
                except Exception:
                    stale = "revalidation failed"
                if stale:
                    audit.log("action_aborted", tool=action.action, arguments=args, reason=stale)
                    out.skipped.append({"action": action.action, "target": action.target,
                                        "why": f"revalidation before execution: {stale}"})
                    continue
            audit.log("action_executing", tool=action.action, arguments=args)   # intent first
        except Exception:
            out.skipped.append({"action": action.action, "target": action.target,
                                "why": "audit trail unavailable; no unaudited actions"})
            continue
        out.executed.append(tool.run(args))
        try:
            audit.log("action_executed", tool=action.action, arguments=args)
        except Exception:
            pass  # the intent record above already exists; alert on audit health separately
    return out


def case_notes(result: TriageResult, outcome: ResponseOutcome | None = None) -> str:
    """Markdown for a war room or ticket. Every model-influenced string goes through safe_md."""
    lines = [
        f"## Automated triage: alert {safe_md(result.alert_id, defang_iocs=False)}",
        f"**Verdict:** {result.verdict.value}  |  **Model-reported confidence:** {result.confidence:.2f}  "
        f"|  **Severity:** {result.severity.value}",
        "", safe_md(result.summary), "", "### Evidence",
    ]
    lines += [f"- {safe_md(e.claim)} _(source: {safe_md(e.source_tool)})_" for e in result.evidence]
    if result.attack_techniques:
        lines += ["", "### MITRE ATT&CK", ", ".join(result.attack_techniques)]
    if result.runbook_refs:
        lines += ["", "### Runbooks followed", ", ".join(safe_md(r, defang_iocs=False) for r in result.runbook_refs)]
    if outcome:
        lines += ["", "### Response"]
        lines += [f"- Executed: {e.get('action')} on {safe_md(e.get('target', ''))}" for e in outcome.executed]
        lines += [f"- Denied by {safe_md(d['by'])}: {d['action']} on {safe_md(d['target'])}" for d in outcome.denied]
        lines += [f"- Not proposed for approval: {s['action']} on {safe_md(s.get('target', ''))} ({s['why']})"
                  for s in outcome.skipped]
    lines += ["", "_Generated by the AI triage agent. Model-reported confidence is not a calibrated "
              "probability. An analyst owns the final decision._"]
    return "\n".join(lines)
