"""The agent loop, written by hand so nothing is hidden.

perceive -> reason -> act -> verify, with hard limits on steps, tool calls,
tokens and wall-clock time, a permission check on every tool call, evidence
provenance checks, and a single validated exit: the `submit_triage` tool.

Failure contract: `run()` never raises and never returns `benign` because of
a failure. Any exception (provider outage, malformed response, audit outage,
approver outage, bug) ends the run as `needs_human` with the reason recorded.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from .approval import ApprovalPolicy, ApprovalRequest, Approver, DenyAll
from .audit import AuditLog
from .guards import truncate
from .llm import ModelClient, ModelError
from .schemas import (CODE_ONLY_SOURCES, MODEL_STATIC_SOURCES, Evidence, Severity,
                      TriageResult, Verdict)
from .tools.registry import Permission, ToolRegistry

SUBMIT = "submit_triage"
RUNBOOK_TOOL = "search_runbooks"


class AuditUnavailable(RuntimeError):
    """Raised when the audit trail cannot be written. Nothing proceeds unaudited."""


@dataclass
class AgentRun:
    result: TriageResult
    steps: int
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    stopped_because: str = "submitted"
    retrieved_runbooks: set[str] = field(default_factory=set)


class Agent:
    def __init__(
        self,
        model: ModelClient,
        registry: ToolRegistry,
        approver: Approver | None = None,
        policy: ApprovalPolicy | None = None,
        audit: AuditLog | None = None,
        max_steps: int = 12,
        max_tool_calls: int = 25,
        token_budget: int = 150_000,
        max_seconds: float = 300.0,
        expose_up_to: Permission = Permission.READ,
        tenant_id: str | None = None,
    ):
        self.model = model
        self.registry = registry
        self.approver = approver or DenyAll()
        self.policy = policy or ApprovalPolicy()
        self.audit = audit or AuditLog()
        self.max_steps = max_steps
        self.max_tool_calls = max_tool_calls
        self.token_budget = token_budget
        self.max_seconds = max_seconds
        self.expose_up_to = expose_up_to  # triage agents see read-only tools by default
        self.tenant_id = tenant_id

    def _tool_specs(self) -> list[dict[str, Any]]:
        submit_schema = TriageResult.model_json_schema()
        submit_schema.pop("title", None)
        return self.registry.specs(self.expose_up_to) + [{
            "name": SUBMIT,
            "description": ("Finish the investigation. Call exactly once. Every evidence item must cite "
                            "'facts' or a tool you called, with that call's tool_call_id."),
            "parameters": submit_schema,
        }]

    # -- public entry point: the failure boundary -----------------------------
    def run(self, alert_id: str, system: str, user: str) -> AgentRun:
        run = AgentRun(result=_fallback(alert_id, "not started"), steps=0)
        try:
            return self._run(run, alert_id, system, user)
        except ModelError as e:
            return self._stop(run, alert_id, f"model unavailable ({e.kind})")
        except AuditUnavailable:
            return self._stop(run, alert_id, "audit trail unavailable", log=False)
        except Exception as e:  # any bug or unexpected failure: fail safe, never raise
            return self._stop(run, alert_id, f"internal error ({type(e).__name__})")

    def _audit(self, event: str, **data: Any) -> None:
        try:
            self.audit.log(event, tenant_id=self.tenant_id, **data)
        except Exception as e:
            raise AuditUnavailable(str(e)) from e

    def _run(self, run: AgentRun, alert_id: str, system: str, user: str) -> AgentRun:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        tools = self._tool_specs()
        deadline = time.monotonic() + self.max_seconds
        self._audit("run_start", alert_id=alert_id)

        for step in range(1, self.max_steps + 1):
            run.steps = step
            if time.monotonic() > deadline:
                return self._stop(run, alert_id, "time limit reached")
            resp = self.model.complete(messages, tools)          # may raise ModelError
            run.input_tokens += max(0, int(resp.input_tokens or 0))
            run.output_tokens += max(0, int(resp.output_tokens or 0))
            self._audit("model_response", step=step, content=truncate(resp.content or "", 2000),
                        tool_calls=[c.name for c in resp.tool_calls])

            if run.input_tokens + run.output_tokens > self.token_budget:
                return self._stop(run, alert_id, "token budget exceeded")

            if not resp.tool_calls:
                messages.append({"role": "assistant", "content": resp.content or ""})
                messages.append({"role": "user", "content":
                                 f"Continue the investigation. You must finish by calling {SUBMIT}."})
                continue

            messages.append({"role": "assistant", "content": resp.content,
                             "tool_calls": [c.__dict__ for c in resp.tool_calls]})

            for call in resp.tool_calls:
                if call.name == SUBMIT:
                    outcome = self._try_submit(alert_id, call.arguments, run)
                    if isinstance(outcome, TriageResult):
                        run.result = outcome
                        self._audit("submitted", verdict=outcome.verdict.value,
                                    model_confidence=outcome.confidence)
                        return run
                    messages.append({"role": "tool", "tool_call_id": call.id, "content": outcome})
                    continue

                if len(run.tool_calls) >= self.max_tool_calls:
                    return self._stop(run, alert_id, "tool-call limit reached")

                output = self._execute(alert_id, call.name, call.arguments)
                run.tool_calls.append({"id": call.id, "name": call.name,
                                       "arguments": call.arguments, "output": output})
                if call.name == RUNBOOK_TOOL and isinstance(output, dict):
                    run.retrieved_runbooks |= {r["id"] for r in output.get("results", [])}
                messages.append({"role": "tool", "tool_call_id": call.id,
                                 "content": truncate(json.dumps(output, default=str))})

        return self._stop(run, alert_id, "step limit reached")

    # -- internals -------------------------------------------------------------
    def _execute(self, alert_id: str, name: str, arguments: dict[str, Any]) -> Any:
        tool = self.registry.get(name)
        if tool is None or tool.permission > self.expose_up_to:
            self._audit("tool_rejected", tool=name, reason="unknown or not exposed")
            return {"error": f"tool '{name}' is not available"}
        if not isinstance(arguments, dict):
            return {"error": "arguments must be a JSON object"}
        if self.policy.needs_human(tool.permission, arguments):
            req = ApprovalRequest(name, arguments, tool.permission, alert_id)
            self._audit("approval_requested", tool=name, arguments=arguments)
            try:
                decision = self.approver.decide(req)
            except Exception as e:                      # approver outage = denied
                self._audit("approval_error", tool=name, error=type(e).__name__)
                return {"status": "denied", "by": "approval-service-unavailable"}
            self._audit("approval", tool=name, arguments=arguments,
                        approved=decision.approved, approver=decision.approver)
            if not decision.approved:
                return {"status": "denied", "by": decision.approver, "comment": decision.comment}
        # Write the intent BEFORE the action: if the audit write fails, the action never runs.
        self._audit("tool_call_start", tool=name, arguments=arguments)
        try:
            output = tool.run(arguments)
        except Exception as e:  # a failing tool must not kill the investigation
            output = {"error": type(e).__name__, "message": str(e)[:300]}
        self._audit("tool_call", tool=name, output=truncate(output, 1000))
        return output

    def _try_submit(self, alert_id: str, arguments: dict[str, Any], run: AgentRun) -> TriageResult | str:
        if not isinstance(arguments, dict):
            return json.dumps({"error": "submission must be a JSON object"})
        arguments = {**arguments, "alert_id": alert_id}  # never trust the model with the ID
        try:
            result = TriageResult.model_validate(arguments)
        except ValidationError as e:
            self._audit("submit_invalid", errors=str(e)[:1000])
            return json.dumps({"error": "invalid submission, fix and resubmit",
                               "details": e.errors(include_url=False)}, default=str)
        problems = self._provenance_problems(result, run)
        unknown = [a.action for a in result.proposed_actions if self.registry.get(a.action) is None]
        if unknown:
            problems.append(f"proposed_actions use unknown tools: {unknown}")
        if problems:
            self._audit("submit_rejected", problems=problems)
            return json.dumps({"error": "submission rejected, fix and resubmit", "problems": problems})
        return result

    @staticmethod
    def _provenance_problems(result: TriageResult, run: AgentRun) -> list[str]:
        """Every claim must point at something that actually happened in this run."""
        calls = {c["id"]: c for c in run.tool_calls}
        problems = []
        for i, ev in enumerate(result.evidence):
            if ev.source_tool in CODE_ONLY_SOURCES:
                problems.append(f"evidence[{i}]: source '{ev.source_tool}' is reserved for code")
            elif ev.source_tool in MODEL_STATIC_SOURCES:
                continue
            else:
                call = calls.get(ev.tool_call_id or "")
                if call is None or call["name"] != ev.source_tool:
                    problems.append(f"evidence[{i}]: no call to '{ev.source_tool}' with "
                                    f"tool_call_id '{ev.tool_call_id}' in this run")
                elif ev.observable and ev.observable.lower() not in json.dumps(
                        [call["arguments"], call["output"]], default=str).lower():
                    problems.append(f"evidence[{i}]: observable '{ev.observable}' does not appear "
                                    f"in call {ev.tool_call_id}")
        stray = [r for r in result.runbook_refs if r not in run.retrieved_runbooks]
        if stray:
            problems.append(f"runbook_refs not returned by search_runbooks in this run: {stray}")
        return problems

    def _stop(self, run: AgentRun, alert_id: str, reason: str, log: bool = True) -> AgentRun:
        run.result = _fallback(alert_id, reason)
        run.stopped_because = reason
        if log:
            try:
                self.audit.log("stopped", tenant_id=self.tenant_id, reason=reason)
            except Exception:
                run.stopped_because = reason + "; audit trail unavailable"
        return run


def _fallback(alert_id: str, reason: str) -> TriageResult:
    """Fail safe: when in doubt, hand it to a human, never call it benign."""
    return TriageResult(
        alert_id=alert_id,
        verdict=Verdict.NEEDS_HUMAN,
        confidence=0.0,
        severity=Severity.MEDIUM,
        summary=f"Automated triage did not complete ({reason}). Routed to an analyst.",
        evidence=[Evidence(claim=f"Agent stopped: {reason}", source_tool="agent")],
    )
