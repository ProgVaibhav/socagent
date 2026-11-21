"""Core data contracts for the SOC triage agent.

Every object that crosses a trust boundary (model output, tool output,
SOAR input) is validated against one of these models.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    NEEDS_HUMAN = "needs_human"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Alert(BaseModel):
    """A normalised alert, whatever SIEM, EDR or mailbox it came from."""

    id: str
    source: str  # e.g. "phishing_mailbox", "edr", "idp"
    title: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: Severity = Severity.MEDIUM
    entities: dict[str, list[str]] = Field(default_factory=dict)  # {"ip": [...], "user": [...]}
    raw: dict[str, Any] = Field(default_factory=dict)  # untrusted original payload


# Sources only deterministic code may use. The model may cite "facts" (computed
# before the run) or a tool it actually called, never these.
CODE_ONLY_SOURCES = {"guardrail", "reviewer", "agent", "rules", "policy"}
MODEL_STATIC_SOURCES = {"facts", "alert"}


class Evidence(BaseModel):
    """One fact the agent relied on, with where it came from.

    `tool_call_id` links the claim to an entry in the run's execution history.
    The agent loop rejects evidence that names a tool without a matching call,
    or an observable that never appeared in that call's arguments or output.
    """

    claim: str = Field(min_length=3, max_length=500)
    source_tool: str  # "facts", "alert", or the name of a tool that was called
    observable: str | None = None  # the IP/domain/hash it is about
    tool_call_id: str | None = None


class ProposedAction(BaseModel):
    action: str  # must be a registered tool name
    target: str
    reason: str = Field(min_length=10, max_length=500)


def _load_attack_ids() -> dict[str, str]:
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "data" / "attack" / "techniques_subset.json"
    if not path.exists():
        return {}
    return {k: v for k, v in json.loads(path.read_text()).items() if not k.startswith("_")}


ATTACK_IDS = _load_attack_ids()


class TriageResult(BaseModel):
    """The only shape the agent is allowed to finish with."""

    alert_id: str
    verdict: Verdict
    # Model-reported, NOT a calibrated probability. Never gate actions on it alone.
    confidence: float = Field(ge=0.0, le=1.0, description="Model-reported confidence (uncalibrated)")
    severity: Severity
    summary: str = Field(min_length=20, max_length=1500)
    evidence: list[Evidence] = Field(min_length=1)
    attack_techniques: list[str] = Field(default_factory=list)  # e.g. ["T1566.002"]
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    runbook_refs: list[str] = Field(default_factory=list)

    @field_validator("attack_techniques")
    @classmethod
    def _valid_technique_ids(cls, v: list[str]) -> list[str]:
        import re

        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        bad = [t for t in v if not pattern.match(t)]
        if bad:
            raise ValueError(f"not ATT&CK technique IDs: {bad}")
        if ATTACK_IDS:
            unknown = [t for t in v if t not in ATTACK_IDS]
            if unknown:
                raise ValueError(f"technique IDs not in the loaded ATT&CK data: {unknown}")
        return v

    def low_confidence(self, threshold: float = 0.7) -> bool:
        return self.confidence < threshold
