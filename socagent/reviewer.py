"""The reviewer pattern (Chapter 7).

Two layers: a free deterministic check that every observable named in the
summary appears in the evidence, and an optional second-model review.
Either can lower confidence; neither can raise it.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .llm import ModelClient
from .schemas import Evidence, TriageResult, Verdict

OBSERVABLE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"                      # IPv4
    r"|\b[a-f0-9]{64}\b"                                 # SHA-256
    r"|\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|info|biz|xyz|top|ru|cn|in|uk|de)\b",
    re.IGNORECASE,
)

REVIEW_PROMPT = """You are reviewing another analyst's triage. Given the evidence list
and the summary, list every claim in the summary that is not supported by an evidence
item, and say whether the verdict follows from the evidence. Reply with JSON only:
{"unsupported_claims": [...], "verdict_supported": true or false}"""


@dataclass
class Review:
    unsupported_observables: list[str] = field(default_factory=list)
    unsupported_claims: list[str] = field(default_factory=list)
    verdict_supported: bool = True
    error: str | None = None        # reviewer unavailable (timeout, outage, unreadable reply)

    @property
    def clean(self) -> bool:
        return (not (self.unsupported_observables or self.unsupported_claims)
                and self.verdict_supported and self.error is None)


def check_observables(result: TriageResult) -> list[str]:
    evidence_text = " ".join(f"{e.claim} {e.observable or ''}" for e in result.evidence).lower()
    named = {m.group(0).lower() for m in OBSERVABLE.finditer(result.summary)}
    return sorted(o for o in named if o not in evidence_text)


def review(result: TriageResult, model: ModelClient | None = None) -> Review:
    rev = Review(unsupported_observables=check_observables(result))
    if model is not None:
        payload = {"summary": result.summary, "verdict": result.verdict.value,
                   "evidence": [e.model_dump() for e in result.evidence]}
        try:
            resp = model.complete([{"role": "system", "content": REVIEW_PROMPT},
                                   {"role": "user", "content": json.dumps(payload)}])
            data = json.loads(resp.content or "{}")
            if not isinstance(data, dict) or not isinstance(data.get("verdict_supported"), bool):
                raise ValueError("review reply missing verdict_supported")
            rev.unsupported_claims = [str(c) for c in data.get("unsupported_claims", [])][:10]
            rev.verdict_supported = data["verdict_supported"]
        except Exception as e:  # timeout, outage or unreadable reply: never a pass
            rev.error = type(e).__name__
            rev.verdict_supported = False
    return rev


def apply_review(result: TriageResult, rev: Review, penalty: float = 0.25) -> TriageResult:
    """Apply a review. A review can only make the outcome MORE cautious:
    it lowers model-reported confidence, and a failed review of a benign verdict
    sends the case to a human. It never raises confidence or relaxes a verdict."""
    if rev.clean:
        return result
    notes = []
    if rev.unsupported_observables:
        notes.append(f"summary names observables with no evidence: {rev.unsupported_observables}")
    if rev.unsupported_claims:
        notes.append(f"{len(rev.unsupported_claims)} unsupported claim(s)")
    if rev.error:
        notes.append(f"reviewer unavailable ({rev.error})")
    elif not rev.verdict_supported:
        notes.append("reviewer: verdict does not follow from evidence")
    update = {
        "confidence": max(0.0, round(result.confidence - penalty, 2)),
        "evidence": result.evidence + [Evidence(claim="Review: " + "; ".join(notes), source_tool="reviewer")],
    }
    if result.verdict == Verdict.BENIGN:
        update["verdict"] = Verdict.NEEDS_HUMAN   # an unconfirmed "benign" is not closed automatically
    return result.model_copy(update=update)
