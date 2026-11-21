"""Evaluation harness (Chapter 12).

Two different questions, two different numbers:
  * Safe coverage: of the real threats, how many did NOT get closed as benign
    (flagged as a threat OR escalated to a human)? This is the safety number.
  * Automated threat recall: of the real threats, how many did the agent itself
    call malicious or suspicious? This is the usefulness number.
An agent that escalates everything has perfect safe coverage and is useless,
so the quality gate also caps the escalation rate.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Callable

from .schemas import TriageResult, Verdict

POSITIVE = {Verdict.MALICIOUS, Verdict.SUSPICIOUS}


@dataclass
class Case:
    alert_id: str
    expected: Verdict
    payload: str


def miss_rate_upper_bound(misses: int, n: int, z: float = 1.96) -> float:
    """Upper 95% bound on the true critical-miss rate.

    With zero misses this is the classic 'rule of three' (about 3/n). Otherwise the
    Wilson score upper bound. Zero misses in 50 cases still allows a true rate near 6%.
    """
    if n == 0:
        return 1.0
    if misses == 0:
        return min(1.0, 3.0 / n)
    p = misses / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return min(1.0, (centre + margin) / (1 + z * z / n))


@dataclass
class Report:
    total: int
    positives: int
    precision: float               # of automated threat verdicts, how many were right
    automated_recall: float        # threats the agent itself flagged
    safe_coverage: float           # threats flagged OR escalated (not closed as benign)
    escalation_rate: float         # share of ALL alerts routed to a human
    critical_misses: list[str]     # expected malicious/suspicious, predicted benign
    false_alarms: list[str]        # expected benign, predicted malicious/suspicious
    miss_rate_upper95: float
    confusion: dict[tuple[str, str], int]

    @property
    def recall(self) -> float:      # kept for backwards compatibility: means safe coverage
        return self.safe_coverage

    def passes(self, min_safe_coverage: float = 0.95, max_critical_misses: int = 0,
               max_escalation_rate: float = 0.25, min_automated_recall: float = 0.0) -> bool:
        return (self.safe_coverage >= min_safe_coverage
                and len(self.critical_misses) <= max_critical_misses
                and self.escalation_rate <= max_escalation_rate
                and self.automated_recall >= min_automated_recall)

    def render(self) -> str:
        return (f"cases={self.total} precision={self.precision:.2f} automated_recall={self.automated_recall:.2f} "
                f"safe_coverage={self.safe_coverage:.2f} escalated={self.escalation_rate:.0%} "
                f"critical_misses={len(self.critical_misses)} (95% upper bound on miss rate "
                f"{self.miss_rate_upper95:.1%}) false_alarms={len(self.false_alarms)}")


def evaluate(cases: list[Case], triage: Callable[[Case], TriageResult]) -> Report:
    flagged_tp = flagged_fp = escalated = escalated_pos = 0
    misses, alarms = [], []
    confusion: Counter[tuple[str, str]] = Counter()
    positives = sum(1 for c in cases if c.expected in POSITIVE)
    for case in cases:
        got = triage(case).verdict
        confusion[(case.expected.value, got.value)] += 1
        true_pos = case.expected in POSITIVE
        if got == Verdict.NEEDS_HUMAN:
            escalated += 1
            escalated_pos += true_pos
        elif got in POSITIVE:
            if true_pos:
                flagged_tp += 1
            else:
                flagged_fp += 1
                alarms.append(case.alert_id)
        elif true_pos:                       # benign verdict on a real threat
            misses.append(case.alert_id)
    n = len(cases) or 1
    return Report(
        total=len(cases), positives=positives,
        precision=flagged_tp / (flagged_tp + flagged_fp) if flagged_tp + flagged_fp else 1.0,
        automated_recall=flagged_tp / positives if positives else 1.0,
        safe_coverage=(flagged_tp + escalated_pos) / positives if positives else 1.0,
        escalation_rate=escalated / n,
        critical_misses=misses, false_alarms=alarms,
        miss_rate_upper95=miss_rate_upper_bound(len(misses), positives),
        confusion=dict(confusion),
    )
