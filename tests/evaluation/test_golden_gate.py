"""Quality gate on the 50-case golden set (Chapter 12). Runs offline on every commit."""
import json
from datetime import date

from socagent.baseline import triage_rules
from socagent.evaluate import Case, evaluate
from socagent.factory import DATA, PROTECTED
from socagent.schemas import Verdict
from socagent.tools.intel import IntelSource


def test_golden_set_quality_gate():
    rows = [json.loads(l) for l in (DATA / "golden" / "phishing_cases.jsonl").read_text().splitlines()]
    assert len(rows) == 50
    intel = IntelSource()
    cases = [Case(r["alert_id"], Verdict(r["expected"]), r["raw_email"]) for r in rows]
    rep = evaluate(cases, lambda c: triage_rules(c.alert_id, c.payload, PROTECTED, intel,
                                                 date(2026, 11, 20), escalate_unknown=True))
    assert rep.critical_misses == [] and rep.safe_coverage == 1.0
    assert rep.passes(max_escalation_rate=0.25)
