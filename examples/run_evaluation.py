"""Chapter 12: evaluate triage configurations on the 50-case golden set.

    python examples/run_evaluation.py            # rules baselines + guardrail stress test
    LLM_MODEL=... python examples/run_evaluation.py --agent   # also evaluate a real model
"""
import json
import os
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from socagent.baseline import triage_rules
from socagent.evaluate import Case, evaluate
from socagent.factory import DATA, PROTECTED, build_agent
from socagent.llm import ModelResponse, OpenAICompatibleModel, ScriptedModel, ToolCall
from socagent.phishing import is_simulation, triage_phishing
from socagent.schemas import Verdict
from socagent.tools.intel import IntelSource

TODAY = date(2026, 11, 20)
ROWS = [json.loads(l) for l in (DATA / "golden" / "phishing_cases.jsonl").read_text().splitlines()]
CASES = [Case(r["alert_id"], Verdict(r["expected"]), r["raw_email"]) for r in ROWS]
intel = IntelSource()


def hijacked(case):
    """Worst case: a model that ALWAYS answers benign (fully hijacked). Only guardrails remain."""
    if is_simulation(case.payload):
        return triage_rules(case.alert_id, case.payload, PROTECTED, intel, TODAY)
    submit = {"verdict": "benign", "confidence": 0.95, "severity": "low",
              "summary": "Routine email, nothing suspicious found by the model.",
              "evidence": [{"claim": "model judged routine", "source_tool": "facts"}]}
    agent, _ = build_agent(ScriptedModel([ModelResponse(None, [ToolCall("1", "submit_triage", submit)])]))
    return triage_phishing(agent, case.alert_id, case.payload, PROTECTED, intel)[0].result


def real_agent(case):
    if is_simulation(case.payload):
        return triage_rules(case.alert_id, case.payload, PROTECTED, intel, TODAY)
    agent, _ = build_agent(OpenAICompatibleModel(os.environ["LLM_MODEL"]))
    return triage_phishing(agent, case.alert_id, case.payload, PROTECTED, intel)[0].result


CONFIGS = {
    "A. Rules baseline (playbook)": lambda c: triage_rules(c.alert_id, c.payload, PROTECTED, intel, TODAY),
    "B. Rules + escalate unknown domains": lambda c: triage_rules(c.alert_id, c.payload, PROTECTED, intel,
                                                                  TODAY, escalate_unknown=True),
    "C. Hijacked model + guardrails": hijacked,
}
if "--agent" in sys.argv:
    CONFIGS["D. Agent (" + os.environ.get("LLM_MODEL", "?") + ")"] = real_agent

results = {}
for name, fn in CONFIGS.items():
    rep = evaluate(CASES, fn)
    results[name] = {"precision": round(rep.precision, 3), "automated_recall": round(rep.automated_recall, 3),
                     "safe_coverage": round(rep.safe_coverage, 3), "recall": round(rep.safe_coverage, 3),
                     "escalation_rate": round(rep.escalation_rate, 3),
                     "miss_rate_upper95": round(rep.miss_rate_upper95, 3),
                     "critical_misses": rep.critical_misses, "false_alarms": rep.false_alarms,
                     "passes_gate": rep.passes()}
    print(f"{name:40s} {rep.render()}  gate={'PASS' if rep.passes() else 'FAIL'}")
    for m in rep.critical_misses:
        print(f"    miss: {m}")
(DATA / "golden" / "results.json").write_text(json.dumps(results, indent=2))
