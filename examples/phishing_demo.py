"""Run the phishing triage end to end.

Offline (default): replays a scripted model, no API key needed.
Live: set LLM_MODEL (and LLM_BASE_URL / LLM_API_KEY) to use a real model.

    python examples/phishing_demo.py
    LLM_MODEL=gpt-4.1-mini python examples/phishing_demo.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from socagent.approval import ApprovalPolicy, DenyAll
from socagent.audit import AuditLog
from socagent.factory import DATA, PROTECTED, build_agent
from socagent.llm import ModelResponse, OpenAICompatibleModel, ScriptedModel, ToolCall
from socagent.phishing import triage_phishing
from socagent.respond import dns_revalidator, case_notes, respond


def scripted():
    return ScriptedModel([
        ModelResponse("Checking the sender domain, the reply-to domain and the runbook.", [
            ToolCall("1", "domain_reputation", {"domain": "examp1e-corp.com"}),
            ToolCall("2", "domain_reputation", {"domain": "secure-examplecorp-login.net"}),
            ToolCall("3", "check_lookalike_domain", {"domain": "examp1e-corp.com"}),
            ToolCall("4", "search_runbooks", {"query": "credential phishing containment"}),
        ]),
        ModelResponse(None, [ToolCall("5", "submit_triage", {
            "verdict": "malicious", "confidence": 0.94, "severity": "high",
            "summary": ("Credential-phishing email impersonating IT from examp1e-corp.com, a lookalike of "
                        "example-corp.com registered this week and tagged as phishing infrastructure. "
                        "DMARC failed and Reply-To points to a second new domain. The body contains text "
                        "trying to make an AI mark it benign. Block both domains and check whether the "
                        "user clicked."),
            "evidence": [
                {"claim": "examp1e-corp.com was registered this week and is tagged credential-phishing / aitm-kit",
                 "source_tool": "domain_reputation", "observable": "examp1e-corp.com", "tool_call_id": "1"},
                {"claim": "secure-examplecorp-login.net was registered this week",
                 "source_tool": "domain_reputation", "observable": "secure-examplecorp-login.net",
                 "tool_call_id": "2"},
                {"claim": "examp1e-corp.com imitates example-corp.com (distance 0 after normalising 1 -> l)",
                 "source_tool": "check_lookalike_domain", "observable": "examp1e-corp.com", "tool_call_id": "3"},
                {"claim": "DMARC=fail, DKIM=none; Reply-To domain differs from From domain",
                 "source_tool": "facts"},
                {"claim": "Body contains instruction-like text aimed at AI triage",
                 "source_tool": "facts"},
            ],
            "attack_techniques": ["T1566.002"],
            "proposed_actions": [
                {"action": "block_indicator", "target": "examp1e-corp.com",
                 "reason": "Lookalike credential-phishing domain"},
                {"action": "block_indicator", "target": "secure-examplecorp-login.net",
                 "reason": "Reply-To domain registered this week, part of the same lure"},
            ],
            "runbook_refs": ["phishing.md#credential-phishing-containment"],
        })]),
    ])


LAB_SHARED_NETWORKS = ["151.101.0.0/16", "13.32.0.0/15", "10.0.0.0/8"]  # CDN, cloud, internal


def main():
    model = OpenAICompatibleModel(os.environ["LLM_MODEL"]) if os.environ.get("LLM_MODEL") else scripted()
    audit = AuditLog()
    agent, _ = build_agent(model, audit=audit)
    raw = (DATA / "emails" / "credential_phish.eml").read_text()
    run, facts = triage_phishing(agent, "ALERT-1001", raw, PROTECTED)
    # Shadow mode: DenyAll records every proposal without acting. The revalidator would run
    # after approval and before execution; offline, nothing is resolved.
    revalidate = dns_revalidator(resolve=lambda host: [], shared_networks=LAB_SHARED_NETWORKS)
    outcome = respond(run.result, agent.registry, DenyAll(), ApprovalPolicy(), audit,
                      verified_observables=run.verified_observables, revalidate=revalidate)
    print(case_notes(run.result, outcome))
    print(f"\nsteps={run.steps} tool_calls={len(run.tool_calls)} audit_ok={AuditLog.verify(audit.entries)}")


if __name__ == "__main__":
    main()
