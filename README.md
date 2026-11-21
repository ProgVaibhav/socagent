# socagent

Companion code for **AI Agents for Security Operations: Building Secure, Evidence-Grounded SOC Agents with Python** by Vaibhav Gondaliya.

A small, readable, model-agnostic SOC triage agent in Python. It computes facts in code, fences off attacker-controlled text, reasons with a model, checks every claim against the tool calls that actually happened, lets deterministic guardrails have the last word, and routes every action through a human.

The book's text refers to the tag **`v1.0.0`**. Check it out to get code that matches the printed listings exactly.

## Quick start

```bash
git clone https://github.com/ProgVaibhav/socagent && cd socagent
git checkout v1.0.0
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                               # 96 tests, no API key needed
python examples/phishing_demo.py     # offline replay of a full investigation
python examples/run_evaluation.py    # measured results on the 50-case golden set
```

Tested with Python 3.13, Pydantic 2.14 and pytest 9.2, from a fresh clone with no network access beyond the package install.

Use a real model (any OpenAI-compatible endpoint, hosted or local):

```bash
export LLM_MODEL=your-model-name
export LLM_BASE_URL=http://localhost:11434/v1   # e.g. a local server
export LLM_API_KEY=...
python examples/phishing_demo.py
python examples/run_evaluation.py --agent       # adds configuration D: your model
```

Run the triage service (refuses to start without a strong token):

```bash
export TRIAGE_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
python examples/service.py
```

## Layout

| Path | Chapter | What it is |
|---|---|---|
| `socagent/schemas.py` | 4 | `Evidence`, `TriageResult`; ATT&CK validation; code-only evidence sources |
| `socagent/llm.py` | 4 | `ModelClient`, `ScriptedModel`, `OpenAICompatibleModel`, `ModelError`, transient-only retries |
| `socagent/tools/registry.py` | 5 | `Tool`, `ToolRegistry`, permission tiers |
| `socagent/tools/intel.py` | 5 | IP / domain / hash reputation (lab fixture) |
| `socagent/rag.py` | 6 | Runbook chunking, versions, tenant scoping, relevance threshold |
| `socagent/agent.py` | 7 | Agent loop: failure boundary, limits, provenance checks, audit-before-act |
| `socagent/reviewer.py` | 7 | Deterministic and model-based review of a verdict |
| `socagent/tools/email_tools.py`, `phishing.py` | 8 | Email parsing (trusted authserv-id), lookalikes and combosquatting, trusted/untrusted prompt, guardrails |
| `socagent/tools/endpoint.py` | 9 | Process trees (observed vs suspected ATT&CK), PowerShell decoding, per-user travel and MFA, inbox rules |
| `socagent/tools/correlation.py` | 9 | Related alerts and incident timelines, tenant-bound |
| `socagent/approval.py`, `respond.py` | 10 | Approval policy, target normalisation, `ChatApprover`, deterministic response gate, case notes |
| `socagent/guards.py`, `render.py`, `audit.py` | 11 | Spotlighting, injection signals, `safe_md`, hash-chained audit with signed checkpoints |
| `socagent/evaluate.py`, `baseline.py` | 12 | Safe coverage, automated recall, critical misses, miss-rate bounds, rules baselines |
| `socagent/service.py`, `jobs.py`, `integrations/xsoar/` | 13 | Fail-closed async service and Cortex XSOAR automation |
| `socagent/tools/cloud.py` | 14 | CloudTrail event scoring, OAuth consent scoring |
| `socagent/tenancy.py` | 15 | Tenant context, tenant-keyed cache, per-tenant budgets |
| `data/golden/` | 6, 12 | 50-case phishing golden set, retrieval cases, recorded results |
| `data/redteam/injection_corpus.jsonl` | 11 | Prompt-injection payloads across email fields |
| `tests/unit`, `tests/security`, `tests/evaluation` | all | 96 tests |

## Safety defaults

- Triage agents see read-only tools only; exposure is enforced again at execution time.
- Containment and protected targets always need a human. No configuration turns that off.
- Any failure, outage, limit or doubt ends in `needs_human`, never `benign`. The agent never raises.
- Evidence must point at tool calls that happened in the run; `guardrail`, `reviewer` and `agent` sources are reserved for code.
- Nothing runs unless its intent was written to the audit log first.
- Model-reported confidence is labelled as such and never qualifies an action on its own.
- The service refuses to start without a token of at least 32 characters, unless explicitly in local-only mode on 127.0.0.1.
- All lab data is synthetic. Never commit real alerts, emails or credentials.

## Security policy

This is teaching code. It is deliberately small and readable, and it is not a hardened product. If you find a vulnerability in the code as published, please report it privately through GitHub's "Report a vulnerability" feature on this repository rather than opening a public issue. Please do not include real customer data in reports.

## Licence

MIT for the code (see `LICENSE`). The book text is © Vaibhav Gondaliya, all rights reserved.
