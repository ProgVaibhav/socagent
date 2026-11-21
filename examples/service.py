"""Run the triage service (Chapter 13).

    export TRIAGE_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
    LLM_MODEL=... python examples/service.py

The service refuses to start without a token. For local experiments only:
    TRIAGE_INSECURE_LOCAL=1 python examples/service.py   (binds to 127.0.0.1)
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from socagent.audit import AuditLog
from socagent.factory import PROTECTED, build_agent
from socagent.jobs import JobManager
from socagent.llm import OpenAICompatibleModel
from socagent.phishing import triage_phishing
from socagent.service import make_server
from socagent.tools.intel import IntelSource

INTEL = IntelSource()


def run_triage(alert_id: str, raw_email: str) -> dict:
    agent, _ = build_agent(OpenAICompatibleModel(os.environ["LLM_MODEL"]), audit=AuditLog("audit.jsonl"))
    run, _ = triage_phishing(agent, alert_id, raw_email, PROTECTED, INTEL)
    return {"result": run.result.model_dump(mode="json"), "steps": run.steps,
            "stopped_because": run.stopped_because}


if __name__ == "__main__":
    insecure = os.environ.get("TRIAGE_INSECURE_LOCAL") == "1"
    server = make_server(JobManager(run_triage, max_workers=int(os.environ.get("TRIAGE_WORKERS", 4))),
                         token=os.environ.get("TRIAGE_API_TOKEN"),
                         host="127.0.0.1" if insecure else os.environ.get("HOST", "0.0.0.0"),
                         port=int(os.environ.get("PORT", 8080)), allow_insecure_local=insecure)
    server.serve_forever()
