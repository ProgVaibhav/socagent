"""Cortex XSOAR automation script: send a phishing incident to the triage service.

Runs inside XSOAR, where `demisto`, `CommandResults`, `return_results`,
`return_error` and `tableToMarkdown` are provided by CommonServerPython.
Store the service URL and token as script arguments or an XSOAR list,
never hard-code them. Pattern only: adapt field names to your content.
"""
import json
import re
import time

import requests  # available in the standard XSOAR Python docker images


_MD = re.compile(r"([\\`*_{}\[\]()#+!|<>~])")


def _safe(text, limit=2000):
    """Model-written text is attacker-influenced: defang IOCs and escape Markdown before
    it reaches the war room, so it can never render as a link, image or HTML."""
    text = re.sub(r"[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]", " ", str(text))[:limit]
    text = re.sub(r"\bhttp(s?)://", r"hxxp\1[://]", text, flags=re.I)
    text = re.sub(r"\b((?:[a-z0-9-]+\.)+)([a-z]{2,24})\b",
                  lambda m: m.group(1)[:-1].replace(".", "[.]") + "[.]" + m.group(2), text, flags=re.I)
    return _MD.sub(r"\\\1", text)


def main():
    args = demisto.args()
    incident = demisto.incident()
    raw_email = args.get("raw_email") or incident.get("CustomFields", {}).get("emailrawcontent", "")
    if not raw_email:
        return_error("No raw email found on this incident")

    base = args["service_url"].rstrip("/")
    headers = {"Authorization": f"Bearer {args['api_token']}"}
    job = requests.post(base + "/triage", headers=headers, timeout=30,
                        json={"alert_id": str(incident["id"]), "raw_email": raw_email})
    job.raise_for_status()
    job_id = job.json()["job_id"]

    # Poll for the result. For long waits, prefer XSOAR scheduled commands
    # (polling without holding a script runner); this loop keeps the example short.
    deadline = time.time() + int(args.get("timeout", 300))
    while time.time() < deadline:
        status = requests.get(f"{base}/jobs/{job_id}", headers=headers, timeout=30).json()
        if status["status"] in ("done", "failed"):
            break
        time.sleep(5)
    else:
        return_error("AI triage timed out: route this incident to manual triage")
    if status["status"] == "failed":
        return_error("AI triage failed: route this incident to manual triage")
    result = status["result"]

    evidence_rows = [{"Claim": _safe(e["claim"]), "Source": _safe(e["source_tool"])} for e in result["evidence"]]
    action_rows = [{"Action": _safe(a["action"]), "Target": _safe(a["target"]), "Reason": _safe(a["reason"])}
                   for a in result["proposed_actions"]]
    readable = (
        f"### AI triage: {_safe(result['verdict']).upper()} "
        f"(model-reported confidence {float(result['confidence']):.2f})\n"
        f"{_safe(result['summary'])}\n\n"
        + tableToMarkdown("Evidence", evidence_rows)
        + tableToMarkdown("Proposed actions (need analyst approval)", action_rows)
    )
    return_results(CommandResults(
        readable_output=readable,
        outputs_prefix="AITriage",
        outputs_key_field="alert_id",
        outputs=result,
    ))


if __name__ in ("__main__", "__builtin__", "builtins"):
    try:
        main()
    except Exception as e:
        return_error(f"AI triage failed: {e}")
