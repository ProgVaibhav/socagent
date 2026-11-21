"""Alert correlation (Chapter 9).

Find alerts that share an entity within a time window, and turn a set of
already-triaged verdicts into an ordered incident timeline. Deterministic:
the model reasons over the timeline; it does not build it.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .registry import Tool

# Primary ATT&CK tactic for the techniques used in this book. Extend from
# MITRE's enterprise STIX bundle in production.
TACTIC = {
    "T1566": "Initial Access", "T1566.001": "Initial Access", "T1566.002": "Initial Access",
    "T1078": "Initial Access", "T1078.004": "Initial Access",
    "T1204.002": "Execution", "T1059.001": "Execution", "T1218": "Defense Evasion",
    "T1621": "Credential Access", "T1110": "Credential Access", "T1528": "Credential Access",
    "T1098": "Persistence", "T1098.001": "Persistence", "T1136.003": "Persistence",
    "T1562.008": "Defense Evasion", "T1114.003": "Collection", "T1530": "Collection",
    "T1537": "Exfiltration",
}
TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Defense Evasion",
                "Credential Access", "Collection", "Exfiltration"]


class AlertStore:
    """In the lab: a JSON file of alerts. In production: a SIEM or SOAR query."""

    def __init__(self, alerts: list[dict[str, Any]]):
        self.alerts = [{**a, "time": _dt(a["time"])} for a in alerts]

    @classmethod
    def from_file(cls, path: str | Path) -> "AlertStore":
        return cls(json.loads(Path(path).read_text()))

    def related(self, entity: str, around: datetime | None = None, hours: int = 24,
                tenant: str | None = None) -> list[dict[str, Any]]:
        entity = entity.lower()
        out = []
        for a in self.alerts:
            if tenant is not None and a.get("tenant") != tenant:
                continue  # an MSSP's alert store holds many customers: never cross them
            values = {v.lower() for vs in a.get("entities", {}).values() for v in vs}
            if entity not in values:
                continue
            if around and abs(a["time"] - around) > timedelta(hours=hours):
                continue
            out.append(a)
        return sorted(out, key=lambda a: a["time"])


def _dt(v: Any) -> datetime:
    return v if isinstance(v, datetime) else datetime.fromisoformat(str(v))


def build_timeline(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """Order alerts, attach tactics, and score the incident."""
    rows = []
    for a in sorted(alerts, key=lambda a: _dt(a["time"])):
        techs = a.get("attack_techniques", [])
        tactics = sorted({TACTIC.get(t, "Unknown") for t in techs},
                         key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99)
        rows.append({"time": _dt(a["time"]).strftime("%Y-%m-%d %H:%M"), "alert_id": a["id"],
                     "title": a["title"], "techniques": techs, "tactics": tactics,
                     "verdict": a.get("verdict")})
    stages = {t for r in rows for t in r["tactics"] if t != "Unknown"}
    # A chain that reaches beyond initial access is worse than any single alert in it.
    escalate = len(stages) >= 3 or {"Credential Access", "Collection"} <= stages
    return {"timeline": rows, "tactics_seen": [t for t in TACTIC_ORDER if t in stages],
            "kill_chain_depth": len(stages),
            "incident_severity": "critical" if escalate else "high" if len(stages) == 2 else "medium"}


class RelatedArgs(BaseModel):
    entity: str = Field(description="User, host, IP or domain to search for")
    hours: int = Field(default=24, ge=1, le=168)


def make_correlation_tools(store: AlertStore, now: datetime | None = None,
                           tenant: str | None = None) -> list[Tool]:
    """`tenant` is bound in code; the model cannot widen the search to other customers."""

    def related_alerts(entity: str, hours: int = 24) -> dict[str, Any]:
        found = store.related(entity, around=now, hours=hours, tenant=tenant)
        return {"entity": entity, "count": len(found),
                "alerts": [{"id": a["id"], "time": a["time"].isoformat(), "source": a["source"],
                            "title": a["title"], "verdict": a.get("verdict"),
                            "attack_techniques": a.get("attack_techniques", [])} for a in found]}

    class TimelineArgs(BaseModel):
        alert_ids: list[str] = Field(min_length=1)

    def incident_timeline(alert_ids: list[str]) -> dict[str, Any]:
        chosen = [a for a in store.alerts if a["id"] in set(alert_ids)
                  and (tenant is None or a.get("tenant") == tenant)]
        return build_timeline(chosen)

    return [
        Tool("related_alerts", "Alerts in the last N hours that share this entity "
             "(id, time, source, title, verdict, ATT&CK).", RelatedArgs, related_alerts),
        Tool("incident_timeline", "Order the given alerts into a timeline with ATT&CK tactics and "
             "an incident severity.", TimelineArgs, incident_timeline),
    ]
