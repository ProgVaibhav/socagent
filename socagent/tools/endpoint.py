"""Endpoint and identity analysis tools (Chapter 9).

All deterministic. The model reasons over their output; it does not do
the arithmetic or the pattern matching itself.
"""
from __future__ import annotations

import re

import math
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .registry import Tool

# Living-off-the-land binaries frequently abused after initial access.
# Curated from the LOLBAS project; extend for your environment.
LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "wmic.exe", "cscript.exe", "wscript.exe", "msbuild.exe",
    "installutil.exe", "schtasks.exe",
}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
SUSPICIOUS_ARGS = ["-enc", "-encodedcommand", "frombase64string", "downloadstring", "iex",
                   "-nop", "-w hidden", "urlcache", "/transfer", "javascript:", "scrobj.dll"]


class Process(BaseModel):
    pid: int
    ppid: int
    image: str
    cmdline: str = ""


class TreeArgs(BaseModel):
    processes: list[Process] = Field(min_length=1)


# Behaviour-specific ATT&CK mapping.
#
# A technique is OBSERVED only when the command line itself shows the behaviour the
# technique describes (a remote script handed to mshta, a file fetched by certutil).
# A LOLBin that merely appears with a suspicious-looking argument is SUSPECTED: the
# binary is consistent with the technique, but the telemetry does not prove it.
# Every finding keeps the condition that decided its status ("basis").
_URL = re.compile(r"\b(?:https?|ftp)://", re.IGNORECASE)
_SCRIPT_URI = re.compile(r"\b(?:javascript|vbscript):", re.IGNORECASE)
_USER_WRITABLE = re.compile(r"\\(?:appdata|temp|users\\public|programdata|downloads)\\", re.IGNORECASE)

PROXY_EXEC = {  # System Binary Proxy Execution sub-techniques
    "mshta.exe": "T1218.005", "regsvr32.exe": "T1218.010", "rundll32.exe": "T1218.011",
}


def _technique_for(image: str, cmd: str) -> tuple[str | None, str, str]:
    """(technique, status, basis) for a LOLBin seen with suspicious arguments."""
    if image in ("powershell.exe", "pwsh.exe"):
        # The process is PowerShell and its arguments are in the telemetry: execution is observed.
        return "T1059.001", "observed", "PowerShell process with suspicious arguments"
    if image == "mshta.exe":
        if _URL.search(cmd) or _SCRIPT_URI.search(cmd):
            return "T1218.005", "observed", "mshta given a remote URL or inline script"
        return "T1218.005", "suspected", "mshta with suspicious arguments but no remote or inline script"
    if image == "regsvr32.exe":
        if "scrobj.dll" in cmd and ("/i:" in cmd and _URL.search(cmd)):
            return "T1218.010", "observed", "regsvr32 loading scrobj.dll with a remote /i: scriptlet"
        return "T1218.010", "suspected", "regsvr32 with suspicious arguments but no remote scriptlet"
    if image == "rundll32.exe":
        if _SCRIPT_URI.search(cmd) or _URL.search(cmd) or _USER_WRITABLE.search(cmd):
            return "T1218.011", "observed", "rundll32 running script, a remote path or a DLL from a user-writable folder"
        return "T1218.011", "suspected", "rundll32 with suspicious arguments; DLL location not shown to be abnormal"
    if image == "certutil.exe" and "urlcache" in cmd:
        if _URL.search(cmd):
            return "T1105", "observed", "certutil -urlcache fetching a URL"     # Ingress Tool Transfer
        return "T1105", "suspected", "certutil -urlcache without a visible URL"
    if image == "bitsadmin.exe" and "/transfer" in cmd:
        if _URL.search(cmd):
            return "T1197", "observed", "bitsadmin /transfer with a URL"          # BITS Jobs
        return "T1197", "suspected", "bitsadmin /transfer without a visible URL"
    if image in ("wscript.exe", "cscript.exe"):
        if re.search(r"\.js[e]?\b", cmd):
            return "T1059.007", "observed", "script host running a JScript file"
        if re.search(r"\.vb[se]\b", cmd):
            return "T1059.005", "observed", "script host running a VBScript file"
        return None, "unmapped", "script host without an identifiable script file"
    return None, "unmapped", "no behaviour-specific rule for this binary"


def analyze_process_tree(processes: list[dict[str, Any]]) -> dict[str, Any]:
    procs = {p["pid"]: p for p in processes}
    findings = []
    for p in processes:
        image = p["image"].lower().rsplit("\\", 1)[-1]
        parent = procs.get(p["ppid"])
        parent_image = parent["image"].lower().rsplit("\\", 1)[-1] if parent else None
        cmd = p.get("cmdline", "").lower()
        if parent_image in OFFICE and image in LOLBINS:
            # Suspicious, but T1204.002 needs evidence a user opened a malicious file.
            findings.append({"pid": p["pid"], "finding": f"{parent_image} spawned {image}",
                             "technique": "T1204.002", "status": "suspected",
                             "basis": "Office parent spawned a LOLBin; the opened file has not been examined",
                             "needs": "the document path and its reputation", "weight": 3})
        hits = [a for a in SUSPICIOUS_ARGS if a in cmd]
        if image in LOLBINS and hits:
            tech, status, basis = _technique_for(image, cmd)
            findings.append({"pid": p["pid"], "finding": f"{image} with suspicious arguments {hits}",
                             "technique": tech, "status": status, "basis": basis,
                             # raw evidence, attacker-controlled: keep it, but treat it as untrusted
                             "cmdline": p.get("cmdline", "")[:500],
                             "weight": 2 if status == "observed" else 1})
    score = sum(f["weight"] for f in findings)
    return {"findings": findings, "risk_score": score,
            "observed_techniques": sorted({f["technique"] for f in findings
                                           if f["status"] == "observed" and f["technique"]}),
            "suspected_techniques": sorted({f["technique"] for f in findings if f["status"] == "suspected"}),
            "assessment": "high" if score >= 4 else "medium" if score >= 2 else "low"}


class Login(BaseModel):
    user: str
    time: datetime
    lat: float
    lon: float
    country: str
    ip: str


class TravelArgs(BaseModel):
    logins: list[Login] = Field(min_length=2)
    max_kmh: float = 900.0  # roughly airliner speed
    known_egress_ips: list[str] = Field(default_factory=list)  # corporate VPN / cloud egress


def _haversine_km(a: dict[str, Any], b: dict[str, Any]) -> float:
    r = 6371.0
    p1, p2 = math.radians(a["lat"]), math.radians(b["lat"])
    dp, dl = p2 - p1, math.radians(b["lon"] - a["lon"])
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def impossible_travel(logins: list[dict[str, Any]], max_kmh: float = 900.0,
                      known_egress_ips: list[str] | None = None) -> dict[str, Any]:
    """Compare consecutive sign-ins PER USER. Never pair sign-ins of different users."""
    egress = set(known_egress_ips or [])
    by_user: dict[str, list[dict[str, Any]]] = {}
    for l in logins:
        if l["ip"] not in egress:
            by_user.setdefault(l["user"].lower(), []).append(l)
    pairs = []
    for user, items in by_user.items():
        items.sort(key=lambda x: x["time"])
        for a, b in zip(items, items[1:]):
            km = _haversine_km(a, b)
            hours = max((b["time"] - a["time"]).total_seconds() / 3600, 1 / 60)
            if km / hours > max_kmh:
                pairs.append({"user": user, "from": a["country"], "to": b["country"], "km": round(km),
                              "hours": round(hours, 2), "kmh": round(km / hours)})
    return {"impossible": bool(pairs), "pairs": pairs, "excluded_egress_ips": sorted(egress),
            "note": "VPNs and cloud egress cause false positives; check the IPs' ASN before acting."}


class MfaEvent(BaseModel):
    user: str
    time: datetime
    result: str = Field(pattern="^(approved|denied|timeout)$")
    request_id: str | None = None   # IdP correlation id for the sign-in attempt, if available


class MfaArgs(BaseModel):
    events: list[MfaEvent]
    window_minutes: int = 10
    threshold: int = 5
    grace_minutes: int = 5          # an approval this soon after the burst counts as part of it


def mfa_push_burst(events: list[dict[str, Any]], window_minutes: int = 10, threshold: int = 5,
                   grace_minutes: int = 5) -> dict[str, Any]:
    """Find MFA push bursts PER USER and link an approval only to the burst it follows.

    An approval belongs to a burst when it is for the same user, occurs inside the burst
    window or within `grace_minutes` after its last prompt. The strength of that link is
    reported as `approval_correlation`: "strong" (shared request id), "temporal" (user and
    time only) or "unlinked".
    """
    from datetime import timedelta

    by_user: dict[str, list[dict[str, Any]]] = {}
    for e in events:
        by_user.setdefault(e["user"].lower(), []).append(e)
    bursts = []
    for user, ev in by_user.items():
        ev.sort(key=lambda e: e["time"])
        prompts = [e for e in ev if e["result"] != "approved"]
        best, start = (0, 0, -1), 0
        for end in range(len(prompts)):
            while prompts[end]["time"] - prompts[start]["time"] > timedelta(minutes=window_minutes):
                start += 1
            if end - start + 1 > best[0]:
                best = (end - start + 1, start, end)
        size, s_i, e_i = best
        if size < threshold:
            continue
        first, last = prompts[s_i]["time"], prompts[e_i]["time"]
        ids = {p.get("request_id") for p in prompts[s_i:e_i + 1]} - {None}
        in_window = [a for a in ev if a["result"] == "approved"
                     and first <= a["time"] <= last + timedelta(minutes=grace_minutes)]
        # Correlation quality, strongest first:
        #   strong   - the approval carries a request id that a prompt in this burst also carries
        #   temporal - same user, inside the burst window, but ids are missing on one side
        #   unlinked - no defensible link: both sides have ids and they differ (a different
        #              sign-in attempt), or no approval in the window at all
        strong = [a for a in in_window if ids and a.get("request_id") in ids]
        temporal = [a for a in in_window if not ids or not a.get("request_id")]
        if strong:
            correlation, approval = "strong", strong[0]
        elif temporal:
            correlation, approval = "temporal", temporal[0]
        else:
            correlation, approval = "unlinked", None
        bursts.append({"user": user, "prompts": size, "first": first.isoformat(), "last": last.isoformat(),
                       "approved_after_burst": approval is not None,
                       "approval_correlation": correlation,
                       "approval_time": approval["time"].isoformat() if approval else None})
    worst = max((b["prompts"] for b in bursts), default=0)
    order = {"strong": 2, "temporal": 1, "unlinked": 0}
    best_corr = max((b["approval_correlation"] for b in bursts), key=order.get, default="unlinked")
    return {"bursts": bursts, "burst": bool(bursts), "max_pushes_in_window": worst,
            "approved_after_burst": any(b["approved_after_burst"] for b in bursts),
            "approval_correlation": best_corr,
            "note": ("A 'temporal' link means same user and time window only: do not describe it as "
                     "confirmed approval of the same sign-in attempt." if best_corr == "temporal" else ""),
            "technique": "T1621" if bursts else None}


# --- Mailbox rules (Chapter 9) ------------------------------------------------
FINANCE_WORDS = {"invoice", "payment", "wire", "bank", "remittance", "payroll", "iban", "swift"}
HIDING_FOLDERS = {"rss feeds", "rss subscriptions", "conversation history", "archive", "junk email", "notes"}


class InboxRuleArgs(BaseModel):
    user: str
    rule_name: str = ""
    forward_to: list[str] = Field(default_factory=list)
    redirect_to: list[str] = Field(default_factory=list)
    move_to_folder: str | None = None
    delete: bool = False
    mark_as_read: bool = False
    subject_or_body_contains: list[str] = Field(default_factory=list)
    internal_domains: list[str] = Field(default_factory=list)


def analyze_inbox_rule(user: str, rule_name: str = "", forward_to: list[str] | None = None,
                       redirect_to: list[str] | None = None, move_to_folder: str | None = None,
                       delete: bool = False, mark_as_read: bool = False,
                       subject_or_body_contains: list[str] | None = None,
                       internal_domains: list[str] | None = None) -> dict[str, Any]:
    """Score a new mailbox rule. Rule fields come from the mail platform's audit log.
    Sign-in risk for the session that created it comes from the identity provider."""
    internal = {d.lower() for d in (internal_domains or [])}
    dests = [d.lower() for d in (forward_to or []) + (redirect_to or [])]
    external = [d for d in dests if d.split("@")[-1] not in internal]
    words = {w.lower() for w in (subject_or_body_contains or [])}
    findings, score = [], 0
    if external:
        findings.append({"finding": f"forwards mail to external address(es) {external}",
                         "technique": "T1114.003", "status": "observed"}); score += 3
    hides = delete or (move_to_folder or "").lower() in HIDING_FOLDERS or mark_as_read
    if hides:
        findings.append({"finding": "rule hides matching mail (delete, obscure folder or mark read)",
                         "technique": "T1564.008", "status": "observed"}); score += 2
    if words & FINANCE_WORDS:
        findings.append({"finding": f"matches finance keywords {sorted(words & FINANCE_WORDS)}",
                         "technique": None, "status": "context"}); score += 2
    if len(rule_name.strip()) <= 2:
        findings.append({"finding": "rule name is blank or one or two characters",
                         "technique": None, "status": "context"}); score += 1
    return {"user": user, "findings": findings, "risk_score": score,
            "assessment": "high" if score >= 5 else "medium" if score >= 3 else "low",
            "next_step": "check the identity provider for a risky sign-in on the session that created this rule"}


def make_endpoint_tools() -> list[Tool]:
    return [
        Tool("analyze_process_tree", "Score an EDR process tree for Office-spawned LOLBins and "
             "suspicious command lines.", TreeArgs, analyze_process_tree),
        Tool("impossible_travel", "Detect sign-ins too far apart to be physically possible.",
             TravelArgs, impossible_travel),
        Tool("mfa_push_burst", "Detect MFA push bombing per user and whether an approval followed "
             "that burst.", MfaArgs, mfa_push_burst),
        Tool("analyze_inbox_rule", "Score a new mailbox rule for external forwarding, hiding and "
             "finance targeting.", InboxRuleArgs, analyze_inbox_rule),
    ]


# --- Encoded PowerShell (Chapter 9) ---------------------------------------
import base64 as _b64
import re as _re

_ENC = _re.compile(r"-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{8,})", _re.IGNORECASE)


class DecodeArgs(BaseModel):
    cmdline: str = Field(max_length=20000)


def decode_powershell(cmdline: str) -> dict[str, Any]:
    """Decode -EncodedCommand (base64 of UTF-16LE) for READING only. Never executes."""
    m = _ENC.search(cmdline)
    if not m:
        return {"encoded": False}
    try:
        text = _b64.b64decode(m.group(1)).decode("utf-16-le", errors="replace")
    except Exception:
        return {"encoded": True, "decoded": None, "error": "not valid base64"}
    flags = [k for k in ("downloadstring", "invoke-expression", "iex", "net.webclient",
                         "frombase64string", "invoke-webrequest", "start-process", "bypass")
             if k in text.lower()]
    return {"encoded": True, "decoded": text[:4000], "risky_keywords": flags,
            "note": "Decoded text is attacker-controlled: spotlight it before showing a model."}


def make_decode_tool() -> Tool:
    return Tool("decode_powershell", "Decode a PowerShell -EncodedCommand argument to text "
                "for analysis (never executes it).", DecodeArgs, decode_powershell)
