"""Cloud and SaaS analysis tools (Chapter 14).

Each function inspects one event or grant and returns findings with ATT&CK
technique IDs. Event shapes follow AWS CloudTrail and Microsoft Entra ID
OAuth consent records, simplified for the lab.
"""
from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from .registry import Tool

# CloudTrail eventName -> (finding, ATT&CK, weight)
RISKY_API = {
    "StopLogging": ("CloudTrail logging stopped", "T1562.008", 4),
    "DeleteTrail": ("CloudTrail trail deleted", "T1562.008", 4),
    "UpdateTrail": ("CloudTrail trail modified", "T1562.008", 2),
    "PutEventSelectors": ("CloudTrail event selectors changed", "T1562.008", 2),
    "CreateAccessKey": ("New long-lived access key created", "T1098.001", 2),
    "CreateUser": ("New IAM user created", "T1136.003", 2),
    "AttachUserPolicy": ("Policy attached directly to a user", "T1098", 2),
    "PutUserPolicy": ("Inline policy added to a user", "T1098", 2),
    "CreateLoginProfile": ("Console password set for a user", "T1098", 2),
    "PutBucketPolicy": ("S3 bucket policy changed", "T1530", 1),
    "PutBucketAcl": ("S3 bucket ACL changed", "T1530", 1),
    "DeletePublicAccessBlock": ("S3 Block Public Access removed", "T1530", 3),
    "ModifySnapshotAttribute": ("EBS snapshot sharing changed", "T1537", 3),
}
ADMIN_POLICIES = {"arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::aws:policy/IAMFullAccess"}


class TrailArgs(BaseModel):
    event: dict[str, Any] = Field(description="One CloudTrail record")


def analyze_cloudtrail_event(event: dict[str, Any]) -> dict[str, Any]:
    name = event.get("eventName", "")
    params = event.get("requestParameters") or {}
    ident = event.get("userIdentity") or {}
    findings = []
    if name in RISKY_API:
        what, tech, w = RISKY_API[name]
        findings.append({"finding": what, "attack": tech, "weight": w})
    if name in ("AttachUserPolicy", "AttachRolePolicy") and params.get("policyArn") in ADMIN_POLICIES:
        findings.append({"finding": f"Administrator policy attached: {params['policyArn']}",
                         "attack": "T1098", "weight": 3})
    if name in ("PutBucketPolicy",) and '"Principal":"*"' in json.dumps(params.get("bucketPolicy", {})).replace(" ", ""):
        findings.append({"finding": "Bucket policy grants access to everyone (Principal *)",
                         "attack": "T1530", "weight": 3})
    if name == "ConsoleLogin":
        mfa = (event.get("additionalEventData") or {}).get("MFAUsed")
        if ident.get("type") == "Root":
            findings.append({"finding": "Root account console sign-in", "attack": "T1078.004", "weight": 3})
        if mfa == "No":
            findings.append({"finding": "Console sign-in without MFA", "attack": "T1078.004", "weight": 2})
    if event.get("errorCode") in ("AccessDenied", "Client.UnauthorizedOperation"):
        findings.append({"finding": "Call was denied (possible permission probing)", "attack": None, "weight": 1})
    score = sum(f["weight"] for f in findings)
    return {"event": name, "actor": ident.get("arn") or ident.get("userName"),
            "source_ip": event.get("sourceIPAddress"), "findings": findings, "risk_score": score,
            "assessment": "high" if score >= 4 else "medium" if score >= 2 else "low"}


# OAuth scopes that let an app read or send mail, read files, or act broadly.
HIGH_RISK_SCOPES = {"Mail.Read", "Mail.ReadWrite", "Mail.Send", "Files.Read.All", "Files.ReadWrite.All",
                    "Sites.Read.All", "Directory.ReadWrite.All", "offline_access", "full_access_as_user"}


class ConsentArgs(BaseModel):
    app_name: str
    publisher_verified: bool
    scopes: list[str]
    app_age_days: int = Field(ge=0)
    tenant_users_consented: int = Field(ge=0)


def score_oauth_consent(app_name: str, publisher_verified: bool, scopes: list[str],
                        app_age_days: int, tenant_users_consented: int) -> dict[str, Any]:
    risky = sorted(set(scopes) & HIGH_RISK_SCOPES)
    reasons, score = [], 0
    if risky:
        reasons.append(f"high-risk scopes {risky}"); score += 2 + len(risky) // 2
    if not publisher_verified:
        reasons.append("publisher not verified"); score += 2
    if app_age_days < 30:
        reasons.append(f"app registered {app_age_days} days ago"); score += 2
    if tenant_users_consented <= 2:
        reasons.append("almost no one else in the tenant uses this app"); score += 1
    if "offline_access" in scopes and risky:
        reasons.append("offline_access keeps access after password reset"); score += 1
    return {"app": app_name, "risk_score": score, "reasons": reasons,
            "assessment": "high" if score >= 6 else "medium" if score >= 3 else "low",
            "attack": "T1528" if score >= 6 else None,
            "note": "Revoking the grant, not resetting the password, removes an app's access."}


def make_cloud_tools() -> list[Tool]:
    return [
        Tool("analyze_cloudtrail_event", "Score one AWS CloudTrail event for defence evasion, persistence "
             "and exposure, with ATT&CK IDs.", TrailArgs, analyze_cloudtrail_event),
        Tool("score_oauth_consent", "Score an OAuth app consent grant for consent phishing risk.",
             ConsentArgs, score_oauth_consent),
    ]
