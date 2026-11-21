"""Deterministic email analysis.

Rule of thumb used throughout the book: if plain code can compute a fact
reliably (header parsing, URL extraction, edit distance), compute it in
code and hand the *result* to the model. Never ask the model to parse.
"""
from __future__ import annotations

import email
import re
from email import policy
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from .registry import Permission, Tool

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)

# Characters attackers swap in lookalike domains (a small, illustrative map).
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _registered(domain: str) -> str:
    """Naive registered-domain: last two labels. Use `tldextract` in production."""
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def lookalike_score(candidate: str, protected: list[str]) -> dict[str, Any]:
    cand = _registered(candidate)
    label = cand.split(".")[0].replace("rn", "m").translate(HOMOGLYPHS)
    best: dict[str, Any] = {"domain": candidate, "lookalike_of": None, "distance": None}
    for p in protected:
        if cand == p:
            return {"domain": candidate, "lookalike_of": None, "distance": 0, "is_protected": True}
        p_label = p.split(".")[0]
        d = levenshtein(label, p_label)
        if best["distance"] is None or d < best["distance"]:
            best.update(lookalike_of=p, distance=d)
    best["is_protected"] = False
    # Combosquatting: the protected name embedded with extra words ("example-corp-hr").
    flat = label.replace("-", "")
    combo = next((p for p in protected if p.split(".")[0].replace("-", "") in flat), None)
    if combo and best["distance"] and best["distance"] > 2:
        best.update(lookalike_of=combo, technique="combosquatting")
    best["suspicious"] = (best["distance"] is not None and best["distance"] <= 2) or bool(combo)
    return best


TRUSTED_AUTHSERV_ID = "mx.example-corp.com"   # your own gateway's authserv-id


def parse_email(raw: str, authserv_id: str = TRUSTED_AUTHSERV_ID) -> dict[str, Any]:
    msg = email.message_from_string(raw, policy=policy.default)
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    reply_name, reply_addr = parseaddr(str(msg.get("Reply-To", "")))
    # Only trust Authentication-Results added by OUR gateway. Senders can forge others.
    auth = next((str(h) for h in msg.get_all("Authentication-Results", [])
                 if str(h).strip().lower().startswith(authserv_id.lower())), "")

    def _auth(mech: str) -> str:
        m = re.search(rf"\b{mech}=(\w+)", auth, re.IGNORECASE)
        return m.group(1).lower() if m else "none"

    body_parts: list[str] = []
    attachments: list[dict[str, Any]] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True) or b""
            attachments.append({"filename": filename, "content_type": part.get_content_type(),
                                "size": len(payload)})
        elif part.get_content_type() in ("text/plain", "text/html"):
            body_parts.append(part.get_content())
    body = "\n".join(body_parts)
    urls = sorted(set(u.rstrip(".,;") for u in URL_RE.findall(body)))
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
    reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""
    return {
        "subject": str(msg.get("Subject", "")),
        "from_display": from_name,
        "from_address": from_addr.lower(),
        "from_domain": from_domain,
        "reply_to": reply_addr.lower() or None,
        "reply_to_domain": reply_domain or None,
        "reply_to_mismatch": bool(reply_domain) and reply_domain != from_domain,
        "spf": _auth("spf"),
        "dkim": _auth("dkim"),
        "dmarc": _auth("dmarc"),
        "urls": urls,
        "url_domains": sorted({urlparse(u).hostname or "" for u in urls} - {""}),
        "attachments": attachments,
        "body": body,  # UNTRUSTED: always spotlight before showing to a model
    }


class LookalikeArgs(BaseModel):
    domain: str = Field(description="Domain to compare against the organisation's protected domains")


def make_email_tools(protected_domains: list[str]) -> list[Tool]:
    def check_lookalike(domain: str) -> dict[str, Any]:
        return lookalike_score(domain, protected_domains)

    return [Tool("check_lookalike_domain",
                 "Checks whether a domain imitates one of the organisation's own domains "
                 "(edit distance and common character swaps).",
                 LookalikeArgs, check_lookalike, Permission.READ)]
