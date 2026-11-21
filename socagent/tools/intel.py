"""Read-only enrichment tools.

In the lab these read a local JSON fixture so you can practise with no
paid API keys. In production, replace `IntelSource` with a client for
your real threat-intel provider; the tool contracts stay the same.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import date
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .registry import Permission, Tool

DATA = Path(__file__).resolve().parent.parent.parent / "data"


class IntelSource:
    def __init__(self, *paths: Path):
        paths = paths or tuple(p for p in (DATA / "intel.json", DATA / "golden" / "intel_golden.json")
                               if p.exists())
        self._db: dict[str, dict[str, Any]] = {}
        for path in paths:
            for kind, records in json.loads(Path(path).read_text()).items():
                self._db.setdefault(kind, {}).update(records)

    def lookup(self, kind: str, value: str) -> dict[str, Any]:
        record = self._db.get(kind, {}).get(value.lower())
        if record is None:
            return {"observable": value, "type": kind, "known": False}
        return {"observable": value, "type": kind, "known": True, **record}


class IPArgs(BaseModel):
    ip: str = Field(description="IPv4 or IPv6 address")


class DomainArgs(BaseModel):
    domain: str = Field(description="Fully qualified domain name, no scheme")


class HashArgs(BaseModel):
    sha256: str = Field(min_length=64, max_length=64, description="SHA-256 file hash")


def make_intel_tools(src: IntelSource | None = None, today: date | None = None) -> list[Tool]:
    src = src or IntelSource()
    today = today or date.today()

    def ip_reputation(ip: str) -> dict[str, Any]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"error": f"not an IP address: {ip}"}
        if addr.is_private or addr.is_loopback:
            return {"observable": ip, "type": "ip", "known": True, "verdict": "internal",
                    "note": "RFC1918/loopback address; check asset inventory instead"}
        return src.lookup("ip", ip)

    def domain_reputation(domain: str) -> dict[str, Any]:
        result = src.lookup("domain", domain.strip(".").lower())
        created = result.get("created")
        if created:
            result["age_days"] = (today - date.fromisoformat(created)).days
        return result

    def file_reputation(sha256: str) -> dict[str, Any]:
        return src.lookup("sha256", sha256)

    return [
        Tool("ip_reputation", "Threat-intel reputation for a public IP address.", IPArgs, ip_reputation),
        Tool("domain_reputation",
             "Threat-intel reputation and registration age (age_days) for a domain.",
             DomainArgs, domain_reputation),
        Tool("file_reputation", "Threat-intel verdict for a SHA-256 file hash.", HashArgs, file_reputation),
    ]
