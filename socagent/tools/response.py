"""State-changing tools.

These never execute directly from a model request: the agent loop routes
every call above Permission.READ through the ApprovalGate first.
The implementations here are lab stubs that record what *would* happen.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .registry import Permission, Tool


class ActionLog:
    def __init__(self) -> None:
        self.executed: list[dict[str, Any]] = []

    def record(self, action: str, **kw: Any) -> dict[str, Any]:
        entry = {"action": action, "status": "executed", **kw}
        self.executed.append(entry)
        return entry


class TicketArgs(BaseModel):
    title: str = Field(max_length=200)
    body: str = Field(max_length=5000)
    priority: str = Field(pattern="^(P1|P2|P3|P4)$")


class HostArgs(BaseModel):
    hostname: str = Field(pattern=r"^[A-Za-z0-9.\-]{1,253}$")
    reason: str = Field(min_length=10)


class UserArgs(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9._@\-]{1,128}$")
    reason: str = Field(min_length=10)


class IndicatorArgs(BaseModel):
    indicator: str
    kind: str = Field(pattern="^(ip|domain|url|sha256)$")
    reason: str = Field(min_length=10)


def make_response_tools(log: ActionLog | None = None) -> tuple[list[Tool], ActionLog]:
    log = log or ActionLog()

    def create_ticket(title: str, body: str, priority: str) -> dict[str, Any]:
        return log.record("create_ticket", title=title, priority=priority)

    def isolate_host(hostname: str, reason: str) -> dict[str, Any]:
        return log.record("isolate_host", target=hostname, reason=reason)

    def revoke_sessions(username: str, reason: str) -> dict[str, Any]:
        return log.record("revoke_sessions", target=username, reason=reason)

    def block_indicator(indicator: str, kind: str, reason: str) -> dict[str, Any]:
        return log.record("block_indicator", target=indicator, kind=kind, reason=reason)

    tools = [
        Tool("create_ticket", "Open a ticket in the case-management system.",
             TicketArgs, create_ticket, Permission.WRITE),
        Tool("isolate_host", "Network-isolate an endpoint via EDR. Requires analyst approval.",
             HostArgs, isolate_host, Permission.CONTAINMENT),
        Tool("revoke_sessions", "Revoke all sign-in sessions and tokens for a user. Requires approval.",
             UserArgs, revoke_sessions, Permission.CONTAINMENT),
        Tool("block_indicator", "Add an IOC to the blocklist (proxy, firewall, mail gateway). Requires approval.",
             IndicatorArgs, block_indicator, Permission.CONTAINMENT),
    ]
    return tools, log
