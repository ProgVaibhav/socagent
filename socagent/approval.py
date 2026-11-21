"""Human-in-the-loop approval for anything above read-only.

In production the approver posts an interactive message to Slack/Teams
or creates a SOAR task, then waits. Here we provide simple approvers
plus a policy object that decides *whether* to ask at all.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .tools.registry import Permission


@dataclass
class ApprovalRequest:
    tool: str
    arguments: dict[str, Any]
    permission: Permission
    alert_id: str
    rationale: str = ""


@dataclass
class ApprovalDecision:
    approved: bool
    approver: str
    comment: str = ""


class Approver(Protocol):
    def decide(self, req: ApprovalRequest) -> ApprovalDecision: ...


class DenyAll:
    """Shadow mode: the agent can propose, nothing is ever executed."""

    def decide(self, req: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(False, "shadow-mode", "execution disabled")


class CallbackApprover:
    def __init__(self, fn: Callable[[ApprovalRequest], bool], name: str = "callback"):
        self.fn, self.name = fn, name

    def decide(self, req: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(bool(self.fn(req)), self.name)


class ConsoleApprover:
    def decide(self, req: ApprovalRequest) -> ApprovalDecision:  # pragma: no cover - interactive
        print(f"\n[APPROVAL NEEDED] {req.tool} {req.arguments}\nalert={req.alert_id}\n{req.rationale}")
        ans = input("Approve? [y/N] ").strip().lower()
        return ApprovalDecision(ans == "y", "console")


def normalise_target(value: Any, aliases: dict[str, str] | None = None) -> str:
    """Canonical form for comparing targets: IPs, URLs, domains, hostnames, accounts.

    "HTTPS://DC01.corp.example.com:443/x" -> "dc01.corp.example.com"
    "10.0.0.010" is rejected by ipaddress, "::ffff:10.0.0.1" -> "10.0.0.1"
    aliases map short names to canonical ones: {"dc01": "dc01.corp.example.com"}
    """
    import ipaddress
    from urllib.parse import urlsplit

    s = str(value).strip().lower()
    if "://" in s:
        s = urlsplit(s).hostname or s
    s = s.rstrip(".")
    try:
        ip = ipaddress.ip_address(s.strip("[]"))
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        s = str(ip)
    except ValueError:
        pass
    aliases = {k.lower(): v.lower() for k, v in (aliases or {}).items()}
    return aliases.get(s, s)


@dataclass
class ApprovalPolicy:
    """Autonomy level as configuration, not code.

    auto_approve_up_to=READ  -> 'suggest' mode (default)
    auto_approve_up_to=WRITE -> agent may open tickets on its own
    Containment is never auto-approved by this class, by design.
    """

    auto_approve_up_to: Permission = Permission.READ
    protected_targets: set[str] = field(default_factory=set)  # e.g. domain controllers, VIPs
    aliases: dict[str, str] = field(default_factory=dict)     # short name -> canonical name

    def is_protected(self, value: Any) -> bool:
        protected = {normalise_target(t, self.aliases) for t in self.protected_targets}
        v = normalise_target(value, self.aliases)
        # Also catch the short hostname of a protected FQDN ("dc01" vs "dc01.corp.example.com").
        return v in protected or any(p.split(".")[0] == v for p in protected if "." in p)

    def needs_human(self, permission: Permission, arguments: dict[str, Any]) -> bool:
        if permission >= Permission.CONTAINMENT:
            return True
        if any(self.is_protected(v) for v in arguments.values() if isinstance(v, (str, int))):
            return True
        return permission > self.auto_approve_up_to


# --- Chat approvals (Chapter 10) ------------------------------------------
import secrets as _secrets
import time as _time


class ChatTransport(Protocol):
    """Posts an approval card and reports clicks. Implement for Slack, Teams, etc."""

    def post(self, request_id: str, text: str) -> None: ...
    def poll(self, request_id: str) -> tuple[str, str] | None: ...  # (decision, user_id)


class ChatApprover:
    """Approval through an interactive chat message.

    Security properties, all enforced here on the server side:
      * only users in `allowed_approvers` can approve (anyone else's click is ignored),
      * a request expires after `ttl_seconds` and counts as denied,
      * the approver's identity is returned for the audit log.
    """

    def __init__(self, transport: ChatTransport, allowed_approvers: set[str],
                 ttl_seconds: int = 1800, poll_interval: float = 2.0,
                 clock=_time.monotonic, sleep=_time.sleep):
        self.transport, self.allowed = transport, {a.lower() for a in allowed_approvers}
        self.ttl, self.poll_interval, self.clock, self.sleep = ttl_seconds, poll_interval, clock, sleep

    @staticmethod
    def render(req: ApprovalRequest) -> str:
        args = ", ".join(f"{k}={v}" for k, v in req.arguments.items() if k != "reason")
        return (f"APPROVAL NEEDED: {req.tool}\nTarget: {args}\nAlert: {req.alert_id}\n"
                f"Reason: {req.rationale or req.arguments.get('reason', '')}\n[Approve] [Reject]")

    def decide(self, req: ApprovalRequest) -> ApprovalDecision:
        request_id = _secrets.token_urlsafe(12)
        self.transport.post(request_id, self.render(req))
        deadline = self.clock() + self.ttl
        while self.clock() < deadline:
            click = self.transport.poll(request_id)
            if click:
                decision, user = click
                if user.lower() not in self.allowed:
                    continue  # not on call: ignore and keep waiting
                return ApprovalDecision(decision == "approve", f"chat:{user}")
            self.sleep(self.poll_interval)
        return ApprovalDecision(False, "chat:expired", "no authorised decision before expiry")
