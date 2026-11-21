"""Multi-tenant operation for MSSPs and MDR providers (Chapter 15).

One agent deployment, many customers, zero leakage between them. The rule:
the tenant is fixed by the CALLER (the SOAR incident's customer), bound into
every tool in code, and never taken from the alert content or the model.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    protected_domains: tuple[str, ...]
    protected_targets: frozenset[str] = frozenset()
    daily_token_budget: int = 5_000_000
    credentials_ref: str = ""   # name of the secret holding THIS tenant's tool credentials


class TenantCache:
    """Cache whose keys always include the tenant. A lookup for tenant A can never
    return a value computed for tenant B, even for the same indicator."""

    def __init__(self, ttl_seconds: float = 3600, clock: Callable[[], float] = time.monotonic):
        self.ttl, self.clock = ttl_seconds, clock
        self._data: dict[tuple[str, str, str], tuple[float, Any]] = {}

    def get_or_compute(self, tenant_id: str, kind: str, key: str, fn: Callable[[], Any]) -> Any:
        k = (tenant_id, kind, key.lower())
        hit = self._data.get(k)
        if hit and self.clock() - hit[0] < self.ttl:
            return hit[1]
        value = fn()
        self._data[k] = (self.clock(), value)
        return value


@dataclass
class TenantUsage:
    """Per-tenant cost tracking; refuse new runs when a tenant's daily budget is spent."""
    used: dict[str, int] = field(default_factory=dict)

    def charge(self, tenant: TenantContext, tokens: int) -> None:
        self.used[tenant.tenant_id] = self.used.get(tenant.tenant_id, 0) + tokens

    def allowed(self, tenant: TenantContext) -> bool:
        return self.used.get(tenant.tenant_id, 0) < tenant.daily_token_budget
