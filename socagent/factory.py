"""Wire the standard lab agent together in one place."""
from __future__ import annotations

from pathlib import Path

from .agent import Agent
from .approval import ApprovalPolicy, Approver
from .audit import AuditLog
from .llm import ModelClient
from .rag import RunbookIndex, make_runbook_tool
from .tenancy import TenantContext
from .tools.cloud import make_cloud_tools
from .tools.correlation import AlertStore, make_correlation_tools
from .tools.email_tools import make_email_tools
from .tools.endpoint import make_decode_tool, make_endpoint_tools
from .tools.intel import make_intel_tools
from .tools.registry import ToolRegistry
from .tools.response import ActionLog, make_response_tools

DATA = Path(__file__).resolve().parent.parent / "data"
PROTECTED = ["example-corp.com"]
LAB_TENANT = TenantContext("example-corp", tuple(PROTECTED))


def build_registry(protected: list[str] | None = None,
                   tenant: TenantContext | None = None) -> tuple[ToolRegistry, ActionLog]:
    """Every tool that touches customer data is bound to `tenant` here, in code."""
    tenant = tenant or LAB_TENANT
    reg = ToolRegistry()
    store = AlertStore.from_file(DATA / "alerts.json")
    for t in (make_intel_tools() + make_email_tools(protected or list(tenant.protected_domains))
              + make_endpoint_tools() + [make_decode_tool()]
              + make_correlation_tools(store, tenant=tenant.tenant_id) + make_cloud_tools()):
        reg.register(t)
    reg.register(make_runbook_tool(RunbookIndex.from_dir(DATA / "runbooks"), tenant=tenant.tenant_id))
    response_tools, log = make_response_tools()
    for t in response_tools:
        reg.register(t)
    return reg, log


def build_agent(model: ModelClient, approver: Approver | None = None,
                policy: ApprovalPolicy | None = None, audit: AuditLog | None = None,
                tenant: TenantContext | None = None) -> tuple[Agent, ActionLog]:
    tenant = tenant or LAB_TENANT
    reg, log = build_registry(tenant=tenant)
    policy = policy or ApprovalPolicy(protected_targets=set(tenant.protected_targets))
    return Agent(model, reg, approver=approver, policy=policy, audit=audit,
                 tenant_id=tenant.tenant_id), log
