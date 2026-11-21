"""Tool registry with permission tiers.

The single most important safety decision in a SOC agent is made here:
which tools the model can call on its own, and which need a human.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Callable

from pydantic import BaseModel, ValidationError


class Permission(IntEnum):
    READ = 1          # lookups, enrichment: safe to run automatically
    WRITE = 2         # tickets, notes, tags: reversible, low blast radius
    CONTAINMENT = 3   # isolate host, disable user, block IOC: human approval


@dataclass
class Tool:
    name: str
    description: str
    params: type[BaseModel]
    func: Callable[..., Any]
    permission: Permission = Permission.READ

    def spec(self) -> dict[str, Any]:
        """JSON-schema description the model sees."""
        schema = self.params.model_json_schema()
        schema.pop("title", None)
        return {"name": self.name, "description": self.description, "parameters": schema}

    def run(self, arguments: dict[str, Any]) -> Any:
        try:
            parsed = self.params.model_validate(arguments)
        except ValidationError as e:
            # Return the error to the model instead of crashing: it can fix its call.
            return {"error": "invalid_arguments", "details": e.errors(include_url=False)}
        return self.func(**parsed.model_dump())


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool name: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def specs(self, max_permission: Permission = Permission.CONTAINMENT) -> list[dict[str, Any]]:
        return [t.spec() for t in self._tools.values() if t.permission <= max_permission]

    def names(self) -> list[str]:
        return list(self._tools)
