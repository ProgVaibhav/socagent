"""A thin, model-agnostic layer between the agent and any LLM provider.

The agent only ever talks to `ModelClient`. Swapping providers, or
moving to a local model for data-residency reasons, means writing one
small adapter, never touching the agent.
"""
from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol


class ModelError(RuntimeError):
    """A model call failed after the retry policy was exhausted, or returned garbage.

    kind: "timeout" | "rate_limited" | "server_error" | "client_error" | "network" | "malformed"
    """

    def __init__(self, kind: str, detail: str = ""):
        super().__init__(f"{kind}: {detail}"[:300])
        self.kind = kind


RETRYABLE = {"timeout", "rate_limited", "server_error", "network"}


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ModelResponse:
    content: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0


class ModelClient(Protocol):
    def complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
    ) -> ModelResponse: ...


class ScriptedModel:
    """Deterministic stand-in for an LLM.

    Returns pre-written responses in order. Used for unit tests, for the
    book's offline examples, and for replaying a recorded investigation.
    """

    def __init__(self, script: list[ModelResponse]):
        self._script = list(script)
        self.calls: list[list[dict[str, Any]]] = []

    def complete(self, messages, tools=None) -> ModelResponse:
        self.calls.append([dict(m) for m in messages])
        if not self._script:
            raise RuntimeError("ScriptedModel ran out of responses")
        return self._script.pop(0)


class OpenAICompatibleModel:
    """Works with any server that speaks the OpenAI chat-completions API.

    That includes many hosted providers and local servers such as vLLM,
    Ollama and LM Studio, which matters when alert data must not leave
    your network.
    """

    def __init__(
        self,
        model: str,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 60.0,
        max_retries: int = 3,
        temperature: float = 0.0,
    ):
        self.model = model
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.api_key = api_key or os.environ.get("LLM_API_KEY", "")
        self.timeout = timeout
        self.max_retries = max_retries
        self.temperature = temperature

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST with retries for transient failures only, honouring Retry-After."""
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
        )
        delay = 1.0
        for attempt in range(self.max_retries):
            wait = delay
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    try:
                        return json.loads(resp.read())
                    except ValueError as e:
                        raise ModelError("malformed", "response is not JSON") from e
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    kind = "rate_limited"
                    retry_after = e.headers.get("Retry-After") if e.headers else None
                    if retry_after and retry_after.isdigit():
                        wait = min(float(retry_after), 60.0)
                elif e.code >= 500:
                    kind = "server_error"
                else:
                    raise ModelError("client_error", f"HTTP {e.code}") from e  # 4xx: do not retry
            except (socket.timeout, TimeoutError) as e:
                kind = "timeout"
            except urllib.error.URLError as e:
                kind = "timeout" if isinstance(e.reason, socket.timeout) else "network"
            if attempt == self.max_retries - 1:
                raise ModelError(kind, f"gave up after {self.max_retries} attempts")
            time.sleep(wait)
            delay *= 2  # exponential backoff
        raise ModelError("network", "no attempts made")

    def complete(self, messages, tools=None) -> ModelResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [_to_openai_message(m) for m in messages],
            "temperature": self.temperature,
        }
        if tools:
            payload["tools"] = [{"type": "function", "function": t} for t in tools]
        data = self._post(payload)
        try:
            msg = data["choices"][0]["message"]
            calls = [
                ToolCall(
                    id=str(tc["id"]),
                    name=str(tc["function"]["name"]),
                    arguments=json.loads(tc["function"].get("arguments") or "{}"),
                )
                for tc in msg.get("tool_calls") or []
            ]
        except (KeyError, IndexError, TypeError, ValueError) as e:
            raise ModelError("malformed", f"unexpected response shape: {type(e).__name__}") from e
        usage = data.get("usage") or {}
        return ModelResponse(
            content=msg.get("content"),
            tool_calls=calls,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
        )


def _to_openai_message(m: dict[str, Any]) -> dict[str, Any]:
    if m["role"] == "assistant" and m.get("tool_calls"):
        return {
            "role": "assistant",
            "content": m.get("content"),
            "tool_calls": [
                {"id": c["id"], "type": "function",
                 "function": {"name": c["name"], "arguments": json.dumps(c["arguments"])}}
                for c in m["tool_calls"]
            ],
        }
    if m["role"] == "tool":
        return {"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]}
    return {"role": m["role"], "content": m["content"]}
