"""Model providers for the example agent. Each runs a tool-calling loop and
returns the model's final text.

AnthropicProvider      Anthropic Messages API (https://api.anthropic.com)
OpenAICompatProvider   any Chat Completions-compatible endpoint: OpenAI, and
                       other vendors or local servers that offer that format
OpenAIResponsesProvider  OpenAI /v1/responses: tools with reasoning on
ScriptedProvider       no model; replays a fixed list of tool calls (for tests
                       and for running the example without an API key)

API keys are read from the environment by the caller. Nothing here logs them.
The two network providers have been tested only against recorded-format mock
responses, not against the live APIs.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import httpx

ToolCaller = Callable[[str, dict[str, Any]], dict[str, Any]]


class AnthropicProvider:
    def __init__(self, model: str, api_key: str, client: httpx.Client | None = None) -> None:
        self.model = model
        self.client = client or httpx.Client(base_url="https://api.anthropic.com", timeout=60.0)
        self.headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}

    def run(self, system: str, user: str, tools: list[dict[str, Any]], call_tool: ToolCaller, max_steps: int = 8) -> str:
        messages: list[dict[str, Any]] = [{"role": "user", "content": user}]
        for _ in range(max_steps):
            response = self.client.post(
                "/v1/messages",
                headers=self.headers,
                json={"model": self.model, "max_tokens": 1024, "system": system, "tools": tools, "messages": messages},
            )
            response.raise_for_status()
            content = response.json()["content"]
            calls = [block for block in content if block["type"] == "tool_use"]
            if not calls:
                return "".join(block.get("text", "") for block in content if block["type"] == "text").strip()
            messages.append({"role": "assistant", "content": content})
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": call["id"],
                            "content": json.dumps(call_tool(call["name"], call["input"])),
                        }
                        for call in calls
                    ],
                }
            )
        return "FAILED: step limit reached"


class OpenAICompatProvider:
    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        client: httpx.Client | None = None,
        reasoning_effort: str | None = None,
    ) -> None:
        self.model = model
        self.client = client or httpx.Client(base_url=base_url, timeout=60.0)
        self.headers = {"Authorization": f"Bearer {api_key}"}
        # ponytail: OpenAI reasoning models (e.g. gpt-6-luna) reject function tools on
        # /v1/chat/completions unless reasoning_effort="none". Sent only when set, so other
        # compatible servers never see it. Port to /v1/responses if reasoning with tools matters.
        self.extra = {"reasoning_effort": reasoning_effort} if reasoning_effort else {}

    def run(self, system: str, user: str, tools: list[dict[str, Any]], call_tool: ToolCaller, max_steps: int = 8) -> str:
        functions = [
            {"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}}
            for t in tools
        ]
        messages: list[dict[str, Any]] = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        for _ in range(max_steps):
            response = self.client.post(
                "chat/completions", headers=self.headers, json={"model": self.model, "messages": messages, "tools": functions, **self.extra}
            )
            response.raise_for_status()
            message = response.json()["choices"][0]["message"]
            calls = message.get("tool_calls") or []
            if not calls:
                return (message.get("content") or "").strip()
            messages.append(message)
            for call in calls:
                try:
                    arguments = json.loads(call["function"]["arguments"] or "{}")
                    result = call_tool(call["function"]["name"], arguments)
                except json.JSONDecodeError:
                    result = {"ok": False, "error": "arguments were not valid JSON"}
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": json.dumps(result)})
        return "FAILED: step limit reached"


class OpenAIResponsesProvider:
    """OpenAI /v1/responses loop, so reasoning models can use tools with reasoning on.

    By default, reasoning carries across tool calls via previous_response_id.
    With store=False, the client sends the conversation including encrypted reasoning.
    """

    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        client: httpx.Client | None = None,
        reasoning_effort: str | None = None,
        store: bool = True,
    ) -> None:
        self.model = model
        self.client = client or httpx.Client(base_url=base_url, timeout=120.0)
        self.headers = {"Authorization": f"Bearer {api_key}"}
        self.extra = {"reasoning": {"effort": reasoning_effort}} if reasoning_effort else {}
        self.store = store

    def run(self, system: str, user: str, tools: list[dict[str, Any]], call_tool: ToolCaller, max_steps: int = 8) -> str:
        functions = [{"type": "function", "name": t["name"], "description": t["description"], "parameters": t["input_schema"]} for t in tools]
        body: dict[str, Any] = {"model": self.model, "instructions": system, "tools": functions, "input": [{"role": "user", "content": user}], **self.extra}
        if not self.store:
            body.update(store=False, include=["reasoning.encrypted_content"])
        for _ in range(max_steps):
            response = self.client.post("responses", headers=self.headers, json=body)
            response.raise_for_status()
            data = response.json()
            status = data.get("status")
            if status not in (None, "completed"):
                # Incomplete or failed: a partial function call must not be dispatched and
                # partial text must not count as the agent's final word.
                reason = (data.get("incomplete_details") or {}).get("reason") or status
                return f"FAILED: model response {status} ({reason})"
            calls = [item for item in data["output"] if item["type"] == "function_call"]
            if not calls:
                return "".join(
                    part.get("text", "") for item in data["output"] if item["type"] == "message" for part in item["content"]
                ).strip()
            outputs = []
            for call in calls:
                try:
                    result = call_tool(call["name"], json.loads(call["arguments"] or "{}"))
                except json.JSONDecodeError:
                    result = {"ok": False, "error": "arguments were not valid JSON"}
                outputs.append({"type": "function_call_output", "call_id": call["call_id"], "output": json.dumps(result)})
            if self.store:
                body = {**body, "previous_response_id": data["id"], "input": outputs}
            else:
                body["input"].extend(data["output"])
                body["input"].extend(outputs)
        return "FAILED: step limit reached"


class ScriptedProvider:
    """Replays tool calls produced by `script(user_prompt, call_tool)` and returns its text."""

    def __init__(self, script: Callable[[str, ToolCaller], str]) -> None:
        self.script = script

    def run(self, system: str, user: str, tools: list[dict[str, Any]], call_tool: ToolCaller, max_steps: int = 8) -> str:
        return self.script(user, call_tool)
