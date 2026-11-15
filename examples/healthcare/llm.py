"""Model providers for the example agent. Each runs a tool-calling loop and
returns the model's final text.

AnthropicProvider      Anthropic Messages API (https://api.anthropic.com)
OpenAICompatProvider   any Chat Completions-compatible endpoint: OpenAI, and
                       other vendors or local servers that offer that format
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
    def __init__(self, model: str, api_key: str, base_url: str = "https://api.openai.com/v1", client: httpx.Client | None = None) -> None:
        self.model = model
        self.client = client or httpx.Client(base_url=base_url, timeout=60.0)
        self.headers = {"Authorization": f"Bearer {api_key}"}

    def run(self, system: str, user: str, tools: list[dict[str, Any]], call_tool: ToolCaller, max_steps: int = 8) -> str:
        functions = [
            {"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}}
            for t in tools
        ]
        messages: list[dict[str, Any]] = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        for _ in range(max_steps):
            response = self.client.post(
                "chat/completions", headers=self.headers, json={"model": self.model, "messages": messages, "tools": functions}
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


class ScriptedProvider:
    """Replays tool calls produced by `script(user_prompt, call_tool)` and returns its text."""

    def __init__(self, script: Callable[[str, ToolCaller], str]) -> None:
        self.script = script

    def run(self, system: str, user: str, tools: list[dict[str, Any]], call_tool: ToolCaller, max_steps: int = 8) -> str:
        return self.script(user, call_tool)
