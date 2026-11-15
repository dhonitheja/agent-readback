import json

import httpx

from examples.healthcare import run_eval
from examples.healthcare.llm import AnthropicProvider, OpenAICompatProvider
from examples.healthcare.tools import SYSTEM_PROMPT, TOOL_SCHEMAS

ARGS = {"patient": "Patient/1", "practitioner": "Practitioner/2", "start": "2027-01-04T15:00:00Z", "end": "2027-01-04T15:30:00Z"}


def test_anthropic_loop_sends_tool_results_back_and_returns_final_text():
    requests, calls = [], []

    def handle(request):
        body = json.loads(request.content)
        requests.append((request.headers, body))
        if len(requests) == 1:
            content = [{"type": "text", "text": "Booking now."}, {"type": "tool_use", "id": "tu_1", "name": "book_appointment", "input": ARGS}]
            return httpx.Response(200, json={"content": content, "stop_reason": "tool_use"})
        return httpx.Response(200, json={"content": [{"type": "text", "text": "DONE: booked."}], "stop_reason": "end_turn"})

    client = httpx.Client(transport=httpx.MockTransport(handle), base_url="https://api.anthropic.com")
    provider = AnthropicProvider("claude-haiku-5-5", "test-key", client)
    text = provider.run(SYSTEM_PROMPT, "Book it.", TOOL_SCHEMAS, lambda name, args: calls.append((name, args)) or {"ok": True, "id": "7"})

    assert text == "DONE: booked." and calls == [("book_appointment", ARGS)]
    headers, first = requests[0]
    assert headers["x-api-key"] == "test-key" and headers["anthropic-version"] == "2023-06-01"
    assert first["model"] == "claude-haiku-5-5" and first["tools"] == TOOL_SCHEMAS
    result = requests[1][1]["messages"][-1]["content"][0]
    assert result["type"] == "tool_result" and result["tool_use_id"] == "tu_1"
    assert json.loads(result["content"]) == {"ok": True, "id": "7"}


def test_openai_compatible_loop():
    requests, calls = [], []

    def handle(request):
        requests.append(json.loads(request.content))
        if len(requests) == 1:
            call = {"id": "call_1", "type": "function", "function": {"name": "book_appointment", "arguments": json.dumps(ARGS)}}
            return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [call]}}]})
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "DONE: booked."}}]})

    client = httpx.Client(transport=httpx.MockTransport(handle), base_url="https://api.openai.com/v1")
    provider = OpenAICompatProvider("gpt-6-luna", "test-key", client=client)
    text = provider.run(SYSTEM_PROMPT, "Book it.", TOOL_SCHEMAS, lambda name, args: calls.append((name, args)) or {"ok": True})

    assert text == "DONE: booked." and calls == [("book_appointment", ARGS)]
    assert requests[0]["tools"][0]["function"]["parameters"] == TOOL_SCHEMAS[0]["input_schema"]
    assert requests[1]["messages"][-1] == {"role": "tool", "tool_call_id": "call_1", "content": json.dumps({"ok": True})}


def evaluate(tmp_path, *extra):
    parser_args = ["--provider", "scripted", "--runs", "60", "--log", str(tmp_path / "e.jsonl"), "--out", str(tmp_path / "s.json"), *extra]
    run_eval.main(parser_args)
    return json.loads((tmp_path / "s.json").read_text())


def test_correct_agent_on_a_healthy_server_has_no_false_completions(tmp_path):
    summary = evaluate(tmp_path)
    assert summary["outcomes"] == {"done_and_verified": 60} and summary["chain_intact"]
    assert set(summary["by_task"]) == {"book", "cancel", "reschedule"}


def test_injected_server_faults_surface_as_false_completions(tmp_path):
    summary = evaluate(tmp_path, "--inject-faults", "0.5")
    assert summary["agent_said_done"] == 60
    assert summary["outcomes"]["false_completion"] > 5
    assert summary["outcomes"]["done_and_verified"] + summary["outcomes"]["false_completion"] == 60
