import pytest
import json

import httpx

from examples.healthcare import run_eval
from examples.healthcare.llm import AnthropicProvider, OpenAICompatProvider, OpenAIResponsesProvider
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
    assert "reasoning_effort" not in requests[0]


def test_openai_reasoning_effort_sent_only_when_set():
    requests = []

    def handle(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "DONE: booked."}}]})

    client = httpx.Client(transport=httpx.MockTransport(handle), base_url="https://api.openai.com/v1")
    OpenAICompatProvider("gpt-6-luna", "test-key", client=client, reasoning_effort="none").run(SYSTEM_PROMPT, "Book it.", TOOL_SCHEMAS, lambda n, a: {"ok": True})

    assert requests[0]["reasoning_effort"] == "none"


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


def test_eval_refuses_to_overwrite_an_existing_log(tmp_path):
    (tmp_path / "e.jsonl").write_text("precious\n")
    with pytest.raises(SystemExit):
        evaluate(tmp_path)
    assert (tmp_path / "e.jsonl").read_text() == "precious\n"


def test_eval_reports_model_http_status_once_without_response_details(tmp_path, monkeypatch, capsys):
    def handle(request):
        return httpx.Response(400, text="private body", headers={"X-Private": "private header"})

    messages = []
    append = run_eval.EvidenceLog.append

    def capture(log, verdict):
        messages.append(verdict.claim.agent_said)
        return append(log, verdict)

    with httpx.Client(transport=httpx.MockTransport(handle), base_url="https://example.test") as client:
        provider = OpenAIResponsesProvider("test-model", "test-key", client=client)
        monkeypatch.setattr(run_eval, "build_provider", lambda *_: provider)
        monkeypatch.setattr(run_eval.EvidenceLog, "append", capture)
        summary = evaluate(tmp_path, "--runs", "2")

    message = "FAILED: model request error (HTTPStatusError 400)"
    assert messages == [message, message]
    assert capsys.readouterr().err.splitlines() == [f"Warning: {message}"]
    assert summary["outcomes"] == {"reported_failure": 2}


def test_openai_responses_loop_chains_reasoning_via_previous_response_id():
    requests, calls = [], []

    def handle(request):
        requests.append((request.url.path, json.loads(request.content)))
        if len(requests) == 1:
            output = [
                {"type": "reasoning", "id": "rs_1", "summary": []},
                {"type": "function_call", "call_id": "call_1", "name": "book_appointment", "arguments": json.dumps(ARGS)},
            ]
            return httpx.Response(200, json={"id": "resp_1", "output": output})
        message = {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "DONE: booked."}]}
        return httpx.Response(200, json={"id": "resp_2", "output": [message]})

    client = httpx.Client(transport=httpx.MockTransport(handle), base_url="https://api.openai.com/v1/")
    provider = OpenAIResponsesProvider("gpt-6-luna", "test-key", client=client, reasoning_effort="medium")
    text = provider.run(SYSTEM_PROMPT, "Book it.", TOOL_SCHEMAS, lambda name, args: calls.append((name, args)) or {"ok": True})

    assert text == "DONE: booked." and calls == [("book_appointment", ARGS)]
    path, first = requests[0]
    assert path == "/v1/responses" and first["instructions"] == SYSTEM_PROMPT and first["reasoning"] == {"effort": "medium"}
    assert first["tools"][0] == {"type": "function", "name": TOOL_SCHEMAS[0]["name"], "description": TOOL_SCHEMAS[0]["description"], "parameters": TOOL_SCHEMAS[0]["input_schema"]}
    second = requests[1][1]
    assert second["previous_response_id"] == "resp_1"
    assert second["input"] == [{"type": "function_call_output", "call_id": "call_1", "output": json.dumps({"ok": True})}]


def test_openai_responses_loop_carries_encrypted_reasoning_without_storage():
    requests = []
    reasoning = {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "opaque"}
    call = {"type": "function_call", "call_id": "call_1", "name": "book_appointment", "arguments": json.dumps(ARGS)}

    def handle(request):
        requests.append(json.loads(request.content))
        if len(requests) == 1:
            return httpx.Response(200, json={"id": "resp_1", "output": [reasoning, call]})
        message = {"type": "message", "content": [{"type": "output_text", "text": "DONE: booked."}]}
        return httpx.Response(200, json={"output": [message]})

    with httpx.Client(transport=httpx.MockTransport(handle), base_url="https://example.test") as client:
        provider = OpenAIResponsesProvider("test-model", "test-key", client=client, store=False)
        assert provider.run(SYSTEM_PROMPT, "Book it.", TOOL_SCHEMAS, lambda *_: {"ok": True}) == "DONE: booked."

    first, second = requests
    for request in requests:
        assert request["store"] is False
        assert request["include"] == ["reasoning.encrypted_content"]
        assert "previous_response_id" not in request
    assert second["input"] == [
        *first["input"], reasoning, call,
        {"type": "function_call_output", "call_id": "call_1", "output": json.dumps({"ok": True})},
    ]


def test_openai_responses_incomplete_response_is_not_dispatched_or_trusted():
    calls = []
    partial = {"type": "function_call", "call_id": "c1", "name": "book_appointment", "arguments": json.dumps(ARGS), "status": "incomplete"}
    text = {"type": "message", "content": [{"type": "output_text", "text": "DONE: booked"}]}
    for output in ([partial], [text]):
        body = {"id": "r1", "status": "incomplete", "incomplete_details": {"reason": "max_output_tokens"}, "output": output}
        client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=body)), base_url="https://api.openai.com/v1/")
        said = OpenAIResponsesProvider("gpt-6-luna", "k", client=client).run(SYSTEM_PROMPT, "Book it.", TOOL_SCHEMAS, lambda n, a: calls.append(n) or {"ok": True})
        assert said == "FAILED: model response incomplete (max_output_tokens)"
    assert calls == []


def test_no_store_is_rejected_for_providers_that_ignore_it(capsys):
    with pytest.raises(SystemExit) as raised:
        run_eval.main(["--provider", "openai", "--model", "gpt-6-luna", "--no-store"])
    assert raised.value.code == 2 and "--no-store only applies" in capsys.readouterr().err
