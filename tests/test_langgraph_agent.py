import pytest

pytest.importorskip("langgraph")
pytest.importorskip("langchain_core")

from langchain_core.messages import AIMessage  # noqa: E402
from langgraph.prebuilt import ToolNode  # noqa: E402

from agent_readback import EvidenceLog, Status  # noqa: E402
from examples.healthcare.langgraph_agent import build_tools, run  # noqa: E402

from .conftest import DOCTOR, END, LATER, LATER_END, PATIENT, START  # noqa: E402
from .test_adapters import in_graph  # noqa: E402


def test_every_done_is_verified_without_faults(tmp_path):
    summary = run(runs=10, inject_faults=0.0, seed=1, log_path=tmp_path / "e.jsonl")
    assert summary["outcomes"] == {"done_and_verified": 10} and summary["chain_intact"]


def test_every_false_done_is_caught_when_the_server_lies(tmp_path):
    summary = run(runs=10, inject_faults=1.0, seed=1, log_path=tmp_path / "e.jsonl")
    assert summary["outcomes"] == {"false_completion": 10} and summary["chain_intact"]


def test_cancel_through_tool_node_looks_up_patient_via_verifier(server, tools):
    appointment = tools["book_appointment"](PATIENT, DOCTOR, START, END)["id"]
    verdicts = []
    node = in_graph(ToolNode(build_tools(server.client(), server.client(), None, [verdicts.append])))
    cancel = AIMessage(content="", tool_calls=[{"name": "cancel_appointment", "args": {"appointment_id": appointment}, "id": "c1"}])

    node.invoke({"messages": [cancel]})
    rebook = tools["book_appointment"](PATIENT, DOCTOR, START, END)["id"]
    server.fault = "drop"  # the server says it cancelled, but keeps the record as is
    node.invoke({"messages": [AIMessage(content="", tool_calls=[{"name": "cancel_appointment", "args": {"appointment_id": rebook}, "id": "c2"}])]})

    assert [v.status for v in verdicts] == [Status.VERIFIED, Status.FAILED]
    assert verdicts[0].claim.expected["patient"] == PATIENT


class FakeChat:
    """Replays scripted replies; stands in for ChatAnthropic / ChatOpenAI offline."""

    def __init__(self, replies):
        self.replies = list(replies)

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        return self.replies.pop(0)(messages)


def test_model_saying_done_without_any_write_is_flagged(tmp_path):
    chat = FakeChat([lambda m: AIMessage(content=[{"type": "text", "text": "DONE: all booked."}])])
    summary = run(runs=1, inject_faults=0.0, seed=3, log_path=tmp_path / "e.jsonl", chat=chat)
    assert summary["outcomes"] == {"said_done_no_write": 1}


def test_model_agent_tool_loop_is_verified(tmp_path):
    def book(messages):
        prompt = messages[-1].content  # the task prompt names the patient and practitioner
        patient = next(w.strip(".,") for w in prompt.split() if w.startswith("Patient/"))
        practitioner = next((w.strip(".,") for w in prompt.split() if w.startswith("Practitioner/")), DOCTOR)
        args = {"patient": patient, "practitioner": practitioner, "start": START, "end": END}
        return AIMessage(content="", tool_calls=[{"name": "book_appointment", "args": args, "id": "b1"}])

    chat = FakeChat([book, lambda m: AIMessage(content="DONE: booked.")])
    summary = run(runs=1, inject_faults=1.0, seed=0, log_path=tmp_path / "e.jsonl", chat=chat)
    # every write is faulted (the server still answers ok), so the model's DONE must be caught
    assert summary["outcomes"] == {"false_completion": 1} and summary["chain_intact"]


def test_failed_patient_lookup_still_logs_an_unverified_verdict(server, tmp_path):
    log = EvidenceLog(tmp_path / "e.jsonl")
    verdicts = []
    node = in_graph(ToolNode(build_tools(server.client(), server.client(), log, [verdicts.append])))
    call = {"name": "cancel_appointment", "args": {"appointment_id": "does-not-exist"}, "id": "c1"}

    node.invoke({"messages": [AIMessage(content="", tool_calls=[call])]})

    assert [v.status for v in verdicts] == [Status.UNVERIFIED]
    assert len(log.records()) == 1 and log.verify_chain() == (True, None)


@pytest.mark.parametrize("argv", [["--runs", "0"], ["--runs", "-5"], ["--inject-faults", "1.5"], ["--inject-faults", "-1"]])
def test_bad_arguments_are_rejected_before_running(argv):
    from examples.healthcare.langgraph_agent import main

    with pytest.raises(SystemExit) as stop:
        main(argv)
    assert stop.value.code == 2


def test_log_in_a_missing_directory_is_rejected_up_front(tmp_path):
    from examples.healthcare.langgraph_agent import main

    with pytest.raises(SystemExit) as stop:
        main(["--log", str(tmp_path / "missing" / "e.jsonl")])
    assert stop.value.code == 2 and not (tmp_path / "missing").exists()


def test_outcome_labels_unclear_replies_and_retries():
    from agent_readback import Claim, Finding, FindingKind, Verdict
    from examples.healthcare.langgraph_agent import outcome, text_of

    claim = Claim("fhir.appointment.create", "", {})
    ok = Verdict(Status.VERIFIED, claim, ())
    bad = Verdict(Status.FAILED, claim, (Finding(FindingKind.MISSING, "gone"),))
    assert outcome("I booked it.", [ok]) == "unclear_reply"
    assert outcome("DONE: booked", [bad, ok]) == "done_after_failed_write"
    assert outcome("DONE: booked", [ok, bad]) == "false_completion"
    assert outcome("done: booked", [ok]) == "done_and_verified"
    assert outcome("FAILED: no slot", [bad]) == "reported_failure"
    assert outcome("FAILED: no slot", [ok]) == "said_failed_but_actually_done"
    assert text_of(AIMessage(content=["DONE:", {"type": "text", "text": "booked"}])) == "DONE: booked"


def test_parallel_tool_calls_for_one_patient_are_both_verified(server, tmp_path):
    log = EvidenceLog(tmp_path / "e.jsonl")
    verdicts = []
    node = in_graph(ToolNode(build_tools(server.client(), server.client(), log, [verdicts.append])))
    calls = [
        {"name": "book_appointment", "args": {"patient": PATIENT, "practitioner": DOCTOR, "start": START, "end": END}, "id": "b1"},
        {"name": "book_appointment", "args": {"patient": PATIENT, "practitioner": DOCTOR, "start": LATER, "end": LATER_END}, "id": "b2"},
    ]
    node.invoke({"messages": [AIMessage(content="", tool_calls=calls)]})
    assert [v.status for v in verdicts] == [Status.VERIFIED, Status.VERIFIED]
    assert log.verify_chain() == (True, None) and len(log.records()) == 2


def test_wrong_time_booking_with_done_is_caught_by_the_task_check(tmp_path):
    def book_wrong_time(messages):
        prompt = messages[-1].content
        patient = next(w.strip(".,") for w in prompt.split() if w.startswith("Patient/"))
        practitioner = next((w.strip(".,") for w in prompt.split() if w.startswith("Practitioner/")), DOCTOR)
        args = {"patient": patient, "practitioner": practitioner, "start": "2030-01-01T00:00:00+00:00", "end": "2030-01-01T00:30:00+00:00"}
        return AIMessage(content="", tool_calls=[{"name": "book_appointment", "args": args, "id": "b1"}])

    chat = FakeChat([book_wrong_time, lambda m: AIMessage(content="DONE: booked.")])
    summary = run(runs=1, inject_faults=0.0, seed=0, log_path=tmp_path / "e.jsonl", chat=chat)
    # the write itself verifies against the model's own arguments; the task check does not
    assert summary["outcomes"] == {"false_completion": 1} and summary["chain_intact"]


def test_failed_reply_is_classified_by_the_task_verdict_like_run_eval():
    from agent_readback import Claim, Finding, FindingKind, Verdict
    from examples.healthcare.langgraph_agent import outcome

    claim = Claim("fhir.appointment.create", "", {})
    write_ok = Verdict(Status.VERIFIED, claim, ())
    task_failed = Verdict(Status.FAILED, claim, (Finding(FindingKind.WRONG_VALUE, "wrong time"),))
    task_ok = Verdict(Status.VERIFIED, claim, ())
    # The write held but at the wrong time, and the model said FAILED: the task did not complete.
    assert outcome("FAILED: could not confirm", [write_ok], task_failed) == "reported_failure"
    assert outcome("FAILED: could not confirm", [write_ok], task_ok) == "said_failed_but_actually_done"
    assert outcome("FAILED: no slot", [write_ok]) == "said_failed_but_actually_done"  # no task: write fallback
