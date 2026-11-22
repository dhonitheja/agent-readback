"""A LangGraph scheduling agent whose every write is checked by Readback.

The graph is the standard tool loop: an `agent` node decides, a `ToolNode` runs
the tool, and the loop ends when the agent replies without a tool call. Each
write tool is wrapped with `watched()`, so the verifier snapshots the FHIR
store before the call and reads it back afterwards through its own client.
The agent itself never reads back; it trusts what the tool returned, which is
exactly the gap Readback closes.

No API key needed: the default agent node is scripted and believes the tool's
`ok`. Server faults are injected so some "DONE" replies are false:

    python -m examples.healthcare.langgraph_agent --runs 20 --inject-faults 0.3

With a real model (key from the environment or .env, never committed), the agent
gets the scheduling requests from run_eval (book, reschedule, cancel, in
Central time) and chooses its own tool calls:

    python -m examples.healthcare.langgraph_agent --provider anthropic --model claude-haiku-5-5 --runs 10
    python -m examples.healthcare.langgraph_agent --provider openai --model gpt-6-luna --runs 10

Requires the extras: pip install -e ".[langgraph]"
"""

from __future__ import annotations

import argparse
import functools
import random
import threading
import tempfile
from collections import Counter
from pathlib import Path
from typing import Annotated, Any, Callable, TypedDict

import httpx
from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langgraph.errors import GraphRecursionError
from langgraph.graph import START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from agent_readback import Claim, EvidenceLog, Status, Verdict, watch, watched
from agent_readback.verifiers import FhirAppointmentVerifier

from .mock_fhir import FAULTS, MockFhirServer
from .tasks import VISIT, make_task, seed_people, slot, utc
from .tools import SYSTEM_PROMPT, TOOL_SCHEMAS, make_tools

WRITE_FAULTS = [fault for fault in FAULTS if fault != "ok"]


class State(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]


def claim_makers(reader: httpx.Client) -> dict[str, Callable[..., Claim]]:
    """Map each write tool's arguments to the claim that must hold if it worked.

    Reschedule and cancel only name an appointment id, so the patient is looked
    up through the verifier's own read client, never through the agent. If that
    lookup fails, the claim omits the patient: the tool still runs (Readback
    observes, it does not block) and the verdict is logged as `unverified`.
    """

    def patient_of(appointment_id: str) -> dict[str, str]:
        try:
            response = reader.get(f"Appointment/{appointment_id}")
            response.raise_for_status()
            return {"patient": next(
                p["actor"]["reference"] for p in response.json()["participant"]
                if p["actor"]["reference"].startswith("Patient/")
            )}
        except (httpx.HTTPError, ValueError, KeyError, TypeError, StopIteration):
            return {}

    return {
        "book_appointment": lambda patient, practitioner, start, end: Claim(
            "fhir.appointment.create", "",
            {"patient": patient, "practitioner": practitioner, "start": start, "end": end, "status": "booked"},
        ),
        "reschedule_appointment": lambda appointment_id, start, end: Claim(
            "fhir.appointment.update", "",
            {"id": appointment_id, **patient_of(appointment_id), "start": start, "end": end},
        ),
        "cancel_appointment": lambda appointment_id: Claim(
            "fhir.appointment.cancel", "", {"id": appointment_id, **patient_of(appointment_id)},
        ),
    }


def build_tools(
    agent_client: httpx.Client, verifier_client: httpx.Client, log: EvidenceLog | None,
    on_verdict: list[Callable[[Verdict], None]],
) -> list[StructuredTool]:
    raw = make_tools(agent_client)
    makers = claim_makers(verifier_client)
    verifier = FhirAppointmentVerifier(verifier_client)
    # ToolNode runs a reply's tool calls in parallel threads. Two overlapping
    # snapshot/write/read-back windows for one patient would each report the
    # other's write as an extra effect, so each whole cycle runs under one lock.
    # ponytail: one global lock serializes all writes; per-patient locks if throughput matters.
    lock = threading.Lock()

    def serialized(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def call(*args: Any, **kwargs: Any) -> Any:
            with lock:
                return fn(*args, **kwargs)

        return call

    tools = []
    for schema in TOOL_SCHEMAS:
        name = schema["name"]
        fn = raw[name]
        if name in makers:  # reads (list_appointments) need no check
            fn = serialized(watched(fn, verifier, makers[name], log, on_verdict=on_verdict))
        tools.append(StructuredTool.from_function(func=fn, name=name, description=schema["description"]))
    return tools


def scripted_agent(request: dict[str, Any]) -> Callable[[State], dict[str, Any]]:
    """Stand-in for a chat model: call the tool once, then trust its answer."""

    def agent(state: State) -> dict[str, Any]:
        last = state["messages"][-1]
        if isinstance(last, ToolMessage):
            ok = "'ok': true" in last.content.lower() or '"ok": true' in last.content.lower()
            return {"messages": [AIMessage(content="DONE: booked." if ok else "FAILED: the system refused.")]}
        call = {"name": "book_appointment", "args": request, "id": "call_1"}
        return {"messages": [AIMessage(content="", tool_calls=[call])]}

    return agent


def chat_model(provider: str, model: str) -> Any:
    """A LangChain chat model for `provider`, keyed from the environment or .env."""
    import os

    from ..stripe_sandbox import _load_env_file  # ponytail: shared .env loader; real env vars win

    _load_env_file()
    variable = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}[provider]
    if not os.environ.get(variable):
        raise SystemExit(f"Set {variable} in your environment or .env first.")
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(model=model, max_tokens=1024, timeout=60, max_retries=2)
    from langchain_openai import ChatOpenAI

    return ChatOpenAI(model=model, timeout=60, max_retries=2)


def model_agent(chat: Any, tools: list[StructuredTool]) -> Callable[[State], dict[str, Any]]:
    bound = chat.bind_tools(tools)

    def agent(state: State) -> dict[str, Any]:
        return {"messages": [bound.invoke([SystemMessage(content=SYSTEM_PROMPT), *state["messages"]])]}

    return agent


def text_of(message: AnyMessage) -> str:
    content = message.content
    if isinstance(content, str):
        return content
    return " ".join(part if isinstance(part, str) else part.get("text", "") for part in content if isinstance(part, (str, dict)))


def build_graph(agent: Callable[[State], dict[str, Any]], tools: list[StructuredTool]) -> Any:
    graph = StateGraph(State)
    graph.add_node("agent", agent)
    graph.add_node("tools", ToolNode(tools))
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", tools_condition)  # tool call -> "tools", else END
    graph.add_edge("tools", "agent")
    return graph.compile()


def outcome(reply: str, verdicts: list[Verdict], task: Verdict | None = None) -> str:
    """One label per run, from the agent's reply, the verdicts of its writes and,
    when given, the task-level verdict.

    Per-write checks compare each write with the model's own arguments, so a
    model that books the wrong time passes them. The task verdict compares the
    record with what was actually requested and has the final word on DONE.
    """
    head = reply.strip().upper()
    if not head.startswith(("DONE", "FAILED")):
        return "unclear_reply"  # the model ignored the DONE:/FAILED: contract; not counted either way
    said_done = head.startswith("DONE")
    said = "done" if said_done else "failed"
    if not verdicts:
        return f"said_{said}_no_write"  # e.g. DONE without ever calling a write tool
    # Labels match run_eval.py; only said_*_no_write and done_after_failed_write are LangGraph-specific.
    if said_done and task is not None and task.status is Status.FAILED:
        return "false_completion"  # e.g. every write held, but at the wrong time
    if said_done and task is not None and task.status is Status.UNVERIFIED:
        return "done_but_unverified"
    statuses = {v.status for v in verdicts}
    if said_done and verdicts[-1].status is Status.VERIFIED and Status.FAILED in statuses:
        # The last write held, but an earlier one failed and may have left an effect behind.
        return "done_after_failed_write"
    if statuses == {Status.VERIFIED}:
        return "done_and_verified" if said_done else "said_failed_but_actually_done"
    if said_done:
        return "false_completion" if Status.FAILED in statuses else "done_but_unverified"
    return "reported_failure"


def run(
    runs: int, inject_faults: float, seed: int, log_path: Path, chat: Any | None = None,
) -> dict[str, Any]:
    rng = random.Random(seed)  # seeded for repeatable evals, not security  # nosec B311
    server = MockFhirServer()
    setup = server.client()
    patients, practitioners = seed_people(setup)
    log = EvidenceLog(log_path)
    task_verifier = FhirAppointmentVerifier(server.client())
    verdicts: list[Verdict] = []
    # The agent and the verifier get separate clients; in production, separate credentials.
    tools = build_tools(server.client(), server.client(), log, [verdicts.append])
    real_agent = build_graph(model_agent(chat, tools), tools) if chat is not None else None

    outcomes: Counter[str] = Counter()
    for index in range(runs):
        if real_agent is not None:
            task = make_task(rng, index, setup, patients, practitioners)  # setup writes fault-free
            prompt, probe, app = task.prompt, task.probe, real_agent
        else:
            start = slot(index)
            request = {
                "patient": rng.choice(patients), "practitioner": rng.choice(practitioners),
                "start": utc(start), "end": utc(start + VISIT),
            }
            prompt, app = f"Book {request}", build_graph(scripted_agent(request), tools)
            probe = Claim("fhir.appointment.create", "", {**request, "status": "booked"})
        context = {"run": index, "check": "task"}
        probe = Claim(probe.action, "", probe.expected, context)
        server.fault = rng.choice(WRITE_FAULTS) if rng.random() < inject_faults else "ok"
        seen = len(verdicts)
        # Task-level check: was the request itself done, whatever tools the agent chose?
        with watch(task_verifier, probe, log) as task_check:
            try:  # recursion_limit bounds a model that loops on tool calls
                reply = text_of(app.invoke({"messages": [HumanMessage(content=prompt)]}, {"recursion_limit": 12})["messages"][-1])
            except GraphRecursionError:
                reply = "FAILED: agent hit the step limit"
            task_check.claims(Claim(probe.action, reply, probe.expected, context))
        server.fault = "ok"
        outcomes[outcome(reply, verdicts[seen:], task_check.verdict)] += 1

    intact, _ = log.verify_chain()
    return {"runs": runs, "outcomes": dict(outcomes), "evidence_log": str(log_path), "chain_intact": intact}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--inject-faults", type=float, default=0.3)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--log", type=Path, default=None)
    parser.add_argument("--provider", choices=["scripted", "anthropic", "openai"], default="scripted")
    parser.add_argument("--model", help="e.g. claude-haiku-5-5 or gpt-6-luna (required with a real provider)")
    args = parser.parse_args(argv)
    if args.provider != "scripted" and not args.model:
        parser.error("--model is required with --provider anthropic or openai")
    if args.runs < 1:
        parser.error("--runs must be at least 1")
    if not 0.0 <= args.inject_faults <= 1.0:
        parser.error("--inject-faults must be between 0 and 1")
    log_path = args.log or Path(tempfile.mkdtemp(prefix="readback-langgraph-")) / "evidence.jsonl"
    if log_path.exists():  # same exit status as run_eval
        raise SystemExit(f"{log_path} already exists; pass a fresh --log path (an evidence log is never overwritten)")
    if not log_path.parent.is_dir():
        parser.error(f"directory for --log does not exist: {log_path.parent}")
    chat = chat_model(args.provider, args.model) if args.provider != "scripted" else None
    summary = run(args.runs, args.inject_faults, args.seed, log_path, chat)
    agent = args.model or "scripted"
    print(f"LangGraph agent ({agent}), {summary['runs']} requests, fault rate {args.inject_faults:.0%}")
    for outcome, count in sorted(summary["outcomes"].items()):
        print(f"  {outcome:<28}{count}")
    print(f"Evidence log: {summary['evidence_log']} (chain intact: {summary['chain_intact']})")


if __name__ == "__main__":
    main()
