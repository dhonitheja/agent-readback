import asyncio
import sqlite3
import sys
import threading
from contextlib import closing
from pathlib import Path
from typing import TypedDict

import pytest

from agent_readback import Claim, Status, watched
from agent_readback.verifiers import FhirAppointmentVerifier, SqlRowVerifier
from tests.conftest import DOCTOR, END, PATIENT, START

ARGS = {"patient": PATIENT, "practitioner": DOCTOR, "start": START, "end": END}


def booking_claim(patient, practitioner, start, end):
    expected = {"patient": patient, "practitioner": practitioner, "start": start, "end": end, "status": "booked"}
    return Claim("fhir.appointment.create", "", expected)


def test_sync_call_is_verified_and_result_passes_through(server, tools):
    verdicts = []
    book = watched(tools["book_appointment"], FhirAppointmentVerifier(server.client()), booking_claim, on_verdict=[verdicts.append])

    result = book(**ARGS)

    assert result["ok"] is True
    assert [v.status for v in verdicts] == [Status.VERIFIED]
    assert verdicts[0].claim.agent_said == str(result)


def test_false_success_from_the_server_is_caught(server, tools):
    verdicts = []
    book = watched(tools["book_appointment"], FhirAppointmentVerifier(server.client()), booking_claim, on_verdict=[verdicts.append])
    server.fault = "drop"

    assert book(**ARGS)["ok"] is True  # the tool says it worked
    assert verdicts[0].status is Status.FAILED


def test_none_claim_skips_the_check(server, tools):
    verdicts = []
    listed = watched(tools["list_appointments"], FhirAppointmentVerifier(server.client()), lambda **_: None, on_verdict=[verdicts.append])

    listed(patient=PATIENT)

    assert verdicts == []


def test_a_raising_call_still_leaves_a_verdict(server, tools):
    verdicts = []

    def crashes_after_writing(**args):
        tools["book_appointment"](**args)
        raise RuntimeError("agent crashed")

    book = watched(crashes_after_writing, FhirAppointmentVerifier(server.client()), booking_claim, on_verdict=[verdicts.append])
    with pytest.raises(RuntimeError):
        book(**ARGS)

    assert verdicts[0].status is Status.VERIFIED  # the write landed before the crash


def test_async_call_is_verified(server, tools):
    verdicts = []

    async def book_async(**args):
        return tools["book_appointment"](**args)

    book = watched(book_async, FhirAppointmentVerifier(server.client()), booking_claim, on_verdict=[verdicts.append])
    server.fault = "wrong_time"
    asyncio.run(book(**ARGS))

    assert verdicts[0].status is Status.FAILED


def test_async_verifier_reads_run_off_loop_even_when_tool_raises(server, tools):
    loop_thread = threading.get_ident()
    events, verdicts = [], []

    class Verifier(FhirAppointmentVerifier):
        def snapshot(self, claim):
            assert threading.get_ident() != loop_thread
            events.append("snapshot")
            return super().snapshot(claim)

        def check(self, claim, before):
            assert threading.get_ident() != loop_thread
            events.append("check")
            return super().check(claim, before)

    async def book_and_raise(**args):
        events.append("tool")
        tools["book_appointment"](**args)
        raise RuntimeError("agent crashed")

    book = watched(book_and_raise, Verifier(server.client()), booking_claim, on_verdict=[verdicts.append])
    with pytest.raises(RuntimeError, match="agent crashed"):
        asyncio.run(book(**ARGS))

    assert events == ["snapshot", "tool", "check"]
    assert [v.status for v in verdicts] == [Status.VERIFIED]


def test_mcp_client_session_call_tool(server, tools):
    pytest.importorskip("mcp")
    from mcp.server.fastmcp import FastMCP
    from mcp.shared.memory import create_connected_server_and_client_session

    from agent_readback import mcp_text

    app = FastMCP("scheduler")
    app.tool()(tools["book_appointment"])
    verdicts = []

    def to_claim(name, arguments=None, *_, **__):
        return booking_claim(**arguments) if name == "book_appointment" else None

    async def scenario():
        async with create_connected_server_and_client_session(app) as session:
            session.call_tool = watched(
                session.call_tool, FhirAppointmentVerifier(server.client()), to_claim, said=mcp_text, on_verdict=[verdicts.append]
            )
            await session.call_tool("book_appointment", ARGS)
            server.fault = "duplicate"
            await session.call_tool("book_appointment", ARGS)

    asyncio.run(scenario())

    assert [v.status for v in verdicts] == [Status.VERIFIED, Status.FAILED]
    assert '"ok": true' in verdicts[0].claim.agent_said.lower()


def test_mcp_stdio_tool_write_is_verified(tmp_path):
    pytest.importorskip("mcp")
    from anyio import fail_after
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    from agent_readback import mcp_text

    database = tmp_path / "appointments.sqlite"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE TABLE appointments (patient TEXT PRIMARY KEY, practitioner TEXT, start TEXT, end TEXT)")
    verifier = SqlRowVerifier(
        lambda: sqlite3.connect(database.as_uri() + "?mode=ro", uri=True), "appointments", "patient", placeholder="?"
    )
    params = StdioServerParameters(
        command=sys.executable, args=[str(Path(__file__).with_name("mcp_stdio_server.py")), str(database)]
    )
    verdicts = []

    async def scenario():
        with fail_after(30):  # generous ceiling for a cold subprocess start; normal run is ~2s
            async with stdio_client(params) as streams, ClientSession(*streams) as session:
                await session.initialize()
                book = watched(
                    session.call_tool, verifier,
                    lambda name, arguments: Claim("sql.row.insert", "", arguments),
                    said=mcp_text, on_verdict=[verdicts.append],
                )
                return await book("book_appointment", ARGS)

    # mcp is installed by this point: a hang is a real failure, never a skip.
    result = asyncio.run(scenario())

    assert not result.isError
    assert [v.status for v in verdicts] == [Status.VERIFIED]
    assert verdicts[0].claim.agent_said == "Booked."


def test_langgraph_node(server, tools):
    pytest.importorskip("langgraph")
    from langgraph.graph import END as GRAPH_END
    from langgraph.graph import START as GRAPH_START
    from langgraph.graph import StateGraph

    class State(TypedDict, total=False):
        booking: dict
        result: dict

    def book_node(state: State) -> State:
        return {"result": tools["book_appointment"](**state["booking"])}

    verdicts = []
    graph = StateGraph(State)
    graph.add_node(
        "book", watched(book_node, FhirAppointmentVerifier(server.client()), lambda s: booking_claim(**s["booking"]), on_verdict=[verdicts.append])
    )
    graph.add_edge(GRAPH_START, "book")
    graph.add_edge("book", GRAPH_END)
    app = graph.compile()

    assert app.invoke({"booking": ARGS})["result"]["ok"] is True
    server.fault = "wrong_practitioner"
    app.invoke({"booking": ARGS})

    assert [v.status for v in verdicts] == [Status.VERIFIED, Status.FAILED]


def test_langgraph_tool_node_verifies_wrapped_tool(server, tools):
    pytest.importorskip("langgraph")
    pytest.importorskip("langchain_core")
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from langgraph.prebuilt import ToolNode

    @tool
    def book(patient: str, practitioner: str, start: str, end: str) -> dict:
        """Book an appointment in the mock FHIR store."""
        return tools["book_appointment"](patient, practitioner, start, end)

    verdicts = []
    book.func = watched(book.func, FhirAppointmentVerifier(server.client()), booking_claim, on_verdict=[verdicts.append])
    node = in_graph(ToolNode([book]))
    message = AIMessage(content="", tool_calls=[{"name": book.name, "args": ARGS, "id": "call_1"}])

    result = node.invoke({"messages": [message]})

    assert result["messages"][-1].tool_call_id == "call_1"
    assert [v.status for v in verdicts] == [Status.VERIFIED]


def in_graph(node):
    """LangGraph 1.x runs ToolNode only inside a graph; wrap it in a one-node graph."""
    from langgraph.graph import END as GRAPH_END
    from langgraph.graph import START as GRAPH_START
    from langgraph.graph import MessagesState, StateGraph

    graph = StateGraph(MessagesState)
    graph.add_node("tools", node)
    graph.add_edge(GRAPH_START, "tools")
    graph.add_edge("tools", GRAPH_END)
    return graph.compile()


def test_cancellation_after_the_write_still_leaves_one_verdict(server, tools):
    anyio = pytest.importorskip("anyio")
    verdicts, log = [], []

    async def writes_then_hangs(**args):
        tools["book_appointment"](**args)
        await anyio.sleep(30)

    book = watched(writes_then_hangs, FhirAppointmentVerifier(server.client()), booking_claim, log, on_verdict=[verdicts.append])

    async def scenario():
        with anyio.move_on_after(0.2):  # AnyIO re-cancels every await in the scope, as MCP timeouts do
            await book(**ARGS)

    anyio.run(scenario)

    assert [v.status for v in verdicts] == [Status.VERIFIED] and log == verdicts


def test_object_with_async_call_is_checked_after_it_runs(server, tools):
    verdicts = []

    class BookTool:
        async def __call__(self, **args):
            return tools["book_appointment"](**args)

    book = watched(BookTool(), FhirAppointmentVerifier(server.client()), booking_claim, on_verdict=[verdicts.append])
    asyncio.run(book(**ARGS))

    assert [v.status for v in verdicts] == [Status.VERIFIED]
