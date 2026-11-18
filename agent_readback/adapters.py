"""One-line adapters: wrap any tool call or graph node so its effect is checked.

`watched()` wraps a sync or async function. Before each call, `to_claim` turns
the call's arguments into a claim (or None to skip the check). The function
runs with the `watch()` lifecycle, so the verifier snapshots before and re-reads after,
even if the function raises. Nothing here imports MCP or LangGraph.

MCP client (any `ClientSession`):

    session.call_tool = watched(session.call_tool, verifier, to_claim, log, said=mcp_text)

LangGraph node, or a function wrapped by a LangChain tool:

    graph.add_node("book", watched(book_node, verifier, to_claim, log))

Verdicts go to `on_verdict` callbacks, for example `on_verdict=[verdicts.append]`
or a `WebhookAlert`. The wrapped function's return value is passed through
unchanged: the adapter records and reports, it does not edit what the agent sees.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Callable, Iterable

from .core import Claim, Verdict, Verifier, Watch, _check, watch

ToClaim = Callable[..., "Claim | None"]


def mcp_text(result: Any) -> str:
    """The text an MCP `CallToolResult` returned, used as the agent's claim message."""
    parts = [getattr(block, "text", None) for block in getattr(result, "content", None) or ()]
    text = " ".join(part for part in parts if part)
    return f"ERROR: {text}" if getattr(result, "isError", False) else text


def watched(
    fn: Callable[..., Any],
    verifier: Verifier,
    to_claim: ToClaim,
    log: Any | None = None,
    *,
    said: Callable[[Any], str] = str,
    on_verdict: Iterable[Callable[[Verdict], None]] = (),
    **watch_options: Any,
) -> Callable[..., Any]:
    """Return `fn` wrapped so every call it makes is verified against the system of record.

    `to_claim` receives the same arguments as `fn` and returns the claim that must
    hold if the call succeeds. `said` turns `fn`'s result into the agent's message.
    `watch_options` go to `watch()` (settle_attempts, settle_delay, sleep).
    """
    callbacks = tuple(on_verdict)

    def final(probe: Claim, result: Any) -> Claim:
        return Claim(probe.action, said(result), probe.expected, probe.context)

    # An object with `async def __call__` is not a coroutine function to inspect, but
    # calling it returns a coroutine; treat it as async or the check runs before the write.
    # A plain sync function that returns an awaitable is not supported: wrap the async callee.
    if inspect.iscoroutinefunction(fn) or inspect.iscoroutinefunction(getattr(fn, "__call__", None)):

        @functools.wraps(fn)
        async def run_async(*args: Any, **kwargs: Any) -> Any:
            probe = to_claim(*args, **kwargs)
            if probe is None:
                return await fn(*args, **kwargs)
            w = Watch()
            before = await asyncio.to_thread(verifier.snapshot, probe)

            async def finish(claim: Claim) -> None:
                try:
                    verdict = await asyncio.to_thread(_check, verifier, claim, before, **watch_options)
                except BaseException:
                    # Cancelled during the read-back (AnyIO re-cancels every await in a
                    # cancelled scope). Redo it blocking so the audit record is never lost.
                    w._record(_check(verifier, claim, before, **watch_options), log, callbacks)
                    raise
                w._record(verdict, log, callbacks)

            try:
                result = await fn(*args, **kwargs)
            except BaseException:
                await finish(probe)
                raise
            w.claims(final(probe, result))
            await finish(w.claim)
            return result

        return run_async

    @functools.wraps(fn)
    def run(*args: Any, **kwargs: Any) -> Any:
        probe = to_claim(*args, **kwargs)
        if probe is None:
            return fn(*args, **kwargs)
        with watch(verifier, probe, log, on_verdict=callbacks, **watch_options) as w:
            result = fn(*args, **kwargs)
            w.claims(final(probe, result))
        return result

    return run
