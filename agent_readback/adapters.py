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
import warnings
from typing import Any, Callable, Iterable

from .core import Claim, Verdict, Verifier, Watch, _check, watch

ToClaim = Callable[..., "Claim | None"]


def _is_async(fn: Callable[..., Any]) -> bool:
    # An object with `async def __call__` is not a coroutine function to inspect, but
    # calling it returns a coroutine; treat it as async or the check runs before the write.
    return inspect.iscoroutinefunction(fn) or inspect.iscoroutinefunction(getattr(fn, "__call__", None))


def mcp_text(result: Any) -> str:
    """The text an MCP `CallToolResult` returned, used as the agent's claim message."""
    parts = [getattr(block, "text", None) for block in getattr(result, "content", None) or ()]
    text = " ".join(part for part in parts if part)
    failed = getattr(result, "isError", None)  # mcp 1.x
    if failed is None:
        failed = getattr(result, "is_error", False)  # mcp 2.x renamed the field
    return f"ERROR: {text}" if failed else text


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

    # A plain sync function that returns an awaitable is not supported: wrap the async callee.
    if _is_async(fn):

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


class OutcomeNotVerified(RuntimeError):
    """Raised by a `receipted()` call whose outcome did not verify. `.receipt` holds the receipt.

    The message names the verdict and reason kinds only, never values, because
    agent frameworks show it to the model and may log it.
    """

    def __init__(self, receipt: Any) -> None:
        self.receipt = receipt
        kinds = sorted({reason["kind"] for reason in receipt.reasons})
        super().__init__(f"outcome not verified: {receipt.verdict}" + (f" ({', '.join(kinds)})" if kinds else ""))


def _issue_keeping(error: BaseException, issue: Callable[..., Any], *args: Any) -> None:
    """Issue the receipt for a call that raised, without letting a receipt failure replace its exception."""
    try:
        issue(*args)
    except Exception as secondary:  # the tool's own exception is what the caller handles
        note = f"readback: receipt step failed: {type(secondary).__name__}: {secondary}"
        add_note = getattr(error, "add_note", None)
        if callable(add_note):  # Python 3.11+
            add_note(note)
        else:  # Python 3.10: no notes, so report it as a warning rather than lose it
            warnings.warn(note, RuntimeWarning, stacklevel=3)


class _Seen:
    """The evidence log for one `receipted()` call: keeps each verdict before writing it on.

    So a failed evidence-log write still leaves the verdict for the receipt.
    """

    def __init__(self, log: Any) -> None:
        self.verdicts: list[Verdict] = []
        self._log = log

    def append(self, verdict: Verdict) -> Any:
        self.verdicts.append(verdict)
        return None if self._log is None else self._log.append(verdict)


def receipted(
    fn: Callable[..., Any],
    verifier: Verifier,
    to_claim: ToClaim,
    receipts: Any,
    log: Any | None = None,
    *,
    said: Callable[[Any], str] = str,
    outcome_id: Callable[..., "str | None"] | None = None,
    on_verdict: Iterable[Callable[[Verdict], None]] = (),
    on_receipt: Iterable[Callable[[Any], None]] = (),
    **watch_options: Any,
) -> Callable[..., Any]:
    """Like `watched()`, but the call only succeeds once its receipt verifies.

    After every checked call a receipt is issued and appended to `receipts` (a
    `ReceiptLog`). Unless the receipt is `verified`, `OutcomeNotVerified` is
    raised, so the agent never sees a success it can report as "done". In a
    LangGraph `ToolNode` the error becomes the tool message the model reads; on
    an MCP `ClientSession.call_tool` the caller gets the exception. If `fn`
    itself raises, its receipt is still issued and its own exception propagates;
    if issuing that receipt fails too, the failure is added to it as a note.
    If writing the evidence log fails, the receipt is still issued from the
    verdict and the logging error propagates.

    `outcome_id(*args, **kwargs)` may return an id to store on the receipt.

        refund = receipted(issue_refund, verifier, to_claim, ReceiptLog("receipts.jsonl"), log=evidence)
    """
    from .receipts import issue_receipt, receipt_key  # receipts imports alerts; keep adapters import-light

    receipt_key(receipts.key)  # fail at wrap time, not on the first refund
    verdict_callbacks, receipt_callbacks = tuple(on_verdict), tuple(on_receipt)

    def inner(seen: _Seen) -> Callable[..., Any]:
        # A fresh wrapper per call: parallel calls (ToolNode threads) never share `seen`.
        return watched(fn, verifier, to_claim, seen, said=said, on_verdict=verdict_callbacks, **watch_options)

    def issue(seen: _Seen, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
        if not seen.verdicts:
            return None  # to_claim returned None: nothing was checked
        oid = outcome_id(*args, **kwargs) if outcome_id is not None else None
        receipt = issue_receipt(seen.verdicts[-1], receipts.key, outcome_id=oid, signing_key=receipts.signing_key)
        receipts.append(receipt)
        for callback in receipt_callbacks:
            callback(receipt)
        return receipt

    def gate(receipt: Any) -> None:
        if receipt is not None and not receipt.billable:
            raise OutcomeNotVerified(receipt)

    if _is_async(fn):

        @functools.wraps(fn)
        async def run_async(*args: Any, **kwargs: Any) -> Any:
            seen = _Seen(log)
            try:
                result = await inner(seen)(*args, **kwargs)
            except BaseException as error:
                _issue_keeping(error, issue, seen, args, kwargs)
                raise
            gate(issue(seen, args, kwargs))
            return result

        return run_async

    @functools.wraps(fn)
    def run(*args: Any, **kwargs: Any) -> Any:
        seen = _Seen(log)
        try:
            result = inner(seen)(*args, **kwargs)
        except BaseException as error:
            _issue_keeping(error, issue, seen, args, kwargs)
            raise
        gate(issue(seen, args, kwargs))
        return result

    return run
