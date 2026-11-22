"""Run scheduling requests through an agent and check every result with Readback.

Without an API key (scripted agent that always makes the correct calls, with
server faults injected so there is something to catch):

    python -m examples.healthcare.run_eval --provider scripted --runs 200 --inject-faults 0.2

With a real model (set the key in your shell first, never in a file you commit):

    export ANTHROPIC_API_KEY=...
    python -m examples.healthcare.run_eval --provider anthropic --model claude-haiku-5-5 --runs 100

    export OPENAI_API_KEY=...
    python -m examples.healthcare.run_eval --provider openai --model gpt-6-luna --runs 100

By default the FHIR server is the in-memory mock. Pass --fhir-url to use a real
FHIR R4 test server instead; only synthetic records are created.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import httpx

from agent_readback import Claim, EvidenceLog, Status, watch
from agent_readback.verifiers import FhirAppointmentVerifier

from .llm import AnthropicProvider, OpenAICompatProvider, OpenAIResponsesProvider, ScriptedProvider
from .mock_fhir import FAULTS, MockFhirServer
from .tasks import Task, make_task, seed_people
from .tools import SYSTEM_PROMPT, TOOL_SCHEMAS, make_tools

WRITE_FAULTS = [fault for fault in FAULTS if fault != "ok"]


def build_provider(args: argparse.Namespace, current: dict[str, Task]) -> Any:
    if args.provider == "scripted":
        return ScriptedProvider(lambda prompt, call: current["task"].oracle(call))
    from ..stripe_sandbox import _load_env_file  # ponytail: shared .env loader; real env vars win
    _load_env_file()
    variable = "ANTHROPIC_API_KEY" if args.provider == "anthropic" else "OPENAI_API_KEY"
    key = os.environ.get(variable)
    if not key:
        sys.exit(f"Set {variable} in your environment first.")
    if not args.model:
        sys.exit("Pass --model, for example claude-haiku-5-5 or gpt-6-luna.")
    if args.provider == "anthropic":
        return AnthropicProvider(args.model, key)
    if args.provider == "openai-responses":
        return OpenAIResponsesProvider(
            args.model, key, base_url=args.base_url, reasoning_effort=args.reasoning_effort or None,
            store=not args.no_store,
        )
    return OpenAICompatProvider(args.model, key, base_url=args.base_url, reasoning_effort=args.reasoning_effort or None)


def safe_caller(tools: dict[str, Any]):
    def call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name not in tools:
            return {"ok": False, "error": f"unknown tool {name}"}
        try:
            return tools[name](**arguments)
        except TypeError as error:
            return {"ok": False, "error": f"bad arguments: {error}"}
        except httpx.HTTPError as error:
            return {"ok": False, "error": f"request failed: {error}"}

    return call


def run(args: argparse.Namespace) -> dict[str, Any]:
    rng = random.Random(args.seed)  # seeded for repeatable evals, not security  # nosec B311
    server: MockFhirServer | None = None
    if args.fhir_url:
        new_client = lambda: httpx.Client(base_url=args.fhir_url, timeout=30.0)  # noqa: E731
    else:
        server = MockFhirServer()
        new_client = server.client
    setup, agent_client, verifier_client = new_client(), new_client(), new_client()

    verifier = FhirAppointmentVerifier(verifier_client)
    if args.log.exists():
        sys.exit(f"{args.log} already exists; pass a fresh --log path (an evidence log is never overwritten)")
    log = EvidenceLog(args.log, keep_fields="*" if args.keep_values else ())
    current: dict[str, Task] = {}
    provider = build_provider(args, current)
    call_tool = safe_caller(make_tools(agent_client))
    patients, practitioners = seed_people(setup)

    outcomes: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    by_task: dict[str, Counter[str]] = {}
    warned_model_error = False

    for index in range(args.runs):
        task = make_task(rng, index, setup, patients, practitioners)  # setup writes happen fault-free
        current["task"] = task
        if server is not None and rng.random() < args.inject_faults:
            server.fault = rng.choice(WRITE_FAULTS)
        context = {"run": index, "task": task.kind, "provider": args.provider, "model": args.model or "scripted"}
        probe = Claim(task.probe.action, "", task.probe.expected, context)

        with watch(verifier, probe, log, settle_attempts=args.settle_attempts) as watched:
            try:
                message = provider.run(SYSTEM_PROMPT, task.prompt, TOOL_SCHEMAS, call_tool)
            except httpx.HTTPError as error:
                detail = type(error).__name__
                if isinstance(error, httpx.HTTPStatusError):
                    detail += f" {error.response.status_code}"
                message = f"FAILED: model request error ({detail})"
                if not warned_model_error:
                    print(f"Warning: {message}", file=sys.stderr)
                    warned_model_error = True
            watched.claims(Claim(probe.action, message, probe.expected, context))
        if server is not None:
            server.fault = "ok"

        head = message.strip().upper()
        said_done = head.startswith("DONE")
        status = watched.verdict.status
        if not said_done and not head.startswith("FAILED"):
            outcome = "unclear_reply"  # neither DONE: nor FAILED:; not counted as a claim either way
        elif said_done and status is Status.VERIFIED:
            outcome = "done_and_verified"
        elif said_done and status is Status.FAILED:
            outcome = "false_completion"
        elif said_done:
            outcome = "done_but_unverified"
        elif status is Status.VERIFIED:
            outcome = "said_failed_but_actually_done"
        else:
            outcome = "reported_failure"
        outcomes[outcome] += 1
        by_task.setdefault(task.kind, Counter())[outcome] += 1
        if outcome == "false_completion":
            for finding in watched.verdict.findings:
                kinds[finding.kind.value] += 1

    said_done_total = outcomes["done_and_verified"] + outcomes["false_completion"] + outcomes["done_but_unverified"]
    intact, _ = log.verify_chain()
    return {
        "provider": args.provider,
        "model": args.model or "scripted",
        "fhir_server": args.fhir_url or "in-memory mock",
        "injected_fault_rate": args.inject_faults if server is not None else 0.0,
        "runs": args.runs,
        "seed": args.seed,
        "agent_said_done": said_done_total,
        "outcomes": dict(outcomes),
        "false_completion_rate_of_done": (outcomes["false_completion"] / said_done_total) if said_done_total else 0.0,
        "false_completion_findings": dict(kinds),
        "by_task": {kind: dict(counts) for kind, counts in sorted(by_task.items())},
        "evidence_log": str(args.log),
        "chain_intact": intact,
    }


def render(summary: dict[str, Any]) -> str:
    outcomes = summary["outcomes"]
    lines = [
        f"Agent: {summary['provider']} / {summary['model']}    FHIR server: {summary['fhir_server']}",
        f"Injected server fault rate: {summary['injected_fault_rate']:.0%}",
        f"Requests:                         {summary['runs']}",
        f"Agent said DONE:                  {summary['agent_said_done']}",
        f"  verified in the record:         {outcomes.get('done_and_verified', 0)}",
        f"  FALSE COMPLETIONS caught:       {outcomes.get('false_completion', 0)}  ({summary['false_completion_rate_of_done']:.1%} of DONE)",
        f"  could not be checked:           {outcomes.get('done_but_unverified', 0)}",
        f"Agent said FAILED:                {outcomes.get('reported_failure', 0) + outcomes.get('said_failed_but_actually_done', 0)}",
        f"  yet the record shows it done:   {outcomes.get('said_failed_but_actually_done', 0)}",
    ]
    if outcomes.get("unclear_reply"):
        lines.append(f"Reply neither DONE nor FAILED:    {outcomes['unclear_reply']}")
    if summary["false_completion_findings"]:
        lines.append("Why the false completions failed:")
        lines += [f"  {kind}: {count}" for kind, count in sorted(summary["false_completion_findings"].items())]
    lines.append(f"Evidence log: {summary['evidence_log']} (chain intact: {summary['chain_intact']})")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--provider", choices=["scripted", "anthropic", "openai", "openai-responses"], default="scripted")
    parser.add_argument("--model", default="")
    parser.add_argument("--base-url", default="https://api.openai.com/v1", help="for --provider openai or compatible servers")
    parser.add_argument("--reasoning-effort", default="", help="openai only; gpt-6-luna needs 'none' for tools on chat/completions")
    parser.add_argument("--no-store", action="store_true", help="disable response storage for --provider openai-responses")
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--fhir-url", default="", help="real FHIR R4 base URL; default is the in-memory mock")
    parser.add_argument("--inject-faults", type=float, default=0.0, help="share of runs with a mock-server write fault")
    parser.add_argument("--settle-attempts", type=int, default=1)
    parser.add_argument("--keep-values", action="store_true", help="store field values in the log (synthetic data only)")
    parser.add_argument("--log", type=Path, default=None, help="evidence log path; must not exist yet (default: fresh temp file)")
    parser.add_argument("--out", type=Path, help="also write the summary as JSON")
    args = parser.parse_args(argv)
    if args.no_store and args.provider != "openai-responses":
        parser.error("--no-store only applies to --provider openai-responses")
    if args.log is None:
        handle, name = tempfile.mkstemp(prefix="readback_eval_", suffix=".jsonl")
        os.close(handle)
        args.log = Path(name)
        args.log.unlink()  # mkstemp reserved a unique name; run() requires it not to exist yet
    summary = run(args)
    print(render(summary))
    if args.out:
        args.out.write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    main()
