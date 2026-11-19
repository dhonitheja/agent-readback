# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Readback (`agent-readback`, v0.2.1): checks an AI agent's "Done." claim against the system of record. Snapshot before the agent acts, re-read afterward through a read-only path, emit a deterministic verdict (`verified` / `failed` / `unverified`). Verdicts never come from an LLM. Only runtime dependency: `httpx`.

## Commands

Run everything from this directory (the repo root): tests import `examples.healthcare.*` as a top-level package.

```bash
python -m venv .venv                               # isolated env (recommended)
source .venv/bin/activate                          # macOS/Linux; Windows: .venv\Scripts\activate (cmd/PowerShell) or source .venv/Scripts/activate (Git Bash)
python -m pip install -e ".[dev,langgraph]" mcp    # optional extras enable the MCP and LangGraph tests (MCP 1.x and 2.x both work)
python -m pytest                                   # full suite (in-memory mocks, no network)
python -m pytest tests/test_fhir_verifier.py::test_duplicate_booking_is_an_extra_effect   # single test
python -m examples.healthcare.run_eval --provider scripted --runs 200 --inject-faults 0.2
export READBACK_LOG_KEY=...                        # key the log was written with; omit only for unkeyed logs
readback verify-log evidence.jsonl                 # chain check, prints head hash (0 ok, 1 broken/untrustworthy, 2 bad args, 3 file error; --require-key for audits)
readback report evidence.jsonl                     # verdict counts / failed rate by action
python -m build                                    # wheel + sdist into dist/
```

`run_eval` refuses an existing `--log` path (default: fresh temp file, path printed at the end). Real-model eval: `--provider anthropic|openai --model <id>` with `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` in the environment; `--fhir-url` targets a real FHIR R4 test server instead of the mock. No lint/format config exists. On Windows the `readback` script lands outside PATH; use `python -m agent_readback`.

## Architecture

- `agent_readback/core.py` — the whole contract. `Claim` (action, agent_said, expected fields, context) → `Verifier` protocol (`snapshot(claim)` before, `check(claim, before)` after) → `Verdict` with `Finding`s of kind `missing` / `wrong_value` / `extra_effect` / `unreachable`. `watch()` context manager orchestrates: snapshot on enter with a `probe` claim, check in a `finally` on exit (runs even if the agent raises) with the final claim set via `w.claims(...)`, optional settle retries (only `FAILED` is retried, never `UNVERIFIED`), then appends to the log and fires `on_verdict` callbacks.
- `agent_readback/verifiers/` — FHIR Appointment (create/update/cancel), Stripe refund, SQL row. Shared pattern: snapshot captures prior state (existing IDs for FHIR/Stripe; row + row count for SQL), or `None` on read error; anything new that wasn't claimed becomes `extra_effect`; read errors yield `UNVERIFIED`, never `FAILED`; a `None` snapshot means `UNVERIFIED`. Field comparison goes through `compare_fields`. FHIR normalizes timestamps to UTC and deliberately leaves zoneless times unnormalized so they mismatch. FHIR and Stripe reads are page-capped (`MAX_PAGES`); overflow → `UNVERIFIED`. A `pending` Stripe refund is `UNVERIFIED`, not verified.
- `agent_readback/evidence.py` — append-only JSONL log; each record carries `seq` and hashes the previous (`GENESIS` = 64 zeros). With a key (`key=` or `READBACK_LOG_KEY`) hashes are HMAC-SHA256; `_digest(prev, seq, body, key)` is the single hashing function. File opened `0600` + `O_APPEND`. Redacts by default: no observed values, agent text replaced by a keyed digest, expected/finding values replaced unless the field is in `keep_fields` (`"*"` keeps all). Preserve this default when changing the log format. README "Security model" table must stay in sync with these guarantees.
- `agent_readback/adapters.py` — `watched(fn, verifier, to_claim, log, said=...)` wraps a sync/async callable in `watch()`; `to_claim(*args, **kwargs)` → probe or `None` (skip). Used for MCP (`session.call_tool = watched(...)`, `said=mcp_text`) and LangGraph nodes. Imports neither framework; tests use them via `importorskip`.
- `agent_readback/report.py`, `dashboard.py` (one-file HTML page, everything escaped; `readback dashboard`), `cli.py`, `alerts.py` (`WebhookAlert` as an `on_verdict` callback; swallows every exception; signs the body with `X-Readback-Signature` using `READBACK_ALERT_KEY`, never the log key, so a receiver can't forge the log). FHIR paging refuses next links whose httpx-resolved URL leaves the client's origin (token leak). CLI flags keyless OKs as UNKEYED and never lets `dashboard -o` overwrite a log. Evals label replies that start with neither `DONE` nor `FAILED` as `unclear_reply` (not counted as claims); the LangGraph agent labels a DONE whose last write held after an earlier failed one `done_after_failed_write`. Logs are written with LF endings on every OS.
- `graphify-out/` — generated knowledge graph of this repo (`/graphify`), not part of the package. Refresh with `/graphify --update` after doc changes.
- `examples/healthcare/` — demo harness and test fixtures: `mock_fhir.py` (in-memory FHIR via `httpx.MockTransport`; `server.fault` in `ok|drop|wrong_time|wrong_practitioner|duplicate` — faults still return success; `server.down` simulates outage), `tools.py` (agent's write tools — intentionally never read back), `llm.py` (Anthropic / OpenAI-compatible chat completions / OpenAI Responses (reasoning + tools, chained via `previous_response_id`) / Scripted tool loops via raw httpx), `tasks.py` (Central-time requests plus an oracle for the scripted agent), `run_eval.py`, `langgraph_agent.py` (agent + `ToolNode` loop with `watched()` write tools; scripted agent node by default, `--provider anthropic|openai --model <id>` via the `[langgraph]` extra; reschedule/cancel claims look up the patient via the verifier's client).

## Conventions

- All HTTP goes through an injected `httpx.Client`; tests swap in `httpx.MockTransport`. Keep new verifiers and providers injectable the same way.
- New verifier: implement `snapshot`/`check` per `core.Verifier`, name actions `<system>.<resource>.<verb>`, export from `verifiers/__init__.py`, update the README verifier table.
- The verifier must use credentials the agent doesn't hold; a shared write path makes the check meaningless.
- The README's "What is tested and what is not" and "Security model" tables are kept honest. Update them (and the test count, currently 114) when coverage or guarantees change.
- Security changes need a test that demonstrates the attack failing (see `test_keyed_log_detects_a_chain_forged_without_the_key`), not just the happy path.
