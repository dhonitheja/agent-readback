# Changelog

All notable changes to `agent-readback`. Dates are UTC.

## 0.3.0 — 2026-11-20

### Added

- Truncation detection. `EvidenceLog(path, anchor=...)` calls the anchor
  with `(record count, head hash)` after every append; `FileAnchor(path)`
  keeps them in a separate file, written atomically. `readback verify-log
  --anchor FILE` or `--head HASH` reports BROKEN when the anchored head is no
  longer in the log. A failing anchor warns and sets `log.anchor_error`
  instead of breaking the agent.
- `recheck(verifier, verdict, log)` judges an `unverified` verdict again
  later; the result is logged with `context["recheck_of"]`. Verified and
  failed verdicts are never re-checked. `StripeRefundVerifier.recheck`
  judges only the refunds seen at the first check.
- `FindingKind.PENDING`: a Stripe refund that matches but has not settled.

### Changed

- A pending Stripe refund's finding is `pending` (was `unreachable`), and the
  verdict keeps the new refunds in `observed` so it can be re-checked.

### Fixed

- A pending Stripe refund with a wrong amount, currency or a second refund is
  now `failed`; before, being pending hid the mismatch as `unverified`.

## 0.2.2 — 2026-11-19

### Breaking changes

- **CLI exit codes.** A missing or unreadable file now exits `3` (was `2`).
  Codes are: `0` intact, `1` broken or untrustworthy, `2` bad arguments,
  `3` file error. Scripts that check for `2` on a missing file must change.
- **Webhook signing key.** `WebhookAlert` signs with its own
  `READBACK_ALERT_KEY` and never falls back to `READBACK_LOG_KEY`. Alerts are
  unsigned until `READBACK_ALERT_KEY` is set. A key equal to the log key is
  refused.

### Security

- FHIR verifier: paging `next` links are resolved the way httpx will send
  them and must stay on the client's scheme, host and port. Anything else is
  `unverified` and is never requested, so the read-only token cannot leak to
  another host. Root-relative links resolve against the server origin;
  malformed links (`InvalidURL`) are `unverified` instead of crashing the
  snapshot.
- `WebhookAlert` refuses a key that equals `READBACK_LOG_KEY` or a key used by
  any `EvidenceLog` in the same process, at creation and before each send.
- `verify-log`, `report` and `dashboard` label an OK without a key `UNKEYED`
  (not forgery-proof). New `--require-key` makes audits fail without a key.
  Records written with a key carry `"mac": "hmac-sha256"`, so a keyed log
  checked without its key says so instead of reporting an edit.
- `dashboard -o` refuses to overwrite the log itself, a hard link to it, any
  existing `.jsonl`, or a symlink that resolves to one.
- Malformed records (non-object JSON, missing `claim`, non-hex or non-ASCII
  `hash`/`prev`, boolean `seq`) report `BROKEN` instead of a traceback.

### Fixed

- `EvidenceLog.append` is serialized with a lock, so parallel tool calls
  (for example LangGraph `ToolNode`) can no longer write two records with the
  same sequence number.
- Evidence logs are written with LF line endings on every platform.
- CLI file errors (a directory as the path, a missing output folder) give a
  clean error instead of a traceback. BROKEN messages include the line number.
- `run_eval`: replies that start with neither `DONE` nor `FAILED` are counted
  as `unclear_reply` instead of `reported_failure`.
- `mcp_text` reads both `is_error` (MCP 2.x) and `isError` (MCP 1.x).

### Added

- `examples/healthcare/langgraph_agent.py`: a LangGraph agent (agent node +
  `ToolNode` loop) with every write tool wrapped by `watched()` and a
  task-level check of the requested result. Scripted by default; real models
  via `--provider anthropic|openai --model <id>`.
- `langgraph` extra (`langgraph`, `langchain-core`, `langchain-anthropic`,
  `langchain-openai`); `tzdata` on Windows in the `dev` and `langgraph`
  extras.
- `docs/ROADMAP.md`.
- Tests: 114 offline tests, passing on MCP 1.x and 2.x with LangGraph 1.2.

## 0.2.1 — 2026-11-19

OpenAI-compatible and OpenAI Responses agent loops, MCP and LangGraph
adapters (`watched()`), hardened evidence log.

## 0.2.0 — 2026-11-15

Readback 0.2: verify AI agent actions against the system of record (FHIR
appointments, Stripe refunds, SQL rows), with a hash-chained evidence log,
report, dashboard and webhook alerts.
