# Changelog

All notable changes to `agent-readback`. Dates are UTC.

## Unreleased

### Fixed

- A malformed FHIR or Stripe response (for example a list where an object is
  expected, a string entry, or a non-string id or reference) made the verifier
  raise `AttributeError` or `TypeError` out of `watch()`, breaking the agent's
  call. Responses are now shape-checked where they are parsed and anything
  malformed is `unverified`. A Stripe refund page that repeats now stops after
  the second request instead of after `MAX_PAGES`.

### Documentation

- README reworked as a front page: quick start near the top, a results table,
  shorter security cells with notes.
- `FileAnchor` guidance corrected: the log writer itself rewrites the anchor
  file, so the file is only as safe as the log. Check against a copy the
  writer cannot rewrite that holds the current head (an older copy such as a
  backup lets records added since be dropped undetected), or pass an anchor
  callable that appends to an independent append-only store; monitor
  `anchor_error` if you rely on the anchor. (The old text said to put the file
  where the writer cannot change it, which would make anchoring fail.)

## 0.3.0 — 2026-11-22

### Breaking changes

- `StripeRefundVerifier` refuses a client that sends a Stripe secret key
  (`sk_live_...` or `sk_test_...`, as Basic auth or a Bearer header) with
  `ValueError`. A secret key can also create refunds, which defeats the
  independent check; use a restricted read-only `rk_` key.
- `SqlRowVerifier(..., placeholder=...)` raises `ValueError` for anything
  other than `?`, `%s`, `:name`, `:1` or `$1`.
- A pending Stripe refund's finding is `pending` (was `unreachable`), and the
  verdict keeps the new refunds in `observed` so it can be re-checked.
- The LangGraph example uses the same outcome labels as `run_eval`:
  `false_completion` (was `false_completion_caught`), `done_but_unverified`
  (was `said_done_unverified`), `said_failed_but_actually_done` (was
  `said_failed_but_verified`) and `reported_failure` (was
  `said_failed_and_failed` / `said_failed_unverified`).

### Security

- On Windows, where mode `0600` does nothing, a new evidence log is created
  empty, has every existing access entry (explicit and inherited) removed with
  `icacls` and is granted only to the
  SID of the process's own access token (read with `whoami`), all before the
  first record is written. `icacls` and `whoami` are run from the directory
  `GetSystemDirectoryW` returns; `USERNAME`, `USERDOMAIN`, `SystemRoot` and
  `PATH` are never used, so an environment naming another account cannot
  lock the writer out of its own log. A failure (including an `icacls` that
  prints nothing) warns and the log is still written.
- The `sk_` key check inspects only static keys (exactly httpx `BasicAuth`, not
  a subclass, or a
  Bearer header); a custom auth flow is never run during construction.
- `SqlRowVerifier` validates `placeholder`: it is spliced into the query
  text, so a value such as `? OR 1=1` used to reach the database.

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
- Opt-in read limiting: `RateLimit(per_second, burst=1, *, max_wait=None)`
  (thread-safe token bucket) and `limit_reads(target, limit)`, which applies it
  to a verifier's `httpx.Client` (every request, paging included) or SQL
  `connect` callable. A limit only delays reads. With `max_wait`, a read that
  would wait longer raises `RateLimitTimeout` (a subclass of
  `httpx.TimeoutException`) at once without using a slot, so the verdict is
  `unverified` instead of the agent stalling. Limiting the same target twice
  is refused.
- Test of `watched()` over MCP Streamable HTTP (local server on 127.0.0.1,
  MCP 1.x and 2.x): an honest booking is `verified` and a misdescribed one
  `failed`. `tests/mcp_stdio_server.py DATABASE PORT` serves HTTP.
- `security` extra (bandit, pip-audit, pinned) and a `security` CI job that
  fails on any unmarked bandit finding or any known dependency vulnerability.

### Fixed

- On Windows, output from `whoami`/`icacls` that cannot be decoded (for
  example a non-ASCII account name in another code page) no longer escapes
  and stops the first evidence append; it is decoded tolerantly and any
  failure warns.
- `RateLimit(..., max_wait=0)` no longer refuses a read inside a fresh burst
  because of floating-point rounding. A rounding-sized wait counts as none;
  the cutoff scales with the clock value, since `time.monotonic()` counts
  from boot and its rounding error grows with uptime.
- The LangGraph example classifies a `FAILED` reply by the task verdict when
  there is one, as `run_eval` does: writes that held at the wrong time are
  `reported_failure`, not `said_failed_but_actually_done`.
- A pending Stripe refund with a wrong amount, currency or a second refund is
  now `failed`; before, being pending hid the mismatch as `unverified`.
- The example `.env` loader warns when the file cannot be read instead of
  ignoring the error.

### Documentation

- README: real-model results for the LangGraph agent (claude-sonnet-5-5,
  claude-haiku-5-5, gpt-6-luna; 50 runs each, verdicts identical to
  `run_eval` run for run), MCP 2.x and HTTP coverage, a "Rate limiting the
  verifier's reads" section, and two new Security model rows.

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
