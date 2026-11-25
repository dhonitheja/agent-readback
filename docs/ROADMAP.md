# Roadmap

Derived from the architecture (see `CLAUDE.md`), the README's "Not yet tested
against" column and known limits, and open items from the 0.2.2 hardening work.

## How the pieces fit

```
agent action ──► Claim ──► watch() ──► Verifier (FHIR / Stripe / SQL)
                              │          snapshot before, independent read-only read-back after
                              ▼
                           Verdict: verified | failed | unverified
                              │
                              ▼
                  evidence log (hash chain, HMAC with key)
                              │
                 ┌────────────┼─────────────┐
                 ▼            ▼             ▼
              report      dashboard    webhook alerts

adapters: watched() for plain functions, MCP ClientSession, LangGraph nodes / ToolNode
examples: run_eval harness, LangGraph agent, mock FHIR server, Stripe sandbox runner
```

## Steps

| # | Step | Layer | Why | Depends on |
|---|---|---|---|---|
| 1 | ~~Land the hardening PR: CodeRabbit review and autofix, then merge~~ (done, PR #2) | all | Security fixes and the LangGraph agent | — |
| 2 | ~~Release 0.2.2~~ (done): version bump, CHANGELOG with breaking changes (missing file exits 3; alerts need `READBACK_ALERT_KEY`), rebuild `dist/` | packaging | Behaviour changes need a version | 1 |
| 3 | ~~CI on GitHub Actions: Linux and Windows; MCP 1.x and 2.x~~ (done, PR #4; LangGraph 1.x only, since the `langgraph` extra requires >=1.0) | tests | Both MCP majors were only checked by hand | 1 |
| 4 | FHIR verifier with authenticated read-only access on a test EHR (OAuth read scope) | verifiers | The core promise, independent verifier credentials, is untested against a real auth server | test EHR access |
| 5 | SQL verifier on Postgres with a `SELECT`-only role | verifiers | Only SQLite is tested | Postgres instance |
| 6 | ~~Re-check pending Stripe refunds later instead of leaving them `unverified`~~ (done: `recheck()`, `FindingKind.PENDING`) | core, verifiers | Known limit | — |
| 7 | ~~Anchor the evidence-log head hash outside the log~~ (done: `anchor=`, `FileAnchor`, `verify-log --anchor/--head`) | evidence | Dropping the newest records is undetectable from the file alone | — |
| 8 | ~~Rate-limit the verifier's own reads~~ (done 2026-11-21: `RateLimit` + `limit_reads`, opt-in; no 429 retry) | verifiers | Known limit; matters under production load | — |
| 9 | ~~Real-model eval on the LangGraph agent, 50+ runs per model~~ (done 2026-11-20: Sonnet, Haiku, gpt-6-luna, 50 runs each) | examples | The 3-run smoke test cannot compare models | API keys |
| 10 | ~~MCP over HTTP, not only in-memory and stdio~~ (done 2026-11-21: Streamable HTTP on 127.0.0.1, MCP 1.30 and 2.3; remote hosts with TLS or auth not tested) | adapters | Listed as untested | — |
| 11 | ~~Cross-check `run_eval` and the LangGraph agent on the same seed and model~~ (done: labels aligned in 0.3.0; seed 7 task verdicts identical run for run for all three models) | examples | The two harnesses label outcomes slightly differently | 9 |
| 12 | External security and compliance review (HIPAA) | all | None has been done; the target domain is healthcare | 1–8 |
| 13 | Readback Receipts: signed outcome receipts, `reconcile` for Stripe and FHIR, `receipted()` runtime hook (built 2026-11-24 on `feature/readback-receipts`, not yet merged) | receipts | Outcome-priced agents bill for outcomes nobody checks | — |
| 14 | ~~Ed25519 receipts so a vendor can issue and a buyer verify without sharing a key~~ (done 2026-11-25: optional `signatures` extra) | receipts | HMAC means anyone who can verify can also issue | 13 |
| 15 | Reconcile Zendesk/Intercom resolutions and SQL rows | receipts | Only Stripe and FHIR are supported | 13 |

Steps 1–3 are short and unblock the rest. Steps 4, 5 and 9 need credentials or
infrastructure from the maintainer. Step 12 needs outside reviewers.

## Status

- Done in the hardening PR: FHIR next-link origin check, separate alert key,
  UNKEYED flagging and `--require-key`, dashboard overwrite guard, malformed
  record handling, LF log endings, LangGraph example agent with Anthropic and
  OpenAI models, `tzdata` on Windows.
- Verified locally (2026-11-22, 0.3.0 plus unreleased fixes): 184 tests pass on MCP 1.30 and on MCP 2.3, both with
  LangGraph 1.2 (1 symlink test skips on Windows without symlink privileges).
- Verified locally (2026-11-22, 0.3.1): 198 tests pass, 1 symlink test skips, on Windows with MCP 1.30 and LangGraph 1.2.
  The 0.3.0 line above predates the 0.3.1 fixes; MCP 2.3 has not been re-run on 0.3.1 locally (CI covers both).
