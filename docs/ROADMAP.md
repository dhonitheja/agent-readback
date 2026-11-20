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
| 8 | Rate-limit the verifier's own reads | verifiers | Known limit; matters under production load | — |
| 9 | Real-model eval on the LangGraph agent, 50+ runs per model | examples | The 3-run smoke test cannot compare models | API keys |
| 10 | MCP over HTTP, not only in-memory and stdio | adapters | Listed as untested | — |
| 11 | Cross-check `run_eval` and the LangGraph agent: same seed and model, aligned outcome labels | examples | The two harnesses label outcomes slightly differently | 9 |
| 12 | External security and compliance review (HIPAA) | all | None has been done; the target domain is healthcare | 1–8 |

Steps 1–3 are short and unblock the rest. Steps 4, 5 and 9 need credentials or
infrastructure from the maintainer. Step 12 needs outside reviewers.

## Status

- Done in the hardening PR: FHIR next-link origin check, separate alert key,
  UNKEYED flagging and `--require-key`, dashboard overwrite guard, malformed
  record handling, LF log endings, LangGraph example agent with Anthropic and
  OpenAI models, `tzdata` on Windows.
- Verified locally: 114 tests pass on MCP 1.30 and on MCP 2.3, both with
  LangGraph 1.2 (1 symlink test skips on Windows without symlink privileges).
