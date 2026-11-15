# Readback

Check what an AI agent says it did against the system of record.

An agent that books an appointment, issues a refund or updates a row usually
ends with "Done." That message is a claim. Readback treats it as one: it
snapshots the real system before the agent acts, reads it again afterward
through a path the agent cannot write to, and returns a verdict.

| Verdict | Meaning |
|---|---|
| `verified` | The system shows exactly what was claimed, with nothing extra. |
| `failed` | The effect is missing, a field is wrong, or something unclaimed also changed. |
| `unverified` | The check could not run. Treat it as an open item, never as success. |

Verdicts never come from an LLM; every check is a deterministic comparison.

## What is tested and what is not

Version 0.2. All 35 tests pass, against in-memory stand-ins only.

| Part | Tested against | Not yet tested against |
|---|---|---|
| FHIR appointment verifier (create, update, cancel) | in-memory mock FHIR server | a real FHIR server or EHR |
| Stripe refund verifier | mock of the refunds list endpoint | the Stripe API, test mode or live |
| SQL row verifier | SQLite | Postgres or any other database |
| Anthropic and OpenAI-compatible agent loops | mock responses in each API's message format | the live APIs |
| Evidence log, redaction, report, webhook | unit tests | production load |

No security or compliance review has been done.

## Install and run

```bash
pip install -e ".[dev]"
pytest
python -m examples.healthcare.run_eval --provider scripted --runs 200 --inject-faults 0.2
```

That last command uses a scripted agent that always makes the correct tool
calls, and a mock FHIR server told to mishandle 20% of writes while still
answering "success". Output:

```
Requests:                         200
Agent said DONE:                  200
  verified in the record:         170
  FALSE COMPLETIONS caught:       30  (15.0% of DONE)
Why the false completions failed:
  extra_effect: 7
  missing: 8
  wrong_value: 16
```

The 15% is produced by the injected faults. It demonstrates the mechanism and
is not a measurement of any real agent.

## Measure a real model

Keep the key in your shell environment. Do not put it in a file you commit.

```bash
export ANTHROPIC_API_KEY=...
python -m examples.healthcare.run_eval --provider anthropic --model claude-haiku-5-5 --runs 100 --out results-haiku.json

export OPENAI_API_KEY=...
python -m examples.healthcare.run_eval --provider openai --model gpt-6-luna --runs 100 --out results-luna.json
```

The agent receives requests in plain English with Central Time dates, must
convert them to UTC, and must find the right appointment before changing it.
With no injected faults, every false completion in the result is the model's
own. Add `--fhir-url <base URL>` to run against a real FHIR R4 test server;
only synthetic patients and practitioners are created.

## Use it around your own agent

```python
import httpx
from agent_readback import Claim, EvidenceLog, WebhookAlert, watch
from agent_readback.verifiers import FhirAppointmentVerifier

verifier = FhirAppointmentVerifier(httpx.Client(base_url=FHIR_URL, headers=READ_ONLY_AUTH))
log = EvidenceLog("evidence.jsonl")

expected = {"patient": "Patient/123", "practitioner": "Practitioner/7",
            "start": "2027-01-04T15:00:00Z", "status": "booked"}
probe = Claim("fhir.appointment.create", "", expected)

with watch(verifier, probe, log, settle_attempts=3, on_verdict=[WebhookAlert(ALERT_URL)]) as w:
    message = my_agent.book(...)                       # your agent, unchanged
    w.claims(Claim(probe.action, message, expected))

if not w.verdict.ok:
    escalate_to_human(w.verdict)
```

## Verifiers

| Verifier | Actions | Catches |
|---|---|---|
| `FhirAppointmentVerifier` | `fhir.appointment.create`, `.update`, `.cancel` | never stored, wrong time or practitioner, duplicate booking, wrong appointment changed |
| `StripeRefundVerifier` | `stripe.refund.create` | refund never issued, wrong amount or currency, failed refund, double refund |
| `SqlRowVerifier` | `sql.row.insert`, `sql.row.update` | row absent, wrong column value, unclaimed extra or deleted rows |

To add one, implement `snapshot(claim)` and `check(claim, before)` from
`agent_readback/core.py`. Give every verifier its own read-only credentials.
If the agent and the verifier share a write path, the check proves nothing.

## Evidence log

Every verdict is appended to a JSON-lines file in which each record carries
the hash of the one before it.

```bash
readback verify-log evidence.jsonl   # detects edited or deleted records
readback report evidence.jsonl       # verdict counts and failed rate by action
readback dashboard evidence.jsonl -o report.html   # the same as a one-file HTML page
```

By default the log stores no values from the system of record and no agent
text, only field names, match results and a hash of the agent's message. Pass
`keep_fields=["status"]` to keep named fields, or `keep_fields="*"` for
synthetic data. Decide where the log lives and who can read it before pointing
Readback at a system that holds personal data.

## Planned

- A run against a public FHIR sandbox and Stripe test mode
- Published results for at least two models
- One-line adapters for LangGraph nodes and MCP tool calls

## License

MIT
