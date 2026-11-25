# Readback Receipts: requirements

Status: draft for review, 2026-11-24. Phase 2 (Define) of the SDLC for this feature.
Source: the "First product (MVP)" section of the market-gap research (verified
outcome receipts), and Readback's existing contract in `CLAUDE.md`.

## Problem

An AI agent says "Done: refunded $25" or "Booked your appointment". Readback
already checks that claim against the system of record and logs a verdict.
Two groups need more than a log line:

- **Agent builders** need the agent to be unable to report "done" until the
  outcome has been read back, and a portable record they can hand to someone.
- **Buyers of outcome-priced agents** (paying per resolution, per refund, per
  booking) need to take the vendor's outcome export and see how many billed
  outcomes really happened.

A receipt is that portable record: one signed object per claimed outcome that
says what was claimed, where it was read back, what verdict came out, and
when, without carrying the customer's payment or health data.

## Users

| ID | User | Wants |
|---|---|---|
| U1 | Agent builder | A hook that stops "done" unless the receipt verifies |
| U2 | Buyer's finance or ops reviewer | "412 billed, 371 verified" for a month's outcome export |
| U3 | Auditor or the vendor in a dispute | To check a single receipt was issued by the key holder and not edited |

## Functional requirements

| ID | Requirement | Acceptance |
|---|---|---|
| FR-1 | **Receipt schema.** A receipt holds: receipt id, optional outcome id, action, system of record, a description of the read-back query with no values in it, verdict, reason kinds and field names, `checked_at`, `issued_at`, keyed digests of the claim, the subject (payment intent or patient), the observed state and the matched effect, and a MAC over all of it. Schema is versioned (`receipt_version: 1`). | Unit tests build each verdict and check every field |
| FR-2 | **Verdicts.** Exactly five: `verified`, `missing`, `contradicted`, `pending`, `unverifiable`. Mapping from Readback: verified to `verified`; failed with a missing effect to `missing`; any other failure (wrong value, extra effect, effect already used by another outcome) to `contradicted`; unverified with a pending finding to `pending`; any other unverified to `unverifiable`. | Table-driven test over every Readback status and finding kind |
| FR-3 | **Billable flag.** Only `verified` is billable. Nothing else, including `pending`, counts as verified in any total. | Test that a pending refund is not counted as verified |
| FR-4 | **Issue from a verdict.** `issue_receipt(verdict, key, ...)` turns any Readback `Verdict` into a receipt. | Tests for Stripe and FHIR verdicts |
| FR-5 | **Verify one receipt.** `verify_receipt(receipt, key)` says whether a receipt is intact and was made with that key, and why not if it is not. | Tests: an edited field, a forged MAC, a wrong key and a wrong schema version all fail |
| FR-6 | **Receipt log.** Receipts can be appended to a hash-chained, HMAC-keyed JSONL file with the same guarantees as the evidence log (append-only, owner-only file, anchor support). `readback verify-receipts FILE` checks the chain and every receipt. | CLI tests for intact, edited, reordered and truncated-with-anchor files |
| FR-7 | **Connectors.** Reconciliation reads back Stripe refunds (`stripe.refund.create`) and FHIR Appointments (`fhir.appointment.create`, `.update`, `.cancel`) through the existing verifiers' read paths and read-only clients. | Mock-server tests per action |
| FR-8 | **Reconciliation input.** Read a vendor outcome export as CSV (`outcome_id`, `action`, then expected fields) or JSONL (`{"outcome_id", "action", "expected"}`). `amount` must be a whole number in the smallest currency unit. | Parser tests, including rejects |
| FR-9 | **One effect, one outcome.** During reconciliation each real effect (a refund id, an appointment id with its action) can back at most one outcome. A second outcome claiming the same effect is `contradicted`. A repeated outcome id is `contradicted`. | Double-billing tests |
| FR-10 | **No reuse across periods.** `--prior FILE` loads earlier receipt logs; an effect already used by a verified receipt there is `contradicted`. `--since DATE` ignores Stripe refunds created before the period. | Tests for both |
| FR-11 | **Reconciliation report.** Counts per verdict, billed vs verified, the verified rate, and the outcome ids that were not verified with their verdict and reason kinds. Text by default, `--json` for machines. | Snapshot tests of both forms |
| FR-12 | **Runtime hook.** `receipted(fn, verifier, to_claim, receipts, ...)` wraps a tool or graph node like `watched()`. After the call it issues a receipt and, unless the receipt is `verified`, raises `OutcomeNotVerified` carrying the receipt, so the agent cannot report "done". Works for sync and async callables, so for LangGraph nodes and an MCP `ClientSession.call_tool`. | Tests with plain sync and async functions and a LangGraph `ToolNode` |
| FR-13 | **CLI.** `readback reconcile OUTCOMES --system stripe|fhir --receipts OUT.jsonl [--base-url URL] [--since DATE] [--prior FILE ...] [--json] [--max-rate N]`. | CLI tests against mock servers |

## Non-functional requirements

Security requirements are numbered `SEC-*` and trace to the threat model
(`02-threat-model.md`).

| ID | Requirement | Acceptance |
|---|---|---|
| SEC-1 | **Read-only.** Reconciliation and the hook only read the system of record. The Stripe client must refuse a secret key (`sk_`), as the verifier already does. No code path issues a write request. | Test that `sk_` is refused; test that every request a reconcile run makes is a GET |
| SEC-2 | **Data minimisation.** A receipt and a report contain no payment intent ids, refund ids, patient or practitioner references, amounts, times or agent text. Identifiers appear only as keyed HMAC digests, so a party without the key cannot guess them back (patient ids are often sequential). | Test that serialised receipts and reports contain none of the fixture's identifiers or values |
| SEC-3 | **Keys fail closed.** A receipt key is required (no unkeyed receipts), at least 32 bytes, and must differ from `READBACK_LOG_KEY` and `READBACK_ALERT_KEY`. | Tests for missing, short and reused keys |
| SEC-4 | **Integrity.** Each receipt carries an HMAC-SHA256 over a canonical encoding with a domain prefix; comparisons are constant time. The receipt log is hash-chained. | Forgery tests (FR-5, FR-6) |
| SEC-5 | **Secrets never on the command line.** The CLI reads the Stripe key and FHIR token from environment variables only, never from arguments (which other users can see in the process list), and never prints them. | Test that no argument accepts a key; test that error output omits the key |
| SEC-6 | **Transport.** The CLI only talks to an `https` base URL, except `localhost`, `127.0.0.1` and `::1` for testing; certificates are verified (httpx default). FHIR paging keeps the existing same-origin rule. | Test that an `http://` remote URL is refused |
| SEC-7 | **Untrusted input.** The outcome export is untrusted: file size, row count, column count and cell length are capped; ids and action names are pattern-checked; outcome ids cannot start with a character a spreadsheet treats as a formula; no `eval`, pickle or YAML. | Parser reject tests |
| SEC-8 | **Untrusted server responses.** Malformed or incomplete responses stay `unverifiable`, never `verified` (inherits the verifiers' shape checks). Error text from a server or URL is not copied into receipts or reports. | Test with a malformed server and a leaking error message |
| SEC-9 | **Rate limiting.** The CLI caps its own read rate (default 20 reads per second, under Stripe's 25 per second per endpoint) using the existing `limit_reads`. | Test that the limit is applied |
| SEC-10 | **Files.** Receipt logs are created owner-only (inherits the evidence log). The CLI never overwrites an existing file that is not a receipt log, and never appends receipts to an evidence log. | Tests |
| SEC-11 | **Supply chain.** No new runtime dependency (httpx only). Bandit and pip-audit stay clean; secret scanning is added to CI. | CI jobs pass locally |
| NFR-1 | **Compatibility.** All existing tests keep passing; no change to verdict semantics, the evidence-log format or existing public names. | Full suite |
| NFR-2 | **Determinism.** Verdicts never come from an LLM; given the same reads the same receipt verdict comes out. | Inherited |
| NFR-3 | **Platforms.** Python 3.10+, Linux and Windows (CI matrix). | CI |

## Out of scope for this version

- Public-key signatures (Ed25519) so a third party can verify without holding
  the key. HMAC means anyone who can verify can also forge. See ADR-R2.
- Review workflow states (proposed, disputed, excluded from billing).
- Zendesk, Intercom and SQL reconciliation connectors. SQL already has a runtime verifier.
- Fetching exports from vendor APIs (Fin has no resolution webhook); input is a file.
- A hosted service, dashboards for receipts, or HIPAA certification. Readback
  is a library and CLI; a compliance review stays roadmap step 12.
