# Readback Receipts: design

Status: draft for review, 2026-11-24. Phase 3 (Design). Requirements are in
`01-requirements.md`, threats in `02-threat-model.md`.

## Components

| Module | Role | New / changed |
|---|---|---|
| `agent_readback/receipts.py` | `Receipt`, `ReceiptVerdict`, `issue_receipt`, `verify_receipt`, `ReceiptLog`, key handling | New |
| `agent_readback/reconcile.py` | Export parser, Stripe and FHIR outcome finders, effect allocation, report | New |
| `agent_readback/adapters.py` | `receipted()` and `OutcomeNotVerified` next to `watched()` | Changed (additive) |
| `agent_readback/evidence.py` | `_write(body)` split out of `_append` so `ReceiptLog` reuses the chain, file mode, Windows ACL and anchor code | Changed (refactor, no behaviour change) |
| `agent_readback/cli.py` | `reconcile` and `verify-receipts` commands | Changed (additive) |

## Receipt (version 1)

```json
{
  "receipt_version": 1,
  "receipt_id": "rcpt_3f0c…(32 hex)",
  "outcome_id": "fin-2026-11-00412",
  "action": "stripe.refund.create",
  "system": "stripe",
  "query": "GET /v1/refunds?payment_intent={subject}",
  "verdict": "verified",
  "billable": true,
  "reasons": [],
  "checked_at": "2026-11-24T23:59:00+00:00",
  "issued_at": "2026-11-24T23:59:01+00:00",
  "claim_digest": "…64 hex…",
  "subject_digest": "…",
  "observed_digest": "…",
  "effect_digest": "…",
  "mac_alg": "hmac-sha256",
  "mac": "…"
}
```

- `reasons` is a list of `{"kind", "field"}`. Kinds are Readback's finding
  kinds plus `duplicate_effect`, `duplicate_outcome` and `already_billed`.
- Every digest is `HMAC-SHA256(key, label + ":" + canonical JSON)` with a
  distinct label per digest, so the same value never gives the same digest in
  two roles. `null` when there is nothing to digest (for example no effect was
  found).
- `effect_digest` identifies the matched real-world effect (`stripe:refund:<id>`,
  `fhir:appointment:<id>:<action>`). It is what allocation and `--prior` compare.
- `mac` is `HMAC-SHA256(key, "readback-receipt-v1:" + canonical JSON of every
  other field)`. Canonical JSON is `sort_keys`, compact separators, ASCII only.

## Verdict mapping

| Readback status | Findings | Receipt verdict |
|---|---|---|
| verified | none | `verified` |
| failed | any `missing` | `missing` |
| failed | otherwise | `contradicted` |
| unverified | any `pending` | `pending` |
| unverified | otherwise | `unverifiable` |
| (reconcile) | effect already backs another outcome, or was billed in a `--prior` log | `contradicted` |

## Reconciliation

No snapshot exists after the fact, so reconciliation asks a different
question from `watch()`: "does an unused effect exist that matches this
claim?" It reuses the verifiers' read code (`StripeRefundVerifier._refunds`,
`FhirAppointmentVerifier._appointments` and `_one`), so the same shape checks,
page caps and same-origin rule apply.

- **Stripe `stripe.refund.create`**: list refunds for the payment intent (one
  read per distinct payment intent, cached for the run). Candidates are
  refunds whose expected fields match, optionally created at or after
  `--since`. Prefer an unused `succeeded` candidate, then an unused pending one
  (`pending`). Only used candidates → `contradicted` (`duplicate_effect`).
  A refund that matches everything except a `failed` or `canceled` status →
  `contradicted`. No candidate → `missing`.
- **FHIR `fhir.appointment.create`**: list the patient's appointments; same
  matching and allocation by appointment id.
- **FHIR `.update` / `.cancel`**: read `Appointment/{id}`; absent → `missing`;
  fields differ (cancel requires `status: cancelled`) → `contradicted`.
  Allocated by id and action.
- Outcomes are processed in file order, so the result is deterministic; the
  first claimant of an effect wins.

## Runtime hook

```python
receipts = ReceiptLog("receipts.jsonl")            # key from READBACK_RECEIPT_KEY
refund = receipted(issue_refund, verifier, to_claim, receipts, log=evidence)
refund(...)   # returns normally only if the receipt is verified; else raises OutcomeNotVerified
```

`receipted()` builds a `watched()` wrapper per call with a per-call callback,
so parallel calls (LangGraph `ToolNode` threads) never share state. The
evidence record and the receipt are both written before the raise. In
LangGraph, a `ToolNode` turns the exception into an error `ToolMessage`, so
the model sees "outcome not verified: missing" instead of a success.

## Decisions (ADRs, Nygard style, short)

### ADR-R1: Receipts are a new record type that reuses the evidence chain
- **Context**: receipts need append-only storage with the same guarantees as
  the evidence log.
- **Decision**: `ReceiptLog` subclasses `EvidenceLog` and writes receipt
  bodies through a shared `_write()`. Same record layout (`seq`, `prev`,
  `body`, `hash`, `mac`), so `verify-receipts` reuses `verify_chain` and the
  anchor code.
- **Consequences**: one implementation of the file safety code. `readback
  report` and `dashboard` refuse receipt logs (bodies lack the verdict layout).

### ADR-R2: HMAC-SHA256, not public-key signatures, for version 1
- **Context**: the only runtime dependency is httpx, and the main user (the
  buyer reconciling) issues and checks receipts with their own key.
- **Decision**: HMAC-SHA256 with a dedicated `READBACK_RECEIPT_KEY`.
- **Consequences**: no new dependency. Anyone able to verify can also issue.
- **Amended 2026-11-25**: optional Ed25519 signing (extra `signatures`,
  `cryptography`). A signed receipt has `mac_alg: ed25519` and a 128-hex
  signature over the same domain-prefixed canonical JSON; the HMAC key still
  keys the digests and the log chain. `verify-receipts --public-key` checks
  signatures and record links with no secret, and refuses HMAC receipts.

### ADR-R3: A separate receipt key, required, at least 32 bytes
- **Context**: receipts are meant to be shared; the evidence-log key must
  never leave the log writer (the existing rule for alerts).
- **Decision**: refuse to issue or verify without a key; refuse a key shorter
  than 32 bytes or equal to `READBACK_LOG_KEY`, `READBACK_ALERT_KEY` or a key
  an `EvidenceLog` in this process uses.
- **Consequences**: no unkeyed mode; tests and examples must set a key.

### ADR-R4: Digests, never values
- **Context**: receipts cross organisational boundaries (TB5) and the target
  domains are payments and healthcare.
- **Decision**: no identifiers, amounts, times or agent text in a receipt or
  report; only keyed digests, kinds and field names. Unlike the evidence log,
  there is no `keep_fields` option.
- **Consequences**: a disputed receipt is matched to source records by
  recomputing digests with the key, not by reading the receipt.

### ADR-R5: Reconciliation reuses verifier read paths
- **Context**: the verifiers' readers already carry the hard-won shape checks
  and paging defences.
- **Decision**: call their private readers from `reconcile.py` instead of
  writing new HTTP code.
- **Consequences**: changes to those readers affect both paths; the tests
  cover both.

### ADR-R6: CLI secrets from the environment only
- **Decision**: `READBACK_STRIPE_KEY` and `READBACK_FHIR_TOKEN` are read from
  the environment; there are no flags for them.
- **Consequences**: nothing secret appears in shell history or the process list.

## Traceability

| Requirement | Design element | Tests |
|---|---|---|
| FR-1, FR-2, FR-3, FR-4 | `issue_receipt`, `ReceiptVerdict.from_verdict` | `tests/test_receipts.py` |
| FR-5, FR-6, SEC-3, SEC-4 | `verify_receipt`, `ReceiptLog`, `verify-receipts` | `tests/test_receipts.py` |
| FR-7 to FR-11, SEC-1, SEC-7, SEC-8 | `reconcile.py` | `tests/test_reconcile.py` |
| FR-12 | `receipted`, `OutcomeNotVerified` | `tests/test_receipts.py` |
| FR-13, SEC-5, SEC-6, SEC-9, SEC-10 | `cli.py` | `tests/test_reconcile.py` |
| SEC-2 | all of the above | data-leak scans in both test files |
| SEC-11 | CI `security` job | CI |

Security verification results are in `04-security-review.md`.
