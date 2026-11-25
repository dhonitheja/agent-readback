# Readback Receipts: threat model (STRIDE)

Status: draft for review, 2026-11-24. Covers the receipt format, the receipt
log, `readback reconcile`, `readback verify-receipts` and the `receipted()`
runtime hook. Threats to the existing verifiers and evidence log are in the
README "Security model" table and are only repeated here where receipts change
them.

No design removes the risk of a breach. This model lists what we defend
against, how, and what is left over (residual risk), so the gaps are written
down rather than assumed away.

## System and data flow

```
 vendor outcome export (CSV / JSONL, untrusted)           agent tool call / graph node
                 │                                                   │
                 ▼                                                   ▼
        readback reconcile  ──── read-only GET ────►  Stripe / FHIR server   ◄── receipted() (watch: snapshot, read back)
                 │            (rk_ key / read token,     (system of record)              │
                 │             https, rate-limited)                                      │
                 ▼                                                                       ▼
        receipt per outcome  ──► receipt log (JSONL, HMAC chain, 0600)  ◄──────── receipt per call
                 │                                                                       │
                 ▼                                                                       ▼
        report (counts, outcome ids, reason kinds)                      OutcomeNotVerified unless verified
```

### Trust boundaries

| # | Boundary | Crosses it |
|---|---|---|
| TB1 | Outcome export → Readback | Untrusted file from a vendor or from the agent's own logs |
| TB2 | Readback → system of record | Read-only credential, network |
| TB3 | System of record → Readback | Untrusted JSON responses, paging links |
| TB4 | Readback → receipt log on disk | Other local users, backups, sync tools |
| TB5 | Receipt log → buyer, vendor, auditor | Receipts leave the machine that made them |
| TB6 | Agent → `receipted()` | The agent controls tool arguments and the "done" text |

### Assets

| Asset | Why it matters |
|---|---|
| A1 Read credentials (Stripe `rk_` key, FHIR token) | Read access to payments or patient records |
| A2 Payment and health data in responses | PCI-adjacent and PHI; must not be copied into receipts |
| A3 Receipt key | Whoever holds it can issue receipts that verify |
| A4 Receipts and the receipt log | The billing evidence; tampering changes what gets paid |
| A5 Report | Decides which outcomes are paid |

## STRIDE analysis

Each row names the threat, the defence built in this version, and the
residual risk. IDs are referenced from the security review.

### Spoofing

| ID | Threat | Defence | Residual |
|---|---|---|---|
| S1 | Someone makes a receipt that says `verified` for an outcome that never happened | HMAC-SHA256 over the canonical receipt with the receipt key (SEC-4); `verify_receipt` and `verify-receipts` reject a receipt made without the key | Anyone holding the key can mint receipts (symmetric MAC). Share the key only with parties allowed to issue. Public-key signatures are out of scope (ADR-R2) |
| S2 | A fake "system of record" answers the reads (wrong base URL, DNS or network attacker) | `https` required for non-local hosts, certificate checks on (SEC-6); FHIR next links must stay on the client's origin (existing) | An attacker who controls a trusted CA or the configured URL itself can still answer |
| S3 | The agent impersonates the verifier by sharing its write credential | Stripe `sk_` keys refused (SEC-1); docs require separate read-only credentials | A Stripe `rk_` key with write scopes, or a FHIR token with write scope, cannot be detected by prefix. Documented; checked live by `examples/stripe_sandbox.py` |

### Tampering

| ID | Threat | Defence | Residual |
|---|---|---|---|
| T1 | A receipt's verdict or outcome id is edited after issue | MAC covers every field; constant-time compare | None while the key is secret |
| T2 | A `missing` or `contradicted` receipt is deleted from the log, or receipts reordered | Sequence numbers and hash chain; `verify-receipts --anchor/--head` for dropped tail records | Whoever can rewrite both the log and its anchor copy can still truncate (same as the evidence log) |
| T3 | The vendor bills twice for one refund, or for the same booking in two months | One effect backs at most one outcome (FR-9); `--prior` receipt logs exclude effects already used (FR-10); effects are matched through a keyed effect digest | Reuse across logs that are not passed with `--prior` is not seen. Keep every month's receipt log |
| T4 | An old refund (before the billing period) is used to "verify" a new outcome | `--since` drops Stripe refunds created before the period | FHIR has no reliable creation time in the search used; use `--prior` |
| T5 | The export is crafted so a parse quirk turns a claim into a different claim (floats, `1e3`, blank ids, extra columns) | Strict parser: whole-number amounts only, pattern-checked ids and actions, unknown action rejected, cell and column caps (SEC-7) | — |

### Repudiation

| ID | Threat | Defence | Residual |
|---|---|---|---|
| R1 | The vendor disputes a `missing` verdict ("you checked the wrong thing") | Receipt records the action, the system, a value-free query description, `checked_at`, and keyed digests of the claim and the observed state, so both sides with the key can match it to their own records | Raw observed values are not kept (by design). A party wanting full evidence must keep its own copy of the read |
| R2 | The issuer denies having issued a receipt | MAC binds it to the key holder | With a shared HMAC key either holder could have made it. Non-repudiation needs public-key signatures (ADR-R2) |

### Information disclosure

| ID | Threat | Defence | Residual |
|---|---|---|---|
| I1 | Receipts or reports leak PHI or payment data (patient refs, payment intents, amounts, times, agent text) | Receipts store only kinds, field names and keyed digests (SEC-2); the report lists outcome ids and reason kinds only; a test scans the output for fixture values | The vendor's own `outcome_id` is stored as given (pattern-checked, 128 characters). Do not use personal data as outcome ids |
| I2 | Digests are brute-forced back to identifiers (sequential patient ids) | Digests are HMACs under a 32-byte-minimum key (SEC-3), never plain hashes | Anyone with the key can test guesses. Treat the key as sensitive |
| I3 | Server error text (which can contain the request URL with a payment intent or patient id) ends up in receipts or CLI output | Receipts keep only finding kinds; the CLI prints reason kinds, not exception text (SEC-8) | Exceptions raised by your own code outside Readback are not filtered |
| I4 | Credentials leak through the command line, logs or error output | Keys only from environment variables (SEC-5); never printed; `.env` is git-ignored; secret scanning in CI (SEC-11) | Environment variables are visible to the same user and to root |
| I5 | Other local accounts read the receipt log | Created `0600`, Windows ACL limited to the current account (inherited) | Backups and sync tools copy what they copy |
| I6 | Read token sent to another host by a paging link | Existing FHIR same-origin check; Stripe paging uses cursors, not links | — |

### Denial of service

| ID | Threat | Defence | Residual |
|---|---|---|---|
| D1 | A huge or hostile export exhausts memory or runs for hours | File-size (50 MB), row (100,000), column (32) and cell (1,024 characters) caps (SEC-7) | Caps are flags you can raise; raising them raises the risk |
| D2 | Reconciliation hammers the system of record (Stripe allows 25 reads per second per endpoint) | Default 20 reads per second via `limit_reads` (SEC-9); existing page caps | A slow server makes a run slow, not wrong |
| D3 | A server that pages forever or repeats pages | Existing page caps and repeat detection give `unverifiable` | — |

### Elevation of privilege

| ID | Threat | Defence | Residual |
|---|---|---|---|
| E1 | Reconciliation or the hook writes to the system of record | Only GET requests exist in the code; a test asserts every request a run makes is a GET (SEC-1) | Custom verifiers you plug into `receipted()` are your code |
| E2 | The agent bypasses the hook and says "done" anyway | `receipted()` raises `OutcomeNotVerified`, so the graph or tool layer sees an error, not a success; the receipt is logged before the raise | An agent framework that swallows tool errors and lets the model reply freely can still produce "done" text; gate the final answer on the receipt as well (documented) |
| E3 | Output path tricks overwrite an evidence log or another file | The CLI only appends to a new file or an existing receipt log, never to an evidence log or any other file (SEC-10) | — |
| E4 | A vulnerable dependency | No new runtime dependency; pip-audit and Bandit in CI (SEC-11) | Zero-days in httpx or Python |

## Security controls checklist (traced to the build)

| Control | Threat IDs | Requirement |
|---|---|---|
| HMAC receipts, domain-separated canonical JSON, constant-time compare | S1, T1, R2 | SEC-4 |
| Separate, length-checked receipt key, fail closed | S1, I2 | SEC-3 |
| Keyed digests instead of identifiers and values | I1, I2 | SEC-2 |
| Read-only client, `sk_` refused, GET only | S3, E1 | SEC-1 |
| https only, certificate checks, same-origin paging | S2, I6 | SEC-6 |
| Strict, capped input parser | T5, D1 | SEC-7 |
| Effect allocation, `--prior`, `--since` | T3, T4 | FR-9, FR-10 |
| Chained, owner-only receipt log, anchor | T2, I5 | FR-6, SEC-10 |
| Env-only secrets, no secret echo, secret scanning | I4 | SEC-5, SEC-11 |
| Rate limit and page caps | D2, D3 | SEC-9 |

## Decisions that change the risk (for the maintainer)

1. **Who holds the receipt key.** With HMAC, the buyer can only check receipts
   if they hold the key, and then they could also mint them. Fine when the
   buyer runs Readback themselves (the main reconciliation case). Not enough
   for a vendor handing receipts to a buyer who must not be able to forge
   them; that needs Ed25519 signatures and one new optional dependency.
2. **Outcome ids.** They are stored as given. If a vendor export uses an email
   or ticket subject as the id, it would land in receipts. The parser rejects
   anything outside `[A-Za-z0-9._:-]`, which rules out emails but not every
   personal value.
