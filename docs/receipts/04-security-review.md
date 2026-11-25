# Readback Receipts: security verification

Status: 2026-11-25, updated after fixing the residual risks and the PR review findings. Phase 5 (Verify). Branch `feature/readback-receipts`.
Reviewed against `01-requirements.md` (SEC-1 to SEC-11) and every threat in
`02-threat-model.md`. This is the maintainer's own review, done with automated
tools and a manual read of the new code. It is not an external audit, and no
build can promise that a breach is impossible: the aim is that each threat we
know of has a defence and a test, and that what is left is written down.

## Automated checks

| Check | Tool and scope | Result |
|---|---|---|
| Tests | `pytest`, full suite, run twice | 353 tests: 348 pass, 5 Windows-only ACL tests skip on Linux. 147 are new (62 receipts, 51 reconciliation and CLI, 34 for the fixes below) |
| Static analysis | `bandit 1.9.4 -r agent_readback examples` (the CI gate) | Clean. One new low finding (B105 on the environment variable *name* `READBACK_FHIR_TOKEN`) is a false positive, marked `# nosec B105` with the reason |
| Static analysis, wider | `ruff` rules F, E9, B, S on the changed files | Nothing new to fix. `zip()` in the CSV parser now uses `strict=True`. The other hits are the same B105 name, the existing `icacls` call in `evidence.py` (fixed argument list, no shell) and an existing `__call__` check moved unchanged into `_is_async` |
| Dependency audit | `pip-audit 2.10.1 --skip-editable`, with `cryptography` installed | No known vulnerabilities. No new runtime dependency: httpx is still the only one; `cryptography` is only in the optional `signatures` extra |
| Secret scanning | `detect-secrets 1.5.0` over every tracked file, and a pattern search of the whole git history for live Stripe, Anthropic, OpenAI and AWS keys | Clean. The hits were two environment variable names and the fake `user:pw` URL that a test feeds to the CLI to prove it is refused; each is marked `pragma: allowlist secret`. CI now runs this check on every push (`security` job) |

## Controls checked by hand

| Requirement | What was checked | Test |
|---|---|---|
| SEC-1 read only | Reconciliation only calls the verifiers' GET readers. A Stripe `sk_` key is refused before any request | `test_only_get_requests_are_made`, `test_a_stripe_secret_key_is_still_refused`, `test_cli_refuses_a_secret_key_and_takes_no_key_flag` |
| SEC-2 data minimisation | Receipts, the text report and the JSON summary hold no payment intent, refund id, amount, currency, patient, practitioner, time or agent text | `test_receipts_and_report_hold_no_identifiers_or_values`, the leak tests in `test_receipts.py`, `test_fhir_create_update_cancel` |
| SEC-3 keys | No unkeyed mode; key shorter than 32 bytes, equal to the log or alert key, or used by any `EvidenceLog` in the process is refused; the receipt key is never registered as a log key; a `WebhookAlert` or `EvidenceLog` refuses a key already used as a receipt key in the process, so the reuse is refused in either order; each check and its registration run under one shared lock, so two threads given the same key at once cannot both pass | key tests in `test_receipts.py`, `test_cli_needs_a_receipt_key`, `test_a_receipt_key_already_in_use_is_refused_as_an_alert_key`, `test_a_receipt_key_already_in_use_is_refused_as_an_evidence_log_key`, `test_the_same_key_used_at_once_as_receipt_and_alert_or_log_key_is_refused_once` |
| SEC-4 integrity | MAC over every field with a domain prefix, constant-time compare; a receipt cannot be upgraded to `verified`; edited, reordered or truncated logs are caught; a tampered `--prior` log is refused | per-field tamper tests, `test_a_tampered_prior_log_is_refused` |
| SEC-5 secrets | Stripe key and FHIR token only from the environment; no flags; never printed | `test_cli_refuses_a_secret_key_and_takes_no_key_flag`, `test_cli_fhir` |
| SEC-6 transport | https only, except plain http to localhost; no user info, query or fragment in `--base-url` | `test_cli_refuses_unsafe_base_urls`, `test_cli_allows_plain_http_for_localhost` |
| SEC-7 hostile input | Size, row, column, line and cell caps; whole-number amounts; NaN and deep nesting refused without a crash; formula-like outcome ids refused; errors never echo values | `test_bad_rows_are_refused_without_echoing_values`, `test_bad_jsonl_is_refused`, `test_row_and_size_caps` |
| SEC-8 server errors | Read errors keep only the exception type, because httpx messages quote the URL, which holds the payment intent or patient | `test_server_error_text_never_reaches_a_receipt` |
| SEC-9 load | Default 20 reads per second, one read per subject per run, errors cached too | `test_cli_rate_limits_its_reads`, `test_an_unreachable_server_is_unverifiable_and_read_once` |
| SEC-10 files | Receipt logs are created owner-only; `--receipts` never appends to an evidence log, the export itself or any other file | `test_cli_never_appends_receipts_to_another_file`, mode test in `test_receipts.py` |
| SEC-11 supply chain | No new runtime dependency; scanners pinned in the `security` extra; secret scanning added to CI | CI `security` job |

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| F1 | Medium (existing code) | `FhirAppointmentVerifier._one` put a claimed Appointment id straight into the URL. httpx resolves `Appointment/1/../2` to another resource, so a crafted id made the verifier read a different record with its token. The field check still stopped a false `verified` | Fixed: ids must be valid FHIR ids and not only dots. `test_fhir_id_cannot_walk_the_path` |
| F2 | Low | Regexes anchored with `$` also match before a trailing newline | Fixed in new code (`fullmatch`) |
| F3 | Low (existing code) | The same `$` pattern in SQL identifier and placeholder checks, evidence hash and anchor checks, and the Windows SID check | Fixed: all use `fullmatch`. `test_sql_identifiers_and_placeholders_cannot_end_in_a_newline`, `test_an_anchor_head_with_a_trailing_newline_is_refused` |
| F4 | Low | A receipt log path that is a symlink was followed | Fixed: refused. `test_a_symlinked_receipt_log_is_refused` |
| F5 | High (PR review) | A Stripe refund still `pending` (or `requires_action`) gave a billable `verified` receipt when the export itself claimed that status | Fixed: only a `succeeded` refund can verify. `test_an_unsettled_refund_is_never_billable_even_when_the_export_claims_it` |
| F6 | High (PR review) | `verify-receipts --public-key` with the receipt key set fell back to HMAC for HMAC receipts, so a log forged with only the shared key passed against the issuer's public key | Fixed: `ReceiptLog(require_signed=True)` refuses every unsigned receipt, and the CLI uses it. `test_a_public_key_check_refuses_a_log_made_with_only_the_shared_key` |
| F7 | Medium (PR review) | A misspelt or missing `--prior` path read as an empty history, so already billed effects could be billed again | Fixed: a missing or non-file prior log stops the run (exit 3) before any read. `test_a_missing_prior_log_stops_reconciliation` |
| F9 | Medium (PR review) | A matching refund with no `status`, or a status Stripe does not document, was billed as `verified` | Fixed: only the documented statuses are read; any other gives `unverifiable`. `test_a_refund_with_no_known_status_is_unverifiable_not_billable` |
| F10 | High (PR review) | `receipted()` billed a refund that was still pending or had no status, because the verifier judges whether the claim is true and a claim of "pending" can be true | Fixed in `issue_receipt`, so every path gets it: a Stripe refund receipt is only `verified` when every refund it saw is `succeeded`; otherwise `pending` or `unverifiable`, with a `not_settled` reason. `test_receipted_only_bills_a_settled_refund` |
| F11 | Low (PR review) | A refund `status` that was a list or object raised `TypeError` and stopped reconciliation part way | Fixed: a status that is not text is `unverifiable`. `test_a_refund_status_that_is_not_text_is_unverifiable_not_a_crash` |
| F12 | Major (PR review) | `receipted()` collected the verdict through a callback that ran after the evidence-log write, so a failed write left no receipt | Fixed: the verdict is kept before the evidence log is written; the receipt is still issued and the logging error propagates. `test_a_failed_evidence_log_write_still_leaves_a_receipt` (sync and async) |
| F13 | Major (PR review) | Two `reconcile()` runs sharing one `ReceiptLog` could both read history before either wrote, and both bill one effect | Fixed: `ReceiptLog.append` refuses a second verified receipt for an effect (`AlreadyBilled`) under the write lock; `reconcile()` then logs `already_billed`. `test_overlapping_reconciles_sharing_a_receipt_log_bill_an_effect_once` |
| F14 | Low (PR review) | A receipt log that failed verification during `reconcile` ended in a traceback and exit 1, which reads as "unverified outcomes" | Fixed: exit 3, file error. `test_a_receipt_log_that_does_not_verify_is_a_file_error_in_reconcile` |
| F15 | High (design, user's call) | A public-key-only check could not catch a swapped, moved or dropped receipt | Fixed with log format 2 (signed place per record, published public head). `test_a_public_check_catches_a_body_swapped_for_another_genuine_receipt`, `test_a_public_check_catches_a_dropped_receipt_with_rewritten_links`, `test_a_public_head_catches_dropped_newest_receipts`, `test_stripping_the_place_signature_is_not_an_older_log`, `test_format_1_receipts_need_the_allow_v1_flag` |
| F16 | Low | A public-key-only check took a missing hash and a null `prev` as linked; on Python 3.10 a receipt failure after a tool error was dropped silently | Hashes must be 64 hex characters; on Python 3.10 the failure is a `RuntimeWarning` (a note on 3.11+). `test_a_public_check_rejects_a_missing_or_malformed_hash`, `test_a_receipt_failure_is_a_warning_where_exceptions_take_no_notes` |
| F8 | Low (CI) | Two leak tests searched the whole receipt text, which holds random hex and microsecond timestamps, so a value like `2500` could appear by chance and fail the run | Fixed: the leak checks blank the random-by-design fields first (`leak_text` in `tests/conftest.py`) |

## Residual risks from the first review, and what became of each

| Risk | Now | Test |
|---|---|---|
| HMAC: whoever can verify can also issue | **Fixed in code.** Optional Ed25519 signing. The buyer checks with the public key alone and cannot make a receipt; a public-key check refuses HMAC receipts. The signing key file must be owner-only | `test_a_verifier_with_the_public_key_cannot_forge_or_edit`, `test_an_hmac_receipt_never_passes_a_public_key_check`, `test_cli_signs_and_a_buyer_checks_with_the_public_key_only`, `test_a_signing_key_others_can_read_is_refused` |
| `--base-url` is trusted with the credentials | **Fixed for Stripe**: the key only goes to `api.stripe.com` or localhost. **Narrowed for FHIR**: https only, no credentials or query in the URL, redirects never followed, next links must stay on the same origin, and the command prints the server it reads. Which FHIR server is yours cannot be known from code | `test_the_stripe_key_only_goes_to_stripe`, `test_fhir_redirects_are_never_followed`, `test_cli_says_where_it_reads_and_never_the_key` |
| Outcome ids stored as given | **Fixed in code.** Receipts store a keyed `oid_` stand-in by default; your own report still shows your ids. `--keep-outcome-ids` is an explicit opt-out | `test_receipts_carry_a_keyed_stand_in_for_outcome_ids`, `test_cli_hashes_outcome_ids_unless_told_to_keep_them` |
| Matching by fields, not by intent | **Fixed for Stripe when the vendor tags refunds**: `--match-metadata KEY` only counts a refund whose metadata names the outcome. Metadata never reaches a receipt. Without tags, and for FHIR, matching is still by fields, narrowed by `--since` and one-effect-one-outcome | `test_match_metadata_ties_a_refund_to_its_outcome` |
| Read-only credentials | **Not fixable in code.** Neither Stripe nor FHIR lets a client prove a key is read-only, and testing by writing would break the read-only rule. Mitigation: issue a Stripe restricted key with only `refunds: read` and a FHIR client with only read scope, keep them away from the agent, and confirm once in Stripe test mode, as the README's "Repeat sandbox validation" section describes: a small refund attempted with the restricted key must return `403 more_permissions_required` | `sk_` keys are still refused |
| Not tested on real systems | **Not fixable in code.** Needs a run against Stripe test mode and a test EHR with real credentials (roadmap steps 4 and 13) | |
| No external review | **Not fixable in code.** Needs outside reviewers (roadmap step 12) | |

## What still depends on how you run it

- **Key storage.** `READBACK_RECEIPT_KEY` and the Ed25519 private key decide
  who can make receipts. Keep them in a secrets manager or an owner-only file,
  never in the repo, and rotate them if a machine is lost. Publish only the
  public key.
- **Completeness for a public verifier (fixed in log format 2).** A
  `ReceiptLog` with a signing key signs each record's place: its `seq`, the
  previous record's place link and a digest of its body. With only the public
  key, a buyer now catches a body swapped for another genuine signed receipt,
  a moved record, and a dropped record whose links were rewritten. Dropped
  newest records are caught when the issuer publishes the `public head` and
  the buyer passes it with `--head`; without it, a clean prefix of the log
  still passes. Stripping a place signature after signed records always
  fails. Format 1 logs (no place signatures) fail a public-key check unless
  `--allow-v1` is given, and for those records the receipt key is still the
  only check on swaps and drops.
- **One writing process per receipt log.** A receipt log bills each effect at
  most once, checked under its lock at the moment of writing, so overlapping
  `reconcile()` calls or `receipted()` tools that share one `ReceiptLog` in a
  process cannot both bill the same refund or appointment. The lock is per
  process: two separate processes writing the same file are not covered.
- **Folder access.** Keep receipt and evidence logs in a folder only the
  writer can change.
- No build can promise that a breach is impossible. These are the threats we
  know of, each with a defence and a test.
