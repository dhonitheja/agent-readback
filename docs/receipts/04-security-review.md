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
| Tests | `pytest`, full suite, run twice | 345 tests: 340 pass, 5 Windows-only ACL tests skip on Linux. 139 are new (62 receipts, 51 reconciliation and CLI, 26 for the fixes below) |
| Static analysis | `bandit 1.9.4 -r agent_readback examples` (the CI gate) | Clean. One new low finding (B105 on the environment variable *name* `READBACK_FHIR_TOKEN`) is a false positive, marked `# nosec B105` with the reason |
| Static analysis, wider | `ruff` rules F, E9, B, S on the changed files | Nothing new to fix. `zip()` in the CSV parser now uses `strict=True`. The other hits are the same B105 name, the existing `icacls` call in `evidence.py` (fixed argument list, no shell) and an existing `__call__` check moved unchanged into `_is_async` |
| Dependency audit | `pip-audit 2.10.1 --skip-editable`, with `cryptography` installed | No known vulnerabilities. No new runtime dependency: httpx is still the only one; `cryptography` is only in the optional `signatures` extra |
| Secret scanning | `detect-secrets 1.5.0` over every tracked file, and a pattern search of the whole git history for live Stripe, Anthropic, OpenAI and AWS keys | Clean. The hits were two environment variable names and the fake `user:pw` URL that a test feeds to the CLI to prove it is refused; each is marked `pragma: allowlist secret`. CI now runs this check on every push (`security` job) |

## Controls checked by hand

| Requirement | What was checked | Test |
|---|---|---|
| SEC-1 read only | Reconciliation only calls the verifiers' GET readers. A Stripe `sk_` key is refused before any request | `test_only_get_requests_are_made`, `test_a_stripe_secret_key_is_still_refused`, `test_cli_refuses_a_secret_key_and_takes_no_key_flag` |
| SEC-2 data minimisation | Receipts, the text report and the JSON summary hold no payment intent, refund id, amount, currency, patient, practitioner, time or agent text | `test_receipts_and_report_hold_no_identifiers_or_values`, the leak tests in `test_receipts.py`, `test_fhir_create_update_cancel` |
| SEC-3 keys | No unkeyed mode; key shorter than 32 bytes, equal to the log or alert key, or used by any `EvidenceLog` in the process is refused; the receipt key is never registered as a log key | key tests in `test_receipts.py`, `test_cli_needs_a_receipt_key` |
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
- **Completeness for a public verifier.** With only the public key, a buyer
  can prove each receipt is genuine and unedited, and that the records link,
  but cannot recompute the keyed chain. To catch dropped newest receipts,
  share the anchor head (`FileAnchor`) through a channel the issuer cannot
  rewrite later.
- **Folder access.** Keep receipt and evidence logs in a folder only the
  writer can change.
- No build can promise that a breach is impossible. These are the threats we
  know of, each with a defence and a test.
