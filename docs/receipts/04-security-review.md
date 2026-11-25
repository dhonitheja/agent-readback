# Readback Receipts: security verification

Status: 2026-11-25. Phase 5 (Verify). Branch `feature/readback-receipts`.
Reviewed against `01-requirements.md` (SEC-1 to SEC-11) and every threat in
`02-threat-model.md`. This is the maintainer's own review, done with automated
tools and a manual read of the new code. It is not an external audit, and no
build can promise that a breach is impossible: the aim is that each threat we
know of has a defence and a test, and that what is left is written down.

## Automated checks

| Check | Tool and scope | Result |
|---|---|---|
| Tests | `pytest`, full suite | 319 tests: 314 pass, 5 Windows-only ACL tests skip on Linux. 113 are new (62 receipts, 51 reconciliation and CLI) |
| Static analysis | `bandit 1.9.4 -r agent_readback examples` (the CI gate) | Clean. One new low finding (B105 on the environment variable *name* `READBACK_FHIR_TOKEN`) is a false positive, marked `# nosec B105` with the reason |
| Static analysis, wider | `ruff` rules F, E9, B, S on the changed files | Nothing new to fix. `zip()` in the CSV parser now uses `strict=True`. The other hits are the same B105 name, the existing `icacls` call in `evidence.py` (fixed argument list, no shell) and an existing `__call__` check moved unchanged into `_is_async` |
| Dependency audit | `pip-audit 2.10.1 --skip-editable` | No known vulnerabilities. No new runtime dependency: httpx is still the only one |
| Secret scanning | `detect-secrets 1.5.0` over every tracked file, and a pattern search of the whole git history for live Stripe, Anthropic, OpenAI and AWS keys | Clean. The one hit was the fake `user:pw` URL that a test feeds to the CLI to prove it is refused; it is marked `pragma: allowlist secret`. CI now runs this check on every push (`security` job) |

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
| F1 | Medium (existing code) | `FhirAppointmentVerifier._one` put a claimed Appointment id straight into the URL. httpx resolves `Appointment/1/../2` (and `../Patient/1`) to another resource, so a crafted id made the verifier read a different record with its token. The field check still stopped a false `verified`, so this was a data-read issue, not a verdict issue. Reconciliation reads ids from a vendor's file, which made it reachable | Fixed: ids must match the FHIR id format and not be only dots. `test_fhir_id_cannot_walk_the_path` |
| F2 | Low | Regexes anchored with `$` also match before a trailing newline. All new patterns use `fullmatch` | Fixed in new code |
| F3 | Low (existing code) | The same `$` pattern is used for SQL identifiers (`verifiers/sql.py`) and for hash checks in `evidence.py`. SQL identifiers come from the developer's code, not from input, and a hash with a newline still fails the comparison, so neither is exploitable as far as we can see | Not changed on this branch; worth a small follow-up |
| F4 | Low | `ReceiptLog`, like `EvidenceLog`, follows a symlink at the receipts path. A symlink to a file with content is refused, because that content is not a receipt log | Residual: keep receipt logs in a folder only you can write |

## Residual risks

- **HMAC, not signatures.** Whoever can verify a receipt can also issue one.
  Fine when the buyer checks their own vendor's export; a vendor-to-buyer flow
  needs Ed25519 (roadmap step 14).
- **The read-only credential is still on you.** A prefix check cannot prove an
  `rk_` key or a FHIR token is read-only. Issue them that way.
- **`--base-url` is trusted.** The credentials go wherever you point it, over
  https.
- **Outcome ids are stored as given.** They are the vendor's own references.
  If a vendor puts personal data in them, it ends up in receipts and reports.
- **Matching is by fields, not by intent.** A real refund that happens to match
  a claim verifies it, even if the agent did not cause it. `--since` and
  one-effect-one-outcome narrow this but cannot close it.
- **Not tested** against a real vendor export, live Stripe or a production EHR.
- **No external security or compliance (HIPAA) review** has been done
  (roadmap step 12).
