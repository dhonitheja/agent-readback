"""Fixes for the residual risks in docs/receipts/04-security-review.md, each shown failing for the attacker.

Fake ids and throwaway keys only.
"""

import json
import os
import sqlite3

import httpx
import pytest

from agent_readback import FileAnchor, OutcomeNotVerified, ReceiptLog, issue_receipt, receipted, verify_receipt, verify_signed_receipts
from agent_readback import cli
from agent_readback.cli import main
from agent_readback.core import Claim, Status, Verdict
from agent_readback.reconcile import StripeRefunds, load_outcomes, prior_effects, reconcile, summarise
from agent_readback.receipts import RECEIPT_KEY_ENV, ReceiptKeyError, load_public_key, load_signing_key, outcome_ref
from agent_readback.verifiers import SqlRowVerifier, StripeRefundVerifier
from tests.test_reconcile import FAKE_RK, FHIR_HEADER, KEY, Stripe, csv_file, run_stripe

ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
from cryptography.hazmat.primitives import serialization  # noqa: E402


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in (RECEIPT_KEY_ENV, "READBACK_LOG_KEY", "READBACK_ALERT_KEY", "READBACK_STRIPE_KEY",
                 "READBACK_FHIR_TOKEN", "READBACK_SIGNING_KEY_PASSWORD"):
        monkeypatch.delenv(name, raising=False)


def keypair(tmp_path, name="issuer"):
    private = ed25519.Ed25519PrivateKey.generate()
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_path, public_path = tmp_path / f"{name}.pem", tmp_path / f"{name}.pub.pem"
    private_path.write_bytes(pem)
    os.chmod(private_path, 0o600)
    public_path.write_bytes(public)
    return private, private_path, public_path


def verdict(status=Status.VERIFIED):
    claim = Claim("stripe.refund.create", "", {"payment_intent": "pi_A1", "amount": 2500, "currency": "usd"})
    return Verdict(status, claim, (), {"created": [{"id": "re_1", "status": "succeeded"}]})


# -- F3: anchors match the whole string ------------------------------------------------

def test_sql_identifiers_and_placeholders_cannot_end_in_a_newline(tmp_path):
    connect = lambda: sqlite3.connect(tmp_path / "db.sqlite")  # noqa: E731
    for table, placeholder in (("orders\n", "?"), ("orders", "?\n")):
        with pytest.raises(ValueError, match="unsafe SQL"):
            SqlRowVerifier(connect, table, "id", placeholder=placeholder)


def test_an_anchor_head_with_a_trailing_newline_is_refused(tmp_path):
    path = tmp_path / "anchor.json"
    path.write_text(json.dumps({"count": 1, "head": "a" * 64 + "\n"}))
    with pytest.raises(ValueError, match="bad count or head"):
        FileAnchor(path).read()


# -- F4: no symlinked receipt logs -------------------------------------------------------

def test_a_symlinked_receipt_log_is_refused(tmp_path):
    target = tmp_path / "elsewhere.jsonl"
    link = tmp_path / "receipts.jsonl"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks need extra privileges on this system")
    with pytest.raises(ValueError, match="symbolic link"):
        ReceiptLog(link, key=KEY)
    assert not target.exists()


# -- HMAC means a verifier could also issue: Ed25519 receipts ---------------------------

def test_signed_receipt_verifies_with_the_public_key_alone(tmp_path):
    private, _, _ = keypair(tmp_path)
    receipt = issue_receipt(verdict(), KEY, signing_key=private).to_dict()
    assert receipt["mac_alg"] == "ed25519" and len(receipt["mac"]) == 128
    assert verify_receipt(receipt, public_key=private.public_key()) is None


def test_a_verifier_with_the_public_key_cannot_forge_or_edit(tmp_path):
    private, _, _ = keypair(tmp_path)
    other, _, _ = keypair(tmp_path, "other")
    receipt = issue_receipt(verdict(Status.FAILED), KEY, signing_key=private).to_dict()
    upgraded = {**receipt, "verdict": "verified", "billable": True}
    assert "signature does not match" in verify_receipt(upgraded, public_key=private.public_key())
    forged = issue_receipt(verdict(), KEY, signing_key=other).to_dict()  # someone else's key
    assert "signature does not match" in verify_receipt(forged, public_key=private.public_key())


def test_an_hmac_receipt_never_passes_a_public_key_check(tmp_path):
    """Anyone with the shared key could have made it, so a public verifier must refuse it."""
    private, _, _ = keypair(tmp_path)
    hmac_receipt = issue_receipt(verdict(), KEY).to_dict()
    assert "not signed with Ed25519" in verify_receipt(hmac_receipt, public_key=private.public_key())
    disguised = {**hmac_receipt, "mac_alg": "ed25519", "mac": hmac_receipt["mac"] * 2}
    assert "signature does not match" in verify_receipt(disguised, public_key=private.public_key())


def test_a_signed_receipt_needs_the_public_key(tmp_path):
    private, _, _ = keypair(tmp_path)
    receipt = issue_receipt(verdict(), KEY, signing_key=private).to_dict()
    assert "public key" in verify_receipt(receipt, KEY)


def test_signed_receipt_log_round_trip_and_public_check(tmp_path):
    private, _, _ = keypair(tmp_path)
    log = ReceiptLog(tmp_path / "r.jsonl", key=KEY, signing_key=private)
    for n in range(3):  # three refunds: a log bills each effect once
        log.append(issue_receipt(verdict(), KEY, signing_key=private, effect=f"stripe:refund:re_{n}"))
    assert log.verify() == []
    assert verify_signed_receipts(log.path, private.public_key()) == (3, [])
    with pytest.raises(ValueError, match="does not verify"):
        log.append(issue_receipt(verdict(), KEY, signing_key=keypair(tmp_path, "x")[0]))


def test_public_check_catches_a_dropped_or_edited_receipt(tmp_path):
    private, _, _ = keypair(tmp_path)
    log = ReceiptLog(tmp_path / "r.jsonl", key=KEY, signing_key=private)
    for _ in range(3):
        log.append(issue_receipt(verdict(Status.FAILED), KEY, signing_key=private))
    lines = log.path.read_text().splitlines()
    dropped = tmp_path / "dropped.jsonl"
    dropped.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert verify_signed_receipts(dropped, private.public_key())[1]
    edited = tmp_path / "edited.jsonl"
    edited.write_text("\n".join([lines[0], lines[1].replace('"contradicted"', '"verified"', 1), lines[2]]) + "\n")
    assert verify_signed_receipts(edited, private.public_key())[1]


def test_a_signing_key_others_can_read_is_refused(tmp_path):
    _, private_path, _ = keypair(tmp_path)
    if os.name != "posix":
        pytest.skip("file modes are POSIX only")
    os.chmod(private_path, 0o644)
    with pytest.raises(ReceiptKeyError, match="owner only"):
        load_signing_key(private_path)


def test_a_public_key_file_is_not_a_signing_key(tmp_path):
    _, _, public_path = keypair(tmp_path)
    os.chmod(public_path, 0o600)
    with pytest.raises((ValueError, TypeError)):
        load_signing_key(public_path)
    assert load_public_key(public_path)


def test_receipted_signs_when_the_log_has_a_signing_key(tmp_path):
    from tests.test_receipts import MockStripe

    private, _, _ = keypair(tmp_path)
    stripe = MockStripe()
    log = ReceiptLog(tmp_path / "r.jsonl", key=KEY, signing_key=private)
    claim = {"payment_intent": "pi_A1", "amount": 2500, "currency": "usd"}
    refund = receipted(lambda **kw: stripe.refund(**kw), StripeRefundVerifier(stripe.client()),
                       lambda **kw: Claim("stripe.refund.create", "", claim), log)
    refund(payment_intent="pi_A1", amount=2500, currency="usd")
    assert log.receipts()[0]["mac_alg"] == "ed25519" and log.verify() == []


def test_prior_signed_logs_still_block_rebilling(tmp_path):
    private, _, _ = keypair(tmp_path)
    stripe = Stripe()
    stripe.refund("pi_A1", 2500)
    october = ReceiptLog(tmp_path / "october.jsonl", key=KEY, signing_key=private)
    run_stripe(stripe, csv_file(tmp_path, ["oct-1,stripe.refund.create,pi_A1,2500,usd"]), receipts=october)
    prior = prior_effects([october.path], KEY, public_key=private.public_key())
    again = run_stripe(stripe, csv_file(tmp_path, ["nov-1,stripe.refund.create,pi_A1,2500,usd"], name="n.csv"), prior=prior)
    assert again[0].reasons == ({"kind": "already_billed", "field": None},)


# -- Outcome ids stored as given: keyed stand-ins by default ----------------------------

def test_receipts_carry_a_keyed_stand_in_for_outcome_ids(tmp_path):
    stripe = Stripe()
    path = csv_file(tmp_path, ["jane.doe-5551234567,stripe.refund.create,pi_A1,1,usd"])
    labels = {}
    receipts = reconcile(load_outcomes(path), StripeRefunds(StripeRefundVerifier(stripe.client())), KEY, labels=labels)
    stored = receipts[0].to_dict()
    assert stored["outcome_id"] == outcome_ref(KEY.encode(), "jane.doe-5551234567") and "5551234567" not in json.dumps(stored)
    assert summarise(receipts, labels)["not_verified"][0]["outcome_id"] == "jane.doe-5551234567"  # your report still names it
    kept = reconcile(load_outcomes(path), StripeRefunds(StripeRefundVerifier(stripe.client())), KEY, keep_outcome_ids=True)
    assert kept[0].outcome_id == "jane.doe-5551234567"


# -- Matching by fields, not intent: Stripe metadata ------------------------------------

def test_match_metadata_ties_a_refund_to_its_outcome(tmp_path):
    stripe = Stripe()
    stripe.refund("pi_A1", 2500)                                   # same amount, made for something else
    stripe.refund("pi_A1", 2500)
    stripe.refunds[-1]["metadata"] = {"outcome_id": "fin-2", "note": "PRIVATE-NOTE"}
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd", "fin-2,stripe.refund.create,pi_A1,2500,usd"])
    finder = StripeRefunds(StripeRefundVerifier(stripe.client()), match_metadata="outcome_id")
    receipts = reconcile(load_outcomes(path), finder, KEY)
    assert [r.verdict for r in receipts] == ["missing", "verified"]
    assert "PRIVATE-NOTE" not in json.dumps([r.to_dict() for r in receipts])
    with pytest.raises(ValueError, match="match_metadata"):
        StripeRefunds(StripeRefundVerifier(stripe.client()), match_metadata="a key with spaces")


# -- --base-url is trusted: Stripe locked to Stripe, no redirects -----------------------

@pytest.fixture
def stripe_cli(monkeypatch):
    stripe = Stripe()
    monkeypatch.setattr(cli, "_transport", stripe.transport())
    monkeypatch.setenv("READBACK_STRIPE_KEY", FAKE_RK)
    monkeypatch.setenv(RECEIPT_KEY_ENV, KEY)
    return stripe


def test_the_stripe_key_only_goes_to_stripe(tmp_path, stripe_cli, capsys):
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(tmp_path / "r.jsonl"),
                 "--base-url", "https://api.stripe.com.evil.example"]) == 2
    assert stripe_cli.methods == [] and "api.stripe.com" in capsys.readouterr().err


def test_cli_says_where_it_reads_and_never_the_key(tmp_path, stripe_cli, capsys):
    stripe_cli.refund("pi_A1", 1)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(tmp_path / "r.jsonl")]) == 0
    err = capsys.readouterr().err
    assert "reading stripe at https://api.stripe.com/" in err and FAKE_RK not in err


def test_fhir_redirects_are_never_followed(tmp_path, monkeypatch):
    seen = []

    def handler(request):
        seen.append(request.url.host)
        return httpx.Response(302, headers={"location": "https://evil.example/Appointment"})

    monkeypatch.setattr(cli, "_transport", httpx.MockTransport(handler))
    monkeypatch.setenv(RECEIPT_KEY_ENV, KEY)
    monkeypatch.setenv("READBACK_FHIR_TOKEN", "fake-read-token")
    path = csv_file(tmp_path, ["c-1,fhir.appointment.cancel,7,Patient/1,,,,"], header=FHIR_HEADER)
    assert main(["reconcile", str(path), "--system", "fhir", "--base-url", "https://fhir.test/baseR4/",
                 "--receipts", str(tmp_path / "r.jsonl"), "--json"]) == 1
    assert seen == ["fhir.test"]


def test_cli_hashes_outcome_ids_unless_told_to_keep_them(tmp_path, stripe_cli, capsys):
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    hashed, kept = tmp_path / "h.jsonl", tmp_path / "k.jsonl"
    main(["reconcile", str(path), "--system", "stripe", "--receipts", str(hashed)])
    assert "fin-1  missing" in capsys.readouterr().out
    main(["reconcile", str(path), "--system", "stripe", "--receipts", str(kept), "--keep-outcome-ids"])
    assert "fin-1" not in hashed.read_text() and '"outcome_id":"fin-1"' in kept.read_text().replace(" ", "")


def test_cli_signs_and_a_buyer_checks_with_the_public_key_only(tmp_path, stripe_cli, monkeypatch, capsys):
    _, private_path, public_path = keypair(tmp_path)
    stripe_cli.refund("pi_A1", 1)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    receipts = tmp_path / "r.jsonl"
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(receipts),
                 "--signing-key", str(private_path)]) == 0
    assert main(["verify-receipts", str(receipts), "--public-key", str(public_path)]) == 0  # issuer, with both keys
    monkeypatch.delenv(RECEIPT_KEY_ENV)                                                       # buyer, public key only
    capsys.readouterr()
    assert main(["verify-receipts", str(receipts), "--public-key", str(public_path)]) == 0
    assert "every signature verifies" in capsys.readouterr().out
    assert main(["verify-receipts", str(receipts), "--public-key", str(public_path), "--head", "0" * 64]) == 1
    head = ReceiptLog.public_head_of(receipts)
    assert main(["verify-receipts", str(receipts), "--public-key", str(public_path), "--head", head]) == 0
    assert main(["verify-receipts", str(receipts), "--public-key", str(public_path),
                 "--anchor", str(tmp_path / "anchor.json")]) == 2  # a FileAnchor head is keyed
    receipts.write_text(receipts.read_text().replace('"verified"', '"missing"', 1))
    assert main(["verify-receipts", str(receipts), "--public-key", str(public_path)]) == 1


def test_cli_refuses_a_readable_signing_key(tmp_path, stripe_cli, capsys):
    if os.name != "posix":
        pytest.skip("file modes are POSIX only")
    _, private_path, _ = keypair(tmp_path)
    os.chmod(private_path, 0o644)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(tmp_path / "r.jsonl"),
                 "--signing-key", str(private_path)]) == 2
    assert "owner only" in capsys.readouterr().err and stripe_cli.methods == []


# -- Review findings on the receipts PR -------------------------------------------------

STATUS_HEADER = "outcome_id,action,payment_intent,amount,currency,status\n"


@pytest.mark.parametrize("status", ["pending", "requires_action"])
def test_an_unsettled_refund_is_never_billable_even_when_the_export_claims_it(tmp_path, status):
    stripe = Stripe()
    stripe.refund("pi_A1", 2500, status=status)
    claimed = csv_file(tmp_path, [f"fin-1,stripe.refund.create,pi_A1,2500,usd,{status}"], header=STATUS_HEADER)
    unclaimed = csv_file(tmp_path, ["fin-2,stripe.refund.create,pi_A1,2500,usd"], name="u.csv")
    assert [r.verdict for r in run_stripe(stripe, claimed)] == ["pending"]
    assert [r.verdict for r in run_stripe(stripe, unclaimed)] == ["pending"]
    assert summarise(run_stripe(stripe, claimed))["verified"] == 0


def test_a_settled_refund_claimed_as_succeeded_still_verifies(tmp_path):
    stripe = Stripe()
    stripe.refund("pi_A1", 2500)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd,succeeded"], header=STATUS_HEADER)
    assert [r.verdict for r in run_stripe(stripe, path)] == ["verified"]


def test_a_public_key_check_refuses_a_log_made_with_only_the_shared_key(tmp_path, monkeypatch, capsys):
    """Whoever holds READBACK_RECEIPT_KEY can write HMAC receipts; they must not pass for the issuer's."""
    private, _, public_path = keypair(tmp_path)
    forged = ReceiptLog(tmp_path / "forged.jsonl", key=KEY)
    forged.append(issue_receipt(verdict(), KEY))
    assert forged.verify() == []
    strict = ReceiptLog(forged.path, key=KEY, public_key=private.public_key(), require_signed=True)
    assert "not signed with Ed25519" in strict.verify()[0]
    monkeypatch.setenv(RECEIPT_KEY_ENV, KEY)
    assert main(["verify-receipts", str(forged.path), "--public-key", str(public_path)]) == 1
    assert "not signed with Ed25519" in capsys.readouterr().out
    with pytest.raises(ValueError, match="require_signed"):
        ReceiptLog(tmp_path / "x.jsonl", key=KEY, require_signed=True)


def test_a_missing_prior_log_stops_reconciliation(tmp_path, stripe_cli, capsys):
    with pytest.raises(FileNotFoundError, match="not found"):
        prior_effects([tmp_path / "octber.jsonl"], KEY)
    with pytest.raises(FileNotFoundError):
        prior_effects([tmp_path], KEY)  # a folder is not a log either
    stripe_cli.refund("pi_A1", 1)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    receipts = tmp_path / "r.jsonl"
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(receipts),
                 "--prior", str(tmp_path / "octber.jsonl")]) == 3
    assert "not found" in capsys.readouterr().err
    assert stripe_cli.methods == [] and not receipts.exists()


@pytest.mark.parametrize("status", [None, "paid_out_someday"])
def test_a_refund_with_no_known_status_is_unverifiable_not_billable(tmp_path, status):
    stripe = Stripe()
    stripe.refund("pi_A1", 2500)
    stripe.refunds[-1]["status"] = status
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd"])
    receipts = run_stripe(stripe, path)
    assert [r.verdict for r in receipts] == ["unverifiable"] and summarise(receipts)["verified"] == 0


@pytest.mark.parametrize("status", [["pending"], {"a": 1}])
def test_a_refund_status_that_is_not_text_is_unverifiable_not_a_crash(tmp_path, status):
    stripe = Stripe()
    stripe.refund("pi_A1", 2500)
    stripe.refunds[-1]["status"] = status
    receipts = run_stripe(stripe, csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd"]))
    assert [r.verdict for r in receipts] == ["unverifiable"]


@pytest.mark.parametrize("claimed, actual, expected", [
    ({"status": "pending"}, "pending", "pending"),          # the claim is true, but nothing has settled
    ({}, "requires_action", "pending"),
    ({}, None, "unverifiable"),
    ({}, "succeeded", "verified"),
])
def test_receipted_only_bills_a_settled_refund(tmp_path, claimed, actual, expected):
    stripe = Stripe()
    log = ReceiptLog(tmp_path / "r.jsonl", key=KEY)

    def issue_refund(amount):
        stripe.refund("pi_A1", amount, status=actual or "succeeded")
        if actual is None:
            stripe.refunds[-1].pop("status")
        return "ok"

    to_claim = lambda amount: Claim("stripe.refund.create", "", {"payment_intent": "pi_A1", "amount": amount, **claimed})  # noqa: E731
    refund = receipted(issue_refund, StripeRefundVerifier(stripe.client()), to_claim, log)
    if expected == "verified":
        assert refund(2500) == "ok"
    else:
        with pytest.raises(OutcomeNotVerified):
            refund(2500)
    (receipt,) = log.receipts()
    assert receipt["verdict"] == expected and receipt["billable"] is (expected == "verified")


# -- CodeRabbit review on the receipts PR -----------------------------------------------

def _receipted_refund(tmp_path, stripe, **options):
    log = ReceiptLog(tmp_path / "r.jsonl", key=KEY)

    def issue_refund(amount):
        stripe.refund("pi_A1", amount)
        return "ok"

    to_claim = lambda amount: Claim("stripe.refund.create", "", {"payment_intent": "pi_A1", "amount": amount})  # noqa: E731
    return receipted(issue_refund, StripeRefundVerifier(stripe.client()), to_claim, log, **options), log


def test_a_failing_verdict_callback_still_leaves_a_receipt(tmp_path):
    def broken(verdict):
        raise RuntimeError("callback broke")

    refund, log = _receipted_refund(tmp_path, Stripe(), on_verdict=[broken])
    with pytest.raises(RuntimeError, match="callback broke"):
        refund(2500)
    assert [r["verdict"] for r in log.receipts()] == ["verified"]


def test_the_tools_own_exception_survives_a_receipt_failure(tmp_path):
    class ToolError(Exception):
        pass

    def broken_receipt(receipt):
        raise OSError("disk full")

    log = ReceiptLog(tmp_path / "r.jsonl", key=KEY)
    stripe = Stripe()

    def issue_refund(amount):
        stripe.refund("pi_A1", amount)
        raise ToolError("upstream timeout")

    to_claim = lambda amount: Claim("stripe.refund.create", "", {"payment_intent": "pi_A1", "amount": amount})  # noqa: E731
    refund = receipted(issue_refund, StripeRefundVerifier(stripe.client()), to_claim, log, on_receipt=[broken_receipt])
    with pytest.raises(ToolError) as raised:
        refund(2500)
    assert len(log.receipts()) == 1
    if hasattr(raised.value, "__notes__"):
        assert "receipt step failed: OSError" in raised.value.__notes__[0]


def test_a_bad_metadata_key_is_a_usage_error(tmp_path, stripe_cli, capsys):
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(tmp_path / "r.jsonl"),
                 "--match-metadata", "has space"]) == 2
    assert "--match-metadata" in capsys.readouterr().err and stripe_cli.methods == []


def test_an_alert_key_given_only_in_code_is_refused_as_a_receipt_key():
    from agent_readback import WebhookAlert

    alert_key = "alert-key-only-in-code-0123456789abcdef"
    WebhookAlert("https://alerts.test/hook", key=alert_key)
    with pytest.raises(ReceiptKeyError, match="READBACK_ALERT_KEY"):
        issue_receipt(verdict(), alert_key)


def test_a_receipt_key_already_in_use_is_refused_as_an_alert_key():
    from agent_readback import WebhookAlert

    issue_receipt(verdict(), KEY)  # the receipt key is in use first
    with pytest.raises(ValueError, match="READBACK_RECEIPT_KEY"):
        WebhookAlert("https://alerts.test/hook", key=KEY)
    WebhookAlert("https://alerts.test/hook", key="a-distinct-alert-key-0123456789abcdef")  # a distinct key is fine


def test_a_receipt_key_already_in_use_is_refused_as_an_evidence_log_key(tmp_path):
    from agent_readback import EvidenceLog

    ReceiptLog(tmp_path / "r.jsonl", key=KEY)  # the receipt key is in use first
    with pytest.raises(ValueError, match="READBACK_RECEIPT_KEY"):
        EvidenceLog(tmp_path / "e.jsonl", key=KEY)
    EvidenceLog(tmp_path / "e.jsonl", key="a-distinct-log-key-0123456789abcdef-test")  # a distinct key is fine


@pytest.mark.parametrize("other", ["alert", "log"])
def test_the_same_key_used_at_once_as_receipt_and_alert_or_log_key_is_refused_once(tmp_path, monkeypatch, other):
    """The attack: two threads given one key both pass the check before either registers it."""
    import threading

    from agent_readback import EvidenceLog, WebhookAlert, receipts

    checked = threading.Event()
    other_done = threading.Event()
    real_is_alert_key = receipts.is_alert_key

    def is_alert_key_then_pause(raw):
        result = real_is_alert_key(raw)
        checked.set()  # receipt_key has checked the alert registry but not yet registered the key
        other_done.wait(0.5)  # the other thread gets every chance to slip in here
        return result

    monkeypatch.setattr(receipts, "is_alert_key", is_alert_key_then_pause)
    outcomes = {}

    def make_receipt_key():
        try:
            receipts.receipt_key(KEY)
            outcomes["receipt"] = "ok"
        except (ReceiptKeyError, ValueError):
            outcomes["receipt"] = "refused"

    def make_other():
        checked.wait(2)
        try:
            if other == "alert":
                WebhookAlert("https://alerts.test/hook", key=KEY)
            else:
                EvidenceLog(tmp_path / "e.jsonl", key=KEY)
            outcomes[other] = "ok"
        except ValueError:
            outcomes[other] = "refused"
        finally:
            other_done.set()

    threads = [threading.Thread(target=make_receipt_key), threading.Thread(target=make_other)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
    assert sorted(outcomes.values()) == ["ok", "refused"], outcomes


def test_a_receipt_failure_is_a_warning_where_exceptions_take_no_notes():
    from agent_readback.adapters import _issue_keeping

    class ToolError(Exception):
        pass

    error = ToolError("upstream timeout")
    error.add_note = None  # as on Python 3.10, which has no exception notes

    def broken_issue():
        raise OSError("disk full")

    with pytest.warns(RuntimeWarning, match="receipt step failed: OSError"):
        _issue_keeping(error, broken_issue)
    assert not hasattr(error, "__notes__")


def test_a_receipt_failure_never_replaces_the_tools_exception_with_warnings_as_errors(caplog):
    import warnings

    from agent_readback.adapters import _issue_keeping

    error = ValueError("upstream timeout")
    error.add_note = None  # as on Python 3.10

    def broken_issue():
        raise OSError("disk full")

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        with caplog.at_level("WARNING", logger="agent_readback"):
            _issue_keeping(error, broken_issue)  # must not raise the RuntimeWarning in place of the tool's error
    assert "receipt step failed: OSError" in caplog.text


def test_a_receipt_log_written_with_another_key_is_never_appended_to(tmp_path):
    other = "another-receipt-key-0123456789abcdef-test"
    ReceiptLog(tmp_path / "r.jsonl", key=other).append(issue_receipt(verdict(), other))
    before = (tmp_path / "r.jsonl").read_bytes()
    log = ReceiptLog(tmp_path / "r.jsonl", key=KEY)
    with pytest.raises(ValueError, match="does not verify"):
        log.append(issue_receipt(verdict(), KEY))
    assert (tmp_path / "r.jsonl").read_bytes() == before
    same = ReceiptLog(tmp_path / "s.jsonl", key=KEY)
    same.append(issue_receipt(verdict(), KEY))
    ReceiptLog(same.path, key=KEY).append(issue_receipt(verdict(), KEY, effect="stripe:refund:re_2"))  # same key: fine
    assert len(ReceiptLog(same.path, key=KEY).receipts()) == 2


def test_an_action_that_is_not_text_is_an_export_error(tmp_path):
    from agent_readback.reconcile import ExportError

    path = tmp_path / "o.jsonl"
    path.write_text(json.dumps({"outcome_id": "fin-1", "action": [], "expected": {"payment_intent": "pi_A1", "amount": 1, "currency": "usd"}}) + "\n")
    with pytest.raises(ExportError, match="unknown action"):
        load_outcomes(path, system="stripe")


def test_a_rerun_into_the_same_receipt_log_never_bills_twice(tmp_path, stripe_cli, capsys):
    stripe_cli.refund("pi_A1", 2500)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd"])
    receipts = tmp_path / "november.jsonl"
    args = ["reconcile", str(path), "--system", "stripe", "--receipts", str(receipts), "--json"]
    assert main(args) == 0
    capsys.readouterr()
    assert main(args) == 1
    second = json.loads(capsys.readouterr().out)
    assert second["verified"] == 0
    verdicts = [r["verdict"] for r in ReceiptLog(receipts, key=KEY).receipts()]
    assert verdicts == ["verified", "contradicted"]


# -- CodeRabbit review on 2fe98d9 --------------------------------------------------------

class BrokenEvidenceLog:
    def append(self, verdict):
        raise OSError("evidence disk full")


@pytest.mark.parametrize("is_async", [False, True])
def test_a_failed_evidence_log_write_still_leaves_a_receipt(tmp_path, is_async):
    import asyncio

    stripe = Stripe()
    receipts = ReceiptLog(tmp_path / "r.jsonl", key=KEY)

    def issue_refund(amount):
        stripe.refund("pi_A1", amount)
        return "ok"

    async def issue_refund_async(amount):
        return issue_refund(amount)

    to_claim = lambda amount: Claim("stripe.refund.create", "", {"payment_intent": "pi_A1", "amount": amount})  # noqa: E731
    fn = issue_refund_async if is_async else issue_refund
    refund = receipted(fn, StripeRefundVerifier(stripe.client()), to_claim, receipts, log=BrokenEvidenceLog())
    with pytest.raises(OSError, match="evidence disk full"):
        asyncio.run(refund(2500)) if is_async else refund(2500)
    assert [r["verdict"] for r in receipts.receipts()] == ["verified"]


@pytest.mark.parametrize("is_async", [False, True])
def test_a_failed_evidence_log_write_never_replaces_the_tools_exception(tmp_path, is_async):
    import asyncio
    import sys

    class ToolError(Exception):
        pass

    stripe = Stripe()
    receipts = ReceiptLog(tmp_path / "r.jsonl", key=KEY)

    def issue_refund(amount):
        stripe.refund("pi_A1", amount)  # the refund lands, then the tool fails
        raise ToolError("upstream timeout")

    async def issue_refund_async(amount):
        return issue_refund(amount)

    def to_claim(amount):
        return Claim("stripe.refund.create", "", {"payment_intent": "pi_A1", "amount": amount})

    fn = issue_refund_async if is_async else issue_refund
    refund = receipted(fn, StripeRefundVerifier(stripe.client()), to_claim, receipts, log=BrokenEvidenceLog())
    with pytest.raises(ToolError, match="upstream timeout") as caught:
        asyncio.run(refund(2500)) if is_async else refund(2500)
    assert [r["verdict"] for r in receipts.receipts()] == ["verified"]  # the receipt is still issued
    if sys.version_info >= (3, 11):
        assert any("evidence log write failed: OSError" in note for note in caught.value.__notes__)


def test_an_anchor_failure_raised_as_an_error_still_tracks_the_billed_effect(tmp_path):
    """The attack: under -W error the anchor warning skips billing, so the effect bills twice."""
    import warnings

    from agent_readback import AlreadyBilled

    def broken_anchor(count, head):
        raise OSError("anchor offline")

    log = ReceiptLog(tmp_path / "r.jsonl", key=KEY, anchor=broken_anchor)
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        with pytest.raises(RuntimeWarning, match="anchor failed"):
            log.append(issue_receipt(verdict(), KEY, effect="stripe:refund:re_1"))  # written, then the warning raises
        with pytest.raises(AlreadyBilled):
            log.append(issue_receipt(verdict(), KEY, effect="stripe:refund:re_1"))
    assert [r["billable"] for r in ReceiptLog(log.path, key=KEY).receipts()] == [True]


def test_a_receipt_log_bills_each_effect_once(tmp_path):
    from agent_readback import AlreadyBilled

    log = ReceiptLog(tmp_path / "r.jsonl", key=KEY)
    first = issue_receipt(verdict(), KEY, effect="stripe:refund:re_1")
    log.append(first)
    with pytest.raises(AlreadyBilled):
        log.append(issue_receipt(verdict(), KEY, effect="stripe:refund:re_1"))
    with pytest.raises(AlreadyBilled):  # a fresh instance loads what the file already billed
        ReceiptLog(log.path, key=KEY).append(issue_receipt(verdict(), KEY, effect="stripe:refund:re_1"))
    log.append(issue_receipt(verdict(Status.FAILED), KEY, effect="stripe:refund:re_1"))  # not billable: fine
    log.append(issue_receipt(verdict(), KEY, effect="stripe:refund:re_2"))
    assert [r["billable"] for r in ReceiptLog(log.path, key=KEY).receipts()] == [True, False, True]


def test_overlapping_reconciles_sharing_a_receipt_log_bill_an_effect_once(tmp_path):
    stripe = Stripe()
    stripe.refund("pi_A1", 2500)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,2500,usd"])
    shared = ReceiptLog(tmp_path / "november.jsonl", key=KEY)

    class Overlapping(StripeRefunds):
        ran = False

        def find(self, claim, oid):
            if not Overlapping.ran:  # the other run starts after this one read the log's history
                Overlapping.ran = True
                run_stripe(stripe, path, receipts=shared)
            return super().find(claim, oid)

    finder = Overlapping(StripeRefundVerifier(stripe.client()))
    (late,) = reconcile(load_outcomes(path, system="stripe"), finder, KEY, receipts=shared)
    assert late.verdict == "contradicted" and "already_billed" in [r["kind"] for r in late.reasons]
    rows = ReceiptLog(shared.path, key=KEY).receipts()
    assert [r["billable"] for r in rows] == [True, False]


# -- Log format 2: each receipt's place in the log is signed ------------------------------

def _signed_log(tmp_path, count=3, name="r.jsonl"):
    private, private_path, public_path = keypair(tmp_path)
    log = ReceiptLog(tmp_path / name, key=KEY, signing_key=private)
    for n in range(count):
        log.append(issue_receipt(verdict(), KEY, signing_key=private, effect=f"stripe:refund:re_{n}"))
    return log, private, log.path.read_text().splitlines()


def _write(tmp_path, name, lines):
    path = tmp_path / name
    path.write_text("".join(line + "\n" for line in lines))
    return path


def test_a_public_check_catches_a_body_swapped_for_another_genuine_receipt(tmp_path):
    log, private, lines = _signed_log(tmp_path)
    # Keep record 1's seq, prev and hash, but give it another genuine signed receipt's body.
    record = json.loads(lines[1])
    record["body"] = json.loads(lines[2])["body"]
    assert verify_receipt(record["body"], public_key=private.public_key()) is None  # the body alone still verifies
    swapped = _write(tmp_path, "swapped.jsonl", [lines[0], json.dumps(record), lines[2]])
    count, problems = verify_signed_receipts(swapped, private.public_key())
    assert count == 3 and any("record 1: its place in the log does not verify" in p for p in problems)
    assert verify_signed_receipts(log.path, private.public_key()) == (3, [])


def test_a_public_check_rejects_a_missing_or_malformed_hash(tmp_path):
    _, private, lines = _signed_log(tmp_path)
    first, second = json.loads(lines[0]), json.loads(lines[1])
    del first["hash"]
    second["prev"] = None  # a missing hash and a null prev must not count as linked
    unlinked = _write(tmp_path, "unlinked.jsonl", [json.dumps(first), json.dumps(second), lines[2]])
    problems = verify_signed_receipts(unlinked, private.public_key())[1]
    assert "record 0: missing or malformed hash" in problems
    assert any(p.startswith("record 1: out of order") for p in problems)
    first = json.loads(lines[0])
    first["hash"] = "XYZ"
    second = json.loads(lines[1])
    second["prev"] = "XYZ"
    malformed = _write(tmp_path, "malformed.jsonl", [json.dumps(first), json.dumps(second), lines[2]])
    assert "record 0: missing or malformed hash" in verify_signed_receipts(malformed, private.public_key())[1]


def test_a_public_check_catches_a_dropped_receipt_with_rewritten_links(tmp_path):
    log, private, lines = _signed_log(tmp_path)
    second, third = json.loads(lines[1]), json.loads(lines[2])
    third["seq"], third["prev"] = 1, second["prev"]  # relink record 2 to stand where record 1 was
    dropped = _write(tmp_path, "dropped.jsonl", [lines[0], json.dumps(third)])
    problems = verify_signed_receipts(dropped, private.public_key())[1]
    assert any("record 1: its place in the log does not verify" in p for p in problems)


def test_a_public_head_catches_dropped_newest_receipts(tmp_path):
    log, private, lines = _signed_log(tmp_path)
    head = log.place_head
    assert verify_signed_receipts(log.path, private.public_key(), head=head) == (3, [])
    truncated = _write(tmp_path, "truncated.jsonl", lines[:2])
    assert verify_signed_receipts(truncated, private.public_key())[1] == []  # without the head, a clean prefix
    problems = verify_signed_receipts(truncated, private.public_key(), head=head)[1]
    assert problems == ["the given head is not in the log: receipts were dropped or rewritten"]


def test_stripping_the_place_signature_is_not_an_older_log(tmp_path):
    log, private, lines = _signed_log(tmp_path)
    stripped = json.loads(lines[2])
    stripped.pop("place")
    path = _write(tmp_path, "stripped.jsonl", [lines[0], lines[1], json.dumps(stripped)])
    problems = verify_signed_receipts(path, private.public_key(), allow_v1=True)[1]
    assert any("not signed, after records whose place is" in p for p in problems)


def test_format_1_receipts_need_the_allow_v1_flag(tmp_path, monkeypatch, capsys):
    private, _, public_path = keypair(tmp_path)
    old = ReceiptLog(tmp_path / "old.jsonl", key=KEY)  # format 1: signed receipts, no signing key on the log
    old.path.write_text("")
    for n in range(2):
        receipt = issue_receipt(verdict(), KEY, signing_key=private, effect=f"stripe:refund:re_{n}")
        old._write(receipt.to_dict())
    assert "place" not in old.path.read_text()
    problems = verify_signed_receipts(old.path, private.public_key())[1]
    assert len(problems) == 2 and all("log format 1" in p and "--allow-v1" in p for p in problems)
    assert verify_signed_receipts(old.path, private.public_key(), allow_v1=True) == (2, [])
    assert main(["verify-receipts", str(old.path), "--public-key", str(public_path)]) == 1
    capsys.readouterr()
    assert main(["verify-receipts", str(old.path), "--public-key", str(public_path), "--allow-v1"]) == 0
    out = capsys.readouterr().out
    assert "2 are log format 1" in out and "not caught without the receipt key" in out  # never claims their place
    assert "where the issuer wrote it" not in out
    monkeypatch.setenv(RECEIPT_KEY_ENV, KEY)  # the keyed chain covers place, but the public-key check still asks
    assert main(["verify-receipts", str(old.path), "--public-key", str(public_path)]) == 1
    assert main(["verify-receipts", str(old.path), "--public-key", str(public_path), "--allow-v1"]) == 0


def test_an_older_log_continues_in_format_2_and_still_verifies(tmp_path):
    private, _, _ = keypair(tmp_path)
    path = tmp_path / "r.jsonl"
    ReceiptLog(path, key=KEY).append(issue_receipt(verdict(), KEY, effect="stripe:refund:re_0"))  # format 1, HMAC
    log = ReceiptLog(path, key=KEY, signing_key=private)
    log.append(issue_receipt(verdict(), KEY, signing_key=private, effect="stripe:refund:re_1"))
    log.append(issue_receipt(verdict(), KEY, signing_key=private, effect="stripe:refund:re_2"))
    assert ReceiptLog(path, key=KEY, signing_key=private).verify() == []
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert ["place" in row for row in rows] == [False, True, True]


def test_a_format_2_log_is_never_continued_without_the_signing_key(tmp_path):
    log, private, _ = _signed_log(tmp_path)
    before = log.path.read_bytes()
    with pytest.raises(ValueError, match="open it with signing_key="):
        ReceiptLog(log.path, key=KEY, public_key=private.public_key()).append(
            issue_receipt(verdict(), KEY, signing_key=private, effect="stripe:refund:re_9"))
    assert log.path.read_bytes() == before


def test_a_receipt_log_that_does_not_verify_is_a_file_error_in_reconcile(tmp_path, stripe_cli, capsys):
    other = "another-receipt-key-0123456789abcdef-test"
    receipts = tmp_path / "r.jsonl"
    ReceiptLog(receipts, key=other).append(issue_receipt(verdict(), other))
    stripe_cli.refund("pi_A1", 1)
    path = csv_file(tmp_path, ["fin-1,stripe.refund.create,pi_A1,1,usd"])
    assert main(["reconcile", str(path), "--system", "stripe", "--receipts", str(receipts)]) == 3
    assert "does not verify" in capsys.readouterr().err
