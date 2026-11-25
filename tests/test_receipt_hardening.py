"""Fixes for the residual risks in docs/receipts/04-security-review.md, each shown failing for the attacker.

Fake ids and throwaway keys only.
"""

import json
import os
import sqlite3

import httpx
import pytest

from agent_readback import FileAnchor, ReceiptLog, issue_receipt, receipted, verify_receipt, verify_signed_receipts
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
    return Verdict(status, claim, (), {"created": [{"id": "re_1"}]})


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
    for _ in range(3):
        log.append(issue_receipt(verdict(), KEY, signing_key=private))
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
    assert main(["verify-receipts", str(receipts), "--public-key", str(public_path), "--head", "0" * 64]) == 2
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
