import json

from agent_readback import Claim, EvidenceLog, Finding, FindingKind, Status, Verdict
from agent_readback.cli import main
from agent_readback.report import summarise


def verdict(n: int, status=Status.VERIFIED, findings=()) -> Verdict:
    claim = Claim("demo.action", f"DONE for Patient/{n}", {"patient": f"Patient/{n}", "status": "booked"})
    return Verdict(status, claim, tuple(findings), {"observed_note": "s3cr3t-observed"})


def test_chain_is_intact_and_survives_reopen(tmp_path):
    path = tmp_path / "log.jsonl"
    log = EvidenceLog(path)
    for n in range(3):
        log.append(verdict(n))
    EvidenceLog(path).append(verdict(3))
    assert EvidenceLog(path).verify_chain() == (True, None)
    assert len(path.read_text().splitlines()) == 4


def test_edited_or_deleted_record_breaks_the_chain(tmp_path):
    path = tmp_path / "log.jsonl"
    log = EvidenceLog(path)
    for n in range(3):
        log.append(verdict(n))
    original = path.read_text().splitlines()

    record = json.loads(original[1])
    record["body"]["status"] = "failed"
    path.write_text("\n".join([original[0], json.dumps(record), original[2]]) + "\n")
    assert log.verify_chain() == (False, 1)

    path.write_text("\n".join([original[0], original[2]]) + "\n")
    assert log.verify_chain() == (False, 1)


def test_values_are_redacted_by_default(tmp_path):
    path = tmp_path / "log.jsonl"
    finding = Finding(FindingKind.WRONG_VALUE, "patient is 'Patient/9', expected 'Patient/1'", "patient", "Patient/1", "Patient/9")
    EvidenceLog(path).append(verdict(1, Status.FAILED, [finding]))
    text = path.read_text()
    assert "Patient/" not in text and "s3cr3t-observed" not in text
    body = json.loads(text)["body"]
    assert body["claim"]["expected"] == {"patient": "[redacted]", "status": "[redacted]"}
    assert body["findings"][0]["field"] == "patient" and body["findings"][0]["kind"] == "wrong_value"
    assert len(body["claim"]["agent_said_digest"]) == 64


def test_keep_fields_stores_only_named_fields(tmp_path):
    path = tmp_path / "log.jsonl"
    EvidenceLog(path, keep_fields=["status"]).append(verdict(1))
    expected = json.loads(path.read_text())["body"]["claim"]["expected"]
    assert expected == {"patient": "[redacted]", "status": "booked"}


def test_keep_everything_when_asked(tmp_path):
    path = tmp_path / "log.jsonl"
    EvidenceLog(path, keep_fields="*").append(verdict(1))
    assert "Patient/1" in path.read_text()


def test_report_and_cli(tmp_path, capsys):
    path = tmp_path / "log.jsonl"
    log = EvidenceLog(path)
    log.append(verdict(1))
    log.append(verdict(2, Status.FAILED, [Finding(FindingKind.MISSING, "gone")]))
    log.append(verdict(3, Status.UNVERIFIED, [Finding(FindingKind.UNREACHABLE, "down")]))
    summary = summarise(log.records())
    assert (summary["total"], summary["verified"], summary["failed"], summary["unverified"]) == (3, 1, 1, 1)
    assert summary["finding_kinds"] == {"missing": 1, "unreachable": 1}

    assert main(["verify-log", str(path)]) == 0
    assert main(["report", str(path)]) == 0
    assert "Failed:          1  (33.3%)" in capsys.readouterr().out

    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[1:]) + "\n")
    assert main(["verify-log", str(path)]) == 1


def test_cli_rejects_a_missing_file(tmp_path, capsys):
    assert main(["verify-log", str(tmp_path / "nope.jsonl")]) == 2
    assert "no such file" in capsys.readouterr().err


def test_compare_fields_treats_none_equal_to_none():
    from agent_readback import compare_fields

    assert compare_fields({"x": None}, {"x": None}) == []
    assert [f.detail for f in compare_fields({"x": 1}, {})] == ["x is not set"]


def _rewrite_chain_without_key(path):
    """An attacker with write access to the file but no key forges a 'valid' chain."""
    from agent_readback.evidence import GENESIS, _digest

    records = EvidenceLog(path).records()
    prev, out = GENESIS, []
    for i, record in enumerate(records):
        body = record["body"]
        body["status"] = "verified"  # cover up every failure
        digest = _digest(prev, i, body, key=None)
        out.append({"seq": i, "prev": prev, "body": body, "hash": digest})
        prev = digest
    path.write_text("\n".join(__import__("json").dumps(r) for r in out) + "\n")


def test_keyed_log_detects_a_chain_forged_without_the_key(tmp_path, monkeypatch):
    path = tmp_path / "keyed.jsonl"
    log = EvidenceLog(path, key="s3cret")
    log.append(verdict(1, Status.FAILED, [Finding(FindingKind.MISSING, "gone")]))
    log.append(verdict(2))
    assert EvidenceLog(path, key="s3cret").verify_chain() == (True, None)
    assert EvidenceLog(path).verify_chain()[0] is False  # wrong (absent) key: not trusted

    _rewrite_chain_without_key(path)
    assert EvidenceLog(path).verify_chain() == (True, None)  # looks fine without the key...
    assert EvidenceLog(path, key="s3cret").verify_chain() == (False, 0)  # ...and is caught with it

    monkeypatch.setenv("READBACK_LOG_KEY", "s3cret")
    assert main(["verify-log", str(path)]) == 1


def test_reordered_records_break_the_chain(tmp_path):
    path = tmp_path / "log.jsonl"
    log = EvidenceLog(path)
    for n in range(3):
        log.append(verdict(n))
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2], lines[1]]) + "\n")
    assert EvidenceLog(path).verify_chain() == (False, 1)


def test_malformed_line_is_reported_not_a_traceback(tmp_path, capsys):
    path = tmp_path / "log.jsonl"
    EvidenceLog(path).append(verdict(1))
    with path.open("a") as handle:
        handle.write("not json\n")
    assert main(["verify-log", str(path)]) == 1
    assert "line 2" in capsys.readouterr().err


def test_verify_log_prints_head_hash_for_external_anchoring(tmp_path, capsys):
    path = tmp_path / "log.jsonl"
    log = EvidenceLog(path)
    log.append(verdict(1))
    assert main(["verify-log", str(path)]) == 0
    assert f"head: {log.head}" in capsys.readouterr().out


def test_dashboard_page_is_redacted_and_escapes_hostile_context(tmp_path):
    path, out = tmp_path / "log.jsonl", tmp_path / "page.html"
    log = EvidenceLog(path)
    log.append(verdict(1))
    hostile = Claim("demo.action", "DONE", {"patient": "Patient/2"}, {"run": "<script>alert(1)</script>"})
    log.append(Verdict(Status.FAILED, hostile, (Finding(FindingKind.WRONG_VALUE, "x", "start", "a", "b"),)))

    assert main(["dashboard", str(path), "-o", str(out)]) == 0
    html = out.read_text(encoding="utf-8")
    assert "wrong value (start)" in html and "Evidence chain: intact" in html
    assert "Patient/" not in html and "s3cr3t-observed" not in html  # redaction carries through
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_dashboard_of_a_tampered_log_says_broken_and_exits_1(tmp_path):
    path, out = tmp_path / "log.jsonl", tmp_path / "page.html"
    log = EvidenceLog(path)
    log.append(verdict(1))
    log.append(verdict(2))
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0].replace("verified", "failed"), lines[1]]) + "\n")

    assert main(["dashboard", str(path), "-o", str(out)]) == 1
    assert "BROKEN" in out.read_text(encoding="utf-8")
