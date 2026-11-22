import pytest
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
    assert main(["verify-log", str(tmp_path / "nope.jsonl")]) == 3
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


def test_forged_keyed_log_is_not_called_trustworthy_without_the_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("READBACK_LOG_KEY", raising=False)
    path = tmp_path / "keyed.jsonl"
    log = EvidenceLog(path, key="s3cret")
    log.append(verdict(1))
    log.append(verdict(2))

    # Honest keyed log, auditor forgot the key: a clear "needs key", not "edited", not OK.
    assert main(["verify-log", str(path)]) == 1
    assert "written with a key" in capsys.readouterr().err

    # Forger rebuilds the chain unkeyed and drops the marker: OK is flagged UNKEYED...
    records = [json.loads(line) for line in path.read_text().splitlines()]
    for record in records:
        record.pop("mac")
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    _rewrite_chain_without_key(path)
    assert main(["verify-log", str(path)]) == 0
    captured = capsys.readouterr()
    assert "(UNKEYED)" in captured.out and "not forgery" in captured.err
    # ...and an audit with --require-key refuses it outright.
    assert main(["verify-log", "--require-key", str(path)]) == 1


def test_dashboard_never_overwrites_the_evidence_log(tmp_path):
    path = tmp_path / "log.jsonl"
    EvidenceLog(path).append(verdict(1))
    before = path.read_bytes()
    assert main(["dashboard", str(path), "-o", str(path)]) == 3
    other = tmp_path / "other.jsonl"
    other.write_text("keep me")
    assert main(["dashboard", str(path), "-o", str(other)]) == 3
    assert path.read_bytes() == before and other.read_text() == "keep me"


def test_malformed_records_report_broken_not_a_traceback(tmp_path, capsys):
    path = tmp_path / "log.jsonl"
    for bad in ('"seqprevbodyhash"', '[1, 2]', '{"seq": 0, "prev": "x", "body": {}, "hash": "y"}'):
        path.write_text(bad + "\n")
        for command in ("verify-log", "report"):
            assert main([command, str(path)]) == 1, (bad, command)
        assert main(["dashboard", str(path), "-o", str(tmp_path / "r.html")]) == 1, bad
    assert "Traceback" not in capsys.readouterr().err


def test_boolean_seq_does_not_pass_as_an_integer(tmp_path):
    path = tmp_path / "log.jsonl"
    log = EvidenceLog(path)
    log.append(verdict(1))
    log.append(verdict(2))
    records = [json.loads(line) for line in path.read_text().splitlines()]
    records[1]["seq"] = True
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    assert EvidenceLog(path).verify_chain() == (False, 1)


def test_cli_file_errors_exit_3_without_a_traceback(tmp_path, capsys):
    path = tmp_path / "log.jsonl"
    EvidenceLog(path).append(verdict(1))
    assert main(["verify-log", str(tmp_path)]) == 3  # a directory
    assert main(["dashboard", str(path), "-o", str(tmp_path / "missing" / "r.html")]) == 3
    assert "Traceback" not in capsys.readouterr().err


def test_log_uses_lf_line_endings_on_every_platform(tmp_path):
    path = tmp_path / "log.jsonl"
    log = EvidenceLog(path)
    log.append(verdict(1))
    log.append(verdict(2))
    data = path.read_bytes()
    assert b"\r\n" not in data and data.count(b"\n") == 2


def test_non_ascii_hash_reports_broken_not_a_traceback(tmp_path, capsys):
    from agent_readback.evidence import GENESIS

    path = tmp_path / "log.jsonl"
    path.write_text(json.dumps({"seq": 0, "prev": GENESIS, "body": {}, "hash": "\u00e9"}) + "\n", encoding="utf-8")
    for command in ("verify-log", "report"):
        assert main([command, str(path)]) == 1
    assert "Traceback" not in capsys.readouterr().err


def test_dashboard_refuses_a_hard_link_to_the_log(tmp_path):
    import os

    path = tmp_path / "log.jsonl"
    EvidenceLog(path).append(verdict(1))
    before = path.read_bytes()
    link = tmp_path / "report.html"
    os.link(path, link)
    assert main(["dashboard", str(path), "-o", str(link)]) == 3
    assert path.read_bytes() == before


def test_dashboard_refuses_a_symlink_to_any_log(tmp_path):
    import os

    path = tmp_path / "log.jsonl"
    EvidenceLog(path).append(verdict(1))
    archive = tmp_path / "archive.jsonl"
    archive.write_text("archived evidence")
    link = tmp_path / "report.html"
    try:
        os.symlink(archive, link)
    except OSError:
        pytest.skip("symlinks need extra privileges on this system")
    assert main(["dashboard", str(path), "-o", str(link)]) == 3
    assert archive.read_text() == "archived evidence"


def test_parallel_appends_keep_the_chain_intact(tmp_path):
    import threading

    log = EvidenceLog(tmp_path / "log.jsonl")
    threads = [threading.Thread(target=log.append, args=(verdict(n),)) for n in range(40)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(log.records()) == 40 and log.verify_chain() == (True, None)


def _anchored_log(tmp_path, n=3):
    from agent_readback import FileAnchor

    anchor = FileAnchor(tmp_path / "anchor" / "head.json")
    anchor.path.parent.mkdir()
    log = EvidenceLog(tmp_path / "log.jsonl", anchor=anchor)
    for i in range(n):
        log.append(verdict(i))
    return log, anchor


def test_dropping_the_newest_records_is_caught_with_an_anchor(tmp_path, capsys):
    log, anchor = _anchored_log(tmp_path)
    assert anchor.read() == (3, log.head)
    path = str(log.path)
    assert main(["verify-log", path, "--anchor", str(anchor.path)]) == 0

    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join(lines[:-1]) + "\n")  # attacker drops the newest record
    assert main(["verify-log", path]) == 0  # the file alone still looks intact...
    capsys.readouterr()
    assert main(["verify-log", path, "--anchor", str(anchor.path)]) == 1  # ...the anchor does not
    assert "newest records were dropped" in capsys.readouterr().out


def test_head_flag_catches_truncation_and_allows_later_growth(tmp_path, capsys):
    log, _ = _anchored_log(tmp_path)
    head = log.head
    log.append(verdict(9))  # growth after the head was noted is fine
    assert main(["verify-log", str(log.path), "--head", head.upper()]) == 0
    assert "1 record(s) after it" in capsys.readouterr().out

    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join(lines[:2]) + "\n")
    assert main(["verify-log", str(log.path), "--head", head]) == 1


def test_rewritten_record_at_the_anchor_is_caught(tmp_path, capsys):
    log, anchor = _anchored_log(tmp_path)
    count, head = anchor.read()
    assert log.check_anchor(count, head) is None
    assert "rewritten" in log.check_anchor(count, "0" * 64)


def test_failed_anchor_never_breaks_the_append(tmp_path):
    def broken(count, head):
        raise OSError("anchor store is down")

    log = EvidenceLog(tmp_path / "log.jsonl", anchor=broken)
    with pytest.warns(RuntimeWarning, match="anchor failed"):
        log.append(verdict(1))
    assert len(log.records()) == 1 and isinstance(log.anchor_error, OSError)


def test_bad_or_missing_anchor_file_exits_3(tmp_path):
    log, anchor = _anchored_log(tmp_path)
    assert main(["verify-log", str(log.path), "--anchor", str(tmp_path / "missing.json")]) == 3
    anchor.path.write_text('{"count": "3", "head": "x"}')
    assert main(["verify-log", str(log.path), "--anchor", str(anchor.path)]) == 3


def test_new_log_is_readable_only_by_its_owner(tmp_path):
    import os
    import subprocess

    path = tmp_path / "log.jsonl"
    EvidenceLog(path).append(verdict(0))
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0
        return
    acl = subprocess.run(["icacls", str(path)], capture_output=True, text=True, check=True).stdout
    grants = [line for line in acl.splitlines() if ":(" in line]
    assert len(grants) == 1 and "(I)" not in acl, acl  # one explicit grant, nothing inherited
    assert os.environ["USERNAME"].lower() in grants[0].lower()
    for other in ("Everyone", "Users", "Authenticated Users", "Administrators", "SYSTEM"):
        assert f"\\{other}:" not in acl and f" {other}:" not in acl


def test_log_still_written_when_owner_only_access_cannot_be_set(tmp_path, monkeypatch):
    import os
    import subprocess

    if os.name != "nt":
        pytest.skip("owner-only access uses icacls on Windows only")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 5, "", "Access is denied."))
    path = tmp_path / "log.jsonl"
    with pytest.warns(RuntimeWarning, match="could not restrict"):
        EvidenceLog(path).append(verdict(0))
    assert EvidenceLog(path).verify_chain() == (True, None)


def test_spoofed_username_cannot_lock_the_writer_out_of_its_own_log(tmp_path, monkeypatch):
    import os
    import subprocess

    if os.name != "nt":
        pytest.skip("owner-only access uses icacls on Windows only")
    me = os.environ["USERNAME"]
    # A real, resolvable account that is not this process: the old code granted it the log.
    monkeypatch.setenv("USERDOMAIN", "BUILTIN")
    monkeypatch.setenv("USERNAME", "Guests")
    monkeypatch.setenv("SystemRoot", str(tmp_path))  # a fake System32 here would have been run
    path = tmp_path / "log.jsonl"
    log = EvidenceLog(path)
    log.append(verdict(0))
    log.append(verdict(1))  # failed with PermissionError when the grant went to the wrong account
    assert EvidenceLog(path).verify_chain() == (True, None)
    acl = subprocess.run(["icacls", str(path)], capture_output=True, text=True, check=True).stdout
    assert "Guests" not in acl and me.lower() in acl.lower()


def test_log_is_restricted_before_its_first_record_is_written(tmp_path, monkeypatch):
    from agent_readback import evidence

    sizes = []
    monkeypatch.setattr(evidence, "_owner_only", lambda path: sizes.append(path.stat().st_size))
    path = tmp_path / "log.jsonl"
    log = EvidenceLog(path)
    log.append(verdict(0))
    log.append(verdict(1))
    assert sizes == [0]  # restricted once, while still empty; never again for an existing log


def test_icacls_failing_without_output_still_warns(tmp_path, monkeypatch):
    import os
    import subprocess

    if os.name != "nt":
        pytest.skip("owner-only access uses icacls on Windows only")

    def fake_run(args, **kwargs):
        if args[0].lower().endswith("whoami.exe"):
            return subprocess.CompletedProcess(args, 0, '"host\\me","S-1-5-21-1-2-3-1001"\n', "")
        return subprocess.CompletedProcess(args, 1, "", "")  # icacls: failed, printed nothing

    monkeypatch.setattr(subprocess, "run", fake_run)
    path = tmp_path / "log.jsonl"
    with pytest.warns(RuntimeWarning, match="icacls exited with 1"):
        EvidenceLog(path).append(verdict(0))
    assert EvidenceLog(path).verify_chain() == (True, None)
