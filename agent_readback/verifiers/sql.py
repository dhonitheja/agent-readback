"""Read-back verifier for one row in a SQL table, over any DB-API connection.

Actions:
  sql.row.insert   the row must exist with the expected values, must not have
                   existed before, and the table must have grown by exactly one
  sql.row.update   the row must exist with the expected values and the table
                   size must not have changed

`expected` must include the key column. Table and column names come from your
code, never from the agent, and are checked against a strict pattern.

Use `placeholder="%s"` for psycopg (Postgres) and "?" for sqlite3. Connect with
a read-only database role.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from ..core import Claim, Finding, FindingKind, Status, Verdict, compare_fields

INSERT = "sql.row.insert"
UPDATE = "sql.row.update"
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")
_PLACEHOLDER = re.compile(r"^(\?|%s|:[A-Za-z_][A-Za-z0-9_]*|:[1-9][0-9]*|\$[1-9][0-9]*)$")  # DB-API paramstyles


def _ident(name: str) -> str:
    if not _IDENT.fullmatch(name):
        raise ValueError(f"unsafe SQL identifier: {name!r}")
    return name


class SqlRowVerifier:
    def __init__(self, connect: Callable[[], Any], table: str, key_column: str, placeholder: str = "%s") -> None:
        self.connect = connect
        self.table = _ident(table)
        self.key_column = _ident(key_column)
        if not _PLACEHOLDER.fullmatch(placeholder):  # it is spliced into the query text
            raise ValueError(f"unsafe SQL placeholder: {placeholder!r}")
        self.placeholder = placeholder

    def _read(self, expected: dict[str, Any]) -> tuple[dict[str, Any] | None, int]:
        columns = [_ident(name) for name in expected]
        connection = self.connect()
        try:
            cursor = connection.cursor()
            # Identifiers and placeholder are pattern-checked; the key value is a bound parameter.
            cursor.execute(
                f"SELECT {', '.join(columns)} FROM {self.table} WHERE {self.key_column} = {self.placeholder}",  # nosec B608
                (expected[self.key_column],),
            )
            row = cursor.fetchone()
            cursor.execute(f"SELECT COUNT(*) FROM {self.table}")  # table name pattern-checked  # nosec B608
            count = cursor.fetchone()[0]
        finally:
            connection.close()
        return (dict(zip(columns, row)) if row is not None else None), count

    def snapshot(self, claim: Claim) -> tuple[dict[str, Any] | None, int] | None:
        try:
            return self._read(claim.expected)
        except Exception:  # any driver error means no trustworthy snapshot
            return None

    def check(self, claim: Claim, before: tuple[dict[str, Any] | None, int] | None) -> Verdict:
        unreachable = lambda why: Verdict(  # noqa: E731
            Status.UNVERIFIED, claim, (Finding(FindingKind.UNREACHABLE, why),)
        )
        if before is None:
            return unreachable("no snapshot was taken before the action")
        if claim.action not in (INSERT, UPDATE):
            return unreachable(f"unknown action {claim.action!r}")
        try:
            row, count = self._read(claim.expected)
        except Exception as error:
            return unreachable(f"could not read the database: {error}")

        row_before, count_before = before
        findings: list[Finding] = []
        if row is None:
            findings.append(Finding(FindingKind.MISSING, "the row does not exist"))
        else:
            findings += compare_fields(claim.expected, row)
            if claim.action == INSERT and row_before is not None:
                findings.append(Finding(FindingKind.MISSING, "the row already existed, so nothing was inserted"))
        allowed_growth = 1 if claim.action == INSERT else 0
        growth = count - count_before
        if growth > allowed_growth:
            findings.append(
                Finding(FindingKind.EXTRA_EFFECT, f"{growth - allowed_growth} unclaimed row(s) were added", actual=growth)
            )
        else:
            inserted = int(claim.action == INSERT and row_before is None and row is not None)
            removed = inserted - growth
            if removed > 0:
                findings.append(Finding(FindingKind.EXTRA_EFFECT, f"{removed} row(s) were removed", actual=growth))
        status = Status.VERIFIED if not findings else Status.FAILED
        return Verdict(status, claim, tuple(findings), {"row": row, "row_count": count})
