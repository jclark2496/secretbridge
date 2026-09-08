"""Approval registries for secure handoff sinks."""
from __future__ import annotations

import sqlite3
import urllib.parse
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

from .store import now


@dataclass
class RegistryCheck:
    request_id: str
    destination_label: str
    destination_id: str
    approved: bool
    reason: str


@dataclass
class SQLiteApprovalRegistry:
    """Read-only exact request/name/project/expiry registry for sink approval.

    The handoff store calls the sink while holding a writer transaction. This registry
    opens a separate read-only connection and never mutates state, so adapter writes are
    authorized only by an exact active local request without giving the browser any control
    over destination routing.
    """

    state_path: Path
    checks: list[RegistryCheck] = field(default_factory=list)

    def is_approved(self, *, request_id: str, destination_label: str, destination_id: str) -> bool:
        reason = "not approved"
        approved = False
        try:
            uri = f"file:{urllib.parse.quote(str(self.state_path), safe='/')}?mode=ro"
            with closing(sqlite3.connect(uri, uri=True, timeout=1, isolation_level=None)) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA busy_timeout = 1000")
                conn.execute("PRAGMA query_only = ON")
                conn.execute("PRAGMA journal_mode = WAL")
                row = conn.execute(
                    """
                    SELECT request_id, destination_label, destination_id, expires_at, used
                      FROM requests
                     WHERE request_id = ?
                       AND destination_label = ?
                       AND destination_id = ?
                       AND expires_at > ?
                       AND used = 0
                    """,
                    (request_id, destination_label, destination_id, now()),
                ).fetchone()
            approved = row is not None
            reason = "exact active request match" if approved else "no exact active request match"
        except sqlite3.Error:
            reason = "registry read failed"
            approved = False
        self.checks.append(RegistryCheck(request_id, destination_label, destination_id, approved, reason))
        return approved
