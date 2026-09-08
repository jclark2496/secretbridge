"""SQLite request registry for encrypted handoff.

The registry is Mac-local. Browser clients cannot choose destination metadata; project and destination_label
are bound here when a request is created. Submitted credential values are never stored here in
plaintext; only the encrypted envelope JSON is persisted after sink confirmation.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any

from .crypto import canonical_envelope_json, decrypt_envelope, generate_key_pair
from .key_protector import KeyProtector, KeyProtectorError
from .sinks import DurableSink, HandoffDestination, HandoffReceipt, validate_destination_id, validate_destination_label

TOKEN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
DEFAULT_DESTINATION_ID = "demo-local-destination"


def now() -> int:
    return int(time.time())


def is_urlsafe_token(value: object, *, min_len: int = 1, max_len: int = 256) -> bool:
    if not isinstance(value, str) or not (min_len <= len(value) <= max_len):
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return all(ch in TOKEN_CHARS for ch in value)


class RequestStore:
    def __init__(self, path: Path, *, key_protector: KeyProtector | None = None, require_protected_keys: bool = False):
        self.path = Path(path)
        self.key_protector = key_protector
        self.require_protected_keys = require_protected_keys
        if self.require_protected_keys and self.key_protector is None:
            raise KeyProtectorError("protected key storage requires an available key protector")
        if self.require_protected_keys and self.key_protector is not None:
            assert_available = getattr(self.key_protector, "assert_available", None)
            if callable(assert_available):
                assert_available()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._set_private_permissions()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        self._set_private_permissions()
        return conn

    def _init_db(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY,
                    auth_token TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    used_at INTEGER,
                    destination_id TEXT NOT NULL,
                    destination_label TEXT NOT NULL,
                    private_key_pem TEXT NOT NULL,
                    public_jwk_json TEXT NOT NULL,
                    session_id TEXT,
                    csrf TEXT,
                    session_created_at INTEGER,
                    encrypted_envelope_json TEXT,
                    storage_id TEXT,
                    storage_durable INTEGER,
                    lifecycle_scope TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_expires_at ON requests(expires_at)")
            columns = {row[1] for row in conn.execute("PRAGMA table_info(requests)").fetchall()}
            if "private_key_ciphertext" not in columns:
                conn.execute("ALTER TABLE requests ADD COLUMN private_key_ciphertext TEXT")
            if "private_key_protector_id" not in columns:
                conn.execute("ALTER TABLE requests ADD COLUMN private_key_protector_id TEXT")
            if "lifecycle_scope" not in columns:
                conn.execute("ALTER TABLE requests ADD COLUMN lifecycle_scope TEXT")
            if "storage_durable" not in columns:
                conn.execute("ALTER TABLE requests ADD COLUMN storage_durable INTEGER")

    def _set_private_permissions(self) -> None:
        for path in (self.path, Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")):
            try:
                os.chmod(path, 0o600)
            except FileNotFoundError:
                pass

    def create_request(self, *, ttl_seconds: int, destination_id: str, destination_label: str, lifecycle_scope: str | None = None) -> tuple[str, str]:
        if ttl_seconds <= 0:
            raise ValueError("ttl must be positive")
        destination_id = validate_destination_id(destination_id)
        destination_label = validate_destination_label(destination_label)
        if lifecycle_scope is not None and (
            not lifecycle_scope or len(lifecycle_scope) > 64 or any(ch in lifecycle_scope for ch in "\r\n\x00")
        ):
            raise ValueError("invalid lifecycle scope")
        key_pair = generate_key_pair()
        import json

        created_at = now()
        expires_at = created_at + ttl_seconds
        private_key_pem = key_pair.private_pem
        private_key_ciphertext = None
        private_key_protector_id = None
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            for _ in range(10):
                request_id = secrets.token_urlsafe(16)
                auth_token = secrets.token_urlsafe(24)
                if self.key_protector is not None:
                    try:
                        private_key_ciphertext = self.key_protector.protect_private_pem(key_pair.private_pem, request_id=request_id)
                    except Exception as exc:  # noqa: BLE001 - fail closed without partial row
                        conn.execute("ROLLBACK")
                        raise KeyProtectorError("private key protection failed") from None
                    private_key_pem = ""
                    private_key_protector_id = self.key_protector.protector_id
                try:
                    conn.execute(
                        """
                        INSERT INTO requests (
                            request_id, auth_token, created_at, expires_at, used,
                            destination_id, destination_label, private_key_pem, public_jwk_json,
                            private_key_ciphertext, private_key_protector_id, lifecycle_scope
                        ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            request_id,
                            auth_token,
                            created_at,
                            expires_at,
                            destination_id,
                            destination_label,
                            private_key_pem,
                            json.dumps(key_pair.public_jwk, sort_keys=True),
                            private_key_ciphertext,
                            private_key_protector_id,
                            lifecycle_scope,
                        ),
                    )
                except sqlite3.IntegrityError:
                    continue
                conn.execute("COMMIT")
                self._set_private_permissions()
                return request_id, auth_token
            conn.execute("ROLLBACK")
        raise RuntimeError("could not allocate unique request id")

    def open_session(self, request_id: str, auth_token: str, session_id: str, csrf: str) -> tuple[bool, str, dict[str, Any] | None]:
        if not all(is_urlsafe_token(v, max_len=256) for v in (request_id, auth_token, session_id, csrf)):
            return False, "unauthorized", None
        ts = now()
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM requests WHERE request_id = ?", (request_id,)).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return False, "not found", None
            if int(row["used"]):
                conn.execute("ROLLBACK")
                return False, "already used", dict(row)
            if int(row["expires_at"]) <= ts:
                conn.execute("ROLLBACK")
                return False, "expired", dict(row)
            if row["auth_token"] != auth_token:
                conn.execute("ROLLBACK")
                return False, "unauthorized", dict(row)
            conn.execute(
                "UPDATE requests SET session_id = ?, csrf = ?, session_created_at = ? WHERE request_id = ?",
                (session_id, csrf, ts, request_id),
            )
            row = conn.execute("SELECT * FROM requests WHERE request_id = ?", (request_id,)).fetchone()
            conn.execute("COMMIT")
            return True, "ok", dict(row)

    def submit_envelope(
        self,
        request_id: str,
        *,
        cookie_session: str,
        csrf: str,
        envelope: dict[str, Any],
        sink: DurableSink,
    ) -> tuple[bool, str, int, str | None]:
        if not is_urlsafe_token(request_id, max_len=128):
            return False, "not found", 404, None
        if not is_urlsafe_token(cookie_session, max_len=256):
            return False, "unauthorized", 401, None
        if not is_urlsafe_token(csrf, max_len=256):
            return False, "bad csrf", 403, None
        try:
            envelope_json = canonical_envelope_json(envelope)
        except (TypeError, ValueError):
            return False, "malformed envelope", 400, None
        if len(envelope_json.encode("utf-8")) > 32768:
            return False, "envelope too large", 413, None
        ts = now()
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM requests WHERE request_id = ?", (request_id,)).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return False, "not found", 404, None
            if int(row["used"]):
                conn.execute("ROLLBACK")
                return False, "already used", 410, None
            if int(row["expires_at"]) <= ts:
                conn.execute("ROLLBACK")
                return False, "expired", 410, None
            if not row["session_id"] or row["session_id"] != cookie_session:
                conn.execute("ROLLBACK")
                return False, "unauthorized", 401, None
            if not row["csrf"] or row["csrf"] != csrf:
                conn.execute("ROLLBACK")
                return False, "bad csrf", 403, None
            try:
                private_pem = self._private_pem_for_row(row)
                value = decrypt_envelope(envelope, request_id=request_id, private_pem=private_pem)
            except Exception:  # noqa: BLE001 - never leak crypto parse/decrypt detail to client
                conn.execute("ROLLBACK")
                return False, "malformed envelope", 400, None
            try:
                destination = HandoffDestination(row["destination_id"], row["destination_label"])
                store = getattr(sink, "store", None)
                if not callable(store):
                    raise RuntimeError("sink does not implement store contract")
                sink_durable = getattr(sink, "durable", None)
                if sink_durable is not True and sink_durable is not False:
                    raise RuntimeError("sink durable flag must be boolean")
                receipt = store(destination=destination, value=value, request_id=request_id)
                if not isinstance(receipt, HandoffReceipt):
                    raise RuntimeError("sink did not return structured receipt")
                if (
                    receipt.request_id != request_id
                    or receipt.destination_id != destination.destination_id
                    or receipt.destination_label != destination.label
                    or receipt.storage_confirmed is not True
                    or receipt.durable is not sink_durable
                ):
                    raise RuntimeError("sink did not confirm request-scoped storage")
                if sink_durable is True and receipt.durable is not True:
                    raise RuntimeError("durable sink returned non-durable receipt")
                storage_id = receipt.receipt_id
                storage_durable = 1 if receipt.durable is True else 0
            except Exception:  # noqa: BLE001 - sink failure is reported without credential detail
                conn.execute("ROLLBACK")
                return False, "sink failed", 502, None
            if not isinstance(storage_id, str) or not storage_id or len(storage_id) > 256 or any(ch in storage_id for ch in "\r\n\x00"):
                conn.execute("ROLLBACK")
                return False, "sink failed", 502, None
            updated = conn.execute(
                """
                UPDATE requests
                   SET used = 1,
                       used_at = ?,
                       encrypted_envelope_json = ?,
                       storage_id = ?,
                       storage_durable = ?,
                       private_key_ciphertext = NULL,
                       private_key_pem = '',
                       session_id = NULL,
                       csrf = NULL,
                       session_created_at = NULL
                 WHERE request_id = ? AND used = 0
                """,
                (ts, envelope_json, storage_id, storage_durable, request_id),
            ).rowcount
            conn.execute("COMMIT")
        if updated != 1:
            return False, "already used", 410, None
        return True, "ok", 200, storage_id

    def count_requests(self) -> int:
        with closing(self._connect()) as conn:
            return int(conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0])

    def receipt_metadata(self, request_id: str) -> dict[str, Any]:
        """Return sanitized local request/receipt metadata only; never return auth, private key, or envelope."""
        if not is_urlsafe_token(request_id, max_len=128):
            raise ValueError("invalid request id")
        with closing(self._connect()) as conn:
            row = conn.execute(
                """
                SELECT request_id, created_at, expires_at, used, used_at, destination_id, destination_label,
                       storage_id, storage_durable, lifecycle_scope, encrypted_envelope_json,
                       private_key_ciphertext, private_key_pem
                  FROM requests
                 WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
        if row is None:
            raise LookupError("request not found")
        protected_private_key = bool(row["private_key_ciphertext"]) or (bool(row["storage_id"]) and not row["private_key_pem"])
        if self.require_protected_keys and row["private_key_pem"]:
            raise KeyProtectorError("plaintext private key row refused in protected mode")
        envelope_json = row["encrypted_envelope_json"] or ""
        return {
            "request_id": row["request_id"],
            "created_at": int(row["created_at"]),
            "expires_at": int(row["expires_at"]),
            "expired": int(row["expires_at"]) <= now(),
            "used": bool(row["used"]),
            "used_at": int(row["used_at"]) if row["used_at"] is not None else None,
            "status": (
                "stored"
                if row["storage_id"] and int(row["storage_durable"] or 0) == 1
                else "ephemeral-demo"
                if row["storage_id"] and int(row["storage_durable"] or 0) == 0
                else ("expired" if int(row["expires_at"]) <= now() else "pending")
            ),
            "destination_id": row["destination_id"],
            "destination_label": row["destination_label"],
            "storage_id": row["storage_id"],
            "storage_durable": bool(row["storage_durable"]) if row["storage_durable"] is not None else None,
            "lifecycle_scope": row["lifecycle_scope"],
            "encrypted_envelope_recorded": bool(envelope_json),
            "encrypted_envelope_bytes": len(envelope_json.encode("utf-8")),
            "protected_private_key": protected_private_key,
        }

    def purge_expired_unused(self, *, lifecycle_scope: str, before: int | None = None) -> int:
        """Delete only expired, unused rows created for one explicit lifecycle scope.

        This intentionally does not touch legacy/prototype rows whose scope is NULL, rows
        from any other scope, or used rows retained as write receipts.
        """
        if not lifecycle_scope or len(lifecycle_scope) > 64 or any(ch in lifecycle_scope for ch in "\r\n\x00"):
            raise ValueError("invalid lifecycle scope")
        cutoff = now() if before is None else int(before)
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            deleted = conn.execute(
                """
                DELETE FROM requests
                 WHERE lifecycle_scope = ?
                   AND used = 0
                   AND expires_at <= ?
                   AND private_key_ciphertext IS NOT NULL
                   AND COALESCE(private_key_pem, '') = ''
                """,
                (lifecycle_scope, cutoff),
            ).rowcount
            conn.execute("COMMIT")
        return int(deleted)

    def _private_pem_for_row(self, row: sqlite3.Row) -> str:
        ciphertext = row["private_key_ciphertext"] if "private_key_ciphertext" in row.keys() else None
        if ciphertext:
            if self.key_protector is None:
                raise KeyProtectorError("protected private key requires key protector")
            return self.key_protector.unprotect_private_pem(ciphertext, request_id=row["request_id"])
        if self.require_protected_keys:
            raise KeyProtectorError("plaintext private key row refused in protected mode")
        private_pem = row["private_key_pem"]
        if not private_pem:
            raise KeyProtectorError("private key material unavailable")
        return private_pem

    def dump_text_for_tests(self) -> str:
        with closing(self._connect()) as conn:
            rows = conn.execute("SELECT * FROM requests").fetchall()
        return "\n".join("\t".join("" if v is None else str(v) for v in row) for row in rows)
