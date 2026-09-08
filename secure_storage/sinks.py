"""Provider-neutral handoff sink contract and demo adapter.

A public Hermes Handoff core must not choose a destination from browser input and must not
claim storage until the configured sink acknowledges the exact request-scoped write.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class HandoffDestination:
    """Fixed local destination bound when the operator creates a request."""

    destination_id: str
    label: str


@dataclass(frozen=True)
class HandoffReceipt:
    """Sanitized sink acknowledgement stored as the local receipt."""

    request_id: str
    destination_id: str
    destination_label: str
    receipt_id: str
    storage_confirmed: bool
    durable: bool


class DurableSink(Protocol):
    """Pluggable sink contract for real adapters.

    Implementations must be explicitly configured by the operator, must treat request_id as
    an idempotency key, and must return only after the destination has acknowledged durable
    storage of the exact value. They must not log or return plaintext values.
    """

    durable: bool

    def store(self, *, destination: HandoffDestination, value: str, request_id: str) -> HandoffReceipt:
        ...


class EphemeralDemoSink:
    """In-memory demo sink. It is deliberately not durable storage."""

    durable = False

    def __init__(self) -> None:
        self.records: list[dict[str, str]] = []

    def store(self, *, destination: HandoffDestination, value: str, request_id: str) -> HandoffReceipt:
        value_digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        existing = next((r for r in self.records if r["request_id"] == request_id), None)
        if existing is None:
            receipt_id = "ephemeral-demo:" + secrets.token_urlsafe(12)
            self.records.append({
                "request_id": request_id,
                "destination_id": destination.destination_id,
                "destination_label": destination.label,
                "receipt_id": receipt_id,
                "value_sha256": value_digest,
            })
        else:
            receipt_id = existing["receipt_id"]
        return HandoffReceipt(
            request_id=request_id,
            destination_id=destination.destination_id,
            destination_label=destination.label,
            receipt_id=receipt_id,
            storage_confirmed=True,
            durable=False,
        )


class NoConfiguredSink:
    durable = False

    def store(self, *, destination: HandoffDestination, value: str, request_id: str) -> HandoffReceipt:
        raise RuntimeError("no configured durable sink")


def validate_destination_id(value: str) -> str:
    if not value or len(value) > 128 or value.strip() != value or any(ch in value for ch in "\r\n\x00"):
        raise ValueError("invalid destination id")
    return value


def validate_destination_label(value: str) -> str:
    if not value or len(value) > 128 or any(ch in value for ch in "\r\n\x00"):
        raise ValueError("invalid destination label")
    return value
