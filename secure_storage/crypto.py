"""Cryptography helpers for local-only encrypted credential handoff.

Uses browser-standard RSA-OAEP(SHA-256) wrapping of a random AES-256-GCM key.
No custom cryptographic primitive is implemented here.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = 1
MAX_VALUE_BYTES = 4096


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str, *, max_len: int = 65536) -> bytes:
    if not isinstance(value, str) or len(value) > max_len:
        raise ValueError("invalid base64url")
    if any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in value):
        raise ValueError("invalid base64url")
    padding_len = (-len(value)) % 4
    try:
        return base64.urlsafe_b64decode((value + ("=" * padding_len)).encode("ascii"))
    except Exception as exc:  # noqa: BLE001 - normalize parse failures
        raise ValueError("invalid base64url") from exc


def aad_for_request(request_id: str, version: int = VERSION) -> bytes:
    return f"secure-handoff:v{version}:{request_id}".encode("utf-8")


@dataclass(frozen=True)
class KeyPair:
    private_pem: str
    public_jwk: dict[str, str]


def generate_key_pair() -> KeyPair:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    numbers = private_key.public_key().public_numbers()
    public_jwk = {
        "kty": "RSA",
        "alg": "RSA-OAEP-256",
        "key_ops": ["encrypt"],
        "ext": True,
        "n": b64url_encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": b64url_encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }
    return KeyPair(private_pem=private_pem, public_jwk=public_jwk)


def canonical_envelope_json(envelope: dict[str, Any]) -> str:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def decrypt_envelope(envelope: dict[str, Any], *, request_id: str, private_pem: str) -> str:
    if not isinstance(envelope, dict):
        raise ValueError("malformed envelope")
    if set(envelope) != {"version", "request_id", "wrapped_key", "iv", "ciphertext"}:
        raise ValueError("malformed envelope")
    if envelope.get("version") != VERSION or envelope.get("request_id") != request_id:
        raise ValueError("wrong request context")
    wrapped_key = b64url_decode(envelope.get("wrapped_key", ""), max_len=4096)
    iv = b64url_decode(envelope.get("iv", ""), max_len=64)
    ciphertext = b64url_decode(envelope.get("ciphertext", ""), max_len=65536)
    if len(iv) != 12:
        raise ValueError("malformed envelope")
    private_key = serialization.load_pem_private_key(private_pem.encode("ascii"), password=None)
    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    if len(aes_key) != 32:
        raise ValueError("malformed envelope")
    plaintext = AESGCM(aes_key).decrypt(iv, ciphertext, aad_for_request(request_id, VERSION))
    if len(plaintext) > MAX_VALUE_BYTES:
        raise ValueError("value too large")
    return plaintext.decode("utf-8")
