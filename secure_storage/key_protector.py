"""Private-key wrapping for Mac-hosted handoff state.

Production wrapping keys are looked up from macOS Keychain through the native
Security.framework API and are never accepted on argv, printed, logged, or exposed
through exception text. Tests inject in-memory or mocked Keychain backends instead.
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.util
import os
import threading
from dataclasses import dataclass, field
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import b64url_decode, b64url_encode

PROTECTOR_VERSION = 1
DEFAULT_KEYCHAIN_SERVICE = "Hermes Handoff Wrapping Key"
DEFAULT_KEYCHAIN_ACCOUNT = "secure-storage-production-v1"
WRAPPING_KEY_B64URL_LENGTH = 43
_KEYCHAIN_USER_INTERACTION_LOCK = threading.RLock()


class KeyProtectorError(RuntimeError):
    """Sanitized protector error; never include key material or plaintext PEM."""


class KeyProtector(Protocol):
    protector_id: str

    def protect_private_pem(self, private_pem: str, *, request_id: str) -> str: ...

    def unprotect_private_pem(self, ciphertext: str, *, request_id: str) -> str: ...


def private_pem_aad(request_id: str, version: int = PROTECTOR_VERSION) -> bytes:
    return f"secure-handoff-private-pem:v{version}:{request_id}".encode("utf-8")


def _validate_wrapping_key(key: bytes) -> bytes:
    if len(key) != 32:
        raise KeyProtectorError("wrapping key must be exactly 32 bytes")
    return key


def encode_wrapping_key_b64url(key: bytes) -> str:
    """Encode one documented production key format: 32 random bytes as unpadded base64url."""
    _validate_wrapping_key(bytes(key))
    return base64.urlsafe_b64encode(bytes(key)).rstrip(b"=").decode("ascii")


def decode_wrapping_key_b64url(value: str) -> bytes:
    """Decode the only accepted production Keychain item value format.

    The stored Keychain password must be exactly 43 ASCII base64url characters with no
    padding, decoding to exactly 32 bytes. Hex, padded base64, and AES-128/192 keys are
    intentionally rejected to keep provisioning unambiguous.
    """
    if not isinstance(value, str) or len(value) != WRAPPING_KEY_B64URL_LENGTH or "=" in value:
        raise KeyProtectorError("macOS Keychain wrapping key is malformed")
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii") + b"=")
    except Exception as exc:  # noqa: BLE001 - sanitize parse detail
        raise KeyProtectorError("macOS Keychain wrapping key is malformed") from None
    return _validate_wrapping_key(raw)


@dataclass(frozen=True, repr=False)
class AESGCMKeyProtector:
    """AES-GCM private PEM protector with request-id-bound AAD."""

    wrapping_key: bytes = field(repr=False)
    protector_id: str = "test-memory-aesgcm-v1"

    def __post_init__(self) -> None:
        _validate_wrapping_key(bytes(self.wrapping_key))

    def __repr__(self) -> str:
        return f"AESGCMKeyProtector(protector_id={self.protector_id!r})"

    def protect_private_pem(self, private_pem: str, *, request_id: str) -> str:
        if "PRIVATE KEY" not in private_pem:
            raise KeyProtectorError("invalid private key material")
        try:
            nonce = os.urandom(12)
            ciphertext = AESGCM(bytes(self.wrapping_key)).encrypt(
                nonce,
                private_pem.encode("ascii"),
                private_pem_aad(request_id),
            )
        except Exception as exc:  # noqa: BLE001 - sanitize crypto failure
            raise KeyProtectorError("private key protection failed") from None
        return ".".join(("aesgcm", str(PROTECTOR_VERSION), b64url_encode(nonce), b64url_encode(ciphertext)))

    def unprotect_private_pem(self, ciphertext: str, *, request_id: str) -> str:
        try:
            alg, version_text, nonce_text, ciphertext_text = ciphertext.split(".", 3)
            if alg != "aesgcm" or int(version_text) != PROTECTOR_VERSION:
                raise ValueError("unsupported private key ciphertext")
            nonce = b64url_decode(nonce_text, max_len=64)
            encrypted = b64url_decode(ciphertext_text, max_len=65536)
            if len(nonce) != 12:
                raise ValueError("bad nonce")
            private_pem = AESGCM(bytes(self.wrapping_key)).decrypt(
                nonce,
                encrypted,
                private_pem_aad(request_id),
            ).decode("ascii")
            if "PRIVATE KEY" not in private_pem:
                raise ValueError("bad private key plaintext")
            return private_pem
        except Exception as exc:  # noqa: BLE001 - fail closed without leaking details
            raise KeyProtectorError("private key unprotection failed") from None


class MissingKeychainSecretError(KeyProtectorError):
    """Keychain item missing, locked, inaccessible, malformed, or unavailable."""


class KeychainBackend(Protocol):
    def find_generic_password_no_ui(self, *, service: str, account: str, keychain: str | None = None) -> bytes: ...

    def add_generic_password_create_only(self, *, service: str, account: str, password: bytes, keychain: str | None = None) -> None: ...


class NativeMacOSKeychainBackend:
    """Native macOS Keychain backend using documented Security.framework calls.

    Function shapes are from Apple Security.framework documentation:
    - SecKeychainFindGenericPassword(CFTypeRef, UInt32, const char*, UInt32, const char*, UInt32*, void**, SecKeychainItemRef*)
    - SecKeychainItemFreeContent(SecKeychainAttributeList*, void*)
    - SecKeychainSetUserInteractionAllowed(Boolean)
    - SecKeychainAddGenericPassword(SecKeychainRef, UInt32, const char*, UInt32, const char*, UInt32, const void*, SecKeychainItemRef*)
    - SecKeychainOpen(const char*, SecKeychainRef*) for optional explicit keychain-db paths
    """

    _ERR_SEC_DUPLICATE_ITEM = -25299

    def __init__(self) -> None:
        if os.name != "posix" or not hasattr(ctypes, "CDLL"):
            raise MissingKeychainSecretError("macOS Keychain wrapping key unavailable")
        security_path = ctypes.util.find_library("Security")
        core_foundation_path = ctypes.util.find_library("CoreFoundation")
        if not security_path or not core_foundation_path:
            raise MissingKeychainSecretError("macOS Keychain wrapping key unavailable")
        try:
            self._security = ctypes.CDLL(security_path)
            self._core_foundation = ctypes.CDLL(core_foundation_path)
        except Exception as exc:  # noqa: BLE001
            raise MissingKeychainSecretError("macOS Keychain wrapping key unavailable") from None
        self._bind_signatures()

    def _bind_signatures(self) -> None:
        sec = self._security
        sec.SecKeychainFindGenericPassword.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        sec.SecKeychainFindGenericPassword.restype = ctypes.c_int32
        sec.SecKeychainItemFreeContent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        sec.SecKeychainItemFreeContent.restype = ctypes.c_int32
        sec.SecKeychainSetUserInteractionAllowed.argtypes = [ctypes.c_ubyte]
        sec.SecKeychainSetUserInteractionAllowed.restype = ctypes.c_int32
        sec.SecKeychainGetUserInteractionAllowed.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
        sec.SecKeychainGetUserInteractionAllowed.restype = ctypes.c_int32
        sec.SecKeychainAddGenericPassword.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        sec.SecKeychainAddGenericPassword.restype = ctypes.c_int32
        sec.SecKeychainOpen.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        sec.SecKeychainOpen.restype = ctypes.c_int32
        self._core_foundation.CFRelease.argtypes = [ctypes.c_void_p]
        self._core_foundation.CFRelease.restype = None

    def _encoded(self, value: str) -> bytes:
        try:
            return value.encode("utf-8")
        except UnicodeEncodeError:
            raise MissingKeychainSecretError("macOS Keychain wrapping key unavailable") from None

    def _keychain_ref(self, keychain: str | None) -> ctypes.c_void_p:
        if not keychain:
            return ctypes.c_void_p()
        ref = ctypes.c_void_p()
        status = self._security.SecKeychainOpen(self._encoded(keychain), ctypes.byref(ref))
        if status != 0 or not ref.value:
            raise MissingKeychainSecretError("macOS Keychain wrapping key unavailable")
        return ref

    def _set_user_interaction(self, allowed: bool) -> None:
        status = self._security.SecKeychainSetUserInteractionAllowed(1 if allowed else 0)
        if status != 0:
            raise MissingKeychainSecretError("macOS Keychain wrapping key unavailable")

    def find_generic_password_no_ui(self, *, service: str, account: str, keychain: str | None = None) -> bytes:
        service_b = self._encoded(service)
        account_b = self._encoded(account)
        password_len = ctypes.c_uint32(0)
        password_data = ctypes.c_void_p()
        item_ref = ctypes.c_void_p()
        keychain_ref = ctypes.c_void_p()
        previous_allowed = ctypes.c_ubyte(1)
        restore_previous = False
        with _KEYCHAIN_USER_INTERACTION_LOCK:
            restore_previous = self._security.SecKeychainGetUserInteractionAllowed(ctypes.byref(previous_allowed)) == 0
            try:
                keychain_ref = self._keychain_ref(keychain)
                self._set_user_interaction(False)
                status = self._security.SecKeychainFindGenericPassword(
                    keychain_ref,
                    len(service_b),
                    service_b,
                    len(account_b),
                    account_b,
                    ctypes.byref(password_len),
                    ctypes.byref(password_data),
                    ctypes.byref(item_ref),
                )
                if status != 0 or not password_data.value or password_len.value == 0:
                    raise MissingKeychainSecretError("macOS Keychain wrapping key unavailable")
                return ctypes.string_at(password_data, password_len.value)
            except KeyProtectorError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise MissingKeychainSecretError("macOS Keychain wrapping key unavailable") from None
            finally:
                if password_data.value:
                    self._security.SecKeychainItemFreeContent(None, password_data)
                if item_ref.value:
                    self._core_foundation.CFRelease(item_ref)
                if keychain_ref.value:
                    self._core_foundation.CFRelease(keychain_ref)
                if restore_previous:
                    self._security.SecKeychainSetUserInteractionAllowed(previous_allowed.value)

    def add_generic_password_create_only(self, *, service: str, account: str, password: bytes, keychain: str | None = None) -> None:
        service_b = self._encoded(service)
        account_b = self._encoded(account)
        password_b = bytes(password)
        item_ref = ctypes.c_void_p()
        keychain_ref = ctypes.c_void_p()
        try:
            keychain_ref = self._keychain_ref(keychain)
            password_buf = ctypes.create_string_buffer(password_b)
            status = self._security.SecKeychainAddGenericPassword(
                keychain_ref,
                len(service_b),
                service_b,
                len(account_b),
                account_b,
                len(password_b),
                ctypes.cast(password_buf, ctypes.c_void_p),
                ctypes.byref(item_ref),
            )
            if status == self._ERR_SEC_DUPLICATE_ITEM:
                raise KeyProtectorError("macOS Keychain wrapping key already exists")
            if status != 0:
                raise KeyProtectorError("macOS Keychain wrapping key provisioning failed")
        except KeyProtectorError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise KeyProtectorError("macOS Keychain wrapping key provisioning failed") from None
        finally:
            if item_ref.value:
                self._core_foundation.CFRelease(item_ref)
            if keychain_ref.value:
                self._core_foundation.CFRelease(keychain_ref)


@dataclass(frozen=True, repr=False)
class MacOSKeychainAESGCMKeyProtector:
    """AES-GCM protector whose wrapping key is fetched from macOS Keychain on demand.

    The Keychain item password must be exactly 43 unpadded base64url characters encoding
    32 random bytes. Lookup uses Security.framework in no-user-interaction mode; locked,
    missing, inaccessible, denied, empty, or malformed items fail closed with sanitized errors.
    """

    service: str = DEFAULT_KEYCHAIN_SERVICE
    account: str = DEFAULT_KEYCHAIN_ACCOUNT
    keychain: str | None = None
    backend: KeychainBackend | None = field(default=None, repr=False)
    protector_id: str = "macos-keychain-aesgcm-v1"

    def __repr__(self) -> str:
        return (
            "MacOSKeychainAESGCMKeyProtector("
            f"service={self.service!r}, account={self.account!r}, keychain={'set' if self.keychain else 'default'})"
        )

    def _backend(self) -> KeychainBackend:
        return self.backend if self.backend is not None else NativeMacOSKeychainBackend()

    def _load_wrapping_key(self) -> bytes:
        try:
            secret = self._backend().find_generic_password_no_ui(
                service=self.service,
                account=self.account,
                keychain=self.keychain,
            )
        except Exception as exc:  # noqa: BLE001 - backend details may contain secrets or OS paths
            raise MissingKeychainSecretError("macOS Keychain wrapping key unavailable") from None
        if not secret:
            raise MissingKeychainSecretError("macOS Keychain wrapping key unavailable")
        try:
            return decode_wrapping_key_b64url(secret.decode("ascii"))
        except KeyProtectorError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise MissingKeychainSecretError("macOS Keychain wrapping key unavailable") from None

    def _delegate(self) -> AESGCMKeyProtector:
        return AESGCMKeyProtector(self._load_wrapping_key(), protector_id=self.protector_id)

    def assert_available(self) -> None:
        self._load_wrapping_key()

    def protect_private_pem(self, private_pem: str, *, request_id: str) -> str:
        return self._delegate().protect_private_pem(private_pem, request_id=request_id)

    def unprotect_private_pem(self, ciphertext: str, *, request_id: str) -> str:
        return self._delegate().unprotect_private_pem(ciphertext, request_id=request_id)


def provision_wrapping_key_create_only(
    *,
    service: str = DEFAULT_KEYCHAIN_SERVICE,
    account: str = DEFAULT_KEYCHAIN_ACCOUNT,
    keychain: str | None = None,
    backend: KeychainBackend | None = None,
) -> str:
    """Create, but never overwrite, a production wrapping-key Keychain item.

    Returns the documented encoded value only for a foreground operator to paste into a
    local Keychain prompt or inspect in a one-shot provisioning session. Tests may mock the
    backend; production callers must not log this return value. This helper is not invoked by
    request creation or tests against the real Keychain.
    """
    key = os.urandom(32)
    encoded = encode_wrapping_key_b64url(key)
    (backend if backend is not None else NativeMacOSKeychainBackend()).add_generic_password_create_only(
        service=service,
        account=account,
        keychain=keychain,
        password=encoded.encode("ascii"),
    )
    return encoded
