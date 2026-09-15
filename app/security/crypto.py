"""Windows DPAPI-backed envelope encryption for sensitive Windeep data."""

from __future__ import annotations

import base64
import ctypes
import os
import stat
from ctypes import wintypes
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretProtectionError(RuntimeError):
    """Raised when operating-system secret protection fails."""


class SecretProtector(Protocol):
    """Interface for wrapping small local secrets such as encryption keys."""

    def protect(self, plaintext: bytes) -> bytes:
        """Protect plaintext for the current local user."""

    def unprotect(self, protected: bytes) -> bytes:
        """Recover plaintext protected for the current local user."""


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _blob(data: bytes) -> tuple[_DATA_BLOB, ctypes.Array[ctypes.c_char]]:
    buffer = ctypes.create_string_buffer(data)
    return _DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


class DPAPIProtector:
    """Protect secrets with Windows CryptProtectData for the current user."""

    _CRYPTPROTECT_UI_FORBIDDEN = 0x1

    def __init__(self, entropy: bytes = b"windeep:v1") -> None:
        if os.name != "nt":
            raise OSError("DPAPI is only available on Windows")
        self._crypt32 = ctypes.windll.crypt32
        self._kernel32 = ctypes.windll.kernel32
        self._entropy = entropy

    def protect(self, plaintext: bytes) -> bytes:
        """Protect plaintext with DPAPI."""
        if not plaintext:
            raise ValueError("plaintext must not be empty")
        in_blob, in_buffer = _blob(plaintext)
        entropy_blob, entropy_buffer = _blob(self._entropy)
        out_blob = _DATA_BLOB()
        result = self._crypt32.CryptProtectData(
            ctypes.byref(in_blob), "Windeep local secret", ctypes.byref(entropy_blob),
            None, None, self._CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_blob),
        )
        _ = in_buffer, entropy_buffer
        if not result:
            raise SecretProtectionError(f"CryptProtectData failed: {ctypes.GetLastError()}")
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            self._kernel32.LocalFree(out_blob.pbData)

    def unprotect(self, protected: bytes) -> bytes:
        """Unprotect DPAPI ciphertext."""
        if not protected:
            raise ValueError("protected value must not be empty")
        in_blob, in_buffer = _blob(protected)
        entropy_blob, entropy_buffer = _blob(self._entropy)
        out_blob = _DATA_BLOB()
        result = self._crypt32.CryptUnprotectData(
            ctypes.byref(in_blob), None, ctypes.byref(entropy_blob),
            None, None, self._CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_blob),
        )
        _ = in_buffer, entropy_buffer
        if not result:
            raise SecretProtectionError(f"CryptUnprotectData failed: {ctypes.GetLastError()}")
        try:
            return ctypes.string_at(out_blob.pbData, out_blob.cbData)
        finally:
            self._kernel32.LocalFree(out_blob.pbData)


class FileProtector:
    """Portable test/development protector using a locally generated AES key.

    Production Windows builds use :class:`DPAPIProtector`. This fallback exists
    so the same code can be exercised on Linux/macOS CI runners when needed.
    """

    def __init__(self, key_path: str | Path = "state/crypto/portable-master.key") -> None:
        self.path = Path(key_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self._key = self.path.read_bytes()
        else:
            self._key = AESGCM.generate_key(bit_length=256)
            self.path.write_bytes(self._key)
            try:
                self.path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        if len(self._key) != 32:
            raise SecretProtectionError("portable master key must be 32 bytes")

    def protect(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext with the local fallback key."""
        nonce = os.urandom(12)
        return nonce + AESGCM(self._key).encrypt(nonce, plaintext, b"windeep:file-protector:v1")

    def unprotect(self, protected: bytes) -> bytes:
        """Decrypt fallback-protected bytes."""
        if len(protected) < 13:
            raise SecretProtectionError("protected value is too short")
        nonce, ciphertext = protected[:12], protected[12:]
        return AESGCM(self._key).decrypt(nonce, ciphertext, b"windeep:file-protector:v1")


def default_secret_protector() -> SecretProtector:
    """Return DPAPI on Windows and a local file protector elsewhere."""
    if os.name == "nt":
        return DPAPIProtector()
    return FileProtector()


class CryptoManager:
    """AES-256-GCM envelope encryption with a protected local data-encryption key."""

    PREFIX = "enc:v1:"

    def __init__(
        self,
        *,
        wrapped_key_path: str | Path = "state/crypto/dek.bin",
        protector: SecretProtector | None = None,
    ) -> None:
        self.path = Path(wrapped_key_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.protector = protector or default_secret_protector()
        self._dek = self._load_or_create_dek()
        self._aes = AESGCM(self._dek)

    def _load_or_create_dek(self) -> bytes:
        if self.path.exists():
            wrapped = self.path.read_bytes()
            dek = self.protector.unprotect(wrapped)
        else:
            dek = AESGCM.generate_key(bit_length=256)
            self.path.write_bytes(self.protector.protect(dek))
        if len(dek) != 32:
            raise SecretProtectionError("data-encryption key must be 32 bytes")
        return dek

    def encrypt_bytes(self, plaintext: bytes, *, aad: bytes = b"") -> bytes:
        """Encrypt bytes with a fresh 96-bit nonce."""
        nonce = os.urandom(12)
        return nonce + self._aes.encrypt(nonce, plaintext, aad)

    def decrypt_bytes(self, ciphertext: bytes, *, aad: bytes = b"") -> bytes:
        """Decrypt bytes produced by :meth:`encrypt_bytes`."""
        if len(ciphertext) < 13:
            raise ValueError("ciphertext is too short")
        nonce, payload = ciphertext[:12], ciphertext[12:]
        return self._aes.decrypt(nonce, payload, aad)

    def encrypt_text(self, plaintext: str, *, aad: bytes = b"") -> str:
        """Encrypt text into a versioned ASCII-safe representation."""
        raw = self.encrypt_bytes(plaintext.encode("utf-8"), aad=aad)
        return self.PREFIX + base64.urlsafe_b64encode(raw).decode("ascii")

    def decrypt_text(self, value: str, *, aad: bytes = b"") -> str:
        """Decrypt a versioned string; return plaintext legacy values unchanged."""
        if not value.startswith(self.PREFIX):
            return value
        raw = base64.urlsafe_b64decode(value[len(self.PREFIX) :].encode("ascii"))
        return self.decrypt_bytes(raw, aad=aad).decode("utf-8")

    def healthcheck(self) -> dict[str, object]:
        """Verify encryption/decryption round-trip without exposing key material."""
        marker = b"windeep-health"
        encrypted = self.encrypt_bytes(marker, aad=b"health")
        ok = self.decrypt_bytes(encrypted, aad=b"health") == marker
        return {"ok": ok, "provider": type(self.protector).__name__, "dek_bits": 256}
