"""Signed authorization-consent records for Windeep scans."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from app.security.crypto import SecretProtector, default_secret_protector
from app.security.scope import ScopeEnforcer


class ConsentError(PermissionError):
    """Raised when an authorization record is missing, invalid, or expired."""


@dataclass(frozen=True, slots=True)
class ConsentRecord:
    """Immutable signed authorization for one explicit testing scope."""

    id: str
    authorized_by: str
    purpose: str
    scope_sha256: str
    issued_at: float
    expires_at: float
    nonce: str
    signature: str

    @property
    def active(self) -> bool:
        """Return whether the consent has not expired."""
        return time.time() < self.expires_at


class ConsentAuthority:
    """Create and verify Ed25519-signed local consent records."""

    def __init__(self, directory: str | Path = "state/consent", *, protector: SecretProtector | None = None) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.protector = protector or default_secret_protector()
        self._private_key = self._load_or_create_key()
        self._public_key = self._private_key.public_key()

    @property
    def _key_path(self) -> Path:
        return self.directory / "signing-key.bin"

    def _load_or_create_key(self) -> Ed25519PrivateKey:
        if self._key_path.exists():
            raw = self.protector.unprotect(self._key_path.read_bytes())
            return Ed25519PrivateKey.from_private_bytes(raw)
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        self._key_path.write_bytes(self.protector.protect(raw))
        return key

    @staticmethod
    def _scope_hash(scope: ScopeEnforcer) -> str:
        return hashlib.sha256(scope.fingerprint_material().encode("utf-8")).hexdigest()

    @staticmethod
    def _canonical(payload: Mapping[str, Any]) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def public_key_b64(self) -> str:
        """Return the Ed25519 public key in base64 for audit/export purposes."""
        raw = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def issue(self, scope: ScopeEnforcer, *, authorized_by: str, purpose: str, ttl_seconds: int = 8 * 60 * 60) -> ConsentRecord:
        """Create and persist a time-bounded signed consent record."""
        if not authorized_by.strip():
            raise ValueError("authorized_by must not be empty")
        if not purpose.strip():
            raise ValueError("purpose must not be empty")
        if ttl_seconds < 60 or ttl_seconds > 30 * 24 * 60 * 60:
            raise ValueError("ttl_seconds must be between 60 seconds and 30 days")
        now = time.time()
        unsigned = {
            "id": str(uuid.uuid4()),
            "authorized_by": authorized_by.strip(),
            "purpose": purpose.strip(),
            "scope_sha256": self._scope_hash(scope),
            "issued_at": now,
            "expires_at": now + ttl_seconds,
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii"),
        }
        signature = self._private_key.sign(self._canonical(unsigned))
        record = ConsentRecord(**unsigned, signature=base64.b64encode(signature).decode("ascii"))
        self._record_path(record.id).write_text(json.dumps(asdict(record), indent=2, sort_keys=True), encoding="utf-8")
        return record

    def _record_path(self, consent_id: str) -> Path:
        safe = consent_id.replace("/", "").replace("\\", "")
        return self.directory / f"{safe}.json"

    def load(self, consent_id: str) -> ConsentRecord:
        """Load a consent record by id."""
        path = self._record_path(consent_id)
        if not path.exists():
            raise ConsentError("authorization consent was not found")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return ConsentRecord(**payload)
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            raise ConsentError("authorization consent is malformed") from exc

    def verify(self, consent_id: str, scope: ScopeEnforcer) -> ConsentRecord:
        """Verify signature, expiry, time sanity, and exact scope binding."""
        record = self.load(consent_id)
        unsigned = asdict(record)
        signature_b64 = str(unsigned.pop("signature"))
        try:
            signature = base64.b64decode(signature_b64, validate=True)
            self._public_key.verify(signature, self._canonical(unsigned))
        except Exception as exc:
            raise ConsentError("authorization signature verification failed") from exc
        now = time.time()
        if record.issued_at > now + 300:
            raise ConsentError("authorization issue time is in the future")
        if record.expires_at <= now:
            raise ConsentError("authorization consent has expired")
        if record.scope_sha256 != self._scope_hash(scope):
            raise ConsentError("authorization scope does not match the requested scan")
        return record

    def healthcheck(self) -> dict[str, object]:
        """Return signing-key health without issuing consent."""
        raw = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {"ok": len(raw) == 32, "algorithm": "Ed25519", "public_key": self.public_key_b64()}
