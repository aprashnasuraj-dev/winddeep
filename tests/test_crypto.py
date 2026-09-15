"""Tests for Windeep AES-GCM envelope encryption."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from app.security.crypto import CryptoManager, FileProtector


def _manager(tmp_path) -> CryptoManager:
    protector = FileProtector(tmp_path / "master.key")
    return CryptoManager(wrapped_key_path=tmp_path / "dek.bin", protector=protector)


def test_text_round_trip(tmp_path) -> None:
    crypto = _manager(tmp_path)
    encrypted = crypto.encrypt_text("secret", aad=b"field")
    assert encrypted.startswith("enc:v1:")
    assert crypto.decrypt_text(encrypted, aad=b"field") == "secret"


def test_ciphertext_is_nondeterministic(tmp_path) -> None:
    crypto = _manager(tmp_path)
    first = crypto.encrypt_text("same", aad=b"field")
    second = crypto.encrypt_text("same", aad=b"field")
    assert first != second


def test_aad_mismatch_fails(tmp_path) -> None:
    crypto = _manager(tmp_path)
    encrypted = crypto.encrypt_text("secret", aad=b"one")
    with pytest.raises(InvalidTag):
        crypto.decrypt_text(encrypted, aad=b"two")


def test_dek_persists_through_wrapped_key(tmp_path) -> None:
    protector = FileProtector(tmp_path / "master.key")
    first = CryptoManager(wrapped_key_path=tmp_path / "dek.bin", protector=protector)
    encrypted = first.encrypt_text("persistent", aad=b"x")
    second = CryptoManager(wrapped_key_path=tmp_path / "dek.bin", protector=protector)
    assert second.decrypt_text(encrypted, aad=b"x") == "persistent"


def test_plain_legacy_text_is_returned_unchanged(tmp_path) -> None:
    crypto = _manager(tmp_path)
    assert crypto.decrypt_text("legacy plaintext") == "legacy plaintext"
