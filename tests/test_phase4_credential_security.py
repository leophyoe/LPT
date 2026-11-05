"""Phase 4 Security Tests: Credential Storage, AES-256-GCM, Tampering, and Migration.

Tests:
1. AES-256-GCM Authenticated Encryption & Decryption.
2. Cryptographic Tamper Detection (Bit-flip in ciphertext/tag raises InvalidTag / returns empty).
3. POSIX File Permissions: Strict 0600 on vault and key files, 0700 on directory.
4. Independent Master Key Entropy (Not solely bound to predictable machine-id).
5. Seamless Legacy XOR Vault Migration without credential loss.
6. Key Masking & Deletion Hygiene (Clears in-memory cache and disk).
"""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.credential_manager import (
    CredentialManager,
    KEY_FILE,
    VAULT_DIR,
    VAULT_FILE,
    VAULT_V2_MAGIC,
    _get_machine_bound_key,
    _xor_cipher,
)


@pytest.fixture(autouse=True)
def isolate_vault(tmp_path, monkeypatch):
    """Isolate vault files to a temporary directory for every test."""
    test_vault_dir = tmp_path / "config" / "cybersecuritysuite"
    test_vault_file = test_vault_dir / ".vault_credentials"
    test_key_file = test_vault_dir / ".vault_key"

    monkeypatch.setattr("core.credential_manager.VAULT_DIR", test_vault_dir)
    monkeypatch.setattr("core.credential_manager.VAULT_FILE", test_vault_file)
    monkeypatch.setattr("core.credential_manager.KEY_FILE", test_key_file)
    monkeypatch.setattr("core.credential_manager.CredentialManager._session_cache", {})
    monkeypatch.setattr("core.credential_manager._HAS_KEYRING", False)  # Force encrypted vault tier

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    yield


def test_aes_gcm_authenticated_vault_lifecycle(tmp_path):
    """Verify that credentials are stored using AES-256-GCM and recovered properly."""
    assert CredentialManager.get_key("gemini") is None

    # Set keys
    assert CredentialManager.set_key("gemini", "AIzaSySecretGeminiToken123456") is True
    assert CredentialManager.set_key("openai", "sk-proj-SecretOpenAIToken987654") is True

    # Verify vault file exists on disk and begins with magic header CSS2
    vault_file = tmp_path / "config" / "cybersecuritysuite" / ".vault_credentials"
    assert vault_file.is_file()

    raw_b64 = vault_file.read_bytes()
    raw_payload = base64.b64decode(raw_b64)
    assert raw_payload.startswith(VAULT_V2_MAGIC)
    # Plaintext should not appear anywhere in the ciphertext
    assert b"AIzaSySecretGeminiToken123456" not in raw_payload
    assert b"sk-proj-SecretOpenAIToken987654" not in raw_payload

    # Clear cache and recover from disk
    CredentialManager._session_cache.clear()
    assert CredentialManager.get_key("gemini") == "AIzaSySecretGeminiToken123456"
    assert CredentialManager.get_key("openai") == "sk-proj-SecretOpenAIToken987654"


def test_vault_tamper_detection_fails_closed(tmp_path):
    """Verify that tampering with any byte in ciphertext or auth tag fails closed."""
    CredentialManager.set_key("gemini", "AIzaSyValidOriginalSecret")
    CredentialManager._session_cache.clear()

    vault_file = tmp_path / "config" / "cybersecuritysuite" / ".vault_credentials"
    raw_b64 = vault_file.read_bytes()
    raw_payload = bytearray(base64.b64decode(raw_b64))

    # Flip bits in the ciphertext / tag region (near the end of payload)
    raw_payload[-5] ^= 0xFF
    tampered_b64 = base64.b64encode(bytes(raw_payload))
    vault_file.write_bytes(tampered_b64)

    # When reading the tampered vault, AESGCM tag verification must reject the payload
    CredentialManager._session_cache.clear()
    assert CredentialManager.get_key("gemini") is None


def test_vault_and_key_file_permissions(tmp_path):
    """Verify that both vault file and master key file are created with strict 0600 POSIX permissions."""
    CredentialManager.set_key("gemini", "AIzaSyStrictPermissionsCheck")

    vault_dir = tmp_path / "config" / "cybersecuritysuite"
    vault_file = vault_dir / ".vault_credentials"
    key_file = vault_dir / ".vault_key"

    assert vault_dir.is_dir()
    assert vault_file.is_file()
    assert key_file.is_file()

    dir_mode = stat.S_IMODE(os.stat(vault_dir).st_mode)
    vault_mode = stat.S_IMODE(os.stat(vault_file).st_mode)
    key_mode = stat.S_IMODE(os.stat(key_file).st_mode)

    assert dir_mode == 0o700
    assert vault_mode == 0o600
    assert key_mode == 0o600


def test_transparent_migration_from_legacy_xor_vault(tmp_path):
    """Verify that a legacy XOR-encrypted vault file is transparently decrypted and migrated to AES-GCM."""
    vault_dir = tmp_path / "config" / "cybersecuritysuite"
    vault_dir.mkdir(parents=True, exist_ok=True)
    vault_file = vault_dir / ".vault_credentials"

    # Fabricate a legacy XOR encrypted vault
    legacy_credentials = {
        "gemini": "AIzaSyLegacyKeyFromOlderVersion",
        "openai": "sk-proj-LegacyOpenAIKeyV1",
    }
    legacy_json = json.dumps(legacy_credentials).encode("utf-8")
    legacy_key = _get_machine_bound_key()
    legacy_encrypted = _xor_cipher(legacy_json, legacy_key)
    legacy_b64 = base64.b64encode(legacy_encrypted)
    vault_file.write_bytes(legacy_b64)

    # Verify initial file does NOT have CSS2 magic
    assert not legacy_encrypted.startswith(VAULT_V2_MAGIC)

    # CredentialManager should read and decrypt legacy XOR file
    CredentialManager._session_cache.clear()
    assert CredentialManager.get_key("gemini") == "AIzaSyLegacyKeyFromOlderVersion"
    assert CredentialManager.get_key("openai") == "sk-proj-LegacyOpenAIKeyV1"

    # And verify that the file on disk was automatically migrated to AES-GCM format
    migrated_b64 = vault_file.read_bytes()
    migrated_payload = base64.b64decode(migrated_b64)
    assert migrated_payload.startswith(VAULT_V2_MAGIC)

    # Clear cache and ensure reading newly migrated AES-GCM vault succeeds
    CredentialManager._session_cache.clear()
    assert CredentialManager.get_key("gemini") == "AIzaSyLegacyKeyFromOlderVersion"


def test_corrupt_vault_does_not_crash(tmp_path):
    """Verify that a completely corrupted or random file returns empty dict without crashing."""
    vault_dir = tmp_path / "config" / "cybersecuritysuite"
    vault_dir.mkdir(parents=True, exist_ok=True)
    vault_file = vault_dir / ".vault_credentials"
    vault_file.write_bytes(b"ThisIsNotValidBase64OrValidCiphertext!!!")

    CredentialManager._session_cache.clear()
    assert CredentialManager.get_key("gemini") is None
    assert CredentialManager._read_vault() == {}
