"""Secure API Key & Credential Storage Manager for CyberSecuritySuite.

Provides:
1. OS Keyring Integration: Uses the Python `keyring` package (GNOME Keyring / FreeDesktop Secret Service)
   when available.
2. Secure Authenticated Encrypted Local Vault (AES-256-GCM): When `keyring` is unavailable,
   uses an authenticated encrypted user vault (`~/.config/cybersecuritysuite/.vault_credentials`)
   with strict POSIX permissions (0600) and an isolated 256-bit random master key with PBKDF2 derivation.
3. Tamper Resistance: Built on AES-256-GCM AEAD authenticated encryption to cryptographically detect
   any unauthorized modifications or bit-flips.
4. Seamless Legacy Migration: Automatically migrates legacy XOR-encrypted credentials to AES-256-GCM
   authenticated format without losing credentials.
5. In-Memory Session Cache: Transient storage during execution.
6. Environment Variable Fallbacks: Inspects `GEMINI_API_KEY` and `OPENAI_API_KEY`.
7. Masking Utility: Ensures full API keys are never exposed in UI or logs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from pathlib import Path
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Check if OS keyring is available
try:
    import keyring  # type: ignore
    _HAS_KEYRING = True
except Exception:
    _HAS_KEYRING = False

# Import vetted authenticated cryptography
try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False


SERVICE_NAME = "CyberSecuritySuite"
VAULT_DIR = Path.home() / ".config" / "cybersecuritysuite"
VAULT_FILE = VAULT_DIR / ".vault_credentials"
KEY_FILE = VAULT_DIR / ".vault_key"

# Magic header for version 2 authenticated AES-GCM vault
VAULT_V2_MAGIC = b"CSS2"
VAULT_ASSOCIATED_DATA = b"CyberSecuritySuite_Vault_v2"
PBKDF2_ITERATIONS = 600_000


def _get_machine_bound_key() -> bytes:
    """Generates a stable machine-bound key derived from host identity and user UID.
    
    Retained for legacy vault decryption and migration compatibility.
    """
    try:
        machine_id = Path("/etc/machine-id").read_text().strip()
    except Exception:
        machine_id = "default-machine-salt-cs-suite"

    user_info = f"{os.getuid()}:{os.environ.get('USER', 'user')}:{machine_id}"
    return hashlib.sha256(user_info.encode("utf-8")).digest()


def _xor_cipher(data: bytes, key: bytes) -> bytes:
    """Legacy stream cipher retained strictly for migrating older vault files."""
    out = bytearray(len(data))
    key_len = len(key)
    for i in range(len(data)):
        out[i] = data[i] ^ key[i % key_len]
    return bytes(out)


def _get_or_create_master_key() -> bytes:
    """Resolves or generates a cryptographically secure 256-bit random master secret.
    
    Checks OS Keyring first, then the local restricted `.vault_key` file (0600 POSIX permissions).
    Never uses a predictable machine identifier as the sole encryption secret.
    """
    # 1. Attempt retrieval from OS Keyring
    if _HAS_KEYRING:
        try:
            backend = keyring.get_keyring()
            if backend is not None and "fail" not in backend.__class__.__name__.lower():
                stored_b64 = keyring.get_password(SERVICE_NAME, "vault_master_key")
                if stored_b64:
                    return base64.b64decode(stored_b64)
                # Generate new key and store in keyring
                new_key = secrets.token_bytes(32)
                keyring.set_password(SERVICE_NAME, "vault_master_key", base64.b64encode(new_key).decode("ascii"))
                return new_key
        except Exception:
            pass

    # 2. Local Key File fallback with strict 0600 permissions
    key_path = VAULT_DIR / ".vault_key"
    if key_path.is_file():
        try:
            raw = key_path.read_bytes()
            if len(raw) == 32:
                return raw
        except Exception:
            pass

    # Generate new random 256-bit master key
    new_master = secrets.token_bytes(32)
    try:
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(VAULT_DIR, 0o700)
        except Exception:
            pass

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(key_path, flags, 0o600)
        with open(fd, "wb") as f:
            f.write(new_master)
    except Exception as exc:
        logger.warning("Failed to persist master vault key to %s: %s", key_path, exc)

    return new_master


def _derive_vault_key(salt: bytes) -> bytes:
    """Derives a 256-bit AES key using PBKDF2-HMAC-SHA256 from the master secret and host context."""
    master_secret = _get_or_create_master_key()
    host_context = _get_machine_bound_key()
    combined_secret = master_secret + host_context

    if _HAS_CRYPTO:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(combined_secret)
    else:
        # Fallback SHA-256 KDF loop if cryptography package is missing
        derived = hashlib.pbkdf2_hmac("sha256", combined_secret, salt, PBKDF2_ITERATIONS, dklen=32)
        return derived


class CredentialManager:
    """Manages sensitive API credentials with OS Keyring and authenticated encrypted storage."""

    _session_cache: Dict[str, str] = {}

    @classmethod
    def is_keyring_available(cls) -> bool:
        """Returns True if the system keyring is installed and accessible."""
        if not _HAS_KEYRING:
            return False
        try:
            backend = keyring.get_keyring()
            return backend is not None and "fail" not in backend.__class__.__name__.lower()
        except Exception:
            return False

    @classmethod
    def get_backend_description(cls) -> str:
        """Returns human-readable description of active credential storage backend."""
        if cls.is_keyring_available():
            backend_name = keyring.get_keyring().__class__.__name__
            return f"OS Keyring ({backend_name})"
        return "Authenticated AES-256-GCM Vault (0600 POSIX File)"

    @classmethod
    def mask_key(cls, key: Optional[str]) -> str:
        """Masks sensitive API key, showing only first 4 and last 4 characters."""
        if not key:
            return ""
        clean = key.strip()
        if len(clean) <= 8:
            return "••••••••"
        return f"{clean[:4]}••••••••{clean[-4:]}"

    @classmethod
    def get_key(cls, provider: str) -> Optional[str]:
        """Retrieves an API key for the requested provider (gemini, openai, etc.)."""
        prov_key = provider.lower().strip()

        # 1. Check in-memory session cache
        if prov_key in cls._session_cache:
            return cls._session_cache[prov_key]

        # 2. Check OS Keyring if available
        if cls.is_keyring_available():
            try:
                val = keyring.get_password(SERVICE_NAME, f"{prov_key}_api_key")
                if val:
                    cls._session_cache[prov_key] = val
                    return val
            except Exception:
                pass

        # 3. Check Encrypted Vault file
        vault_data = cls._read_vault()
        if prov_key in vault_data:
            cls._session_cache[prov_key] = vault_data[prov_key]
            return vault_data[prov_key]

        # 4. Check Environment Variables fallback
        if prov_key in ("gemini", "gemini_api", "google"):
            env_val = os.environ.get("GEMINI_API_KEY")
            if env_val:
                return env_val.strip()
        elif prov_key in ("openai", "openai_api"):
            env_val = os.environ.get("OPENAI_API_KEY")
            if env_val:
                return env_val.strip()
        elif prov_key in ("deepseek", "deepseek_api"):
            env_val = os.environ.get("DEEPSEEK_API_KEY")
            if env_val:
                return env_val.strip()
        elif prov_key in ("anthropic", "claude"):
            env_val = os.environ.get("ANTHROPIC_API_KEY")
            if env_val:
                return env_val.strip()
        elif prov_key in ("custom_ai", "custom"):
            env_val = os.environ.get("CUSTOM_AI_API_KEY")
            if env_val:
                return env_val.strip()

        return None

    @classmethod
    def set_key(cls, provider: str, api_key: str) -> bool:
        """Saves an API key securely to the OS Keyring or authenticated encrypted vault."""
        prov_key = provider.lower().strip()
        clean_key = api_key.strip()
        if not clean_key:
            return cls.delete_key(prov_key)

        cls._session_cache[prov_key] = clean_key

        # Save to OS Keyring if available
        if cls.is_keyring_available():
            try:
                keyring.set_password(SERVICE_NAME, f"{prov_key}_api_key", clean_key)
                return True
            except Exception:
                pass

        # Fallback: Save to authenticated encrypted vault
        try:
            vault_data = cls._read_vault()
            vault_data[prov_key] = clean_key
            cls._write_vault(vault_data)
            return True
        except Exception as exc:
            logger.error("Failed to write to encrypted credential vault: %s", exc)
            return False

    @classmethod
    def delete_key(cls, provider: str) -> bool:
        """Deletes an API key from all storage tiers."""
        prov_key = provider.lower().strip()
        cls._session_cache.pop(prov_key, None)

        success = True
        if cls.is_keyring_available():
            try:
                keyring.delete_password(SERVICE_NAME, f"{prov_key}_api_key")
            except Exception:
                success = False

        try:
            vault_data = cls._read_vault()
            if prov_key in vault_data:
                del vault_data[prov_key]
                cls._write_vault(vault_data)
        except Exception:
            success = False

        return success

    @classmethod
    def _read_vault(cls) -> Dict[str, str]:
        """Reads and decrypts local authenticated credentials file with automatic legacy migration."""
        if not VAULT_FILE.exists():
            return {}
        try:
            raw_b64 = VAULT_FILE.read_bytes()
            raw_payload = base64.b64decode(raw_b64)

            # Check for Version 2 Authenticated AES-GCM Vault format
            if raw_payload.startswith(VAULT_V2_MAGIC):
                return cls._decrypt_v2_payload(raw_payload)

            # Otherwise, detect and migrate legacy XOR format
            legacy_data = cls._decrypt_legacy_payload(raw_payload)
            if legacy_data:
                logger.info("Migrating legacy XOR credentials vault to AES-256-GCM authenticated storage.")
                # Migrate file to new AES-GCM format immediately
                try:
                    cls._write_vault(legacy_data)
                except Exception as mig_err:
                    logger.warning("Could not persist migrated vault immediately: %s", mig_err)
                return legacy_data

            return {}
        except Exception as exc:
            logger.warning("Failed reading credential vault: %s", exc)
            return {}

    @classmethod
    def _decrypt_v2_payload(cls, payload: bytes) -> Dict[str, str]:
        """Decrypts AES-256-GCM payload with authenticated integrity verification."""
        header_len = len(VAULT_V2_MAGIC)
        salt = payload[header_len:header_len + 16]
        nonce = payload[header_len + 16:header_len + 16 + 12]
        ciphertext_and_tag = payload[header_len + 16 + 12:]

        aes_key = _derive_vault_key(salt)

        if _HAS_CRYPTO:
            aesgcm = AESGCM(aes_key)
            try:
                decrypted = aesgcm.decrypt(nonce, ciphertext_and_tag, VAULT_ASSOCIATED_DATA)
                return json.loads(decrypted.decode("utf-8"))
            except InvalidTag:
                logger.error("Security Alert: Credential vault authentication tag verification failed. File has been tampered with or corrupted.")
                return {}
        else:
            logger.error("Cryptography package missing; cannot decrypt AES-256-GCM vault.")
            return {}

    @classmethod
    def _decrypt_legacy_payload(cls, encrypted_bytes: bytes) -> Dict[str, str]:
        """Attempts decryption of legacy XOR-encrypted vault files."""
        try:
            key = _get_machine_bound_key()
            decrypted = _xor_cipher(encrypted_bytes, key).decode("utf-8")
            data = json.loads(decrypted)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {}

    @classmethod
    def _write_vault(cls, data: Dict[str, str]) -> None:
        """Encrypts credentials using AES-256-GCM and writes with strict 0600 POSIX permissions."""
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(VAULT_DIR, 0o700)
        except Exception:
            pass

        json_bytes = json.dumps(data).encode("utf-8")
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        aes_key = _derive_vault_key(salt)

        if _HAS_CRYPTO:
            aesgcm = AESGCM(aes_key)
            ciphertext_and_tag = aesgcm.encrypt(nonce, json_bytes, VAULT_ASSOCIATED_DATA)
            payload = VAULT_V2_MAGIC + salt + nonce + ciphertext_and_tag
        else:
            raise RuntimeError("Cannot write secure vault without cryptography package.")

        raw_b64 = base64.b64encode(payload)

        # Write file with strict 0600 permissions
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(VAULT_FILE, flags, 0o600)
        with open(fd, "wb") as f:
            f.write(raw_b64)
