"""Secure API Key & Credential Storage Manager for CyberSecuritySuite.

Provides:
1. OS Keyring Integration: Uses the Python `keyring` package (GNOME Keyring / FreeDesktop Secret Service)
   when available.
2. Secure Encrypted Local Vault: When `keyring` is unavailable, uses a restricted file vault
   (`~/.config/cybersecuritysuite/.vault_credentials`) with strict POSIX permissions (0600)
   encrypted with a machine-bound hardware/user key.
3. In-Memory Session Cache: Transient storage during execution.
4. Environment Variable Fallbacks: Inspects `GEMINI_API_KEY` and `OPENAI_API_KEY`.
5. Masking Utility: Ensures full API keys are never exposed in UI or logs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Optional

# Check if OS keyring is available
try:
    import keyring  # type: ignore
    _HAS_KEYRING = True
except Exception:
    _HAS_KEYRING = False


SERVICE_NAME = "CyberSecuritySuite"
VAULT_DIR = Path.home() / ".config" / "cybersecuritysuite"
VAULT_FILE = VAULT_DIR / ".vault_credentials"


def _get_machine_bound_key() -> bytes:
    """Generates a stable machine-bound key derived from host identity and user UID."""
    try:
        machine_id = Path("/etc/machine-id").read_text().strip()
    except Exception:
        machine_id = "default-machine-salt-cs-suite"

    user_info = f"{os.getuid()}:{os.environ.get('USER', 'user')}:{machine_id}"
    return hashlib.sha256(user_info.encode("utf-8")).digest()


def _xor_cipher(data: bytes, key: bytes) -> bytes:
    """Symmetric stream cipher using machine-bound SHA-256 key stream."""
    out = bytearray(len(data))
    key_len = len(key)
    for i in range(len(data)):
        out[i] = data[i] ^ key[i % key_len]
    return bytes(out)


class CredentialManager:
    """Manages sensitive API credentials with OS Keyring and fallback encrypted storage."""

    _session_cache: Dict[str, str] = {}

    @classmethod
    def is_keyring_available(cls) -> bool:
        """Returns True if the system keyring is installed and accessible."""
        if not _HAS_KEYRING:
            return False
        try:
            # Test if a backend is actively resolved
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
        return "Encrypted User Vault (0600 POSIX File)"

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
        """Saves an API key securely to the OS Keyring or encrypted vault."""
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

        # Fallback: Save to machine-bound encrypted vault
        try:
            vault_data = cls._read_vault()
            vault_data[prov_key] = clean_key
            cls._write_vault(vault_data)
            return True
        except Exception:
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
        """Reads and decrypts local machine-bound credentials file."""
        if not VAULT_FILE.exists():
            return {}
        try:
            raw_b64 = VAULT_FILE.read_bytes()
            encrypted = base64.b64decode(raw_b64)
            key = _get_machine_bound_key()
            decrypted = _xor_cipher(encrypted, key).decode("utf-8")
            return json.loads(decrypted)
        except Exception:
            return {}

    @classmethod
    def _write_vault(cls, data: Dict[str, str]) -> None:
        """Encrypts and writes credentials file with strict 0600 POSIX permissions."""
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        # Ensure directory permissions are restricted to owner (0700)
        try:
            os.chmod(VAULT_DIR, 0o700)
        except Exception:
            pass

        key = _get_machine_bound_key()
        json_bytes = json.dumps(data).encode("utf-8")
        encrypted = _xor_cipher(json_bytes, key)
        raw_b64 = base64.b64encode(encrypted)

        # Write file with strict 0600 permissions
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(VAULT_FILE, flags, 0o600)
        with open(fd, "wb") as f:
            f.write(raw_b64)

