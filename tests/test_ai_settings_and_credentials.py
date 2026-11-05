"""Unit and UI Tests for Phase 11: AI Provider Settings and Credential Management.

Tests:
1. CredentialManager: Masking, OS Keyring/Vault fallback, 0600 POSIX permissions, cache lifecycle.
2. AICopilotEngine: Connection tests with mocked HTTP responses (Gemini, OpenAI, Ollama).
3. Cloud Consent & Redaction: Enforcing user consent before external transmission and redacting secrets.
4. AISettingsDialog UI: Password masking, saving credentials, connection testing, and offline selection.
"""

from __future__ import annotations

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import io
import json
import stat
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from PySide6.QtWidgets import QLineEdit

from core.ai_copilot import AICopilotEngine, AIProvider
from core.credential_manager import CredentialManager, _xor_cipher, _get_machine_bound_key
from desktop.dialogs.ai_settings_dialog import AISettingsDialog


@pytest.fixture(autouse=True)
def isolate_credentials(tmp_path, monkeypatch):
    """Isolate vault files and session cache to a temporary directory for every test."""
    test_vault_dir = tmp_path / "config" / "cybersecuritysuite"
    test_vault_file = test_vault_dir / ".vault_credentials"
    monkeypatch.setattr("core.credential_manager.VAULT_DIR", test_vault_dir)
    monkeypatch.setattr("core.credential_manager.VAULT_FILE", test_vault_file)
    monkeypatch.setattr("core.credential_manager.CredentialManager._session_cache", {})
    # Also clean environment variables
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    yield


# ===========================================================================
# 1. CredentialManager Tests
# ===========================================================================

def test_credential_masking():
    """Verify sensitive keys are masked, showing only 4 prefix and 4 suffix chars."""
    assert CredentialManager.mask_key(None) == ""
    assert CredentialManager.mask_key("") == ""
    assert CredentialManager.mask_key("12345") == "••••••••"
    assert CredentialManager.mask_key("12345678") == "••••••••"
    assert CredentialManager.mask_key("AIzaSyAbcd12344X9Z") == "AIza••••••••4X9Z"
    assert CredentialManager.mask_key("sk-proj-abc999xyz789") == "sk-p••••••••z789"


def test_credential_vault_crud(tmp_path):
    """Test saving, retrieving, and deleting API keys via the encrypted machine vault."""
    # Ensure no keys initially
    assert CredentialManager.get_key("gemini") is None
    assert CredentialManager.get_key("openai") is None

    # Save Gemini Key
    saved = CredentialManager.set_key("gemini", "AIzaSyTestGeminiKey12345")
    assert saved is True
    assert CredentialManager.get_key("gemini") == "AIzaSyTestGeminiKey12345"

    # Save OpenAI Key
    saved_oa = CredentialManager.set_key("openai", "sk-proj-testOpenAIKey67890")
    assert saved_oa is True
    assert CredentialManager.get_key("openai") == "sk-proj-testOpenAIKey67890"

    # Verify vault file exists on disk and is encrypted (does not contain plaintext)
    vault_file = tmp_path / "config" / "cybersecuritysuite" / ".vault_credentials"
    assert vault_file.exists()
    raw_content = vault_file.read_bytes()
    assert b"AIzaSyTestGeminiKey12345" not in raw_content
    assert b"sk-proj-testOpenAIKey67890" not in raw_content

    # Clear session cache to test recovery from disk
    CredentialManager._session_cache.clear()
    assert CredentialManager.get_key("gemini") == "AIzaSyTestGeminiKey12345"
    assert CredentialManager.get_key("openai") == "sk-proj-testOpenAIKey67890"

    # Test Deletion
    CredentialManager.delete_key("gemini")
    CredentialManager._session_cache.clear()
    assert CredentialManager.get_key("gemini") is None
    assert CredentialManager.get_key("openai") == "sk-proj-testOpenAIKey67890"


def test_credential_vault_file_permissions(tmp_path):
    """Verify that the encrypted credential vault is created with strict 0600 POSIX permissions."""
    CredentialManager.set_key("gemini", "AIzaSySecretVaultPermissions")
    vault_file = tmp_path / "config" / "cybersecuritysuite" / ".vault_credentials"
    assert vault_file.exists()

    file_mode = stat.S_IMODE(os.stat(vault_file).st_mode)
    # Mode should be 0o600 (read/write for owner only)
    assert file_mode == 0o600


def test_credential_env_variable_fallback(monkeypatch):
    """Test falling back to GEMINI_API_KEY and OPENAI_API_KEY when no vault key exists."""
    monkeypatch.setenv("GEMINI_API_KEY", "env-gemini-key-999")
    monkeypatch.setenv("OPENAI_API_KEY", "env-openai-key-888")

    assert CredentialManager.get_key("gemini") == "env-gemini-key-999"
    assert CredentialManager.get_key("openai") == "env-openai-key-888"


# ===========================================================================
# 2. AICopilotEngine Connection Testing (Mocked HTTP)
# ===========================================================================

def test_gemini_connection_success():
    """Verify successful Gemini API connection test with 200 OK candidate response."""
    engine = AICopilotEngine(provider=AIProvider.GEMINI_API)
    mock_resp_data = {
        "candidates": [{
            "content": {"parts": [{"text": "PONG"}]}
        }]
    }
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = json.dumps(mock_resp_data).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        ok, msg = engine.test_connection(
            provider=AIProvider.GEMINI_API,
            api_key="AIzaSyValidTestKey123456",
            model="gemini-1.5-flash",
        )
        assert ok is True
        assert "verified successfully" in msg.lower()


def test_gemini_connection_auth_failure():
    """Verify Gemini API connection handles 400 API_KEY_INVALID error cleanly."""
    engine = AICopilotEngine(provider=AIProvider.GEMINI_API)
    http_err = urllib.error.HTTPError(
        url="https://generativelanguage.googleapis.com",
        code=400,
        msg="API_KEY_INVALID",
        hdrs={},
        fp=io.BytesIO(b'{"error":{"message":"API key not valid"}}'),
    )

    with patch("urllib.request.urlopen", side_effect=http_err):
        ok, msg = engine.test_connection(
            provider=AIProvider.GEMINI_API,
            api_key="AIzaSyInvalidKey",
        )
        assert ok is False
        assert "authentication failed" in msg.lower() or "400" in msg


def test_gemini_connection_quota_exceeded():
    """Verify Gemini API connection handles 429 quota exceeded error."""
    engine = AICopilotEngine(provider=AIProvider.GEMINI_API)
    http_err = urllib.error.HTTPError(
        url="https://generativelanguage.googleapis.com",
        code=429,
        msg="RESOURCE_EXHAUSTED",
        hdrs={},
        fp=io.BytesIO(b'{"error":{"message":"Resource has been exhausted"}}'),
    )

    with patch("urllib.request.urlopen", side_effect=http_err):
        ok, msg = engine.test_connection(
            provider=AIProvider.GEMINI_API,
            api_key="AIzaSyQuotaDepleted",
        )
        assert ok is False
        assert "quota exceeded" in msg.lower() or "429" in msg


def test_openai_connection_success():
    """Verify OpenAI connection test succeeds when API returns 200 OK."""
    engine = AICopilotEngine(provider=AIProvider.OPENAI_API)
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        ok, msg = engine.test_connection(
            provider=AIProvider.OPENAI_API,
            api_key="sk-proj-ValidOpenAIKey",
            model="gpt-4o-mini",
        )
        assert ok is True
        assert "verified successfully" in msg.lower()


def test_openai_connection_auth_failure():
    """Verify OpenAI connection test handles 401 Unauthorized invalid key error."""
    engine = AICopilotEngine(provider=AIProvider.OPENAI_API)
    http_err = urllib.error.HTTPError(
        url="https://api.openai.com",
        code=401,
        msg="Unauthorized",
        hdrs={},
        fp=io.BytesIO(b'{"error":{"message":"Incorrect API key provided"}}'),
    )

    with patch("urllib.request.urlopen", side_effect=http_err):
        ok, msg = engine.test_connection(
            provider=AIProvider.OPENAI_API,
            api_key="sk-proj-BadKey",
        )
        assert ok is False
        assert "401" in msg
        assert "invalid" in msg.lower()


def test_ollama_connection_success():
    """Verify local Ollama connection test detects installed models."""
    engine = AICopilotEngine(provider=AIProvider.LOCAL_OLLAMA)
    mock_data = {
        "models": [
            {"name": "llama3:latest"},
            {"name": "mistral:latest"},
        ]
    }
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = json.dumps(mock_data).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        ok, msg = engine.test_connection(provider=AIProvider.LOCAL_OLLAMA)
        assert ok is True
        assert "connection verified" in msg.lower()


def test_ollama_connection_model_missing():
    """Verify Ollama connection warns when server is active but model is missing."""
    engine = AICopilotEngine(provider=AIProvider.LOCAL_OLLAMA, ollama_model="deepseek-r1")
    mock_data = {
        "models": [
            {"name": "llama3:latest"}
        ]
    }
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = json.dumps(mock_data).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        ok, msg = engine.test_connection(provider=AIProvider.LOCAL_OLLAMA)
        assert ok is False
        assert "not downloaded" in msg.lower()


# ===========================================================================
# 3. Cloud Transmission Consent and Secret Redaction
# ===========================================================================

def test_cloud_consent_gate():
    """Verify that diagnosis fails safe when user consent is not granted for cloud AI."""
    engine = AICopilotEngine(
        provider=AIProvider.GEMINI_API,
        gemini_api_key="AIzaSyTestValidKey",
    )
    raw_output = "Nmap scan report for 192.168.1.1\nHost is up."

    # Without consent: Should return consent pending message, NOT transmit
    diag_no_consent = engine.diagnose_output(raw_output, user_consented=False)
    assert "consent required" in diag_no_consent.analysis.lower()
    assert diag_no_consent.provider_used == "gemini_api"


def test_cloud_sensitive_redaction_before_transmission():
    """Verify that credentials and tokens are redacted prior to cloud AI prompt assembly."""
    engine = AICopilotEngine(
        provider=AIProvider.GEMINI_API,
        gemini_api_key="AIzaSyTestValidKey",
    )
    secret_output = (
        "Command executed with password=SuperSecretPassword123!\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SecretToken12345.Signature\n"
        "Target error: connection failed"
    )

    captured_prompt = None

    def fake_query(prompt, model=None, api_key=None):
        nonlocal captured_prompt
        captured_prompt = prompt
        return "Analysis completed safely.", None

    with patch.object(engine, "_query_gemini", side_effect=fake_query):
        diag = engine.diagnose_output(secret_output, user_consented=True)
        assert diag.provider_used == "gemini_api"
        assert captured_prompt is not None

        # Verify secrets were scrubbed
        assert "SuperSecretPassword123!" not in captured_prompt
        assert "SecretToken12345" not in captured_prompt
        assert "[REDACTED_PASSWORD]" in captured_prompt
        assert "[REDACTED_TOKEN]" in captured_prompt


# ===========================================================================
# 4. AISettingsDialog UI Tests
# ===========================================================================

def test_ai_settings_dialog_lifecycle(qtbot):
    """Test full UI lifecycle: loading masked keys, typing new key, saving, and testing."""
    # Pre-populate vault with an initial key
    CredentialManager.set_key("gemini", "AIzaSyPreExistingKey1234")

    engine = AICopilotEngine()
    dialog = AISettingsDialog(engine=engine)
    qtbot.addWidget(dialog)

    # 1. Verify masked key is displayed
    assert "AIza••••••••1234" in dialog.lbl_gemini_saved.text()
    assert "(Active)" in dialog.lbl_gemini_saved.text()

    # 2. Toggle password visibility
    assert dialog.input_gemini_key.echoMode() == QLineEdit.EchoMode.Password
    dialog.btn_toggle_gemini.click()
    assert dialog.input_gemini_key.echoMode() == QLineEdit.EchoMode.Normal
    assert dialog.btn_toggle_gemini.text() == "🔒 Hide"
    dialog.btn_toggle_gemini.click()
    assert dialog.input_gemini_key.echoMode() == QLineEdit.EchoMode.Password

    # 3. Enter and save new OpenAI key
    dialog.input_openai_key.setText("sk-proj-NewSavedOpenAIKey7777")
    dialog._save_openai()

    assert CredentialManager.get_key("openai") == "sk-proj-NewSavedOpenAIKey7777"
    assert "sk-p••••••••7777" in dialog.lbl_openai_saved.text()

    # 4. Clear Gemini key
    dialog._clear_gemini()
    assert CredentialManager.get_key("gemini") is None
    assert "Not Configured" in dialog.lbl_gemini_saved.text()

    # 5. Switch to Built-in offline engine
    with patch("PySide6.QtWidgets.QMessageBox.information") as mock_info:
        dialog._set_offline_active()
        assert engine.provider == AIProvider.BUILTIN_OFFLINE
        mock_info.assert_called_once()
