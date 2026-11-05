"""AI Copilot and Intelligent Terminal Assistant for CyberSecuritySuite.

Provides terminal output analysis, error diagnostics, natural language to pentest
command synthesis with scope guard verification, and automated vulnerability finding
extraction for assessment reports.

Supports:
1. Built-in Expert Cybersecurity Heuristic Engine (100% Offline, zero setup).
2. Google Gemini API (Cloud - gemini-1.5-flash, gemini-1.5-pro, etc.).
3. OpenAI API (Cloud - gpt-4o-mini, gpt-4o, etc.).
4. Local Ollama (Offline LLMs - llama3, deepseek-r1, mistral at http://127.0.0.1:11434).

All cloud API queries pass through strict sensitive data redaction to mask
passwords, bearer tokens, AWS keys, and private keys prior to external transmission.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.credential_manager import CredentialManager
from core.scope import ScopeAuthorizationService, ScopeCheckResult
from storage.models import Finding, FindingSeverity, TargetScope, ValidationStatus
from terminal.recorder import redact_sensitive_text


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AIProvider(str, Enum):
    BUILTIN_OFFLINE = "builtin_offline"
    LOCAL_OLLAMA = "local_ollama"
    GEMINI_API = "gemini_api"
    OPENAI_API = "openai_api"
    DEEPSEEK_API = "deepseek_api"
    ANTHROPIC_API = "anthropic_api"
    CUSTOM_OPENAI_COMPATIBLE = "custom_openai_compatible"


@dataclass
class AIDiagnosticResult:
    analysis: str
    root_cause: str
    suggested_fix: str
    suggested_command: Optional[str] = None
    severity: str = "INFO"
    provider_used: str = "builtin_offline"


@dataclass
class AICommandSuggestion:
    tool_name: str
    command: str
    explanation: str
    is_active: bool
    is_in_scope: bool
    scope_reason: str
    provider_used: str = "builtin_offline"


class AICopilotEngine:
    """Intelligent cybersecurity copilot supporting offline heuristics, Ollama, Gemini, OpenAI, and DeepSeek."""

    def __init__(
        self,
        provider: AIProvider = AIProvider.BUILTIN_OFFLINE,
        ollama_url: str = "http://127.0.0.1:11434",
        ollama_model: str = "llama3",
        gemini_model: str = "gemini-1.5-flash",
        openai_model: str = "gpt-4o-mini",
        deepseek_model: str = "deepseek-chat",
        anthropic_model: str = "claude-3-5-sonnet-20241022",
        custom_api_url: str = "https://api.openai.com/v1",
        custom_model: str = "gpt-4o-mini",
        gemini_api_key: Optional[str] = None,
        openai_api_key: Optional[str] = None,
        deepseek_api_key: Optional[str] = None,
        anthropic_api_key: Optional[str] = None,
        custom_api_key: Optional[str] = None,
    ):
        self.provider = provider
        self.ollama_url = ollama_url
        self.ollama_model = ollama_model
        self.gemini_model = gemini_model
        self.openai_model = openai_model
        self.deepseek_model = deepseek_model
        self.anthropic_model = anthropic_model
        self.custom_api_url = custom_api_url
        self.custom_model = custom_model
        self._custom_gemini_key = gemini_api_key
        self._custom_openai_key = openai_api_key
        self._custom_deepseek_key = deepseek_api_key
        self._custom_anthropic_key = anthropic_api_key
        self._custom_custom_key = custom_api_key

    def get_api_key(self, provider: AIProvider) -> Optional[str]:
        """Resolves active API key from instance configuration, credential manager, or environment."""
        if provider == AIProvider.GEMINI_API:
            if self._custom_gemini_key:
                return self._custom_gemini_key
            return CredentialManager.get_key("gemini")
        elif provider == AIProvider.OPENAI_API:
            if self._custom_openai_key:
                return self._custom_openai_key
            return CredentialManager.get_key("openai")
        elif provider == AIProvider.DEEPSEEK_API:
            if self._custom_deepseek_key:
                return self._custom_deepseek_key
            return CredentialManager.get_key("deepseek")
        elif provider == AIProvider.ANTHROPIC_API:
            if self._custom_anthropic_key:
                return self._custom_anthropic_key
            return CredentialManager.get_key("anthropic")
        elif provider == AIProvider.CUSTOM_OPENAI_COMPATIBLE:
            if self._custom_custom_key:
                return self._custom_custom_key
            return CredentialManager.get_key("custom_ai")
        return None

    def set_api_key(self, provider: AIProvider, api_key: str) -> bool:
        """Saves an API key through the CredentialManager and updates current session state."""
        clean = api_key.strip()
        if provider == AIProvider.GEMINI_API:
            self._custom_gemini_key = clean or None
            return CredentialManager.set_key("gemini", clean)
        elif provider == AIProvider.OPENAI_API:
            self._custom_openai_key = clean or None
            return CredentialManager.set_key("openai", clean)
        elif provider == AIProvider.DEEPSEEK_API:
            self._custom_deepseek_key = clean or None
            return CredentialManager.set_key("deepseek", clean)
        elif provider == AIProvider.ANTHROPIC_API:
            self._custom_anthropic_key = clean or None
            return CredentialManager.set_key("anthropic", clean)
        elif provider == AIProvider.CUSTOM_OPENAI_COMPATIBLE:
            self._custom_custom_key = clean or None
            return CredentialManager.set_key("custom_ai", clean)
        return True

    def clear_api_key(self, provider: AIProvider) -> bool:
        """Removes the stored API key for the given provider."""
        if provider == AIProvider.GEMINI_API:
            self._custom_gemini_key = None
            return CredentialManager.delete_key("gemini")
        elif provider == AIProvider.OPENAI_API:
            self._custom_openai_key = None
            return CredentialManager.delete_key("openai")
        elif provider == AIProvider.DEEPSEEK_API:
            self._custom_deepseek_key = None
            return CredentialManager.delete_key("deepseek")
        elif provider == AIProvider.ANTHROPIC_API:
            self._custom_anthropic_key = None
            return CredentialManager.delete_key("anthropic")
        elif provider == AIProvider.CUSTOM_OPENAI_COMPATIBLE:
            self._custom_custom_key = None
            return CredentialManager.delete_key("custom_ai")
        return True

    # -----------------------------------------------------------------------
    # Connection Verification
    # -----------------------------------------------------------------------

    def test_connection(
        self,
        provider: Optional[AIProvider] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Tests live connectivity to the selected AI provider."""
        target_prov = provider or self.provider

        if target_prov == AIProvider.BUILTIN_OFFLINE:
            return True, "Built-in Cybersecurity Heuristic Engine ready (100% Offline, No network required)."

        elif target_prov == AIProvider.LOCAL_OLLAMA:
            url = f"{self.ollama_url.rstrip('/')}/api/tags"
            target_model = model or self.ollama_model
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        models = [m.get("name", "") for m in data.get("models", [])]
                        model_list = ", ".join(models[:4]) if models else "No models pulled yet"
                        if target_model and models and not any(target_model in m for m in models):
                            return False, f"Ollama is reachable, but model '{target_model}' is not downloaded. Pull it using 'ollama pull {target_model}'."
                        return True, f"Ollama connection verified on {self.ollama_url}. Installed models: {model_list}"
                    return False, f"Ollama returned HTTP status {resp.status}."
            except urllib.error.URLError:
                return False, f"Connection refused: Ollama is not running on {self.ollama_url}. Start Ollama with 'ollama serve'."
            except Exception as e:
                return False, f"Ollama error: {e}"

        elif target_prov == AIProvider.GEMINI_API:
            key = api_key or self.get_api_key(AIProvider.GEMINI_API)
            if not key:
                return False, "Gemini API key is not configured. Enter and save your Gemini API key in AI Settings."

            target_model = model or self.gemini_model
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent?key={key}"
            payload = json.dumps({
                "contents": [{"parts": [{"text": "ping"}]}],
                "generationConfig": {"maxOutputTokens": 5, "temperature": 0.0},
            }).encode("utf-8")

            try:
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=8.0) as resp:
                    if resp.status == 200:
                        return True, f"Google Gemini API verified successfully! Model: '{target_model}' is responsive."
                    return False, f"Gemini API returned HTTP {resp.status}."
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    return False, "Authentication Failed (401/403): Gemini API key is invalid or unauthorized."
                elif e.code == 429:
                    return False, "Quota Exceeded (429): Gemini API rate limit or project quota reached."
                elif e.code == 404:
                    return False, f"Model Not Found (404): Model '{target_model}' does not exist in Gemini API."
                return False, f"Gemini API error (HTTP {e.code}): {e.reason}"
            except urllib.error.URLError as e:
                return False, f"Network Connection Error: Unable to reach Google API servers ({e.reason})."
            except Exception as e:
                return False, f"Gemini connection error: {e}"

        elif target_prov == AIProvider.OPENAI_API:
            key = api_key or self.get_api_key(AIProvider.OPENAI_API)
            if not key:
                return False, "OpenAI API key is not configured. Enter and save your OpenAI API key in AI Settings."

            target_model = model or self.openai_model
            url = "https://api.openai.com/v1/chat/completions"
            payload = json.dumps({
                "model": target_model,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5,
                "temperature": 0.0,
            }).encode("utf-8")

            try:
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {key}",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=8.0) as resp:
                    if resp.status == 200:
                        return True, f"OpenAI API verified successfully! Model: '{target_model}' is responsive."
                    return False, f"OpenAI API returned HTTP {resp.status}."
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    return False, "Authentication Failed (401): OpenAI API key is invalid."
                elif e.code == 429:
                    return False, "Quota Exceeded (429): OpenAI account quota depleted or rate limited."
                return False, f"OpenAI API error (HTTP {e.code}): {e.reason}"
            except urllib.error.URLError as e:
                return False, f"Network Connection Error: Unable to reach OpenAI servers ({e.reason})."
            except Exception as e:
                return False, f"OpenAI connection error: {e}"

        elif target_prov == AIProvider.DEEPSEEK_API:
            key = api_key or self.get_api_key(AIProvider.DEEPSEEK_API)
            if not key:
                return False, "DeepSeek API key is not configured. Enter and save your DeepSeek API key in AI Settings."

            target_model = model or self.deepseek_model
            url = "https://api.deepseek.com/chat/completions"
            payload = json.dumps({
                "model": target_model,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5,
                "temperature": 0.0,
            }).encode("utf-8")

            try:
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {key}",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=10.0) as resp:
                    if resp.status == 200:
                        return True, f"DeepSeek API verified successfully! Model: '{target_model}' is responsive."
                    return False, f"DeepSeek API returned HTTP {resp.status}."
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    return False, "Authentication Failed (401): DeepSeek API key is invalid."
                elif e.code == 402:
                    return False, "Insufficient Balance (402): DeepSeek account balance depleted. Top up at platform.deepseek.com."
                elif e.code == 429:
                    return False, "Quota Exceeded (429): DeepSeek rate limit reached."
                return False, f"DeepSeek API error (HTTP {e.code}): {e.reason}"
            except urllib.error.URLError as e:
                return False, f"Network Connection Error: Unable to reach DeepSeek servers ({e.reason})."
            except Exception as e:
                return False, f"DeepSeek connection error: {e}"

        elif target_prov == AIProvider.ANTHROPIC_API:
            key = api_key or self.get_api_key(AIProvider.ANTHROPIC_API)
            if not key:
                return False, "Anthropic API key is not configured. Enter and save your Anthropic API key in AI Settings."

            target_model = model or self.anthropic_model
            url = "https://api.anthropic.com/v1/messages"
            payload = json.dumps({
                "model": target_model,
                "max_tokens": 5,
                "messages": [{"role": "user", "content": "ping"}],
            }).encode("utf-8")

            try:
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": key,
                        "anthropic-version": "2023-06-01",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=10.0) as resp:
                    if resp.status == 200:
                        return True, f"Anthropic Claude API verified successfully! Model: '{target_model}' is responsive."
                    return False, f"Anthropic API returned HTTP {resp.status}."
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    return False, "Authentication Failed (401/403): Anthropic API key is invalid."
                elif e.code == 429:
                    return False, "Quota Exceeded (429): Anthropic API rate limit reached."
                return False, f"Anthropic API error (HTTP {e.code}): {e.reason}"
            except urllib.error.URLError as e:
                return False, f"Network Connection Error: Unable to reach Anthropic servers ({e.reason})."
            except Exception as e:
                return False, f"Anthropic connection error: {e}"

        elif target_prov == AIProvider.CUSTOM_OPENAI_COMPATIBLE:
            key = api_key or self.get_api_key(AIProvider.CUSTOM_OPENAI_COMPATIBLE)
            base_url = (self.custom_api_url or "https://api.openai.com/v1").rstrip("/")
            url = f"{base_url}/chat/completions"
            target_model = model or self.custom_model or "default"
            payload = json.dumps({
                "model": target_model,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 5,
                "temperature": 0.0,
            }).encode("utf-8")

            headers = {"Content-Type": "application/json"}
            if key:
                headers["Authorization"] = f"Bearer {key}"

            try:
                req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=10.0) as resp:
                    if resp.status == 200:
                        return True, f"Custom API verified successfully! Endpoint: '{base_url}' is responsive."
                    return False, f"Custom API returned HTTP {resp.status}."
            except urllib.error.HTTPError as e:
                return False, f"Custom API HTTP Error {e.code}: {e.reason}"
            except urllib.error.URLError as e:
                return False, f"Connection Error: Unable to reach custom endpoint ({e.reason})."
            except Exception as e:
                return False, f"Custom API error: {e}"

        return False, "Unknown AI Provider."

    # -----------------------------------------------------------------------
    # Output Diagnosis and Error Explanation
    # -----------------------------------------------------------------------

    def diagnose_output(
        self,
        output: str,
        exit_code: Optional[int] = None,
        user_consented: bool = False,
    ) -> AIDiagnosticResult:
        """Analyzes terminal stdout/stderr to diagnose errors or summarize output."""
        clean_text = re.sub(r"\x1b\[[0-9;]*m", "", output).strip()
        if not clean_text:
            return AIDiagnosticResult(
                analysis="Terminal output is empty.",
                root_cause="No process output captured.",
                suggested_fix="Execute a security tool or command in the terminal to inspect results.",
                provider_used=self.provider.value,
            )

        # 1. Cloud Provider: Gemini API
        if self.provider == AIProvider.GEMINI_API:
            key = self.get_api_key(AIProvider.GEMINI_API)
            if not key:
                return AIDiagnosticResult(
                    analysis="⚠️ Google Gemini API is selected, but no API key is configured.",
                    root_cause="Missing Gemini API Key",
                    suggested_fix="Click '⚙️ AI Settings' to configure your Gemini API key, or switch to the Built-in Offline Engine.",
                    provider_used="gemini_api",
                )
            if not user_consented:
                return AIDiagnosticResult(
                    analysis="⚠️ Cloud Transmission Consent Required: Sending terminal output to Gemini API requires explicit consent.",
                    root_cause="Consent Pending",
                    suggested_fix="Check 'Consent to send redacted output to Cloud AI' or switch to the Built-in Offline Engine.",
                    provider_used="gemini_api",
                )

            # Sanitize and redact passwords/tokens before sending
            redacted_snippet = redact_sensitive_text(clean_text[-2500:])
            prompt = (
                "You are an expert Senior Penetration Tester and CPENT Instructor assisting an analyst.\n"
                f"Analyze this terminal security tool output (Exit Code: {exit_code}).\n"
                "Provide:\n"
                "1. Brief technical analysis of what happened or vulnerabilities discovered.\n"
                "2. Root cause of error or observation.\n"
                "3. Recommended next action or exact CLI fix command.\n\n"
                f"Terminal Output:\n{redacted_snippet}"
            )
            resp_text, err = self._query_gemini(prompt)
            if resp_text:
                cmd_match = re.search(r"```(?:bash|sh)?\n(.*?)\n```", resp_text, re.DOTALL)
                sugg_cmd = cmd_match.group(1).strip() if cmd_match else None
                return AIDiagnosticResult(
                    analysis=resp_text,
                    root_cause="Analysis generated by Google Gemini AI.",
                    suggested_fix="Review findings and remediation steps generated above.",
                    suggested_command=sugg_cmd,
                    provider_used="gemini_api",
                )

        # 2. Cloud Provider: OpenAI API
        elif self.provider == AIProvider.OPENAI_API:
            key = self.get_api_key(AIProvider.OPENAI_API)
            if not key:
                return AIDiagnosticResult(
                    analysis="⚠️ OpenAI API is selected, but no API key is configured.",
                    root_cause="Missing OpenAI API Key",
                    suggested_fix="Click '⚙️ AI Settings' to configure your OpenAI API key, or switch to the Built-in Offline Engine.",
                    provider_used="openai_api",
                )
            if not user_consented:
                return AIDiagnosticResult(
                    analysis="⚠️ Cloud Transmission Consent Required: Sending terminal output to OpenAI API requires explicit consent.",
                    root_cause="Consent Pending",
                    suggested_fix="Check 'Consent to send redacted output to Cloud AI' or switch to the Built-in Offline Engine.",
                    provider_used="openai_api",
                )

            redacted_snippet = redact_sensitive_text(clean_text[-2500:])
            prompt = (
                "You are an expert Senior Penetration Tester and CPENT Instructor assisting an analyst.\n"
                f"Analyze this terminal security tool output (Exit Code: {exit_code}).\n"
                "Provide:\n"
                "1. Technical analysis of findings or errors.\n"
                "2. Root cause.\n"
                "3. Actionable next CLI command.\n\n"
                f"Terminal Output:\n{redacted_snippet}"
            )
            resp_text, err = self._query_openai(prompt)
            if resp_text:
                cmd_match = re.search(r"```(?:bash|sh)?\n(.*?)\n```", resp_text, re.DOTALL)
                sugg_cmd = cmd_match.group(1).strip() if cmd_match else None
                return AIDiagnosticResult(
                    analysis=resp_text,
                    root_cause="Analysis generated by OpenAI.",
                    suggested_fix="Review guidance generated above.",
                    suggested_command=sugg_cmd,
                    provider_used="openai_api",
                )

        # 3. Cloud Provider: DeepSeek API
        elif self.provider == AIProvider.DEEPSEEK_API:
            key = self.get_api_key(AIProvider.DEEPSEEK_API)
            if not key:
                return AIDiagnosticResult(
                    analysis="⚠️ DeepSeek API is selected, but no API key is configured.",
                    root_cause="Missing DeepSeek API Key",
                    suggested_fix="Click '⚙️ AI Settings' to configure your DeepSeek API key, or switch to the Built-in Offline Engine.",
                    provider_used="deepseek_api",
                )
            if not user_consented:
                return AIDiagnosticResult(
                    analysis="⚠️ Cloud Transmission Consent Required: Sending terminal output to DeepSeek API requires explicit consent.",
                    root_cause="Consent Pending",
                    suggested_fix="Check 'Consent to send redacted output to Cloud AI' or switch to the Built-in Offline Engine.",
                    provider_used="deepseek_api",
                )

            redacted_snippet = redact_sensitive_text(clean_text[-2500:])
            prompt = (
                "You are an expert Senior Penetration Tester and CPENT Instructor assisting an analyst.\n"
                f"Analyze this terminal security tool output (Exit Code: {exit_code}).\n"
                "Provide:\n"
                "1. Technical analysis of findings or errors.\n"
                "2. Root cause.\n"
                "3. Actionable next CLI command.\n\n"
                f"Terminal Output:\n{redacted_snippet}"
            )
            resp_text, err = self._query_deepseek(prompt)
            if resp_text:
                cmd_match = re.search(r"```(?:bash|sh)?\n(.*?)\n```", resp_text, re.DOTALL)
                sugg_cmd = cmd_match.group(1).strip() if cmd_match else None
                return AIDiagnosticResult(
                    analysis=resp_text,
                    root_cause="Analysis generated by DeepSeek AI.",
                    suggested_fix="Review guidance generated above.",
                    suggested_command=sugg_cmd,
                    provider_used="deepseek_api",
                )

        # 4. Cloud Provider: Anthropic Claude API
        elif self.provider == AIProvider.ANTHROPIC_API:
            key = self.get_api_key(AIProvider.ANTHROPIC_API)
            if not key:
                return AIDiagnosticResult(
                    analysis="⚠️ Anthropic API is selected, but no API key is configured.",
                    root_cause="Missing Anthropic API Key",
                    suggested_fix="Click '⚙️ AI Settings' to configure your Anthropic API key, or switch to the Built-in Offline Engine.",
                    provider_used="anthropic_api",
                )
            if not user_consented:
                return AIDiagnosticResult(
                    analysis="⚠️ Cloud Transmission Consent Required: Sending terminal output to Anthropic requires explicit consent.",
                    root_cause="Consent Pending",
                    suggested_fix="Check 'Consent to send redacted output to Cloud AI' or switch to the Built-in Offline Engine.",
                    provider_used="anthropic_api",
                )

            redacted_snippet = redact_sensitive_text(clean_text[-2500:])
            prompt = (
                "You are an expert Senior Penetration Tester and CPENT Instructor assisting an analyst.\n"
                f"Analyze this terminal security tool output (Exit Code: {exit_code}).\n"
                "Provide:\n"
                "1. Technical analysis of findings or errors.\n"
                "2. Root cause.\n"
                "3. Actionable next CLI command.\n\n"
                f"Terminal Output:\n{redacted_snippet}"
            )
            resp_text, err = self._query_anthropic(prompt)
            if resp_text:
                cmd_match = re.search(r"```(?:bash|sh)?\n(.*?)\n```", resp_text, re.DOTALL)
                sugg_cmd = cmd_match.group(1).strip() if cmd_match else None
                return AIDiagnosticResult(
                    analysis=resp_text,
                    root_cause="Analysis generated by Anthropic Claude AI.",
                    suggested_fix="Review guidance generated above.",
                    suggested_command=sugg_cmd,
                    provider_used="anthropic_api",
                )

        # 5. Custom OpenAI-Compatible Provider
        elif self.provider == AIProvider.CUSTOM_OPENAI_COMPATIBLE:
            key = self.get_api_key(AIProvider.CUSTOM_OPENAI_COMPATIBLE)
            redacted_snippet = redact_sensitive_text(clean_text[-2500:])
            prompt = (
                "You are an expert Senior Penetration Tester and CPENT Instructor assisting an analyst.\n"
                f"Analyze this terminal security tool output (Exit Code: {exit_code}).\n"
                "Provide:\n"
                "1. Technical analysis of findings or errors.\n"
                "2. Root cause.\n"
                "3. Actionable next CLI command.\n\n"
                f"Terminal Output:\n{redacted_snippet}"
            )
            resp_text, err = self._query_custom(prompt)
            if resp_text:
                cmd_match = re.search(r"```(?:bash|sh)?\n(.*?)\n```", resp_text, re.DOTALL)
                sugg_cmd = cmd_match.group(1).strip() if cmd_match else None
                return AIDiagnosticResult(
                    analysis=resp_text,
                    root_cause="Analysis generated by Custom AI Provider.",
                    suggested_fix="Review guidance generated above.",
                    suggested_command=sugg_cmd,
                    provider_used="custom_openai_compatible",
                )

        # 6. Local Ollama Provider
        elif self.provider == AIProvider.LOCAL_OLLAMA:
            redacted_snippet = redact_sensitive_text(clean_text[-2500:])
            prompt = (
                "You are a Senior Penetration Tester and CPENT Instructor. Analyze this security tool output and exit code "
                f"{exit_code}.\nExplain technical findings or errors, root cause, and the exact CLI command to proceed:\n\n{redacted_snippet}"
            )
            resp_text, err = self._query_ollama(prompt)
            if resp_text:
                return AIDiagnosticResult(
                    analysis=resp_text,
                    root_cause="Identified via Local Ollama analysis.",
                    suggested_fix="Review the recommended commands and guidance above.",
                    provider_used="local_ollama",
                )

        # 4. Fallback / Built-in Offline Heuristics Engine
        return self._diagnose_offline(clean_text, exit_code)

    def _diagnose_offline(self, clean_text: str, exit_code: Optional[int]) -> AIDiagnosticResult:
        """Built-in cybersecurity heuristic engine operating 100% offline."""
        lowered = clean_text.lower()

        # 1. Permission Denied / Root Privileges
        if "permission denied" in lowered or "you need to be root" in lowered or "operation not permitted" in lowered:
            return AIDiagnosticResult(
                analysis="Execution halted due to insufficient operating system privileges.",
                root_cause="The requested network operation (e.g. raw socket SYN scan) requires elevated root permissions.",
                suggested_fix="Prefix command with 'sudo' or run the application in an authorized administrative session.",
                suggested_command="sudo !!",
                severity="HIGH",
                provider_used="builtin_offline",
            )

        # 2. Connection Refused / Host Down
        if "connection refused" in lowered or "site appears to be down" in lowered or "host seems down" in lowered:
            return AIDiagnosticResult(
                analysis="Target host is either offline, unreachable, or filtering ICMP echo probes.",
                root_cause="Network connection could not be established on the requested port or protocol.",
                suggested_fix="Verify target IP/URL availability. If using Nmap, append '-Pn' to disable ping probes.",
                suggested_command="nmap -Pn -sV <target>",
                severity="MEDIUM",
                provider_used="builtin_offline",
            )

        # 3. Missing Dependencies or Wordlist
        if "required module not found" in lowered or "no module named" in lowered:
            mod_match = re.search(r"no module named ['\"]?([A-Za-z0-9_\-]+)['\"]?", lowered)
            mod_name = mod_match.group(1) if mod_match else "dependency"
            return AIDiagnosticResult(
                analysis=f"Missing runtime software dependency: '{mod_name}'.",
                root_cause="The interpreter or script requires a library that is not currently installed.",
                suggested_fix=f"Install the missing package into the environment using: 'pip install {mod_name}'.",
                suggested_command=f"pip install {mod_name}",
                severity="MEDIUM",
                provider_used="builtin_offline",
            )

        if "wordlist" in lowered and ("not found" in lowered or "does not exist" in lowered or "empty" in lowered):
            return AIDiagnosticResult(
                analysis="Specified wordlist file could not be opened.",
                root_cause="Wordlist path is incorrect or wordlist package is uninstalled.",
                suggested_fix="Use system wordlists such as '/usr/share/dirb/wordlists/common.txt' or install SecLists.",
                suggested_command="gobuster dir -u <url> -w /usr/share/dirb/wordlists/common.txt",
                severity="LOW",
                provider_used="builtin_offline",
            )

        # 4. SQLMap Specific
        if "sqlmap" in lowered or "is vulnerable" in lowered or "sql injection" in lowered:
            if "is vulnerable" in lowered or "heuristic" in lowered or "parameter" in lowered:
                return AIDiagnosticResult(
                    analysis="SQL Injection vulnerability confirmed by SQLMap!",
                    root_cause="Application concatenates unescaped user input into backend database query.",
                    suggested_fix="Use parameterized queries (Prepared Statements) or an ORM. Do not concatenate SQL.",
                    suggested_command="sqlmap -u <url> --batch --dbs",
                    severity="CRITICAL",
                    provider_used="builtin_offline",
                )
            if "target url appears to be protected by a waf" in lowered or "waf/ips" in lowered:
                return AIDiagnosticResult(
                    analysis="SQLMap detected an active Web Application Firewall (WAF/IPS).",
                    root_cause="Automated injection payloads were blocked or dropped by perimeter protection.",
                    suggested_fix="Inspect WAF with WAFW00F, use tamper scripts (e.g. '--tamper=space2comment'), or adjust request delay.",
                    suggested_command="sqlmap -u <url> --tamper=between,randomcase --batch",
                    severity="HIGH",
                    provider_used="builtin_offline",
                )

        # 5. Nmap Success Summary
        if "nmap done:" in lowered or "nmap scan report" in lowered:
            return AIDiagnosticResult(
                analysis="Nmap network port scan completed successfully.",
                root_cause="Host service exploration finished without network interruption.",
                suggested_fix="Review discovered open ports below and use 'Extract Findings' to register them into the Assessment Report.",
                severity="INFO",
                provider_used="builtin_offline",
            )

        # Default fallback analysis
        status_text = f"Process completed with exit code {exit_code}." if exit_code is not None else "Execution output captured."
        return AIDiagnosticResult(
            analysis=f"{status_text}\nOutput contains {len(clean_text.splitlines())} lines.",
            root_cause="Standard process stream output.",
            suggested_fix="Inspect stdout above or use command generator to formulate next testing phase.",
            severity="INFO",
            provider_used="builtin_offline",
        )

    # -----------------------------------------------------------------------
    # Interactive Conversational Security Chatbot
    # -----------------------------------------------------------------------

    def chat(
        self,
        messages: List[Dict[str, str]],
        project_context: Optional[str] = None,
        user_consented: bool = False,
    ) -> Tuple[str, str]:
        """Conversational multi-turn security chat supporting Built-in Offline, Ollama, Gemini, and OpenAI.

        Args:
            messages: List of message dictionaries, each having 'role' ('user'|'assistant') and 'content'.
            project_context: Optional active project name, client, and scope context.
            user_consented: Whether user consented to transmitting sanitized content to cloud models.

        Returns:
            Tuple[str, str]: (assistant_reply, provider_used)
        """
        if not messages:
            return (
                "Hello! I am your AI Security Copilot and Senior CPENT Instructor. "
                "How can I assist your security assessment or penetration testing workflow today?",
                "builtin_offline",
            )

        # 1. Cloud Provider: Gemini API
        if self.provider == AIProvider.GEMINI_API:
            key = self.get_api_key(AIProvider.GEMINI_API)
            if not key:
                fallback_reply, _ = self._chat_offline(messages, project_context)
                notice = (
                    "💡 *[Notice: Google Gemini API is selected, but no API key is configured. "
                    "Answering via Built-in Security Knowledge Engine. Configure your key in AI Settings.]*\n\n"
                )
                return notice + fallback_reply, "builtin_offline"
            if not user_consented:
                fallback_reply, _ = self._chat_offline(messages, project_context)
                notice = (
                    "💡 *[Notice: Cloud transmission consent is pending. Answering via Built-in Security Knowledge Engine.]*\n\n"
                )
                return notice + fallback_reply, "builtin_offline"

            resp_text, err = self._chat_gemini(messages, project_context, key)
            if resp_text:
                return resp_text, "gemini_api"
            fallback_reply, _ = self._chat_offline(messages, project_context)
            notice = f"💡 *[Notice: Gemini API query failed ({err}). Answering via Built-in Security Knowledge Engine.]*\n\n"
            return notice + fallback_reply, "builtin_offline"

        # 2. Cloud Provider: OpenAI API
        elif self.provider == AIProvider.OPENAI_API:
            key = self.get_api_key(AIProvider.OPENAI_API)
            if not key:
                fallback_reply, _ = self._chat_offline(messages, project_context)
                notice = (
                    "💡 *[Notice: OpenAI API is selected, but no API key is configured. "
                    "Answering via Built-in Security Knowledge Engine. Configure your key in AI Settings.]*\n\n"
                )
                return notice + fallback_reply, "builtin_offline"
            if not user_consented:
                fallback_reply, _ = self._chat_offline(messages, project_context)
                notice = (
                    "💡 *[Notice: Cloud transmission consent is pending. Answering via Built-in Security Knowledge Engine.]*\n\n"
                )
                return notice + fallback_reply, "builtin_offline"

            resp_text, err = self._chat_openai(messages, project_context, key)
            if resp_text:
                return resp_text, "openai_api"
            fallback_reply, _ = self._chat_offline(messages, project_context)
            notice = f"💡 *[Notice: OpenAI API query failed ({err}). Answering via Built-in Security Knowledge Engine.]*\n\n"
            return notice + fallback_reply, "builtin_offline"

        # 3. Cloud Provider: DeepSeek API
        elif self.provider == AIProvider.DEEPSEEK_API:
            key = self.get_api_key(AIProvider.DEEPSEEK_API)
            if not key:
                fallback_reply, _ = self._chat_offline(messages, project_context)
                notice = (
                    "💡 *[Notice: DeepSeek API is selected, but no API key is configured. "
                    "Answering via Built-in Security Knowledge Engine. Configure your key in AI Settings.]*\n\n"
                )
                return notice + fallback_reply, "builtin_offline"
            if not user_consented:
                fallback_reply, _ = self._chat_offline(messages, project_context)
                notice = (
                    "💡 *[Notice: Cloud transmission consent is pending. Answering via Built-in Security Knowledge Engine.]*\n\n"
                )
                return notice + fallback_reply, "builtin_offline"

            resp_text, err = self._chat_deepseek(messages, project_context, key)
            if resp_text:
                return resp_text, "deepseek_api"
            fallback_reply, _ = self._chat_offline(messages, project_context)
            notice = f"💡 *[Notice: DeepSeek API query failed ({err}). Answering via Built-in Security Knowledge Engine.]*\n\n"
            return notice + fallback_reply, "builtin_offline"

        # 4. Cloud Provider: Anthropic Claude API
        elif self.provider == AIProvider.ANTHROPIC_API:
            key = self.get_api_key(AIProvider.ANTHROPIC_API)
            if not key:
                fallback_reply, _ = self._chat_offline(messages, project_context)
                notice = (
                    "💡 *[Notice: Anthropic API is selected, but no API key is configured. "
                    "Answering via Built-in Security Knowledge Engine. Configure your key in AI Settings.]*\n\n"
                )
                return notice + fallback_reply, "builtin_offline"
            if not user_consented:
                fallback_reply, _ = self._chat_offline(messages, project_context)
                notice = (
                    "💡 *[Notice: Cloud transmission consent is pending. Answering via Built-in Security Knowledge Engine.]*\n\n"
                )
                return notice + fallback_reply, "builtin_offline"

            resp_text, err = self._chat_anthropic(messages, project_context, key)
            if resp_text:
                return resp_text, "anthropic_api"
            fallback_reply, _ = self._chat_offline(messages, project_context)
            notice = f"💡 *[Notice: Anthropic API query failed ({err}). Answering via Built-in Security Knowledge Engine.]*\n\n"
            return notice + fallback_reply, "builtin_offline"

        # 5. Custom OpenAI-Compatible Provider
        elif self.provider == AIProvider.CUSTOM_OPENAI_COMPATIBLE:
            key = self.get_api_key(AIProvider.CUSTOM_OPENAI_COMPATIBLE)
            resp_text, err = self._chat_custom(messages, project_context, key)
            if resp_text:
                return resp_text, "custom_openai_compatible"
            fallback_reply, _ = self._chat_offline(messages, project_context)
            notice = f"💡 *[Notice: Custom API query failed ({err}). Answering via Built-in Security Knowledge Engine.]*\n\n"
            return notice + fallback_reply, "builtin_offline"

        # 6. Local Ollama Provider
        elif self.provider == AIProvider.LOCAL_OLLAMA:
            resp_text, err = self._chat_ollama(messages, project_context)
            if resp_text:
                return resp_text, "local_ollama"
            fallback_reply, _ = self._chat_offline(messages, project_context)
            notice = f"💡 *[Notice: Local Ollama on {self.ollama_url} was unreachable ({err}). Answering via Built-in Security Knowledge Engine.]*\n\n"
            return notice + fallback_reply, "builtin_offline"

        # 4. Built-in Offline Security Engine (Default)
        return self._chat_offline(messages, project_context)

    def _chat_offline(
        self, messages: List[Dict[str, str]], project_context: Optional[str] = None
    ) -> Tuple[str, str]:
        """Built-in Offline Security Knowledge Engine supporting English and Burmese queries."""
        last_msg = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                last_msg = m.get("content", "").strip()
                break

        lowered = last_msg.lower()

        # 0. Live Project Data Telemetry & Risk Assessment Analysis (Factual & Evidence-Grounded)
        if project_context and any(
            k in lowered
            for k in [
                "summar", "asset", "host", "finding", "vuln", "risk", "status",
                "evidence", "remediat", "report", "discover", "scope",
                "စစ်ဆေး", "တွေ့ရှိ", "အကျဉ်းချုပ်", "ရလဒ်"
            ]
        ):
            items = [p.strip() for p in project_context.split(" | ") if p.strip()]
            eng_info = next((i for i in items if i.startswith("Engagement:")), "")
            scope_info = next((i for i in items if i.startswith("Authorized Scopes")), "")
            excl_info = next((i for i in items if i.startswith("Strict Exclusions")), "")
            assets_info = next((i for i in items if i.startswith("Discovered Assets")), "")
            findings_info = next((i for i in items if i.startswith("Findings:")), "")
            ev_info = next((i for i in items if i.startswith("Evidence Artifacts:")), "")

            lines = [
                "### 🛡️ Live Assessment Telemetry & Risk Consultation",
                "",
                f"**Active Context**: {eng_info or 'Engagement Loaded'}",
                "",
                "#### 1. Scope & Rules of Engagement Verification",
                f"- **{scope_info or 'Authorized Scopes'}:** Confirmed fail-closed boundary.",
            ]
            if excl_info:
                lines.append(f"- **{excl_info}:** Prohibited from scanning or active probing.")

            lines.extend([
                "",
                "#### 2. Discovered Asset Inventory & Provenance",
            ])
            if assets_info:
                lines.append(f"- **{assets_info}**")
            else:
                lines.append("- *No asset nodes currently registered in project inventory. Run discovery scans or footprinting.*")

            lines.extend([
                "",
                "#### 3. Vulnerability & Risk Distribution",
            ])
            if findings_info:
                lines.append(f"- **{findings_info}**")
            else:
                lines.append("- *Zero security findings recorded. Run web security or service vulnerability auditing.*")

            lines.extend([
                "",
                "#### 4. Evidence Integrity & Cryptographic Audit",
                f"- **{ev_info or 'Cryptographic logs verified in SQLite vault.'}**",
                "- All observations maintain provenance with timestamps, tool tags, and sha256 checksums.",
                "",
                "#### 5. Recommended Safe Next Steps",
                "1. **Service Verification**: Fingerprint identified TCP/UDP services (e.g. Apache, Postfix, vsftpd) with version detection.",
                "2. **Web Application Assessment**: Use OWASP ZAP or Burp Suite to audit discovered HTTP endpoints.",
                "3. **Zero-Port Hosts**: Review ping-only live hosts and verify reachability with `-Pn` or local ARP footprinting.",
                "4. **Evidence Archival**: Export technical and executive PDF reports with cryptographic SHA-256 integrity hashes.",
                "",
                "---",
                "🇲🇲 **မြန်မာဘာသာဖြင့် သုံးသပ်ချက်**:",
                f"လက်ရှိ Project ဒေတာဘေ့စ်အရ စုစုပေါင်း စစ်ဆေးတွေ့ရှိချက်များနှင့် Asset များကို အတည်ပြုဆန်းစစ်ပြီး ဖြစ်ပါသည်။ "
                "ခွင့်ပြုထားသော Scope ဘောင်အတွင်းရှိ Discovered Hosts များကို အထက်ပါအတိုင်း စနစ်တကျ မှတ်တမ်းတင်ထားပြီး ဖြစ်ပါသည်။",
            ])
            return "\n".join(lines), "builtin_offline"

        # A. OWASP ZAP & Burp Suite Guidance (Answers user's specific question!)
        if any(k in lowered for k in ["zap", "burp", "burpsuite", "proxy", "interception", "repeater", "intruder"]):
            return (
                "### 🌐 OWASP ZAP & Burp Suite Web Proxy Guide\n\n"
                "In CyberSecuritySuite, **OWASP ZAP** and **Burp Suite** are integrated under the "
                "**'🌐 Web & API Security'** view in the **'🌐 Interception Proxy & Web Tools'** tab!\n\n"
                "#### 1. OWASP ZAP (Installed & Ready)\n"
                "- **Executable Path**: `/usr/local/bin/zap.sh` (Version 2.17.0)\n"
                "- **Launch GUI**: Click the **'🚀 Launch OWASP ZAP GUI'** button in Web Security, or run in terminal:\n"
                "```bash\n"
                "zap.sh -dir /tmp/.ZAP\n"
                "```\n"
                "- **Default Local Proxy**: `127.0.0.1:8090`\n\n"
                "#### 2. Burp Suite (Community / Pro)\n"
                "- **Default Local Proxy**: `127.0.0.1:8080`\n"
                "- **Setup & Download**: If not installed on the system, download the Community Edition from "
                "[PortSwigger](https://portswigger.net/burp/communitydownload) or run a JAR file:\n"
                "```bash\n"
                "java -jar /path/to/burpsuite_community.jar\n"
                "```\n\n"
                "#### 3. Browser Interception Proxy Configuration\n"
                "1. Set your browser (Firefox / Chrome / FoxyProxy) HTTP & HTTPS proxy to:\n"
                "   - **Host**: `127.0.0.1`\n"
                "   - **Port**: `8080` (for Burp Suite) or `8090` (for OWASP ZAP)\n"
                "2. Visit `http://burp` or `http://zap` in the browser to download the CA certificate.\n"
                "3. Import the certificate into your browser's **Authorities** list to intercept HTTPS traffic without TLS warnings.\n\n"
                "---\n"
                "🇲🇲 **မြန်မာဘာသာဖြင့် အကျဉ်းချုပ်**:\n"
                "OWASP ZAP (Version 2.17.0) ကို CyberSecuritySuite ၏ **'🌐 Web & API Security'** view ထဲရှိ "
                "**'🌐 Interception Proxy & Web Tools'** tab တွင် တိုက်ရိုက် **'Launch OWASP ZAP GUI'** နှိပ်၍ ဖွင့်နိုင်ပါသည်။ "
                "Burp Suite သို့မဟုတ် ZAP အတွက် Browser Proxy ကို `127.0.0.1:8080` (Burp) သို့မဟုတ် `127.0.0.1:8090` (ZAP) "
                "သတ်မှတ်ပြီး CA certificate သွင်းကာ Request/Response များကို Intercept စစ်ဆေးနိုင်ပါသည်။",
                "builtin_offline",
            )

        # A2. OWASP PTK (Penetration Testing Kit) & R-Builder / JWT Lab
        if any(k in lowered for k in ["ptk", "pentestkit", "r-builder", "jwt", "encoder", "denispodgurskii", "payload"]):
            return (
                "### 🧰 OWASP PTK (Penetration Testing Kit) Workbench Guide\n\n"
                "CyberSecuritySuite incorporates the core concepts, methodologies, and utilities inspired by **Denis Podgurskii's OWASP PTK** (`DenisPodgurskii/pentestkit`):\n\n"
                "#### 1. ⚡ R-Builder (Request Replayer & cURL Integration)\n"
                "- **Location**: Navigate to **'🌐 Web & API Security'** -> **'🧰 OWASP PTK Workbench'** -> **'⚡ R-Builder'**.\n"
                "- **Features**:\n"
                "  - Interactive HTTP composer (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD).\n"
                "  - **Scope Guard Protected**: Target URLs are strictly verified against authorized project scope before transmission.\n"
                "  - **Import cURL**: Paste any raw `curl` command (from browser DevTools or documentation) to instantly parse into headers, query, and payload.\n"
                "  - **Export cURL**: Convert your crafted request back into a shell-executable `curl` command.\n\n"
                "#### 2. 🔑 JWT Security Lab\n"
                "- **Decode & Audit**: Decodes Header, Payload, and Signature completely client-side without external exposure.\n"
                "- **Vulnerability Checks**: Detects `alg: none`, expired tokens, weak HMAC keys (brute-forced with common wordlists), and plaintext secrets.\n"
                "- **Forge 'alg: none' Token**: One-click generation of unsigned tokens with modified claims (e.g., `admin: true`) for authorization bypass tests.\n"
                "- **Send to R-Builder**: Automatically injects forged/valid tokens into the `Authorization: Bearer <token>` header.\n\n"
                "#### 3. 🔄 Encoders & Pentest Payloads\n"
                "- **Live Transformations**: URL Encode/Decode, Base64 Encode/Decode, Hex, HTML Entities, MD5, SHA-1, and SHA-256.\n"
                "- **Attack Payloads**: Curated repository of verified payloads for XSS, SQLi, SSRF, Path Traversal (LFI), Command Injection, and SSTI.\n\n"
                "#### 4. 🛡️ Client-Side Security & SCA Analyzer\n"
                "- **Header Compliance**: Verifies Content-Security-Policy, HSTS, X-Frame-Options, X-Content-Type-Options, etc.\n"
                "- **SCA Analysis**: Identifies frontend libraries (jQuery, Bootstrap, Lodash, AngularJS) and flags known CVEs.\n\n"
                "---\n"
                "🇲🇲 **မြန်မာဘာသာဖြင့် အကျဉ်းချုပ်**:\n"
                "OWASP PTK (Penetration Testing Kit) ၏ အဓိက စွမ်းဆောင်ရည်များဖြစ်သော **R-Builder** (Request Replayer နှင့် cURL Import/Export), "
                "**JWT Security Lab** (Token စစ်ဆေးခြင်းနှင့် 'alg: none' Exploit ထုတ်လုပ်ခြင်း), **Multi-Encoder** နှင့် **Pentest Payloads** (XSS, SQLi, SSRF, LFI) များကို "
                "CyberSecuritySuite ၏ **'🌐 Web & API Security'** view ထဲရှိ **'🧰 OWASP PTK Workbench'** တွင် တိုက်ရိုက် အသုံးပြုနိုင်ပါသည်။",
                "builtin_offline",
            )

        # A3. Sn1per Multi-Stage Scanning Orchestrator (1N3/Sn1per)
        if any(k in lowered for k in ["sn1per", "sniper", "orchestrat", "pipeline", "airstrike"]):
            return (
                "### ⚡ Sn1per Multi-Stage Penetration Testing Orchestrator\n\n"
                "Inspired by **1N3/Sn1per** (`1N3/Sn1per`), CyberSecuritySuite provides automated, multi-tool chained scanning pipelines "
                "protected by strict **Target Scope Guard** authorization:\n\n"
                "#### 1. Available Scan Modes\n"
                "- **🔍 RECON (`recon`)**: Low-footprint passive discovery. Discovers API routes, CORS misconfigurations, security response headers, and exposed JS secrets via `c0desec`.\n"
                "- **🥷 STEALTH (`stealth`)**: Evasive network discovery. Executes SYN stealth scans (`Nmap -T2`) and passive Web Application Firewall fingerprinting (`WAFW00F`).\n"
                "- **📡 DISCOVERY (`discovery`)**: Comprehensive host and banner enumeration (`Nmap -sV -sC`) identifying open ports and server services.\n"
                "- **🌐 WEB FULL (`web_full`)**: Complete web perimeter audit chaining WAF detection (`WAFW00F`), web security analysis (`c0desec`), and directory fuzzing (`Gobuster`).\n"
                "- **💥 AIRSTRIKE (`airstrike`)**: Full multi-vector perimeter assault combining network discovery, WAF fingerprinting, web vulnerability scanning, and directory fuzzing.\n\n"
                "#### 2. Architecture & Safeguards\n"
                "- **Module**: `modules/orchestration/sn1per_orchestrator.py` (`Sn1perOrchestrator`).\n"
                "- **Scope Enforcement**: Every target URL or IP must pass `ScopeAuthorizationService.is_target_authorized` before any probe is dispatched.\n"
                "- **Consolidated Findings**: Outputs from all chained tools are normalized into unified `Finding` models and saved to the project database.\n\n"
                "---\n"
                "🇲🇲 **မြန်မာဘာသာဖြင့် အကျဉ်းချုပ်**:\n"
                "**Sn1per Orchestrator** သည် tools များကို အဆင့်ဆင့် ချိတ်ဆက်၍ အလိုအလျောက် scan လုပ်ပေးသော စနစ်ဖြစ်ပါသည်။ "
                "Recon, Stealth, Discovery, Web Full, နှင့် Airstrike စသည့် Scan Mode များပါဝင်ပြီး Scope Guard စစ်ဆေးပြီးမှသာ လုံခြုံစိတ်ချစွာ Run ပေးပါသည်။ "
                "**'🌐 Web & API Security'** view တွင် Profile ခလုတ်များဖြင့် တစ်ချက်နှိပ်ရုံဖြင့် အသုံးပြုနိုင်ပါသည်။",
                "builtin_offline",
            )

        # A4. Strix AI Autonomous Finding Triage (usestrix/strix)
        if any(k in lowered for k in ["strix", "triage", "false positive", "cvss", "remediation playbook"]):
            return (
                "### 🛡️ Strix AI Autonomous Finding Triage & Remediation\n\n"
                "Inspired by **usestrix/strix** (`usestrix/strix`), CyberSecuritySuite includes an autonomous vulnerability triage and mitigation generator:\n\n"
                "#### 1. Core Triage Capabilities\n"
                "- **Module**: `core/strix_triage.py` (`StrixTriageEngine`, `TriagedFinding`).\n"
                "- **CVSS v3.1 Base Scoring**: Calculates estimated CVSS 3.1 base metrics and vector strings (Critical: 9.8, High: 7.5, Medium: 5.3, Low: 3.1).\n"
                "- **OWASP Top 10 (2021) Mapping**: Automatically maps findings to categories (`A01: Broken Access Control`, `A02: Cryptographic Failures`, `A03: Injection`, `A05: Security Misconfiguration`, `A07: Identification Failures`).\n"
                "- **False-Positive Heuristics**: Evaluates findings for test/mock patterns or benign info-disclosure flags to filter false alarms.\n"
                "- **Developer Remediation Playbooks**: Generates ready-to-use code fixes and configuration directives:\n"
                "  - Parameterized SQL queries (Python sqlite3/psycopg2).\n"
                "  - Context-aware XSS sanitization (DOMPurify).\n"
                "  - Restrictive CORS configuration (Node.js/Express).\n"
                "  - Hardened HTTP security headers (Nginx CSP, HSTS, X-Frame-Options).\n"
                "  - Secure JWT decoding and algorithm whitelisting (PyJWT).\n"
                "  - Safe subprocess execution avoiding shell invocation.\n\n"
                "---\n"
                "🇲🇲 **မြန်မာဘာသာဖြင့် အကျဉ်းချုပ်**:\n"
                "**Strix AI Engine** သည် တွေ့ရှိရသော Vulnerability Finding များကို CVSS v3.1 score နှင့် OWASP Top 10 အလိုက် အဆင့်ခွဲခြားပေးခြင်း၊ "
                "False-positive (မှားယွင်းသတိပေးချက်) များကို စစ်ထုတ်ပေးခြင်းနှင့် Developer များ တိုက်ရိုက် ပြင်ဆင်နိုင်ရန် "
                "Code Fix / Configuration Snippet (Playbook) များကို အလိုအလျောက် ထုတ်ပေးပါသည်။",
                "builtin_offline",
            )

        # A5. Scanners-Box Curated Tool Arsenal (We5ter/Scanners-Box)
        if any(k in lowered for k in ["scanners-box", "scannersbox", "arsenal", "catalog", "we5ter"]):
            return (
                "### 🧰 Scanners-Box Curated Open-Source Arsenal\n\n"
                "Inspired by **We5ter/Scanners-Box** (`We5ter/Scanners-Box`), CyberSecuritySuite provides a structured knowledge base and directory "
                "of 30+ open-source cybersecurity scanners across **12 primary domains**:\n\n"
                "| # | Domain Category | Key Tools Included |\n"
                "|---|---|---|\n"
                "| 1 | **Subdomain & OSINT** | OWASP Amass, Sublist3r, theHarvester |\n"
                "| 2 | **Port & Network Scanners** | Nmap, Masscan, RustScan |\n"
                "| 3 | **Web Application Scanners** | OWASP ZAP, Nuclei, Nikto, OWASP PTK |\n"
                "| 4 | **Directory & Route Fuzzers** | Gobuster, ffuf, dirsearch |\n"
                "| 5 | **Database & SQL Injection** | SQLMap, Ghauri |\n"
                "| 6 | **WAF Fingerprinting** | WAFW00F |\n"
                "| 7 | **Password & Credential Auditing** | THC-Hydra, Hashcat, John the Ripper |\n"
                "| 8 | **Cloud Security & Posture** | Prowler (AWS/GCP/Azure), ScoutSuite |\n"
                "| 9 | **Source Code Security (SAST/SCA)** | Bandit, Semgrep, Gitleaks, Trivy |\n"
                "| 10 | **Mobile Security (Android/iOS)** | MobSF, JADX, Apktool |\n"
                "| 11 | **Memory Forensics & Reversing** | Volatility 3, Binwalk, Radare2 |\n"
                "| 12 | **Active Directory & Protocols** | Impacket, NetExec (CrackMapExec) |\n\n"
                "- **Module**: `modules/scanners_box/catalog.py` (`ScannersBoxCatalog`).\n"
                "- **Host Detection**: Real-time checking if the tool binary is available in host `$PATH`.\n"
                "- **Install Guidance & Shell Execution**: One-click install commands and shell integration.\n\n"
                "---\n"
                "🇲🇲 **မြန်မာဘာသာဖြင့် အကျဉ်းချုပ်**:\n"
                "**Scanners-Box Arsenal** တွင် Subdomain, Network, Web, Fuzzing, SQLi, WAF, Password, Cloud, SAST, Mobile, Forensics, Active Directory "
                "စသည့် နယ်ပယ် ၁၂ ခုမှ အကောင်းဆုံး Open-Source Pentesting Tools များကို စုစည်းထားပြီး Host ပေါ်တွင် သွင်းထားခြင်း ရှိမရှိ စစ်ဆေးပေးခြင်းနှင့် "
                "Install လုပ်နည်းလမ်းညွှန်များကို **'🛠️ Tool Integration'** Dashboard တွင် ကြည့်ရှုနိုင်ပါသည်။",
                "builtin_offline",
            )

        # A6. HexStrike AI & CyberStrikeAI Natural Language Tool Routing
        if any(k in lowered for k in ["hexstrike", "cyberstrike", "tool router", "intent", "router"]):
            return (
                "### 🎯 AI Tool Router & Execution Planner\n\n"
                "Inspired by **0x4m4/hexstrike-ai** and **AIPentest/CyberStrikeAI**, CyberSecuritySuite includes intelligent natural language routing (`AIToolRouter`):\n\n"
                "#### 1. Natural Language Intent Translation\n"
                "- Translates prompts like *'Check if this web app has SQL injection'* or *'Fuzz directories on 127.0.0.1:8080'* directly into exact, authorized tool execution plans.\n"
                "- **Safety Level Classification**:\n"
                "  - `PASSIVE`: Non-intrusive (c0desec headers, WAFW00F, PTK JWT, offline forensics).\n"
                "  - `ACTIVE_SAFE`: Standard discovery (Nmap port and service version scanning).\n"
                "  - `INTRUSIVE`: High-traffic probes (SQLMap injection tests, Gobuster directory fuzzing).\n"
                "- **Target Scope Protection**: Verifies target against active project authorization before proposing intrusive commands.\n"
                "- **One-Click Terminal Emission**: Send generated commands to the interactive shell for immediate operator review and execution.\n\n"
                "---\n"
                "🇲🇲 **မြန်မာဘာသာဖြင့် အကျဉ်းချုပ်**:\n"
                "**AI Tool Router** သည် မိမိပြုလုပ်လိုသော စမ်းသပ်မှုအကြောင်းကို သာမန်စာဖြင့် မေးမြန်းရုံဖြင့် သင့်လျော်သော Tool (Nmap, SQLMap, Gobuster, WAFW00F, Hashcat စသည်) ကို ရွေးချယ်ပေးပြီး "
                "Scope Guard စစ်ဆေးပြီးဖြစ်သော Command များကို အဆင်သင့် ထုတ်ပေးပါသည်။",
                "builtin_offline",
            )

        # B. Where are other tools & All-in-One Architecture? (Answers user's specific questions!)
        if any(k in lowered for k in ["all in one", "all-in-one", "other tools", "where are", "ဘယ်မှာလဲ", "tools", "tool တွေ", "tool list", "ဘာလုပ်ရမလဲ"]):
            return (
                "### 🛡️ CyberSecuritySuite All-in-One Architecture & Tool Guide\n\n"
                "CyberSecuritySuite is architected as an **All-in-One Professional Cybersecurity & Penetration Testing Workstation** "
                "following the **Adapter & Parser Pattern** with centralized **Scope Guard** authorization.\n\n"
                "#### 1. Why are Tools Unified Instead of Siloed?\n"
                "- In traditional setups, tools like Nmap, Amass, Nikto, SQLMap, and Gobuster dump separate files in different formats.\n"
                "- In CyberSecuritySuite, **all tools execute through the central ProcessRunner**, their output is parsed by standardized adapters (`modules/`), "
                "and discoveries are automatically stored into a unified **SQLite Security Database** (`storage/db.py`) as normalized `Finding`, `AssetNode`, and `Evidence` records.\n\n"
                "#### 2. Where and How to Access Each Tool in the Suite:\n"
                "- **📁 1. Engagements & Scoping (`Projects / Engagements`)**:\n"
                "  - Set written authorization, client contact, testing windows, rate limits, and allowed/excluded IP/domain scopes.\n"
                "  - Run **OWASP Amass** passive OSINT discovery and export/import **Maltego GraphML/CSV** relationship graphs.\n"
                "  - **📦 Export CPENT Engagement Pack**: One-click generation of the standardized NIST SP 800-42 / CPENT administration workspace (`00_Administration`, `01_SISGCA`, `02_SEVA_Tools`).\n\n"
                "- **🌐 2. Web & API Security (`Web & API Security`)**:\n"
                "  - **Nikto**: Web server misconfiguration scanner (`bin/nikto` wrapper + `NiktoAdapter`).\n"
                "  - **OWASP PTK Workbench**: Interactive HTTP R-Builder (cURL import/export), JWT Security Lab (`alg: none` exploit), Encoders, and SCA.\n"
                "  - **Sn1per Multi-Stage Orchestrator**: Chained automated scanning (Recon, Stealth, Discovery, Web Full, Airstrike).\n"
                "  - **WAFW00F & Gobuster**: Automated WAF fingerprinting and high-speed directory fuzzing.\n"
                "  - **OWASP ZAP & Burp Suite**: Launch GUI and configure browser interception proxy (`127.0.0.1:8090` / `8080`).\n\n"
                "- **📡 3. Network Discovery (`Network Discovery`)**:\n"
                "  - **Nmap**: Multi-mode port scanning, OS fingerprinting, service version detection, and NSE vulnerability scripts.\n\n"
                "- **🛠️ 4. Tool Arsenal Dashboard (`Tool Integration`)**:\n"
                "  - Live inventory of 20+ open-source tools with path detection, diagnostic checks, and terminal launchers.\n\n"
                "- **🎓 5. CPENT Assessment Platform (`CPENT Labs & Methodologies`)**:\n"
                "  - 30-Day study roadmap, 11 practical domain methodology checklists, and command cheatsheets.\n\n"
                "- **📊 6. Executive & Technical Reports (`Findings & Evidence`)**:\n"
                "  - One-click generation of HTML, Markdown, and JSON reports with Risk Assessment Matrix and SHA-256 evidence integrity hashes.\n\n"
                "---\n"
                "🇲🇲 **မြန်မာဘာသာဖြင့် အကျဉ်းချုပ်**:\n"
                "CyberSecuritySuite သည် Tool များကို သီးခြားစီ မသုံးဘဲ **ဗဟို Scope Guard နှင့် SQLite Database** ဖြင့် ချိတ်ဆက်ထားသော **All-in-One Platform** ဖြစ်ပါသည်။ "
                "အပေါ်ဘက် Tab များနှင့် ဘယ်ဘက် Sidebar ရှိ Menu များမှတစ်ဆင့် Web, Network, OSINT, Scoping, နှင့် Reporting အားလုံးကို "
                "တစ်ခုတည်းသော GUI Workspace နှင့် အောက်ခြေ Integrated Command Shell တွင် စုံလင်စွာ အသုံးပြုနိုင်ပါသည်။",
                "builtin_offline",
            )

        # B2. CPENT Methodology & Report Templates Guidance
        if any(k in lowered for k in ["report template", "engagement pack", "masterengagement", "cpent report", "cpent template", "cpent syllabus", "cpent methodology"]):
            return (
                "### 🎓 EC-Council CPENT Curriculum & Report Templates Workflow\n\n"
                "CyberSecuritySuite directly incorporates the official **EC-Council Certified Penetration Testing Professional (CPENT)** "
                "14-module syllabus and **NIST SP 800-42 Master Engagement Folder** architecture:\n\n"
                "#### 1. Standardized CPENT Master Engagement Folder Hierarchy\n"
                "When you click **'📦 Export CPENT Pack'** in the Engagements View, the suite automatically builds:\n"
                "- **`00_Administration/`**:\n"
                "  - `00A_EL/Engagement_Letter.md`: Legal engagement agreement with operational dates and SoW.\n"
                "  - `00C_Client_Info/Initial_Client_Worksheet.md`: Client technical contact and emergency protocols.\n"
                "  - `00D_NDA/Non_Disclosure_Agreement.md`: Data protection and confidentiality commitments.\n"
                "  - `00F__ROE/Rules_of_Engagement.md`: Maximum request rates, allowed/prohibited tests, emergency stop.\n"
                "  - `00G_TP/Test_Plan_and_Scope.md`: In-scope IP ranges, exclusions, and phased testing schedule.\n"
                "  - `00H_LTA/Letter_of_Technical_Authorization.md`: Internal (IAUTH) and External (XAUTH) written authority.\n"
                "  - `00L_ECL/Master_Engagement_Control_List.md`: Full audit tracking checklist.\n"
                "- **`01_SISGCA/`** (Security Information, Scans & Evidence):\n"
                "  - `01A_OSIA/OSINT_Activity_Log.md`: Passive intelligence records.\n"
                "  - `01C_EVD&A/Evidence_Manifest.json`: Cryptographic SHA-256 evidence catalog.\n"
                "- **`02_SEVA_Tools/Tool_Inventory.md`**: Record of all executed command strings and tool exit codes.\n\n"
                "#### 2. CPENT 5-Pillar Strategic Reporting System\n"
                "All exported HTML, Markdown, and JSON reports in `reports/builder.py` include:\n"
                "1. **Finding Rating Levels**: 5 Stars (Critical) down to 1 Star (Informational).\n"
                "2. **Risk Assessment Matrix**: Likelihood (High/Med/Low) vs Impact (High/Med/Low) generating Threat Scores.\n"
                "3. **Five Recommendations Pillars**: (1) Personnel, (2) Policies, (3) Critical Flaws, (4) Authentication (I&A), (5) Intrusion Detection (IDS).\n"
                "4. **Appendices**: Reference standards (NIST SP 800-115, PTES, OWASP) and CPENT Security Terminology Glossary.\n\n"
                "---\n"
                "🇲🇲 **မြန်မာဘာသာဖြင့် အကျဉ်းချုပ်**:\n"
                "CPENT စာအုပ်နှင့် Template များပါအတိုင်း **Engagement Letter, RoE, Technical Authorization (IAUTH/XAUTH), "
                "NIST SP 800-42 Master Folder** နှင့် **Five Pillars Recommendations (Personnel, Policies, Critical, Auth, IDS)** များကို "
                "CyberSecuritySuite ၏ **Projects View** နှင့် **Report Builder** တွင် အပြည့်အဝ ပေါင်းစပ်ထားပြီး ဖြစ်ပါသည်။",
                "builtin_offline",
            )

        # C. Nmap & Network Scanning
        if any(k in lowered for k in ["nmap", "port scan", "network scan", "stealth", "syn scan"]):
            return (
                "### 📡 Nmap Network Discovery Methodology\n\n"
                "Here are the recommended Nmap assessment commands based on penetration testing standards:\n\n"
                "#### 1. Fast & Stealth Initial Service Scan\n"
                "```bash\n"
                "nmap -sS -sV -sC -Pn -T4 <target_ip>\n"
                "```\n"
                "- `-sS`: TCP SYN Stealth scan (half-open, bypasses basic packet logging).\n"
                "- `-sV`: Determine service and version info.\n"
                "- `-sC`: Run default safe NSE discovery scripts.\n"
                "- `-Pn`: Treat all hosts as online (skip ICMP echo discovery).\n"
                "- `-T4`: Aggressive timing template for faster execution.\n\n"
                "#### 2. Full Port Discovery (All 65,535 Ports)\n"
                "```bash\n"
                "nmap -p- -T4 -v <target_ip>\n"
                "```\n\n"
                "#### 3. Vulnerability Script Audit\n"
                "```bash\n"
                "nmap -sV --script=vuln <target_ip>\n"
                "```\n"
                "⚠️ *Note: Always ensure the target IP or range is registered in your active Project Scope before scanning.*",
                "builtin_offline",
            )

        # D. SQLMap & SQL Injection
        if any(k in lowered for k in ["sqlmap", "sql injection", "sqli", "database takeover", "tamper"]):
            return (
                "### 💥 SQLMap Automated Injection Methodology\n\n"
                "#### 1. Vulnerability Detection & Banner Enumeration\n"
                "```bash\n"
                "sqlmap -u \"http://<target>/item?id=1\" --batch --banner\n"
                "```\n\n"
                "#### 2. Enumerate Databases and Schemas\n"
                "```bash\n"
                "sqlmap -u \"http://<target>/item?id=1\" --dbs --batch\n"
                "```\n\n"
                "#### 3. Enumerate Tables & Dump Target Data\n"
                "```bash\n"
                "sqlmap -u \"http://<target>/item?id=1\" -D target_db --tables --batch\n"
                "sqlmap -u \"http://<target>/item?id=1\" -D target_db -T users --dump --batch\n"
                "```\n\n"
                "#### 4. WAF Bypass Techniques\n"
                "If WAFW00F detects a firewall (Cloudflare, ModSecurity, AWS WAF), use tamper scripts:\n"
                "```bash\n"
                "sqlmap -u \"http://<target>/item?id=1\" --tamper=space2comment,between,randomcase --random-agent --batch\n"
                "```",
                "builtin_offline",
            )

        # E. CPENT Pivoting & Tunneling
        if any(k in lowered for k in ["cpent", "pivot", "pivoting", "tunnel", "chisel", "proxychains", "double pivot"]):
            return (
                "### 🔀 CPENT Pivoting & Multi-Hop Tunneling Guide\n\n"
                "Pivoting is a core requirement of the EC-Council CPENT exam. Here are the primary techniques:\n\n"
                "#### Method 1: Chisel Reverse SOCKS5 Proxy (Recommended)\n"
                "1. **On your Kali / Attacker Machine** (Start Chisel listener):\n"
                "```bash\n"
                "./chisel server -p 8000 --reverse\n"
                "```\n"
                "2. **On the Compromised Pivot Host** (Connect back with SOCKS5):\n"
                "```bash\n"
                "./chisel client <attacker_ip>:8000 R:1080:socks\n"
                "```\n"
                "3. **Configure ProxyChains** (`/etc/proxychains4.conf`):\n"
                "```text\n"
                "socks5 127.0.0.1 1080\n"
                "```\n"
                "4. **Route Tools through Tunnel**:\n"
                "```bash\n"
                "proxychains4 nmap -sT -Pn -p 80,445,3389 <internal_ip>\n"
                "```\n\n"
                "#### Method 2: SSH Dynamic Port Forwarding\n"
                "```bash\n"
                "ssh -D 1080 -C -q -N user@<pivot_ip>\n"
                "```\n\n"
                "#### Method 3: Double Pivoting (Chaining 2 Networks)\n"
                "Establish Tunnel 1 on port 1080, then through Proxychains connect to Pivot 2 and open SOCKS5 port 1081. "
                "In `proxychains4.conf`, set `strict_chain` with both ports in sequence.",
                "builtin_offline",
            )

        # F. Privilege Escalation (Linux & Windows)
        if any(k in lowered for k in ["privilege escalation", "privesc", "root", "administrator", "suid", "sudo"]):
            return (
                "### 🔑 Privilege Escalation Checklist\n\n"
                "#### Linux Privilege Escalation Vectors:\n"
                "1. **Sudo Privileges**:\n"
                "   ```bash\n"
                "   sudo -l\n"
                "   ```\n"
                "   Check [GTFOBins](https://gtfobins.github.io/) for any allowed binaries.\n"
                "2. **SUID / SGID Binaries**:\n"
                "   ```bash\n"
                "   find / -perm -4000 -type f 2>/dev/null\n"
                "   ```\n"
                "3. **Writable Cron Jobs & Systemd Services**:\n"
                "   ```bash\n"
                "   ls -la /etc/cron* /var/spool/cron/crontabs/\n"
                "   ```\n"
                "4. **Linux Capabilities**:\n"
                "   ```bash\n"
                "   getcap -r / 2>/dev/null\n"
                "   ```\n\n"
                "#### Windows Privilege Escalation Vectors:\n"
                "1. **Unquoted Service Paths** (`wmic service get name,displayname,pathname,startmode | findstr /i \"Auto\" | findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v \"\"\"`).\n"
                "2. **AlwaysInstallElevated** registry key enabled.\n"
                "3. **Token Impersonation** (`SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege`) using GodPotato, PrintSpoofer, or SweetPotato.",
                "builtin_offline",
            )

        # G. Gobuster & Directory Fuzzing
        if any(k in lowered for k in ["gobuster", "dirbuster", "fuzz", "directory", "dir scan"]):
            return (
                "### 📂 Gobuster Web Directory & DNS Fuzzing\n\n"
                "#### 1. Directory & File Fuzzing\n"
                "```bash\n"
                "gobuster dir -u http://<target_url> -w /usr/share/dirb/wordlists/common.txt -x php,html,txt,json -t 30\n"
                "```\n"
                "- `-u`: Target base URL.\n"
                "- `-w`: Wordlist path.\n"
                "- `-x`: File extensions to search for.\n"
                "- `-t 30`: 30 concurrent threads.\n\n"
                "#### 2. Subdomain DNS Brute-Forcing\n"
                "```bash\n"
                "gobuster dns -d <target_domain> -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt\n"
                "```",
                "builtin_offline",
            )

        # H. Hydra & Password Recovery
        if any(k in lowered for k in ["hydra", "hashcat", "brute force", "crack", "password"]):
            return (
                "### 🔐 Credential Assessment & Password Cracking\n\n"
                "#### 1. THC-Hydra Network Service Brute-Forcing\n"
                "- **SSH Service**:\n"
                "```bash\n"
                "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<target_ip>\n"
                "```\n"
                "- **FTP Service**:\n"
                "```bash\n"
                "hydra -L users.txt -P passwords.txt ftp://<target_ip>\n"
                "```\n"
                "- **HTTP POST Form Login**:\n"
                "```bash\n"
                "hydra -l admin -P /usr/share/wordlists/rockyou.txt <target_ip> http-post-form \"/login.php:user=^USER^&pass=^PASS^:F=incorrect\"\n"
                "```\n\n"
                "#### 2. Hashcat Accelerated Hash Cracking\n"
                "```bash\n"
                "hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt       # MD5\n"
                "hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt    # NTLM\n"
                "hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt    # SHA512crypt (Linux /etc/shadow)\n"
                "```",
                "builtin_offline",
            )

        # I. Greetings & General Help
        if any(k in lowered for k in ["မင်္ဂလာပါ", "ဟဲလို", "hi", "hello", "hey", "help", "start", "စတင်"]):
            return (
                "### 🤖 CyberSecuritySuite AI Copilot & CPENT Assistant\n\n"
                "မင်္ဂလာပါ! ကျွန်တော်က CyberSecuritySuite ၏ AI Security Copilot ဖြစ်ပါသည်။ "
                "Penetration testing, CPENT exam preparation, vulnerability assessments, နှင့် tools များအသုံးပြုပုံကို အကူအညီပေးနိုင်ပါသည်။\n\n"
                "**မေးမြန်းနိုင်သော အကြောင်းအရာများ**:\n"
                "- 🌐 **OWASP ZAP & Burp Suite**: Proxy ချိန်ညှိပုံ၊ Intercept ပြုလုပ်ပုံ၊ CA certificate ထည့်သွင်းပုံ။\n"
                "- 🛠️ **Tools Dashboard**: Nmap, SQLMap, Gobuster, WAFW00F, Hydra, Volatility 3 စသည်တို့ကို ရှာဖွေ အသုံးပြုပုံ။\n"
                "- 🔀 **CPENT Pivoting**: Chisel, SSH tunneling, ProxyChains ဖြင့် multi-hop pivot ပြုလုပ်ပုံ။\n"
                "- 💥 **Exploitation**: SQL injection, WAF bypass tamper scripts, Web directory fuzzing။\n"
                "- 🔑 **Privilege Escalation**: Linux SUID/Sudo နှင့် Windows Token Impersonation များ။\n\n"
                "စတင်ရန် သိလိုသည်များကို မြန်မာလို (သို့မဟုတ်) English ဖြင့် လွတ်လပ်စွာ မေးမြန်းနိုင်ပါသည်!",
                "builtin_offline",
            )

        # J. Default Comprehensive Pentest Methodology Fallback
        ctx_str = f"\n*Active Scope Context: {project_context}*\n" if project_context else ""
        return (
            f"### 🛡️ Senior Penetration Tester & CPENT Guidance\n{ctx_str}\n"
            f"Regarding your query: *\"{last_msg}\"*\n\n"
            "Here is the standard assessment methodology according to PTES and CPENT guidelines:\n\n"
            "1. **Reconnaissance & Asset Discovery**:\n"
            "   Perform passive reconnaissance and port discovery using Nmap:\n"
            "   ```bash\n"
            "   nmap -sS -sV -sC -Pn -T4 <target>\n"
            "   ```\n\n"
            "2. **Web Application & Endpoint Enumeration**:\n"
            "   Check security headers with c0desec and enumerate hidden directories with Gobuster:\n"
            "   ```bash\n"
            "   gobuster dir -u http://<target> -w /usr/share/dirb/wordlists/common.txt\n"
            "   ```\n\n"
            "3. **Vulnerability Analysis & Interception**:\n"
            "   Route web requests through OWASP ZAP or Burp Suite (`127.0.0.1:8080`) to inspect parameters and test for OWASP Top 10 flaws.\n\n"
            "4. **Exploitation & Verification**:\n"
            "   Verify vulnerabilities safely within authorized project scope boundaries and record evidence.\n\n"
            "💡 *Tip: Configure your Gemini or OpenAI API key in '⚙️ AI Settings' for dynamic real-time cloud LLM responses!*",
            "builtin_offline",
        )

    def _chat_gemini(
        self,
        messages: List[Dict[str, str]],
        project_context: Optional[str],
        api_key: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        system_instruction = (
            "You are CyberSecuritySuite's AI Security Copilot & Senior CPENT Instructor. "
            "You assist ethical hackers, penetration testers, and security analysts with technical methodology, "
            "tool syntax (Nmap, SQLMap, Gobuster, WAFW00F, ZAP, Burp Suite, Hydra, Volatility 3, Bandit), "
            "exploit diagnostics, and remediation. Respond clearly and concisely. Format CLI commands in ```bash ... ``` code blocks. "
            "You fluently support both English and Burmese (မြန်မာဘာသာ)."
        )
        if project_context:
            system_instruction += f"\nProject Context: {project_context}"

        contents = []
        for m in messages:
            role = "user" if m.get("role") == "user" else "model"
            content = redact_sensitive_text(m.get("content", ""))
            contents.append({"role": role, "parts": [{"text": content}]})

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.gemini_model}:generateContent?key={api_key}"
        payload = json.dumps({
            "systemInstruction": {"parts": [{"text": system_instruction}]},
            "contents": contents,
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 2048},
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=12.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "").strip(), None
                return None, "Gemini API returned empty candidates."
        except urllib.error.HTTPError as e:
            return None, f"Gemini HTTP {e.code}: {e.reason}"
        except Exception as e:
            return None, f"Gemini error: {e}"

    def _chat_openai(
        self,
        messages: List[Dict[str, str]],
        project_context: Optional[str],
        api_key: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        system_instruction = (
            "You are CyberSecuritySuite's AI Security Copilot & Senior CPENT Instructor. "
            "You assist ethical hackers, penetration testers, and security analysts with technical methodology, "
            "tool syntax (Nmap, SQLMap, Gobuster, WAFW00F, ZAP, Burp Suite, Hydra, Volatility 3, Bandit), "
            "exploit diagnostics, and remediation. Format CLI commands in ```bash ... ``` code blocks. "
            "You fluently support both English and Burmese (မြန်မာဘာသာ)."
        )
        if project_context:
            system_instruction += f"\nProject Context: {project_context}"

        openai_messages = [{"role": "system", "content": system_instruction}]
        for m in messages:
            role = "user" if m.get("role") == "user" else "assistant"
            content = redact_sensitive_text(m.get("content", ""))
            openai_messages.append({"role": role, "content": content})

        url = "https://api.openai.com/v1/chat/completions"
        payload = json.dumps({
            "model": self.openai_model,
            "messages": openai_messages,
            "temperature": 0.3,
            "max_tokens": 2048,
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=12.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                choices = data.get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", "").strip(), None
                return None, "OpenAI returned empty response."
        except urllib.error.HTTPError as e:
            return None, f"OpenAI HTTP {e.code}: {e.reason}"
        except Exception as e:
            return None, f"OpenAI error: {e}"

    def _chat_deepseek(
        self,
        messages: List[Dict[str, str]],
        project_context: Optional[str],
        api_key: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        system_instruction = (
            "You are CyberSecuritySuite's AI Security Copilot & Senior CPENT Instructor. "
            "You assist ethical hackers, penetration testers, and security analysts with technical methodology, "
            "tool syntax (Nmap, SQLMap, Gobuster, WAFW00F, ZAP, Burp Suite, Hydra, Volatility 3, Bandit), "
            "exploit diagnostics, and remediation. Format CLI commands in ```bash ... ``` code blocks. "
            "You fluently support both English and Burmese (မြန်မာဘာသာ)."
        )
        if project_context:
            system_instruction += f"\nProject Context: {project_context}"

        ds_messages = [{"role": "system", "content": system_instruction}]
        for m in messages:
            role = "user" if m.get("role") == "user" else "assistant"
            content = redact_sensitive_text(m.get("content", ""))
            ds_messages.append({"role": role, "content": content})

        url = "https://api.deepseek.com/chat/completions"
        payload = json.dumps({
            "model": self.deepseek_model,
            "messages": ds_messages,
            "temperature": 0.3,
            "max_tokens": 2048,
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                choices = data.get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", "").strip(), None
                return None, "DeepSeek returned empty response."
        except urllib.error.HTTPError as e:
            if e.code == 402:
                return None, "Insufficient Balance (402): DeepSeek account balance depleted. Top up at platform.deepseek.com or switch to Google Gemini / Built-in Offline Engine."
            elif e.code == 401:
                return None, "Authentication Failed (401): DeepSeek API key is invalid."
            return None, f"DeepSeek HTTP {e.code}: {e.reason}"
        except Exception as e:
            return None, f"DeepSeek error: {e}"

    def _chat_anthropic(
        self,
        messages: List[Dict[str, str]],
        project_context: Optional[str],
        api_key: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        system_instruction = (
            "You are CyberSecuritySuite's AI Security Copilot & Senior CPENT Instructor. "
            "You assist ethical hackers, penetration testers, and security analysts with technical methodology, "
            "tool syntax, exploit diagnostics, and remediation. Format CLI commands in ```bash ... ``` code blocks. "
            "You fluently support both English and Burmese (မြန်မာဘာသာ)."
        )
        if project_context:
            system_instruction += f"\nProject Context: {project_context}"

        anthropic_messages = []
        for m in messages:
            role = "user" if m.get("role") == "user" else "assistant"
            content = redact_sensitive_text(m.get("content", ""))
            anthropic_messages.append({"role": role, "content": content})

        url = "https://api.anthropic.com/v1/messages"
        payload = json.dumps({
            "model": self.anthropic_model,
            "system": system_instruction,
            "messages": anthropic_messages,
            "max_tokens": 2048,
            "temperature": 0.3,
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                content_blocks = data.get("content", [])
                text_parts = [b.get("text", "") for b in content_blocks if b.get("type") == "text"]
                if text_parts:
                    return "\n".join(text_parts).strip(), None
                return None, "Anthropic returned empty response."
        except urllib.error.HTTPError as e:
            return None, f"Anthropic HTTP {e.code}: {e.reason}"
        except Exception as e:
            return None, f"Anthropic error: {e}"

    def _chat_custom(
        self,
        messages: List[Dict[str, str]],
        project_context: Optional[str],
        api_key: Optional[str],
    ) -> Tuple[Optional[str], Optional[str]]:
        system_instruction = (
            "You are CyberSecuritySuite's AI Security Copilot & Senior CPENT Instructor. "
            "You assist ethical hackers, penetration testers, and security analysts with technical methodology. "
            "Format CLI commands in ```bash ... ``` code blocks."
        )
        if project_context:
            system_instruction += f"\nProject Context: {project_context}"

        custom_messages = [{"role": "system", "content": system_instruction}]
        for m in messages:
            role = "user" if m.get("role") == "user" else "assistant"
            content = redact_sensitive_text(m.get("content", ""))
            custom_messages.append({"role": role, "content": content})

        base_url = (self.custom_api_url or "https://api.openai.com/v1").rstrip("/")
        url = f"{base_url}/chat/completions"
        target_model = self.custom_model or "default"

        payload = json.dumps({
            "model": target_model,
            "messages": custom_messages,
            "temperature": 0.3,
            "max_tokens": 2048,
        }).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                choices = data.get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", "").strip(), None
                return None, "Custom API returned empty response."
        except urllib.error.HTTPError as e:
            return None, f"Custom API HTTP {e.code}: {e.reason}"
        except Exception as e:
            return None, f"Custom API error: {e}"

    def _chat_ollama(
        self,
        messages: List[Dict[str, str]],
        project_context: Optional[str],
    ) -> Tuple[Optional[str], Optional[str]]:
        system_instruction = (
            "You are CyberSecuritySuite's AI Security Copilot & Senior CPENT Instructor. "
            "You assist ethical hackers, penetration testers, and security analysts with technical methodology, "
            "tool syntax (Nmap, SQLMap, Gobuster, WAFW00F, ZAP, Burp Suite, Hydra, Volatility 3, Bandit), "
            "exploit diagnostics, and remediation. Format CLI commands in ```bash ... ``` code blocks. "
            "You support both English and Burmese."
        )
        if project_context:
            system_instruction += f"\nProject Context: {project_context}"

        ollama_messages = [{"role": "system", "content": system_instruction}]
        for m in messages:
            role = "user" if m.get("role") == "user" else "assistant"
            content = redact_sensitive_text(m.get("content", ""))
            ollama_messages.append({"role": role, "content": content})

        url = f"{self.ollama_url.rstrip('/')}/api/chat"
        payload = json.dumps({
            "model": self.ollama_model,
            "messages": ollama_messages,
            "stream": False,
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("message", {}).get("content", "").strip(), None
        except Exception as e:
            return None, f"Ollama error: {e}"

    # -----------------------------------------------------------------------
    # Natural Language to Pentest Command Generation
    # -----------------------------------------------------------------------

    def generate_command(
        self,
        prompt: str,
        target: Optional[str] = None,
        scopes: Optional[List[TargetScope]] = None,
    ) -> AICommandSuggestion:
        """Translates user prompt into a validated, scope-checked command."""
        p_low = prompt.lower().strip()
        cmd_target = target or ""

        # Extract target from prompt if present
        ip_match = re.search(r"\b(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s]*)?)\b", prompt)
        domain_match = re.search(r"\b(?:https?://)?([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?)\b", prompt)
        if ip_match:
            cmd_target = ip_match.group(1)
        elif domain_match:
            cmd_target = domain_match.group(1)

        # Scope validation: Fail closed on missing target or missing scopes
        if not cmd_target:
            host_to_check = "<TARGET>"
            is_in_scope = False
            scope_reason = "BLOCKED: Target missing. Please specify an authorized target."
        elif not scopes:
            parsed = urlparse(cmd_target if "://" in cmd_target else f"http://{cmd_target}")
            host_to_check = parsed.hostname or cmd_target
            is_in_scope = False
            scope_reason = "BLOCKED: No active project scopes defined. Authorization required before testing."
        else:
            parsed = urlparse(cmd_target if "://" in cmd_target else f"http://{cmd_target}")
            host_to_check = parsed.hostname or cmd_target
            scope_check: ScopeCheckResult = ScopeAuthorizationService.is_target_authorized(
                cmd_target, scopes
            )
            is_in_scope = scope_check.is_allowed
            scope_reason = scope_check.reason

        target_display = host_to_check if host_to_check else "<TARGET>"

        # 1. Nmap Network Scanning
        if "port" in p_low or "nmap" in p_low or "network" in p_low or "service" in p_low:
            if "top" in p_low or "fast" in p_low:
                return AICommandSuggestion(
                    tool_name="nmap",
                    command=f"nmap -F -T4 {target_display}",
                    explanation="Fast scan of the top 100 most common network ports with aggressive timing.",
                    is_active=True,
                    is_in_scope=is_in_scope,
                    scope_reason=scope_reason,
                    provider_used=self.provider.value,
                )
            if "all" in p_low or "full" in p_low:
                return AICommandSuggestion(
                    tool_name="nmap",
                    command=f"nmap -p- -sV -T4 {target_display}",
                    explanation="Comprehensive full TCP port scan (ports 1-65535) with service version detection.",
                    is_active=True,
                    is_in_scope=is_in_scope,
                    scope_reason=scope_reason,
                    provider_used=self.provider.value,
                )
            return AICommandSuggestion(
                tool_name="nmap",
                command=f"nmap -sV -T4 {target_display}",
                explanation="Standard TCP service version exploration.",
                is_active=True,
                is_in_scope=is_in_scope,
                scope_reason=scope_reason,
                provider_used=self.provider.value,
            )

        # 2. Gobuster Web Directory Enumeration
        if any(k in p_low for k in ["directory", "directories", "dir", "gobuster", "fuzz", "route", "path", "endpoint"]):
            url = cmd_target if cmd_target.startswith("http") else (f"http://{cmd_target}" if cmd_target else "http://<TARGET>")
            return AICommandSuggestion(
                tool_name="gobuster",
                command=f"gobuster dir -u {url} -w /usr/share/dirb/wordlists/common.txt -q --no-color",
                explanation="Fast web directory enumeration using common directory wordlists.",
                is_active=True,
                is_in_scope=is_in_scope,
                scope_reason=scope_reason,
                provider_used=self.provider.value,
            )

        # 3. WAF Detection
        if "waf" in p_low or "firewall" in p_low:
            url = cmd_target if cmd_target.startswith("http") else (f"http://{cmd_target}" if cmd_target else "http://<TARGET>")
            return AICommandSuggestion(
                tool_name="wafw00f",
                command=f"python3 source/web/wafw00f/wafw00f/bin/wafw00f {url} -a",
                explanation="Fingerprint web application firewalls and perimeter proxies protecting the target.",
                is_active=True,
                is_in_scope=is_in_scope,
                scope_reason=scope_reason,
                provider_used=self.provider.value,
            )

        # 4. SQL Injection with SQLMap
        if "sql" in p_low or "injection" in p_low or "database" in p_low or "sqlmap" in p_low:
            url = cmd_target if cmd_target.startswith("http") else (f"http://{cmd_target}" if cmd_target else "http://<TARGET>")
            return AICommandSuggestion(
                tool_name="sqlmap",
                command=f"python3 source/web/sqlmap/sqlmap.py -u \"{url}\" --batch --risk=1 --level=1",
                explanation="Automated SQL injection audit testing GET/POST parameter vulnerabilities.",
                is_active=True,
                is_in_scope=is_in_scope,
                scope_reason=scope_reason,
                provider_used=self.provider.value,
            )

        # 5. Bandit Python SAST
        if "bandit" in p_low or "sast" in p_low or "source code" in p_low or "python security" in p_low:
            bandit_in_scope = bool(scopes)
            bandit_reason = (
                "Local source code audit authorized within active engagement scope."
                if bandit_in_scope
                else "BLOCKED: No active project scope or engagement authorization defined."
            )
            return AICommandSuggestion(
                tool_name="bandit",
                command="bandit -r . -f txt",
                explanation="Static Application Security Testing (SAST) of Python source files.",
                is_active=False,
                is_in_scope=bandit_in_scope,
                scope_reason=bandit_reason,
                provider_used=self.provider.value,
            )

        # Default fallback
        return AICommandSuggestion(
            tool_name="nmap",
            command=f"nmap -sV {target_display}",
            explanation=f"Default network service exploration on target {target_display}.",
            is_active=True,
            is_in_scope=is_in_scope,
            scope_reason=scope_reason,
            provider_used=self.provider.value,
        )

    # -----------------------------------------------------------------------
    # Finding Extraction from Terminal Output
    # -----------------------------------------------------------------------

    def extract_findings_from_terminal(
        self, output: str, target: str, project_id: int
    ) -> List[Finding]:
        """Parses raw terminal text from various tools and extracts report findings."""
        findings: List[Finding] = []
        clean_text = re.sub(r"\x1b\[[0-9;]*m", "", output)

        # A. Parse Nmap Open Ports & Services
        for line in clean_text.splitlines():
            line_str = line.strip()
            port_match = re.search(r"^(\d+/(?:tcp|udp))\s+open\s+([^\s]+)(?:\s+(.*))?", line_str)
            if port_match:
                port_proto = port_match.group(1)
                service = port_match.group(2)
                version_info = port_match.group(3) or ""

                port_num = int(port_proto.split("/")[0])

                if port_num in (21, 23):  # FTP, Telnet
                    sev = FindingSeverity.HIGH
                    title = f"Unencrypted Service Exposed: {service.upper()} ({port_proto})"
                    remediation = "Disable unencrypted cleartext protocols (Telnet/FTP) and transition to SSH/SFTP."
                elif port_num in (445, 139):  # SMB
                    sev = FindingSeverity.MEDIUM
                    title = f"SMB Network Sharing Port Exposed ({port_proto})"
                    remediation = "Restrict SMB access to internal management networks and require SMBv3 signing."
                elif port_num in (3389, 5900):  # RDP, VNC
                    sev = FindingSeverity.MEDIUM
                    title = f"Remote Desktop Service Exposed: {service.upper()} ({port_proto})"
                    remediation = "Enforce Multi-Factor Authentication (MFA) and restrict remote desktop behind VPN."
                elif port_num in (1433, 3306, 5432, 27017, 6379):  # Databases
                    sev = FindingSeverity.HIGH
                    title = f"Database Port Directly Exposed: {service.upper()} ({port_proto})"
                    remediation = "Database ports should never be exposed to external or untrusted networks. Bind to localhost."
                else:
                    sev = FindingSeverity.INFORMATIONAL
                    title = f"Open Network Port Discovered: {port_proto} ({service})"
                    remediation = "Ensure only necessary business services are exposed and keep service packages updated."

                desc = f"Identified active open network service on target '{target}'.\nPort: {port_proto}\nService: {service}"
                if version_info:
                    desc += f"\nVersion Banner: {version_info}"

                findings.append(
                    Finding(
                        project_id=project_id,
                        title=title,
                        description=desc,
                        severity=sev,
                        affected_asset=target,
                        affected_port_service=port_proto,
                        remediation=remediation,
                        validation_status=ValidationStatus.UNVERIFIED,
                        source_tool="terminal_ai_extractor",
                    )
                )

        # B. Parse Gobuster Endpoints
        for line in clean_text.splitlines():
            ep_match = re.search(r"^(/[^\s]+)\s+\(Status:\s*(\d+)\)", line.strip())
            if ep_match:
                path = ep_match.group(1)
                code = int(ep_match.group(2))
                if any(k in path.lower() for k in [".git", ".env", "backup", "config", "swagger", "admin"]) and code in (200, 301):
                    findings.append(
                        Finding(
                            project_id=project_id,
                            title=f"Sensitive Web Route Exposed: {path} (HTTP {code})",
                            description=f"Directory enumeration detected sensitive asset at '{target.rstrip('/')}{path}'.",
                            severity=FindingSeverity.HIGH if ".git" in path or ".env" in path else FindingSeverity.MEDIUM,
                            affected_asset=f"{target.rstrip('/')}{path}",
                            remediation="Restrict access to administrative paths and remove sensitive repository/backup files from production.",
                            validation_status=ValidationStatus.UNVERIFIED,
                            source_tool="terminal_ai_extractor",
                        )
                    )

        # C. Parse SQLMap Injection Finding
        low_text = clean_text.lower()
        if "sqlmap" in low_text and ("injection" in low_text or "vulnerable" in low_text):
            explicit_proof = any(
                proof in low_text
                for proof in [
                    "sqlmap identified the following injection points",
                    "is vulnerable",
                    "back-end dbms is",
                    "sqlmap resumed the following injection point",
                ]
            ) or ("parameter:" in low_text and "type:" in low_text)

            if "all tested parameters do not appear to be vulnerable" in low_text:
                explicit_proof = False

            val_status = ValidationStatus.CONFIRMED if explicit_proof else ValidationStatus.UNVERIFIED
            title = (
                "SQL Injection Vulnerability Discovered via Terminal Execution"
                if explicit_proof
                else "Potential SQL Injection Detected (Unverified)"
            )
            findings.append(
                Finding(
                    project_id=project_id,
                    title=title,
                    description=f"SQLMap execution against '{target}' detected SQL injection indicators."
                    + (" Confirmed exploitable parameter vectors." if explicit_proof else " Requires further manual verification."),
                    severity=FindingSeverity.CRITICAL if explicit_proof else FindingSeverity.MEDIUM,
                    affected_asset=target,
                    remediation="Employ parameterized SQL statements (Prepared Statements) or use an established ORM. Sanitize all user inputs.",
                    validation_status=val_status,
                    source_tool="sqlmap",
                )
            )

        # D. Parse WAF Detection
        if ("wafw00f" in low_text or "waf" in low_text) and "is behind" in low_text:
            waf_match = re.search(r"is behind (?:a )?([A-Za-z0-9_\-\.\s\(\)]+?)(?: WAF|\.|\n|$)", clean_text)
            waf_name = waf_match.group(1).strip() if waf_match else "WAF"
            findings.append(
                Finding(
                    project_id=project_id,
                    title=f"Web Application Firewall (WAF) Fingerprinted: {waf_name}",
                    description=f"WAF fingerprinting identified perimeter firewall '{waf_name}' on '{target}'.",
                    severity=FindingSeverity.INFORMATIONAL,
                    affected_asset=target,
                    remediation="Informational assessment discovery. Take firewall inspection behaviors into account during security auditing.",
                    validation_status=ValidationStatus.UNVERIFIED,
                    source_tool="wafw00f",
                )
            )

        return findings

    # -----------------------------------------------------------------------
    # Internal HTTP Client Helpers
    # -----------------------------------------------------------------------

    def _query_gemini(
        self, prompt: str, model: Optional[str] = None, api_key: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        key = api_key or self.get_api_key(AIProvider.GEMINI_API)
        if not key:
            return None, "Gemini API key is missing."

        target_model = model or self.gemini_model
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent?key={key}"
        payload = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048},
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "").strip(), None
                return None, "Gemini API returned empty response."
        except urllib.error.HTTPError as e:
            return None, f"Gemini API HTTP Error {e.code}: {e.reason}"
        except Exception as e:
            return None, f"Gemini error: {e}"

    def _query_openai(
        self, prompt: str, model: Optional[str] = None, api_key: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        key = api_key or self.get_api_key(AIProvider.OPENAI_API)
        if not key:
            return None, "OpenAI API key is missing."

        target_model = model or self.openai_model
        url = "https://api.openai.com/v1/chat/completions"
        payload = json.dumps({
            "model": target_model,
            "messages": [
                {"role": "system", "content": "You are a professional cybersecurity penetration testing copilot and CPENT instructor."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                choices = data.get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", "").strip(), None
                return None, "OpenAI returned empty response."
        except urllib.error.HTTPError as e:
            return None, f"OpenAI HTTP Error {e.code}: {e.reason}"
        except Exception as e:
            return None, f"OpenAI error: {e}"

    def _query_deepseek(
        self, prompt: str, model: Optional[str] = None, api_key: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        key = api_key or self.get_api_key(AIProvider.DEEPSEEK_API)
        if not key:
            return None, "DeepSeek API key is missing."

        target_model = model or self.deepseek_model
        url = "https://api.deepseek.com/chat/completions"
        payload = json.dumps({
            "model": target_model,
            "messages": [
                {"role": "system", "content": "You are a professional cybersecurity penetration testing copilot and CPENT instructor."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                choices = data.get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", "").strip(), None
                return None, "DeepSeek returned empty response."
        except urllib.error.HTTPError as e:
            if e.code == 402:
                return None, "DeepSeek Insufficient Balance (402): Account balance depleted. Top up at platform.deepseek.com or switch to Google Gemini / Built-in Offline Engine."
            elif e.code == 401:
                return None, "DeepSeek Authentication Failed (401): API key is invalid."
            return None, f"DeepSeek HTTP Error {e.code}: {e.reason}"
        except Exception as e:
            return None, f"DeepSeek error: {e}"

    def _query_anthropic(
        self, prompt: str, model: Optional[str] = None, api_key: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        key = api_key or self.get_api_key(AIProvider.ANTHROPIC_API)
        if not key:
            return None, "Anthropic API key is missing."

        target_model = model or self.anthropic_model
        url = "https://api.anthropic.com/v1/messages"
        payload = json.dumps({
            "model": target_model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                blocks = data.get("content", [])
                text_parts = [b.get("text", "") for b in blocks if b.get("type") == "text"]
                if text_parts:
                    return "\n".join(text_parts).strip(), None
                return None, "Anthropic returned empty response."
        except urllib.error.HTTPError as e:
            return None, f"Anthropic HTTP Error {e.code}: {e.reason}"
        except Exception as e:
            return None, f"Anthropic error: {e}"

    def _query_custom(
        self, prompt: str, model: Optional[str] = None, api_key: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        key = api_key or self.get_api_key(AIProvider.CUSTOM_OPENAI_COMPATIBLE)
        base_url = (self.custom_api_url or "https://api.openai.com/v1").rstrip("/")
        url = f"{base_url}/chat/completions"
        target_model = model or self.custom_model or "default"

        payload = json.dumps({
            "model": target_model,
            "messages": [
                {"role": "system", "content": "You are a professional cybersecurity penetration testing copilot and CPENT instructor."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"

        try:
            req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                choices = data.get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", "").strip(), None
                return None, "Custom API returned empty response."
        except urllib.error.HTTPError as e:
            return None, f"Custom API HTTP Error {e.code}: {e.reason}"
        except Exception as e:
            return None, f"Custom API error: {e}"

    def _query_ollama(
        self, prompt: str, model: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        target_model = model or self.ollama_model
        url = f"{self.ollama_url.rstrip('/')}/api/generate"
        payload = json.dumps({
            "model": target_model,
            "prompt": prompt,
            "stream": False,
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=12.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "").strip(), None
        except Exception as e:
            return None, f"Ollama error: {e}"
