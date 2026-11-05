"""Enterprise Multi-Provider AI Model Router with 3-Tier Fallback Chain.

Manages intelligent failover across AI providers (Google Gemini, OpenAI, Anthropic,
OpenRouter, DeepSeek, Local Ollama, and Built-in Offline Heuristics).
Provides:
- 3-tier fallback routing chain: Primary -> Secondary -> Final Fallback.
- Safe secret handling with CredentialManager integration.
- Sensitive credential and token redaction before any external transmission.
- Token consumption tracking (prompt, completion, total) and reference cost estimation.
- Comprehensive connection verification and diagnostic reporting.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.credential_manager import CredentialManager

logger = logging.getLogger(__name__)


class AIProvider(str, Enum):
    BUILTIN_OFFLINE = "builtin_offline"
    LOCAL_OLLAMA = "local_ollama"
    GEMINI_API = "gemini_api"
    OPENAI_API = "openai_api"
    ANTHROPIC_API = "anthropic_api"
    OPENROUTER_API = "openrouter_api"
    DEEPSEEK_API = "deepseek_api"
    CUSTOM_OPENAI_COMPATIBLE = "custom_openai_compatible"


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


@dataclass
class ModelTierConfig:
    provider: AIProvider
    model_name: str
    api_key: Optional[str] = None
    api_url: Optional[str] = None
    timeout_seconds: float = 20.0
    max_retries: int = 1


@dataclass
class AIResponse:
    content: str
    provider_used: AIProvider
    model_used: str
    fallback_occurred: bool = False
    failover_history: List[Dict[str, Any]] = field(default_factory=list)
    token_usage: TokenUsage = field(default_factory=TokenUsage)
    duration_seconds: float = 0.0
    success: bool = True
    error_message: Optional[str] = None


class ReferencePricing:
    """Official published token pricing (USD per 1,000,000 tokens) for accurate cost estimation."""

    RATES: Dict[str, Tuple[float, float]] = {
        # Format: (prompt_per_1m, completion_per_1m)
        "gemini-1.5-flash": (0.075, 0.30),
        "gemini-1.5-pro": (1.25, 5.00),
        "gemini-2.0-flash": (0.10, 0.40),
        "gpt-4o-mini": (0.15, 0.60),
        "gpt-4o": (2.50, 10.00),
        "claude-3-5-sonnet-20241022": (3.00, 15.00),
        "claude-3-5-haiku-20241022": (0.80, 4.00),
        "deepseek-chat": (0.14, 0.28),
        "deepseek-reasoner": (0.55, 2.19),
        "meta-llama/llama-3.3-70b-instruct": (0.70, 0.80),
    }

    @classmethod
    def calculate_cost(cls, model_name: str, prompt_tokens: int, completion_tokens: int) -> float:
        model_lower = (model_name or "").lower().strip()
        matched_rate = None
        for key, rate in cls.RATES.items():
            if key in model_lower:
                matched_rate = rate
                break

        if not matched_rate:
            return 0.0

        p_rate, c_rate = matched_rate
        cost = (prompt_tokens / 1_000_000.0 * p_rate) + (completion_tokens / 1_000_000.0 * c_rate)
        return round(cost, 6)


class AIUsageTracker:
    """Persists and monitors session and cumulative token consumption."""

    _STORAGE_PATH = Path.home() / ".config" / "cybersecuritysuite" / "ai_usage_stats.json"

    def __init__(self):
        self._session_records: List[Dict[str, Any]] = []

    def record_usage(
        self,
        provider: AIProvider,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        cost_usd: float,
    ) -> None:
        rec = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provider": provider.value,
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "cost_usd": cost_usd,
        }
        self._session_records.append(rec)
        self._persist_record(rec)

    def _persist_record(self, record: Dict[str, Any]) -> None:
        try:
            self._STORAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
            existing: List[Dict[str, Any]] = []
            if self._STORAGE_PATH.is_file():
                try:
                    data = json.loads(self._STORAGE_PATH.read_text(encoding="utf-8"))
                    if isinstance(data, list):
                        existing = data
                except Exception:
                    existing = []
            existing.append(record)
            # Keep last 500 records
            if len(existing) > 500:
                existing = existing[-500:]
            self._STORAGE_PATH.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.debug("Failed saving AI usage stats: %s", exc)

    def get_summary(self) -> Dict[str, Any]:
        """Calculates total usage across session and historical records."""
        total_prompt = sum(r.get("prompt_tokens", 0) for r in self._session_records)
        total_completion = sum(r.get("completion_tokens", 0) for r in self._session_records)
        total_cost = sum(r.get("cost_usd", 0.0) for r in self._session_records)
        return {
            "session_requests": len(self._session_records),
            "session_prompt_tokens": total_prompt,
            "session_completion_tokens": total_completion,
            "session_total_tokens": total_prompt + total_completion,
            "session_cost_usd": round(total_cost, 4),
        }


def redact_sensitive_ai_data(text: str) -> str:
    """Masks authorization tokens, private keys, AWS credentials, and passwords prior to cloud transmission."""
    if not text:
        return ""
    # Mask JWT Bearer Tokens and Standalone JWTs
    text = re.sub(r"Bearer\s+ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "Bearer [REDACTED_JWT]", text, flags=re.IGNORECASE)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "[REDACTED_JWT]", text)
    # Mask AWS Access and Secret Keys
    text = re.sub(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b", "[REDACTED_AWS_KEY]", text)
    text = re.sub(r"(?i)(aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", r"\1: [REDACTED_AWS_SECRET]", text)
    # Mask GCP Service Account private keys
    text = re.sub(r'(?i)"private_key"\s*:\s*"-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----\\n"', '"private_key": "[REDACTED_GCP_PRIVATE_KEY]"', text)
    # Mask GitHub Personal Access Tokens
    text = re.sub(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b", "[REDACTED_GITHUB_TOKEN]", text)
    text = re.sub(r"\bgithub_pat_[A-Za-z0-9_]{82}\b", "[REDACTED_GITHUB_TOKEN]", text)
    # Mask OpenAI and Anthropic API keys
    text = re.sub(r"\bsk-(?:proj-|admin-)?[A-Za-z0-9_-]{20,}\b", "[REDACTED_OPENAI_KEY]", text)
    text = re.sub(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", "[REDACTED_ANTHROPIC_KEY]", text)
    # Mask Google Gemini API keys
    text = re.sub(r"\bAIzaSy[A-Za-z0-9_-]{33}\b", "[REDACTED_GEMINI_KEY]", text)
    # Mask Private Key blocks (PEM and OpenSSH)
    text = re.sub(r"-----BEGIN [A-Z0-9_\- ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9_\- ]+PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]", text)
    # Mask URL-embedded basic authentication credentials
    text = re.sub(r"(https?://)([^:\s]+):([^@\s]+)@", r"\1\2:[REDACTED_PASSWORD]@", text)
    # Mask CLI password parameters
    text = re.sub(r"(?i)(--password|--pass|-P)\s+([^\s]+)", r"\1 [REDACTED_PASSWORD]", text)
    # Mask Generic API Keys / Passwords in flags or assignments
    text = re.sub(r"(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{8,})['\"]?", r"\1: [REDACTED_SECRET]", text, flags=re.IGNORECASE)
    return text


class AIModelRouter:
    """Orchestrates 3-tier fallback routing chain for AI completions with token & cost tracking."""

    _instance: Optional[AIModelRouter] = None

    def __init__(
        self,
        primary: Optional[ModelTierConfig] = None,
        secondary: Optional[ModelTierConfig] = None,
        final_fallback: Optional[ModelTierConfig] = None,
    ):
        self.primary = primary or ModelTierConfig(
            provider=AIProvider.GEMINI_API,
            model_name="gemini-1.5-flash",
            timeout_seconds=15.0,
        )
        self.secondary = secondary or ModelTierConfig(
            provider=AIProvider.OPENAI_API,
            model_name="gpt-4o-mini",
            timeout_seconds=15.0,
        )
        self.final_fallback = final_fallback or ModelTierConfig(
            provider=AIProvider.BUILTIN_OFFLINE,
            model_name="offline-expert-rules",
            timeout_seconds=5.0,
        )
        self.usage_tracker = AIUsageTracker()
        self.last_response: Optional[AIResponse] = None

    @classmethod
    def get_instance(cls) -> AIModelRouter:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def resolve_api_key(self, config: ModelTierConfig) -> Optional[str]:
        """Resolves active key from config, CredentialManager, or system environment."""
        if config.api_key:
            return config.api_key

        prov = config.provider
        if prov == AIProvider.GEMINI_API:
            return CredentialManager.get_key("gemini")
        elif prov == AIProvider.OPENAI_API:
            return CredentialManager.get_key("openai")
        elif prov == AIProvider.ANTHROPIC_API:
            return CredentialManager.get_key("anthropic")
        elif prov == AIProvider.OPENROUTER_API:
            return CredentialManager.get_key("openrouter") or CredentialManager.get_key("custom_ai")
        elif prov == AIProvider.DEEPSEEK_API:
            return CredentialManager.get_key("deepseek")
        elif prov == AIProvider.CUSTOM_OPENAI_COMPATIBLE:
            return CredentialManager.get_key("custom_ai")
        return None

    def route_completion(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
    ) -> AIResponse:
        """Executes prompt through the 3-tier fallback chain (Primary -> Secondary -> Final Fallback)."""
        clean_prompt = redact_sensitive_ai_data(prompt)
        clean_system = redact_sensitive_ai_data(system_prompt or "You are an expert cybersecurity penetration testing assistant.")

        chain: List[Tuple[str, ModelTierConfig]] = [
            ("Primary", self.primary),
            ("Secondary", self.secondary),
            ("Final Fallback", self.final_fallback),
        ]

        failover_history: List[Dict[str, Any]] = []
        fallback_occurred = False

        start_time = time.time()

        for tier_name, config in chain:
            tier_start = time.time()
            try:
                content, p_tok, c_tok = self._invoke_tier(
                    config=config,
                    prompt=clean_prompt,
                    system_prompt=clean_system,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                duration = round(time.time() - tier_start, 3)
                cost = ReferencePricing.calculate_cost(config.model_name, p_tok, c_tok)
                self.usage_tracker.record_usage(
                    provider=config.provider,
                    model=config.model_name,
                    prompt_tokens=p_tok,
                    completion_tokens=c_tok,
                    cost_usd=cost,
                )

                resp = AIResponse(
                    content=content,
                    provider_used=config.provider,
                    model_used=config.model_name,
                    fallback_occurred=fallback_occurred,
                    failover_history=failover_history,
                    token_usage=TokenUsage(
                        prompt_tokens=p_tok,
                        completion_tokens=c_tok,
                        total_tokens=p_tok + c_tok,
                        estimated_cost_usd=cost,
                    ),
                    duration_seconds=round(time.time() - start_time, 3),
                    success=True,
                )
                self.last_response = resp
                return resp

            except Exception as exc:
                duration = round(time.time() - tier_start, 3)
                err_msg = str(exc)
                logger.warning(
                    "AI Tier [%s: %s (%s)] failed after %.2fs: %s. Initiating failover.",
                    tier_name,
                    config.provider.value,
                    config.model_name,
                    duration,
                    err_msg,
                )
                failover_history.append({
                    "tier": tier_name,
                    "provider": config.provider.value,
                    "model": config.model_name,
                    "duration_seconds": duration,
                    "error": err_msg,
                })
                fallback_occurred = True
                continue

        # If all tiers failed, return safe offline fallback failure response
        total_duration = round(time.time() - start_time, 3)
        return AIResponse(
            content="[!] All configured AI providers (Primary, Secondary, Final) failed to respond. Please verify network connectivity and API keys in AI Settings.",
            provider_used=AIProvider.BUILTIN_OFFLINE,
            model_used="offline-fallback-error",
            fallback_occurred=True,
            failover_history=failover_history,
            duration_seconds=total_duration,
            success=False,
            error_message="All tiers exhausted.",
        )

    def _invoke_tier(
        self,
        config: ModelTierConfig,
        prompt: str,
        system_prompt: str,
        max_tokens: int,
        temperature: float,
    ) -> Tuple[str, int, int]:
        """Dispatches request to specific provider implementation."""
        prov = config.provider
        timeout = config.timeout_seconds

        if prov == AIProvider.BUILTIN_OFFLINE:
            content = self._run_offline_heuristics(prompt)
            # Heuristic token approximation (~4 chars per token)
            p_tok = len(prompt) // 4
            c_tok = len(content) // 4
            return content, p_tok, c_tok

        elif prov == AIProvider.LOCAL_OLLAMA:
            return self._call_ollama(config, prompt, system_prompt, timeout)

        elif prov == AIProvider.GEMINI_API:
            api_key = self.resolve_api_key(config)
            if not api_key:
                raise ValueError("Gemini API key is not configured in settings or environment.")
            return self._call_gemini(config, api_key, prompt, system_prompt, timeout)

        elif prov in (AIProvider.OPENAI_API, AIProvider.DEEPSEEK_API, AIProvider.OPENROUTER_API, AIProvider.CUSTOM_OPENAI_COMPATIBLE):
            api_key = self.resolve_api_key(config)
            if not api_key and prov != AIProvider.CUSTOM_OPENAI_COMPATIBLE:
                raise ValueError(f"{prov.value} API key is not configured.")
            return self._call_openai_compatible(config, api_key or "no-key", prompt, system_prompt, timeout)

        elif prov == AIProvider.ANTHROPIC_API:
            api_key = self.resolve_api_key(config)
            if not api_key:
                raise ValueError("Anthropic API key is not configured.")
            return self._call_anthropic(config, api_key, prompt, system_prompt, timeout)

        else:
            raise ValueError(f"Unsupported AI provider: {prov}")

    def _call_gemini(
        self,
        config: ModelTierConfig,
        api_key: str,
        prompt: str,
        system_prompt: str,
        timeout: float,
    ) -> Tuple[str, int, int]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{config.model_name}:generateContent?key={api_key}"
        payload = {
            "contents": [{"parts": [{"text": f"System: {system_prompt}\n\nUser: {prompt}"}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 2048},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            res_json = json.loads(response.read().decode("utf-8"))
            candidates = res_json.get("candidates", [])
            if not candidates:
                raise RuntimeError("Gemini returned empty candidate list.")
            text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            usage = res_json.get("usageMetadata", {})
            p_tok = usage.get("promptTokenCount", len(prompt) // 4)
            c_tok = usage.get("candidatesTokenCount", len(text) // 4)
            return text, p_tok, c_tok

    def _call_openai_compatible(
        self,
        config: ModelTierConfig,
        api_key: str,
        prompt: str,
        system_prompt: str,
        timeout: float,
    ) -> Tuple[str, int, int]:
        base_url = config.api_url or self._default_endpoint_for(config.provider)
        endpoint = f"{base_url.rstrip('/')}/chat/completions"
        payload = {
            "model": config.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        if config.provider == AIProvider.OPENROUTER_API:
            headers["HTTP-Referer"] = "https://github.com/leophyoe/LPT"
            headers["X-Title"] = "CyberSecuritySuite LPT Workstation"

        req = urllib.request.Request(endpoint, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            res_json = json.loads(response.read().decode("utf-8"))
            choices = res_json.get("choices", [])
            if not choices:
                raise RuntimeError("Provider returned empty choices array.")
            text = choices[0].get("message", {}).get("content", "")
            usage = res_json.get("usage", {})
            p_tok = usage.get("prompt_tokens", len(prompt) // 4)
            c_tok = usage.get("completion_tokens", len(text) // 4)
            return text, p_tok, c_tok

    def _call_anthropic(
        self,
        config: ModelTierConfig,
        api_key: str,
        prompt: str,
        system_prompt: str,
        timeout: float,
    ) -> Tuple[str, int, int]:
        endpoint = "https://api.anthropic.com/v1/messages"
        payload = {
            "model": config.model_name,
            "max_tokens": 2048,
            "system": system_prompt,
            "messages": [{"role": "user", "content": prompt}],
        }
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        req = urllib.request.Request(endpoint, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            res_json = json.loads(response.read().decode("utf-8"))
            content_blocks = res_json.get("content", [])
            text = "".join(b.get("text", "") for b in content_blocks if b.get("type") == "text")
            usage = res_json.get("usage", {})
            p_tok = usage.get("input_tokens", len(prompt) // 4)
            c_tok = usage.get("output_tokens", len(text) // 4)
            return text, p_tok, c_tok

    def _call_ollama(
        self,
        config: ModelTierConfig,
        prompt: str,
        system_prompt: str,
        timeout: float,
    ) -> Tuple[str, int, int]:
        base = (config.api_url or "http://127.0.0.1:11434").rstrip("/")
        endpoint = f"{base}/api/chat"
        payload = {
            "model": config.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(endpoint, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            res_json = json.loads(response.read().decode("utf-8"))
            text = res_json.get("message", {}).get("content", "")
            p_tok = res_json.get("prompt_eval_count", len(prompt) // 4)
            c_tok = res_json.get("eval_count", len(text) // 4)
            return text, p_tok, c_tok

    def _run_offline_heuristics(self, prompt: str) -> str:
        """Rule-based security response engine requiring 0% network and 0 API keys."""
        lower = prompt.lower()

        # Nmap analysis
        if "nmap" in lower and ("port" in lower or "scan" in lower):
            return (
                "### 🔍 Offline Scan Telemetry Analysis\n"
                "- **Classification**: Observed Open Services\n"
                "- **Key Assessment Points**:\n"
                "  1. Review exposed administrative ports (SSH 22, RDP 3389, Telnet 23).\n"
                "  2. Verify encryption configuration on Web services (HTTP 80 vs HTTPS 443).\n"
                "  3. Check SMB/RPC exposure (TCP 445, 139) for unauthorized lateral movement pathways.\n"
                "- **Recommended Safe Verification**: `nmap -sV -sC -Pn -p <PORTS> <TARGET>`"
            )

        # SQL Injection / SQLMap
        if "sql" in lower or "sqlmap" in lower:
            return (
                "### 🛡️ SQL Injection Diagnostic & Guidance\n"
                "- **Classification**: Suspected Database Input Vulnerability\n"
                "- **Operational Safety Reminder**: High-risk intrusive options (`--os-shell`, `--dump-all`) require explicit operator authorization.\n"
                "- **Recommended Safe Test**: `sqlmap -u \"<URL>\" --batch --banner` (Verify DBMS version safely without data alteration)."
            )

        # Web Directory Enumeration / Gobuster
        if "gobuster" in lower or "dir" in lower or "404" in lower or "403" in lower:
            return (
                "### 🌐 Web Endpoint Discovery Guidance\n"
                "- **Classification**: Observed Information Disclosure\n"
                "- **Findings**: Look for `.env`, `.git`, `/admin`, `/backup`, `/api` disclosures.\n"
                "- **Recommendation**: Verify permissions on HTTP 403 endpoints using standard authenticated tests."
            )

        # Default expert guidance
        return (
            "### 🛡️ CyberSecuritySuite Copilot (Offline Heuristic Mode)\n"
            "- **Status**: Analyzed via Local Heuristic Rule Engine.\n"
            "- **Finding Classification Standard**:\n"
            "  - `Observed`: Confirmed network or service telemetry.\n"
            "  - `Suspected`: Probable vulnerability requiring proof-of-concept.\n"
            "  - `Confirmed`: Cryptographically or functionally validated risk.\n"
            "  - `Needs Validation`: Inconclusive output requiring targeted testing.\n"
            "- **Guidance**: Ensure all targets are explicitly covered under authorized project scope before launching active scans."
        )

    @staticmethod
    def _default_endpoint_for(provider: AIProvider) -> str:
        if provider == AIProvider.OPENAI_API:
            return "https://api.openai.com/v1"
        elif provider == AIProvider.DEEPSEEK_API:
            return "https://api.deepseek.com/v1"
        elif provider == AIProvider.OPENROUTER_API:
            return "https://openrouter.ai/api/v1"
        return "https://api.openai.com/v1"

    def test_connection(
        self,
        provider: AIProvider,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Probes endpoint availability and returns status tuple (is_healthy, message)."""
        if provider == AIProvider.BUILTIN_OFFLINE:
            return True, "Built-in Offline Expert Engine is ready (100% availability, 0ms latency)."

        cfg = ModelTierConfig(
            provider=provider,
            model_name=model or "default",
            api_key=api_key,
            api_url=api_url,
            timeout_seconds=8.0,
        )
        try:
            content, _, _ = self._invoke_tier(
                config=cfg,
                prompt="Respond with 'PONG' to verify connection.",
                system_prompt="Diagnostic probe.",
                max_tokens=10,
                temperature=0.0,
            )
            return True, f"Connection successful! Received response from {cfg.model_name}."
        except Exception as exc:
            return False, f"Connection failed: {exc}"
