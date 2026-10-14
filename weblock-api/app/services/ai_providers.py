"""AI provider abstraction (Phase 9).

The application talks to AIProvider only. No vendor SDKs: the built-in
HTTP provider speaks OpenAI-compatible chat/completions over HTTPS with a
timeout, so no new dependencies. Secrets live in settings, never in logs,
responses, or audit rows.
"""
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Protocol

logger = logging.getLogger("weblock.ai")


@dataclass
class ProviderResult:
    ok: bool
    text: str = ""
    error_code: str = ""
    error_message: str = ""
    latency_ms: int = 0
    provider: str = ""
    model: str = ""


class AIProvider(Protocol):
    name: str
    model: str

    def available(self) -> tuple[bool, str]:
        """(is_available, reason_if_not). No network I/O required."""
        ...

    def analyze(self, *, system: str, user: str,
                timeout_seconds: int) -> ProviderResult:
        ...


class MockProvider:
    """Deterministic test double. NEVER used outside tests."""

    name = "mock"
    model = "mock-1"

    def __init__(self, script: dict | None = None,
                 fail: str | None = None, latency_ms: int = 0):
        self._script = script
        self._fail = fail
        self._latency_ms = latency_ms
        self.calls: list[dict] = []

    def available(self) -> tuple[bool, str]:
        if self._fail == "unavailable":
            return False, "mock marked unavailable"
        return True, ""

    def analyze(self, *, system: str, user: str,
                timeout_seconds: int) -> ProviderResult:
        self.calls.append({"system": system, "user": user})
        if self._fail == "timeout":
            return ProviderResult(ok=False, error_code="TIMEOUT",
                                  error_message="mock timeout",
                                  provider=self.name, model=self.model)
        if self._fail == "malformed":
            return ProviderResult(ok=True, text="NOT JSON {{{",
                                  provider=self.name, model=self.model)
        if self._fail == "oversized":
            return ProviderResult(ok=True, text="x" * 100000,
                                  provider=self.name, model=self.model)
        if self._script is not None:
            return ProviderResult(ok=True, text=json.dumps(self._script),
                                  latency_ms=self._latency_ms,
                                  provider=self.name, model=self.model)
        raise AssertionError("MockProvider needs script or fail mode")


class OpenAICompatibleProvider:
    """HTTPS chat provider (OpenAI-compatible). No vendor SDK."""

    name = "openai-compatible"

    def __init__(self, *, model: str, api_key: str, base_url: str):
        self.model = model
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")

    def available(self) -> tuple[bool, str]:
        from app.core.config import settings
        if not settings.AI_ENABLED:
            return False, "AI_ENABLED is false"
        if not self._api_key:
            return False, "AI_API_KEY is not configured"
        if not self.model:
            return False, "AI_MODEL is not configured"
        return True, ""

    def analyze(self, *, system: str, user: str,
                timeout_seconds: int) -> ProviderResult:
        import requests
        started = time.perf_counter()
        try:
            resp = requests.post(
                f"{self._base_url}/chat/completions",
                # Real key on the wire; never logged (only status codes are).
                headers={"Authorization": f"Bearer {self._api_key}",
                         "Content-Type": "application/json"},
                json={"model": self.model,
                      "messages": [{"role": "system", "content": system},
                                   {"role": "user", "content": user}],
                      "temperature": 0.1,
                      "response_format": {"type": "json_object"}},
                timeout=timeout_seconds)
        except Exception as exc:
            # requests exceptions carry no secrets (key lives in settings,
            # never in the message); still, truncate defensively.
            return ProviderResult(
                ok=False, error_code="PROVIDER_ERROR",
                error_message=str(exc)[:300],
                latency_ms=int((time.perf_counter() - started) * 1000),
                provider=self.name, model=self.model)
        if resp.status_code == 429:
            return ProviderResult(ok=False, error_code="RATE_LIMITED",
                                  error_message="provider rate limit",
                                  provider=self.name, model=self.model)
        if resp.status_code >= 400:
            code = "AUTH_FAILED" if resp.status_code in (401, 403) \
                else "PROVIDER_ERROR"
            return ProviderResult(ok=False, error_code=code,
                                  error_message=f"HTTP {resp.status_code}",
                                  provider=self.name, model=self.model)
        try:
            text = resp.json()["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            return ProviderResult(ok=False, error_code="MALFORMED_RESPONSE",
                                  error_message="unparseable provider payload",
                                  provider=self.name, model=self.model)
        return ProviderResult(ok=True, text=text or "",
                              latency_ms=int(
                                  (time.perf_counter() - started) * 1000),
                              provider=self.name, model=self.model)


def default_provider() -> AIProvider:
    from app.core.config import settings
    return OpenAICompatibleProvider(model=settings.AI_MODEL,
                                    api_key=settings.AI_API_KEY,
                                    base_url=settings.AI_BASE_URL)


@dataclass
class AnalysisField:
    statement: str
    references: list[str] = field(default_factory=list)


OUTPUT_VERSION = "1"
PROMPT_VERSION = "1"
