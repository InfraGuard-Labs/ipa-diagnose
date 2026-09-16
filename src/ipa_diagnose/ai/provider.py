"""AI provider abstraction.

Exactly one job: turn an already-computed, deterministic Diagnosis into more
readable prose. A provider implementation NEVER sees raw evidence beyond
what the privacy/redaction pipeline approved (see privacy/preview.py, which
renders the exact same payload this module sends - "ai-preview" and the real
call must never diverge). A provider MUST NOT be asked to produce root
causes, evidence, confidence, or commands - prompt.py's contract enforces
this by construction (it only ever asks for an explanation of given facts),
and render code must ignore/discard anything a provider response contains
that looks like a new claim (see ai/prompt.py `sanitize_explanation`).

Every concrete provider (OpenAI, Anthropic, Bedrock) is a thin ~20-40 line
adapter: build client, make one call, map that SDK's specific exceptions
into the ProviderError hierarchy below so the rest of the codebase never
branches on provider identity. See docs/ai-configuration.md for the research
backing the model/error-handling choices per provider.
"""

from __future__ import annotations

import abc
import dataclasses


class ProviderError(Exception):
    """Base class for all AI provider failures. Any of these must leave
    ipa-diagnose fully functional in local-explanation mode - never fatal."""


class ProviderAuthError(ProviderError):
    """Invalid/missing API key or credentials."""


class ProviderRateLimitError(ProviderError):
    """Rate limited; retrying immediately will not help."""


class ProviderTimeoutError(ProviderError):
    """Request exceeded the configured timeout."""


class ProviderConnectionError(ProviderError):
    """Network/connectivity failure reaching the provider."""


class ProviderRefusalError(ProviderError):
    """Provider returned a content-policy refusal or empty/invalid response."""


class ProviderUnavailableError(ProviderError):
    """Provider-side server error (5xx) or service outage."""


@dataclasses.dataclass(frozen=True)
class AIRequest:
    system_prompt: str
    user_prompt: str
    max_tokens: int = 700
    timeout: float = 12.0


@dataclasses.dataclass(frozen=True)
class AIResponse:
    text: str
    provider_name: str
    model: str


class AIProvider(abc.ABC):
    """Implemented by OpenAIProvider, AnthropicProvider, BedrockProvider."""

    provider_name: str

    @abc.abstractmethod
    def generate(self, request: AIRequest) -> AIResponse:
        """Returns a response, or raises a ProviderError subclass. Must never
        raise anything else - implementations should catch their SDK's own
        exception types and re-raise as ProviderError subclasses."""
        raise NotImplementedError

    @abc.abstractmethod
    def is_configured(self) -> bool:
        """True if required credentials/config are present, without making a
        network call. Used to fail fast with a clear message before ever
        reaching the provider."""
        raise NotImplementedError


class NoAIProvider(AIProvider):
    """The default. Explicitly refuses to run rather than silently no-op,
    so callers always go through the same code path (try provider, catch
    ProviderError, fall back to local explanation)."""

    provider_name = "none"

    def generate(self, request: AIRequest) -> AIResponse:
        raise ProviderError("AI explanation is disabled (--no-ai or no provider configured)")

    def is_configured(self) -> bool:
        return False
