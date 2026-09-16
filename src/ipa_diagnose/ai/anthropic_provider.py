"""Anthropic adapter. Requires the `anthropic` extra (`pip install ipa-diagnose[anthropic]`)."""

from __future__ import annotations

from typing import Optional

from ipa_diagnose.ai.provider import (
    AIProvider,
    AIRequest,
    AIResponse,
    ProviderAuthError,
    ProviderConnectionError,
    ProviderError,
    ProviderRateLimitError,
    ProviderRefusalError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)


class AnthropicProvider(AIProvider):
    provider_name = "anthropic"

    def __init__(self, *, api_key: Optional[str], model: str, timeout: float):
        self._api_key = api_key
        self._model = model
        self._timeout = timeout

    def is_configured(self) -> bool:
        return bool(self._api_key)

    def generate(self, request: AIRequest) -> AIResponse:
        if not self._api_key:
            raise ProviderAuthError("ANTHROPIC_API_KEY is not set")
        try:
            import anthropic
        except ImportError as e:
            raise ProviderError(
                "the 'anthropic' package is not installed (pip install 'ipa-diagnose[anthropic]')"
            ) from e

        client = anthropic.Anthropic(api_key=self._api_key, timeout=min(request.timeout, self._timeout))
        try:
            message = client.messages.create(
                model=self._model,
                max_tokens=request.max_tokens,
                system=request.system_prompt,
                messages=[{"role": "user", "content": request.user_prompt}],
            )
        except anthropic.AuthenticationError as e:
            raise ProviderAuthError(str(e)) from e
        except anthropic.RateLimitError as e:
            raise ProviderRateLimitError(str(e)) from e
        except anthropic.APITimeoutError as e:
            raise ProviderTimeoutError(str(e)) from e
        except anthropic.APIConnectionError as e:
            raise ProviderConnectionError(str(e)) from e
        except anthropic.APIStatusError as e:
            raise ProviderUnavailableError(str(e)) from e

        if getattr(message, "stop_reason", None) == "refusal":
            raise ProviderRefusalError("Claude declined to produce a response")
        blocks = [b.text for b in message.content if getattr(b, "type", None) == "text"]
        text = "\n".join(blocks).strip()
        if not text:
            raise ProviderRefusalError("Claude returned an empty response")
        return AIResponse(text=text, provider_name=self.provider_name, model=self._model)
