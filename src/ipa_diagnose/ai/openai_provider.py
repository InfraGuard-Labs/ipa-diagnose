"""OpenAI adapter. Requires the `openai` extra (`pip install ipa-diagnose[openai]`).

Import of the `openai` package is deferred into __init__ so this module can
be imported (e.g. by config.py's lazy factory) without the dependency being
installed - only actually *using* the openai provider requires it.
"""

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


class OpenAIProvider(AIProvider):
    provider_name = "openai"

    def __init__(self, *, api_key: Optional[str], model: str, timeout: float):
        self._api_key = api_key
        self._model = model
        self._timeout = timeout

    def is_configured(self) -> bool:
        return bool(self._api_key)

    def generate(self, request: AIRequest) -> AIResponse:
        if not self._api_key:
            raise ProviderAuthError("OPENAI_API_KEY is not set")
        try:
            import openai
        except ImportError as e:
            raise ProviderError(
                "the 'openai' package is not installed (pip install 'ipa-diagnose[openai]')"
            ) from e

        client = openai.OpenAI(api_key=self._api_key, timeout=min(request.timeout, self._timeout))
        try:
            completion = client.chat.completions.create(
                model=self._model,
                max_tokens=request.max_tokens,
                messages=[
                    {"role": "developer", "content": request.system_prompt},
                    {"role": "user", "content": request.user_prompt},
                ],
            )
        except openai.AuthenticationError as e:
            raise ProviderAuthError(str(e)) from e
        except openai.RateLimitError as e:
            raise ProviderRateLimitError(str(e)) from e
        except openai.APITimeoutError as e:
            raise ProviderTimeoutError(str(e)) from e
        except openai.APIConnectionError as e:
            raise ProviderConnectionError(str(e)) from e
        except openai.InternalServerError as e:
            raise ProviderUnavailableError(str(e)) from e
        except openai.APIStatusError as e:
            raise ProviderUnavailableError(str(e)) from e

        choice = completion.choices[0] if completion.choices else None
        if choice is None or getattr(choice, "finish_reason", None) == "content_filter":
            raise ProviderRefusalError("OpenAI declined to produce a response (content filter)")
        text = (choice.message.content or "").strip()
        if not text:
            raise ProviderRefusalError("OpenAI returned an empty response")
        return AIResponse(text=text, provider_name=self.provider_name, model=self._model)
