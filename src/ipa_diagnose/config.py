"""Runtime configuration: AI provider selection and defaults.

Every default here is overridable via environment variable specifically so a
model-name change on the provider side never requires an ipa-diagnose code
change - see docs/ai-configuration.md for why these particular defaults were
chosen (cheap, text-only explanation task; no vision/tools needed).
"""

from __future__ import annotations

import dataclasses
import os
from typing import Optional

DEFAULT_OPENAI_MODEL = os.environ.get("IPA_DIAGNOSE_OPENAI_MODEL", "gpt-5.6-luna")
DEFAULT_ANTHROPIC_MODEL = os.environ.get("IPA_DIAGNOSE_ANTHROPIC_MODEL", "claude-haiku-4-5")
DEFAULT_BEDROCK_MODEL = os.environ.get(
    "IPA_DIAGNOSE_BEDROCK_MODEL", "us.anthropic.claude-haiku-4-5-20251001-v1:0"
)
DEFAULT_BEDROCK_REGION = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
DEFAULT_TIMEOUT_SECONDS = float(os.environ.get("IPA_DIAGNOSE_AI_TIMEOUT", "12"))


@dataclasses.dataclass(frozen=True)
class AIConfig:
    provider: str = "none"
    """"none", "openai", "anthropic", or "bedrock"."""
    openai_model: str = DEFAULT_OPENAI_MODEL
    anthropic_model: str = DEFAULT_ANTHROPIC_MODEL
    bedrock_model: str = DEFAULT_BEDROCK_MODEL
    bedrock_region: str = DEFAULT_BEDROCK_REGION
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None

    @classmethod
    def from_env_and_args(cls, *, no_ai: bool, provider_arg: Optional[str]) -> "AIConfig":
        if no_ai:
            return cls(provider="none")
        provider = provider_arg or os.environ.get("IPA_DIAGNOSE_AI_PROVIDER", "none")
        return cls(
            provider=provider,
            openai_api_key=os.environ.get("OPENAI_API_KEY"),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY"),
        )


def build_provider(config: AIConfig):
    """Factory: returns an AIProvider for config.provider. Import of concrete
    providers is lazy so `--no-ai` never requires openai/anthropic/boto3 to be
    installed at all (they are optional extras - see pyproject.toml)."""

    from ipa_diagnose.ai.provider import NoAIProvider

    if config.provider == "openai":
        from ipa_diagnose.ai.openai_provider import OpenAIProvider

        return OpenAIProvider(api_key=config.openai_api_key, model=config.openai_model, timeout=config.timeout_seconds)
    if config.provider == "anthropic":
        from ipa_diagnose.ai.anthropic_provider import AnthropicProvider

        return AnthropicProvider(
            api_key=config.anthropic_api_key, model=config.anthropic_model, timeout=config.timeout_seconds
        )
    if config.provider == "bedrock":
        from ipa_diagnose.ai.bedrock_provider import BedrockProvider

        return BedrockProvider(model_id=config.bedrock_model, region=config.bedrock_region, timeout=config.timeout_seconds)
    return NoAIProvider()
