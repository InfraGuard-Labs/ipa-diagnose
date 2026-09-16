"""AWS Bedrock adapter (Converse API). Requires the `bedrock` extra
(`pip install ipa-diagnose[bedrock]`, which installs boto3).

Uses boto3's standard credential chain (env vars, ~/.aws, EC2/ECS instance
role, assumed role) rather than requiring explicit keys - the realistic
default for this tool's audience is an IAM role already attached to the
host. See docs/ai-configuration.md for the cross-region inference-profile
gotcha this adapter's default model id already works around.
"""

from __future__ import annotations

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

_RETRYABLE_BUT_STILL_UNAVAILABLE = {"ServiceUnavailableException", "InternalServerError", "ModelTimeoutException"}


class BedrockProvider(AIProvider):
    provider_name = "bedrock"

    def __init__(self, *, model_id: str, region: str, timeout: float):
        self._model_id = model_id
        self._region = region
        self._timeout = timeout
        self._client = None

    def is_configured(self) -> bool:
        try:
            import boto3
        except ImportError:
            return False
        try:
            session = boto3.Session()
            return session.get_credentials() is not None
        except Exception:
            return False

    def _get_client(self):
        if self._client is None:
            import boto3
            from botocore.config import Config

            self._client = boto3.client(
                "bedrock-runtime",
                region_name=self._region,
                config=Config(connect_timeout=self._timeout, read_timeout=self._timeout, retries={"max_attempts": 2}),
            )
        return self._client

    def generate(self, request: AIRequest) -> AIResponse:
        try:
            import botocore
        except ImportError as e:
            raise ProviderError(
                "the 'boto3' package is not installed (pip install 'ipa-diagnose[bedrock]')"
            ) from e

        client = self._get_client()
        try:
            response = client.converse(
                modelId=self._model_id,
                system=[{"text": request.system_prompt}],
                messages=[{"role": "user", "content": [{"text": request.user_prompt}]}],
                inferenceConfig={"maxTokens": request.max_tokens},
            )
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "UnrecognizedClientException"):
                raise ProviderAuthError(str(e)) from e
            if code == "ThrottlingException":
                raise ProviderRateLimitError(str(e)) from e
            if code in _RETRYABLE_BUT_STILL_UNAVAILABLE:
                raise ProviderUnavailableError(str(e)) from e
            if code == "ValidationException":
                raise ProviderError(f"Bedrock rejected the request: {e}") from e
            raise ProviderUnavailableError(str(e)) from e
        except botocore.exceptions.ConnectTimeoutError as e:
            raise ProviderTimeoutError(str(e)) from e
        except botocore.exceptions.EndpointConnectionError as e:
            raise ProviderConnectionError(str(e)) from e

        stop_reason = response.get("stopReason")
        if stop_reason == "content_filtered":
            raise ProviderRefusalError("Bedrock content filter declined to produce a response")
        content = response.get("output", {}).get("message", {}).get("content", [])
        text = "\n".join(block.get("text", "") for block in content if "text" in block).strip()
        if not text:
            raise ProviderRefusalError("Bedrock returned an empty response")
        return AIResponse(text=text, provider_name=self.provider_name, model=self._model_id)
