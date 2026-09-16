# AI configuration

Entirely optional. `ipa-diagnose` is fully useful with zero AI involvement
(`--no-ai`, the default) - AI only rephrases an already-computed
deterministic diagnosis into plainer language (see
[docs/security-privacy.md](security-privacy.md) for exactly what is and
isn't sent, and the structural guarantees that AI can't invent a root cause
or a command).

## Enabling a provider

```bash
# OpenAI
pip install 'ipa-diagnose[openai]'
export OPENAI_API_KEY=sk-...
sudo ipa-diagnose --ai-provider openai

# Anthropic
pip install 'ipa-diagnose[anthropic]'
export ANTHROPIC_API_KEY=sk-ant-...
sudo ipa-diagnose --ai-provider anthropic

# AWS Bedrock - uses boto3's normal credential chain (IAM role, env vars,
# ~/.aws/credentials); no explicit API key needed if the host already has
# an IAM role attached.
pip install 'ipa-diagnose[bedrock]'
sudo ipa-diagnose --ai-provider bedrock
```

Or set `IPA_DIAGNOSE_AI_PROVIDER=openai|anthropic|bedrock` once instead of
passing `--ai-provider` every time. `--no-ai` always overrides both.

Each provider's SDK is an **optional extra** - `pip install ipa-diagnose`
alone pulls in none of them, so the base install (and the RPM - see
[packaging/rpm/README.md](../packaging/rpm/README.md)) has no AI-related
dependencies at all.

## Why three hand-rolled adapters instead of a library like litellm

`src/ipa_diagnose/ai/{openai,anthropic,bedrock}_provider.py` are each a thin
(~60-90 line) adapter implementing one interface
(`ai/provider.py`'s `AIProvider.generate()`). A unified multi-provider
library (`litellm` was the specific alternative considered) was deliberately
not used:

1. **`--no-ai` must have zero required dependencies.** `litellm` pulls in
   `httpx`, `pydantic`, `jinja2`, and more - a lot of transitive surface to
   vendor into a security-sensitive tool touching FreeIPA, when the honest
   baseline needs nothing at all. Three thin adapters let each provider be
   its own pip extra.
2. **The actual need is trivial** - one text-in/text-out call, no tools, no
   streaming, no multi-provider routing or fallback chains, no cost
   tracking. That's exactly the complexity a routing library amortizes, and
   none of it applies here.
3. **Auditability.** An administrator (or reviewer) can read all three call
   sites directly, end to end, rather than trusting a fourth-party
   translation layer between the redacted prompt and each vendor's API -
   worth it specifically because this project promises "AI never invents a
   root cause or command" and that promise should be verifiable by reading
   three short files.

## Model defaults (all overridable via environment variable)

| Provider | Default model | Override |
|---|---|---|
| OpenAI | `gpt-5.6-luna` (cheapest current tier, sufficient for a bounded rephrasing task) | `IPA_DIAGNOSE_OPENAI_MODEL` |
| Anthropic | `claude-haiku-4-5` | `IPA_DIAGNOSE_ANTHROPIC_MODEL` |
| Bedrock | `us.anthropic.claude-haiku-4-5-20251001-v1:0` | `IPA_DIAGNOSE_BEDROCK_MODEL` |

The Bedrock default is a cross-region inference-profile ID (`us.` prefix),
not a bare model ID - many current Bedrock models reject direct on-demand
invocation and require this, with an error that otherwise looks unrelated
("Invocation with on-demand throughput isn't supported"). If you use a
different Bedrock model, keep this in mind and check whether it needs the
same prefix (or a `global.` prefix) for your region, and that your IAM
policy grants `bedrock:InvokeModel`/`Converse` on the inference-profile ARN,
not just the foundation-model ARN.

Model names move fast; these are config defaults specifically so a vendor
renaming or retiring a model never requires an `ipa-diagnose` code change.

## Error handling

Every adapter maps its SDK's own exceptions into a small shared hierarchy
(`ai/provider.py`): `ProviderAuthError`, `ProviderRateLimitError`,
`ProviderTimeoutError`, `ProviderConnectionError`, `ProviderRefusalError`,
`ProviderUnavailableError`. `ai/prompt.py`'s `explain_diagnosis()` catches
all of them uniformly and returns `None` - see
[docs/security-privacy.md](security-privacy.md#failure-modes-are-all-handled-the-same-way)
for what happens next (the local deterministic explanation, always).

## Seeing what a provider would receive, without sending it

```bash
sudo ipa-diagnose ai-preview
```

See [docs/security-privacy.md](security-privacy.md#ai-preview-proof-not-a-promise).
