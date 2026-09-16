# Security and privacy

FreeIPA is identity infrastructure. `ipa-diagnose` treats every piece of
evidence it collects as potentially sensitive, and every log line as
untrusted input - whether or not AI is ever enabled.

## The redaction pipeline

Before anything can reach an external AI provider (`src/ipa_diagnose/privacy/minimize.py`,
`build_ai_payload()`):

```text
Raw Evidence → Normalization → Minimum Evidence Selection → Secret Detection
                                                            → Redaction → Minimization → Approved Payload
```

1. **Minimum evidence selection.** Only the `Finding`/`EvidenceItem` objects
   a `Diagnosis` actually cites via `EvidenceRef` are considered - never the
   full evidence bundle. A diagnosis that cites 3 findings out of 60
   `ipa-healthcheck` results sends 3, not 60
   (`AIPayload.excluded_evidence_count` reports how many were left out).
2. **Secret detection**, two independent strategies, both always applied
   (`privacy/redact.py`):
   - **Field-name based** - a dict key like `password`, `bindpw`, `secret`,
     `keytab`, `token`, or `api_key` gets its value replaced entirely,
     regardless of what the value looks like.
   - **Pattern based** - free-text scanning for AWS/OpenAI/Anthropic/GitHub/
     Slack key shapes, `-----BEGIN ... PRIVATE KEY-----` blocks, bearer
     tokens, `user:pass@host` URLs, and a generic 40+ character
     high-entropy-token catch-all.

   Neither is complete alone (field names lie; patterns miss novel formats),
   so both always run on every string.
3. **Redaction and minimization** - matched text becomes
   `[REDACTED:<type>]`; messages are truncated to 400 characters.

## `ai-preview`: proof, not a promise

```bash
sudo ipa-diagnose ai-preview
```

renders the *exact* system prompt, user prompt, and redaction summary that
would be sent - and it does so by calling the identical `build_ai_payload()`
function the real AI call uses (`ai/prompt.py`'s `explain_diagnosis()`).
There is no second code path that could drift from what `ai-preview` shows.
See `16_ai_payload_redaction_preview.png` for a captured example (a
synthetic secret redacted end-to-end).

## AI can explain, never decide

This is enforced structurally, not just by prompt instructions:

- The system prompt (`privacy/minimize.py`'s `_SYSTEM_PROMPT`) explicitly
  forbids inventing root causes, evidence, confidence, or commands beyond
  what's given.
- **The rendered "Actions" section always comes from the deterministic
  `Diagnosis.actions` list** - never from AI output. An AI explanation is
  prose displayed alongside that section, never a replacement for it.
- `ai/prompt.py`'s `sanitize_explanation()` is a second, defense-in-depth
  layer: it scans an AI response for command-shaped lines (`sudo`, `rm -rf`,
  `ipa *`, `systemctl`, `dnf`, ...) and **rejects the entire response** (not
  just the offending line - a partially-sanitized paragraph is more
  misleading than falling back cleanly) if it finds one that isn't already
  in the diagnosis's own approved actions.

## Failure modes are all handled the same way

Any `ProviderError` (auth failure, rate limit, timeout, connection failure,
content refusal, malformed/empty response, a sanitizer rejection) causes
`explain_diagnosis()` to return `None`. The caller always has the
diagnosis's own deterministic `why` text ready as a fallback - AI failure
never blocks, crashes, or degrades the core diagnosis. See
`15_ai_unavailable_fallback.png`.

## Adversarial test coverage (`tests/adversarial/`)

- **`test_false_correlation.py`** - merges evidence from independently-built
  pack fixtures to confirm unrelated problems are never merged into one
  story, and that the one documented real causal link (DNS → Kerberos) *is*
  recognized. Also re-checks, across every existing fixture, that every
  `EvidenceRef` a diagnosis cites actually exists in the bundle it was given.
- **`test_prompt_injection.py`** - a log line engineered to look like an
  instruction to an LLM passes through as inert evidence text (never
  specially interpreted by `ipa-diagnose` itself); a hostile *AI response*
  containing a fabricated command is rejected by `sanitize_explanation()`.
- **`test_secret_leakage.py`** - secrets in a finding's message, its
  keywords, an evidence item's data, and evidence *not* cited by the
  diagnosis are all confirmed absent from the real `build_ai_payload()`
  output (not just the lower-level `redact.py` unit tests).
- **`test_command_injection.py`** - a static guard: no collector may use
  `shell=True`, `os.system()`, or `os.popen()`. Every collector shells out
  with an argument list, so even attacker-influenced data in one argv
  element (e.g. a hostname) can't break out into a second command.
- **`test_malformed_input.py`** - unknown future healthcheck check IDs,
  5000-finding inputs, malformed JSON (both the healthcheck output and a
  collector's own fixture), and hostile Unicode/control characters must all
  be handled without crashing, and without ever reaching a confident
  `DIAGNOSED` result from garbage input.

One bug this suite actually found and fixed during development: secret
redaction in `build_ai_payload()` was silently applied twice, which still
prevented leakage but caused the audit-trail match list to under-report
what was redacted - caught by `test_secret_in_finding_message_is_not_sent`,
fixed in `privacy/minimize.py`.

## What this tool never does

- Never executes a CAUTION or HIGH_RISK action automatically.
- Never sends full raw logs to an AI provider - only the specific,
  redacted, cited evidence for one diagnosis.
- Never requires network access or an LLM to produce a diagnosis (`--no-ai`
  is the default).
