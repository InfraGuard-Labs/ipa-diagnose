# Architecture

```text
ipa-healthcheck JSON  +  targeted read-only evidence
        │           (journalctl, getcert, ipa-replica-manage, dig, klist/kvno, ldapsearch)
        ▼
Evidence Normalizer
        ▼
Privacy / Redaction
        ▼
Diagnostic Engine (5 packs)
        ▼
Correlation + Prioritization
        ▼
Structured Diagnosis
   ┌────────┴────────┐
   ▼                 ▼
Local Explanation   Optional AI
   └────────┬────────┘
            ▼
           CLI
            ▼
        Verification
```

## Evidence model

`src/ipa_diagnose/evidence/model.py` defines two evidence shapes, both
required to carry a `Provenance`:

- **`Finding`** - one `ipa-healthcheck` result, normalized 1:1 from its JSON
  shape (`source`, `check`, `severity`, `message`, `keywords`).
- **`EvidenceItem`** - a fact from a targeted collector (a `getcert list`
  entry, a replication agreement, a journal line, a DNS lookup result), each
  tagged with a `kind` string.

`Provenance` records the exact command that produced the evidence
(`command`), whether it came from a live host or `--replay` fixtures
(`live`), and when. This is not incidental - it is what lets `--details`
answer "where did this come from?" for every claim the tool makes, and it's
the anchor the privacy pipeline uses to decide what's safe to send an AI
provider.

Collectors (`src/ipa_diagnose/evidence/collectors/*.py`) are read-only by
contract, each implementing both `collect_live()` (a `subprocess.run()` call
with an argument list, never `shell=True` - see
`tests/adversarial/test_command_injection.py`) and `collect_replay()` (reads
a fixture file), so the identical pack/rule code runs against a real host
and against test fixtures. Collection is staged: `evidence/collect.py` only
runs a pack's targeted collectors once that pack's own `ipa-healthcheck`
sources show a WARNING-or-worse finding - a healthy system never triggers
`journalctl` or `getcert` calls at all.

## Diagnostic packs and rules

A **pack** (`src/ipa_diagnose/engine/packs/base.py`) is a small, versioned
group of **rules** for one problem family. A rule's contract:

- Return `None` when its trigger evidence isn't present - silence is the
  default outcome for most rules on most runs.
- Once triggered, return a `Diagnosis` - which may itself be `DIAGNOSED` or
  one of the `UNKNOWN_*`/`TRANSIENT_SUSPECTED` statuses. Reaching "I can't
  tell which of two causes this is" is a valid, encouraged outcome, not a
  failure of the rule.
- Never fabricate an `EvidenceRef` - every citation must point at a real
  `Finding.finding_id` or `EvidenceItem.item_id` actually in the bundle
  (enforced by `tests/adversarial/test_false_correlation.py`'s
  `test_every_evidence_ref_traces_to_the_merged_bundle`, run against
  cross-pack merged evidence specifically to catch a rule that grabbed
  another pack's evidence via a too-broad query).

A hard runtime guardrail lives in `engine/model.py`'s `Diagnosis.__post_init__`:
constructing a `Diagnosis` with `status=DIAGNOSED` and `confidence.level` of
`LOW` or `INSUFFICIENT` raises `ValueError`. This isn't a lint rule a pack
author can forget - it's enforced every time a `Diagnosis` object is built,
by any pack, in any run. See [docs/diagnostic-packs.md](diagnostic-packs.md)
for what each of the 5 packs actually checks.

## Correlation and prioritization (`engine/correlate.py`)

This module - never a rule, never AI - makes the final PRIMARY /
RELATED_SYMPTOM / SECONDARY_INDEPENDENT / WARNING call, from two inputs a
rule provides:

- **`severity`** (`Severity.WARNING`/`ERROR`/`CRITICAL`) - how bad this is
  *if true*.
- **`upstream_candidates`** - which other packs, per the documented
  causality chain **DNS → Kerberos → Replication → Certificates**, with
  **Directory Server foundational under all of them**, could be the real
  root cause behind this diagnosis's symptoms.

Correlation logic: if a diagnosis's `upstream_candidates` names a pack that
also fired in the same run, the diagnosis is demoted to `RELATED_SYMPTOM`
and the concurrently-firing upstream pack is promoted. Diagnoses with no
causal link between them (including diagnoses within the *same* pack, which
never demote each other - see `04_correlated_findings.png`'s
`dns.srv-autodiscovery` staying `SECONDARY_INDEPENDENT` rather than being
folded into `dns.named-service-down`) are ranked by a score combining
severity, confidence level, and corroborating-evidence count; the top scorer
becomes `PRIMARY`, the rest `SECONDARY_INDEPENDENT`. This is deterministic
and inspectable - see `tests/unit/test_correlate.py` and
`tests/adversarial/test_false_correlation.py` (the latter merges evidence
from independently-built pack fixtures specifically to test this without
hand-rolled synthetic data).

`OverallStatus` (HEALTHY/DEGRADED/CRITICAL/UNKNOWN) is likewise computed
centrally from the resulting diagnoses' severities and statuses, never set
by a rule.

## Optional AI (`ai/`, `privacy/`)

An `AIProvider` (`ai/provider.py`) has exactly one job:
`generate(system_prompt, user_prompt) -> text`, given a payload the privacy
pipeline already built and approved. `ai/prompt.py`'s `explain_diagnosis()`
is the only caller; on any `ProviderError` it returns `None` and the caller
falls back to the diagnosis's own deterministic `why` text. See
[docs/ai-configuration.md](ai-configuration.md) for the provider adapters
and [docs/security-privacy.md](security-privacy.md) for the payload pipeline.

## CLI and rendering

`cli.py` wires collection → diagnosis → (optional) AI explanation →
rendering, for three subcommands (`diagnose` [default], `verify`,
`ai-preview`). `render/console.py` renders the default and `--details`
views; `render/json_output.py` serializes the same `DiagnosisReport` for
`--json`/automation use - both from the identical `DiagnosisReport` object,
so there is exactly one source of truth for what a run concluded.

## Access diagnosis (`access/`)

`ipa-diagnose access USER HOST SERVICE` is a separate path. It does not use ipa-healthcheck, collectors or packs.
`access/api.py` sends a fixed allowlist of read-only FreeIPA API calls (JSON-RPC over HTTPS with the caller's
Kerberos ticket), or answers them from a recorded `access_api.json` in `--replay`. `access/evaluate.py` runs a
fixed, bounded sequence: user, host, service, then `hbactest` (the decision), then only the rules and group chains
needed to explain it. `access/relations.py` is the L2 relationship index: typed nodes and edges with provenance,
deduplicated, cycle-safe and bounded. It explains the decision and never makes it. With `--runtime` (on HOST itself) it hands the runtime side to client mode (below). `access/output.py` renders the answer as text or as JSON
(`access_schema_version`), a document separate from the v1 diagnosis report. Details:
[access-diagnosis.md](access-diagnosis.md).

## Planner and client mode (`planner/`, `client/`)

`planner/core.py` is L3: a bounded, deterministic executor for an explicit, ordered graph of steps. Each step names a
check from the closed registry (`resolution/checks.py` REGISTRY, with `resolution/client_checks.py` for the client
checks and their privilege, timeout, side-effect and secret metadata), its prerequisites, a relevance gate over the
results already collected, and a classifier. A plan is validated before it runs (a step may depend only on earlier
steps, so it is acyclic; depth and fan-out are bounded); the run is bounded in checks, wall clock, per-check timeout
and retries, suppresses duplicate checks, keeps partial evidence on cancellation and records a full trace.
`client/plan.py` is the client plan, `client/diagnose.py` (L4) turns a trace into diagnoses with causal roles,
`client/run.py` attaches fixes through the Slice 1 resolution engine (L5) and builds the verdicts, and
`client/verify.py` (L6) re-checks with fresh evidence. `access/runtime.py` connects `access --runtime` to it. The
L2 relationship index stays in `access/`. Details: [client-mode.md](client-mode.md).

## Verification (`verify.py`)

See [docs/verification.md](verification.md).
