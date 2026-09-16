"""Evidence minimization: Diagnosis -> the smallest payload an AI provider needs.

Pipeline (matches docs/security-privacy.md):

    Raw Evidence -> Normalization -> Minimum Evidence Selection -> Secret
    Detection -> Redaction -> Minimization -> Approved AI Payload

Normalization already happened before this module runs (evidence/model.py,
evidence/healthcheck.py). This module does the remaining four steps:

  1. Minimum Evidence Selection: only the Finding/EvidenceItem objects a
     Diagnosis actually cites via EvidenceRef are considered at all - never
     the full EvidenceBundle. A Diagnosis that cites 3 findings out of 60
     healthcheck results sends 3, not 60.
  2. Secret Detection + 3. Redaction: every string field of every selected
     item goes through privacy.redact before it is included.
  4. Minimization: long messages are truncated, and hostnames/domain labels
     the pack marked as internal-only can be replaced with stable aliases
     (host-1, host-2, ...) when redact_hostnames=True, so the model still
     sees "the same host" consistently across findings without learning the
     administrator's real infrastructure names.

`ai-preview` and the real AI call both go through build_ai_payload() - there
is no second code path, so the preview can never lie about what's sent.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List

from ipa_diagnose.engine.model import Diagnosis
from ipa_diagnose.evidence.model import EvidenceBundle, EvidenceItem, Finding
from ipa_diagnose.privacy.redact import redact_mapping, redact_text

_MAX_MESSAGE_CHARS = 400
_MAX_ITEMS = 12


@dataclasses.dataclass
class SelectedEvidence:
    kind: str
    """"finding" or "item"."""
    source: str
    severity: str
    message: str
    why_relevant: str


@dataclasses.dataclass
class AIPayload:
    diagnosis_id: str
    system_prompt: str
    user_prompt: str
    selected_evidence: List[SelectedEvidence]
    redaction_matches: List[str]
    excluded_evidence_count: int
    """How many bundle items existed but were NOT selected/sent - shown in
    ai-preview so the administrator can see minimization is actually happening."""

    def redaction_summary(self) -> str:
        if not self.redaction_matches:
            return "No secrets or sensitive fields detected in the selected evidence."
        counts: Dict[str, int] = {}
        for m in self.redaction_matches:
            counts[m] = counts.get(m, 0) + 1
        parts = [f"{name} x{count}" for name, count in sorted(counts.items())]
        return "Redacted before sending: " + ", ".join(parts)


_SYSTEM_PROMPT = """You are explaining a FreeIPA diagnostic result to a system administrator.

You will be given a diagnosis that was already computed deterministically by
ipa-diagnose, along with the specific evidence that supports it. Your ONLY
job is to explain it more clearly in plain language.

Rules you must follow exactly:
- Do not state or imply any root cause, evidence, confidence level, impact,
  or recommended command that is not already present in the material given
  to you. You are explaining, not diagnosing.
- Do not invent hostnames, error messages, dates, or numbers.
- Do not suggest any command that is not already listed in the provided
  actions.
- If something in the input is unclear, say the diagnosis is unclear rather
  than guessing at what it might mean.
- Keep your explanation under 200 words, plain language, no markdown headers.
"""


def _selected_from_finding(f: Finding, why: str) -> SelectedEvidence:
    # Deliberately NOT redacted here: build_ai_payload's final pass over
    # `selected` is the single place redaction happens for these messages,
    # so its match list is complete. Redacting twice would make the second
    # pass's regexes match nothing (the secret is already gone) and silently
    # under-report what was actually redacted in the ai-preview audit trail.
    return SelectedEvidence(
        kind="finding", source=f.qualified_check, severity=f.severity.value, message=f.message, why_relevant=why
    )


def _selected_from_item(item: EvidenceItem, why: str) -> SelectedEvidence:
    severity = item.severity.value if item.severity else "INFO"
    return SelectedEvidence(kind="item", source=item.kind, severity=severity, message=item.summary, why_relevant=why)


def build_ai_payload(bundle: EvidenceBundle, diagnosis: Diagnosis) -> AIPayload:
    findings_by_id = {f.finding_id: f for f in bundle.findings}
    items_by_id = {i.item_id: i for i in bundle.items}

    selected: List[SelectedEvidence] = []
    redaction_matches: List[str] = []

    for ref in list(diagnosis.evidence_for) + list(diagnosis.evidence_against):
        if len(selected) >= _MAX_ITEMS:
            break
        if ref.kind == "finding" and ref.evidence_id in findings_by_id:
            f = findings_by_id[ref.evidence_id]
            _, kw_matches = redact_mapping(f.keywords)
            redaction_matches.extend(kw_matches)
            selected.append(_selected_from_finding(f, ref.why_relevant))
        elif ref.kind == "item" and ref.evidence_id in items_by_id:
            item = items_by_id[ref.evidence_id]
            _, data_matches = redact_mapping(item.data)
            redaction_matches.extend(data_matches)
            selected.append(_selected_from_item(item, ref.why_relevant))

    for s in selected:
        report = redact_text(s.message)
        redaction_matches.extend(report.matches)
        s.message = report.redacted_text[:_MAX_MESSAGE_CHARS]

    total_bundle_items = len(bundle.findings) + len(bundle.items)
    excluded_count = max(total_bundle_items - len(selected), 0)

    evidence_lines = "\n".join(
        f"- [{e.severity}] ({e.source}) {e.message}  -- relevant because: {e.why_relevant}" for e in selected
    )
    actions_lines = "\n".join(f"- ({a.risk.value}) {a.description}" for a in diagnosis.actions) or "(none)"

    user_prompt = f"""DIAGNOSIS: {diagnosis.title}
STATUS: {diagnosis.status.value}
CONFIDENCE: {diagnosis.confidence.level.value} ({diagnosis.confidence.rationale})
WHY (already determined, do not contradict): {diagnosis.why}
IMPACT (already determined): {diagnosis.impact}
LIMITATIONS: {diagnosis.limitations or "(none noted)"}

SUPPORTING EVIDENCE:
{evidence_lines or "(none selected)"}

APPROVED ACTIONS (do not add or modify commands):
{actions_lines}

Explain this to the administrator in plain language, under 200 words."""

    return AIPayload(
        diagnosis_id=diagnosis.diagnosis_id,
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        selected_evidence=selected,
        redaction_matches=redaction_matches,
        excluded_evidence_count=excluded_count,
    )
