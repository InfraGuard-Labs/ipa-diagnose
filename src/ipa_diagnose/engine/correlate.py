"""Deterministic correlation and prioritization.

This module - not any diagnostic rule, and never an AI provider - decides
final priority buckets. Rules only describe *what* is wrong and *why*, plus
which packs could plausibly be an upstream root cause (`upstream_candidates`,
based on the researched causality chain: DNS -> Kerberos -> Replication ->
Certificates, with Directory Server foundational under all of them). This
module turns that into PRIMARY / RELATED_SYMPTOM / SECONDARY_INDEPENDENT /
WARNING, and computes the overall status.

Design rationale (see docs/architecture.md for the full writeup):
  - "Related" is causal, not coincidental: a diagnosis is only demoted to
    RELATED_SYMPTOM when it explicitly names the concurrently-firing pack as
    a plausible cause. Two unrelated real problems must never be silently
    merged into one story.
  - Severity (how bad if true) and confidence (how sure we are) are scored
    independently, then combined - a low-confidence CRITICAL claim does not
    automatically outrank a high-confidence ERROR claim.
  - UNKNOWN diagnoses compete for PRIMARY on equal footing with DIAGNOSED
    ones: not knowing the root cause of a real symptom is itself the primary
    problem to surface, per "unknown is better than wrong".
"""

from __future__ import annotations

from typing import Dict, List

from ipa_diagnose.engine.model import (
    ConfidenceLevel,
    Diagnosis,
    DiagnosisReport,
    DiagnosisStatus,
    OverallStatus,
    PriorityBucket,
)
from ipa_diagnose.evidence.model import EvidenceBundle, Severity

STATUS_WEIGHT: Dict[DiagnosisStatus, float] = {
    DiagnosisStatus.DIAGNOSED: 1.0,
    DiagnosisStatus.UNKNOWN_CONFLICTING_EVIDENCE: 0.85,
    DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE: 0.7,
    DiagnosisStatus.TRANSIENT_SUSPECTED: 0.5,
}

CONFIDENCE_WEIGHT: Dict[ConfidenceLevel, float] = {
    ConfidenceLevel.HIGH: 1.0,
    ConfidenceLevel.MEDIUM: 0.7,
    ConfidenceLevel.LOW: 0.4,
    ConfidenceLevel.INSUFFICIENT: 0.2,
}


def _score(d: Diagnosis) -> float:
    return (
        (d.severity.rank + 1)
        * STATUS_WEIGHT[d.status]
        * CONFIDENCE_WEIGHT[d.confidence.level]
        * (1.0 + 0.05 * min(d.confidence.corroborating_evidence_count, 6))
    )


def _is_real_problem(d: Diagnosis) -> bool:
    """A WARNING-severity DIAGNOSED finding is a benign heads-up (e.g.
    "replication conflicts exist, which means replication IS working"), not
    a real problem another pack's symptoms could be downstream of. Found in
    adversarial review: without this check, ANY diagnosis from an upstream
    pack - including a benign one - would count as that pack "firing" and
    could demote a genuinely unrelated diagnosis in another pack to
    RELATED_SYMPTOM. Any UNKNOWN_*/TRANSIENT_SUSPECTED status still counts,
    since "we don't know if the upstream pack has a real problem" is itself
    a real reason to hold off blaming a different pack."""

    return not (d.status == DiagnosisStatus.DIAGNOSED and d.severity == Severity.WARNING)


def _demote_via_causality(diagnoses: List[Diagnosis]) -> Dict[str, List[str]]:
    """Returns {diagnosis_id: [causing_pack_ids]} for diagnoses whose declared
    upstream_candidates actually fired - as a REAL problem, not merely any
    diagnosis at all - in this same report."""

    fired_packs = {d.pack_id for d in diagnoses if _is_real_problem(d)}
    demotions: Dict[str, List[str]] = {}
    for d in diagnoses:
        causing = [p for p in d.upstream_candidates if p in fired_packs and p != d.pack_id]
        if causing:
            demotions[d.diagnosis_id] = causing
    return demotions


def build_report(
    bundle: EvidenceBundle,
    diagnoses: List[Diagnosis],
    packs_evaluated: List[str],
) -> DiagnosisReport:
    diagnoses = list(diagnoses)
    demotions = _demote_via_causality(diagnoses)
    titles_by_pack: Dict[str, List[str]] = {}
    for d in diagnoses:
        if _is_real_problem(d):
            titles_by_pack.setdefault(d.pack_id, []).append(d.title)

    root_candidates: List[Diagnosis] = []
    for d in diagnoses:
        if d.diagnosis_id in demotions:
            causes = demotions[d.diagnosis_id]
            d.priority = PriorityBucket.RELATED_SYMPTOM
            d.related_to_titles = [t for pack in causes for t in titles_by_pack.get(pack, [])]
            cause_note = " and ".join(causes)
            d.why = f"{d.why}\n\nLikely a downstream symptom of the {cause_note} problem reported above."
        elif d.severity == Severity.WARNING and d.status == DiagnosisStatus.DIAGNOSED:
            d.priority = PriorityBucket.WARNING
        else:
            root_candidates.append(d)

    root_candidates.sort(key=_score, reverse=True)
    for idx, d in enumerate(root_candidates):
        d.priority = PriorityBucket.PRIMARY if idx == 0 else PriorityBucket.SECONDARY_INDEPENDENT

    overall = _overall_status(diagnoses)

    return DiagnosisReport(
        generated_at=EvidenceBundle.now(),
        hostname=bundle.hostname,
        overall_status=overall,
        diagnoses=sorted(diagnoses, key=_priority_sort_key),
        collection_errors=[f"{e.collector}: {e.message}" for e in bundle.collection_errors],
        packs_evaluated=packs_evaluated,
        replay_source=bundle.replay_source,
        environment=bundle.environment,
        unknown_severity_findings=_unknown_severity_notes(bundle),
    )


def _unknown_severity_notes(bundle: EvidenceBundle) -> List[str]:
    notes = []
    for f in bundle.findings:
        if f.severity == Severity.UNKNOWN:
            raw_result = f.raw.get("result") if isinstance(f.raw, dict) else None
            notes.append(
                f"{f.source}.{f.check}: unrecognized severity {raw_result!r} - treated as ERROR-equivalent, not dropped"
            )
    return notes


_PRIORITY_ORDER = {
    PriorityBucket.PRIMARY: 0,
    PriorityBucket.SECONDARY_INDEPENDENT: 1,
    PriorityBucket.RELATED_SYMPTOM: 2,
    PriorityBucket.WARNING: 3,
    PriorityBucket.INFORMATIONAL: 4,
}


def _priority_sort_key(d: Diagnosis):
    return (_PRIORITY_ORDER[d.priority], -_score(d))


def _overall_status(diagnoses: List[Diagnosis]) -> OverallStatus:
    if not diagnoses:
        return OverallStatus.HEALTHY
    # Deliberately checks PRIMARY only, not SECONDARY_INDEPENDENT: the
    # headline status must track whether *the* primary problem is resolved,
    # not whether every independent problem in the report is. A confidently
    # DIAGNOSED primary sitting next to an unrelated TRANSIENT_SUSPECTED
    # secondary is still a known problem overall - it must not present as
    # "Overall: UNKNOWN" and bury the fully-diagnosed primary underneath it
    # (a real UX defect found in review: see docs/limitations.md history).
    primary_is_unresolved = any(
        d.priority == PriorityBucket.PRIMARY and d.status != DiagnosisStatus.DIAGNOSED for d in diagnoses
    )
    max_severity = max((d.severity for d in diagnoses), default=Severity.SUCCESS)
    if primary_is_unresolved and max_severity.rank >= Severity.ERROR.rank:
        return OverallStatus.UNKNOWN
    if max_severity.rank >= Severity.CRITICAL.rank:
        return OverallStatus.CRITICAL
    if max_severity.rank >= Severity.ERROR.rank:
        return OverallStatus.DEGRADED
    if any(d.priority != PriorityBucket.INFORMATIONAL for d in diagnoses):
        return OverallStatus.DEGRADED
    return OverallStatus.HEALTHY
