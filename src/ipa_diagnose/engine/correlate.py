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
    EvidenceCompleteness,
    OverallStatus,
    UndiagnosedFinding,
    UnverifiedCapability,
    PriorityBucket,
)
from ipa_diagnose.evidence.healthcheck_catalog import CATALOG
from ipa_diagnose.evidence.model import EvidenceBundle, Severity
from ipa_diagnose.textsafe import sanitize_text

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

    return d.severity.rank >= Severity.ERROR.rank


_SERVICE_PACK = {
    "dirsrv": "directory-server",
    "krb5kdc": "kerberos",
    "named": "dns",
    "named-pkcs11": "dns",
    "pki-tomcatd": "certificates",
    "certmonger": "certificates",
}


def _effective_pack(d: Diagnosis) -> str:
    """A 'service X is not running' diagnosis stands for the pack that depends on X,
    so it counts as an upstream cause of that pack's downstream symptoms."""

    if d.pack_id == "healthcheck" and d.rule_id.startswith("service-not-running-"):
        service = d.rule_id[len("service-not-running-"):].split("@")[0]
        return _SERVICE_PACK.get(service, d.pack_id)
    return d.pack_id


def _demote_via_causality(diagnoses: List[Diagnosis]) -> Dict[str, List[str]]:
    """Returns {diagnosis_id: [causing_pack_ids]} for diagnoses whose declared
    upstream_candidates actually fired - as a REAL problem, not merely any
    diagnosis at all - in this same report."""

    fired_packs = {_effective_pack(d) for d in diagnoses if _is_real_problem(d)}
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
            titles_by_pack.setdefault(_effective_pack(d), []).append(d.title)

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

    completeness = _assess_completeness(bundle)
    claimed = {r.evidence_id for d in diagnoses for r in list(d.evidence_for) + list(d.evidence_against)}
    unclaimed_warnings = sum(
        1 for f in bundle.findings if f.severity == Severity.WARNING and f.finding_id not in claimed
    )
    undiagnosed = _undiagnosed_findings(bundle, diagnoses)
    overall = _apply_completeness(_overall_status(diagnoses), completeness)

    return DiagnosisReport(
        generated_at=EvidenceBundle.now(),
        hostname=bundle.hostname,
        overall_status=overall,
        diagnoses=sorted(diagnoses, key=_priority_sort_key),
        collection_errors=[f"{e.collector}: {sanitize_error_text(e.message)}" for e in bundle.collection_errors],
        evidence_completeness=completeness,
        unclaimed_warnings=unclaimed_warnings,
        undiagnosed_findings=undiagnosed,
        packs_evaluated=packs_evaluated,
        replay_source=bundle.replay_source,
        environment=bundle.environment,
        unknown_severity_findings=_unknown_severity_notes(bundle),
    )


class _KeepUnknown(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def _display_message(f) -> str:
    """The finding's message with upstream's own {placeholders} filled from its keywords. A result with
    no message shows only which fields it carries, never a raw dict dump."""

    kw = f.keywords if isinstance(f.keywords, dict) else {}
    text = f.message or ""
    if not text:
        names = ", ".join(sanitize_text(k, 40) for k in list(kw)[:8])
        return f"(no message; fields: {names})" if names else "(no message)"
    if "{" in text:
        try:
            text = text.format_map(_KeepUnknown({str(k): sanitize_text(v, 80) for k, v in kw.items()}))
        except (ValueError, IndexError, KeyError, AttributeError):
            pass
    # Local output may be pasted into tickets: mask secret-looking text (same patterns as the AI path).
    from ipa_diagnose.privacy.redact import redact_text

    return redact_text(sanitize_text(text, 300)).redacted_text


def _undiagnosed_findings(bundle: EvidenceBundle, diagnoses: List[Diagnosis]) -> List[UndiagnosedFinding]:
    """Every WARNING-or-worse (or unrecognized-severity) finding that no diagnosis cites as
    evidence. A finding whose id is shared with another finding is ambiguous and never counts
    as claimed. Only the deterministic fact "no rule explains this" is recorded - no guess."""

    from ipa_diagnose.engine.unexplained import is_check_crash  # local: avoids an import cycle

    id_counts: Dict[str, int] = {}
    for f in bundle.findings:
        id_counts[f.finding_id] = id_counts.get(f.finding_id, 0) + 1
    # Only positive citations count: a finding cited merely as counter-evidence is still unexplained.
    claimed = {r.evidence_id for d in diagnoses for r in d.evidence_for}
    version = bundle.environment.ipa_healthcheck_version if bundle.environment else None
    out: List[UndiagnosedFinding] = []
    for f in bundle.findings:
        if f.severity == Severity.SUCCESS:
            continue
        if f.finding_id in claimed and id_counts[f.finding_id] == 1:
            continue
        crashed = is_check_crash(f)
        known = CATALOG.get(f.qualified_check)
        if crashed:
            reason = "The check raised an exception instead of returning a result, so it says nothing about the system."
        elif known is None:
            reason = "ipa-diagnose has no rule for this check, and it is not in this build's catalog of upstream checks (possibly newer or custom)."
        else:
            reason = "ipa-diagnose has no rule that explains this finding; it may or may not matter."
        kw = f.keywords if isinstance(f.keywords, dict) else {}
        key = kw.get("key")
        key_text = sanitize_text(key, 160) if isinstance(key, (str, int)) and str(key) != f.check else None
        out.append(
            UndiagnosedFinding(
                source=sanitize_text(f.source, 120),
                check=sanitize_text(f.check, 120),
                severity=f.severity.value,
                message=_display_message(f),
                key=key_text,
                reason=reason,
                crashed=crashed,
                check_known_since=known[0] if known else None,
                ipa_healthcheck_version=sanitize_text(version, 40) if version else None,
                finding_id=sanitize_text(f.finding_id, 120),
            )
        )
    out.sort(key=lambda u: (-{"CRITICAL": 4, "ERROR": 3, "UNKNOWN": 3, "WARNING": 1}.get(u.severity, 2), u.source, u.check))
    return out


_CAPABILITY_LABELS = {
    "ipa-healthcheck": "ipa-healthcheck (base health evidence)",
    "replication_agreements": "Replication agreements / RUV",
}

_MAX_ERROR_LEN = 300


def sanitize_error_text(text: str) -> str:
    """Collector error text comes from subprocess stderr, i.e. untrusted."""

    return sanitize_text(text, _MAX_ERROR_LEN)


def _hint_for(collector: str, reason: str) -> str:
    low = reason.lower()
    if "ldapsearch is not installed" in low:
        return "Install the OpenLDAP client tools (dnf install openldap-clients) and run as root."
    if "not running as root" in low:
        return "Run ipa-diagnose as root (sudo ipa-diagnose)."
    if collector == "ipa-healthcheck" and "not installed" in low:
        return "Install ipa-healthcheck (dnf install freeipa-healthcheck)."
    if collector == "ipa-healthcheck" and "timed out" in low:
        return (
            "ipa-healthcheck did not finish in time. A stopped or unreachable DNS, LDAP or Kerberos service "
            "is a common cause - check those services, then re-run."
        )
    if collector == "ipa-healthcheck" and ("no output" in low or "could not parse" in low or "no usable" in low):
        return "ipa-healthcheck produced no usable output; it normally needs root - re-run with sudo."
    if "directory manager password" in low:
        return (
            "ipa-diagnose never asks for the Directory Manager password; as root it reads the replica "
            "update vector over the local LDAPI socket instead."
        )
    return ""


def _assess_completeness(bundle: EvidenceBundle) -> EvidenceCompleteness:
    unverified = [
        UnverifiedCapability(
            capability=_CAPABILITY_LABELS.get(e.collector, e.collector),
            collector=e.collector,
            reason=sanitize_error_text(e.message),
            permission_related=e.permission_related,
            hint=_hint_for(e.collector, sanitize_error_text(e.message)),
        )
        for e in bundle.collection_errors
    ]
    healthcheck_ok = not any(e.collector == "ipa-healthcheck" for e in bundle.collection_errors)

    ruv_error = next((e for e in bundle.collection_errors if e.collector == "replication_agreements"), None)
    has_ruv_items = any(i.kind == "replication_ruv" for i in bundle.items)
    no_replication = any(
        i.kind == "replication_topology" and i.data.get("state") == "no_replication_configured" for i in bundle.items
    )
    if no_replication and not has_ruv_items:
        # Read as cn=Directory Manager over LDAPI and no RUV exists: replication
        # is not configured (single-server). Verified, not a gap.
        ruv_state, ruv_reason = "NONE_CONFIGURED", None
    elif has_ruv_items:
        # RUV entries WERE read (even if a sibling `list` call failed and the
        # error is still recorded separately as an unverified capability).
        ruv_state, ruv_reason = "VERIFIED", None
    elif ruv_error is not None:
        ruv_state, ruv_reason = "NOT_VERIFIED", sanitize_error_text(ruv_error.message)
    else:
        ruv_state, ruv_reason = "NOT_COLLECTED", None

    if not healthcheck_ok:
        level = "insufficient"
    elif unverified:
        level = "partial"
    else:
        level = "complete"
    return EvidenceCompleteness(
        level=level,
        healthcheck_collected=healthcheck_ok,
        unverified=unverified,
        ruv_state=ruv_state,
        ruv_reason=ruv_reason,
    )


def _apply_completeness(status: OverallStatus, completeness: EvidenceCompleteness) -> OverallStatus:
    """HEALTHY is only ever reported when the evidence needed to say so was
    collected. A found problem always wins (a collection gap must never hide
    a real diagnosis); only the *absence* of problems is downgraded."""

    if status != OverallStatus.HEALTHY:
        return status
    if completeness.level == "insufficient":
        return OverallStatus.UNKNOWN
    if completeness.level == "partial":
        return OverallStatus.NOT_FULLY_VERIFIED
    return OverallStatus.HEALTHY


def _unknown_severity_notes(bundle: EvidenceBundle) -> List[str]:
    notes = []
    for f in bundle.findings:
        if f.severity == Severity.UNKNOWN:
            raw_result = f.raw.get("result") if isinstance(f.raw, dict) else None
            notes.append(
                sanitize_text(
                    f"{f.source}.{f.check}: unrecognized severity {raw_result!r} - treated as ERROR-equivalent, not dropped",
                    300,
                )
            )
    if len(notes) > 20:
        notes = notes[:20] + [f"(+{len(notes) - 20} more unrecognized severity value(s) not shown)"]
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
