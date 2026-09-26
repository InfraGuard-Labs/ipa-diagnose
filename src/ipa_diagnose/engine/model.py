"""Diagnosis data model.

This is the contract between diagnostic packs (src/ipa_diagnose/engine/packs/*)
and everything downstream: correlation, rendering, AI explanation, and
verification. A diagnostic rule's ONLY job is to look at an EvidenceBundle and
return a RuleOutcome; it must never fabricate evidence, and every claim it
makes must cite EvidenceRefs that trace back to real Finding/EvidenceItem
objects. AI providers only ever see an already-built Diagnosis - they cannot
change confidence, evidence, or actions.
"""

from __future__ import annotations

import dataclasses
import enum
from typing import Any, Callable, Dict, List, Optional

from ipa_diagnose.evidence.model import EnvironmentInfo, EvidenceBundle, Severity


class DiagnosisStatus(enum.Enum):
    DIAGNOSED = "DIAGNOSED"
    """A specific root cause was identified with sufficient confidence."""
    UNKNOWN_INSUFFICIENT_EVIDENCE = "UNKNOWN_INSUFFICIENT_EVIDENCE"
    UNKNOWN_CONFLICTING_EVIDENCE = "UNKNOWN_CONFLICTING_EVIDENCE"
    TRANSIENT_SUSPECTED = "TRANSIENT_SUSPECTED"
    """Evidence matches a known transient/self-healing pattern; not a confirmed root cause."""


class PriorityBucket(enum.Enum):
    PRIMARY = "PRIMARY_PROBLEM"
    RELATED_SYMPTOM = "RELATED_SYMPTOM"
    SECONDARY_INDEPENDENT = "SECONDARY_INDEPENDENT_PROBLEM"
    WARNING = "WARNING"
    INFORMATIONAL = "INFORMATIONAL"


class RiskLevel(enum.Enum):
    SAFE = "SAFE"
    """Read-only / diagnostic. No state change."""
    CAUTION = "CAUTION"
    """Changes configuration or state, but is reversible and scoped."""
    HIGH_RISK = "HIGH_RISK"
    """Potentially disruptive or destructive; never auto-suggested as a first step."""


class ConfidenceLevel(enum.Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT = "INSUFFICIENT"


@dataclasses.dataclass(frozen=True)
class Confidence:
    """A rule's self-assessed confidence, plus *why* - never a bare number.

    Contract: a rule may only set ``Diagnosis.status = DIAGNOSED`` when
    ``level`` is HIGH or MEDIUM. LOW or INSUFFICIENT confidence must produce
    ``UNKNOWN_INSUFFICIENT_EVIDENCE`` (or ``UNKNOWN_CONFLICTING_EVIDENCE`` if
    ``contradicting_evidence_count > 0``) instead - "unknown is better than
    wrong". ``rationale`` is shown to the administrator in --details so
    confidence is never a black-box score.
    """

    level: ConfidenceLevel
    rationale: str
    corroborating_evidence_count: int = 0
    contradicting_evidence_count: int = 0


@dataclasses.dataclass(frozen=True)
class EvidenceRef:
    """Points back at a real Finding or EvidenceItem, never a copy of its content."""

    evidence_id: str
    kind: str
    """"finding" or "item"."""
    why_relevant: str
    """One sentence: why this specific piece of evidence supports/contradicts the diagnosis."""


@dataclasses.dataclass(frozen=True)
class Action:
    """A recommended step. Only ever created by deterministic pack code - never by AI."""

    description: str
    risk: RiskLevel
    command: Optional[str] = None
    rationale: str = ""
    reference: Optional[str] = None
    """Optional citation (doc URL) backing this action, for administrator trust."""


@dataclasses.dataclass(frozen=True)
class VerificationCondition:
    """How to check, after remediation, whether this specific diagnosis cleared.

    ``recheck`` re-runs the same evidence collection this rule depends on and
    returns True only if the rule's trigger condition is actually gone -
    never merely "the remediation command exited 0".
    """

    description: str
    recheck: Callable[[EvidenceBundle], bool]
    healthcheck_sources: List[str] = dataclasses.field(default_factory=list)
    """ipa-healthcheck --source values to re-run, surfaced to the CLI so `verify`
    knows what fresh evidence to collect before calling `recheck`."""


@dataclasses.dataclass
class Diagnosis:
    """One diagnostic rule's output for one run."""

    pack_id: str
    rule_id: str
    status: DiagnosisStatus
    title: str
    why: str
    """Plain-language explanation of the reasoning, grounded in evidence_for."""
    confidence: Confidence
    severity: Severity = Severity.WARNING
    """The rule's own assessment of how bad this is IF true (independent of
    confidence, which is how sure we are it IS true). Drives prioritization
    in correlate.py alongside status/confidence and cross-pack causality -
    rule authors should not set `priority` themselves."""
    evidence_for: List[EvidenceRef] = dataclasses.field(default_factory=list)
    evidence_against: List[EvidenceRef] = dataclasses.field(default_factory=list)
    impact: str = ""
    priority: PriorityBucket = PriorityBucket.INFORMATIONAL
    actions: List[Action] = dataclasses.field(default_factory=list)
    """Ordered - first action is "do this first"."""
    verification: List[VerificationCondition] = dataclasses.field(default_factory=list)
    limitations: str = ""
    next_diagnostic_step: Optional[str] = None
    """Required when status is UNKNOWN_*: the safe read-only step that would
    disambiguate, per "unknown is better than wrong"."""
    upstream_candidates: List[str] = dataclasses.field(default_factory=list)
    """pack_ids that, per the documented causality chain (DNS -> Kerberos ->
    Replication -> Certificates, Directory Server underlying all), could be the
    real root cause behind this diagnosis's symptoms. Used by correlate.py to
    demote this to RELATED_SYMPTOM when an upstream pack fires concurrently."""
    diagnosis_id: str = ""
    related_to_titles: List[str] = dataclasses.field(default_factory=list)
    """Set by correlate.py (never by rule code) when this diagnosis is
    demoted to RELATED_SYMPTOM: the title(s) of the concurrently-firing
    upstream diagnosis/diagnoses that caused the demotion. Lets the CLI show
    "related to: <title>" directly rather than requiring the reader to parse
    it out of `why`'s free text - a real UX gap found in review, where a
    RELATED SYMPTOMS entry's parent problem wasn't visually obvious."""
    resolution_key: Optional[str] = None
    """Stable id of the diagnosed *condition* that a resolution procedure can
    attach to (e.g. "healthcheck.service-not-running"). Set by rule code only
    when the rule's evidence identifies the condition exactly."""
    variant: Optional[str] = None
    """Sub-case of the condition that changes the fix (e.g. "expiring" vs "expired")."""
    bindings: Dict[str, Any] = dataclasses.field(default_factory=dict)
    """Structured values from the evidence that a procedure may use (validated
    again by type before any of them can reach a printed command)."""
    evidence_severity: Optional["Severity"] = None
    """Worst severity of the evidence itself when a rule reports a higher diagnosis severity (e.g. a file-mode
    WARNING reported as an ERROR-level diagnosis). Ranking uses the lower of the two, so such a diagnosis never
    outranks one backed by ERROR/CRITICAL evidence."""
    not_caused_by: List[str] = dataclasses.field(default_factory=list)
    """Packs that cannot be this diagnosis's upstream cause given its own evidence (e.g. a replication break whose
    error is a network connection failure is not caused by a Kerberos key problem). Used by correlate.py only."""
    explains_downstream: bool = True
    """Whether this diagnosis, as a real problem, can be the upstream cause of other packs' symptoms
    (correlate.py). False for conditions that cannot break other subsystems, e.g. a too-permissive
    mode on a PKI (Tomcat) file filed under the directory-server pack."""

    def __post_init__(self) -> None:
        if not self.diagnosis_id:
            self.diagnosis_id = f"{self.pack_id}.{self.rule_id}"
        if self.status != DiagnosisStatus.DIAGNOSED and not self.next_diagnostic_step:
            raise ValueError(
                f"{self.diagnosis_id}: UNKNOWN/transient diagnoses must set "
                "next_diagnostic_step (a safe read-only step to disambiguate)."
            )
        if self.status == DiagnosisStatus.DIAGNOSED and self.confidence.level in (
            ConfidenceLevel.LOW,
            ConfidenceLevel.INSUFFICIENT,
        ):
            raise ValueError(
                f"{self.diagnosis_id}: a DIAGNOSED status requires HIGH or MEDIUM confidence "
                f"(got {self.confidence.level.value}). Use UNKNOWN_INSUFFICIENT_EVIDENCE or "
                "UNKNOWN_CONFLICTING_EVIDENCE instead - unknown is better than wrong."
            )


class OverallStatus(enum.Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"
    NOT_FULLY_VERIFIED = "NOT_FULLY_VERIFIED"
    """No problem was found in the evidence that WAS collected, but some
    relevant evidence could not be collected, so health is not established.
    Deliberately distinct from HEALTHY: "could not verify" is never
    "healthy" (see EvidenceCompleteness)."""


@dataclasses.dataclass
class UnverifiedCapability:
    """One thing ipa-diagnose could not check this run, and why."""

    capability: str
    collector: str
    reason: str
    permission_related: bool = False
    hint: str = ""
    """Plain-language remedy (what the administrator can do), when known."""


@dataclasses.dataclass
class EvidenceCompleteness:
    """How much of the relevant evidence was actually collected.

    level: "complete" (everything relevant collected), "partial" (something
    relevant is unverified), or "insufficient" (ipa-healthcheck itself, the
    base evidence, could not be collected - nothing can be claimed healthy).
    ruv_state: "VERIFIED", "NOT_VERIFIED" (collection failed) or
    "NOT_COLLECTED" (not attempted / no data, e.g. replayed fixture without
    RUV evidence). A NOT_VERIFIED RUV is never itself a stale-RUV claim."""

    level: str = "complete"
    healthcheck_collected: bool = True
    unverified: List[UnverifiedCapability] = dataclasses.field(default_factory=list)
    ruv_state: str = "NOT_COLLECTED"
    ruv_reason: Optional[str] = None


@dataclasses.dataclass
class UndiagnosedFinding:
    """An ipa-healthcheck finding (WARNING or worse) that no ipa-diagnose rule explains.

    Kept structurally so it can never silently disappear: ipa-diagnose has no
    deterministic logic for it, which is NOT a statement that it is harmless.
    All text is sanitized (untrusted); nothing here is ever executed."""

    source: str
    check: str
    severity: str
    message: str
    reason: str
    crashed: bool = False
    check_known_since: Optional[str] = None
    """First upstream ipa-healthcheck release this check appears in (None = unknown to this build)."""
    ipa_healthcheck_version: Optional[str] = None
    finding_id: str = ""
    key: Optional[str] = None
    """ipa-healthcheck's own ``kw.key`` (e.g. the DNS record name), which tells apart findings with identical text."""


@dataclasses.dataclass
class DiagnosisReport:
    """Top-level result of one ipa-diagnose run."""

    generated_at: str
    hostname: str
    overall_status: OverallStatus
    diagnoses: List[Diagnosis] = dataclasses.field(default_factory=list)
    collection_errors: List[str] = dataclasses.field(default_factory=list)
    packs_evaluated: List[str] = dataclasses.field(default_factory=list)
    replay_source: Optional[str] = None
    environment: Optional[EnvironmentInfo] = None
    evidence_completeness: EvidenceCompleteness = dataclasses.field(default_factory=EvidenceCompleteness)
    unclaimed_warnings: int = 0
    """ipa-healthcheck WARNING findings that no diagnostic rule covers (never dropped silently)."""
    undiagnosed_findings: List[UndiagnosedFinding] = dataclasses.field(default_factory=list)
    """Every WARNING-or-worse ipa-healthcheck finding no rule explains, by name (never only a count)."""
    resolutions: Dict[str, Any] = dataclasses.field(default_factory=dict)
    """diagnosis_id -> resolution.engine.Resolution, filled by resolve_report (1.0 Slice 1)."""
    carried_fixes: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    carried_diagnoses: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    """Saved diagnosis entries kept only because a fix shown for them is not confirmed yet (verify)."""
    service_states: Dict[str, str] = dataclasses.field(default_factory=dict)
    """unit -> systemd state, read by ipa-diagnose itself when ipa-healthcheck gave no results (live only)."""
    side_effects: List[str] = dataclasses.field(default_factory=list)
    """State changes observed during collection that ipa-diagnose itself did not make."""
    """Verify-baseline fix records carried over from the previous run (see verify.carry_forward_fixes)."""
    unknown_severity_findings: List[str] = dataclasses.field(default_factory=list)
    """Human-readable notes for any Finding whose raw ipa-healthcheck
    ``result`` value did not match a known severity (see Severity.UNKNOWN) -
    surfaced so an unrecognized-but-treated-as-ERROR-equivalent value is
    visible, not silently absorbed into a diagnosis with no explanation."""

    def by_priority(self, bucket: PriorityBucket) -> List[Diagnosis]:
        return [d for d in self.diagnoses if d.priority == bucket]
