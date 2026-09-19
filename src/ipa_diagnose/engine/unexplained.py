"""Safety net: an ipa-healthcheck ERROR/CRITICAL finding must never vanish.

Found in live testing against a real FreeIPA 4.13.3 server: with the
Directory Server (or the KDC) stopped, ipa-healthcheck itself reported
``dirsrv: not running`` / ``krb5kdc: not running`` (ERROR) plus CRITICAL
follow-on failures - and ipa-diagnose dropped every one of them, because no
pack rule *claimed* those findings. The report then headlined an unrelated
file-permission warning as the PRIMARY problem while the server was down.

This module adds no new root-cause logic. It only guarantees visibility:

  - ``meta.services`` "<svc>: not running": ipa-healthcheck directly states
    that a required service is not running - that fact is DIAGNOSED (HIGH:
    the check itself asserts it). *Why* it is not running is deliberately
    left open, with a safe read-only next step.
  - Any other unclaimed ERROR/CRITICAL/unrecognized-severity finding is
    grouped into ONE honest UNKNOWN diagnosis quoting the raw finding, never
    a guessed root cause.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Set

from ipa_diagnose.engine.model import (
    Action,
    Confidence,
    ConfidenceLevel,
    Diagnosis,
    DiagnosisStatus,
    EvidenceRef,
    RiskLevel,
)
from ipa_diagnose.evidence.model import EvidenceBundle, Finding, Severity
from ipa_diagnose.textsafe import sanitize_text

PACK_ID = "healthcheck"

_NOT_RUNNING_RE = re.compile(r"^\s*([A-Za-z0-9_][A-Za-z0-9_.@-]*):\s*not running\s*$", re.IGNORECASE)
# ipa-healthcheck source/check identifiers are interpolated into a DISPLAYED
# read-only command: only plain identifiers are ever accepted (untrusted input).
_SOURCE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.]*$")
_CHECK_RE = re.compile(r"^[A-Za-z0-9_]+$")
_CORE_SERVICES = {"dirsrv", "krb5kdc", "kadmin", "httpd", "named", "named-pkcs11", "pki-tomcatd"}
_MAX_GROUPED = 6


def _claimed_ids(diagnoses: Iterable[Diagnosis]) -> Set[str]:
    claimed: Set[str] = set()
    for d in diagnoses:
        claimed.update(r.evidence_id for r in d.evidence_for)
        claimed.update(r.evidence_id for r in d.evidence_against)
    return claimed


def _short(text: object, limit: int = 160) -> str:
    return sanitize_text(text, limit)


def _service_diagnosis(f: Finding, service: str) -> Diagnosis:
    severity = Severity.CRITICAL if service.split("@")[0] in _CORE_SERVICES else Severity.ERROR
    return Diagnosis(
        pack_id=PACK_ID,
        rule_id=f"service-not-running-{service}",
        status=DiagnosisStatus.DIAGNOSED,
        title=f"Required service '{service}' is not running",
        why=(
            f"ipa-healthcheck ({_short(f.qualified_check, 80)}) directly reports: {_short(f.message)}. "
            "This is the check's own statement, not an inference. Why the service is not running is "
            "NOT determined by this finding."
        ),
        confidence=Confidence(
            level=ConfidenceLevel.HIGH,
            rationale="Direct report from ipa-healthcheck's service status check.",
            corroborating_evidence_count=1,
        ),
        severity=severity,
        evidence_for=[
            EvidenceRef(
                evidence_id=f.finding_id,
                kind="finding",
                why_relevant="ipa-healthcheck states this service is not running.",
            )
        ],
        impact=(
            "Functions that depend on this service are unavailable or degraded. Other failures in this "
            "report (for example ipa-healthcheck checks that could not connect) may be consequences."
        ),
        actions=[
            Action(
                description="Check why the service is not running before starting it.",
                risk=RiskLevel.SAFE,
                command=f"systemctl status --no-pager -- {service}; journalctl --no-pager -n 50 -u {service}",
                rationale="Read-only: shows the unit state and its most recent log lines.",
            )
        ],
        limitations="Root cause of the outage is not established by this finding alone.",
    )


def _grouped_unknown(findings: List[Finding]) -> Diagnosis:
    worst = max((f.severity for f in findings), key=lambda s: s.rank)
    shown = findings[:_MAX_GROUPED]
    lines = "; ".join(
        f"{_short(f.qualified_check, 80)} ({f.severity.value}): {_short(f.message or f.keywords, 110)}" for f in shown
    )
    more = f" (+{len(findings) - len(shown)} more)" if len(findings) > len(shown) else ""
    first = shown[0]
    safe_target = bool(_SOURCE_RE.match(first.source) and _CHECK_RE.match(first.check))
    recheck = (
        f"ipa-healthcheck --source {first.source} --check {first.check} --failures-only"
        if safe_target
        else "ipa-healthcheck --failures-only"
    )
    return Diagnosis(
        pack_id=PACK_ID,
        rule_id="unexplained-findings",
        status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
        title="ipa-healthcheck reports ERROR/CRITICAL findings that no diagnostic rule explains",
        why=(
            f"{len(findings)} finding(s) from ipa-healthcheck are at ERROR or CRITICAL and are not covered by any "
            f"ipa-diagnose rule, so their cause is not determined: {lines}{more}. They may be consequences of "
            "another problem in this report (for example a stopped service) or independent problems."
        ),
        confidence=Confidence(
            level=ConfidenceLevel.INSUFFICIENT,
            rationale="No rule links these findings to a cause; shown so they are never silently dropped.",
            corroborating_evidence_count=0,
        ),
        severity=worst,
        evidence_for=[
            EvidenceRef(evidence_id=f.finding_id, kind="finding", why_relevant="Unexplained ipa-healthcheck finding.")
            for f in shown
        ],
        impact="Unknown - depends on what the underlying checks were verifying.",
        next_diagnostic_step=recheck,
        actions=[
            Action(
                description="Re-run the specific failing check for full detail.",
                risk=RiskLevel.SAFE,
                command=recheck,
                rationale="Read-only.",
            )
        ],
        limitations="ipa-diagnose has no rule for these findings; this is a visibility safeguard, not a diagnosis.",
    )


def unexplained_finding_diagnoses(bundle: EvidenceBundle, diagnoses: List[Diagnosis]) -> List[Diagnosis]:
    claimed = _claimed_ids(diagnoses)
    unclaimed = [
        f
        for f in bundle.findings
        if f.severity.rank >= Severity.ERROR.rank and f.finding_id not in claimed
    ]
    result: List[Diagnosis] = []
    others: List[Finding] = []
    seen_services: Set[str] = set()
    for f in unclaimed:
        m = _NOT_RUNNING_RE.match(f.message or "") if f.source.endswith("meta.services") else None
        if m:
            service = m.group(1)
            if service not in seen_services:
                seen_services.add(service)
                result.append(_service_diagnosis(f, service))
        else:
            others.append(f)
    if others:
        result.append(_grouped_unknown(others))
    return result
