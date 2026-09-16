import pytest

from ipa_diagnose.engine.model import (
    Confidence,
    ConfidenceLevel,
    Diagnosis,
    DiagnosisStatus,
    PriorityBucket,
)
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.model import EvidenceBundle, Severity


def test_empty_bundle_is_healthy():
    bundle = EvidenceBundle(hostname="h", collected_at=EvidenceBundle.now())
    report = run_diagnosis(bundle)
    assert report.overall_status.value == "HEALTHY"
    assert report.diagnoses == []
    assert set(report.packs_evaluated) == {
        "directory-server",
        "dns",
        "kerberos",
        "replication",
        "certificates",
    }


def test_diagnosed_requires_high_or_medium_confidence():
    with pytest.raises(ValueError):
        Diagnosis(
            pack_id="p",
            rule_id="r",
            status=DiagnosisStatus.DIAGNOSED,
            title="t",
            why="w",
            confidence=Confidence(level=ConfidenceLevel.LOW, rationale="weak"),
        )
    with pytest.raises(ValueError):
        Diagnosis(
            pack_id="p",
            rule_id="r",
            status=DiagnosisStatus.DIAGNOSED,
            title="t",
            why="w",
            confidence=Confidence(level=ConfidenceLevel.INSUFFICIENT, rationale="weak"),
        )
    # HIGH/MEDIUM are fine.
    Diagnosis(
        pack_id="p",
        rule_id="r",
        status=DiagnosisStatus.DIAGNOSED,
        title="t",
        why="w",
        confidence=Confidence(level=ConfidenceLevel.HIGH, rationale="strong"),
    )


def test_unknown_status_requires_next_diagnostic_step():
    with pytest.raises(ValueError):
        Diagnosis(
            pack_id="p",
            rule_id="r",
            status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
            title="t",
            why="w",
            confidence=Confidence(level=ConfidenceLevel.LOW, rationale="ambiguous"),
        )
    # Providing next_diagnostic_step is fine.
    Diagnosis(
        pack_id="p",
        rule_id="r",
        status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
        title="t",
        why="w",
        confidence=Confidence(level=ConfidenceLevel.LOW, rationale="ambiguous"),
        next_diagnostic_step="Run X to disambiguate.",
    )


def test_severity_ordering():
    assert Severity.SUCCESS < Severity.WARNING < Severity.ERROR < Severity.CRITICAL
