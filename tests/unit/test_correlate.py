from ipa_diagnose.engine import correlate
from ipa_diagnose.engine.model import Confidence, ConfidenceLevel, Diagnosis, DiagnosisStatus, OverallStatus, PriorityBucket
from ipa_diagnose.evidence.model import EvidenceBundle, Severity


def _diagnosed(pack_id, rule_id, severity=Severity.ERROR, upstream=None, confidence=ConfidenceLevel.HIGH):
    return Diagnosis(
        pack_id=pack_id,
        rule_id=rule_id,
        status=DiagnosisStatus.DIAGNOSED,
        title=f"{pack_id}.{rule_id} problem",
        why="because evidence",
        confidence=Confidence(level=confidence, rationale="test", corroborating_evidence_count=2),
        severity=severity,
        upstream_candidates=upstream or [],
    )


def _bundle():
    return EvidenceBundle(hostname="h", collected_at=EvidenceBundle.now())


def test_downstream_demoted_when_upstream_fires():
    dns_problem = _diagnosed("dns", "named-down", severity=Severity.CRITICAL)
    kerberos_symptom = _diagnosed("kerberos", "kdc-discovery-failure", upstream=["dns"])

    report = correlate.build_report(_bundle(), [dns_problem, kerberos_symptom], packs_evaluated=["dns", "kerberos"])

    dns_result = next(d for d in report.diagnoses if d.pack_id == "dns")
    kerberos_result = next(d for d in report.diagnoses if d.pack_id == "kerberos")
    assert dns_result.priority == PriorityBucket.PRIMARY
    assert kerberos_result.priority == PriorityBucket.RELATED_SYMPTOM
    assert "dns" in kerberos_result.why


def test_independent_problems_become_primary_and_secondary():
    a = _diagnosed("replication", "peer-unreachable", severity=Severity.ERROR)
    b = _diagnosed("certificates", "cert-expired", severity=Severity.CRITICAL)

    report = correlate.build_report(_bundle(), [a, b], packs_evaluated=["replication", "certificates"])

    priorities = {d.pack_id: d.priority for d in report.diagnoses}
    # Higher severity (CRITICAL cert-expired) should win PRIMARY over ERROR-level replication issue.
    assert priorities["certificates"] == PriorityBucket.PRIMARY
    assert priorities["replication"] == PriorityBucket.SECONDARY_INDEPENDENT
    assert report.overall_status == OverallStatus.CRITICAL


def test_warning_severity_diagnosed_does_not_become_primary():
    warn = _diagnosed("certificates", "cert-expiring-soon", severity=Severity.WARNING)
    report = correlate.build_report(_bundle(), [warn], packs_evaluated=["certificates"])
    assert report.diagnoses[0].priority == PriorityBucket.WARNING
    assert report.overall_status == OverallStatus.DEGRADED
