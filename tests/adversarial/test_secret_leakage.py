"""End-to-end secret-leakage tests: a secret injected anywhere in evidence
that a Diagnosis cites must never appear in the resulting AI payload -
tested through the real build_ai_payload() pipeline (not just the
lower-level redact.py unit tests), since that's the function that actually
gates what leaves the process.
"""

from ipa_diagnose.engine.model import (
    Action,
    Confidence,
    ConfidenceLevel,
    Diagnosis,
    DiagnosisStatus,
    EvidenceRef,
    RiskLevel,
)
from ipa_diagnose.evidence.model import EvidenceBundle, EvidenceItem, Finding, Provenance, Severity
from ipa_diagnose.privacy.minimize import build_ai_payload

SECRET_AWS_KEY = "AKIAABCDEFGHIJKLMNOP"
SECRET_PASSWORD = "hunter2-super-secret"


def _base_diagnosis() -> Diagnosis:
    return Diagnosis(
        pack_id="directory-server",
        rule_id="ownership-selinux-mismatch",
        status=DiagnosisStatus.DIAGNOSED,
        title="test",
        why="test",
        confidence=Confidence(level=ConfidenceLevel.HIGH, rationale="test"),
        actions=[Action(description="check", risk=RiskLevel.SAFE, command="ls -lZ")],
    )


def test_secret_in_finding_message_is_not_sent():
    finding = Finding(
        finding_id="f1",
        source="ipahealthcheck.ds.config",
        check="ConfigCheck",
        severity=Severity.ERROR,
        message=f"bind failed using access key {SECRET_AWS_KEY} in config",
        provenance=Provenance(source="ipa-healthcheck"),
    )
    bundle = EvidenceBundle(hostname="h", collected_at=EvidenceBundle.now(), findings=[finding])
    diagnosis = _base_diagnosis()
    diagnosis.evidence_for = [EvidenceRef(evidence_id="f1", kind="finding", why_relevant="trigger")]

    payload = build_ai_payload(bundle, diagnosis)
    assert SECRET_AWS_KEY not in payload.user_prompt
    assert "aws_access_key" in payload.redaction_matches


def test_secret_in_finding_keywords_is_not_sent():
    finding = Finding(
        finding_id="f1",
        source="ipahealthcheck.ds.config",
        check="ConfigCheck",
        severity=Severity.ERROR,
        message="bind configuration error",
        keywords={"msg": "bind configuration error", "bindpw": SECRET_PASSWORD},
        provenance=Provenance(source="ipa-healthcheck"),
    )
    bundle = EvidenceBundle(hostname="h", collected_at=EvidenceBundle.now(), findings=[finding])
    diagnosis = _base_diagnosis()
    diagnosis.evidence_for = [EvidenceRef(evidence_id="f1", kind="finding", why_relevant="trigger")]

    payload = build_ai_payload(bundle, diagnosis)
    assert SECRET_PASSWORD not in payload.user_prompt
    assert "field:bindpw" in payload.redaction_matches


def test_secret_in_evidence_item_data_is_not_sent():
    item = EvidenceItem(
        item_id="i1",
        kind="journal_line",
        summary=f"connection using token {SECRET_AWS_KEY}",
        data={"token": SECRET_AWS_KEY, "line": f"auth token={SECRET_AWS_KEY}"},
        severity=Severity.ERROR,
        provenance=Provenance(source="collector"),
    )
    bundle = EvidenceBundle(hostname="h", collected_at=EvidenceBundle.now(), items=[item])
    diagnosis = _base_diagnosis()
    diagnosis.evidence_for = [EvidenceRef(evidence_id="i1", kind="item", why_relevant="trigger")]

    payload = build_ai_payload(bundle, diagnosis)
    assert SECRET_AWS_KEY not in payload.user_prompt


def test_evidence_not_cited_by_the_diagnosis_is_never_sent_at_all():
    """Minimum-evidence-selection: even unredacted secrets sitting elsewhere
    in the bundle must not leak simply because they're in the same run -
    only evidence the diagnosis actually cites is considered."""

    cited = Finding(
        finding_id="f1",
        source="ipahealthcheck.ds.config",
        check="ConfigCheck",
        severity=Severity.ERROR,
        message="ownership mismatch on cert8.db",
        provenance=Provenance(source="ipa-healthcheck"),
    )
    uncited_with_secret = Finding(
        finding_id="f2",
        source="ipahealthcheck.ipa.certs",
        check="IPACertTracking",
        severity=Severity.WARNING,
        message=f"unrelated finding containing {SECRET_AWS_KEY}",
        provenance=Provenance(source="ipa-healthcheck"),
    )
    bundle = EvidenceBundle(hostname="h", collected_at=EvidenceBundle.now(), findings=[cited, uncited_with_secret])
    diagnosis = _base_diagnosis()
    diagnosis.evidence_for = [EvidenceRef(evidence_id="f1", kind="finding", why_relevant="trigger")]

    payload = build_ai_payload(bundle, diagnosis)
    assert SECRET_AWS_KEY not in payload.user_prompt
    assert payload.excluded_evidence_count >= 1
