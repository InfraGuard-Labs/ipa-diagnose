"""Tests for the directory-server diagnostic pack.

The first group runs the full pipeline (collect_evidence -> run_diagnosis)
against the fixtures under tests/fixtures/directory-server/, matching
outcomes recorded in each fixture's meta.json. The second group exercises
branches of the 4 rules that aren't covered by those 5 required fixture
directories (healthy/disk-space/permissions/nss-db/index-health) - the
confident "hard failure" branch of disk-space-exhaustion, and the
UNKNOWN_CONFLICTING_EVIDENCE branch of nss-tls-db-format - directly against
hand-built EvidenceBundle objects, so those code paths aren't left untested.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from ipa_diagnose.engine.model import ConfidenceLevel, DiagnosisStatus, RiskLevel
from ipa_diagnose.engine.packs.directory_server import PACK
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.evidence.model import EvidenceBundle, EvidenceItem, Finding, Provenance, Severity

FIXTURES_DIR = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "directory-server"


def _load_meta(fixture_name: str) -> dict:
    return json.loads((FIXTURES_DIR / fixture_name / "meta.json").read_text(encoding="utf-8"))


def _assert_evidence_refs_are_real(diagnosis, bundle: EvidenceBundle) -> None:
    finding_ids = {f.finding_id for f in bundle.findings}
    item_ids = {i.item_id for i in bundle.items}
    for ref in list(diagnosis.evidence_for) + list(diagnosis.evidence_against):
        if ref.kind == "finding":
            assert ref.evidence_id in finding_ids, f"evidence cites unknown finding_id {ref.evidence_id!r}"
        elif ref.kind == "item":
            assert ref.evidence_id in item_ids, f"evidence cites unknown item_id {ref.evidence_id!r}"
        else:
            pytest.fail(f"unexpected EvidenceRef.kind {ref.kind!r}")


@pytest.mark.parametrize("fixture_name", ["healthy", "disk-space", "permissions", "nss-db", "index-health"])
def test_fixture_matches_expected_outcome(fixture_name):
    meta = _load_meta(fixture_name)
    fixture_dir = FIXTURES_DIR / fixture_name

    bundle = collect_evidence(replay_dir=str(fixture_dir))
    report = run_diagnosis(bundle)

    assert not bundle.collection_errors, f"{fixture_name}: unexpected collection errors: {bundle.collection_errors}"

    assert report.overall_status.value == meta["expected_overall_status"], (
        f"{fixture_name}: expected overall_status={meta['expected_overall_status']!r}, "
        f"got {report.overall_status.value!r} (diagnoses: {[d.diagnosis_id for d in report.diagnoses]})"
    )

    actual_by_id = {d.diagnosis_id: d for d in report.diagnoses}
    expected_ids = {e["diagnosis_id"] for e in meta["expected_diagnoses"]}

    # Only assert on directory-server-pack diagnoses; the other (currently
    # stub) packs contribute nothing today, but this keeps the test from
    # being brittle if that changes.
    ds_diagnoses = {k: v for k, v in actual_by_id.items() if k.startswith("directory-server.")}
    assert set(ds_diagnoses.keys()) == expected_ids, (
        f"{fixture_name}: expected diagnosis ids {expected_ids}, got {set(ds_diagnoses.keys())}"
    )

    for expected in meta["expected_diagnoses"]:
        actual = ds_diagnoses[expected["diagnosis_id"]]
        assert actual.status.value == expected["status"], (
            f"{fixture_name}/{expected['diagnosis_id']}: expected status={expected['status']!r}, "
            f"got {actual.status.value!r}"
        )
        assert actual.priority.value == expected["priority"], (
            f"{fixture_name}/{expected['diagnosis_id']}: expected priority={expected['priority']!r}, "
            f"got {actual.priority.value!r}"
        )
        # Core "never invent evidence" contract.
        _assert_evidence_refs_are_real(actual, bundle)
        assert actual.upstream_candidates == [], "directory-server sits at the base of the causality chain"
        if actual.status != DiagnosisStatus.DIAGNOSED:
            assert actual.next_diagnostic_step, (
                f"{fixture_name}/{expected['diagnosis_id']}: non-DIAGNOSED status must set next_diagnostic_step"
            )
        else:
            assert actual.confidence.level in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM)


def test_disk_space_transient_actions_start_safe_and_never_high_risk():
    bundle = collect_evidence(replay_dir=str(FIXTURES_DIR / "disk-space"))
    report = run_diagnosis(bundle)
    diag = next(d for d in report.diagnoses if d.diagnosis_id == "directory-server.disk-space-exhaustion")
    assert diag.actions[0].risk == RiskLevel.SAFE
    assert all(a.risk != RiskLevel.HIGH_RISK for a in diag.actions)


def test_permissions_ambiguous_next_step_covers_both_unix_and_selinux():
    bundle = collect_evidence(replay_dir=str(FIXTURES_DIR / "permissions"))
    report = run_diagnosis(bundle)
    diag = next(d for d in report.diagnoses if d.diagnosis_id == "directory-server.ownership-selinux-mismatch")
    step = diag.next_diagnostic_step.lower()
    assert "ausearch" in step
    assert "-lz" in step or "ls -lz" in step


def test_index_health_recommends_scoped_reindex_and_warns_off_bare_command():
    bundle = collect_evidence(replay_dir=str(FIXTURES_DIR / "index-health"))
    report = run_diagnosis(bundle)
    diag = next(d for d in report.diagnoses if d.diagnosis_id == "directory-server.missing-system-index")
    high_risk = [a for a in diag.actions if a.risk == RiskLevel.HIGH_RISK]
    assert high_risk, "bare db2index.pl must be called out as HIGH_RISK"
    assert "replicat" in high_risk[0].rationale.lower()
    scoped = [a for a in diag.actions if a.risk == RiskLevel.CAUTION and "-t" in (a.command or "")]
    assert scoped, "expected a scoped `-t <attribute>` reindex action"
    # Safest step first, dangerous warning last.
    assert diag.actions[0].risk == RiskLevel.SAFE
    assert diag.actions[-1].risk == RiskLevel.HIGH_RISK


# ---------------------------------------------------------------------------
# Direct PACK.evaluate() tests for branches the 5 fixtures above don't cover.
# ---------------------------------------------------------------------------


def _bundle(findings=None, items=None) -> EvidenceBundle:
    return EvidenceBundle(
        hostname="ipa01.example.test",
        collected_at=EvidenceBundle.now(),
        findings=findings or [],
        items=items or [],
    )


def _finding(source, check, severity, message="", finding_id=None, keywords=None) -> Finding:
    return Finding(
        finding_id=finding_id or f"{source}.{check}",
        source=source,
        check=check,
        severity=severity,
        message=message,
        keywords=keywords or {},
        provenance=Provenance(source="ipa-healthcheck"),
    )


def _journal_item(item_id, category, message, severity=Severity.ERROR) -> EvidenceItem:
    return EvidenceItem(
        item_id=item_id,
        kind="dirsrv_journal_line",
        summary=message,
        data={"unit": "dirsrv@TEST.service", "timestamp": "", "message": message, "category": category},
        severity=severity,
        provenance=Provenance(source="collector:journal_dirsrv"),
    )


def test_disk_space_hard_failure_is_diagnosed_high_confidence_when_journal_corroborates():
    findings = [
        _finding(
            "ipahealthcheck.system.filesystemspace",
            "FileSystemSpaceCheck",
            Severity.CRITICAL,
            message="/var/lib/dirsrv/: free space percentage under threshold: 4% < 20%",
            keywords={"store": "/var/lib/dirsrv/", "percent_free": 4, "threshold": 20},
        )
    ]
    items = [_journal_item("journal-dirsrv-0", "disk_space", "No space left on device")]
    bundle = _bundle(findings=findings, items=items)
    diagnoses = PACK.evaluate(bundle)
    diag = next(d for d in diagnoses if d.rule_id == "disk-space-exhaustion")
    assert diag.status == DiagnosisStatus.DIAGNOSED
    assert diag.confidence.level == ConfidenceLevel.HIGH
    assert diag.severity == Severity.CRITICAL
    _assert_evidence_refs_are_real(diag, bundle)


def test_disk_space_no_findings_does_not_fire():
    bundle = _bundle()
    diagnoses = PACK.evaluate(bundle)
    assert not any(d.rule_id == "disk-space-exhaustion" for d in diagnoses)


def test_nss_conflicting_when_cert_expiry_finding_also_present():
    findings = [
        _finding(
            "ipahealthcheck.ipa.certs",
            "IPACertmongerExpirationCheck",
            Severity.ERROR,
            message="Certificate is expired",
        )
    ]
    items = [_journal_item("journal-dirsrv-0", "nss_tls", "TLS alert: handshake failure")]
    bundle = _bundle(findings=findings, items=items)
    diagnoses = PACK.evaluate(bundle)
    diag = next(d for d in diagnoses if d.rule_id == "nss-tls-db-format")
    assert diag.status == DiagnosisStatus.UNKNOWN_CONFLICTING_EVIDENCE
    assert diag.confidence.contradicting_evidence_count == 1
    assert diag.evidence_against
    assert diag.next_diagnostic_step
    _assert_evidence_refs_are_real(diag, bundle)


def test_nss_tls_journal_without_cert_expiry_is_diagnosed_as_db_format_issue():
    items = [_journal_item("journal-dirsrv-0", "nss_tls", "SEC_ERROR_BAD_DATABASE: unable to load certificate")]
    bundle = _bundle(items=items)
    diagnoses = PACK.evaluate(bundle)
    diag = next(d for d in diagnoses if d.rule_id == "nss-tls-db-format")
    assert diag.status == DiagnosisStatus.DIAGNOSED
    assert diag.confidence.level in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM)
    assert "certificates pack" in diag.why.lower()


def test_ownership_diagnosed_when_ipafilecheck_names_exact_value():
    findings = [
        _finding(
            "ipahealthcheck.ipa.files",
            "IPAFileNSSDBCheck",
            Severity.ERROR,
            message="Ownership of /etc/dirsrv/slapd-TEST/cert8.db is root and should be dirsrv",
            keywords={"key": "/etc/dirsrv/slapd-TEST/cert8.db", "path": "/etc/dirsrv/slapd-TEST/cert8.db", "type": "owner", "expected": "dirsrv", "got": "root"},
        )
    ]
    bundle = _bundle(findings=findings)
    diagnoses = PACK.evaluate(bundle)
    diag = next(d for d in diagnoses if d.rule_id == "ownership-selinux-mismatch")
    assert diag.status == DiagnosisStatus.DIAGNOSED
    assert diag.confidence.level == ConfidenceLevel.MEDIUM  # no journal corroboration in this bundle
    assert any(a.risk == RiskLevel.CAUTION for a in diag.actions)
    _assert_evidence_refs_are_real(diag, bundle)


def test_index_backends_success_does_not_fire():
    findings = [_finding("ipahealthcheck.ds.backends", "BackendsCheck", Severity.SUCCESS)]
    bundle = _bundle(findings=findings)
    diagnoses = PACK.evaluate(bundle)
    assert not any(d.rule_id == "missing-system-index" for d in diagnoses)


def test_no_evidence_at_all_produces_no_diagnoses():
    bundle = _bundle()
    diagnoses = PACK.evaluate(bundle)
    assert diagnoses == []
