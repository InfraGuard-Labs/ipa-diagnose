"""Fixture-driven tests for the DNS diagnostic pack.

Each tests/fixtures/dns/<scenario>/ directory is replayed through the real
collect_evidence -> run_diagnosis pipeline (the same path the CLI uses) and
the resulting DiagnosisReport is checked against that scenario's meta.json.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from ipa_diagnose.engine.model import DiagnosisStatus, OverallStatus, PriorityBucket
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence

FIXTURES_DIR = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "dns"

SCENARIOS = [
    "healthy",
    "named-down",
    "forward-zone-conflict",
    "srv-missing",
    "srv-error-collectors-unavailable",
]


def _load_meta(scenario: str) -> dict:
    meta_path = FIXTURES_DIR / scenario / "meta.json"
    return json.loads(meta_path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_dns_fixture_matches_expected_report(scenario: str):
    meta = _load_meta(scenario)
    fixture_dir = FIXTURES_DIR / scenario

    bundle = collect_evidence(replay_dir=str(fixture_dir))
    report = run_diagnosis(bundle)

    assert report.overall_status == OverallStatus(meta["expected_overall_status"]), (
        f"{scenario}: expected overall_status={meta['expected_overall_status']!r}, "
        f"got {report.overall_status!r} with diagnoses={[ (d.diagnosis_id, d.status, d.priority) for d in report.diagnoses ]}"
    )

    dns_diagnoses = {d.diagnosis_id: d for d in report.diagnoses if d.pack_id == "dns"}
    expected_ids = {entry["diagnosis_id"] for entry in meta["expected_diagnoses"]}
    assert set(dns_diagnoses.keys()) == expected_ids, (
        f"{scenario}: expected dns diagnosis ids {expected_ids}, got {set(dns_diagnoses.keys())}"
    )

    for entry in meta["expected_diagnoses"]:
        diag = dns_diagnoses[entry["diagnosis_id"]]
        assert diag.status == DiagnosisStatus(entry["status"]), (
            f"{scenario}/{entry['diagnosis_id']}: expected status {entry['status']}, got {diag.status}"
        )
        assert diag.priority == PriorityBucket(entry["priority"]), (
            f"{scenario}/{entry['diagnosis_id']}: expected priority {entry['priority']}, got {diag.priority}"
        )

    min_errors = meta.get("expected_collection_errors_at_least")
    if min_errors is not None:
        assert len(bundle.collection_errors) >= min_errors


def test_named_down_cites_directory_server_upstream_and_real_evidence():
    fixture_dir = FIXTURES_DIR / "named-down"
    bundle = collect_evidence(replay_dir=str(fixture_dir))
    report = run_diagnosis(bundle)

    diag = next(d for d in report.diagnoses if d.diagnosis_id == "dns.named-service-down")
    assert diag.upstream_candidates == ["directory-server"]
    assert diag.confidence.level.value in ("HIGH", "MEDIUM")

    # Every cited evidence_for must trace back to a real finding/item id in the bundle.
    finding_ids = {f.finding_id for f in bundle.findings}
    item_ids = {i.item_id for i in bundle.items}
    for ref in diag.evidence_for:
        if ref.kind == "finding":
            assert ref.evidence_id in finding_ids
        else:
            assert ref.evidence_id in item_ids


def test_srv_missing_evidence_refs_are_real():
    fixture_dir = FIXTURES_DIR / "srv-missing"
    bundle = collect_evidence(replay_dir=str(fixture_dir))
    report = run_diagnosis(bundle)

    diag = next(d for d in report.diagnoses if d.diagnosis_id == "dns.srv-autodiscovery")
    assert diag.status == DiagnosisStatus.DIAGNOSED
    assert diag.confidence.level.value == "HIGH"
    assert "single" in diag.limitations.lower() or "resolver" in diag.limitations.lower()

    finding_ids = {f.finding_id for f in bundle.findings}
    item_ids = {i.item_id for i in bundle.items}
    for ref in diag.evidence_for:
        if ref.kind == "finding":
            assert ref.evidence_id in finding_ids
        else:
            assert ref.evidence_id in item_ids


def test_srv_error_without_corroboration_is_unknown_not_diagnosed():
    fixture_dir = FIXTURES_DIR / "srv-error-collectors-unavailable"
    bundle = collect_evidence(replay_dir=str(fixture_dir))
    report = run_diagnosis(bundle)

    diag = next(d for d in report.diagnoses if d.diagnosis_id == "dns.srv-autodiscovery")
    assert diag.status == DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE
    assert diag.next_diagnostic_step
    assert "dig" in diag.next_diagnostic_step.lower()
    assert len(bundle.collection_errors) >= 2
    assert all(e.permission_related for e in bundle.collection_errors if e.collector in ("dns_lookup", "journal_named"))


def test_forward_zone_warning_false_positive_is_not_diagnosed_without_corroboration():
    fixture_dir = FIXTURES_DIR / "forward-zone-conflict"
    bundle = collect_evidence(replay_dir=str(fixture_dir))
    report = run_diagnosis(bundle)

    diagnosis_ids = {d.diagnosis_id for d in report.diagnoses}
    # The idns WARNING (issue #270 style false positive) must not, by itself,
    # produce an srv-autodiscovery diagnosis - only the journal-confirmed
    # forward-zone-conflict should fire.
    assert "dns.srv-autodiscovery" not in diagnosis_ids
    assert "dns.forward-zone-conflict" in diagnosis_ids
