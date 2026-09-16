"""End-to-end tests for the kerberos diagnostic pack, driven entirely by the
fixtures under tests/fixtures/kerberos/<scenario>/ - each scenario's
meta.json documents the exact expected outcome and *why*.

Each test follows the same real flow the CLI uses: collect_evidence(replay)
-> run_diagnosis(bundle) -> compare against meta.json's expectations.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from ipa_diagnose.engine.model import DiagnosisStatus, OverallStatus, PriorityBucket
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence

FIXTURES_ROOT = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "kerberos"

SCENARIOS = [
    "healthy",
    "clock-skew",
    "keytab-mismatch",
    "dns-discovery",
    "ambiguous-preauth",
]


def _load_meta(scenario: str) -> dict:
    return json.loads((FIXTURES_ROOT / scenario / "meta.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_scenario_matches_meta(scenario: str):
    fixture_dir = FIXTURES_ROOT / scenario
    meta = _load_meta(scenario)

    bundle = collect_evidence(replay_dir=str(fixture_dir))
    report = run_diagnosis(bundle)

    assert report.overall_status == OverallStatus(meta["expected_overall_status"])

    kerberos_diagnoses = {d.diagnosis_id: d for d in report.diagnoses if d.pack_id == "kerberos"}
    expected_ids = {d["diagnosis_id"] for d in meta["expected_diagnoses"]}
    assert set(kerberos_diagnoses.keys()) == expected_ids, (
        f"{scenario}: expected kerberos diagnoses {expected_ids}, got {set(kerberos_diagnoses.keys())}"
    )

    for expected in meta["expected_diagnoses"]:
        actual = kerberos_diagnoses[expected["diagnosis_id"]]
        assert actual.status == DiagnosisStatus(expected["status"])
        assert actual.priority == PriorityBucket(expected["priority"])


def test_healthy_has_no_kerberos_evidence_items_collected():
    bundle = collect_evidence(replay_dir=str(FIXTURES_ROOT / "healthy"))
    # No WARNING-or-worse finding among the pack's healthcheck_sources means
    # the staged collectors (kerberos_client, journal_krb5kdc) never run.
    assert bundle.items == []
    assert bundle.collection_errors == []


def test_clock_skew_diagnosis_cites_real_evidence_ids():
    bundle = collect_evidence(replay_dir=str(FIXTURES_ROOT / "clock-skew"))
    report = run_diagnosis(bundle)
    diag = next(d for d in report.diagnoses if d.diagnosis_id == "kerberos.clock-skew")

    known_finding_ids = {f.finding_id for f in bundle.findings}
    known_item_ids = {i.item_id for i in bundle.items}
    for ref in diag.evidence_for:
        if ref.kind == "finding":
            assert ref.evidence_id in known_finding_ids
        else:
            assert ref.evidence_id in known_item_ids

    assert diag.confidence.level.value in ("HIGH", "MEDIUM")
    assert diag.upstream_candidates == []


def test_keytab_mismatch_does_not_use_generic_error_string_alone():
    bundle = collect_evidence(replay_dir=str(FIXTURES_ROOT / "keytab-mismatch"))
    report = run_diagnosis(bundle)
    diag = next(d for d in report.diagnoses if d.diagnosis_id == "kerberos.keytab-kvno-mismatch")

    assert diag.status == DiagnosisStatus.DIAGNOSED
    # The disambiguating evidence must be the direct kvno_comparison item, not
    # just the generic healthcheck finding text.
    item_refs = [r for r in diag.evidence_for if r.kind == "item"]
    assert any(r.evidence_id == "kerberos_client.kvno_comparison" for r in item_refs)
    # ktutil must never be recommended as a remediation action.
    for action in diag.actions:
        assert "ktutil" not in (action.command or "").lower()
        assert "ktutil" not in action.description.lower()


def test_dns_discovery_diagnosis_cites_dns_upstream():
    bundle = collect_evidence(replay_dir=str(FIXTURES_ROOT / "dns-discovery"))
    report = run_diagnosis(bundle)
    diag = next(d for d in report.diagnoses if d.diagnosis_id == "kerberos.kdc-discovery-failure")

    assert diag.upstream_candidates == ["dns"]
    assert diag.severity.value == "CRITICAL"


def test_ambiguous_preauth_requires_next_diagnostic_step():
    bundle = collect_evidence(replay_dir=str(FIXTURES_ROOT / "ambiguous-preauth"))
    report = run_diagnosis(bundle)
    diag = next(d for d in report.diagnoses if d.diagnosis_id == "kerberos.keytab-kvno-mismatch")

    assert diag.status == DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE
    assert diag.next_diagnostic_step
    assert "kvno" in diag.next_diagnostic_step.lower()


def test_all_kerberos_evidence_refs_point_to_real_evidence():
    """Cross-scenario guard against ever inventing an EvidenceRef."""

    for scenario in SCENARIOS:
        bundle = collect_evidence(replay_dir=str(FIXTURES_ROOT / scenario))
        report = run_diagnosis(bundle)
        known_finding_ids = {f.finding_id for f in bundle.findings}
        known_item_ids = {i.item_id for i in bundle.items}
        for diag in report.diagnoses:
            if diag.pack_id != "kerberos":
                continue
            for ref in diag.evidence_for + diag.evidence_against:
                pool = known_finding_ids if ref.kind == "finding" else known_item_ids
                assert ref.evidence_id in pool, f"{scenario}/{diag.diagnosis_id}: invented evidence {ref}"
