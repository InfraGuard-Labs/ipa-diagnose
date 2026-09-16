"""Fixture-driven tests for the certificates/CA diagnostic pack.

Each scenario directory under tests/fixtures/certificates/ carries a
meta.json describing the expected outcome (see the module docstring in
engine/packs/certificates.py for why each rule fires or stays silent per
scenario). This test replays evidence collection exactly the way `--replay`
does, runs it through the same engine/run.py entry point used live, and
checks the resulting report against meta.json - not against the pack's
internals - so it stays honest about what an administrator would actually
see.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from ipa_diagnose.engine.model import DiagnosisStatus, PriorityBucket
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence

FIXTURES_ROOT = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "certificates"
SCENARIOS = ["healthy", "expiring", "expired", "ambiguous"]


def _load_meta(scenario: str) -> dict:
    meta_path = FIXTURES_ROOT / scenario / "meta.json"
    return json.loads(meta_path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_certificates_scenarios_match_meta(scenario: str):
    fixture_dir = FIXTURES_ROOT / scenario
    meta = _load_meta(scenario)

    bundle = collect_evidence(replay_dir=str(fixture_dir))
    report = run_diagnosis(bundle)

    assert report.overall_status.value == meta["expected_overall_status"], (
        f"{scenario}: overall_status {report.overall_status.value} != expected {meta['expected_overall_status']}"
    )

    actual_by_id = {d.diagnosis_id: d for d in report.diagnoses if d.pack_id == "certificates"}
    expected_ids = {entry["diagnosis_id"] for entry in meta["expected_diagnoses"]}
    assert set(actual_by_id.keys()) == expected_ids, (
        f"{scenario}: certificates diagnoses {sorted(actual_by_id)} != expected {sorted(expected_ids)}"
    )

    for expected in meta["expected_diagnoses"]:
        diag = actual_by_id[expected["diagnosis_id"]]
        assert diag.status == DiagnosisStatus(expected["status"]), (
            f"{scenario}: {expected['diagnosis_id']} status {diag.status.value} != expected {expected['status']}"
        )
        assert diag.priority == PriorityBucket(expected["priority"]), (
            f"{scenario}: {expected['diagnosis_id']} priority {diag.priority.value} != expected {expected['priority']}"
        )
        # Every diagnosis must ground itself in real evidence from the
        # bundle it was given - never fabricated - and UNKNOWN/transient
        # statuses must always carry a safe next step, per the engine's own
        # __post_init__ guardrails (re-asserted here as a pack-level
        # regression check, not just relying on the constructor not raising).
        for ref in diag.evidence_for:
            if ref.kind == "finding":
                assert any(f.finding_id == ref.evidence_id for f in bundle.findings), (
                    f"{scenario}: {diag.diagnosis_id} cites unknown finding {ref.evidence_id}"
                )
            elif ref.kind == "item":
                assert any(i.item_id == ref.evidence_id for i in bundle.items), (
                    f"{scenario}: {diag.diagnosis_id} cites unknown item {ref.evidence_id}"
                )
        if diag.status != DiagnosisStatus.DIAGNOSED:
            assert diag.next_diagnostic_step, f"{scenario}: {diag.diagnosis_id} is {diag.status} but has no next_diagnostic_step"


def test_healthy_scenario_does_not_stage_targeted_collectors():
    bundle = collect_evidence(replay_dir=str(FIXTURES_ROOT / "healthy"))
    assert bundle.items == []
    assert bundle.collection_errors == []


def test_ambiguous_scenario_stages_certmonger_and_journal_items():
    bundle = collect_evidence(replay_dir=str(FIXTURES_ROOT / "ambiguous"))
    assert any(i.kind == "certmonger_request" for i in bundle.items)
    assert any(i.kind == "pki_journal_line" for i in bundle.items)


def test_upstream_candidates_match_documented_causality():
    for scenario in SCENARIOS:
        bundle = collect_evidence(replay_dir=str(FIXTURES_ROOT / scenario))
        report = run_diagnosis(bundle)
        for diag in report.diagnoses:
            if diag.pack_id != "certificates":
                continue
            if diag.rule_id in ("certmonger-tracking-stuck", "renewal-master-unreachable"):
                assert diag.upstream_candidates == ["replication"]
            elif diag.rule_id == "ra-agent-desync":
                assert diag.upstream_candidates == ["directory-server"]
            elif diag.rule_id == "cert-expired":
                assert diag.upstream_candidates == []
