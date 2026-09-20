"""Replay fixtures used by the release lifecycle/post-publish gates (tests/fixtures/coverage/*)."""

import json
import pathlib

import pytest

from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence

ROOT = pathlib.Path(__file__).parents[1] / "fixtures" / "coverage"


@pytest.mark.parametrize("name", sorted(p.name for p in ROOT.iterdir()))
def test_coverage_fixture_matches_meta(name):
    meta = json.loads((ROOT / name / "meta.json").read_text(encoding="utf-8"))
    report = run_diagnosis(collect_evidence(replay_dir=str(ROOT / name)))
    assert report.overall_status.value == meta["expected_overall_status"]
    ids = {d.diagnosis_id for d in report.diagnoses}
    for exp in meta["expected_diagnoses"]:
        assert exp["diagnosis_id"] in ids
    if name == "ds-cert-expired":
        assert "directory-server.nss-tls-db-format" not in ids
    if name == "undiagnosed-warning":
        assert not report.diagnoses and report.undiagnosed_findings and report.evidence_completeness.level == "complete"
