"""Slice 1 hardening: the third fresh red team's reproductions (tests/fixtures/redteam3, CONSTRUCTED)."""

from __future__ import annotations

import pathlib

import pytest

from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence

ROOT = pathlib.Path(__file__).resolve().parents[1] / "fixtures"


def run(name):
    return run_diagnosis(collect_evidence(replay_dir=str(ROOT / name)))


def bucket(report, needle):
    return [d.priority.value for d in report.diagnoses if needle in d.title]


@pytest.mark.parametrize("name", ["redteam3/q1", "redteam3/q1w"])
def test_missing_kerberos_srv_record_is_the_cause_of_the_kdc_failure(name):
    report = run(name)
    assert bucket(report, "DNS record(s)") == ["PRIMARY_PROBLEM"]
    assert bucket(report, "no KDC could be found") == ["RELATED_SYMPTOM"]


@pytest.mark.parametrize("name", ["redteam3/q3", "redteam3/q5", "redteam3/q6", "redteam3/q9"])
def test_independent_critical_findings_are_not_absorbed_by_unrelated_or_weaker_causes(name):
    report = run(name)
    assert "RELATED_SYMPTOM" not in bucket(report, "no diagnostic rul")


def test_forward_zone_collision_does_not_explain_an_unreachable_replica():
    report = run("redteam3/q7")
    assert bucket(report, "Replication agreement broken") == ["PRIMARY_PROBLEM"]


def test_journal_line_about_dirsrv_does_not_corroborate_a_file_in_etc():
    report = run("redteam3/q8")
    d = next(x for x in report.diagnoses if "File ownership" in x.title)
    assert d.confidence.level.value != "HIGH"
    assert "RELATED_SYMPTOM" not in bucket(report, "RA agent certificate")


@pytest.mark.parametrize("name", ["redteam/p5c-pki-down-certmonger", "redteam/p5d-pki-down-certmonger-hyphen"])
def test_stopped_local_ca_absorbs_its_own_certificate_symptoms(name):
    report = run(name)
    assert all(b == "RELATED_SYMPTOM" for b in bucket(report, "Certmonger tracking is stuck") + bucket(report, "RA agent / Dogtag"))
