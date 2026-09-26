"""Slice 1 hardening: the fifth fresh red team's reproductions (tests/fixtures/redteam5, CONSTRUCTED)."""

from __future__ import annotations

import pathlib

import pytest

from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.resolution.checks import ReplayRunner
from ipa_diagnose.resolution.engine import resolve_report

ROOT = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "redteam5"


def run(name):
    report = run_diagnosis(collect_evidence(replay_dir=str(ROOT / name)))
    resolve_report(report, ReplayRunner(str(ROOT / name)))
    return report


def bucket(report, needle):
    return [d.priority.value for d in report.diagnoses if needle in d.title]


def test_ordinary_busy_disk_does_not_explain_a_crashed_dirsrv():
    report = run("s02")
    assert bucket(report, "'dirsrv' is not running") == ["PRIMARY_PROBLEM"]
    assert any(r.status == "OFFERED" for r in report.resolutions.values())


def test_really_full_directory_server_disk_still_explains_the_chain():
    report = run("s10")
    assert bucket(report, "Disk space exhaustion") == ["PRIMARY_PROBLEM"]
    assert bucket(report, "'dirsrv' is not running") == ["RELATED_SYMPTOM"]
    assert not any(r.status == "OFFERED" for r in report.resolutions.values())


@pytest.mark.parametrize("name,victim", [
    ("s01", "Replication agreement broken"), ("s03", "named failed to start"), ("s04", "Replication agreement broken"),
    ("s08", "RA agent certificate"), ("s14", "named failed to start"),
])
def test_independent_problems_are_not_absorbed_by_a_disk(name, victim):
    assert "RELATED_SYMPTOM" not in bucket(run(name), victim)


def test_stale_ca_error_on_a_monitoring_request_does_not_split_the_ca_cascade():
    assert bucket(run("s07"), "Certmonger tracking is stuck") == ["RELATED_SYMPTOM"]
