"""Slice 1 hardening: the seventh fresh red team's reproductions (tests/fixtures/redteam7, CONSTRUCTED)."""

from __future__ import annotations

import pathlib

import pytest

from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.resolution.checks import ReplayRunner
from ipa_diagnose.resolution.engine import resolve_report

ROOT = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "redteam7"


def run(name):
    report = run_diagnosis(collect_evidence(replay_dir=str(ROOT / name)))
    resolve_report(report, ReplayRunner(str(ROOT / name)))
    return report


def bucket(report, needle):
    return [d.priority.value for d in report.diagnoses if needle in d.title]


@pytest.mark.parametrize("name,victim", [("p2s03", "named failed to start"), ("p2s08", "RA agent certificate"),
                                         ("p2d", "'dirsrv' is not running"), ("p1", "'dirsrv' is not running")])
def test_disk_with_absolute_space_left_absorbs_nothing(name, victim):
    assert "RELATED_SYMPTOM" not in bucket(run(name), victim)


@pytest.mark.parametrize("name", ["p1", "p1c"])
def test_crashed_dirsrv_start_fix_offered_when_the_disk_is_not_really_full(name):
    report = run(name)
    assert bucket(report, "'dirsrv' is not running") == ["PRIMARY_PROBLEM"]
    assert any(r.status == "OFFERED" for r in report.resolutions.values())
