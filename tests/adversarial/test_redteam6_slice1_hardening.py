"""Slice 1 hardening: the sixth fresh red team's reproductions (tests/fixtures/redteam6, CONSTRUCTED)."""

from __future__ import annotations

import pathlib

import pytest

from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.resolution.checks import ReplayRunner
from ipa_diagnose.resolution.engine import resolve_report

ROOT = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "redteam6"


def run(name):
    report = run_diagnosis(collect_evidence(replay_dir=str(ROOT / name)))
    resolve_report(report, ReplayRunner(str(ROOT / name)))
    return report


def bucket(report, needle):
    return [d.priority.value for d in report.diagnoses if needle in d.title]


@pytest.mark.parametrize("name", ["p11a", "p11", "p11w"])
def test_named_running_now_is_not_diagnosed_down_from_old_journal_lines(name):
    report = run(name)
    assert not [d for d in report.diagnoses if d.status.value == "DIAGNOSED"
                and ("named failed to start" in d.title or "named/bind-dyndb-ldap is not running" in d.title)]
    assert "RELATED_SYMPTOM" not in bucket(report, "DNS record(s)")


@pytest.mark.parametrize("name", ["p2r", "p3"])
def test_disk_with_plenty_of_absolute_space_does_not_explain_a_stopped_dirsrv(name):
    report = run(name)
    assert bucket(report, "'dirsrv' is not running") == ["PRIMARY_PROBLEM"]


def test_busy_disk_control_still_offers_the_start():
    report = run("p2c")
    assert bucket(report, "'dirsrv' is not running") == ["PRIMARY_PROBLEM"]
    assert any(r.status == "OFFERED" for r in report.resolutions.values())


@pytest.mark.parametrize("name", ["p12", "p5"])
def test_a_check_that_ran_is_not_a_symptom_of_a_stopped_service(name):
    report = run(name)
    assert "RELATED_SYMPTOM" not in bucket(report, "no diagnostic rul")
