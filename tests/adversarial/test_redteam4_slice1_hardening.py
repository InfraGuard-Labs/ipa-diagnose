"""Slice 1 hardening: the fourth fresh red team's reproductions (tests/fixtures/redteam4, CONSTRUCTED)."""

from __future__ import annotations

import pathlib

import pytest

from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.resolution.checks import ReplayRunner
from ipa_diagnose.resolution.engine import resolve_report

ROOT = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "redteam4"


def run(name, resolve=False):
    report = run_diagnosis(collect_evidence(replay_dir=str(ROOT / name)))
    if resolve:
        resolve_report(report, ReplayRunner(str(ROOT / name)))
    return report


def bucket(report, needle):
    return [d.priority.value for d in report.diagnoses if needle in d.title]


@pytest.mark.parametrize("name,victim", [
    ("c1b-backup-full-named-aci", "named failed to start"),
    ("c9-backup-full-ra-desync", "RA agent certificate"),
    ("c28-dslog-full-plus-ra-desync", "RA agent certificate"),
    ("c15-srv-missing-plus-repl-refused", "Replication agreement broken"),
    ("c24-named-down-plus-repl-refused", "Replication agreement broken"),
    ("c3b-pki-down-ra-desync", "RA agent certificate"),
    ("c2b-pki-down-cm-trust", "cannot validate the CA"),
])
def test_unrelated_problems_are_not_absorbed(name, victim):
    assert "RELATED_SYMPTOM" not in bucket(run(name), victim)


@pytest.mark.parametrize("name", ["c4-dsdisk-full-dirsrv-down", "c16-dsdisk-full-dirsrv-down-offered"])
def test_full_directory_server_disk_is_the_cause_of_the_stopped_dirsrv(name):
    report = run(name, resolve=True)
    assert bucket(report, "Disk space exhaustion") == ["PRIMARY_PROBLEM"]
    assert bucket(report, "'dirsrv' is not running") == ["RELATED_SYMPTOM"]
    assert not any(r.status == "OFFERED" for r in report.resolutions.values())  # no "start it" while the disk is full


def test_related_to_names_the_actual_cause_only():
    report = run("c4-dsdisk-full-dirsrv-down")
    d = next(x for x in report.diagnoses if "'dirsrv' is not running" in x.title)
    assert d.related_to_titles and all("Disk space" in t for t in d.related_to_titles)
