"""Slice 1 hardening: the second fresh red team's reproductions (fixtures under tests/fixtures/redteam2,
CONSTRUCTED). Each asserts the outcome that is true."""

from __future__ import annotations

import pathlib

import pytest

from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.resolution.checks import ReplayRunner
from ipa_diagnose.resolution.engine import resolve_report

ROOT = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "redteam2"


def run(name, resolve=False):
    report = run_diagnosis(collect_evidence(replay_dir=str(ROOT / name)))
    if resolve:
        resolve_report(report, ReplayRunner(str(ROOT / name)))
    return report


def titles(report, bucket):
    return [d.title for d in report.diagnoses if d.priority.value == bucket]


def primary(report):
    return titles(report, "PRIMARY_PROBLEM")[0]


@pytest.mark.parametrize("name,root", [
    ("a1-ds-mode-loose-plus-kdc-unreach", "no KDC could be found"),
    ("g2-named-aci-plus-ds-mode-loose", "named failed to start"),
    ("b1-backup-full-plus-kdc-unreach", "no KDC could be found"),
    ("g1-forwarder-timeout-plus-kdc-unreach", "no KDC could be found"),
    ("g3-forwarder-timeout-plus-repl-peer-down", "Replication agreement broken"),
    ("h2-ra-desync-cscfg-plus-ds-permjournal", "RA agent certificate"),
])
def test_real_root_cause_is_not_demoted_or_outranked(name, root):
    report = run(name)
    assert root in primary(report)
    assert not any(root in t for t in titles(report, "RELATED_SYMPTOM"))


@pytest.mark.parametrize("name", ["a3-ds-mode-loose-plus-unexplained-crit", "d1-certmonger-stopped-plus-unexplained-crit",
                                  "i1-ca-chain-expired-plus-normal-expiring"])
def test_unexplained_critical_findings_are_never_absorbed_by_unrelated_or_weaker_problems(name):
    report = run(name)
    assert not any("no diagnostic rul" in t for t in titles(report, "RELATED_SYMPTOM"))


def test_permissive_directory_server_file_mode_cannot_explain_other_packs():
    report = run("a1-ds-mode-loose-plus-kdc-unreach")
    assert not any("File ownership" in t for t in titles(report, "PRIMARY_PROBLEM"))


def test_stale_host_keytab_does_not_hide_a_network_replication_break():
    report = run("j2-host-keytab-stale-plus-repl-peer-down")
    assert any("Replication agreement broken" in t for t in titles(report, "SECONDARY_INDEPENDENT_PROBLEM"))


@pytest.mark.parametrize("name", ["c1-offset-plus-principal-missing", "c2-offset-plus-principal-missing-offered",
                                  "c3-offset-plus-keytab-no-keys-offered"])
def test_big_local_offset_does_not_explain_a_kinit_failure_that_names_another_cause(name):
    report = run(name, resolve=True)
    assert not any("clock skew" in d.title and d.status.value == "DIAGNOSED" for d in report.diagnoses)
    assert not any(r.status == "OFFERED" and r.procedure_id == "proc.time.step-clock-with-chrony"
                   for r in report.resolutions.values())


def test_clock_skew_control_still_diagnosed():
    report = run("c4-control-original")
    assert "clock skew" in primary(report)
