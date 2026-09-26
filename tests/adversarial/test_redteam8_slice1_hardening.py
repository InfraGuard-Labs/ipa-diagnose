"""Slice 1 hardening: the eighth fresh red team's reproductions (tests/fixtures/redteam8, CONSTRUCTED)."""

from __future__ import annotations

import pathlib

from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence

ROOT = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "redteam8"


def bucket(name, needle):
    report = run_diagnosis(collect_evidence(replay_dir=str(ROOT / name)))
    return [d.priority.value for d in report.diagnoses if needle in d.title]


def test_ldap_access_denial_is_not_a_full_disk_symptom_while_dirsrv_runs():
    assert "RELATED_SYMPTOM" not in bucket("p1_aci_reallyfull", "missing LDAP ACI")


def test_tracking_result_that_ran_is_not_a_stopped_certmonger_symptom():
    assert "RELATED_SYMPTOM" not in bucket("p3_cm_stopped_tracking", "no diagnostic rul")

