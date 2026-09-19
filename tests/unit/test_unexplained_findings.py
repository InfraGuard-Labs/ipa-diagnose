"""An ipa-healthcheck ERROR/CRITICAL finding must never vanish (live-discovered).

Fixture: REAL LIVE CAPTURE - ipa-healthcheck --failures-only from a real
FreeIPA 4.13.3 server with dirsrv stopped. Before the fix ipa-diagnose dropped
`dirsrv: not running` and the CRITICAL follow-on and headlined a CS.cfg
permission warning as the PRIMARY problem."""

from __future__ import annotations

import pathlib

from ipa_diagnose.engine.model import DiagnosisStatus, OverallStatus, PriorityBucket
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence

FIXTURE = pathlib.Path(__file__).parent.parent / "fixtures" / "real-freeipa-capture" / "dirsrv-stopped"


def _report():
    return run_diagnosis(collect_evidence(replay_dir=str(FIXTURE)))


def test_stopped_directory_server_is_reported_not_dropped():
    report = _report()
    titles = [d.title for d in report.diagnoses]
    assert any("'dirsrv' is not running" in t for t in titles), titles


def test_stopped_service_is_the_primary_problem_and_status_is_critical():
    report = _report()
    primary = report.by_priority(PriorityBucket.PRIMARY)[0]
    assert "dirsrv" in primary.title
    assert primary.status == DiagnosisStatus.DIAGNOSED
    assert report.overall_status == OverallStatus.CRITICAL


def test_service_finding_does_not_claim_a_root_cause():
    d = next(d for d in _report().diagnoses if "dirsrv" in d.title)
    assert "NOT determined" in d.why
    assert all(a.command is None or "restart" not in a.command and "start " not in a.command.split(";")[0] for a in d.actions)


def test_unexplained_critical_followon_is_shown_as_unknown_never_a_guessed_cause():
    report = _report()
    unknown = [d for d in report.diagnoses if d.rule_id == "unexplained-findings"]
    assert len(unknown) == 1
    assert unknown[0].status == DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE
    assert "IPAauthzdatapacCheck" in unknown[0].why
    assert unknown[0].next_diagnostic_step


def test_claimed_findings_are_not_duplicated(tmp_path):
    """A finding already used as evidence by a real rule is not re-reported."""
    from ipa_diagnose.engine import unexplained

    bundle = collect_evidence(replay_dir=str(FIXTURE))
    first = unexplained.unexplained_finding_diagnoses(bundle, [])
    claimed_ids = {r.evidence_id for d in first for r in d.evidence_for}
    assert claimed_ids
    assert unexplained.unexplained_finding_diagnoses(bundle, first) == []
