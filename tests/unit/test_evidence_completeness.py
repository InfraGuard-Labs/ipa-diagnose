"""Evidence-completeness semantics: "could not verify" is never "healthy".

Regressions for the live-discovered gap (public v0.1.1 reported HEALTHY when
ipa-healthcheck could not run at all, and silently dropped RUV evidence when
``ipa-replica-manage list-ruv`` needed the Directory Manager password)."""

from __future__ import annotations

import io
import json
import subprocess

from rich.console import Console

from ipa_diagnose.cli import _exit_code_for
from ipa_diagnose.engine import correlate
from ipa_diagnose.engine.model import (
    Confidence,
    ConfidenceLevel,
    Diagnosis,
    DiagnosisStatus,
    OverallStatus,
)
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence import collect
from ipa_diagnose.evidence.model import CollectionError, EvidenceBundle, EvidenceItem, Severity
from ipa_diagnose.render.console import render_report
from ipa_diagnose.render.json_output import report_to_dict


def _bundle(errors=(), items=()):
    b = EvidenceBundle(hostname="ipa01.example.test", collected_at=EvidenceBundle.now())
    b.collection_errors.extend(errors)
    b.items.extend(items)
    return b


def _ruv_item():
    return EvidenceItem(
        item_id="ruv:domain:4",
        kind="replication_ruv",
        summary="ruv",
        data={"replica_id": 4, "alive": True, "suffix": "domain"},
    )


def _render(report, details=False):
    buf = io.StringIO()
    render_report(report, Console(file=buf, width=120, force_terminal=False, highlight=False), details=details)
    return buf.getvalue()


def test_healthcheck_unavailable_is_unknown_never_healthy():
    b = _bundle(errors=[CollectionError(collector="ipa-healthcheck", message="ipa-healthcheck is not installed")])
    report = run_diagnosis(b)
    assert report.overall_status == OverallStatus.UNKNOWN
    assert report.evidence_completeness.level == "insufficient"
    assert report.evidence_completeness.healthcheck_collected is False
    assert _exit_code_for(report) == 3
    out = _render(report)
    assert "No problems detected" not in out
    assert "nothing can be reported healthy" in out


def test_all_collectors_fail_is_never_healthy(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    bundle = collect.collect_evidence()
    assert bundle.collection_errors, "the missing ipa-healthcheck must be recorded"
    report = run_diagnosis(bundle)
    assert report.overall_status != OverallStatus.HEALTHY
    assert report.overall_status == OverallStatus.UNKNOWN


def test_healthcheck_ok_but_ruv_not_collected_is_not_fully_verified():
    b = _bundle(
        errors=[
            CollectionError(
                collector="replication_agreements",
                message="ipa-replica-manage list-ruv exited 1: Directory Manager password required",
                permission_related=True,
            )
        ]
    )
    report = run_diagnosis(b)
    assert report.overall_status == OverallStatus.NOT_FULLY_VERIFIED
    assert report.evidence_completeness.level == "partial"
    assert report.evidence_completeness.ruv_state == "NOT_VERIFIED"
    assert "Directory Manager" in report.evidence_completeness.ruv_reason
    assert _exit_code_for(report) == 4
    out = _render(report)
    # The RUV gap is in the header block, before any footer.
    assert out.index("RUV state: NOT VERIFIED") < out.index("No problem was observed")
    assert "NOT a stale-RUV finding" in " ".join(out.split())
    assert "No problems detected" not in out


def test_ruv_not_verified_never_creates_a_stale_ruv_diagnosis():
    b = _bundle(errors=[CollectionError(collector="replication_agreements", message="list-ruv failed")])
    report = run_diagnosis(b)
    assert report.diagnoses == []


def test_complete_evidence_is_healthy_and_ruv_verified():
    report = run_diagnosis(_bundle(items=[_ruv_item()]))
    assert report.overall_status == OverallStatus.HEALTHY
    assert report.evidence_completeness.level == "complete"
    assert report.evidence_completeness.ruv_state == "VERIFIED"
    assert _exit_code_for(report) == 0
    assert "No problems detected" in _render(report)


def test_found_problem_is_never_hidden_by_a_collection_gap():
    d = Diagnosis(
        pack_id="dns",
        rule_id="named-down",
        status=DiagnosisStatus.DIAGNOSED,
        title="named down",
        why="w",
        confidence=Confidence(level=ConfidenceLevel.HIGH, rationale="t", corroborating_evidence_count=2),
        severity=Severity.CRITICAL,
    )
    b = _bundle(errors=[CollectionError(collector="ipa-healthcheck", message="boom")])
    report = correlate.build_report(b, [d], packs_evaluated=["dns"])
    assert report.overall_status == OverallStatus.CRITICAL
    assert report.evidence_completeness.level == "insufficient"


def test_one_optional_collector_failure_does_not_make_everything_unknown():
    b = _bundle(errors=[CollectionError(collector="journal_dirsrv", message="journalctl timed out")])
    report = run_diagnosis(b)
    assert report.overall_status == OverallStatus.NOT_FULLY_VERIFIED
    assert report.evidence_completeness.healthcheck_collected is True


def test_json_contract_exposes_completeness_and_keeps_collection_errors():
    b = _bundle(errors=[CollectionError(collector="replication_agreements", message="Directory Manager password required", permission_related=True)])
    data = json.loads(json.dumps(report_to_dict(run_diagnosis(b))))
    assert data["overall_status"] == "NOT_FULLY_VERIFIED"
    assert data["collection_errors"] == ["replication_agreements: Directory Manager password required"]
    ec = data["evidence_completeness"]
    assert ec["level"] == "partial"
    assert ec["ruv_state"] == "NOT_VERIFIED"
    assert ec["unverified"][0]["permission_related"] is True


def test_hostile_collector_error_text_is_sanitized_and_markup_escaped():
    hostile = "\x1b[31mRED\x1b[0m \x1b]0;pwn\x07 [bold red]INJECT[/bold red]\x00\x08 " + "A" * 1000
    b = _bundle(errors=[CollectionError(collector="replication_agreements", message=hostile)])
    report = run_diagnosis(b)
    text = report.collection_errors[0] + report.evidence_completeness.ruv_reason
    assert "\x1b" not in text and "\x07" not in text and "\x00" not in text
    assert len(report.collection_errors[0]) < 400
    out = _render(report, details=True)
    assert "\x1b" not in out
    assert "[bold red]INJECT" in out  # shown literally, not interpreted as markup


def test_partial_replication_failure_end_to_end_via_collect(monkeypatch):
    """list succeeds but list-ruv needs DM: previously silent, now visible."""

    def fake_run(args, **kwargs):
        if args[:1] == ["ipa-healthcheck"]:
            ok = [{"source": "ipahealthcheck.meta.services", "check": "dirsrv", "result": "SUCCESS", "uuid": "u", "kw": {}}]
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(ok), stderr="")
        if args[:2] == ["ipa-replica-manage", "list"]:
            return subprocess.CompletedProcess(args, 0, stdout="ipa02.example.test\n", stderr="")
        if args[:2] == ["ipa-replica-manage", "list-ruv"]:
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="Directory Manager password required")
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="unexpected")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/sbin/" + name)
    monkeypatch.setattr("socket.gethostname", lambda: "ipa01.example.test")
    report = run_diagnosis(collect.collect_evidence())
    assert report.overall_status == OverallStatus.NOT_FULLY_VERIFIED
    assert report.evidence_completeness.ruv_state == "NOT_VERIFIED"


# ---- regressions from the independent review ------------------------------


def test_verify_never_reports_resolved_when_healthcheck_could_not_run():
    from ipa_diagnose.verify import VerifyOutcome, compare

    previous = {
        "generated_at": "2026-01-01T00:00:00Z",
        "diagnoses": [{"diagnosis_id": "certificates.x", "pack_id": "certificates", "title": "cert problem"}],
    }
    current = run_diagnosis(_bundle(errors=[CollectionError(collector="ipa-healthcheck", message="exited 3")]))
    result = compare(previous, current)
    assert [i.outcome for i in result.items] == [VerifyOutcome.UNABLE_TO_VERIFY]


def test_verify_maps_failed_collector_to_its_pack_not_by_substring():
    from ipa_diagnose.verify import VerifyOutcome, compare

    previous = {
        "generated_at": "2026-01-01T00:00:00Z",
        "diagnoses": [
            {"diagnosis_id": "directory-server.x", "pack_id": "directory-server", "title": "ds problem"},
        ],
    }
    current = run_diagnosis(_bundle(errors=[CollectionError(collector="journal_dirsrv", message="timeout")]))
    result = compare(previous, current)
    assert result.items[0].outcome == VerifyOutcome.UNABLE_TO_VERIFY


def test_verify_banner_and_exit_are_not_clean_when_evidence_incomplete(monkeypatch, tmp_path):
    from ipa_diagnose import cli

    b = _bundle(errors=[CollectionError(collector="ipa-healthcheck", message="missing")])
    monkeypatch.setattr(cli, "_collect_and_diagnose", lambda args: (b, run_diagnosis(b)))
    monkeypatch.setattr(cli, "default_state_path", lambda: tmp_path / "state.json")
    buf = io.StringIO()
    args = cli.build_parser().parse_args(["verify"])
    code = cli.cmd_verify(args, Console(file=buf, width=120, highlight=False))
    assert code == 3  # no baseline: the fresh run is UNKNOWN, exactly what a plain diagnose returns


def test_ai_preview_with_incomplete_evidence_is_not_a_green_all_clear(monkeypatch):
    from ipa_diagnose import cli

    b = _bundle(errors=[CollectionError(collector="ipa-healthcheck", message="missing")])
    monkeypatch.setattr(cli, "_collect_and_diagnose", lambda args: (b, run_diagnosis(b)))
    buf = io.StringIO()
    args = cli.build_parser().parse_args(["ai-preview"])
    code = cli.cmd_ai_preview(args, Console(file=buf, width=120, highlight=False))
    assert code == 3
    assert "No primary or independent problems" not in buf.getvalue()


def test_ruv_state_is_verified_when_only_the_agreement_listing_failed():
    b = _bundle(
        errors=[CollectionError(collector="replication_agreements", message="ipa-replica-manage list exited 1: boom")],
        items=[_ruv_item()],
    )
    report = run_diagnosis(b)
    assert report.evidence_completeness.ruv_state == "VERIFIED"
    assert report.evidence_completeness.level == "partial"  # the agreement gap is still surfaced


def test_unregistered_collector_is_a_visible_gap(monkeypatch):
    from ipa_diagnose.evidence import collect as collect_mod

    monkeypatch.setattr(collect_mod, "get_collector", lambda name: None)
    monkeypatch.setattr("shutil.which", lambda name: None)
    bundle = collect_mod.collect_evidence()
    assert any("not registered" in e.message for e in bundle.collection_errors)


def test_sanitizer_handles_dcs_c1_length_and_bidi():
    text = correlate.sanitize_error_text("a\x1bPq;secret\x1b\b \x9b31m c ‮ rtl " + "Z" * 10000)
    assert "secret" not in text
    assert "\x9b" not in text and "‮" not in text
    assert len(text) <= 300


def test_json_has_fully_verified_flag():
    complete = report_to_dict(run_diagnosis(_bundle(items=[_ruv_item()])))
    partial = report_to_dict(run_diagnosis(_bundle(errors=[CollectionError(collector="x", message="y")])))
    assert complete["fully_verified"] is True
    assert partial["fully_verified"] is False


def test_no_replication_configured_is_verified_healthy_single_server():
    item = EvidenceItem(
        item_id="replication-topology:none",
        kind="replication_topology",
        summary="none",
        data={"state": "no_replication_configured"},
    )
    report = run_diagnosis(_bundle(items=[item]))
    assert report.evidence_completeness.ruv_state == "NONE_CONFIGURED"
    assert report.overall_status == OverallStatus.HEALTHY
    assert report.evidence_completeness.level == "complete"
