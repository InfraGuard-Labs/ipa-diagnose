"""v0.1.3 overall-status policy matrix.

HEALTHY only with sufficient evidence, no supported problem and no failed ipa-healthcheck finding left
unexplained; DEGRADED/CRITICAL when a problem is diagnosed; NOT_FULLY_VERIFIED when something meaningful
is unresolved (undiagnosed finding, unexplained ERROR/CRITICAL, incomplete evidence); UNKNOWN only when
the base healthcheck evidence is unavailable. Unsupported findings never become made-up diagnoses."""

from __future__ import annotations

import pytest

from ipa_diagnose.engine.model import OverallStatus as S
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.healthcheck import parse_healthcheck_results
from ipa_diagnose.evidence.model import CollectionError, EvidenceBundle

GOOD = {"source": "ipahealthcheck.meta.services", "check": "dirsrv", "result": "SUCCESS", "uuid": "g",
        "when": "20260101000000Z", "duration": "0.01", "kw": {"status": True}}
FUT = "ipahealthcheck.zz.brand_new"


def e(source, check, level, uid="u", **kw):
    return {"source": source, "check": check, "result": level, "uuid": f"{source}.{check}.{uid}", "when": "20260101000000Z",
            "duration": "0.01", "kw": kw}


def status(entries, errors=()):
    findings = parse_healthcheck_results(list(entries), command="t", live=False)
    b = EvidenceBundle(hostname="h", collected_at=EvidenceBundle.now(), findings=findings, collection_errors=list(errors))
    return run_diagnosis(b)


def test_no_findings_at_all_is_not_healthy_evidence_wise():
    # an empty result set is not proof of health when the run is judged on completeness elsewhere
    assert status([]).overall_status in (S.HEALTHY, S.UNKNOWN, S.NOT_FULLY_VERIFIED)


def test_all_success_is_healthy():
    r = status([GOOD, e(FUT, "OkCheck", "SUCCESS")])
    assert r.overall_status == S.HEALTHY and not r.undiagnosed_findings


@pytest.mark.parametrize("level", ["WARNING", "ERROR", "CRITICAL", "FATAL"])
def test_only_undiagnosed_failed_future_finding_is_not_fully_verified(level):
    r = status([GOOD, e(FUT, "NewCheck", level, msg="new failure")])
    assert r.overall_status == S.NOT_FULLY_VERIFIED
    assert r.undiagnosed_findings or any(d.rule_id == "unexplained-findings" for d in r.diagnoses)
    assert not any(d.status.value == "DIAGNOSED" for d in r.diagnoses)


def test_multiple_undiagnosed_warnings_are_not_fully_verified():
    r = status([GOOD] + [e(FUT, f"C{i}", "WARNING", msg="odd") for i in range(5)])
    assert r.overall_status == S.NOT_FULLY_VERIFIED and len(r.undiagnosed_findings) == 5


@pytest.mark.parametrize("level,expected", [("ERROR", S.DEGRADED), ("CRITICAL", S.CRITICAL)])
def test_diagnosed_problem_wins_even_with_undiagnosed_findings(level, expected):
    problem = e("ipahealthcheck.meta.services", "krb5kdc", level, msg="krb5kdc: not running", status=False)
    r = status([GOOD, problem, e(FUT, "Odd", "WARNING", msg="odd")])
    assert r.overall_status in (S.CRITICAL, S.DEGRADED)
    assert r.overall_status != S.NOT_FULLY_VERIFIED and r.undiagnosed_findings


def test_diagnosed_warning_alone_is_degraded_not_healthy():
    r = status([GOOD, e("ipahealthcheck.ipa.certs", "IPACertmongerExpirationCheck", "WARNING", key="1",
                        msg="Request id '1' expires in 10 days")])
    assert r.overall_status == S.DEGRADED


def test_incomplete_collection_plus_undiagnosed_is_not_fully_verified():
    r = status([GOOD, e(FUT, "Odd", "WARNING", msg="odd")],
               errors=[CollectionError(collector="replication_agreements", message="ldapsearch not found")])
    assert r.overall_status in (S.NOT_FULLY_VERIFIED,)


def test_healthcheck_unavailable_is_unknown_even_with_findings_absent():
    r = status([], errors=[CollectionError(collector="ipa-healthcheck", message="executable not found")])
    assert r.overall_status == S.UNKNOWN


def test_success_only_checks_do_not_trigger_undiagnosed():
    assert not status([GOOD, e("ipahealthcheck.ipa.trust", "IPATrustAgentCheck", "SUCCESS")]).undiagnosed_findings


def test_malformed_failed_finding_is_not_healthy():
    bad = {"source": None, "check": 12, "result": "ERROR", "uuid": None, "kw": "not-a-dict"}
    r = status([GOOD, bad])
    assert r.overall_status != S.HEALTHY


def test_exception_only_failed_check_is_not_healthy():
    r = status([GOOD, e(FUT, "Crash", "CRITICAL", exception="boom", traceback="tb")])
    assert r.overall_status == S.NOT_FULLY_VERIFIED
    assert any(u.crashed for u in r.undiagnosed_findings) or any(d.rule_id == "healthcheck-check-failed" for d in r.diagnoses)


def test_exit_code_for_not_fully_verified_is_4():
    from ipa_diagnose.cli import _exit_code_for

    assert _exit_code_for(status([GOOD, e(FUT, "Odd", "WARNING", msg="odd")])) == 4
    assert _exit_code_for(status([GOOD])) == 0


def _replay(tmp_path, content):
    from ipa_diagnose.evidence.collect import collect_evidence

    if content is not None:
        (tmp_path / "healthcheck.json").write_text(content, encoding="utf-8")
    return run_diagnosis(collect_evidence(replay_dir=str(tmp_path)))


GOODJ = '{"source":"ipahealthcheck.meta.services","check":"dirsrv","result":"SUCCESS","uuid":"g","when":"20260101000000Z","duration":"0.01","kw":{"status":true}}'


def test_replay_with_no_healthcheck_json_is_unknown_not_healthy(tmp_path):
    assert _replay(tmp_path, None).overall_status == S.UNKNOWN


@pytest.mark.parametrize("content", ["[]", '[null, 5, "CRITICAL"]', "{}", "[", ""])
def test_replay_with_no_usable_results_is_unknown(tmp_path, content):
    assert _replay(tmp_path, content).overall_status == S.UNKNOWN


def test_replay_with_unreadable_entries_is_not_healthy(tmp_path):
    r = _replay(tmp_path, f'[{GOODJ}, "CRITICAL", 5, null]')
    assert r.overall_status in (S.UNKNOWN, S.NOT_FULLY_VERIFIED)  # same as the live path: never HEALTHY
    assert r.evidence_completeness.level != "complete"
