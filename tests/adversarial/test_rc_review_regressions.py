"""Regressions from the release-candidate reviews (deterministic-diagnosis + security).

A rule must key on the SPECIFIC result it is about, not on a source/check name or a
loose substring; a stopped service must demote its own symptoms; hostile input must
not hang the tool or reach the terminal."""

from __future__ import annotations

import json
import time

from ipa_diagnose.engine.model import DiagnosisStatus, PriorityBucket
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collectors.replication_agreements import _parse_list_output
from ipa_diagnose.evidence.healthcheck import parse_healthcheck_results
from ipa_diagnose.evidence.model import EvidenceBundle, EvidenceItem
from ipa_diagnose.privacy.minimize import build_ai_payload
from ipa_diagnose.verify import VerifyOutcome, compare


def _entry(source, check, result, msg="", **kw):
    body = {"key": check}
    if msg:
        body["msg"] = msg
    body.update(kw)
    return {"source": source, "check": check, "result": result, "uuid": f"{source}.{check}.{result}", "kw": body}


def _bundle(entries, items=()):
    findings = parse_healthcheck_results(entries, command="test", live=False)
    return EvidenceBundle(hostname="h", collected_at=EvidenceBundle.now(), findings=findings, items=list(items))


def _rule(report, rule_id):
    return next((d for d in report.diagnoses if d.rule_id == rule_id), None)


def test_generic_tls_journal_line_is_not_an_nss_db_format_diagnosis():
    b = _bundle(
        [_entry("ipahealthcheck.ipa.files", "TomcatFileCheck", "WARNING", "mode 0664")],
        items=[EvidenceItem(item_id="j1", kind="dirsrv_journal_line", summary="tls", data={"category": "nss_tls", "message": "SSL alert: handshake failure from client"})],
    )
    d = _rule(run_diagnosis(b), "nss-tls-db-format")
    assert d is None or d.status != DiagnosisStatus.DIAGNOSED


def test_nss_db_format_needs_db_file_evidence_or_a_healthcheck_result():
    b = _bundle(
        [_entry("ipahealthcheck.ipa.files", "TomcatFileCheck", "WARNING", "mode 0664")],
        items=[EvidenceItem(item_id="j1", kind="dirsrv_journal_line", summary="nss", data={"category": "nss_tls", "message": "NSS error: unable to open cert8.db"})],
    )
    assert _rule(run_diagnosis(b), "nss-tls-db-format").status == DiagnosisStatus.DIAGNOSED


def test_ca_connectivity_error_alone_is_not_an_ra_agent_desync():
    b = _bundle([_entry("ipahealthcheck.ipa.certs", "DogtagCertsConnectivityCheck", "ERROR", "Request for certificate failed, connection refused")])
    d = _rule(run_diagnosis(b), "ra-agent-desync")
    assert d is None or d.status != DiagnosisStatus.DIAGNOSED


def test_other_backend_results_are_not_a_missing_index_diagnosis():
    b = _bundle([_entry("ipahealthcheck.ds.backends", "BackendsCheck", "ERROR", "backend is not initialised", key="DSBLE0003")])
    assert _rule(run_diagnosis(b), "missing-system-index") is None


def test_unsynchronised_ntp_with_unrelated_keytab_failure_is_not_clock_skew():
    b = _bundle(
        [_entry("ipahealthcheck.ipa.host", "IPAHostKeytab", "ERROR", "Server not found in Kerberos database")],
        items=[EvidenceItem(item_id="clk", kind="clock_sync", summary="ntp", data={"method": "chronyc", "ntp_synchronized": False, "offset_seconds": None})],
    )
    assert _rule(run_diagnosis(b), "clock-skew") is None


def test_stopped_kdc_is_not_also_reported_as_a_dns_srv_problem():
    b = _bundle(
        [
            _entry("ipahealthcheck.meta.services", "krb5kdc", "ERROR", "krb5kdc: not running"),
            _entry("ipahealthcheck.ipa.host", "IPAHostKeytab", "ERROR", "Cannot contact any KDC for realm 'LAB.TEST'"),
        ]
    )
    assert _rule(run_diagnosis(b), "kdc-discovery-failure") is None


def test_service_outage_demotes_its_unexplained_symptoms():
    b = _bundle(
        [
            _entry("ipahealthcheck.meta.services", "dirsrv", "ERROR", "dirsrv: not running"),
            _entry("ipahealthcheck.ipa.trust", "IPAauthzdatapacCheck", "CRITICAL", exception="ldap2 is not connected", traceback="tb"),
        ]
    )
    report = run_diagnosis(b)
    primary = report.by_priority(PriorityBucket.PRIMARY)[0]
    assert "dirsrv" in primary.title
    crashed = _rule(report, "healthcheck-check-failed")
    assert crashed.priority == PriorityBucket.RELATED_SYMPTOM
    assert any("dirsrv" in t for t in crashed.related_to_titles)


def test_verify_never_says_resolved_when_checks_now_crash():
    previous = {"generated_at": "t", "diagnoses": [{"diagnosis_id": "certificates.cert-expired", "pack_id": "certificates", "title": "cert expired"}]}
    now = run_diagnosis(
        _bundle([_entry("ipahealthcheck.ipa.certs", "IPACertTracking", "CRITICAL", exception="Failed to start certmonger", traceback="tb")])
    )
    result = compare(previous, now)
    assert [i.outcome for i in result.items] == [VerifyOutcome.UNABLE_TO_VERIFY]


def test_unclaimed_warnings_are_counted_not_hidden():
    report = run_diagnosis(_bundle([_entry("ipahealthcheck.meta.services", "dirsrv", "SUCCESS"), _entry("ipahealthcheck.zzz.future", "C", "WARNING", "odd")]))
    assert report.unclaimed_warnings == 1


def test_pathological_replica_list_output_cannot_hang_the_parser():
    hostile = " " * 200000 + "x\n" + "a: b" * 50000
    start = time.monotonic()
    _parse_list_output(hostile, command="test")
    assert time.monotonic() - start < 3


def test_ai_payload_strips_terminal_escapes_from_evidence():
    b = _bundle([_entry("ipahealthcheck.zzz.future", "Chk", "CRITICAL", "boom \x1b]0;pwn\x07\x1b[2J")])
    report = run_diagnosis(b)
    d = next(d for d in report.diagnoses if d.rule_id == "unexplained-findings")
    payload = build_ai_payload(b, d)
    assert "\x1b" not in payload.user_prompt
    assert all("\x1b" not in s.message for s in payload.selected_evidence)
