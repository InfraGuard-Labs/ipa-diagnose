"""Adversarial review: can an evidence-collection failure still yield a
misleading HEALTHY / exit 0 / "No problems detected"?

Every scenario runs the REAL live code path (collect_evidence -> run_diagnosis
-> render/JSON/CLI) with subprocess.run / shutil.which / socket.gethostname
faked, so nothing touches the host.

Legend used in the test docstrings:
  GUARD               expected to PASS today (documents a defence that holds)
  HEALTHY-NEGATIVE    expected to PASS today (a genuinely healthy system must stay HEALTHY)
  EXPECTED FAIL       expected to FAIL today: exposes a real bug (see docstring)
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import types

import pytest
from rich.console import Console

from ipa_diagnose import cli
from ipa_diagnose.cli import _exit_code_for
from ipa_diagnose.engine import correlate, unexplained
from ipa_diagnose.engine.model import (
    Confidence,
    ConfidenceLevel,
    Diagnosis,
    DiagnosisStatus,
    OverallStatus,
)
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence import collect
from ipa_diagnose.evidence.collectors import replication_agreements as ra
from ipa_diagnose.evidence.collectors.base import CollectorError
from ipa_diagnose.evidence.collectors.registry import get as get_collector
from ipa_diagnose.evidence.model import EvidenceBundle, Finding, Severity
from ipa_diagnose.render.console import render_report
from ipa_diagnose.render.json_output import report_to_dict
from ipa_diagnose.verify import VerifyOutcome, compare, save_report

HOST = "ipa01.example.test"

# ---------------------------------------------------------------------------
# fake live environment
# ---------------------------------------------------------------------------


def _entry(source, check, result, msg="", **kw):
    body = {"key": check}
    if msg:
        body["msg"] = msg
    body.update(kw)
    return {
        "source": source,
        "check": check,
        "result": result,
        "uuid": f"{source}.{check}.{result}",
        "when": "20260101000000Z",
        "duration": "0.01",
        "kw": body,
    }


GOOD_HC = json.dumps([_entry("ipahealthcheck.meta.services", "dirsrv", "SUCCESS")])
UNKNOWN_SRC = "ipahealthcheck.zzz.futurecheck"  # no pack rule claims this source

LIST_GOOD = (
    "ipa02.example.test: replica\n"
    "  last update status: Error (0) Replica acquired successfully: Incremental update succeeded\n"
    "  last update ended: 2026-01-01 12:00:00+00:00\n"
)
RUV_GOOD = "Replica Update Vectors:\nipa01.example.test:389: 4\nipa02.example.test:389: 5\n"
LDIF_DOMAIN = (
    "dn: nsuniqueid=ffffffff-ffffffff-ffffffff-ffffffff,dc=example,dc=test\n"
    "nsds50ruv: {replicageneration} 5f0000\n"
    "nsds50ruv: {replica 4 ldap://ipa01.example.test:389} 1 2\n"
    "nsds50ruv: {replica 5 ldap://ipa02.example.test:389} 1 2\n"
)
LDIF_CA_ONLY = (
    "dn: nsuniqueid=ffffffff-ffffffff-ffffffff-ffffffff,o=ipaca\n"
    "nsds50ruv: {replica 6 ldap://ipa01.example.test:389} 1 2\n"
)
BASEDN = "dc=example,dc=test"


def _cp(args, rc=0, out="", err=""):
    return subprocess.CompletedProcess(args, rc, stdout=out, stderr=err)


def _install(monkeypatch, *, healthcheck=(0, GOOD_HC, ""), list_=(0, LIST_GOOD, ""), ruv=(0, RUV_GOOD, ""),
             extra=None, missing=()):
    """Each spec is (rc, stdout, stderr), an exception instance to raise, or a callable(args)->spec."""
    extra = extra or {}

    def resolve(spec, args):
        if callable(spec):
            spec = spec(args)
        if isinstance(spec, BaseException):
            raise spec
        rc, out, err = spec
        return _cp(args, rc, out, err)

    def fake_run(args, *a, **kw):
        if args[0] == "ipa-healthcheck":
            return resolve(healthcheck, args)
        if args[:2] == ["ipa-replica-manage", "list"]:
            return resolve(list_, args)
        if args[:2] == ["ipa-replica-manage", "list-ruv"]:
            return resolve(ruv, args)
        if args[0] in extra:
            return resolve(extra[args[0]], args)
        return _cp(args, 1, "", "unexpected")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda n: None if n in missing else "/usr/bin/" + n)
    monkeypatch.setattr("socket.gethostname", lambda: HOST)


def _install_ldapi(monkeypatch):
    """Make ra._ldapi_read_ruv believe it is root with a readable /etc/ipa/default.conf."""
    fake_os = types.SimpleNamespace(name="posix", geteuid=lambda: 0, path=types.SimpleNamespace(exists=lambda p: True))
    monkeypatch.setattr(ra, "os", fake_os)
    monkeypatch.setattr(ra, "_read_ipa_conf", lambda: ("EXAMPLE.TEST", BASEDN))


def _base_of(args):
    return args[args.index("-b") + 1]


def _diagnose():
    return run_diagnosis(collect.collect_evidence())


def _render(report):
    buf = io.StringIO()
    render_report(report, Console(file=buf, width=140, force_terminal=False, highlight=False))
    return buf.getvalue()


def _assert_not_reassuring(report):
    assert report.overall_status != OverallStatus.HEALTHY, report.overall_status
    assert _exit_code_for(report) != 0
    assert report_to_dict(report)["overall_status"] != "HEALTHY"
    assert "No problems detected" not in _render(report)


# ---------------------------------------------------------------------------
# 0. baselines: a genuinely healthy system stays HEALTHY (HEALTHY-NEGATIVE)
# ---------------------------------------------------------------------------


def test_baseline_healthy_replica_is_healthy(monkeypatch):
    """HEALTHY-NEGATIVE: hc SUCCESS, list ok, list-ruv ok -> HEALTHY, RUV VERIFIED, exit 0."""
    _install(monkeypatch)
    report = _diagnose()
    assert report.overall_status == OverallStatus.HEALTHY
    assert report.evidence_completeness.ruv_state == "VERIFIED"
    assert report.evidence_completeness.level == "complete"
    assert _exit_code_for(report) == 0
    assert report_to_dict(report)["fully_verified"] is True


def test_healthcheck_rc1_with_only_success_results_is_healthy(monkeypatch):
    """HEALTHY-NEGATIVE: rc 1 with a valid all-SUCCESS array must not be treated as a failure."""
    _install(monkeypatch, healthcheck=(1, GOOD_HC, ""))
    assert _diagnose().overall_status == OverallStatus.HEALTHY


def test_healthy_single_server_none_configured_is_healthy(monkeypatch):
    """HEALTHY-NEGATIVE: single server, DM identity confirmed, no RUV -> NONE_CONFIGURED, HEALTHY."""
    _install(
        monkeypatch,
        list_=(1, "", "kinit: no ticket"),
        ruv=(1, "", "Directory Manager password required"),
        extra={"ldapsearch": (0, "", ""), "ldapwhoami": (0, "dn:cn=directory manager\n", "")},
    )
    _install_ldapi(monkeypatch)
    report = _diagnose()
    assert report.evidence_completeness.ruv_state == "NONE_CONFIGURED"
    assert report.overall_status == OverallStatus.HEALTHY
    assert _exit_code_for(report) == 0


def test_healthy_three_node_line_topology_is_not_degraded(monkeypatch):
    """HEALTHY-NEGATIVE / EXPECTED FAIL (false DEGRADED).
    This host (ipa01) only has an agreement with ipa02; ipa03 is a healthy replica reachable
    via ipa02 (line topology, normal for 3+ servers). `list -v <self>` only shows this host's
    own agreements, so RUV rid for ipa03 gets alive=False -> 'Possible stale RUV' WARNING ->
    DEGRADED (exit 1) on a healthy topology.
    Minimal fix: derive the known-server set from the topology/`cn=masters` (or
    `ipa-replica-manage list` without host) instead of only this host's agreements."""
    ruv = RUV_GOOD + "ipa03.example.test:389: 6\n"
    _install(monkeypatch, ruv=(0, ruv, ""))
    report = _diagnose()
    assert not any(d.rule_id == "stale-ruv" for d in report.diagnoses)
    assert report.overall_status == OverallStatus.HEALTHY


def test_healthy_replica_without_kerberos_ticket_makes_no_stale_ruv_claim(monkeypatch):
    """EXPECTED FAIL (false DEGRADED / spec drift). Root without a ticket: `list` fails, list-ruv
    falls back to LDAPI and returns both RUV entries. With the peer list unknown every
    non-self RID gets alive=None, and StaleRuvRule treats None as a candidate -> UNKNOWN
    'Possible stale RUV' -> DEGRADED. The collector docstring says alive=None must be treated as
    'not stale'; the rule does the opposite. A collection gap must yield NOT_FULLY_VERIFIED, not a
    stale-RUV finding.
    Minimal fix: in StaleRuvRule candidate_items, ignore alive=None unless an explicit ds.ruv
    ERROR finding names that RID."""

    def ldapsearch(args):
        return (0, LDIF_DOMAIN, "") if _base_of(args) == BASEDN else (0, "", "")

    _install(
        monkeypatch,
        list_=(1, "", "kinit: no ticket"),
        ruv=(1, "", "Directory Manager password required"),
        extra={"ldapsearch": ldapsearch},
    )
    _install_ldapi(monkeypatch)
    report = _diagnose()
    assert not any(d.rule_id == "stale-ruv" for d in report.diagnoses)
    assert report.overall_status == OverallStatus.NOT_FULLY_VERIFIED


# ---------------------------------------------------------------------------
# 1. ipa-healthcheck failure modes must never be HEALTHY (GUARD)
# ---------------------------------------------------------------------------

_HC_FAILURES = [
    pytest.param((2, "", "boom"), id="rc2"),
    pytest.param((3, GOOD_HC, ""), id="rc3-with-valid-json"),
    pytest.param((127, "", "not found"), id="rc127"),
    pytest.param((-9, "", ""), id="rc-9-killed"),
    pytest.param((255, "", ""), id="rc255"),
    pytest.param(subprocess.TimeoutExpired("ipa-healthcheck", 120), id="timeout"),
    pytest.param(PermissionError("denied"), id="permission-error"),
    pytest.param(FileNotFoundError("gone"), id="file-not-found"),
    pytest.param((0, "", ""), id="empty-stdout-rc0"),
    pytest.param((1, "", ""), id="empty-stdout-rc1"),
    pytest.param((0, "  \n", ""), id="whitespace-stdout"),
    pytest.param((1, "Traceback (most recent call last):\n  File x\nKeyError", ""), id="traceback-rc1"),
    pytest.param((0, GOOD_HC[:25], ""), id="truncated-json"),
    pytest.param((0, "WARNING: noise\n" + GOOD_HC, ""), id="noise-prefix"),
    pytest.param((0, '{"a": 1}', ""), id="json-object"),
    pytest.param((0, "null", ""), id="json-null"),
    pytest.param((0, '"ok"', ""), id="json-string"),
    pytest.param((0, "0", ""), id="json-number"),
    pytest.param((0, '{"results": "x"}', ""), id="results-not-a-list"),
]


@pytest.mark.parametrize("spec", _HC_FAILURES)
def test_healthcheck_failure_is_unknown_never_healthy(monkeypatch, spec):
    """GUARD"""
    _install(monkeypatch, healthcheck=spec)
    report = _diagnose()
    _assert_not_reassuring(report)
    assert report.overall_status == OverallStatus.UNKNOWN
    assert report.evidence_completeness.level == "insufficient"
    assert _exit_code_for(report) == 3


def test_healthcheck_missing_is_unknown_never_healthy(monkeypatch):
    """GUARD"""
    _install(monkeypatch, missing=("ipa-healthcheck",))
    report = _diagnose()
    _assert_not_reassuring(report)
    assert report.overall_status == OverallStatus.UNKNOWN


def test_every_subprocess_fails_is_never_healthy(monkeypatch):
    """GUARD: all collectors fail at once."""
    _install(monkeypatch, healthcheck=OSError("x"), list_=OSError("x"), ruv=OSError("x"))
    _assert_not_reassuring(_diagnose())


@pytest.mark.parametrize(
    "hc,missing",
    [
        pytest.param((0, "", ""), (), id="empty"),
        pytest.param((2, "", "x"), (), id="rc2"),
        pytest.param(subprocess.TimeoutExpired("x", 1), (), id="timeout"),
        pytest.param((0, GOOD_HC, ""), ("ipa-healthcheck",), id="missing"),
    ],
)
def test_json_consumers_never_see_fully_verified_or_exit0(monkeypatch, tmp_path, capsys, hc, missing):
    """GUARD: `--json` contract (fully_verified / overall_status / exit code) on healthcheck failure."""
    _install(monkeypatch, healthcheck=hc, missing=missing)
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    code = cli.main(["--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 3
    assert data["overall_status"] == "UNKNOWN"
    assert data["fully_verified"] is False
    assert data["evidence_completeness"]["healthcheck_collected"] is False


# ---------------------------------------------------------------------------
# 2. ipa-healthcheck "ran but proved nothing"
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stdout",
    [
        pytest.param("[]", id="empty-array"),
        pytest.param('{"results": []}', id="empty-results"),
        pytest.param("[1, 2, 3]", id="array-of-numbers"),
        pytest.param('["x"]', id="array-of-strings"),
        pytest.param("[null]", id="array-of-null"),
        pytest.param("[[]]", id="array-of-arrays"),
    ],
)
@pytest.mark.parametrize("rc", [0, 1])
def test_healthcheck_with_no_usable_results_is_not_healthy(monkeypatch, stdout, rc):
    """EXPECTED FAIL (P1). ipa-healthcheck's default output always contains SUCCESS results, so
    an empty array (zero checks ran) or an array whose entries are all non-dicts carries no
    health evidence. parse_healthcheck_results() silently drops non-dict entries and an empty
    list yields no findings and no CollectionError -> overall HEALTHY, exit 0, 'No problems
    detected' (evidence/collect.py:96-107 + evidence/healthcheck.py:75-77).
    Minimal fix: in _collect_healthcheck, if no dict entry was parsed (or any entry was
    skipped as non-dict) append CollectionError('ipa-healthcheck', 'returned no usable results').
    NOTE: tests/unit/test_evidence_completeness.py::test_partial_replication_failure_end_to_end_via_collect
    stubs healthcheck as '[]' and would then see UNKNOWN instead of NOT_FULLY_VERIFIED; give it
    a SUCCESS entry."""
    _install(monkeypatch, healthcheck=(rc, stdout, ""))
    _assert_not_reassuring(_diagnose())


@pytest.mark.parametrize(
    "entries",
    [
        pytest.param([{}], id="empty-object"),
        pytest.param([{"source": "a", "check": "b"}], id="missing-result"),
        pytest.param([{"source": UNKNOWN_SRC, "check": "C", "result": None}], id="null-result"),
        pytest.param([{"source": UNKNOWN_SRC, "check": "C", "result": 5}], id="numeric-result"),
        pytest.param([{"source": UNKNOWN_SRC, "check": "C", "result": " ERROR "}], id="padded-result"),
    ],
)
def test_entries_with_missing_or_odd_fields_are_never_healthy(monkeypatch, entries):
    """GUARD: unusable severity becomes Severity.UNKNOWN (ERROR-equivalent), never SUCCESS."""
    _install(monkeypatch, healthcheck=(1, json.dumps(entries), ""))
    _assert_not_reassuring(_diagnose())


def test_unknown_severity_fatal_surfaces_as_unknown_with_note(monkeypatch):
    """GUARD"""
    hc = json.dumps([_entry(UNKNOWN_SRC, "C", "FATAL", "disk on fire")])
    _install(monkeypatch, healthcheck=(1, hc, ""))
    report = _diagnose()
    assert report.overall_status == OverallStatus.UNKNOWN
    assert _exit_code_for(report) == 3
    assert report.unknown_severity_findings
    assert "FATAL" in "".join(report.unknown_severity_findings)


@pytest.mark.parametrize("severity", ["ERROR", "CRITICAL", "error"])
def test_unclaimed_error_or_critical_from_unknown_check_is_never_healthy(monkeypatch, severity):
    """GUARD: unknown future check at ERROR/CRITICAL must not vanish."""
    hc = json.dumps([_entry(UNKNOWN_SRC, "C", severity, "bad")])
    _install(monkeypatch, healthcheck=(1, hc, ""))
    report = _diagnose()
    _assert_not_reassuring(report)
    assert _exit_code_for(report) in (2, 3)


def test_critical_without_msg_key_is_never_healthy(monkeypatch):
    """GUARD: real CRITICAL results may carry only kw.exception/traceback."""
    e = _entry(UNKNOWN_SRC, "C", "CRITICAL")
    e["kw"] = {"traceback": "Traceback...\nAttributeError: ldap2 is not connected"}
    _install(monkeypatch, healthcheck=(1, json.dumps([e]), ""))
    _assert_not_reassuring(_diagnose())


def test_stopped_service_is_never_healthy(monkeypatch):
    """GUARD: 'dirsrv: not running' via the live path."""
    e = _entry("ipahealthcheck.meta.services", "dirsrv", "ERROR", "dirsrv: not running", status=False)
    _install(monkeypatch, healthcheck=(1, json.dumps([e]), ""))
    report = _diagnose()
    _assert_not_reassuring(report)
    assert report.diagnoses


def test_unknown_source_warning_is_not_reported_as_all_clear(monkeypatch):
    """EXPECTED FAIL (P3, design gap, not a collection failure). A WARNING from a check no rule
    knows is dropped entirely: overall HEALTHY + 'No problems detected. All evaluated checks
    passed.' although ipa-healthcheck itself reported a WARNING (engine/unexplained.py:144
    only looks at >= ERROR).
    Minimal fix: surface unclaimed WARNINGs as WARNING-bucket diagnoses, or at least list them and
    do not print 'All evaluated checks passed'."""
    hc = json.dumps([_entry(UNKNOWN_SRC, "C", "WARNING", "something is off")])
    _install(monkeypatch, healthcheck=(1, hc, ""))
    _assert_not_reassuring(_diagnose())


# ---------------------------------------------------------------------------
# 3. exceptions escaping collect_evidence
# ---------------------------------------------------------------------------


class _Boom:
    name = "boom"

    def collect_live(self):
        raise RuntimeError("kaboom")

    def collect_replay(self, d):
        raise RuntimeError("kaboom")


def test_unexpected_collector_exception_becomes_a_collection_error(monkeypatch):
    """EXPECTED FAIL (P2). _collect_staged only catches CollectorError (evidence/collect.py:152), so
    any other exception (RuntimeError, KeyError, ValueError, UnicodeDecodeError ...) aborts the
    whole run with a traceback and exit code 1, which is indistinguishable from DEGRADED and
    loses every other collector's evidence.
    Minimal fix: `except Exception as e:` (after CollectorError) -> CollectionError(name, repr(e))."""
    _install(monkeypatch)
    monkeypatch.setattr(collect, "get_collector", lambda name: _Boom())
    report = _diagnose()  # must not raise
    assert report.evidence_completeness.level == "partial"
    assert report.overall_status == OverallStatus.NOT_FULLY_VERIFIED


def test_undecodable_healthcheck_output_is_a_collection_error(monkeypatch):
    """EXPECTED FAIL (P2). subprocess.run(text=True) raises UnicodeDecodeError (a ValueError, not
    OSError/SubprocessError) on non-UTF-8 output; it escapes collect.py:83 and crashes the run
    (exit 1). Same pattern in every collector's `except (OSError, SubprocessError)`.
    Minimal fix: pass errors='replace' to subprocess.run everywhere, and/or catch ValueError."""
    _install(monkeypatch, healthcheck=UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"))
    report = _diagnose()  # must not raise
    _assert_not_reassuring(report)


def test_undecodable_list_ruv_output_is_a_collection_error(monkeypatch):
    """EXPECTED FAIL (P2): same UnicodeDecodeError escape in replication_agreements._try_run_list_ruv."""
    _install(monkeypatch, ruv=UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"))
    report = _diagnose()  # must not raise
    _assert_not_reassuring(report)


def test_crash_exit_code_is_not_zero_or_degraded_lookalike(monkeypatch, tmp_path, capsys):
    """GUARD (weak): a crash must at least never be exit 0."""
    _install(monkeypatch)
    monkeypatch.setattr(collect, "get_collector", lambda name: _Boom())
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    try:
        code = cli.main(["--json"])
    except Exception:
        return  # traceback => interpreter exit code 1, never 0
    assert code != 0


# ---------------------------------------------------------------------------
# 4. timeouts in every collector
# ---------------------------------------------------------------------------


def _timeout(*a, **k):
    raise subprocess.TimeoutExpired(cmd="x", timeout=1)


@pytest.mark.parametrize(
    "name", ["certmonger", "journal_dirsrv", "journal_krb5kdc", "journal_named", "journal_pki", "ldap_query"]
)
def test_collector_timeout_raises_collector_error(monkeypatch, name):
    """GUARD: TimeoutExpired (a SubprocessError) is turned into CollectorError."""
    monkeypatch.setattr(subprocess, "run", _timeout)
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr("socket.gethostname", lambda: HOST)
    collector = get_collector(name)
    assert collector is not None
    with pytest.raises(CollectorError):
        collector.collect_live()


def test_dns_lookup_timeout_is_error_evidence_not_success(monkeypatch):
    """GUARD"""
    monkeypatch.setattr(subprocess, "run", _timeout)
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/" + n)
    items = get_collector("dns_lookup").collect_live()
    assert items
    assert all(i.severity == Severity.ERROR for i in items)


def test_kerberos_client_total_subcheck_failure_is_not_silent(monkeypatch):
    """EXPECTED FAIL (P3). When klist and the clock check all time out, kerberos_client returns []
    with no CollectorError (collectors/kerberos_client.py:121,146,205,226 swallow errors), so the
    gap is invisible in evidence_completeness. The safety net still shows ERROR findings, so this
    cannot yield HEALTHY on its own, but 'complete' is overstated.
    Minimal fix: raise CollectorError when every sub-check produced nothing because of an error."""
    monkeypatch.setattr(subprocess, "run", _timeout)
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/" + n)
    with pytest.raises(CollectorError):
        get_collector("kerberos_client").collect_live()


# ---------------------------------------------------------------------------
# 5. RUV collection attacks
# ---------------------------------------------------------------------------


def _ldapi_unavailable(monkeypatch):
    monkeypatch.setattr(ra, "_ldapi_read_ruv", lambda *a, **k: ([], "fake: LDAPI unavailable"))


@pytest.mark.parametrize(
    "ruv",
    [
        pytest.param((1, "", "Directory Manager password required"), id="dm-password"),
        pytest.param((1, "", "permission denied"), id="permission"),
        pytest.param(subprocess.TimeoutExpired("x", 30), id="timeout"),
        pytest.param(FileNotFoundError("ipa-replica-manage"), id="oserror"),
    ],
)
def test_ruv_unavailable_is_not_fully_verified(monkeypatch, ruv):
    """GUARD"""
    _install(monkeypatch, ruv=ruv)
    _ldapi_unavailable(monkeypatch)
    report = _diagnose()
    _assert_not_reassuring(report)
    assert report.overall_status == OverallStatus.NOT_FULLY_VERIFIED
    assert report.evidence_completeness.ruv_state == "NOT_VERIFIED"
    assert _exit_code_for(report) == 4
    assert report_to_dict(report)["fully_verified"] is False


def test_ipa_replica_manage_missing_is_not_fully_verified(monkeypatch):
    """GUARD"""
    _install(monkeypatch, missing=("ipa-replica-manage",))
    report = _diagnose()
    _assert_not_reassuring(report)
    assert report.overall_status == OverallStatus.NOT_FULLY_VERIFIED


@pytest.mark.parametrize("out", ["", "\n", "no RUV here\n", "Replica Update Vectors:\n"])
def test_list_ruv_rc0_with_no_parsable_entries_is_not_healthy(monkeypatch, out):
    """EXPECTED FAIL (P1). `list-ruv` exits 0 but nothing parses (empty, changed wording,
    localized text). No error is raised and no topology item exists, so ruv_state ends up
    'NOT_COLLECTED' with level 'complete' -> HEALTHY. In LIVE mode the collector is unconditional,
    so NOT_COLLECTED must never be reported as verified
    (evidence/collectors/replication_agreements.py:183-189, engine/correlate.py:190-191).
    Minimal fix: in _try_run_list_ruv, if rc==0 and no items parsed, treat as failure and go to the
    LDAPI fallback (which yields NONE_CONFIGURED only when authoritative)."""
    _install(monkeypatch, ruv=(0, out, ""))
    _ldapi_unavailable(monkeypatch)
    report = _diagnose()
    _assert_not_reassuring(report)


def test_empty_ldapi_result_without_dm_identity_is_not_none_configured(monkeypatch):
    """GUARD: empty search result from a non-DM identity is an ACL artefact, not 'no replication'."""
    _install(
        monkeypatch,
        list_=(1, "", "x"),
        ruv=(1, "", "DM password"),
        extra={"ldapsearch": (0, "", ""), "ldapwhoami": (0, "dn:uid=admin,cn=users,cn=accounts\n", "")},
    )
    _install_ldapi(monkeypatch)
    report = _diagnose()
    assert report.evidence_completeness.ruv_state == "NOT_VERIFIED"
    _assert_not_reassuring(report)


def test_ldapi_timeout_is_not_verified(monkeypatch):
    """GUARD"""
    _install(
        monkeypatch,
        list_=(1, "", "x"),
        ruv=(1, "", "DM password"),
        extra={"ldapsearch": subprocess.TimeoutExpired("ldapsearch", 30)},
    )
    _install_ldapi(monkeypatch)
    report = _diagnose()
    assert report.evidence_completeness.ruv_state == "NOT_VERIFIED"
    assert report.overall_status == OverallStatus.NOT_FULLY_VERIFIED


def test_unparsable_ruv_ldif_must_not_become_none_configured(monkeypatch):
    """EXPECTED FAIL (P2). The LDAPI search returns an nsds50ruv entry whose value shape the parser
    does not understand (here ldaps://). No item is parsed, DM identity is confirmed, so
    _ldapi_read_ruv returns ([], None) => 'replication not configured' => HEALTHY, although an
    RUV entry demonstrably exists (replication_agreements.py:599-601).
    Minimal fix: if stdout contains any 'nsds50ruv:' line but zero items were parsed, record an
    error instead of treating the result as authoritative emptiness."""
    weird = "dn: cn=replica,cn=x\nnsds50ruv: {replica 4 ldaps://ipa01.example.test:636} 1 2\n"
    _install(
        monkeypatch,
        list_=(1, "", "x"),
        ruv=(1, "", "DM password"),
        extra={"ldapsearch": (0, weird, ""), "ldapwhoami": (0, "dn:cn=directory manager\n", "")},
    )
    _install_ldapi(monkeypatch)
    report = _diagnose()
    assert report.evidence_completeness.ruv_state != "NONE_CONFIGURED"
    _assert_not_reassuring(report)


def test_domain_suffix_read_failure_is_not_masked_by_ca_suffix_success(monkeypatch):
    """EXPECTED FAIL (P3). Required domain search fails but the optional o=ipaca search returns an
    RUV: _ldapi_read_ruv returns (items, 'error') and _ldapi_fallback drops the error whenever
    items is non-empty (replication_agreements.py:204-205) => ruv_state VERIFIED with the domain
    RUV never read.
    Minimal fix: keep fallback_error when it is not None even if items were returned (raise with
    partial_items)."""

    def ldapsearch(args):
        return (1, "", "Insufficient access") if _base_of(args) == BASEDN else (0, LDIF_CA_ONLY, "")

    _install(monkeypatch, extra={"ldapsearch": ldapsearch})
    _install_ldapi(monkeypatch)
    items, err = ra.ReplicationAgreementsCollector()._ldapi_fallback({HOST}, True, "list-ruv failed")
    assert err is not None, "the failed domain-suffix read must remain a visible gap"


# ---------------------------------------------------------------------------
# 6. verify / ai-preview
# ---------------------------------------------------------------------------


def _problem_bundle():
    b = EvidenceBundle(hostname=HOST, collected_at=EvidenceBundle.now())
    b.findings.append(
        Finding(finding_id="f1", source=UNKNOWN_SRC, check="ZCheck", severity=Severity.ERROR, message="boom")
    )
    return b


def _console():
    return Console(file=io.StringIO(), width=140, highlight=False)


def test_verify_still_present_is_not_exit_zero(monkeypatch, tmp_path):
    """EXPECTED FAIL (P2, design). cmd_verify returns 0 whenever evidence is complete, even when
    every previous problem is STILL_PRESENT (cli.py:138-142). `ipa-diagnose verify && echo fixed`
    then reports success while the problem persists.
    Minimal fix: return 1 (or the current report's exit code) when any item is STILL_PRESENT /
    PARTIALLY_RESOLVED or new_conditions is non-empty."""
    b = _problem_bundle()
    state = tmp_path / "state.json"
    save_report(state, run_diagnosis(b))
    monkeypatch.setattr(cli, "_collect_and_diagnose", lambda args: (b, run_diagnosis(b)))
    monkeypatch.setattr(cli, "default_state_path", lambda: state)
    args = cli.build_parser().parse_args(["verify"])
    code = cli.cmd_verify(args, _console())
    assert code != 0


def test_verify_without_previous_state_does_not_bless_a_critical_system(monkeypatch, tmp_path):
    """EXPECTED FAIL (P2, design). With no saved state, compare() returns no items and cmd_verify
    returns 0 even though the fresh run is UNKNOWN/CRITICAL."""
    b = _problem_bundle()
    monkeypatch.setattr(cli, "_collect_and_diagnose", lambda args: (b, run_diagnosis(b)))
    monkeypatch.setattr(cli, "default_state_path", lambda: tmp_path / "missing.json")
    args = cli.build_parser().parse_args(["verify"])
    assert cli.cmd_verify(args, _console()) != 0


def test_verify_incomplete_evidence_is_exit_4(monkeypatch, tmp_path):
    """GUARD"""
    _install(monkeypatch, healthcheck=(2, "", "boom"))
    monkeypatch.setattr(cli, "default_state_path", lambda: tmp_path / "s.json")
    args = cli.build_parser().parse_args(["verify"])
    assert cli.cmd_verify(args, _console()) == 4


def test_verify_never_says_resolved_when_healthcheck_returned_nothing(monkeypatch):
    """EXPECTED FAIL (P1, consequence of the `[]` bug): healthcheck exits 0 with `[]`, so the
    previous problem 'disappears' and verify reports RESOLVED."""
    _install(monkeypatch, healthcheck=(0, "[]", ""))
    current = _diagnose()
    previous = {
        "generated_at": "2026-01-01T00:00:00Z",
        "diagnoses": [{"diagnosis_id": "healthcheck.unexplained-findings", "pack_id": "healthcheck", "title": "x"}],
    }
    result = compare(previous, current)
    assert [i.outcome for i in result.items] == [VerifyOutcome.UNABLE_TO_VERIFY]


def test_ai_preview_is_not_a_green_all_clear_when_only_warnings_exist(monkeypatch):
    """EXPECTED FAIL (P3). A WARNING-only report is DEGRADED (exit 1 for `diagnose`), but with no
    PRIMARY/SECONDARY diagnosis ai-preview prints the green 'No primary or independent problems'
    and returns 0 (cli.py:156-157).
    Minimal fix: return _exit_code_for(report) and do not print the green line unless
    overall_status is HEALTHY."""
    d = Diagnosis(
        pack_id="replication",
        rule_id="benign",
        status=DiagnosisStatus.DIAGNOSED,
        title="benign heads-up",
        why="w",
        confidence=Confidence(level=ConfidenceLevel.HIGH, rationale="r"),
        severity=Severity.WARNING,
    )
    b = EvidenceBundle(hostname=HOST, collected_at=EvidenceBundle.now())
    report = correlate.build_report(b, [d], ["replication"])
    assert report.overall_status == OverallStatus.DEGRADED
    monkeypatch.setattr(cli, "_collect_and_diagnose", lambda args: (b, report))
    buf = io.StringIO()
    args = cli.build_parser().parse_args(["ai-preview"])
    code = cli.cmd_ai_preview(args, Console(file=buf, width=140, highlight=False))
    assert code == _exit_code_for(report)
    assert "No primary or independent problems" not in buf.getvalue()


# ---------------------------------------------------------------------------
# 7. --json output hygiene, replay semantics
# ---------------------------------------------------------------------------


def test_json_output_is_pure_json_when_not_root(monkeypatch, tmp_path, capsys):
    """EXPECTED FAIL (P3). cli.main prints the 'not running as root' warning to STDOUT (rich
    Console default) before the JSON document (cli.py:187-191), so `ipa-diagnose --json | jq`
    breaks for non-root users.
    Minimal fix: Console(stderr=True) for that warning, or skip it when --json."""
    _install(monkeypatch)
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    if os.name == "nt":
        pytest.skip("root warning is POSIX-only")
    cli.main(["--json"])
    json.loads(capsys.readouterr().out)


def test_replay_of_nonexistent_directory_is_not_healthy(tmp_path):
    """EXPECTED FAIL (P4, replay-only). A typo'd --replay path yields no errors at all
    (missing healthcheck.json is tolerated by design) => HEALTHY exit 0. The tolerated-missing
    file is a known limitation, but a missing DIRECTORY is a plain user error.
    Minimal fix: in collect_evidence, if replay_dir is given and not a directory, raise/record an
    ipa-healthcheck CollectionError."""
    report = run_diagnosis(collect.collect_evidence(replay_dir=str(tmp_path / "does-not-exist")))
    assert report.overall_status != OverallStatus.HEALTHY
