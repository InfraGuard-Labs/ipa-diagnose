"""Round-2 adversarial review (independent of round 1): can an evidence-collection
failure still yield a misleading HEALTHY / exit 0 / "No problems detected", and does a
genuinely healthy system stay HEALTHY?

Every scenario runs the REAL live path (collect_evidence -> run_diagnosis -> render/CLI)
with subprocess.run / shutil.which / socket.gethostname faked; nothing touches the host.
This file was written WITHOUT being able to execute it, so each expectation below is
derived from reading the code at the 0.1.2 release-candidate HEAD.

Legend:
  GUARD               expected to PASS today (a defence that holds; keep it holding)
  HEALTHY-NEGATIVE    expected to PASS today (a healthy system must stay HEALTHY)
  EXPECTED FAIL (Pn)  expected to FAIL today; Pn = priority (P1 worst). "false-DEGRADED" /
                      "false-NFV" = a healthy system is reported as a problem / unverified.
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
    EvidenceRef,
    OverallStatus,
)
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence import collect
from ipa_diagnose.evidence.collectors import replication_agreements as ra
from ipa_diagnose.evidence.collectors.base import CollectorError
from ipa_diagnose.evidence.collectors.registry import get as get_collector
from ipa_diagnose.evidence.model import EvidenceBundle, Finding, Severity
from ipa_diagnose.render.console import render_report, render_verify
from ipa_diagnose.render.json_output import report_to_dict
from ipa_diagnose.textsafe import sanitize_text
from ipa_diagnose.verify import compare, save_report

HOST = "ipa01.example.test"
BASEDN = "dc=example,dc=test"
MASTERS_BASE = f"cn=masters,cn=ipa,cn=etc,{BASEDN}"

# ---------------------------------------------------------------------------
# helpers (copied from test_false_reassurance.py, plus a few new ones)
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


GOOD_HC = json.dumps([_entry("ipahealthcheck.meta.services", "dirsrv", "SUCCESS"), _entry("ipahealthcheck.ds.replication", "ReplicationCheck", "SUCCESS"), _entry("ipahealthcheck.ipa.certs", "IPACertmongerExpirationCheck", "SUCCESS")])
UNKNOWN_SRC = "ipahealthcheck.zzz.futurecheck"  # no pack rule claims this source
DISK_SRC = "ipahealthcheck.ds.disk_space"  # claimed by DiskSpaceExhaustionRule

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
LDIF_DOMAIN_3 = LDIF_DOMAIN + "nsds50ruv: {replica 6 ldap://ipa03.example.test:389} 1 2\n"
TWO = ("ipa01.example.test", "ipa02.example.test")
THREE = TWO + ("ipa03.example.test",)


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
    fake_os = types.SimpleNamespace(name="posix", geteuid=lambda: 0, path=types.SimpleNamespace(exists=lambda p: True))
    monkeypatch.setattr(ra, "os", fake_os)
    monkeypatch.setattr(ra, "_read_ipa_conf", lambda: ("EXAMPLE.TEST", BASEDN))


def _ldapi_unavailable(monkeypatch):
    monkeypatch.setattr(ra, "_ldapi_read_ruv", lambda *a, **k: ([], "fake: LDAPI unavailable"))


def _base_of(args):
    return args[args.index("-b") + 1]


def _masters_ldif(hosts):
    return "".join(f"dn: cn={h},cn=masters,cn=ipa,cn=etc,{BASEDN}\n\n" for h in hosts)


def _ldapi_topology(monkeypatch, *, hosts, domain_ldif, ca=(0, "", ""), list_=(0, LIST_GOOD, ""), healthcheck=None):
    """Root on a replica: `list-ruv` refuses (DM password) so the LDAPI fallback is used, exactly
    as observed live. cn=masters is readable over LDAPI (authoritative server list)."""

    def ldapsearch(args):
        base = _base_of(args)
        if base == MASTERS_BASE:
            return (0, _masters_ldif(hosts), "")
        if base == BASEDN:
            return (0, domain_ldif, "")
        return ca  # o=ipaca

    kwargs = {}
    if healthcheck is not None:
        kwargs["healthcheck"] = healthcheck
    _install(
        monkeypatch,
        list_=list_,
        ruv=(1, "", "Directory Manager password required"),
        extra={"ldapsearch": ldapsearch},
        **kwargs,
    )
    _install_ldapi(monkeypatch)


def _diagnose():
    return run_diagnosis(collect.collect_evidence())


def _console():
    return Console(file=io.StringIO(), width=140, highlight=False)


def _render(report, details=False):
    buf = io.StringIO()
    render_report(report, Console(file=buf, width=140, force_terminal=False, highlight=False), details=details)
    return buf.getvalue()


def _assert_not_reassuring(report):
    assert report.overall_status != OverallStatus.HEALTHY, report.overall_status
    assert _exit_code_for(report) != 0
    assert report_to_dict(report)["overall_status"] != "HEALTHY"
    assert "No problems detected" not in _render(report)


def _problem_bundle():
    b = EvidenceBundle(hostname=HOST, collected_at=EvidenceBundle.now())
    b.findings.append(
        Finding(finding_id="f1", source=UNKNOWN_SRC, check="ZCheck", severity=Severity.ERROR, message="boom")
    )
    return b


def _benign_warning_report():
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
    return b, correlate.build_report(b, [d], ["replication"])


# ---------------------------------------------------------------------------
# A. healthy systems must stay HEALTHY
# ---------------------------------------------------------------------------


def test_healthy_three_node_line_via_ldapi_cn_masters_is_healthy(monkeypatch):
    """HEALTHY-NEGATIVE. Root on a replica of a 3-node line topology; list-ruv refuses, so RUV
    comes from LDAPI and the authoritative server list from cn=masters. ipa03 (reachable only
    through ipa02) must not become a stale-RUV candidate."""
    _ldapi_topology(monkeypatch, hosts=THREE, domain_ldif=LDIF_DOMAIN_3)
    report = _diagnose()
    assert not any(d.rule_id == "stale-ruv" for d in report.diagnoses)
    assert report.evidence_completeness.ruv_state == "VERIFIED"
    assert report.overall_status == OverallStatus.HEALTHY
    assert _exit_code_for(report) == 0


def test_healthy_ca_less_replica_stays_healthy(monkeypatch):
    """HEALTHY-NEGATIVE. o=ipaca does not exist (CA-less replica): LDAP rc 32 'No such object' on
    the optional CA suffix must remain a non-event (guards the fix for the CA-suffix test below)."""
    _ldapi_topology(monkeypatch, hosts=TWO, domain_ldif=LDIF_DOMAIN, ca=(32, "", "No such object (32)"))
    report = _diagnose()
    assert report.overall_status == OverallStatus.HEALTHY


def test_root_without_ticket_on_healthy_replica_with_authoritative_topology_is_healthy(monkeypatch):
    """EXPECTED FAIL (P2, false-NFV / design call). Root, no Kerberos ticket, healthy replica.
    cn=masters (LDAPI) gives the authoritative server list and LDAPI gives every RUV entry, so the
    ONLY gap is `ipa-replica-manage list` needing a ticket (agreement statuses, which ipa-healthcheck
    already covers). collect_live still raises CollectorError(list_error)
    (replication_agreements.py:145-151) => NOT_FULLY_VERIFIED / exit 4 on the most common way
    `sudo ipa-diagnose` is run on a healthy replica.
    NOTE: tests/adversarial/test_false_reassurance.py::
    test_healthy_replica_without_kerberos_ticket_makes_no_stale_ruv_claim blesses NFV, but there
    the topology is NOT known (cn=masters returns nothing); here it is.
    Minimal fix: when hosts_complete comes from an authoritative masters read and RUV entries were
    verified, downgrade the `list` failure to a non-blocking note (as is already done for the
    single-server case, lines 130-131)."""
    _ldapi_topology(monkeypatch, hosts=TWO, domain_ldif=LDIF_DOMAIN, list_=(1, "", "kinit: no ticket"))
    report = _diagnose()
    assert report.evidence_completeness.ruv_state == "VERIFIED"
    assert report.overall_status == OverallStatus.HEALTHY


def _dig(args):
    """dig fake for a healthy IPv4-only IPA server: SRV/A answer, AAAA is NOERROR with no answer."""
    qtype, qname = args[3], args[4]
    header = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"
    if qtype == "AAAA":
        return (0, header + ";; SERVER: 10.0.0.53#53(10.0.0.53)\n", "")
    answer = {"SRV": "0 100 88 ipa01.example.test.", "A": "10.0.0.5"}[qtype]
    return (0, header + ";; ANSWER SECTION:\n" + f"{qname}. 3600 IN {qtype} {answer}\n\n;; SERVER: 10.0.0.53#53(10.0.0.53)\n", "")


def test_idns_warning_on_ipv4_only_healthy_server_is_not_a_dns_diagnosis(monkeypatch):
    """EXPECTED FAIL (P1, false-DEGRADED). ipa-healthcheck issue #270: IPADNSSystemRecordsCheck WARNs
    on healthy systems (AAAA/ipa-ca). dns.py:504-515 promises 'do not diagnose from the WARNING
    alone' unless the live dig lookups independently show a broken record. But dns_lookup queries
    AAAA for ipa-ca and the FQDN (dns_lookup.py:_QUERY_PLAN) and marks any query with zero answers
    Severity.ERROR (dns_lookup.py:179); _looks_broken() (dns.py:482-491) treats that as broken. An
    IPv4-only healthy server therefore gets a DIAGNOSED ERROR 'DNS records ... are broken' =>
    overall DEGRADED, exit 1 (worse: it asserts a false root cause).
    Minimal fix: a NOERROR/NODATA AAAA lookup must not be ERROR (only SRV and A are required), or
    exclude AAAA queries from `_looks_broken` when the healthcheck warning is the only trigger."""
    hc = json.dumps(
        [
            _entry("ipahealthcheck.meta.services", "dirsrv", "SUCCESS"), _entry("ipahealthcheck.ds.replication", "ReplicationCheck", "SUCCESS"), _entry("ipahealthcheck.ipa.certs", "IPACertmongerExpirationCheck", "SUCCESS"),
            _entry("ipahealthcheck.ipa.idns", "IPADNSSystemRecordsCheck", "WARNING", "Expected SRV/AAAA record missing"),
        ]
    )
    _install(monkeypatch, healthcheck=(1, hc, ""), extra={"dig": _dig, "journalctl": (0, "", "")})
    monkeypatch.setattr("socket.getfqdn", lambda *a: HOST)
    report = _diagnose()
    assert not any(d.rule_id == "srv-autodiscovery" for d in report.diagnoses), [d.title for d in report.diagnoses]
    assert report.overall_status == OverallStatus.NOT_FULLY_VERIFIED  # the WARNING stays undiagnosed, never HEALTHY


# ---------------------------------------------------------------------------
# B. evidence-collection failures that can still look healthy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ca",
    [
        pytest.param(subprocess.TimeoutExpired("ldapsearch", 30), id="timeout"),
        pytest.param((1, "", "ldap_result: Insufficient access (50)"), id="insufficient-access"),
    ],
)
def test_ca_suffix_ruv_read_failure_is_not_silently_healthy(monkeypatch, ca):
    """EXPECTED FAIL (P2). The LDAPI fallback is the NORMAL path for root (list-ruv wants the DM
    password). Only the domain suffix is `required`; a timeout / access error on o=ipaca is
    swallowed (replication_agreements.py:655-665 `if required: ...; continue`), so the CA RUV
    (where stale replica IDs are common after removing a CA replica) is never checked, yet the run
    is 'complete' => HEALTHY exit 0.
    Minimal fix: for the optional CA base, ignore only LDAP rc 32 (no such object); any other
    failure appends an error (or a NOT_VERIFIED note for the CA suffix)."""
    _ldapi_topology(monkeypatch, hosts=TWO, domain_ldif=LDIF_DOMAIN, ca=ca)
    _assert_not_reassuring(_diagnose())


def test_agreements_present_contradict_single_server_none_configured(monkeypatch):
    """EXPECTED FAIL (P2). `list -v` shows a live peer (ipa02) but list-ruv refuses and the LDAPI
    tombstone search returns nothing while the identity is Directory Manager: the collector
    concludes 'replication is not configured (single server)' (_ldapi_fallback) although its own
    agreement list proves replication IS configured. Contradictory evidence => complete/HEALTHY.
    Minimal fix: never emit the no_replication_configured item (or fall back to NOT_VERIFIED)
    when any replication_agreement item was collected."""
    _install(
        monkeypatch,
        list_=(0, LIST_GOOD, ""),
        ruv=(1, "", "Directory Manager password required"),
        extra={"ldapsearch": (0, "", ""), "ldapwhoami": (0, "dn:cn=directory manager\n", "")},
    )
    _install_ldapi(monkeypatch)
    report = _diagnose()
    assert report.evidence_completeness.ruv_state != "NONE_CONFIGURED" or report.overall_status != OverallStatus.HEALTHY


def test_list_ruv_partially_unparseable_is_not_verified(monkeypatch):
    """EXPECTED FAIL (P3, design). list-ruv exits 0 and two lines parse, but a third RUV-looking
    line (format drift / different tool version) does not match _RUV_LINE_RE and is silently
    skipped (replication_agreements.py:455-457). The skipped entry could be the stale one; the run
    is VERIFIED / HEALTHY.
    Minimal fix: count non-blank, non-header lines that fail every pattern and, if any, record a
    CollectorError('list-ruv output partially unparseable') (keep partial_items)."""
    ruv = RUV_GOOD + "retired.example.test:389 => 7 (no longer in topology)\n"
    _install(monkeypatch, ruv=(0, ruv, ""))
    report = _diagnose()
    assert report.overall_status != OverallStatus.HEALTHY


def test_healthcheck_that_ran_none_of_the_core_checks_is_not_healthy(monkeypatch):
    """EXPECTED FAIL (P2, design). ipa-healthcheck returns a well-formed array, but its only
    result is one SUCCESS from an unrelated source (subset of expected checks: no meta.services,
    no ds.*, no ipa.*). collect.py:118-135 only demands `usable` entries, so this is 'complete'
    and HEALTHY although nothing about IPA/389-ds/KDC/certs was verified (e.g. a plugin-load
    failure or an unconfigured host that still emits a meta result).
    Minimal fix: require at least one result from ipahealthcheck.meta.services (present in every
    real run and in GOOD_HC); otherwise CollectionError -> UNKNOWN."""
    hc = json.dumps([_entry("ipahealthcheck.meta.core", "MetaCheck", "SUCCESS")])
    _install(monkeypatch, healthcheck=(0, hc, ""))
    _assert_not_reassuring(_diagnose())


def test_healthcheck_json_nesting_bomb_is_a_collection_error(monkeypatch):
    """EXPECTED FAIL (P3, crash = exit 1 = DEGRADED lookalike). json.loads raises RecursionError
    (not ValueError) on deeply nested output; collect.py:108-114 only catches
    (ValueError, JSONDecodeError), so the whole run aborts with a traceback.
    Minimal fix: also catch RecursionError (or Exception) around parse_healthcheck_json_text /
    the replay json.loads."""
    bomb = "[" * 20000 + "]" * 20000
    _install(monkeypatch, healthcheck=(0, bomb, ""))
    report = _diagnose()  # must not raise
    _assert_not_reassuring(report)


def test_huge_replica_id_digits_in_ruv_finding_do_not_crash_the_rule(monkeypatch):
    """EXPECTED FAIL (P4, Python >= 3.10.7). replication.py:_explicit_ruv_finding_rid does
    int(m.group(1)) on the message with no try/except (only the kw branch is guarded); 5000 digits
    exceeds the int-string-conversion limit => ValueError => uncaught in run_diagnosis => exit 1.
    Minimal fix: wrap in try/except ValueError (and bound the digits, `\\d{1,9}`)."""
    hc = json.dumps(
        [
            _entry("ipahealthcheck.meta.services", "dirsrv", "SUCCESS"), _entry("ipahealthcheck.ds.replication", "ReplicationCheck", "SUCCESS"), _entry("ipahealthcheck.ipa.certs", "IPACertmongerExpirationCheck", "SUCCESS"),
            _entry("ipahealthcheck.ds.ruv", "RUVCheck", "ERROR", "Replica ID " + "9" * 5000 + " has no corresponding live server"),
        ]
    )
    _install(monkeypatch, healthcheck=(1, hc, ""), ruv=(0, RUV_GOOD + "ipa03.example.test:389: 6\n", ""))
    report = _diagnose()  # must not raise
    _assert_not_reassuring(report)


def test_undecodable_rpm_output_does_not_crash_environment_detection(monkeypatch):
    """EXPECTED FAIL (P4). detect_environment() is documented 'never raises', but _rpm_version only
    catches (OSError, SubprocessError); subprocess.run(text=True) raises UnicodeDecodeError
    (a ValueError) on non-UTF-8 rpm output and the whole run aborts before any evidence is
    collected (environment.py:109-118).
    Minimal fix: errors='replace' and `except (OSError, ValueError, SubprocessError)`."""
    _install(monkeypatch, extra={"rpm": UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")})
    report = _diagnose()  # must not raise
    assert report.overall_status == OverallStatus.HEALTHY


def test_duplicate_finding_id_cannot_hide_an_unclaimed_error():
    """EXPECTED FAIL (P3). unexplained._claimed_ids() keys on finding_id (= the healthcheck `uuid`).
    If two results share a uuid (buggy plugin, hostile/edited output, fixture), a rule that cites
    the benign one 'claims' the ERROR one, which is then dropped by the safety net.
    Minimal fix: key claims by object identity / (index) or de-duplicate ids on ingest by
    suffixing a counter."""
    benign = Finding(finding_id="dup", source="ipahealthcheck.x.y", check="A", severity=Severity.WARNING, message="m")
    error = Finding(finding_id="dup", source=UNKNOWN_SRC, check="B", severity=Severity.ERROR, message="boom")
    bundle = EvidenceBundle(hostname=HOST, collected_at=EvidenceBundle.now(), findings=[benign, error])
    claimer = Diagnosis(
        pack_id="x",
        rule_id="r",
        status=DiagnosisStatus.DIAGNOSED,
        title="t",
        why="w",
        confidence=Confidence(level=ConfidenceLevel.HIGH, rationale="r"),
        severity=Severity.WARNING,
        evidence_for=[EvidenceRef(evidence_id="dup", kind="finding", why_relevant="w")],
    )
    assert unexplained.unexplained_finding_diagnoses(bundle, [claimer]), "the ERROR finding vanished"


@pytest.mark.parametrize("name", ["journal_dirsrv", "journal_krb5kdc", "journal_named", "journal_pki"])
def test_permission_limited_journal_is_not_a_clean_empty_result(monkeypatch, name):
    """EXPECTED FAIL (P4, non-root only). journalctl run by a user outside adm/systemd-journal exits 0
    with a stderr 'Hint: You are currently not seeing messages from other users and the system'
    (or 'No journal files were opened due to insufficient permissions'). Collectors only look at
    rc, so 'no matching lines' is reported as evidence of absence.
    Minimal fix: treat that stderr text (rc 0 and empty stdout) as a permission-related
    CollectorError."""
    hint = (
        "Hint: You are currently not seeing messages from other users and the system.\n"
        "      Users in groups 'adm', 'systemd-journal' can see all messages."
    )
    monkeypatch.setattr(subprocess, "run", lambda args, *a, **k: _cp(args, 0, "", hint))
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/" + n)
    with pytest.raises(CollectorError):
        get_collector(name).collect_live()


# ---------------------------------------------------------------------------
# C. renderer crashes (a traceback is exit 1 == DEGRADED lookalike, and skips save_report)
# ---------------------------------------------------------------------------

_HOSTILE_UNKNOWN_SEVERITY = [
    pytest.param(_entry(UNKNOWN_SRC, "C", "[/x]", "m"), id="result-closing-tag"),
    pytest.param(_entry("bad[/x]", "C", "FATAL", "m"), id="source-closing-tag"),
    pytest.param(_entry(UNKNOWN_SRC, "C[/x]", "FATAL", "m"), id="check-closing-tag"),
]


@pytest.mark.parametrize("entry", _HOSTILE_UNKNOWN_SEVERITY)
def test_unknown_severity_note_cannot_crash_the_renderer(monkeypatch, entry):
    """EXPECTED FAIL (P1-ish). correlate._unknown_severity_notes() embeds the raw `result` repr and
    the UNSANITISED source/check, and console._print_coverage prints them as
    `[yellow]- {note}[/yellow]` WITHOUT rich.markup.escape (render/console.py:~235). A stray
    closing tag such as '[/x]' raises rich.errors.MarkupError after the diagnosis was printed
    (exit 1, state never saved). A CRITICAL host reports as 'exit 1'.
    Minimal fix: escape(note) at print time AND sanitize_text() the note when it is built."""
    _install(monkeypatch, healthcheck=(1, json.dumps([entry]), ""))
    report = _diagnose()
    assert report.unknown_severity_findings
    _render(report)  # must not raise
    _render(report, details=True)


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param(_entry(UNKNOWN_SRC, "C", "X" * 200000, "m"), id="huge-result"),
        pytest.param(_entry("\x1b[31mred\x1b[0m." + UNKNOWN_SRC, "C", "FATAL", "m"), id="escape-in-source"),
        pytest.param(_entry(UNKNOWN_SRC, "C", "‮fatal", "m"), id="bidi-in-result"),
    ],
)
def test_unknown_severity_notes_are_sanitized_and_bounded(monkeypatch, entry):
    """EXPECTED FAIL (P3). Same note as above is neither length-bounded (repr of a 200 kB result
    goes to the terminal and into --json / the saved state) nor stripped of ESC/bidi characters in
    source/check (repr() only protects the result field). Every other free-text field goes through
    textsafe.sanitize_text.
    Minimal fix: sanitize_text(note, 300) in _unknown_severity_notes."""
    _install(monkeypatch, healthcheck=(1, json.dumps([entry]), ""))
    report = _diagnose()
    assert report.unknown_severity_findings
    for note in report.unknown_severity_findings:
        assert len(note) <= 600
        assert all(ch == " " or ch.isprintable() for ch in note)


_HOSTILE_MESSAGES = [
    pytest.param("[/bold]", id="closing-tag"),
    pytest.param("[/]", id="bare-close"),
    pytest.param("[red]unclosed", id="unclosed-open"),
    pytest.param("[link=http://evil.example]click[/link]", id="link-markup"),
    pytest.param("ends with backslash \\", id="trailing-backslash"),
    pytest.param("\x1b]0;pwned\x07 title", id="osc-title"),
    pytest.param("\x1b[2Jcleared", id="csi-clear"),
    pytest.param("A" * 300000, id="huge"),
]


@pytest.mark.parametrize("source", [UNKNOWN_SRC, DISK_SRC], ids=["unclaimed-source", "rule-claimed-source"])
@pytest.mark.parametrize("message", _HOSTILE_MESSAGES)
def test_hostile_healthcheck_message_never_crashes_any_render_path(monkeypatch, source, message):
    """GUARD. Markup, ESC and huge text in an ERROR message must not crash render_report
    (default and --details), --json serialisation, or ai-preview (exit 1 would mimic DEGRADED)."""
    hc = json.dumps([_entry(source, "C", "ERROR", message)])
    _install(monkeypatch, healthcheck=(1, hc, ""))
    report = _diagnose()
    _assert_not_reassuring(report)
    _render(report, details=True)
    json.dumps(report_to_dict(report))
    args = cli.build_parser().parse_args(["ai-preview"])
    cli.cmd_ai_preview(args, _console())


@pytest.mark.parametrize(
    "message",
    [
        pytest.param("\x1b]0;pwned\x07 title", id="osc-title"),
        pytest.param("\x1b[2Jcleared", id="csi-clear"),
        pytest.param("‮evil", id="bidi-override"),
        pytest.param("A" * 300000, id="huge"),
    ],
)
def test_terminal_escapes_and_bulk_from_rule_claimed_findings_are_neutralised(monkeypatch, message):
    """EXPECTED FAIL (P2). Only the unexplained-findings path sanitizes healthcheck text. Findings that
    a pack rule claims have their message interpolated verbatim into Diagnosis.why / EvidenceRef
    .why_relevant (e.g. directory_server.py:97, certificates.py:375, replication.py:770); the
    renderer's escape() neutralises rich markup but NOT ESC (rich strips only \\a \\b \\v \\f \\r),
    so terminal escape sequences / bidi overrides / 300 kB of text reach the terminal.
    Minimal fix: apply textsafe.sanitize_text to f.message once at ingest
    (evidence/healthcheck.py) so no rule can leak it."""
    hc = json.dumps([_entry(DISK_SRC, "DiskSpaceCheck", "ERROR", message)])
    _install(monkeypatch, healthcheck=(1, hc, ""))
    out = _render(_diagnose(), details=True)
    assert "\x1b" not in out
    assert "‮" not in out
    assert len(out) < 50000


def test_render_verify_survives_hostile_previous_generated_at(monkeypatch):
    """EXPECTED FAIL (P4). render_verify prints `[dim]Comparing against diagnosis from {ts}[/dim]`
    with the timestamp taken from the on-disk state file, unescaped (render/console.py:~205).
    A '[/x]' in that file raises MarkupError.
    Minimal fix: escape(result.previous_generated_at)."""
    _install(monkeypatch)
    result = compare({"generated_at": "[/x]", "diagnoses": []}, _diagnose())
    render_verify(result, _console())  # must not raise


def test_render_report_survives_hostile_replay_hostname(tmp_path):
    """EXPECTED FAIL (P4, replay only). `Host: {report.hostname}` is printed unescaped
    (render/console.py:~53) and the hostname comes from the fixture's meta.json. The same holds
    for --details environment strings (distro etc.).
    Minimal fix: escape() every interpolated value, or use Text.assemble."""
    (tmp_path / "meta.json").write_text(json.dumps({"hostname": "[/x]"}), encoding="utf-8")
    (tmp_path / "healthcheck.json").write_text(GOOD_HC, encoding="utf-8")
    report = run_diagnosis(collect.collect_evidence(replay_dir=str(tmp_path)))
    _render(report)  # must not raise


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param("A" * 10_000_000, id="10MB"),
        pytest.param("\x1b[" * 50000, id="csi-storm"),
        pytest.param("\x1b]0;" + "x" * 100000, id="unterminated-osc"),
        pytest.param("‮" * 1000 + "abc", id="bidi"),
        pytest.param("\ud800abc", id="lone-surrogate"),
        pytest.param("a\x00b\x07c\x7fd", id="controls"),
    ],
)
@pytest.mark.parametrize("limit", [80, 300])
def test_sanitizer_is_bounded_and_strips_control_characters(payload, limit):
    """GUARD. sanitize_text never exceeds `limit`, never leaves ESC/control/format characters."""
    out = sanitize_text(payload, limit)
    assert len(out) <= limit
    assert all(ch == " " or ch.isprintable() for ch in out)


# ---------------------------------------------------------------------------
# D. verify / ai-preview / diagnose exit-code matrix
# ---------------------------------------------------------------------------


def _parse(*argv):
    return cli.build_parser().parse_args(list(argv))


def test_verify_previous_problem_gone_but_new_warning_bucket_diagnosis_is_not_exit_zero(monkeypatch, tmp_path):
    """EXPECTED FAIL (P2). cmd_verify only counts new ROOT-TIER diagnoses (verify.py:171-175). Previous
    problem X is RESOLVED, but a NEW diagnosis in the WARNING/RELATED bucket makes the fresh report
    DEGRADED (a plain `diagnose` exits 1). verify returns 0 (cli.py:149) and prints 'nothing to
    verify' / RESOLVED, so `ipa-diagnose verify && echo fixed` goes green on a DEGRADED host.
    Same when the previous run had no problems at all (items == []).
    Minimal fix: after the STILL_PRESENT/UNABLE checks, `return fresh` (0 only if fresh == 0)."""
    state = tmp_path / "state.json"
    save_report(state, run_diagnosis(_problem_bundle()))  # previous: healthcheck.unexplained-findings
    b, report = _benign_warning_report()
    assert report.overall_status == OverallStatus.DEGRADED
    monkeypatch.setattr(cli, "_collect_and_diagnose", lambda args: (b, report))
    monkeypatch.setattr(cli, "default_state_path", lambda: state)
    assert cli.cmd_verify(_parse("verify"), _console()) != 0


def test_verify_with_incomplete_run_does_not_overwrite_the_baseline(monkeypatch, tmp_path):
    """EXPECTED FAIL (P3). cmd_verify (and diagnose) always save_report() the fresh report, even when
    ipa-healthcheck could not run. The next `verify` then diffs against an EMPTY report: the original
    problem is gone from history (a persisting WARNING-bucket problem then reads 'nothing to
    verify', see the test above).
    Minimal fix: do not replace the baseline when evidence_completeness.healthcheck_collected is
    False."""
    state = tmp_path / "state.json"
    save_report(state, run_diagnosis(_problem_bundle()))
    _install(monkeypatch, healthcheck=(2, "", "boom"))
    monkeypatch.setattr(cli, "default_state_path", lambda: state)
    cli.cmd_verify(_parse("verify"), _console())
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert any(d["diagnosis_id"] == "healthcheck.unexplained-findings" for d in saved["diagnoses"])


@pytest.mark.parametrize(
    "content",
    [
        pytest.param("[]", id="list-instead-of-object"),
        pytest.param('{"diagnoses": [{"title": "x"}]}', id="entry-without-id"),
        pytest.param('{"diagnoses": "x"}', id="diagnoses-not-a-list"),
    ],
)
def test_verify_with_corrupt_state_file_does_not_crash(monkeypatch, tmp_path, content):
    """EXPECTED FAIL (P4). The state file may sit in a user-writable ~/.cache. load_previous_report
    only guards JSON syntax; compare() then raises AttributeError/KeyError/TypeError (exit 1).
    Minimal fix: validate shape in load_previous_report and return None (no baseline) otherwise."""
    state = tmp_path / "state.json"
    state.write_text(content, encoding="utf-8")
    _install(monkeypatch)
    monkeypatch.setattr(cli, "default_state_path", lambda: state)
    assert isinstance(cli.cmd_verify(_parse("verify"), _console()), int)


def test_verify_with_unrelated_collector_gap_never_exits_zero(monkeypatch, tmp_path):
    """GUARD. Previous kerberos-pack diagnosis; this run is otherwise clean but the replication
    collector failed (a collector that verify's pack->collector mapping does not attribute to the
    kerberos pack). The item may read RESOLVED, but the overall exit must not be 0."""
    state = tmp_path / "state.json"
    state.write_text(
        json.dumps(
            {
                "generated_at": "2026-01-01T00:00:00Z",
                "diagnoses": [
                    {
                        "diagnosis_id": "kerberos.x",
                        "pack_id": "kerberos",
                        "title": "t",
                        "priority": "PRIMARY",
                        "status": "DIAGNOSED",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    _install(monkeypatch, ruv=(1, "", "permission denied"))
    _ldapi_unavailable(monkeypatch)
    monkeypatch.setattr(cli, "default_state_path", lambda: state)
    assert cli.cmd_verify(_parse("verify"), _console()) != 0


def test_ai_preview_exit_code_matches_diagnose_when_problems_exist(monkeypatch):
    """EXPECTED FAIL (P4, design). With an explainable (PRIMARY) problem, ai-preview always returns 0
    (cli.py:175) while `diagnose` on the same evidence returns 3/2/1. Round 1 fixed only the
    'nothing to explain' branches. A wrapper using the exit code as a health gate is misled.
    Minimal fix: return _exit_code_for(report) at the end of cmd_ai_preview."""
    hc = json.dumps([_entry(UNKNOWN_SRC, "C", "ERROR", "boom")])
    _install(monkeypatch, healthcheck=(1, hc, ""))
    expected = _exit_code_for(_diagnose())
    assert expected != 0
    assert cli.cmd_ai_preview(_parse("ai-preview"), _console()) == expected


class _BrokenProvider:
    def is_configured(self):
        return True

    def generate(self, request):
        raise RuntimeError("provider bug (not a ProviderError)")


def test_ai_provider_bug_never_aborts_the_deterministic_report(monkeypatch, tmp_path):
    """EXPECTED FAIL (P3). explain_diagnosis only catches ProviderError; any other exception from an
    AI provider/SDK propagates out of _maybe_explain, which runs BEFORE render_report, so a CRITICAL
    host prints no report and exits 1.
    Minimal fix: `except Exception` in explain_diagnosis (or around _maybe_explain)."""
    hc = json.dumps([_entry(UNKNOWN_SRC, "C", "ERROR", "boom")])
    _install(monkeypatch, healthcheck=(1, hc, ""))
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(cli, "build_provider", lambda config: _BrokenProvider())
    code = cli.cmd_diagnose(_parse("--ai-provider", "openai"), _console())
    assert code == 3
