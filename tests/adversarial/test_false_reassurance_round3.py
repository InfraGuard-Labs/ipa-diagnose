"""Round-3 adversarial review (independent of rounds 1 and 2).

GATE QUESTION: can an evidence-collection failure still cause a misleading HEALTHY / exit 0 /
"No problems detected"?  Also checked: false DIAGNOSIS (missing evidence treated as "not
contradicting"), false DEGRADED, hostile text in displayed commands, Python 3.9 syntax.

This file was written WITHOUT being able to execute it: every expectation is derived from reading
the code at the 0.1.2 release-candidate HEAD.

Legend used in the test docstrings:
  GUARD               expected to PASS today (a defence that holds; keep it holding)
  EXPECTED FAIL (Pn)  expected to FAIL today; Pn = priority (P1 worst). The docstring states the
                      minimal fix.
"""

from __future__ import annotations

import ast
import json
import pathlib
import re
import subprocess

import pytest

from ipa_diagnose.cli import _exit_code_for
from ipa_diagnose.engine import correlate
from ipa_diagnose.engine.model import (
    Confidence,
    ConfidenceLevel,
    Diagnosis,
    DiagnosisStatus,
    OverallStatus,
    PriorityBucket,
)
from ipa_diagnose.engine.registry import all_packs
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence import collect
from ipa_diagnose.evidence.collectors.kerberos_client import KerberosClientCollector
from ipa_diagnose.evidence.collectors.registry import get as get_collector
from ipa_diagnose.evidence.model import (
    CollectionError,
    EvidenceBundle,
    EvidenceItem,
    Finding,
    Severity,
)
from ipa_diagnose.render.json_output import report_to_dict
from ipa_diagnose.verify import VerifyOutcome, compare

HOST = "ipa01.example.test"

# ---------------------------------------------------------------------------
# helpers (copied from test_false_reassurance.py so this file is standalone)
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


META_OK = _entry("ipahealthcheck.meta.services", "dirsrv", "SUCCESS")
GOOD_HC = json.dumps([META_OK])

LIST_GOOD = (
    "ipa02.example.test: replica\n"
    "  last update status: Error (0) Replica acquired successfully: Incremental update succeeded\n"
    "  last update ended: 2026-01-01 12:00:00+00:00\n"
)
RUV_GOOD = "Replica Update Vectors:\nipa01.example.test:389: 4\nipa02.example.test:389: 5\n"


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
    monkeypatch.setattr("socket.getfqdn", lambda *a, **k: HOST)


def _diagnose():
    return run_diagnosis(collect.collect_evidence())


def _bundle(findings=(), items=(), errors=()):
    b = EvidenceBundle(hostname=HOST, collected_at=EvidenceBundle.now())
    b.findings.extend(findings)
    b.items.extend(items)
    b.collection_errors.extend(errors)
    return b


def _finding(fid, source, check, severity, message="", **keywords):
    return Finding(
        finding_id=fid, source=source, check=check, severity=severity, message=message, keywords=dict(keywords)
    )


def _item(iid, kind, **data):
    return EvidenceItem(item_id=iid, kind=kind, summary=iid, data=data)


def _diag_by_rule(report, rule_id):
    return next((d for d in report.diagnoses if d.rule_id == rule_id), None)


# ---------------------------------------------------------------------------
# A. GUARDS: exit code / JSON / status agreement, verify collector->pack mapping
# ---------------------------------------------------------------------------


def _report_variants():
    healthy = correlate.build_report(_bundle(), [], ["x"])
    nfv = correlate.build_report(
        _bundle(errors=[CollectionError(collector="replication_agreements", message="boom")]), [], ["x"]
    )
    insufficient = correlate.build_report(
        _bundle(errors=[CollectionError(collector="ipa-healthcheck", message="boom")]), [], ["x"]
    )
    return healthy, nfv, insufficient


def test_exit_code_json_status_matrix_agrees_for_reports_without_diagnoses():
    """GUARD. With no diagnoses: HEALTHY <=> exit 0 <=> fully_verified; NFV -> 4; UNKNOWN -> 3."""
    healthy, nfv, insufficient = _report_variants()
    assert (healthy.overall_status, _exit_code_for(healthy), report_to_dict(healthy)["fully_verified"]) == (
        OverallStatus.HEALTHY, 0, True)
    assert (nfv.overall_status, _exit_code_for(nfv), report_to_dict(nfv)["fully_verified"]) == (
        OverallStatus.NOT_FULLY_VERIFIED, 4, False)
    assert (insufficient.overall_status, _exit_code_for(insufficient), report_to_dict(insufficient)["fully_verified"]) == (
        OverallStatus.UNKNOWN, 3, False)


@pytest.mark.parametrize("pack", [p.pack_id for p in all_packs()])
def test_verify_marks_every_pack_collector_failure_unable_to_verify(pack):
    """GUARD. For every pack and each of its declared collectors, a failure of that collector
    must turn a previously diagnosed problem of that pack into UNABLE_TO_VERIFY (never RESOLVED)."""
    p = next(x for x in all_packs() if x.pack_id == pack)
    for name in list(p.additional_collectors) + list(p.unconditional_collectors):
        assert get_collector(name) is not None, f"collector {name} is declared but not registered"
        current = correlate.build_report(
            _bundle(errors=[CollectionError(collector=name, message="boom")]), [], ["x"]
        )
        previous = {
            "generated_at": "t",
            "diagnoses": [
                {"diagnosis_id": f"{pack}.some-rule", "pack_id": pack, "title": "T", "status": "DIAGNOSED",
                 "priority": "PRIMARY_PROBLEM"}
            ],
        }
        result = compare(previous, current)
        assert [i.outcome for i in result.items] == [VerifyOutcome.UNABLE_TO_VERIFY], (pack, name)


# ---------------------------------------------------------------------------
# B. Python 3.9 compatibility (package claims 3.9-3.14)
# ---------------------------------------------------------------------------

SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "ipa_diagnose"


def _py_files():
    return sorted(SRC.rglob("*.py"))


@pytest.mark.parametrize("path", _py_files(), ids=lambda p: str(p.relative_to(SRC)))
def test_source_parses_with_python39_grammar(path):
    """GUARD. No match statements / newer-only syntax. (ast.parse feature_version is best effort.)"""
    ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 9))


@pytest.mark.parametrize("path", _py_files(), ids=lambda p: str(p.relative_to(SRC)))
def test_no_runtime_evaluated_pep604_or_builtin_generics_without_future_import(path):
    """GUARD. Modules without `from __future__ import annotations` must not use `X | Y` or
    `list[int]` in annotations (they are evaluated at definition time on 3.9). Also no
    dataclass(slots=/kw_only=) which is 3.10+."""
    text = path.read_text(encoding="utf-8")
    assert "slots=True" not in text and "kw_only=True" not in text
    tree = ast.parse(text)
    has_future = any(
        isinstance(n, ast.ImportFrom) and n.module == "__future__" and any(a.name == "annotations" for a in n.names)
        for n in tree.body
    )
    if has_future:
        return
    for node in ast.walk(tree):
        anns = []
        if isinstance(node, ast.FunctionDef):
            anns = [a.annotation for a in node.args.args + node.args.kwonlyargs if a.annotation] + (
                [node.returns] if node.returns else [])
        elif isinstance(node, ast.AnnAssign):
            anns = [node.annotation]
        for ann in anns:
            for sub in ast.walk(ann):
                assert not (isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.BitOr)), path
                assert not (
                    isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name)
                    and sub.value.id in {"list", "dict", "tuple", "set"}
                ), path


# ---------------------------------------------------------------------------
# C. Missing / unusable evidence treated as "not contradicting"
# ---------------------------------------------------------------------------


def test_keytab_warning_with_undetermined_kvno_is_not_healthy():
    """EXPECTED FAIL (P3, false HEALTHY). engine/packs/kerberos.py KeytabKvnoMismatchRule.evaluate:
    an IPAHostKeytab WARNING plus a kvno_comparison item whose match is None (kvno could not be
    determined, e.g. root without a ticket) -> `not kvno_items` is False, `mismatches` is empty, the
    rule falls through to `return None`. WARNING is below the unexplained-finding ERROR gate, so the
    run is HEALTHY / exit 0 although the rule covers this exact check and the KVNO evidence is
    missing. Minimal fix: treat `match is None` like an absent comparison (UNKNOWN_INSUFFICIENT)."""
    b = _bundle(
        findings=[_finding("k1", "ipahealthcheck.ipa.host", "IPAHostKeytab", Severity.WARNING,
                           "kinit -kt failed: something odd")],
        items=[_item("kvno", "kvno_comparison", principal="host/x@R", kdc_kvno=None, keytab_kvno=2, match=None,
                     error="no ticket")],
    )
    report = run_diagnosis(b)
    assert report.overall_status != OverallStatus.HEALTHY
    assert _exit_code_for(report) != 0


def test_clock_skew_is_not_blamed_for_a_dns_style_kinit_failure():
    """EXPECTED FAIL (P1, false DIAGNOSIS). engine/packs/kerberos.py ClockSkewRule +
    KdcDiscoveryFailureRule: IPAHostKeytab fails with 'Cannot resolve network address for KDC'
    (a DNS problem). This host's NTP is merely unsynchronised. ClockSkewRule cites *any* WARNING+
    IPAHostKeytab finding as corroboration and reaches DIAGNOSED/MEDIUM 'clock skew'; then
    KdcDiscoveryFailureRule returns None because a desynced clock exists. The real DNS-style
    cause is replaced by a wrong one. Minimal fix: ClockSkewRule must ignore keytab findings that
    _is_dns_style() (and not report DIAGNOSED from desync alone without a clock-style failure)."""
    b = _bundle(
        findings=[_finding("k1", "ipahealthcheck.ipa.host", "IPAHostKeytab", Severity.ERROR,
                           "Failed to obtain host TGT: Cannot resolve network address for KDC in requested realm")],
        items=[_item("clk", "clock_sync", method="chronyc", ntp_synchronized=False, offset_seconds=None)],
    )
    report = run_diagnosis(b)
    assert _diag_by_rule(report, "clock-skew") is None
    assert _diag_by_rule(report, "kdc-discovery-failure") is not None


def test_unsynchronised_ntp_alone_is_not_a_kerberos_failure_diagnosis():
    """EXPECTED FAIL (P3, false DEGRADED / false DIAGNOSIS). The kerberos pack is triggered by ANY
    WARNING+ finding from ipa.kdc / ipa.host / meta.services (here a benign KDCWorkersCheck
    WARNING). kerberos_client then reports chrony 'Not synchronised' (very common in labs/VMs)
    and ClockSkewRule returns DIAGNOSED ERROR 'Kerberos authentication failing due to clock
    skew' with no Kerberos failure evidence at all. Minimal fix: require a keytab/KDC failure
    finding (clock-style) or a krb5kdc clock-skew journal line for the DIAGNOSED status."""
    b = _bundle(
        findings=[_finding("w1", "ipahealthcheck.ipa.kdc", "KDCWorkersCheck", Severity.WARNING,
                           "Workers is 1, CPUs is 4")],
        items=[_item("clk", "clock_sync", method="chronyc", ntp_synchronized=False, offset_seconds=None)],
    )
    report = run_diagnosis(b)
    assert _diag_by_rule(report, "clock-skew") is None


def test_bind_failure_of_the_local_check_is_not_discarded_as_a_transient_blip():
    """EXPECTED FAIL (P2, false downgrade). ldap_query's live _keytab_bind_check always binds to
    the LOCAL host (data['target'] = this hostname, evidence_id 'keytab-bind-check'), but
    PeerConnectivityBreakRule keeps bind failures only when target == the peer named in the
    ReplicationCheck agreement DN. A failing bind is dropped, the green agreement remains, and the
    rule returns TRANSIENT_SUSPECTED/WARNING claiming 'the keytab/bind check succeeded' - false.
    Minimal fix: do not filter bind items by peer unless target is a peer (target != own host), or
    treat a non-matching failing bind as UNKNOWN_CONFLICTING, never as 'succeeded'."""
    trig = _finding(
        "r1", "ipahealthcheck.ds.replication", "ReplicationCheck", Severity.ERROR,
        "agreement in error",
        agreement="cn=meToipa02.example.test,cn=replica,cn=dc\\3Dexample\\2Cdc\\3Dtest,cn=mapping tree,cn=config",
    )
    b = _bundle(
        findings=[trig],
        items=[
            _item("keytab-bind-check", "keytab_bind_check", bind_ok=False, target=HOST, principal="ldap/x"),
            _item("ra:ipa02", "replication_agreement", peer="ipa02.example.test", status="green"),
        ],
    )
    report = run_diagnosis(b)
    d = _diag_by_rule(report, "peer-connectivity-break")
    assert d is not None
    assert d.status != DiagnosisStatus.TRANSIENT_SUSPECTED
    assert "bind check succeeded" not in d.why


def test_failed_ldap_query_collector_does_not_yield_a_transient_verdict(monkeypatch):
    """EXPECTED FAIL (P2, missing evidence == 'not contradicting'). Live path: ReplicationCheck
    ERROR; `list -v` works (green agreement); the ldap_query collector FAILS (GSSAPI conflict search
    exits 254 -> CollectorError, so the keytab/bind check never runs at all). bind_items is empty
    but agreement_items is not, so PeerConnectivityBreakRule skips its 'nothing corroborates' branch
    and emits TRANSIENT_SUSPECTED/WARNING ('the keytab/bind check succeeded ... matches a transient
    blip') for an ERROR finding. The collection error is listed but the verdict is a lowered, false
    'probably transient'. Minimal fix: in the rule, treat 'ldap_query collector errored' (or no
    keytab_bind_check item) as insufficient evidence -> UNKNOWN_INSUFFICIENT_EVIDENCE at trigger
    severity, and never say the bind check succeeded when it did not run."""
    hc = json.dumps([
        META_OK,
        _entry("ipahealthcheck.ds.replication", "ReplicationCheck", "ERROR", msg="agreement is in error state"),
    ])
    _install(monkeypatch, healthcheck=(1, hc, ""),
             extra={"ldapsearch": (254, "", "SASL/GSSAPI: no credentials")})
    report = _diagnose()
    assert any(e.startswith("ldap_query") for e in report.collection_errors)
    d = _diag_by_rule(report, "peer-connectivity-break")
    assert d is not None
    assert d.status != DiagnosisStatus.TRANSIENT_SUSPECTED
    assert d.severity != Severity.WARNING


def test_same_host_with_two_replica_ids_is_not_silently_healthy(monkeypatch):
    """EXPECTED FAIL (P2, false HEALTHY). replication_agreements marks a RUV alive purely by
    hostname membership in the known-server set. A replica that was removed and re-installed with
    the same hostname leaves its OLD replica id (5) in the RUV next to the new one (9): both map to
    ipa02.example.test, both alive=True, no candidate, no diagnosis -> HEALTHY/exit 0 while a stale
    RUV exists. Minimal fix: in _parse_list_ruv_output/_parse_ldapi_ruv_ldif, when the same
    (suffix, host:port) appears with more than one replica id, mark the extra ids alive=False (or
    surface as UNKNOWN 'duplicate RUV for one host')."""
    ruv = "Replica Update Vectors:\nipa01.example.test:389: 4\nipa02.example.test:389: 5\nipa02.example.test:389: 9\n"
    _install(monkeypatch, ruv=(0, ruv, ""))
    report = _diagnose()
    assert report.overall_status != OverallStatus.HEALTHY
    assert _exit_code_for(report) != 0


def test_dns_lookup_timeouts_are_not_a_high_confidence_record_diagnosis(monkeypatch):
    """EXPECTED FAIL (P2, false HIGH DIAGNOSIS from a collection failure). dns_lookup._run_dig
    turns a dig TIMEOUT into rcode 'TIMEOUT', answers [] and the collector marks it
    severity=ERROR; SrvAutodiscoveryRule._looks_broken() then counts every timed-out query as
    'live dig independently confirms this record is missing or wrong' -> DIAGNOSED / HIGH
    'DNS records broken' although no record was ever observed. Minimal fix: _looks_broken() must
    ignore rcode TIMEOUT/UNKNOWN items (treat them as insufficient evidence -> UNKNOWN)."""
    hc = json.dumps([
        META_OK,
        _entry("ipahealthcheck.ipa.idns", "IPADNSSystemRecordsCheck", "ERROR", msg="Expected SRV record missing"),
    ])
    _install(monkeypatch, healthcheck=(1, hc, ""), extra={"dig": subprocess.TimeoutExpired("dig", 5)})
    report = _diagnose()
    d = _diag_by_rule(report, "srv-autodiscovery")
    assert d is not None
    assert not (d.status == DiagnosisStatus.DIAGNOSED and d.confidence.level == ConfidenceLevel.HIGH)


def test_kvno_collector_parses_real_klist_kte_output(monkeypatch):
    """EXPECTED FAIL (P2, silent evidence gap). kerberos_client._KEYTAB_ENTRY_RE expects
    '<kvno> <principal@REALM>' adjacent, but real `klist -kte` prints a timestamp column between
    them ('   2 09/15/2026 10:00:00 host/x@R (aes256-...)'). No entry ever parses live, so no
    kvno_comparison item is produced and NO collection error is raised: the HIGH-confidence
    keytab-KVNO diagnosis is unreachable outside fixtures and the collector reports success.
    Minimal fix: allow an optional timestamp: r'^\\s*(\\d+)\\s+(?:\\S+\\s+\\S+\\s+)?(\\S+@\\S+)\\s'."""
    out = (
        "Keytab name: FILE:/etc/krb5.keytab\n"
        "KVNO Timestamp           Principal\n"
        "---- ------------------- ------------------------------------------------------\n"
        "   2 09/15/2026 10:00:00 host/ipa01.example.test@EXAMPLE.TEST (aes256-cts-hmac-sha384-192) \n"
    )
    monkeypatch.setattr(subprocess, "run", lambda args, *a, **k: _cp(args, 0, out, ""))
    c = KerberosClientCollector()
    c._failures = []
    assert c._read_keytab_entries() == [("host/ipa01.example.test@EXAMPLE.TEST", 2)]


# ---------------------------------------------------------------------------
# D. correlate: demotion by a weak upstream diagnosis
# ---------------------------------------------------------------------------


def _mk(pack, rule, status, severity, level, upstream=()):
    return Diagnosis(
        pack_id=pack, rule_id=rule, status=status, title=f"{pack}.{rule}", why="w",
        confidence=Confidence(level=level, rationale="r"), severity=severity,
        next_diagnostic_step=None if status == DiagnosisStatus.DIAGNOSED else "look",
        upstream_candidates=list(upstream),
    )


def test_warning_level_unknown_upstream_does_not_demote_an_error_level_problem():
    """EXPECTED FAIL (P3, design risk: a real problem hidden in RELATED SYMPTOMS).
    correlate._is_real_problem() only excludes DIAGNOSED+WARNING, so a merely *possible* stale RUV
    (UNKNOWN, WARNING - very common) 'fires' the replication pack and demotes a DIAGNOSED ERROR
    certificates finding (upstream_candidates=['replication']) to RELATED_SYMPTOM, whose actions
    are not shown in the default output, with the false note 'downstream symptom of the
    replication problem'. Minimal fix: _is_real_problem() requires severity >= ERROR for any
    status (a WARNING-severity UNKNOWN cannot be a cause of an ERROR)."""
    weak = _mk("replication", "stale-ruv", DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE, Severity.WARNING,
               ConfidenceLevel.LOW)
    real = _mk("certificates", "certmonger-tracking-stuck", DiagnosisStatus.DIAGNOSED, Severity.ERROR,
               ConfidenceLevel.MEDIUM, upstream=["replication"])
    report = correlate.build_report(_bundle(), [weak, real], ["replication", "certificates"])
    d = next(x for x in report.diagnoses if x.pack_id == "certificates")
    assert d.priority != PriorityBucket.RELATED_SYMPTOM


# ---------------------------------------------------------------------------
# E. hostile ipa-healthcheck text reaching DISPLAYED commands
# ---------------------------------------------------------------------------


def _all_commands(report):
    return [a.command for d in report.diagnoses for a in d.actions if a.command] + [
        d.next_diagnostic_step or "" for d in report.diagnoses
    ]


def test_untrusted_index_attribute_is_not_interpolated_into_a_suggested_command():
    """EXPECTED FAIL (P2, security). engine/packs/directory_server.py:670 builds
    `db2index.pl -Z <instance> -t {attribute}` from ipa-healthcheck kw['attr'] verbatim (CAUTION
    action shown as 'do this'), so a hostile/odd value becomes a copy-pasteable shell fragment.
    unexplained.py already guards this with an identifier regex; the packs do not.
    Minimal fix: only interpolate when re.fullmatch(r'[A-Za-z0-9_.-]+', str(attribute)), else use
    the '<attribute>' placeholder."""
    evil = "x; touch /tmp/pwned #"
    b = _bundle(findings=[_finding("b1", "ipahealthcheck.ds.backends", "BackendsCheck", Severity.ERROR,
                                   "missing index", attr=evil)])
    report = run_diagnosis(b)
    assert not any("touch /tmp/pwned" in c for c in _all_commands(report))


def test_untrusted_topology_suffix_is_not_interpolated_into_a_suggested_command():
    """EXPECTED FAIL (P2, security). engine/packs/replication.py:790/795 interpolate
    kw['suffix'] of IPATopologyDomainCheck into `ipa topologysegment-find {suffix}` and
    `ipa topologysuffix-verify {suffix}` unsanitised. Same minimal fix as the index attribute."""
    evil = "domain; touch /tmp/pwned #"
    b = _bundle(findings=[_finding("t1", "ipahealthcheck.ipa.topology", "IPATopologyDomainCheck", Severity.ERROR,
                                   "suffix domain is not connected", suffix=evil)])
    report = run_diagnosis(b)
    assert not any("touch /tmp/pwned" in c for c in _all_commands(report))


# ---------------------------------------------------------------------------
# F. robustness / bounds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("meta", ["5", '"hostname"', "[1]", "null"])
def test_replay_meta_json_of_unexpected_shape_does_not_crash_collection(tmp_path, meta):
    """EXPECTED FAIL for '5', '"hostname"' and 'null' (P4; '[1]' passes). collect._resolve_hostname
    catches only JSONDecodeError/OSError: a valid-JSON but non-object meta.json ('5' ->
    `'hostname' in 5`; 'null' -> `'hostname' in None`; '"hostname"' -> `str['hostname']`) raises TypeError out of collect_evidence (the CLI then exits
    70 instead of a degraded run). Minimal fix: `if isinstance(meta, dict) and 'hostname' in meta`."""
    (tmp_path / "meta.json").write_text(meta, encoding="utf-8")
    (tmp_path / "healthcheck.json").write_text(json.dumps([META_OK]), encoding="utf-8")
    bundle = collect.collect_evidence(replay_dir=str(tmp_path))
    assert bundle.hostname


def test_unknown_severity_notes_are_bounded():
    """EXPECTED FAIL (P4, output flood). correlate._unknown_severity_notes emits one note per
    Severity.UNKNOWN finding with no cap, and render/JSON print all of them (a hostile or buggy
    ipa-healthcheck with 100k odd results floods the terminal and the state file).
    Minimal fix: cap to ~20 notes plus '(+N more)'."""
    findings = [
        Finding(finding_id=f"u{i}", source="ipahealthcheck.zzz.x", check="C", severity=Severity.UNKNOWN,
                message="m", raw={"result": "BOGUS"})
        for i in range(3000)
    ]
    report = run_diagnosis(_bundle(findings=findings))
    assert len(report.unknown_severity_findings) <= 100


# ---------------------------------------------------------------------------
# G. private Kerberos credential cache (ldap_query) cleanup
# ---------------------------------------------------------------------------


def test_ldap_query_private_ccache_dir_is_removed_even_when_the_check_raises(monkeypatch):
    """GUARD. _keytab_bind_check creates a private tempdir for KRB5CCNAME and must always delete
    it, including when the inner check raises unexpectedly."""
    import tempfile

    from ipa_diagnose.evidence.collectors import ldap_query

    created = []
    real_mkdtemp = tempfile.mkdtemp

    def spy(*a, **k):
        p = real_mkdtemp(*a, **k)
        created.append(p)
        return p

    monkeypatch.setattr(tempfile, "mkdtemp", spy)

    def boom(*a, **k):
        raise RuntimeError("unexpected")

    monkeypatch.setattr("shutil.which", boom)
    with pytest.raises(RuntimeError):
        ldap_query.LdapQueryCollector()._keytab_bind_check(HOST)
    assert created and not any(pathlib.Path(p).exists() for p in created)


def test_ldap_query_kinit_uses_a_private_ccache(monkeypatch):
    """GUARD. kinit must run with KRB5CCNAME pointing into the throw-away directory, never the
    invoking user's default cache."""
    from ipa_diagnose.evidence.collectors import ldap_query

    seen = {}

    def fake_run(args, *a, **kw):
        if args[0] == "kinit":
            seen["env"] = kw.get("env") or {}
        return _cp(args, 1, "", "kinit failed")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/" + n)
    item = ldap_query.LdapQueryCollector()._keytab_bind_check(HOST)
    assert seen["env"].get("KRB5CCNAME", "").startswith("FILE:")
    assert item.data["bind_ok"] is False
