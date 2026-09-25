"""Slice 1 resolution framework: every procedure's positive, wrong-version, look-alike and
contradicting-evidence cases, plus catalogue validation, rendering order, JSON and verify.

A procedure must never appear unless its applicability and prerequisites are established."""

from __future__ import annotations

import copy
import io
import json
import pathlib

import pytest
from rich.console import Console

from ipa_diagnose.engine.model import Confidence, ConfidenceLevel, Diagnosis, DiagnosisStatus
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.healthcheck import parse_healthcheck_results
from ipa_diagnose.evidence.model import EnvironmentInfo, EvidenceBundle, EvidenceItem
from ipa_diagnose.render.console import render_report
from ipa_diagnose.render.json_output import report_to_dict
from ipa_diagnose.resolution import checks as C
from ipa_diagnose.resolution import knowledge as K
from ipa_diagnose.resolution.engine import NONE, OFFERED, WITHHELD, evaluate_verify, resolve_report

ROOT = pathlib.Path(__file__).resolve().parents[2]
ENV = EnvironmentInfo(distro="fedora", distro_version="43", freeipa_version="4.13.3-2.fc43")


class FakeRunner(C.Runner):
    """Answers registry checks from a dict; anything not listed is NOT_RUN (like an unavailable tool)."""

    def __init__(self, results):
        super().__init__()
        self.results = results
        self.calls = []

    def _execute(self, spec, params):
        key = C._key(spec.check_id, params)
        self.calls.append(key)
        status, fields, display = self.results.get(key, (C.NOT_RUN, {}, "not available"))
        return C.CheckResult(spec.check_id, params, status, dict(fields), display)


def ok(fields, display=""):
    return (C.OK, fields, display or "ok")


ROOT_OK = {"host.privilege|": ok({"is_root": True})}
NOT_ROOT = {"host.privilege|": ok({"is_root": False})}


def hc(source, check, result, uid="u", **kw):
    return {"source": source, "check": check, "result": result, "uuid": f"{source}.{check}.{uid}", "kw": kw}


GOOD = [hc("ipahealthcheck.meta.services", s, "SUCCESS", status=True) for s in ("krb5kdc", "httpd")]


def report_for(entries, results, env=ENV, items=()):
    findings = parse_healthcheck_results(GOOD + list(entries), command="t", live=False)
    bundle = EvidenceBundle(hostname="ipa01.lab.test", collected_at=EvidenceBundle.now(), findings=findings,
                            items=list(items), environment=env)
    report = run_diagnosis(bundle)
    runner = FakeRunner(results)
    resolve_report(report, runner)
    return report, runner


def res_of(report, key):
    for d in report.diagnoses:
        if d.resolution_key == key:
            return report.resolutions.get(d.diagnosis_id)
    return None


# ------------------------------------------------------------------------------------------- catalogue


def test_shipped_catalogue_is_valid_and_complete():
    K.reset_cache()
    procs, error = K.load_catalogue()
    assert error is None
    ids = {p["id"] for p in procs}
    assert {"proc.service.start-stopped-service", "proc.files.restore-expected-permissions",
            "proc.time.step-clock-with-chrony", "proc.certs.renew-expiring-ds-certificate",
            "none.certs.expired-ds-certificate", "none.time.kdc-reported-skew"} <= ids


def test_compiled_json_matches_the_yaml_sources():
    yaml = pytest.importorskip("yaml")  # noqa: F841 - build-time dependency (dev extra)
    import importlib.util

    spec = importlib.util.spec_from_file_location("ck", ROOT / "scripts" / "compile_knowledge.py")
    ck = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ck)
    assert ck.compile_catalogue() == (ROOT / "src/ipa_diagnose/resolution/procedures.json").read_text(encoding="utf-8")


def _cat():
    return json.loads((ROOT / "src/ipa_diagnose/resolution/procedures.json").read_text(encoding="utf-8"))


def _mutate(fn):
    cat = _cat()
    proc = next(p for p in cat["procedures"] if p["id"] == "proc.files.restore-expected-permissions")
    fn(proc)
    with pytest.raises(K.KnowledgeError):
        K.validate_catalogue(cat)


@pytest.mark.parametrize("mutation", [
    lambda p: p["withhold_if"][0].__setitem__("when", "stat.exists == false"),               # string expression
    lambda p: p["steps"][0].__setitem__("command", ["chmod", "0660; rm -rf /", {"item": "path", "type": "ipa_path"}]),
    lambda p: p["steps"][0].__setitem__("command", ["sh", "-c", "chmod"]) or p["steps"][0]["command"].append("x y"),
    lambda p: p["steps"][0].__setitem__("command", ["chmod", {"item": "expected"}, {"item": "path", "type": "ipa_path"}]),  # untyped
    lambda p: p["steps"][0].__setitem__("risk", "READ_ONLY"),
    lambda p: p["steps"][0].__setitem__("changes", ["service-start"]),                        # LOW < MEDIUM minimum
    lambda p: p.__setitem__("surprise", 1),                                                   # unknown field
    lambda p: p["provenance"].update(tier="BUILT_IN_VERIFIED", verified_on=[], reviews=[]),  # no live record / review
    lambda p: p["steps"][0].__setitem__("run_on", "every_server"),
    lambda p: p["investigate"][1].__setitem__("check", "shell.run"),
    lambda p: p["verify"].clear(),
])
def test_loader_rejects_unsafe_or_unproven_knowledge(mutation):
    _mutate(mutation)


def test_built_in_verified_requires_every_o10_element():
    cat = _cat()
    proc = next(p for p in cat["procedures"] if p["id"] == "proc.service.start-stopped-service")
    prov = proc["provenance"]
    prov["tier"] = "BUILT_IN_VERIFIED"
    prov["verified_on"] = [{"freeipa": "4.13.3", "os": "fedora-43", "tier": "LIVE", "evidence": "https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36055264033"}]
    prov["reviews"] = []
    with pytest.raises(K.KnowledgeError, match="independent review"):
        K.validate_catalogue(copy.deepcopy(cat))
    prov["reviews"] = [{"by": "fresh reviewer", "date": "2026-09-24", "scope": "procedure", "independent": True}]
    K.validate_catalogue(copy.deepcopy(cat))  # now complete
    prov["sources"] = [{"kind": "blog", "ref": "https://blog.example.test/post"}]
    with pytest.raises(K.KnowledgeError, match="authoritative"):
        K.validate_catalogue(copy.deepcopy(cat))


def test_two_procedures_for_the_same_diagnosis_are_rejected():
    cat = _cat()
    dup = copy.deepcopy(next(p for p in cat["procedures"] if p["id"] == "proc.service.start-stopped-service"))
    dup["id"] = "proc.service.other"
    cat["procedures"].append(dup)
    with pytest.raises(K.KnowledgeError, match="unambiguous"):
        K.validate_catalogue(cat)


def test_invalid_catalogue_fails_closed(monkeypatch):
    monkeypatch.setattr(K, "_CACHE", ([], "procedure catalogue rejected: test"))
    report, _ = report_for([hc("ipahealthcheck.meta.services", "dirsrv", "ERROR", msg="dirsrv: not running")], ROOT_OK)
    assert report.resolutions == {}
    assert any("catalogue rejected" in e for e in report.collection_errors)


def test_strict_yaml_loader_rejects_duplicates_anchors_and_tags(tmp_path):
    pytest.importorskip("yaml")
    import importlib.util

    spec = importlib.util.spec_from_file_location("ck", ROOT / "scripts" / "compile_knowledge.py")
    ck = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ck)
    for text in ("a: 1\na: 2\n", "a: &x 1\nb: *x\n", "a: !!python/object:os.system x\n"):
        p = tmp_path / "k.yaml"
        p.write_text(text, encoding="utf-8")
        with pytest.raises(Exception):
            ck.load_file(p)


# ------------------------------------------------------------------------------------------- service not running

DIRSRV_DOWN = [hc("ipahealthcheck.meta.services", "dirsrv", "ERROR", msg="dirsrv: not running", status=False)]


def unit(state="inactive", load="loaded", method="ipactl", unit_name="dirsrv@LAB-TEST.service"):
    return ok({"unit": unit_name, "start_method": method, "load_state": load, "active_state": state,
               "sub_state": "dead", "unit_file_state": "enabled", "result": "success"}, f"{unit_name}: {state}")


SERVICE_OK = {**ROOT_OK, "systemd.unit|service=dirsrv": unit(), "binary.present|name=ipactl": ok({"present": True}),
              "systemd.journal_tail|unit=dirsrv@LAB-TEST.service": ok({"lines": 3, "last_line": "Stopped"})}


def test_service_procedure_offered_with_exact_command():
    r = res_of(report_for(DIRSRV_DOWN, SERVICE_OK)[0], "healthcheck.service-not-running")
    assert r.status == OFFERED and [s.argv for s in r.steps] == [["systemctl", "start", "dirsrv@LAB-TEST.service"]]
    assert r.rollback[0]["argv"] == ["systemctl", "stop", "dirsrv@LAB-TEST.service"]
    assert r.risk == "MEDIUM" and r.verify and not r.definitive


def test_systemctl_managed_service_uses_its_validated_unit():
    entries = [hc("ipahealthcheck.meta.services", "certmonger", "ERROR", msg="certmonger: not running", status=False)]
    results = {**ROOT_OK, "systemd.unit|service=certmonger": unit(method="systemctl", unit_name="certmonger.service"),
               "binary.present|name=ipactl": ok({"present": True}),
               "systemd.journal_tail|unit=certmonger.service": ok({"lines": 0, "last_line": ""})}
    r = res_of(report_for(entries, results)[0], "healthcheck.service-not-running")
    assert r.status == OFFERED and r.steps[0].argv == ["systemctl", "start", "certmonger.service"]


@pytest.mark.parametrize("override,needle", [
    ({"systemd.unit|service=dirsrv": unit(load="masked")}, "masked"),
    ({"systemd.unit|service=dirsrv": unit(state="active")}, "running now"),
    ({"systemd.unit|service=dirsrv": unit(load="not-found")}, "not a loaded unit"),
    ({"systemd.unit|service=dirsrv": unit(state="activating")}, "activating"),
    ({"systemd.unit|service=dirsrv": (C.NOT_RUN, {}, "systemctl: not installed")}, "Could not"),
    (NOT_ROOT, "prerequisite"),
])
def test_service_procedure_withheld_on_contradiction_or_missing_prerequisite(override, needle):
    r = res_of(report_for(DIRSRV_DOWN, {**SERVICE_OK, **override})[0], "healthcheck.service-not-running")
    assert r.status == WITHHELD and not r.steps
    assert any(needle.lower() in reason.lower() for reason in r.reasons), r.reasons


@pytest.mark.parametrize("env", [
    EnvironmentInfo(distro="fedora", freeipa_version=None),       # version unknown
    EnvironmentInfo(distro="rhel", freeipa_version="4.8.10"),     # older than the procedure's minimum
    None,
])
def test_service_procedure_withheld_when_applicability_not_established(env):
    r = res_of(report_for(DIRSRV_DOWN, SERVICE_OK, env=env)[0], "healthcheck.service-not-running")
    assert r.status == WITHHELD and not r.steps


@pytest.mark.parametrize("name", ["ipa-otpd", "foo", "dirsrv@EVIL", "sshd"])
def test_unknown_or_unsupported_service_gets_no_fix(name):
    entries = [hc("ipahealthcheck.meta.services", name, "ERROR", msg=f"{name}: not running", status=False)]
    r = res_of(report_for(entries, SERVICE_OK)[0], "healthcheck.service-not-running")
    assert r is None or (r.status == WITHHELD and not r.steps)


def test_rhel_version_in_range_is_offered_but_labelled_not_verified_here():
    env = EnvironmentInfo(distro="rhel", distro_version="9.6", freeipa_version="4.12.2-15.el9")
    r = res_of(report_for(DIRSRV_DOWN, SERVICE_OK, env=env)[0], "healthcheck.service-not-running")
    assert r.status == OFFERED and not r.definitive and "Check each step" in r.verification_label


# ------------------------------------------------------------------------------------------- file permissions

CS = "/var/lib/pki/pki-tomcat/conf/ca/CS.cfg"


def perm(path=CS, kind="mode", expected="0660", got="0664", check="TomcatFileCheck"):
    return hc("ipahealthcheck.ipa.files", check, "WARNING", uid=path + kind, key=f"{path}_{kind}", path=path, type=kind,
              expected=expected, got=got, msg=f"Permissions of {path} are too permissive: {got} and should be {expected}")


def stat(mode="0664", owner="pkiuser", group="pkiuser", symlink=False, exists=True, real=None, allowed=True):
    real = real or CS
    if not exists:
        return ok({"exists": False})
    return ok({"exists": True, "is_symlink": symlink, "is_regular": True, "is_dir": False, "mode": mode,
               "owner": owner, "group": group, "mode_a": mode.lstrip("0") or "0", "links": 1, "canonical": True, "realpath": real, "target": real, "realpath_allowed": allowed, "container_data_mirror": False})


def test_file_mode_procedure_offered_with_exact_command_and_rollback():
    r = res_of(report_for([perm()], {**ROOT_OK, f"file.stat|path={CS}": stat()})[0], "directory-server.ipa-file-permissions")
    assert r.status == OFFERED
    assert [s.argv for s in r.steps] == [["chmod", "o-r", CS]]      # removes permissions only
    assert r.rollback[0]["argv"] == ["chmod", "o+r", CS] and r.risk == "LOW"
    assert r.verify[0]["params"] == {"path": CS}


def test_owner_and_group_targets_use_chown_and_chgrp():
    entries = [perm(kind="owner", expected="pkiuser", got="root"), perm(kind="group", expected="pkiuser", got="root")]
    results = {**ROOT_OK, f"file.stat|path={CS}": stat(owner="root", group="root"),
               "account.user|name=pkiuser": ok({"exists": True}), "account.group|name=pkiuser": ok({"exists": True})}
    r = res_of(report_for(entries, results)[0], "directory-server.ipa-file-permissions")
    assert r.status == OFFERED
    assert sorted(s.argv[:2] for s in r.steps) == [["chgrp", "-h"], ["chown", "-h"]]  # never follow a symlink


@pytest.mark.parametrize("entry,stat_result,needle", [
    (perm(expected="one of 0640,0660"), stat(), "not a single value"),
    (perm(), stat(mode="0660"), "already has mode"),
    (perm(), stat(mode="0600"), "changed since"),
    (perm(), stat(symlink=True), "symbolic link"),
    (perm(), stat(exists=False), "no longer exists"),
    (perm(path="/tmp/x"), stat(), "not a single value"),            # outside IPA-managed locations
    (perm(path="/etc/../etc/shadow"), stat(), "not a single value"),
    (perm(path="/etc/ipa/a b"), stat(), "not a single value"),
    (perm(expected="0660; rm -rf /"), stat(), "not a single value"),
])
def test_file_procedure_fails_safe(entry, stat_result, needle):
    path = entry["kw"]["path"]
    r = res_of(report_for([entry], {**ROOT_OK, f"file.stat|path={path}": stat_result})[0], "directory-server.ipa-file-permissions")
    assert r is not None and r.status == WITHHELD and not r.steps
    assert any(needle in x for x in r.reasons), r.reasons


def test_missing_expected_owner_account_withholds_the_fix():
    entries = [perm(kind="owner", expected="pkiuser", got="root")]
    results = {**ROOT_OK, f"file.stat|path={CS}": stat(owner="root"), "account.user|name=pkiuser": ok({"exists": False})}
    r = res_of(report_for(entries, results)[0], "directory-server.ipa-file-permissions")
    assert r.status == WITHHELD and not r.steps


def test_one_bad_target_is_dropped_and_the_good_one_still_fixed():
    other = "/etc/ipa/default.conf"
    entries = [perm(), perm(path=other, expected="0640", got="0644", check="IPAFileCheck")]
    results = {**ROOT_OK, f"file.stat|path={CS}": stat(mode="0660"), f"file.stat|path={other}": stat(mode="0644", real=other)}
    r = res_of(report_for(entries, results)[0], "directory-server.ipa-file-permissions")
    assert r.status == OFFERED and [s.argv for s in r.steps] == [["chmod", "o-r", other]]
    assert any("already has mode" in x for x in r.reasons)


@pytest.mark.parametrize("entry", [
    hc("ipahealthcheck.ipa.files", "IPAFileCheck", "WARNING", type="umask", expected="0o022", got="0o027",
       msg="Unexpected umask 0o027 expected 0o022, skipping file permissions."),
    hc("ipahealthcheck.ipa.files", "IPAFileCheck", "WARNING", key="k", path=CS, type="owner", expected="pkiuser",
       got="Unknown uid 1234"),
])
def test_file_look_alikes_never_get_a_fix(entry):
    r = res_of(report_for([entry], {**ROOT_OK})[0], "directory-server.ipa-file-permissions")
    assert r is None or (r.status == WITHHELD and not r.steps)


# ------------------------------------------------------------------------------------------- clock skew

KEYTAB_SKEW = [hc("ipahealthcheck.ipa.host", "IPAHostKeytab", "ERROR", msg="Failed to obtain host TGT: Clock skew too great")]
DESYNC = [EvidenceItem(item_id="clk", kind="clock_sync", summary="c", data={"method": "chronyc", "ntp_synchronized": True, "offset_seconds": 421.2})]
CHRONY_OK = {**ROOT_OK,
             "systemd.unit|service=chronyd": unit(state="active", method="systemctl", unit_name="chronyd.service"),
             "chrony.tracking|": ok({"offset_seconds": 421.2, "offset_abs": 421.2, "direction": "ahead of", "leap_status": "Normal",
                                     "synchronized": True, "reference": "10.0.0.5"}),
             "chrony.sources|": ok({"total": 2, "reachable": 2})}


def test_clock_procedure_offered_with_admin_confirmation():
    r = res_of(report_for(KEYTAB_SKEW, CHRONY_OK, items=DESYNC)[0], "kerberos.clock-skew")
    assert r.status == OFFERED and r.steps[0].argv == ["chronyc", "makestep"]
    assert any(p.state == "confirm" for p in r.prerequisites)


@pytest.mark.parametrize("override,needle", [
    ({"chrony.tracking|": ok({"offset_seconds": 0.02, "offset_abs": 0.02, "direction": "ahead of", "leap_status": "Normal", "synchronized": True, "reference": "x"})}, "300 s tolerance"),
    ({"chrony.tracking|": ok({"offset_seconds": 0.02, "offset_abs": 0.02, "direction": "ahead of", "leap_status": "Not synchronised", "synchronized": False, "reference": ""})}, "300 s tolerance"),
    ({"chrony.tracking|": ok({"offset_seconds": 421.2, "offset_abs": 421.2, "direction": "ahead of", "leap_status": "Not synchronised", "synchronized": False, "reference": "10.0.0.5"})}, "has not synchronized"),
    ({"chrony.tracking|": ok({"offset_seconds": 421.2, "offset_abs": 421.2, "direction": "ahead of", "leap_status": "Normal", "synchronized": True, "reference": ""})}, "no reference"),
    ({"chrony.tracking|": ok({"offset_seconds": -31536000.0, "offset_abs": 31536000.0, "direction": "behind", "leap_status": "Normal", "synchronized": True, "reference": "10.0.0.5"})}, "more than a day"),
    ({"chrony.sources|": ok({"total": 2, "reachable": 0})}, "No time source"),
    ({"systemd.unit|service=chronyd": unit(state="inactive", method="systemctl", unit_name="chronyd.service")}, "not running"),
    ({"chrony.tracking|": (C.NOT_RUN, {}, "chronyc: not installed")}, "Could not"),
])
def test_clock_procedure_fails_safe(override, needle):
    r = res_of(report_for(KEYTAB_SKEW, {**CHRONY_OK, **override}, items=DESYNC)[0], "kerberos.clock-skew")
    assert r.status == WITHHELD and not r.steps and any(needle in x for x in r.reasons), r.reasons


def test_kdc_reported_skew_without_local_desync_gets_no_fix():
    journal = [EvidenceItem(item_id="kj", kind="krb5kdc_journal_line", summary="skew",
                            data={"matched_pattern": "clock_skew", "message": "CLOCK_SKEW"})]
    entries = [hc("ipahealthcheck.ipa.host", "IPAHostKeytab", "ERROR", msg="Failed to obtain host TGT: Clock skew too great")]
    r = res_of(report_for(entries, CHRONY_OK, items=journal)[0], "kerberos.clock-skew")
    assert r is not None and r.status == NONE and not r.steps


# ------------------------------------------------------------------------------------------- DS certificate

def nss(key="DSCERTLE0001", nick="Server-Cert", verb="will expire in less than 30 days", uid="n"):
    return hc("ipahealthcheck.ds.nss_ssl", "NssCheck", "ERROR", uid=uid, key=key, items=["x"], msg=f"The certificate ({nick}) {verb}")


def cert(**over):
    f = {"found": True, "request_id": "20260101120000", "state": "MONITORING", "ca": "IPA", "ca_error": "",
         "not_after": "x", "days_left": 12, "post_save_restarts_dirsrv": True, "profile": "caIPAserviceCert"}
    f.update(over)
    return ok(f)


DS_OK = {**ROOT_OK, "ds.instance|": ok({"count": 1, "instance": "LAB-TEST"}),
         "systemd.unit|service=certmonger": unit(state="active", method="systemctl", unit_name="certmonger.service"),
         "certmonger.ds_cert|instance=LAB-TEST,nickname=Server-Cert": cert(),
         "binary.present|name=getcert": ok({"present": True})}


def test_ds_certificate_expiring_offers_resubmit_of_the_tracked_request():
    r = res_of(report_for([nss()], DS_OK)[0], "directory-server.certificate-expiry")
    assert r.status == OFFERED and r.steps[0].argv == ["getcert", "resubmit", "-i", "20260101120000"]


def test_expired_ds_certificate_gets_no_invented_fix():
    r = res_of(report_for([nss(key="DSCERTLE0002", verb="has expired")], DS_OK)[0], "directory-server.certificate-expiry")
    assert r.status == NONE and not r.steps and r.reference and "ipa-cert-fix" in r.reasons[0]


@pytest.mark.parametrize("override,needle", [
    ({"certmonger.ds_cert|instance=LAB-TEST,nickname=Server-Cert": cert(days_left=-1)}, "already expired"),
    ({"certmonger.ds_cert|instance=LAB-TEST,nickname=Server-Cert": cert(state="CA_UNREACHABLE")}, "CA_UNREACHABLE"),
    ({"certmonger.ds_cert|instance=LAB-TEST,nickname=Server-Cert": cert(ca_error="Server at https://ipa01/ipa/xml denied")}, "reports an error"),
    ({"certmonger.ds_cert|instance=LAB-TEST,nickname=Server-Cert": cert(days_left=700)}, "probably been renewed"),
    ({"certmonger.ds_cert|instance=LAB-TEST,nickname=Server-Cert": cert(ca="external")}, "not the IPA CA"),
    ({"certmonger.ds_cert|instance=LAB-TEST,nickname=Server-Cert": ok({"found": False})}, "does not track"),
    ({"certmonger.ds_cert|instance=LAB-TEST,nickname=Server-Cert": cert(post_save_restarts_dirsrv=False)}, "does not restart"),
    ({"ds.instance|": ok({"count": 2, "instance": None})}, "2 Directory Server instances"),
    ({"systemd.unit|service=certmonger": unit(state="inactive", method="systemctl", unit_name="certmonger.service")}, "certmonger is not running"),
])
def test_ds_certificate_procedure_fails_safe(override, needle):
    r = res_of(report_for([nss()], {**DS_OK, **override})[0], "directory-server.certificate-expiry")
    assert r.status == WITHHELD and not r.steps and any(needle in x for x in r.reasons), r.reasons


@pytest.mark.parametrize("entries", [
    [nss(key="SOMETHING-ELSE")],                                        # text says "will expire" but not lib389's key
    [nss(nick="Server-Cert; rm -rf /")],                                # hostile nickname
    [nss(uid="a"), nss(nick="CA-Cert", uid="b")],                       # two certificates: ambiguous
])
def test_ds_certificate_look_alikes_get_no_fix(entries):
    r = res_of(report_for(entries, DS_OK)[0], "directory-server.certificate-expiry")
    assert r is None or (r.status in (WITHHELD, NONE) and not r.steps)


def test_nss_db_format_and_other_diagnoses_never_get_a_procedure():
    """Only the four keyed conditions can ever carry a procedure."""

    keys = set()
    for fixture in sorted((ROOT / "tests" / "fixtures").rglob("healthcheck.json")):
        from ipa_diagnose.evidence.collect import collect_evidence

        report = run_diagnosis(collect_evidence(replay_dir=str(fixture.parent)))
        resolve_report(report, C.ReplayRunner(str(fixture.parent)))
        for d in report.diagnoses:
            if d.diagnosis_id in report.resolutions:
                keys.add(d.resolution_key)
    assert keys <= {"healthcheck.service-not-running", "directory-server.ipa-file-permissions",
                    "kerberos.clock-skew", "directory-server.certificate-expiry"}


def test_low_confidence_diagnosis_never_gets_a_procedure():
    d = Diagnosis(pack_id="healthcheck", rule_id="x", status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
                  title="t", why="w", confidence=Confidence(ConfidenceLevel.LOW, "r"), next_diagnostic_step="s",
                  resolution_key="healthcheck.service-not-running", bindings={"service": "dirsrv"})
    from ipa_diagnose.resolution.engine import resolve_diagnosis

    r = resolve_diagnosis(d, ENV, FakeRunner(SERVICE_OK))
    assert r.status == WITHHELD and not r.steps


# ------------------------------------------------------------------------------------------- rendering + JSON

ORDER = ["ROOT CAUSE", "WHY", "CHECKED FOR YOU", "IMPACT", "FIX", "PREREQUISITES", "WHAT THIS CHANGES", "RISK",
         "ROLLBACK", "VERIFY"]


def _render(report, details=False):
    buf = io.StringIO()
    render_report(report, Console(file=buf, width=200, force_terminal=False, color_system=None), details=details)
    return buf.getvalue()


@pytest.mark.parametrize("entries,results,items", [
    (DIRSRV_DOWN, SERVICE_OK, ()), ([perm()], {**ROOT_OK, f"file.stat|path={CS}": stat()}, ()),
    (KEYTAB_SKEW, CHRONY_OK, DESYNC), ([nss()], DS_OK, ()),
])
def test_contract_sections_render_in_the_required_order(entries, results, items):
    out = _render(report_for(entries, results, items=items)[0])
    positions = [out.find("\n" + h + "\n") for h in ORDER]
    assert all(p >= 0 for p in positions), [h for h, p in zip(ORDER, positions) if p < 0]
    assert positions == sorted(positions)


def test_withheld_fix_shows_reasons_and_no_state_changing_legacy_command():
    report, _ = report_for([perm()], {**ROOT_OK, f"file.stat|path={CS}": stat(mode="0660")})
    out = _render(report)
    assert "No fix is shown" in out and "already has mode" in out
    assert "chmod" not in out and "chown <expected-owner>" not in out


def test_json_v2_carries_the_resolution_and_v1_is_untouched():
    report, _ = report_for(DIRSRV_DOWN, SERVICE_OK)
    data = report_to_dict(report)
    assert data["report_schema_version"] == 2
    res = data["v2"]["resolutions"][0]
    assert res["status"] == "OFFERED" and res["steps"][0]["argv"] == ["systemctl", "start", "dirsrv@LAB-TEST.service"]
    assert all(c["source"] == "live" for c in res["checked"])
    assert {"diagnoses", "overall_status", "undiagnosed_findings"} <= set(data)
    assert all(set(d) == set(data["diagnoses"][0]) for d in data["diagnoses"])  # no new keys inside v1 diagnoses
    json.dumps(data)


def test_hostile_check_output_is_sanitized_in_console_and_json():
    evil = "\x1b]0;pwn\x07[bold red]X[/bold red] ‮$(reboot)"
    results = {**SERVICE_OK, "systemd.journal_tail|unit=dirsrv@LAB-TEST.service": ok({"lines": 1, "last_line": evil}, evil)}
    report, _ = report_for(DIRSRV_DOWN, results)
    out = _render(report)
    assert "\x1b" not in out and "‮" not in out and "[bold red]X" in out  # markup shown literally, not applied
    assert "\x1b" not in json.dumps(report_to_dict(report))


# ------------------------------------------------------------------------------------------- verify


def _previous(report):
    return json.loads(json.dumps(report_to_dict(report)))


def test_verify_resolved_only_when_the_fix_criteria_pass_with_fresh_checks():
    from ipa_diagnose.verify import VerifyOutcome, compare

    before, _ = report_for(DIRSRV_DOWN, SERVICE_OK)
    after, _ = report_for([], SERVICE_OK)
    for runner_results, outcome in [
        ({"systemd.unit|service=dirsrv": unit(state="active")}, VerifyOutcome.RESOLVED),
        ({"systemd.unit|service=dirsrv": unit(state="inactive")}, VerifyOutcome.PARTIALLY_RESOLVED),
        ({}, VerifyOutcome.UNABLE_TO_VERIFY),
    ]:
        result = compare(_previous(before), after, runner=FakeRunner(runner_results))
        item = next(i for i in result.items if i.diagnosis_id.startswith("healthcheck.service-not-running"))
        assert item.outcome == outcome, (runner_results, item)


def test_verify_still_present_is_not_affected_by_criteria():
    from ipa_diagnose.verify import VerifyOutcome, compare

    before, _ = report_for(DIRSRV_DOWN, SERVICE_OK)
    result = compare(_previous(before), before, runner=FakeRunner({"systemd.unit|service=dirsrv": unit(state="active")}))
    assert all(i.outcome == VerifyOutcome.STILL_PRESENT for i in result.items)


def test_verify_criteria_from_a_tampered_state_file_cannot_run_anything_unexpected():
    criteria = [{"text": "x", "check": "shell.run", "params": {"cmd": "reboot"}, "when": {"left": 1, "op": "eq", "right": 1}},
                {"text": "y", "check": "file.stat", "params": {"path": "/etc/../etc/shadow"},
                 "when": {"left": {"ref": "this", "field": "mode"}, "op": "eq", "right": "0000"}},
                "garbage"]
    runner = FakeRunner({})
    results = evaluate_verify(criteria, runner)
    assert [ok_ for _, ok_, _ in results] == [None, None, None]
    assert runner.calls == []


# ------------------------------------------------------------------------------------------- review findings (Slice 1)


@pytest.mark.parametrize("entry,needle", [
    (perm(path="/etc/shadow", expected="0000", got="0640"), "not a single value"),              # outside IPA locations
    (perm(expected="0666", got="0664"), "would ADD permissions"),                                # loosening
    (perm(expected="0644", got="0600"), "would ADD permissions"),
])
def test_file_fix_never_touches_non_ipa_files_or_adds_permissions(entry, needle):
    path = entry["kw"]["path"]
    r = res_of(report_for([entry], {**ROOT_OK, f"file.stat|path={path}": stat(mode=entry["kw"]["got"])})[0],
               "directory-server.ipa-file-permissions")
    assert r.status == WITHHELD and not r.steps and any(needle in x for x in r.reasons), r.reasons


def test_conflicting_results_for_one_file_are_never_both_applied():
    entries = [perm(expected="0640", got="0664"), dict(perm(expected="0600", got="0664"), uuid="other")]
    r = res_of(report_for(entries, {**ROOT_OK, f"file.stat|path={CS}": stat()})[0], "directory-server.ipa-file-permissions")
    assert r.status == WITHHELD and not r.steps and any("conflicting" in x for x in r.reasons), r.reasons


@pytest.mark.parametrize("path,expected", [
    ("/var/lib/ipa/private/kdc.key", "apache"),     # key material
    ("/etc/ipa/default.conf", "nobody"),            # not an IPA service account
])
def test_ownership_of_key_material_or_to_non_ipa_accounts_is_never_offered(path, expected):
    entry = perm(path=path, kind="owner", expected=expected, got="root")
    results = {**ROOT_OK, f"file.stat|path={path}": stat(owner="root"), f"account.user|name={expected}": ok({"exists": True})}
    r = res_of(report_for([entry], results)[0], "directory-server.ipa-file-permissions")
    assert r.status == WITHHELD and not r.steps


def test_symlinked_parent_resolving_inside_ipa_locations_acts_on_the_real_path():
    # Real FreeIPA layout, found in the live lab: /var/lib/pki/pki-tomcat/conf -> /etc/pki/pki-tomcat
    real = "/etc/pki/pki-tomcat/ca/CS.cfg"
    r = res_of(report_for([perm()], {**ROOT_OK, f"file.stat|path={CS}": stat(real=real)})[0], "directory-server.ipa-file-permissions")
    assert r.status == OFFERED and r.steps[0].argv == ["chmod", "o-r", real]
    assert r.verify[0]["params"] == {"path": real}


def test_symlinked_parent_resolving_outside_ipa_locations_withholds_the_fix():
    r = res_of(report_for([perm()], {**ROOT_OK, f"file.stat|path={CS}": stat(real="/etc/shadow", allowed=False)})[0],
               "directory-server.ipa-file-permissions")
    assert r.status == WITHHELD and not r.steps and any("outside IPA-managed locations" in x for x in r.reasons)


def test_container_data_mirror_acts_on_the_standard_ipa_path():
    # freeipa-container layout, found in the live lab: /etc/pki -> /data/etc/pki
    data = "/data/etc/pki/pki-tomcat/ca/CS.cfg"
    std = "/etc/pki/pki-tomcat/ca/CS.cfg"
    st = stat(real=data)
    st[1].update({"target": std, "container_data_mirror": True})
    r = res_of(report_for([perm()], {**ROOT_OK, f"file.stat|path={CS}": st})[0], "directory-server.ipa-file-permissions")
    assert r.status == OFFERED and r.steps[0].argv == ["chmod", "o-r", std]
    assert r.verify[0]["params"] == {"path": std}


@pytest.mark.parametrize("real,resolves,expect", [
    ("/etc/pki/pki-tomcat/ca/CS.cfg", {}, ("/etc/pki/pki-tomcat/ca/CS.cfg", True, False)),
    ("/data/etc/pki/pki-tomcat/ca/CS.cfg", {"/etc/pki/pki-tomcat/ca/CS.cfg": "/data/etc/pki/pki-tomcat/ca/CS.cfg"},
     ("/etc/pki/pki-tomcat/ca/CS.cfg", True, True)),
    # the standard path does not lead to this file: refused
    ("/data/etc/pki/pki-tomcat/ca/CS.cfg", {"/etc/pki/pki-tomcat/ca/CS.cfg": "/etc/pki/pki-tomcat/ca/CS.cfg"},
     ("/data/etc/pki/pki-tomcat/ca/CS.cfg", False, False)),
    # a /data file whose standard path is not IPA-managed: refused
    ("/data/etc/shadow", {"/etc/shadow": "/data/etc/shadow"}, ("/data/etc/shadow", False, False)),
    ("/data/../etc/shadow", {}, ("/data/../etc/shadow", False, False)),
    ("/etc/shadow", {}, ("/etc/shadow", False, False)),
    ("/datax/etc/pki/pki-tomcat/ca/CS.cfg", {}, ("/datax/etc/pki/pki-tomcat/ca/CS.cfg", False, False)),
])
def test_command_target_only_follows_the_verified_container_mirror(monkeypatch, real, resolves, expect):
    monkeypatch.setattr(C.os.path, "realpath", lambda p: resolves.get(p, p))
    assert C._command_target(real) == expect


def test_disabled_systemctl_unit_is_not_started_but_failed_ipa_unit_is_offered_scoped():
    entries = [hc("ipahealthcheck.meta.services", "sssd", "ERROR", msg="sssd: not running", status=False)]
    dis = ok({"unit": "sssd.service", "start_method": "systemctl", "load_state": "loaded", "active_state": "inactive",
              "sub_state": "dead", "unit_file_state": "disabled", "result": "success"})
    r = res_of(report_for(entries, {**ROOT_OK, "systemd.unit|service=sssd": dis})[0], "healthcheck.service-not-running")
    assert r.status == WITHHELD and any("disabled" in x for x in r.reasons)
    failed = ok({"unit": "dirsrv@LAB-TEST.service", "start_method": "ipactl", "load_state": "loaded", "active_state": "failed",
                 "sub_state": "failed", "unit_file_state": "disabled", "result": "exit-code"})
    r2 = res_of(report_for(DIRSRV_DOWN, {**SERVICE_OK, "systemd.unit|service=dirsrv": failed})[0], "healthcheck.service-not-running")
    assert r2.status == OFFERED and r2.steps[0].argv == ["systemctl", "start", "dirsrv@LAB-TEST.service"]


@pytest.mark.parametrize("version", ["10.0.1", "5.0.0-1.fc50", "4.9garbage", "v4.13"])
def test_unknown_future_or_malformed_versions_withhold(version):
    env = EnvironmentInfo(distro="fedora", freeipa_version=version)
    r = res_of(report_for(DIRSRV_DOWN, SERVICE_OK, env=env)[0], "healthcheck.service-not-running")
    assert r.status == WITHHELD and not r.steps


@pytest.mark.parametrize("criterion", [
    {"text": "x", "check": "file.stat", "params": {"path": CS}, "when": {"all": [], "any": [{"left": {"ref": "this", "field": "mode"}, "op": "eq", "right": "0"}]}},
    {"text": "x", "check": "file.stat", "params": {"path": CS}, "when": {"left": {"ref": "this", "field": "mode"}, "op": "eq", "right": {"ref": "this", "field": "mode"}}},
    {"text": "x", "check": "file.stat", "params": ["abc"], "when": {"left": {"ref": "this", "field": "mode"}, "op": "eq", "right": "0660"}},
    {"text": "x", "check": "file.stat", "params": {"path": CS}, "when": {"left": {"ref": "this", "field": "mode"}, "op": "is_empty", "right": 1}},
])
def test_tampered_verify_criteria_never_pass_or_crash(criterion):
    runner = FakeRunner({f"file.stat|path={CS}": stat(mode="0660")})
    assert [ok_ for _, ok_, _ in evaluate_verify([criterion], runner)] == [None]


def test_runtime_loader_rejects_duplicate_json_keys():
    with pytest.raises(K.KnowledgeError):
        json.loads('{"a": 1, "a": 2}', object_pairs_hook=K._no_duplicate_keys)


def test_yaml_compiler_rejects_explicit_safe_tags_too(tmp_path):
    pytest.importorskip("yaml")
    import importlib.util

    spec = importlib.util.spec_from_file_location("ck", ROOT / "scripts" / "compile_knowledge.py")
    ck = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ck)
    p = tmp_path / "k.yaml"
    p.write_text("a: !!str 5\n", encoding="utf-8")
    with pytest.raises(ValueError):
        ck.load_file(p)


def test_replayed_check_results_are_labelled_as_recorded():
    from ipa_diagnose.evidence.collect import collect_evidence

    fx = ROOT / "tests" / "fixtures" / "resolution" / "file-permissions"
    report = run_diagnosis(collect_evidence(replay_dir=str(fx)))
    resolve_report(report, C.ReplayRunner(str(fx)))
    out = _render(report)
    assert "recorded in this replay fixture (not run now)" in out
    assert all(c["source"] == "recorded" for c in report_to_dict(report)["v2"]["resolutions"][0]["checked"])


def test_display_command_is_shell_quoted():
    from ipa_diagnose.resolution.engine import Step

    assert Step("s", "t", ["getcert", "list", "-n", "Server Cert"], "LOW", [], "", "local").command == "getcert list -n 'Server Cert'"


def test_local_offset_inside_kerberos_tolerance_gets_no_clock_fix():
    """Round-2 review: a 2 s local offset cannot cause 'Clock skew too great' (300 s tolerance)."""
    small = [EvidenceItem(item_id="clk", kind="clock_sync", summary="c", data={"method": "chronyc", "ntp_synchronized": False, "offset_seconds": 2.0})]
    results = {**CHRONY_OK, "chrony.tracking|": ok({"offset_seconds": 2.0, "offset_abs": 2.0, "direction": "ahead of",
                                                     "leap_status": "Normal", "synchronized": True, "reference": "10.0.0.5"})}
    r = res_of(report_for(KEYTAB_SKEW, results, items=small)[0], "kerberos.clock-skew")
    # A 2 s local offset is not evidence of local skew: the diagnosis is "KDC-reported skew" (no deterministic
    # fix - the wrong clock may be elsewhere), never the local clock fix.
    assert r.status == NONE and not r.steps and r.procedure_id == "none.time.kdc-reported-skew"


def test_clock_procedure_withholds_below_the_window_when_it_does_apply():
    """The procedure's own 240 s gate still holds when the diagnosis rests on a big measured offset that has
    since become small (checked fresh)."""
    big = [EvidenceItem(item_id="clk", kind="clock_sync", summary="c", data={"method": "chronyc", "ntp_synchronized": False, "offset_seconds": 421.0})]
    results = {**CHRONY_OK, "chrony.tracking|": ok({"offset_seconds": 2.0, "offset_abs": 2.0, "direction": "ahead of",
                                                     "leap_status": "Normal", "synchronized": True, "reference": "10.0.0.5"})}
    r = res_of(report_for(KEYTAB_SKEW, results, items=big)[0], "kerberos.clock-skew")
    assert r.status == WITHHELD and not r.steps and any("300 s tolerance" in x for x in r.reasons)


@pytest.mark.parametrize("name", ["named", "named-pkcs11"])
def test_named_is_never_given_a_start_command(name):
    entries = [hc("ipahealthcheck.meta.services", name, "ERROR", msg=f"{name}: not running", status=False)]
    r = res_of(report_for(entries, SERVICE_OK)[0], "healthcheck.service-not-running")
    assert r is None or not r.steps


@pytest.mark.parametrize("path", ["/etc/dirsrv/slapd-LAB-TEST/key4.db", "/etc/pki/pki-tomcat/password.conf",
                                  "/var/kerberos/krb5kdc/.k5.LAB.TEST", "/etc/ipa/custodia/server.keys"])
def test_ownership_of_key_databases_and_stash_files_is_never_offered(path):
    entry = perm(path=path, kind="owner", expected="dirsrv", got="root")
    results = {**ROOT_OK, f"file.stat|path={path}": stat(owner="root", real=path), "account.user|name=dirsrv": ok({"exists": True})}
    r = res_of(report_for([entry], results)[0], "directory-server.ipa-file-permissions")
    assert r.status == WITHHELD and not r.steps


def test_ownership_rollback_never_hands_a_file_to_a_non_ipa_account():
    entry = perm(kind="owner", expected="pkiuser", got="nobody")
    results = {**ROOT_OK, f"file.stat|path={CS}": stat(owner="nobody"), "account.user|name=pkiuser": ok({"exists": True})}
    r = res_of(report_for([entry], results)[0], "directory-server.ipa-file-permissions")
    assert r.status == WITHHELD and not r.steps


def test_unrelated_log_files_are_not_touched():
    path = "/var/log/secure"
    r = res_of(report_for([perm(path=path, expected="0600", got="0640")], {**ROOT_OK, f"file.stat|path={path}": stat(mode="0640", real=path)})[0],
               "directory-server.ipa-file-permissions")
    assert r.status == WITHHELD and not r.steps
