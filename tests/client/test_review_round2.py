"""Regressions for the Slice 4 review round 2 (focused re-review + security/privacy review)."""

from __future__ import annotations

import json
import os

import pytest

from ipa_diagnose.cli import main
from ipa_diagnose.client import verify as V
from ipa_diagnose.resolution import client_checks as C
from tests.access.helpers import World
from tests.client import helpers as H
from tests.client import scenarios as S
from tests.client.scenarios import DOMAIN, PRINCIPAL, key


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    return tmp_path


# ---- BLOCKER (focused re-review): a failed SRV query is never reported as missing records
@pytest.mark.parametrize("rcode", ["TIMEOUT", "SERVFAIL"])
def test_srv_query_failure_is_never_called_missing(rcode):
    def m(d):
        for n in (f"_ldap._tcp.{DOMAIN}", f"_kerberos._tcp.{DOMAIN}"):
            d[key("dns.srv", name=n)]["fields"].update(rcode=rcode, answers=[], found=False)
        d[key("krb.host_kinit", principal=PRINCIPAL)]["fields"].update(ok=False, error_class="kdc_unresolvable")

    r = H.run("healthy", mutate=m)
    c = H.codes(r)
    assert "DNS_SRV_MISSING" not in c
    assert c.get("DNS_SRV_QUERY_FAILED") == "PRIMARY"
    d = next(x for x in r.diagnoses if x.code == "KDC_NOT_RESOLVABLE")
    assert d.confidence == "MEDIUM" and d.related_to == "DNS_SRV_QUERY_FAILED"
    assert "records are missing" not in d.detail


# ---- MINOR (focused re-review): missing SRV with sssd.conf unreadable is not HIGH
def test_missing_srv_with_unreadable_sssd_conf_is_not_high():
    def m(d):
        S.srv_missing_fixed_fallback(d)
        d[key("sssd.conf")] = S.ok({}, "permission denied", status="DENIED")
        d[key("krb.host_kinit", principal=PRINCIPAL)]["fields"].update(ok=False, error_class="kdc_unresolvable")

    r = H.run("healthy", mutate=m)
    assert next(x for x in r.diagnoses if x.code == "KDC_NOT_RESOLVABLE").confidence != "HIGH"


# ---- BLOCKER (security review): the client state file is never written or read through a symlink
def test_state_save_never_follows_a_symlink(state, tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("original")
    path = V.state_path(False)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(victim, path)
    V.save(path, H.run("sssd-stopped"))
    assert victim.read_text() == "original"
    with pytest.raises(V.UnreadableState):
        V.load(path)
    os.unlink(path)
    tmpname = path.with_name(path.name + ".tmp")
    os.symlink(victim, tmpname)  # the old fixed temporary name, planted: must not matter
    V.save(path, H.run("sssd-stopped"))
    assert victim.read_text() == "original"
    assert V.load(path)["diagnoses"]


# ---- MINOR (security review): SSSD log read never follows a symlink
def test_sssd_log_is_never_read_through_a_symlink(monkeypatch, tmp_path):
    secret = tmp_path / "rootsecret"
    secret.write_text("ldb_connect failed: Input/output error key CANARYKEY2\n")
    logs = tmp_path / "logs"
    logs.mkdir()
    os.symlink(secret, logs / "sssd_lab.test.log")
    monkeypatch.setattr(C, "SSSD_LOG_DIR", str(logs))
    monkeypatch.setattr(C, "_is_root", lambda: True)
    monkeypatch.setattr(C, "_run", lambda argv, timeout=15: (1, "", ""))
    r = C._log_signals({"domain": "lab.test"})
    assert r.fields["counts"] == {} and "CANARYKEY2" not in repr(r.fields)


def test_cache_file_symlink_is_reported_not_followed(monkeypatch, tmp_path):
    target = tmp_path / "elsewhere"
    target.write_bytes(b"x" * 100)
    os.symlink(target, tmp_path / "cache_lab.test.ldb")
    monkeypatch.setattr(C, "SSS_DB", str(tmp_path))
    r = C._cache_files({"domain": "lab.test"})
    assert r.fields.get("not_regular") is True and r.fields["size"] == 0


# ---- MINOR (security review): user-checks error text never carries the NSS block (GECOS, home)
def test_user_checks_error_never_carries_the_nss_block(monkeypatch):
    monkeypatch.setattr(C, "_is_root", lambda: True)
    out = "SSSD nss user lookup result:\n - user name: alice\n - gecos: Alice Private Name\n - home directory: /home/a\n"
    monkeypatch.setattr(C, "_run", lambda argv, timeout=45: (1, out, ""))
    r = C._user_checks({"user": "alice", "service": "sshd"})
    assert "Private Name" not in repr(r.fields) and "/home/a" not in repr(r.fields)


# ---- MINOR (security review): poisoned replay types never crash and never produce a fix
@pytest.mark.parametrize("check,field,value", [
    ("client.ipa_conf", "realm", True), ("sssd.conf", "ipa_hostname", True), ("ipa.https", "offset_seconds", 10**40),
    ("krb.keytab", "principals", True), ("krb.keytab", "kvnos", True), ("client.versions", "sssd", True),
    ("dns.resolvers", "nameservers", True), ("sssd.conf", "ipa_server", True)])
def test_poisoned_replay_types_never_crash(check, field, value):
    k = next(x for x in S.healthy() if x.split("|")[0] == check)

    def m(d):
        d[k]["fields"][field] = value

    r = H.run("healthy", mutate=m)
    assert r.status in ("NOT_FULLY_VERIFIED", "PROBLEM_FOUND", "HEALTHY", "HEALTHY_WITH_WARNINGS")
    assert not H.offered(r)


# ---- MINOR (security review): access --runtime discloses the side effects of its checks
def test_runtime_steps_disclose_side_effects(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    d = tmp_path / "fx"
    H.write_checks(H.scenario("healthy"), directory=d)
    w = World().user("alice").host(S.HOST).service("sshd")
    w.rule("r1", users=["alice"], hosts=[S.HOST], services=["sshd"])
    w.write(d, "alice", S.HOST, "sshd")
    main(["access", "alice", S.HOST, "sshd", "--replay", str(d), "--json", "--runtime"])
    doc = json.loads(capsys.readouterr().out)
    steps = {s["step"]: s for s in doc["runtime_access"]["client"]["steps"]}
    assert steps["krb"]["side_effects"] != "none"
    main(["access", "alice", S.HOST, "sshd", "--replay", str(d), "--runtime", "--details"])
    assert "Kerberos AS request" in capsys.readouterr().out


# ---- MINOR (security review): the host-identity API call does not inherit root's environment
def test_host_identity_api_uses_a_minimal_environment(monkeypatch):
    from ipa_diagnose.access import api

    monkeypatch.setenv("SSLKEYLOGFILE", "/tmp/keys")
    monkeypatch.setenv("https_proxy", "http://evil:3128")
    monkeypatch.setattr(api, "read_ipa_conf", lambda path: {})
    a = api.LiveApi(ccache="FILE:/tmp/x/cc")
    assert "SSLKEYLOGFILE" not in a._env and "https_proxy" not in a._env and a._env["KRB5CCNAME"] == "FILE:/tmp/x/cc"


# ---- BLOCKER (fresh-user review): a broken ONLINE authentication path is not "the login will fail"
@pytest.mark.parametrize("scenario", ["dns-failure", "time-skew", "keytab-mismatch", "server-unreachable",
                                      "kdc-unreachable", "host-entry-missing", "ca-untrusted"])
def test_auth_path_failures_do_not_claim_runtime_failure(scenario):
    r = H.run(scenario)
    assert r.runtime.state == "NOT_VERIFIED" and r.authentication.state == "FAIL"
    assert "cached credentials or SSH keys may still log in" in r.runtime.summary


def test_auth_path_failure_with_hbac_pass_is_not_exit_5(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    d = tmp_path / "fx"
    H.write_checks(H.scenario("dns-failure"), directory=d)
    w = World().user("alice").host(S.HOST).service("sshd")
    w.rule("r1", users=["alice"], hosts=[S.HOST], services=["sshd"])
    w.write(d, "alice", S.HOST, "sshd")
    code = main(["access", "alice", S.HOST, "sshd", "--replay", str(d), "--json", "--runtime"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 0 and doc["runtime_access"]["state"] == "NOT_VERIFIED"


def test_identity_failure_while_offline_is_still_a_runtime_failure():
    r = H.run("sssd-offline-unexplained")
    assert r.runtime.state == "FAIL"


# ---- live run 4 (C13): consequences of an offline SSSD are RELATED, not independent causes
def test_account_denial_while_offline_is_related_not_independent():
    def m(d):
        S.dns_down(d)
        S.pam_denied(d)

    r = H.run("healthy", mutate=m)
    c = H.codes(r)
    assert c.get("RUNTIME_ACCOUNT_DENIED") == "RELATED"
    assert next(x for x in r.diagnoses if x.code == "RUNTIME_ACCOUNT_DENIED").confidence == "MEDIUM"


def test_new_mit_wording_for_unresolvable_kdc_is_classified():
    assert C._classify_kinit("kinit: Cannot resolve servers for KDC in realm \"LAB.TEST\" while getting initial "
                             "credentials") == "kdc_unresolvable"


def test_unclassified_kerberos_error_under_a_dns_failure_is_related():
    def m(d):
        S.dns_down(d)
        d[key("krb.host_kinit", principal=PRINCIPAL)]["fields"].update(error_class="other")

    r = H.run("healthy", mutate=m)
    assert H.codes(r).get("KERBEROS_FAILED") == "RELATED"


# ---- focused re-review (round 3b): an online-path failure never vanishes from both verdicts
@pytest.mark.parametrize("mutation", ["offline", "ldap", "srv_only", "keytab_unreadable"])
def test_online_path_failures_always_fail_authentication(mutation):
    def m(d):
        dom = key("sssd.domain_status", domain=DOMAIN)
        d[dom]["fields"].update(online=False)
        d[key("sssd.log_signals", domain=DOMAIN)]["fields"].update(counts={"offline": 3})
        if mutation == "ldap":
            d[key("net.tcp", host=S.SERVER, port="389")]["fields"].update(state="timeout", open=False)
        if mutation == "srv_only":
            d[key("sssd.conf")]["fields"].update(ipa_server=["_srv_"], uses_srv=True)
            S.srv_missing_fixed_fallback(d)
        if mutation == "keytab_unreadable":
            d[key("krb.keytab")]["fields"].update(readable=False, error="permission denied")

    r = H.run("healthy", mutate=m)
    assert r.authentication.state == "FAIL", H.codes(r)
    assert r.runtime.state in ("NOT_VERIFIED", "FAIL")
    if r.runtime.state == "NOT_VERIFIED":
        assert "cached credentials or SSH keys may still log in" in r.runtime.summary


def test_incomplete_default_conf_is_not_a_runtime_failure():
    def m(d):
        d[key("client.ipa_conf")]["fields"].update(server=None)

    r = H.run("healthy", mutate=m)
    assert "CLIENT_CONFIG_INCOMPLETE" in H.codes(r) and r.runtime.state == "NOT_VERIFIED"


# ---- focused re-review (round 3c): a PAM auth stack without SSSD is an AUTHENTICATION failure, not silence
def test_pam_auth_without_sssd_fails_authentication_but_not_runtime():
    def m(d):
        d[key("pam.stack", service="sshd")]["fields"].update(auth_modules=["pam_unix.so"], auth_has_sss=False)

    r = H.run("healthy", mutate=m, hbac="PASS")
    assert H.codes(r) == {"PAM_AUTH_WITHOUT_SSSD": "WARNING"}
    assert r.authentication.state == "FAIL" and "does not use SSSD" in r.authentication.summary
    assert "cached credentials" not in " ".join([r.authentication.summary] + r.authentication.reasons)
    assert r.runtime.state == "NOT_VERIFIED" and "online authentication" not in r.runtime.summary


def test_pam_service_without_sssd_fails_authentication_only():
    r = H.run("pam-not-integrated")
    assert r.authentication.state == "FAIL"
    assert r.runtime.state == "NOT_VERIFIED" and "only key-based logins may still work" in r.runtime.summary


# ---- focused re-review (round 3d)
@pytest.mark.parametrize("scenario", ["dns-failure", "kdc-unreachable", "time-skew", "sssd-offline-unexplained",
                                      "sssd-stopped"])
@pytest.mark.parametrize("pam", ["auth_only", "none"])
def test_local_pam_break_is_never_hidden_by_the_online_path(scenario, pam):
    def m(d):
        k = key("pam.stack", service="sshd")
        if pam == "auth_only":
            d[k]["fields"].update(auth_modules=["pam_unix.so"], auth_has_sss=False)
        else:
            S.pam_not_integrated(d)

    r = H.run(scenario, mutate=m)
    text = " ".join([r.authentication.summary] + r.authentication.reasons)
    assert r.authentication.state == "FAIL" and "does not use SSSD" in r.authentication.summary
    assert "cached credentials" not in text
    assert "cached credentials" not in r.runtime.summary


def test_pam_auth_only_runtime_says_only_keys_may_work():
    def m(d):
        d[key("pam.stack", service="sshd")]["fields"].update(auth_modules=["pam_unix.so"], auth_has_sss=False)

    r = H.run("dns-failure", mutate=m)
    assert r.runtime.state == "NOT_VERIFIED" and "only key-based logins may still work" in r.runtime.summary


def test_unreadable_included_pam_file_is_not_a_failure(tmp_path, monkeypatch):
    (tmp_path / "sshd").write_text("auth substack password-auth\naccount include password-auth\n")
    pa = tmp_path / "password-auth"
    pa.write_text("auth sufficient pam_sss.so\naccount required pam_sss.so\n")
    monkeypatch.setattr(C, "PAM_D", str(tmp_path))
    real_open = open

    def fake_open(path, *a, **k):
        if str(path).endswith("password-auth"):
            raise PermissionError(13, "denied")
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)
    r = C._pam_stack({"service": "sshd"})
    assert r.status == "DENIED" and "password-auth" in r.display


# ---- focused re-review (round 3e)
@pytest.mark.parametrize("other_text,pa", [("auth include pa\naccount include pa\n", "unreadable"),
                                           ("auth include pa\naccount include pa\n", "missing"),
                                           (None, None)])
def test_other_fallback_is_held_to_the_same_rule(tmp_path, monkeypatch, other_text, pa):
    if other_text is not None:
        (tmp_path / "other").write_text(other_text)
    else:
        (tmp_path / "other").write_text("x")
    if pa == "unreadable":
        (tmp_path / "pa").write_text("account required pam_sss.so\n")
    monkeypatch.setattr(C, "PAM_D", str(tmp_path))
    real_open = open

    def fake_open(path, *a, **k):
        if (pa == "unreadable" and str(path).endswith("/pa")) or (other_text is None and str(path).endswith("/other")):
            raise PermissionError(13, "denied")
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)
    r = C._pam_stack({"service": "nosuchservice"})
    assert r.status in ("DENIED", "FAILED") and "cannot be evaluated" in r.display


def test_account_phase_without_sssd_is_an_enforcement_gap_not_an_auth_failure():
    def m(d):
        d[key("pam.stack", service="sshd")]["fields"].update(account_modules=["pam_unix.so"],
                                                             auth_modules=["pam_unix.so", "pam_sss.so"],
                                                             account_has_sss=False, auth_has_sss=True)

    r = H.run("healthy", mutate=m, hbac="PASS")
    assert H.codes(r) == {"PAM_ACCOUNT_WITHOUT_SSSD": "WARNING"}
    assert r.authentication.state == "NOT_VERIFIED" and r.runtime.state == "NOT_VERIFIED"
