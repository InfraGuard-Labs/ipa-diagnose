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
