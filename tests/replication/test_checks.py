"""The replication checks themselves (collectors), with the external commands faked."""

from __future__ import annotations

import base64
import os
import pathlib
import subprocess

import pytest

from ipa_diagnose.replication import checks as C
from ipa_diagnose.replication import ldif
from ipa_diagnose.resolution.checks import REGISTRY, Runner

BASEDN = "dc=lab,dc=test"

AGREEMENTS_LDIF = f"""dn: cn=meToipa02.lab.test,cn=replica,cn=dc\\3Dlab\\2Cdc\\3Dtest,cn=mapping tree,cn=config
cn: meToipa02.lab.test
objectClass: nsds5replicationagreement
nsDS5ReplicaHost: ipa02.lab.test
nsDS5ReplicaPort: 389
nsDS5ReplicaTransportInfo: LDAP
nsDS5ReplicaBindMethod: SASL/GSSAPI
nsDS5ReplicaRoot: dc=lab,dc=test
nsds5replicaLastUpdateStatus: Error (0) Replica acquired successfully: Incremental update succeeded
nsds5replicaLastUpdateStatusJSON: {{"state": "green", "ldap_rc": "0", "ldap_rc_text": "Success", "repl_rc": "0", "repl_rc_text": "replica acquired", "date": "2026-09-29T10:00:00Z", "message": "Error (0) Replica acquired successfully: Incremental update succeeded"}}
nsds5replicaLastUpdateStart: 20260929100000Z
nsds5replicaLastUpdateEnd: 20260929100001Z
nsds5replicaUpdateInProgress: FALSE
nsds5replicaLastInitStatus: Error (0) Total update succeeded
nsDS5ReplicaCredentials: {{AES}}c2VjcmV0LXNob3VsZC1uZXZlci1hcHBlYXI=

dn: cn=caToipa02.lab.test,cn=replica,cn=o\\3Dipaca,cn=mapping tree,cn=config
cn: caToipa02.lab.test
objectClass: nsds5replicationagreement
nsDS5ReplicaHost: ipa02.lab.test
nsDS5ReplicaPort: 389
nsDS5ReplicaTransportInfo: LDAP
nsDS5ReplicaBindMethod: SASL/GSSAPI
nsDS5ReplicaRoot: o=ipaca
nsds5replicaLastUpdateStatus:: {base64.b64encode(b"Error (-1) Problem connecting to replica - LDAP error: Can't contact LDAP server (connection error)").decode()}
nsds5replicaLastUpdateEnd: 19700101000000Z
nsds5replicaUpdateInProgress: FALSE

dn: cn=evil,cn=replica,cn=dc\\3Dlab\\2Cdc\\3Dtest,cn=mapping tree,cn=config
cn: evil
objectClass: nsds5replicationagreement
nsDS5ReplicaHost: $(reboot).lab.test
nsDS5ReplicaPort: 389
nsDS5ReplicaRoot: dc=lab,dc=test

dn: cn=win,cn=replica,cn=dc\\3Dlab\\2Cdc\\3Dtest,cn=mapping tree,cn=config
cn: win
objectClass: nsDSWindowsReplicationAgreement
"""

TOPOLOGY_MASTERS = f"""dn: cn=masters,cn=ipa,cn=etc,{BASEDN}
cn: masters

dn: cn=ipa01.lab.test,cn=masters,cn=ipa,cn=etc,{BASEDN}
cn: ipa01.lab.test

dn: cn=CA,cn=ipa01.lab.test,cn=masters,cn=ipa,cn=etc,{BASEDN}
cn: CA
ipaConfigString: enabledService
ipaConfigString: caRenewalMaster

dn: cn=KDC,cn=ipa01.lab.test,cn=masters,cn=ipa,cn=etc,{BASEDN}
cn: KDC
ipaConfigString: enabledService

dn: cn=ipa02.lab.test,cn=masters,cn=ipa,cn=etc,{BASEDN}
cn: ipa02.lab.test

dn: cn=CA,cn=ipa02.lab.test,cn=masters,cn=ipa,cn=etc,{BASEDN}
cn: CA
ipaConfigString: configuredService
"""

TOPOLOGY_SEGMENTS = f"""dn: cn=domain,cn=topology,cn=ipa,cn=etc,{BASEDN}
objectClass: iparepltopoconf
ipaReplTopoConfRoot: {BASEDN}

dn: cn=ipa01-to-ipa02,cn=domain,cn=topology,cn=ipa,cn=etc,{BASEDN}
objectClass: iparepltoposegment
ipaReplTopoSegmentLeftNode: ipa01.lab.test
ipaReplTopoSegmentRightNode: ipa02.lab.test
ipaReplTopoSegmentDirection: both

dn: cn=ca,cn=topology,cn=ipa,cn=etc,{BASEDN}
objectClass: iparepltopoconf
ipaReplTopoConfRoot: o=ipaca
"""


class FakeExec:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, argv, timeout, env_extra=None, stdin_text=None):
        self.calls.append((list(argv), dict(env_extra or {})))
        joined = " ".join(argv)
        for needle, ans in self.answers:
            if needle in joined:
                return ans(argv, env_extra) if callable(ans) else ans
        return 1, "", "unexpected"


@pytest.fixture
def ldapi(monkeypatch):
    monkeypatch.setattr(C, "_ldapi", lambda: ("ldapi://%2Frun%2Fslapd-LAB-TEST.socket", BASEDN, None))


def test_ldif_parser_handles_folding_base64_and_bounds():
    text = "dn: cn=a\nattr: one\n two\nb64:: " + base64.b64encode("héllo".encode()).decode() + "\n\n" + \
           "\n".join(f"dn: cn=x{i}\nv: {i}\n" for i in range(ldif.MAX_ENTRIES + 20))
    es = ldif.parse(text)
    assert es[0]["attr"] == ["onetwo"] and es[0]["b64"] == ["héllo"]
    assert len(es) == ldif.MAX_ENTRIES
    assert ldif.parse("garbage without dn\nfoo: bar") == []


def test_agreements_are_projected_per_suffix_and_never_carry_credentials(monkeypatch, ldapi):
    fake = FakeExec([("nsds5replicationagreement", (0, AGREEMENTS_LDIF, "")),
                     ("objectClass=nsds5replica)", (0, "dn: cn=replica,cn=x\nnsDS5ReplicaRoot: dc=lab,dc=test\n"
                                                       "nsDS5ReplicaId: 4\nnsds5ReplicaBindDNGroup: cn=rm\n", "")),
                     ("nsTombstone", (0, "", "")), ("cleanallruv", (32, "", "No such object")),
                     ("ldapwhoami", (0, "dn: cn=directory manager\n", ""))])
    monkeypatch.setattr(C, "_exec", fake)
    res = C._agreements({})
    assert res.status == "OK"
    ags = res.fields["agreements"]
    assert [a["subject"] for a in ags] == ["ca:ipa02.lab.test", "domain:ipa02.lab.test"]
    ca = ags[0]
    assert ca["suffix_kind"] == "ca" and "Can't contact LDAP server" in ca["status_text"]
    assert ca["last_update_end"] is None  # 1970 = never
    dom = ags[1]
    assert dom["last_update_end"] == "2026-09-29T10:00:01Z" and dom["bind_method"] == "SASL/GSSAPI"
    assert dom["status_json"] and "green" in dom["status_json"]
    assert "c2VjcmV0" not in repr(res.fields) and "AES" not in repr(res.fields)
    other = res.fields["other_agreements"]
    assert {"kind": "winsync", "name": "win"} in other
    assert any(o.get("consumer") == "$(reboot).lab.test" for o in other)  # listed, never a subject
    assert res.fields["complete"] is False  # an agreement it could not use makes the read incomplete
    assert res.fields["clean_tasks"] == 0
    for argv, _env in fake.calls:
        assert argv[0] in ("ldapsearch", "ldapwhoami") and "-Y" in argv and "EXTERNAL" in argv
        assert "nsDS5ReplicaCredentials" not in argv


def test_a_truncated_read_is_never_complete(monkeypatch, ldapi):
    many = "".join(f"dn: cn=a{i},cn=mapping tree,cn=config\nobjectClass: nsds5replicationagreement\n"
                   f"nsDS5ReplicaHost: h{i}.lab.test\nnsDS5ReplicaRoot: dc=lab,dc=test\n\n"
                   for i in range(ldif.MAX_ENTRIES + 5))
    monkeypatch.setattr(C, "_exec", FakeExec([("nsds5replicationagreement", (0, many, "")),
                                              ("objectClass=nsds5replica)", (0, "", "")),
                                              ("nsTombstone", (0, "", "")), ("cleanallruv", (32, "", "")),
                                              ("ldapwhoami", (0, "dn: cn=directory manager", ""))]))
    assert C._agreements({}).fields["complete"] is False


def test_bind_method_and_transport_are_closed_enums(monkeypatch, ldapi):
    text = AGREEMENTS_LDIF.replace("nsDS5ReplicaBindMethod: SASL/GSSAPI", "nsDS5ReplicaBindMethod: ipa02.secret.corp", 1)
    text = text.replace("nsDS5ReplicaTransportInfo: LDAP", "nsDS5ReplicaTransportInfo: evil.example.com", 1)
    monkeypatch.setattr(C, "_exec", FakeExec([("nsds5replicationagreement", (0, text, "")),
                                              ("objectClass=nsds5replica)", (0, "", "")),
                                              ("nsTombstone", (0, "", "")), ("cleanallruv", (32, "", "")),
                                              ("ldapwhoami", (0, "dn: cn=directory manager", ""))]))
    f = C._agreements({}).fields
    assert "secret.corp" not in repr(f) and "evil.example.com" not in repr(f)
    assert {a["bind_method"] for a in f["agreements"]} <= {"SASL/GSSAPI", "other"}


def test_agreements_read_failure_is_not_ok(monkeypatch, ldapi):
    monkeypatch.setattr(C, "_exec", FakeExec([("nsds5replicationagreement", (50, "", "Insufficient access"))]))
    assert C._agreements({}).status == "FAILED"


def test_ldapi_unavailable_without_root_is_denied(monkeypatch):
    monkeypatch.setattr(C, "_ldapi", lambda: (None, None, "not running as root (LDAPI EXTERNAL identity is the "
                                                          "local uid)"))
    assert C._agreements({}).status == "DENIED"
    assert C._topology({}).status == "DENIED"


def test_topology_roles_flags_and_segments(monkeypatch, ldapi):
    monkeypatch.setattr(C, "_exec", FakeExec([("cn=masters", (0, TOPOLOGY_MASTERS, "")),
                                              ("cn=topology", (0, TOPOLOGY_SEGMENTS, "")),
                                              ("ldapwhoami", (0, "dn: cn=directory manager", ""))]))
    f = C._topology({}).fields
    assert f["masters"] == ["ipa01.lab.test", "ipa02.lab.test"]
    assert f["roles"] == {"ipa01.lab.test": ["CA", "KDC"]}  # ipa02's CA is only configured, not enabled
    assert f["flags"] == {"ipa01.lab.test": ["caRenewalMaster"]}
    assert f["segments"] == [{"suffix": "domain", "left": "ipa01.lab.test", "right": "ipa02.lab.test",
                              "name": "ipa01-to-ipa02", "direction": "both"}]
    assert {s["name"] for s in f["suffixes"]} == {"domain", "ca"} and f["complete"] is True


def test_topology_is_incomplete_without_a_confirmed_identity(monkeypatch, ldapi):
    monkeypatch.setattr(C, "_exec", FakeExec([("cn=masters", (0, TOPOLOGY_MASTERS, "")),
                                              ("cn=topology", (0, TOPOLOGY_SEGMENTS, "")),
                                              ("ldapwhoami", (0, "dn: uid=admin", ""))]))
    assert C._topology({}).fields["complete"] is False


def test_peer_rootdse_clock_and_answer(monkeypatch):
    import datetime

    peer = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=600)).strftime("%Y%m%d%H%M%SZ")
    monkeypatch.setattr(C, "_exec", FakeExec([("ldapsearch", (0, f"dn:\ncurrentTime: {peer}\nvendorVersion: 389\n"
                                                                 "supportedSASLMechanisms: GSSAPI\n", ""))]))
    f = C._peer_rootdse({"host": "ipa02.lab.test", "port": "389", "transport": "LDAP"}).fields
    assert f["answered"] and f["ok"] and 590 <= f["offset_seconds"] <= 610 and f["sasl_gssapi"] is True


@pytest.mark.parametrize("rc,err,answered,cls", [
    (255, "ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)", False, "TRANSPORT"),
    (None, "timed out after 15s", False, "TRANSPORT"),
    (50, "ldap_search_ext: Insufficient access (50)", True, "INSUFFICIENT_ACCESS"),
])
def test_peer_rootdse_failures(monkeypatch, rc, err, answered, cls):
    monkeypatch.setattr(C, "_exec", FakeExec([("ldapsearch", (rc, "", err))]))
    f = C._peer_rootdse({"host": "ipa02.lab.test", "port": "389", "transport": "LDAP"}).fields
    assert f["answered"] is answered and f["ok"] is False and f["error_class"] == cls


@pytest.mark.parametrize("err", ["BlockingIOError", "PermissionError", "OSError"])
def test_peer_rootdse_that_cannot_start_here_is_not_run_not_a_peer_failure(monkeypatch, err):
    """Freeze review: an OSError starting ldapsearch on THIS host became TRANSPORT and a HIGH peer diagnosis."""

    monkeypatch.setattr(C, "_exec", FakeExec([("ldapsearch", (None, "", err))]))
    r = C._peer_rootdse({"host": "ipa02.lab.test", "port": "389", "transport": "LDAP"})
    assert r.status == "NOT_RUN" and "could not be run on this host" in r.display


@pytest.mark.parametrize("errno_", [24, 99, 12])  # EMFILE, EADDRNOTAVAIL, ENOMEM
def test_tcp_local_socket_error_is_not_run_not_unreachable(monkeypatch, errno_):
    from ipa_diagnose.resolution import client_checks as CC

    def boom(*a, **k):
        raise OSError(errno_, "local failure")

    monkeypatch.setattr(CC.socket, "create_connection", boom)
    r = CC._tcp({"host": "ipa02.lab.test", "port": "389"})
    assert r.status == "NOT_RUN" and "could not test from this host" in r.display


def test_tcp_network_unreachable_stays_unreachable(monkeypatch):
    from ipa_diagnose.resolution import client_checks as CC

    def boom(*a, **k):
        raise OSError(113, "No route to host")

    monkeypatch.setattr(CC.socket, "create_connection", boom)
    assert CC._tcp({"host": "ipa02.lab.test", "port": "389"}).fields["state"] == "unreachable"


def test_a_peer_probe_that_did_not_run_is_never_a_peer_cause():
    """Diagnosis level: the root DSE read and TCP checks did not run on this host (NOT_RUN): no PEER_* cause."""

    from tests.replication import helpers as H
    from tests.replication.scenarios import IPA02, Lab, key

    lab = Lab()
    lab.data[key("repl.peer_rootdse", {"host": IPA02, "port": "389", "transport": "LDAP"})] = {
        "status": "NOT_RUN", "fields": {}, "display": "ldapsearch could not be run on this host (BlockingIOError)",
        "command": "ldapsearch"}
    r = H.run(lab)
    assert not [d for d in r.diagnoses if d.code.startswith("PEER_") and d.role in ("PRIMARY", "INDEPENDENT")]
    assert r.status != "HEALTHY"


def test_tls_transports_use_the_ipa_ca_and_demand_verification(monkeypatch):
    fake = FakeExec([("ldapsearch", (255, "", "Can't contact LDAP server"))])
    monkeypatch.setattr(C, "_exec", fake)
    C._peer_rootdse({"host": "ipa02.lab.test", "port": "636", "transport": "SSL"})
    argv, env = fake.calls[0]
    assert "ldaps://ipa02.lab.test:636" in argv and env["LDAPTLS_REQCERT"] == "demand"
    C._peer_rootdse({"host": "ipa02.lab.test", "port": "389", "transport": "TLS"})
    assert "-ZZ" in fake.calls[1][0]


def _keytab(tmp_path, monkeypatch, mode=0o600):
    kt = tmp_path / "ds.keytab"
    kt.write_bytes(b"\x05\x02not-a-real-keytab")
    os.chmod(kt, mode)
    monkeypatch.setattr(C, "DS_KEYTAB", str(kt))
    monkeypatch.setattr(C, "_is_root", lambda: True)
    return kt


def test_gssapi_bind_uses_a_private_ccache_and_always_removes_it(tmp_path, monkeypatch):
    _keytab(tmp_path, monkeypatch)
    seen = {}

    def kinit(argv, env):
        seen["cc"] = env["KRB5CCNAME"]
        path = env["KRB5CCNAME"][len("FILE:"):]
        pathlib.Path(path).write_text("ticket")
        return 0, "", ""

    fake = FakeExec([("kinit", kinit), ("ldapwhoami", (0, "dn:krbprincipalname=ldap/ipa01.lab.test@LAB.TEST,cn=x", ""))])
    monkeypatch.setattr(C, "_exec", fake)
    res = C._gssapi_bind({"host": "ipa02.lab.test", "port": "389", "transport": "LDAP",
                          "principal": "ldap/ipa01.lab.test@LAB.TEST"})
    assert res.fields["bind_ok"] and res.fields["ccache_removed"] is True
    cc_dir = os.path.dirname(seen["cc"][len("FILE:"):])
    assert not os.path.exists(cc_dir)
    kinit_argv = fake.calls[0][0]
    assert kinit_argv[:3] == ["kinit", "-k", "-t"] and "-K" not in kinit_argv
    who = fake.calls[1][0]
    assert who[:4] == ["ldapwhoami", "-Q", "-Y", "GSSAPI"] and "-N" in who
    assert "ticket" not in repr(res.fields)


def test_gssapi_bind_removes_the_ccache_even_when_the_command_breaks(tmp_path, monkeypatch):
    _keytab(tmp_path, monkeypatch)
    made = []
    real = C._ccache_dir

    def spy():
        d = real()
        made.append(d)
        return d

    monkeypatch.setattr(C, "_ccache_dir", spy)

    def boom(argv, timeout, env_extra=None, stdin_text=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(C, "_exec", boom)
    with pytest.raises(RuntimeError):
        C._gssapi_bind({"host": "ipa02.lab.test", "port": "389", "transport": "LDAP",
                        "principal": "ldap/ipa01.lab.test@LAB.TEST"})
    assert made and not os.path.exists(made[0])


def test_gssapi_kinit_failure_is_classified_and_no_bind_is_attempted(tmp_path, monkeypatch):
    _keytab(tmp_path, monkeypatch)
    fake = FakeExec([("kinit", (1, "", "kinit: Cannot contact any KDC for realm 'LAB.TEST' while getting initial "
                                       "credentials"))])
    monkeypatch.setattr(C, "_exec", fake)
    f = C._gssapi_bind({"host": "ipa02.lab.test", "port": "389", "transport": "LDAP",
                        "principal": "ldap/ipa01.lab.test@LAB.TEST"}).fields
    assert f["kinit_class"] == "kdc_unreachable" and not f["bind_attempted"] and len(fake.calls) == 1


def test_symlinked_or_hardlinked_keytab_is_never_used(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("POSIX")
    real = tmp_path / "real.keytab"
    real.write_bytes(b"x")
    link = tmp_path / "ds.keytab"
    link.symlink_to(real)
    monkeypatch.setattr(C, "DS_KEYTAB", str(link))
    monkeypatch.setattr(C, "_is_root", lambda: True)
    fake = FakeExec([])
    monkeypatch.setattr(C, "_exec", fake)
    assert C._gssapi_bind({"host": "ipa02.lab.test", "port": "389", "transport": "LDAP",
                           "principal": "ldap/ipa01.lab.test@LAB.TEST"}).status == "NOT_RUN"
    res = C._ds_keytab({})
    assert res.fields["is_symlink"] is True and res.fields["principals"] == []
    assert not fake.calls  # klist never ran on a symlink
    link.unlink()
    os.link(real, link)
    assert C._ds_keytab({}).fields["links"] == 2 and not fake.calls


def test_keytab_readability_for_dirsrv(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("POSIX")
    import grp
    import pwd

    kt = _keytab(tmp_path, monkeypatch, mode=0o600)

    class P:
        pw_uid, pw_gid, pw_name = 4242, 4242, "dirsrv"

    monkeypatch.setattr(pwd, "getpwnam", lambda n: P())
    monkeypatch.setattr(grp, "getgrall", lambda: [])
    monkeypatch.setattr(C, "_exec", FakeExec([("klist", (0, "Keytab name: FILE:x\nKVNO Principal\n---- ---\n"
                                                           "   2 ldap/ipa01.lab.test@LAB.TEST\n", ""))]))
    f = C._ds_keytab({}).fields
    assert f["dirsrv_can_read"] is False  # owned by the test user, 0600: dirsrv (4242) cannot read it
    assert f["principals"] == ["ldap/ipa01.lab.test@LAB.TEST"]
    os.chmod(kt, 0o644)
    assert C._ds_keytab({}).fields["world_readable"] is True


def test_reverse_read_needs_a_ticket_and_an_empty_answer_is_not_visible(monkeypatch):
    monkeypatch.setattr(C, "_exec", FakeExec([("klist", (1, "", ""))]))
    p = {"host": "ipa02.lab.test", "port": "389", "transport": "LDAP", "self_host": "ipa01.lab.test"}
    assert C._peer_agreement(p).status == "NOT_RUN"
    fake = FakeExec([("klist", (0, "", "")), ("ldapsearch", (0, "", ""))])
    monkeypatch.setattr(C, "_exec", fake)
    res = C._peer_agreement(p)
    assert res.status == "OK" and res.fields["visible"] is False and "not proof" in res.display
    argv = fake.calls[1][0]
    assert "(&(objectClass=nsds5replicationagreement)(nsDS5ReplicaHost=ipa01.lab.test))" in argv
    monkeypatch.setattr(C, "_exec", FakeExec([("klist", (0, "", "")), ("ldapsearch", (50, "", "Insufficient"))]))
    assert C._peer_agreement(p).status == "DENIED"


def test_reverse_read_parses_the_peers_agreement(monkeypatch):
    text = AGREEMENTS_LDIF.replace("ipa02.lab.test", "ipa01.lab.test")
    monkeypatch.setattr(C, "_exec", FakeExec([("klist", (0, "", "")), ("ldapsearch", (0, text, ""))]))
    f = C._peer_agreement({"host": "ipa02.lab.test", "port": "389", "transport": "LDAP",
                           "self_host": "ipa01.lab.test"}).fields
    kinds = sorted(a["suffix_kind"] for a in f["agreements"])
    assert f["visible"] and kinds[:2] == ["ca", "domain"]
    assert "c2VjcmV0" not in repr(f)


def test_only_well_formed_operator_ccache_names_are_passed_on(monkeypatch):
    monkeypatch.setenv("KRB5CCNAME", "FILE:/tmp/krb5cc_0")
    assert C._operator_ccache() == {"KRB5CCNAME": "FILE:/tmp/krb5cc_0"}
    monkeypatch.setenv("KRB5CCNAME", "FILE:/tmp/x;rm -rf /")
    assert C._operator_ccache() == {}


# ---------------------------------------------------------------- registry-level guarantees


def test_every_replication_check_declares_its_contract():
    for cid, spec in REGISTRY.items():
        if not cid.startswith("repl."):
            continue
        assert spec.evidence and spec.privilege in ("any", "root") and spec.timeout <= 60, cid
        if spec.check_id in ("repl.gssapi_bind", "repl.peer_agreement", "repl.peer_rootdse", "repl.topology",
                             "repl.agreements", "repl.principals"):
            assert spec.side_effects != "none", cid


@pytest.mark.parametrize("check,params", [
    ("repl.peer_rootdse", {"host": "ipa02.lab.test;reboot", "port": "389", "transport": "LDAP"}),
    ("repl.peer_rootdse", {"host": "ipa02.lab.test", "port": "389 -x", "transport": "LDAP"}),
    ("repl.peer_rootdse", {"host": "ipa02.lab.test", "port": "389", "transport": "SASL"}),
    ("repl.gssapi_bind", {"host": "ipa02.lab.test", "port": "389", "transport": "LDAP",
                          "principal": "admin@LAB.TEST"}),
    ("repl.peer_agreement", {"host": "ipa02.lab.test", "port": "389", "transport": "LDAP",
                             "self_host": "*)(objectClass=*"}),
    ("dns.address", {"name": "-oProxyCommand=x"}),
])
def test_hostile_parameters_never_reach_a_command(check, params, monkeypatch):
    calls = []
    monkeypatch.setattr(C, "_exec", lambda *a, **k: calls.append(a) or (0, "", ""))
    res = Runner().run(check, params)
    assert res.status == "FAILED" and "did not validate" in res.display and not calls


def test_commands_never_use_a_shell_and_close_stdin(monkeypatch):
    seen = {}

    class P:
        pid, returncode = 1, 0

        def communicate(self, timeout=None):
            return "", ""

    def popen(argv, **kw):
        seen.update(kw, argv=argv)
        return P()

    monkeypatch.setattr(C.shutil, "which", lambda *a, **k: "/usr/bin/x")
    monkeypatch.setattr(subprocess, "Popen", popen)
    C._exec(["ldapsearch", "-x"], timeout=1)
    assert seen["stdin"] is subprocess.DEVNULL and not seen.get("shell") and seen["cwd"] == "/"
    assert set(seen["env"]) <= {"LC_ALL", "LANG", "PATH"}
    src = pathlib.Path(C.__file__).read_text(encoding="utf-8")
    assert "shell=True" not in src and "os.system" not in src


def test_a_command_that_hangs_is_killed_and_reported(monkeypatch):
    class P:
        pid, returncode = 1, None

        def __init__(self):
            self.n = 0

        def communicate(self, timeout=None):
            self.n += 1
            if self.n == 1:
                raise subprocess.TimeoutExpired("x", timeout)
            return "", ""

        def kill(self):
            pass

    monkeypatch.setattr(C.shutil, "which", lambda *a, **k: "/usr/bin/x")
    monkeypatch.setattr(subprocess, "Popen", lambda argv, **kw: P())
    monkeypatch.setattr(C.os, "killpg", lambda *a: None, raising=False)
    rc, _o, err = C._exec(["ipa-replica-manage", "list-ruv"], timeout=1)
    assert rc is None and "timed out" in err
