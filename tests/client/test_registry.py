"""Closed check registry (client checks): metadata, side-effect disclosure, secret handling, bounded parsers."""

from __future__ import annotations

import os
import struct
import subprocess

import pytest

from ipa_diagnose.client import dnsq
from ipa_diagnose.resolution import client_checks as C
from ipa_diagnose.resolution import types as T
from ipa_diagnose.resolution.checks import REGISTRY

CLIENT = [REGISTRY[s.check_id] for s in C.specs()]


def test_every_client_check_is_registered_with_metadata():
    for s in CLIENT:
        assert s.privilege in ("any", "root") and s.timeout > 0 and s.evidence and s.describe
        assert s.side_effects and s.secrets


@pytest.mark.parametrize("check", ["net.tcp", "ipa.https", "krb.host_kinit", "ipa.api_user", "pam.user_checks",
                                   "nss.user_sss", "nss.user", "nss.group_sss", "sssd.domain_status"])
def test_checks_that_touch_something_disclose_it(check):
    assert REGISTRY[check].side_effects != "none"


def test_no_registered_check_is_a_mutating_tool():
    import inspect

    src = inspect.getsource(C)
    for bad in ('"sss_cache"', '"cache-remove"', '"cache-expire"', '"systemctl", "start"', '"-K"', '"--start"',
                '"kdestroy"', '"ipa-getkeytab"', '"rm"'):
        assert bad not in src, bad


def test_typed_parameters_refuse_option_and_shell_shapes():
    for bad in ("-rf", "--all", "1000", "all", "a b", "a;b", "$(x)", "", "a" * 300):
        assert T.validate("ipa_user", bad) is None, bad
    assert T.validate("ipa_user", "alice") == "alice"
    assert T.validate("pam_service", "-x") is None and T.validate("pam_service", "sshd") == "sshd"
    assert T.validate("fqdn", "-x.example") is None and T.validate("fqdn", "IPA01.Lab.Test") == "ipa01.lab.test"
    assert T.validate("host_principal", "host/a.lab.test@LAB.TEST") == "host/a.lab.test@LAB.TEST"
    assert T.validate("host_principal", "admin@LAB.TEST") is None
    assert T.validate("srv_name", "_ldap._tcp.lab.test") and T.validate("srv_name", "_x._tcp.lab.test") is None
    assert T.validate("ipa_port", "22") is None and T.validate("ipa_port", 88) == "88"
    assert T.validate("sssd_domain", "../etc") is None


def test_sssd_conf_never_reads_secret_options(tmp_path, monkeypatch):
    conf = tmp_path / "sssd.conf"
    conf.write_text("[sssd]\ndomains = lab.test\nservices = nss, pam\n[domain/lab.test]\nid_provider = ipa\n"
                    "ipa_server = _srv_, ipa01.lab.test\nldap_default_authtok = TopSecret99\n"
                    "krb5_password = Nope\nipa_domain = lab.test\n", encoding="utf-8")
    monkeypatch.setattr(C, "SSSD_CONF", str(conf))
    monkeypatch.setattr(C, "SSSD_CONF_D", str(tmp_path / "none"))
    r = C._sssd_conf({})
    assert r.status == "OK" and r.fields["ipa_domain"] == "lab.test" and r.fields["uses_srv"] is True
    assert "TopSecret99" not in repr(r) and "Nope" not in repr(r)


def test_sssd_conf_unparsable_and_missing(tmp_path, monkeypatch):
    conf = tmp_path / "sssd.conf"
    conf.write_text("garbage without section\n", encoding="utf-8")
    monkeypatch.setattr(C, "SSSD_CONF", str(conf))
    monkeypatch.setattr(C, "SSSD_CONF_D", str(tmp_path / "none"))
    assert C._sssd_conf({}).fields["parsable"] is False
    monkeypatch.setattr(C, "SSSD_CONF", str(tmp_path / "missing"))
    assert C._sssd_conf({}).fields == {"present": False}


def test_keytab_listing_never_asks_for_keys(monkeypatch, tmp_path):
    kt = tmp_path / "krb5.keytab"
    kt.write_bytes(b"\x05\x02binary")
    os.chmod(kt, 0o600)
    seen = []

    def fake_run(argv, timeout=10):
        seen.append(argv)
        return 0, ("Keytab name: FILE:/etc/krb5.keytab\nKVNO Principal\n---- ----\n"
                   "   2 host/c1.lab.test@LAB.TEST\n   2 host/c1.lab.test@LAB.TEST\n"), ""

    monkeypatch.setattr(C, "KEYTAB", str(kt))
    monkeypatch.setattr(C, "_run", fake_run)
    monkeypatch.setattr(C, "_is_root", lambda: True)
    r = C._keytab({})
    assert seen == [["klist", "-k", str(kt)]]
    assert r.fields["principals"] == ["host/c1.lab.test@LAB.TEST"] and r.fields["kvnos"]["host/c1.lab.test@LAB.TEST"] == [2]


def test_kinit_errors_are_classified_by_the_kdcs_answer():
    cases = {"kinit: Clock skew too great while getting initial credentials": "clock_skew",
             "kinit: Cannot contact any KDC for realm 'LAB.TEST' while getting initial credentials": "kdc_unreachable",
             "kinit: Client 'host/x@LAB.TEST' not found in Kerberos database while getting initial credentials":
                 "principal_unknown",
             "kinit: Preauthentication failed while getting initial credentials": "key_rejected",
             "kinit: Keytab contains no suitable keys for host/x@LAB.TEST while getting initial credentials":
                 "keytab_no_entry",
             "kinit: something new": "other"}
    for text, cls in cases.items():
        assert C._classify_kinit(text) == cls, text


def test_host_ticket_cache_is_private_and_removed(monkeypatch, tmp_path):
    made = {}

    class P:
        returncode = 0
        stderr = ""

    def fake_run(argv, **kw):
        made["cc"] = kw["env"]["KRB5CCNAME"]
        path = made["cc"][len("FILE:"):]
        open(path, "w").close()
        made["mode"] = oct(os.stat(os.path.dirname(path)).st_mode & 0o777)
        return P()

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(C.shutil, "which", lambda *a, **k: "/usr/bin/kinit")
    monkeypatch.setattr(C, "_is_root", lambda: True)
    r = C._host_kinit({"principal": "host/c1.lab.test@LAB.TEST"})
    assert r.fields["ok"] is True and made["mode"] == "0o700"
    assert not os.path.exists(made["cc"][len("FILE:"):])
    assert not os.path.exists(os.path.dirname(made["cc"][len("FILE:"):]))


def test_log_signals_are_counted_and_the_example_redacted(monkeypatch, tmp_path):
    log = tmp_path / "sssd_lab.test.log"
    log.write_text("(2026) [be] ldb_connect failed: Input/output error on cache_lab.test.ldb\n"
                   "(2026) Going offline. ldap_default_authtok = SuperSecret1\n"
                   "\x1b[31mClock skew too great\x1b[0m\n", encoding="utf-8")
    monkeypatch.setattr(C, "SSSD_LOG_DIR", str(tmp_path))
    monkeypatch.setattr(C, "_is_root", lambda: True)
    monkeypatch.setattr(C, "_run", lambda argv, timeout=15: (1, "", ""))
    r = C._log_signals({"domain": "lab.test"})
    assert r.fields["counts"] == {"cache_db": 1, "offline": 1, "clock_skew": 1}
    assert "SuperSecret1" not in repr(r.fields) and "\x1b" not in repr(r.fields["examples"])


def test_pam_stack_follows_includes_and_detects_pam_sss(tmp_path, monkeypatch):
    (tmp_path / "sshd").write_text("#%PAM-1.0\nauth substack password-auth\naccount include password-auth\n")
    (tmp_path / "password-auth").write_text("auth sufficient pam_sss.so forward_pass\n"
                                            "account [default=bad success=ok user_unknown=ignore] pam_sss.so\n")
    monkeypatch.setattr(C, "PAM_D", str(tmp_path))
    r = C._pam_stack({"service": "sshd"})
    assert r.fields["account_has_sss"] and r.fields["auth_has_sss"] and r.fields["files"] == ["sshd", "password-auth"]


def test_pam_stack_include_loop_and_escape_are_bounded(tmp_path, monkeypatch):
    (tmp_path / "a").write_text("account include b\naccount include ../../etc/shadow\n")
    (tmp_path / "b").write_text("account include a\n")
    monkeypatch.setattr(C, "PAM_D", str(tmp_path))
    r = C._pam_stack({"service": "a"})
    assert r.fields["files"] == ["a", "b"] and not r.fields["account_has_sss"]


def _answer(qid, answers=b"", an=0, flags=0x8180):
    q = dnsq._encode_name("_ldap._tcp.lab.test") + struct.pack("!HH", 33, 1)
    return struct.pack("!HHHHHH", qid, flags, 1, an, 0, 0) + q + answers


def test_dns_parser_reads_srv_answers():
    target = dnsq._encode_name("ipa01.lab.test")
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 33, 1, 60, 6 + len(target)) + struct.pack("!HHH", 0, 100, 389) + target
    rcode, ans = dnsq.parse_srv_response(_answer(7, rr, 1), 7)
    assert rcode == "NOERROR" and ans == [{"priority": 0, "weight": 100, "port": 389, "target": "ipa01.lab.test"}]


@pytest.mark.parametrize("payload", [
    b"\xc0\x40" + struct.pack("!HHIH", 33, 1, 60, 8) + b"\x00" * 8,      # pointer forwards
    b"\x3f" + b"a" * 5,                                                  # truncated label
    b"\xc0\x0c" + struct.pack("!HHIH", 33, 1, 60, 500),                  # rdlen beyond the packet
])
def test_dns_parser_refuses_hostile_packets(payload):
    with pytest.raises(dnsq.DnsError):
        dnsq.parse_srv_response(_answer(9, payload, 1), 9)


def test_dns_parser_refuses_a_wrong_id_and_loops():
    with pytest.raises(dnsq.DnsError):
        dnsq.parse_srv_response(_answer(1), 2)
    loop = struct.pack("!HHHHHH", 3, 0x8180, 0, 1, 0, 0) + b"\xc0\x0c"
    with pytest.raises(dnsq.DnsError):
        dnsq.parse_srv_response(loop, 3)


def test_resolv_conf_is_bounded(tmp_path):
    p = tmp_path / "resolv.conf"
    p.write_text("nameserver 10.0.0.1\nnameserver not-an-ip\nnameserver ::1\nnameserver 10.0.0.2\n"
                 "nameserver 10.0.0.3\nsearch a.test b.test\n")
    rc = dnsq.read_resolv_conf(str(p))
    assert rc["nameservers"] == ["10.0.0.1", "::1", "10.0.0.2"] and rc["search"] == ["a.test", "b.test"]


def test_user_checks_parser(monkeypatch):
    monkeypatch.setattr(C, "_is_root", lambda: True)
    out = ("user: alice\naction: acct\nservice: sshd\n\nSSSD nss user lookup result:\n - user name: alice\n"
           "pam_acct_mgmt: Permission denied\n\n")
    monkeypatch.setattr(C, "_run", lambda argv, timeout=45: (0, out, ""))
    r = C._user_checks({"user": "alice", "service": "sshd"})
    assert r.fields["result_class"] == "permission_denied" and r.fields["nss_found"] is True


def test_getent_keeps_only_name_uid_gid(monkeypatch):
    monkeypatch.setattr(C, "_run", lambda argv, timeout=30: (0, "alice:*:1234:1234:Alice Secret Name:/home/a:/bin/sh\n",
                                                             ""))
    r = C._nss_user(True)({"user": "alice"})
    assert r.fields == {"found": True, "exit": 0, "seconds": r.fields["seconds"], "name": "alice", "uid": 1234,
                        "gid": 1234}
    assert "Secret Name" not in repr(r)


def test_user_checks_result_printed_on_stderr_is_read(monkeypatch):
    """Live lab run 2: sssctl user-checks prints 'pam_acct_mgmt: ...' on stderr."""

    monkeypatch.setattr(C, "_is_root", lambda: True)
    monkeypatch.setattr(C, "_run", lambda argv, timeout=45: (
        0, "user: alice\naction: acct\nservice: sshd\n\n", "pam_acct_mgmt: Success\n\nPAM Environment:\n - no env -\n"))
    r = C._user_checks({"user": "alice", "service": "sshd"})
    assert r.status == "OK" and r.fields["result_class"] == "success"
