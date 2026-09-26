"""Regressions for the round-4 independent review of the round-3 fixes (each case was reproduced first)."""

from __future__ import annotations

import os

import pytest

from ipa_diagnose.ai.prompt import sanitize_explanation
from ipa_diagnose.engine.model import Action, Confidence, ConfidenceLevel, Diagnosis, DiagnosisStatus, RiskLevel
from ipa_diagnose.engine.packs.directory_server import _is_key_material
from ipa_diagnose.resolution import checks as C

from tests.resolution.test_round3_regressions import _fs

DS = "/etc/dirsrv/slapd-LAB"


# --- blocker: chained PKI layout links into the Directory Server NSS database ---------------------------------

@pytest.mark.parametrize("links,path", [
    ({"/var/lib/pki/pki-tomcat/alias": DS, "/etc/pki/pki-tomcat/alias": "/var/lib/pki/pki-tomcat/alias"},
     "/etc/pki/pki-tomcat/alias/cert9.db"),
    ({"/etc/pki/pki-tomcat/alias": DS, "/var/lib/pki/pki-tomcat/alias": "/etc/pki/pki-tomcat/alias"},
     "/var/lib/pki/pki-tomcat/alias/pkcs11.txt"),
    ({"/var/lib/pki/pki-tomcat/alias": DS, "/var/lib/pki/pki-tomcat/ca/alias": "/var/lib/pki/pki-tomcat/alias"},
     "/var/lib/pki/pki-tomcat/ca/alias/cert9.db"),
    ({"/etc/pki/pki-tomcat/ca": DS, "/var/lib/pki/pki-tomcat/ca/conf": "/etc/pki/pki-tomcat/ca"},
     "/var/lib/pki/pki-tomcat/ca/conf/CS.cfg"),
])
def test_chained_layout_links_into_another_component_are_refused(monkeypatch, links, path):
    _fs(monkeypatch, links)
    real = C.os.path.realpath(path)
    assert real.startswith(DS)
    assert C._layout_ok(path) is False
    assert C._command_target(real, path)[1] is False


@pytest.mark.parametrize("links,path", [
    ({"/etc/pki/pki-tomcat/alias": "/var/lib/pki/pki-tomcat/alias"}, "/etc/pki/pki-tomcat/alias/cert9.db"),
    ({"/var/lib/pki/pki-tomcat/alias": "/etc/pki/pki-tomcat/alias"}, "/var/lib/pki/pki-tomcat/alias/cert9.db"),
    ({"/var/lib/pki/pki-tomcat/ca/alias": "/var/lib/pki/pki-tomcat/alias",
      "/var/lib/pki/pki-tomcat/alias": "/etc/pki/pki-tomcat/alias"}, "/var/lib/pki/pki-tomcat/ca/alias/cert9.db"),
    ({"/etc/pki": "/data/etc/pki", "/var/lib/pki": "/data/var/lib/pki",
      "/data/var/lib/pki/pki-tomcat/alias": "/etc/pki/pki-tomcat/alias"}, "/var/lib/pki/pki-tomcat/alias/cert9.db"),
])
def test_real_pki_layouts_are_still_accepted(monkeypatch, links, path):
    _fs(monkeypatch, links)
    assert C._layout_ok(path) is True


@pytest.mark.parametrize("real,reported,ok", [
    ("/etc/pki/pki-tomcat/ca/CS.cfg", "/var/lib/pki/pki-tomcat/conf/ca/CS.cfg", True),
    (DS + "/cert9.db", "/etc/pki/pki-tomcat/alias/cert9.db", False),
    ("/etc/ipa/default.conf", "/etc/httpd/conf.d/ipa.conf", False),
    ("/etc/krb5.keytab", "/var/kerberos/krb5kdc/kdc.conf", True),
    ("/etc/named.keytab", "/etc/ipa/x", False),
])
def test_command_target_must_stay_in_the_reported_component(real, reported, ok):
    assert C._command_target(real, reported)[1] is ok


def test_second_hard_link_withholds(monkeypatch):
    path = "/etc/pki/pki-tomcat/ca/CS.cfg"
    st = os.stat_result((0o100664, 1, 1, 2, 0, 0, 10, 0, 0, 0))  # regular file, st_nlink = 2
    monkeypatch.setattr(C.os, "lstat", lambda p: st)
    monkeypatch.setattr(C.os.path, "realpath", lambda p: p)
    monkeypatch.setattr(C.os.path, "islink", lambda p: False)
    res = C._file_stat({"path": path})
    assert res.fields["realpath_allowed"] is False


# --- AI sanitizer boundaries -------------------------------------------------------------------------------------

def _diag():
    return Diagnosis(pack_id="kerberos", rule_id="clock-skew", status=DiagnosisStatus.DIAGNOSED, title="t", why="t",
                     confidence=Confidence(level=ConfidenceLevel.HIGH, rationale="t"),
                     actions=[Action(description="a", risk=RiskLevel.SAFE, command="systemctl status chronyd"),
                              Action(description="b", risk=RiskLevel.CAUTION, command="chronyc makestep")])


@pytest.mark.parametrize("text", [
    "Run 'chronyc makestep'.",
    "**systemctl stop krb5kdc**",
    '"systemctl stop krb5kdc"',
    "(systemctl stop krb5kdc)",
    "/bin/systemctl stop krb5kdc",
    "systemctl status chronyd&&chronyc makestep",
    "systemctl status chronyd|sh",
    "date -s 12:00 then hwclock -w",
    "ntpdate -u pool.ntp.org",
    "setenforce 0 and timedatectl set-time 12:00",
])
def test_ai_command_smuggling_is_rejected(text):
    assert sanitize_explanation(text, _diag()) is None


# --- journal redaction ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("line,secret", [
    ('{"password": "Hunter2secret"}', "Hunter2secret"),
    ("bind_password=Hunter2secret", "Hunter2secret"),
    ("dm_password=Hunter2secret", "Hunter2secret"),
    ("userPassword: Hunter2secret", "Hunter2secret"),
    ("ldapmodify -w Hunter2secret -D cn=dm", "Hunter2secret"),
    ("Cookie: ipa_session=MagBearerToken=abcdef0123", "MagBearerToken"),
    ("ipa-server-install --password Hunter2secret", "Hunter2secret"),
    ("nsslapd-rootpw: {PBKDF2_SHA256}AAAAAAAA", "PBKDF2_SHA256"),
    ("ldap_default_authtok = Hunter2secret", "Hunter2secret"),
])
def test_journal_secret_shapes_are_redacted(line, secret):
    assert secret not in C._redact_log_line(line)


# --- key-material siblings ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/etc/dirsrv/slapd-LAB/dse.ldif.bak", "/etc/dirsrv/slapd-LAB/dse.ldif.startOK", "/etc/dirsrv/slapd-LAB/dse.ldif.tmp",
    "/etc/sssd/sssd.conf", "/etc/dirsrv/slapd-LAB/pwdfile.txt.orig", "/etc/dirsrv/slapd-LAB/key4.db-journal",
])
def test_secret_siblings_are_key_material(path):
    assert _is_key_material(path)
