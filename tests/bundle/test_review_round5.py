"""Reproductions from the fifth fresh review (privacy: credentials and identities) of the support bundle."""

from __future__ import annotations

import json
import pathlib
import shutil

import pytest

from ipa_diagnose.bundle import selftest
from ipa_diagnose.bundle.build import build
from ipa_diagnose.bundle.sanitize import Sanitizer

from tests.bundle.helpers import ROOT, all_text, diagnose_replay


def _san(*texts, host="ipa01.example.test"):
    s = Sanitizer()
    s.add_host(host, force=True)
    s.add_domain(host.split(".", 1)[1], force=True)
    s.add_realm(host.split(".", 1)[1].upper(), force=True)
    for t in texts:
        s.discover(t)
    return s


def _bundle_with_kw(tmp_path: pathlib.Path, kw):
    d = tmp_path / "fx"
    shutil.copytree(ROOT / "replication" / "peer-unreachable", d)
    hc = json.loads((d / "healthcheck.json").read_text(encoding="utf-8"))
    hc.append({"source": "ipahealthcheck.zzz.probe", "check": "ProbeCheck", "result": "ERROR", "uuid": "p1",
               "when": "20260101120000Z", "duration": "0.1", "kw": kw})
    (d / "healthcheck.json").write_text(json.dumps(hc), encoding="utf-8")
    ev, rep = diagnose_replay(d)
    b = build(ev, rep, created_at="2026-09-27T00:00:00Z")
    selftest.check(b.members, b.sanitizer.originals(), [str(d)], b.sanitizer.secret_values)
    return b


@pytest.mark.parametrize("kw", [{"session_id": "ZqCanary50x"}, {"pincode": "ZqCanary51x"}, {"totp": "ZqCanary52x"},
                                {"pass️word": "ZqCanary53x"}, {"passㅤword": "ZqCanary54x"}])
def test_a_secret_field_value_quoted_elsewhere_never_reaches_the_bundle(tmp_path, kw):
    """The engine quotes a finding's keywords in diagnosis text before the bundle sees it; the value found under the
    secret-named field is removed there too, and the self-test searches for it independently."""

    b = _bundle_with_kw(tmp_path, kw)
    assert list(kw.values())[0] not in all_text(b.members)


def test_the_self_test_refuses_a_tracked_secret_value_that_survived(tmp_path):
    b = _bundle_with_kw(tmp_path, {"session_id": "ZqCanary55x"})
    tampered = dict(b.members)
    rep = json.loads(tampered["report.json"])
    rep["note"] = "ZqCanary55x"
    tampered["report.json"] = json.dumps(rep).encode()
    with pytest.raises(selftest.LeakDetected) as e:
        selftest.check(tampered, b.sanitizer.originals(), [], b.sanitizer.secret_values)
    assert ("report.json", "value of a secret-named field") in e.value.problems


@pytest.mark.parametrize("text,secret", [
    ("bind failed (ldap://admin:ZqCanary20x@ipa02.example.test:389) retrying", "ZqCanary20x"),
    ("'ldaps://admin:ZqCanary21x@ipa02.example.test:636'", "ZqCanary21x"),
    ("(ldap://admin:ZqCanary23x@ipa02)", "ZqCanary23x"),
    ('payload {"password": "Zq\\"Canary6x"}', "Canary6x"),
    ("password='Zq''Canary30x'", "Canary30x"),
    ("ldapsearch -x -w 'Zq'\\''Canary7x' -b cn=config", "Canary7x"),
    ("adminPw=ZqCanary34x", "ZqCanary34x"),
    ("ldap bindPass: ZqCanary35x", "ZqCanary35x"),
    ('keystorePass="ZqCanary33x"', "ZqCanary33x"),
    ("pass͏word=ZqCanary10x", "ZqCanary10x"),
    ("<password>ZqCanary60x</password>", "ZqCanary60x"),
    ("password: |\n  ZqCanary61x\nnext: 1", "ZqCanary61x"),
    ("token xapp-1-ABCDEFGHIJKLMN", "ABCDEFGHIJKLMN"),
])
def test_credential_shapes_from_round_five_are_redacted(text, secret):
    out = _san(text).text(text)
    assert secret not in out and "[REDACTED:[REDACTED" not in out


def test_a_url_host_followed_by_a_bracket_has_one_pseudonym():
    s = _san("(ldap://admin:ZqPw@ipa02.example.test) and ipa02.example.test")
    out = s.text("(ldap://admin:ZqPw@ipa02.example.test) and ipa02.example.test")
    assert out.count("HOST-002") == 2 and "HOST-003" not in out


@pytest.mark.parametrize("text,leaked", [
    ("/home/zqad.lab/zqalice11/.cache", ["zqalice11", "zqad"]),
    ("zqalice12\\@zqad.lab@EXAMPLE.TEST", ["zqalice12", "zqad"]),
    ("address:fd00:1234::5 unreachable", ["fd00"]),
    ("host_fd00:abcd::7 down", ["fd00"]),
    ("base dc\\=zqcorp\\,dc\\=test", ["zqcorp"]),
    ("zqbob@zqfirma.pl wrote", ["zqbob", "zqfirma"]),
    ("AD DC zqdc1.zqfirma.pl unreachable", ["zqdc1", "zqfirma"]),
    ("lookup of zqad\\zqcarol failed", ["zqcarol"]),
    ("CN=Zq Gina Smith,CN=Users,DC=ad,DC=lab", ["Gina"]),
    ("/var/lib/sss/pubconf/krb5.include.d/domain_realm_example_test", ["example_test"]),
])
def test_identities_from_round_five_are_pseudonymized(text, leaked):
    out = _san(text).text(text)
    for x in leaked:
        assert x.lower() not in out.lower(), (x, out)


def test_members_lists_are_users():
    s = _san()
    s.discover({"members": ["zqalice", "zqbob"]})
    assert s.transform({"members": ["zqalice", "zqbob"]}) == {"members": ["USER-001", "USER-002"]}
