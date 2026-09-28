"""Reproductions from the sixteenth fresh privacy review: multi-label DNS record names in idnsname= DNs."""

from __future__ import annotations

import json
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


@pytest.mark.parametrize("text,leaked", [
    ("nsuniqueid=66446001-1dd211b2-a527ce8b-8fa47d35+idnsname=zqws7.zqdev,idnsname=example.test.,cn=dns,"
     "dc=example,dc=test", ("zqws7", "zqdev")),
    ("named[812]: update_record (syncrepl) failed, dn 'idnsname=zqws5.zqlab,idnsname=example.test.,cn=dns,"
     "dc=example,dc=test' change type 0x4. Records can be outdated, run `rndc reload`: not found", ("zqws5", "zqlab")),
    ("idnsname=zqa.zqb.zqc,idnsname=example.test.,cn=dns,dc=example,dc=test", ("zqa", "zqb", "zqc")),
])
def test_a_multi_label_record_name_is_pseudonymized(text, leaked):
    out = _san(text).text(text, limit=2000)
    for name in leaked:
        assert name not in out


def test_the_record_name_and_the_fqdn_are_the_same_host():
    rec = "idnsname=zqws7.zqdev,idnsname=example.test.,cn=dns,dc=example,dc=test"
    fqdn = "zqws7.zqdev.example.test resolves"
    s = _san(rec, fqdn)
    a, b = s.text(rec), s.text(fqdn)
    pseudo = b.split()[0]
    assert pseudo.startswith("HOST-") and f"idnsname={pseudo}," in a


def test_a_one_label_record_keeps_one_pseudonym():
    rec = "idnsname=zqipa03,idnsname=example.test.,cn=dns,dc=example,dc=test"
    s = _san(rec, "zqipa03.example.test is down")
    assert s.text(rec).split(",")[0].split("=")[1] == s.text("zqipa03.example.test is down").split()[0]


@pytest.mark.parametrize("text,kept", [
    ("idnsname=_ldap._tcp,idnsname=example.test.,cn=dns,dc=example,dc=test", "_ldap._tcp"),
    ("idnsname=5.2,idnsname=10.10.in-addr.arpa.,cn=dns,dc=example,dc=test", "idnsname=5.2,"),
])
def test_service_and_reverse_records_are_not_hosts(text, kept):
    assert kept in _san(text).text(text, limit=2000)


def test_a_record_conflict_entry_in_a_bundle(tmp_path):
    d = tmp_path / "fx"
    shutil.copytree(ROOT / "replication" / "conflicting", d)
    lq = json.loads((d / "ldap_query.json").read_text(encoding="utf-8"))
    dn = ("nsuniqueid=66446001-1dd211b2-a527ce8b-8fa47d35+idnsname=zqws7.zqdev,idnsname=example.test.,cn=dns,"
          "dc=example,dc=test")
    lq["conflicts"] = [{"dn": dn, "message": "namingConflict (ADD) idnsname=zqws7.zqdev,idnsname=example.test.,"
                                              "cn=dns,dc=example,dc=test"}]
    (d / "ldap_query.json").write_text(json.dumps(lq), encoding="utf-8")
    ev, rep = diagnose_replay(d)
    b = build(ev, rep, created_at="2026-09-28T00:00:00Z")
    selftest.check(b.members, b.sanitizer.originals(), [str(d)], b.sanitizer.secret_values)
    text = all_text(b.members)
    assert "zqws7" not in text and "zqdev" not in text
