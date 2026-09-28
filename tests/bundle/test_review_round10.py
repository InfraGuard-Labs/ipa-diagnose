"""Reproductions from the tenth fresh privacy review of the support bundle."""

from __future__ import annotations

import json
import pathlib
import shutil

import pytest

from ipa_diagnose.bundle import selftest
from ipa_diagnose.bundle.build import build
from ipa_diagnose.bundle.sanitize import Sanitizer

from tests.bundle.helpers import ROOT, all_text, diagnose_replay
from tests.bundle.test_review_round5 import _bundle_with_kw


def _san(*texts, host="ipa01.example.test"):
    s = Sanitizer()
    s.add_host(host, force=True)
    s.add_domain(host.split(".", 1)[1], force=True)
    s.add_realm(host.split(".", 1)[1].upper(), force=True)
    for t in texts:
        s.discover(t)
    return s


@pytest.mark.parametrize("text,leaked", [
    ('filter="(&(objectClass=posixAccount)(uid=zqalice))" then account zqalice is locked', "zqalice"),
    ("uid=zqerin; account zqerin disabled", "zqerin"),
    ("uid='zqfoo' ... zqfoo unknown", "zqfoo"),
    ("no entry for uid=zqgus. Check that zqgus exists", "zqgus"),
    ("Could not create home directory /home/zqcarol. User zqcarol cannot log in", "zqcarol"),
    ("user zqdan (home /home/zqdan) locked", "zqdan"),
    ("[/home/zqhal] missing for zqhal", "zqhal"),
    ("id zqbob: uid=1001(zqbob) gid=1001(zqbob)", "zqbob"),
    ("record idnsname=zqipa03,idnsname=example.test.,cn=dns,dc=example,dc=test", "zqipa03"),
    ("login zqivy@example.test failed; zqivy locked", "zqivy"),
])
def test_user_and_host_names_from_round_ten(text, leaked):
    assert leaked not in _san(text).text(text)


def test_a_numeric_uid_is_not_treated_as_a_name():
    text = "uid=1001(zqbob) and 1001 entries"
    out = _san(text).text(text)
    assert "1001 entries" in out and "zqbob" not in out


@pytest.mark.parametrize("text,secret", [
    ("API key: ZqCanary4", "ZqCanary4"),
    ("pass phrase: ZqCanary5", "ZqCanary5"),
    ("pass-phrase=ZqCanary6", "ZqCanary6"),
    ("Access key: ZqCanary7", "ZqCanary7"),
    ("kadmin -p admin/admin -w ZqCanary1 -q listprincs", "ZqCanary1"),
    ("pki -U https://ipa01.example.test:8443 -u caadmin -w ZqCanary2 ca-user-find", "ZqCanary2"),
    ("kdb5_util create -s -r EXAMPLE.TEST -P ZqCanary7", "ZqCanary7"),
    ("wbinfo -a zqaduser%ZqCanary3", "ZqCanary3"),
    ("admin password updated to ZqCanary1", "ZqCanary1"),
    ("password now ZqCanary2", "ZqCanary2"),
    ("2 host/ipa01.example.test@EXAMPLE.TEST (aes128-cts-hmac-sha1-96) (0x8f2a3c4d5e6f708192a3b4c5d6e7f809)",
     "8f2a3c4d5e6f7081"),
    ("git clone https://ZqCanaryTok1Abc2Def3@github.com/org/repo failed", "ZqCanaryTok1"),
])
def test_credential_shapes_from_round_ten(text, secret):
    assert secret not in _san(text).text(text)


def test_the_key_of_an_unknown_check_is_withheld(tmp_path):
    d = tmp_path / "fx"
    shutil.copytree(ROOT / "replication" / "peer-unreachable", d)
    hc = json.loads((d / "healthcheck.json").read_text(encoding="utf-8"))
    hc.append({"source": "ipahealthcheck.zzz.future", "check": "Future", "result": "ERROR", "uuid": "k1",
               "when": "20260101120000Z", "duration": "0.1",
               "kw": {"key": "home of zqkeyuser; token ZqCanaryKeyTok1", "msg": "x"}})
    (d / "healthcheck.json").write_text(json.dumps(hc), encoding="utf-8")
    ev, rep = diagnose_replay(d)
    b = build(ev, rep, created_at="2026-09-27T00:00:00Z")
    selftest.check(b.members, b.sanitizer.originals(), [str(d)], b.sanitizer.secret_values)
    text = all_text(b.members)
    assert "zqkeyuser" not in text and "ZqCanaryKeyTok1" not in text
    probe = [f for f in json.loads(b.members["healthcheck.json"])["findings"] if f["check"] == "Future"][0]
    assert probe["key"] == "[WITHHELD]"
