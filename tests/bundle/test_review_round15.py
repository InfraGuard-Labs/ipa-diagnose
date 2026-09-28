"""Reproductions from the fifteenth fresh privacy review: certificate serial numbers are never included."""

from __future__ import annotations

import json
import shutil

import pytest

from ipa_diagnose.bundle import selftest
from ipa_diagnose.bundle.build import build
from ipa_diagnose.bundle.sanitize import Sanitizer

from tests.bundle.helpers import ROOT, all_text, diagnose_replay

SERIAL_A = "314159265358979323846264338327950288419"
SERIAL_B = "271828182845904523536028747135266249775"
SERIAL_HEX = "0x94c4b21d9884e383e4d5e69cf0c80ba5"


def _bundle(tmp_path, findings):
    d = tmp_path / "fx"
    shutil.copytree(ROOT / "certificates" / "expired", d)
    hc = json.loads((d / "healthcheck.json").read_text(encoding="utf-8"))
    hc.extend(findings)
    (d / "healthcheck.json").write_text(json.dumps(hc), encoding="utf-8")
    ev, rep = diagnose_replay(d)
    b = build(ev, rep, created_at="2026-09-27T00:00:00Z")
    selftest.check(b.members, b.sanitizer.originals(), [str(d)], b.sanitizer.secret_values)
    return b


def _finding(source, check, uuid, kw):
    return {"source": source, "check": check, "result": "ERROR", "uuid": uuid, "when": "20260101120000Z",
            "duration": "0.1", "kw": kw}


def test_ra_agent_description_serials_are_removed(tmp_path):
    exp = f"2;{SERIAL_A};CN=Certificate Authority,O=EXAMPLE.TEST;CN=IPA RA,O=EXAMPLE.TEST"
    got = f"2;{SERIAL_B};CN=Certificate Authority,O=EXAMPLE.TEST;CN=IPA RA,O=EXAMPLE.TEST"
    b = _bundle(tmp_path, [_finding("ipahealthcheck.ipa.certs", "IPARAAgent", "ra1", {
        "expected": exp, "got": got,
        "msg": "RA agent description does not match. Found {got} in LDAP and expected {expected}"})])
    text = all_text(b.members)
    assert SERIAL_A not in text and SERIAL_B not in text
    assert "CN=IPA RA" in text  # the rest of the description is kept


def test_a_serial_keyword_is_removed(tmp_path):
    b = _bundle(tmp_path, [_finding("ipahealthcheck.dogtag.ca", "DogtagCertsConnectivityCheck", "dc1", {
        "serial": SERIAL_HEX, "msg": "Request for certificate failed, {error}", "error": "CA unreachable"})])
    assert SERIAL_HEX not in all_text(b.members)
    red = json.loads(b.members["redaction-report.json"])
    assert red["certificate_serial_fields_removed"] >= 1


@pytest.mark.parametrize("text,serial", [
    ("certificate with serial number 1234567 expired", "1234567"),
    ("Serial Number: 3a:4f:9c:12:ab", "3a:4f:9c:12:ab"),
    ("SerialNumber=0x1f2e3d", "0x1f2e3d"),
    ("cert serial 65537 revoked", "65537"),
])
def test_serials_in_text_are_redacted(text, serial):
    assert serial not in Sanitizer().text(text)


@pytest.mark.parametrize("text", ["serial number mismatch", "serial console", "the RA agent serial must match"])
def test_the_word_serial_alone_is_kept(text):
    assert Sanitizer().text(text) == text


def test_the_self_test_refuses_a_serial_field_that_was_not_removed():
    members = {"evidence.json": json.dumps({"items": [{"data": {"serial": "12345"}}]}).encode()}
    with pytest.raises(selftest.LeakDetected):
        selftest.check(members, [], [], ())
