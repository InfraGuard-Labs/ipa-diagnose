"""Reproductions from the ninth fresh privacy review of the support bundle."""

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


@pytest.mark.parametrize("text", [
    "GET /ipa/session/sync?ticket=ZqCanary1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdEFGH failed",
    "server said sessid=ZqCanary1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdEFGH",
    "code=0123456789abcdef0123456789abcdef0123456789",
])
def test_a_random_token_after_an_equals_sign_is_redacted(text):
    out = _san().text(text)
    assert "ZqCanary1" not in out and "0123456789abcdef0123" not in out


@pytest.mark.parametrize("text,leaked", [
    ("_kerberos._udp.zqipadom.lan SRV record missing", "zqipadom"),
    ("_kerberos._tcp.zqother.lan. missing", "zqother"),
    ("SRV _kerberos-master._udp.ZQOTHER.LAN missing", "zqother"),
    ("_ldap._tcp.dc._msdcs.ad.zqother.lan not found", "zqother"),
    ("ipa-ca.zqipadom.lan A record missing", "zqipadom"),
])
def test_domains_named_only_in_srv_or_ipa_ca_records_are_pseudonymized(text, leaked):
    out = _san(text).text(text)
    assert leaked.lower() not in out.lower(), out
    assert "_kerberos" in out or "_ldap" in out or "ipa-ca" in out  # service labels keep their meaning


def test_ipa_domain_different_from_the_host_dns_domain(tmp_path):
    d = tmp_path / "fx"
    shutil.copytree(ROOT / "dns" / "srv-missing", d)
    for f in d.iterdir():
        text = f.read_text(encoding="utf-8")
        text = text.replace("ipa01.example.test", "ipa01.zqhostdom.lan").replace("example.test", "zqipadom.lan")
        text = text.replace("EXAMPLE.TEST", "ZQIPADOM.LAN")
        f.write_text(text, encoding="utf-8")
    ev, rep = diagnose_replay(d)
    b = build(ev, rep, created_at="2026-09-27T00:00:00Z")
    selftest.check(b.members, b.sanitizer.originals(), [str(d)], b.sanitizer.secret_values)
    text = all_text(b.members).lower()
    assert "zqipadom" not in text and "zqhostdom" not in text


def test_an_email_in_the_diagnosed_public_listed_domain_is_pseudonymized():
    s = Sanitizer()
    s.add_host("ipa01.fedoraproject.org", force=True)
    s.add_domain("fedoraproject.org", force=True)
    text = "agreement contact zqalice.smith@fedoraproject.org was notified"
    s.discover(text)
    out = s.text(text)
    assert "zqalice" not in out and "fedoraproject" not in out


@pytest.mark.parametrize("text,leaked", [
    ("using password 'zq canary horse battery'", "horse"),
    ("net ads join -U 'Administrator%ZqCanary1'", "ZqCanary1"),
    ('smbclient -U "admin%ZqCanary1"', "ZqCanary1"),
    ("ipaNTHash:: ZqCanary1AbCdEfGhIjKl==", "ZqCanary1"),
    ("host ipaclient.zqcorp.lan unreachable", "zqcorp"),
])
def test_round_nine_non_blockers_fixed_anyway(text, leaked):
    assert leaked.lower() not in _san(text).text(text).lower()


def test_ipa_python_module_names_stay_readable():
    text = "ipahealthcheck.dogtag.ca.DogtagCertsConfigCheck and ipaserver.install.certs failed"
    assert _san(text).text(text) == text
