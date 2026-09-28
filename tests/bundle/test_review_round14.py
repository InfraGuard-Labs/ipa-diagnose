"""Reproductions from the fourteenth fresh privacy review of the support bundle."""

from __future__ import annotations

import json
import shutil

import pytest

from ipa_diagnose.bundle import selftest
from ipa_diagnose.bundle.build import build
from ipa_diagnose.bundle.sanitize import Sanitizer

from tests.bundle.helpers import ROOT, all_text, diagnose_replay


def _san(*texts, host="ipa01.example.test", realm=None):
    s = Sanitizer()
    s.add_host(host, force=True)
    s.add_domain(host.split(".", 1)[1], force=True)
    s.add_realm(realm or host.split(".", 1)[1].upper(), force=True)
    for t in texts:
        s.discover(t)
    return s


@pytest.mark.parametrize("text,leaked", [
    ("krb5kdc[1](info): AS_REQ (4 etypes {18 17}) 2001:db8:77::15: CLOCK_SKEW: host/web01.example.test@EXAMPLE.TEST"
     " for krbtgt/EXAMPLE.TEST@EXAMPLE.TEST, Clock skew too great", "2001:db8:77::15"),
    ("krb5kdc[1](info): AS_REQ (2 etypes {18 17}) fd00:10:20::1a2b: PREAUTH_FAILED: zqeve@EXAMPLE.TEST for "
     "krbtgt/EXAMPLE.TEST@EXAMPLE.TEST, Preauthentication failed", "fd00:10:20::1a2b"),
])
def test_an_ipv6_address_followed_by_a_colon_is_pseudonymized(text, leaked):
    out = _san(text).text(text, limit=2000)
    assert leaked not in out and "IP-" in out


def test_an_ipv6_address_is_not_mistaken_for_a_longer_one():
    s = _san("peer fd00::5 and fd00::5:6 seen")
    out = s.text("peer fd00::5 and fd00::5:6 seen")
    assert "fd00" not in out
    assert out.split()[1] != out.split()[3]


@pytest.mark.parametrize("text", [
    "ldapsearch -LLL -Y EXTERNAL -H ldapi://%2Frun%2Fslapd-ACME-CORP.socket -b dc=east,dc=acme,dc=corp nsds50ruv",
    "cannot connect to 'ldapi://%2frun%2fslapd-ACME-CORP.socket': Can't contact LDAP server",
])
def test_the_instance_in_a_url_encoded_ldapi_path_is_pseudonymized(text):
    # a host whose domain differs from the realm: the instance is known only from this text
    out = _san(text, host="ipa01.east.acme.corp", realm="EAST.ACME.CORP").text(text, limit=2000)
    assert "ACME-CORP" not in out.upper()


@pytest.mark.parametrize("text,leaked", [
    ("nsuniqueid=66446001-1dd211b2-a527ce8b-8fa47d35+uid=4711jdoe,cn=users,cn=accounts,dc=example,dc=test",
     "4711jdoe"),
    ("Password expired for uid=9zqann,cn=users,cn=accounts,dc=example,dc=test", "9zqann"),
])
def test_a_user_name_starting_with_a_digit_is_pseudonymized(text, leaked):
    assert leaked not in _san(text).text(text, limit=2000)


def test_a_numeric_uid_is_still_not_a_name():
    text = "uid=1001(zqbob) gid=1001 and 1001 entries"
    out = _san(text).text(text)
    assert "1001 entries" in out and "zqbob" not in out


@pytest.mark.parametrize("dev,short", [
    ("/dev/mapper/rhel_ipa01-root", "ipa01"),
    ("/dev/mapper/rhel_ipa--01-var", "ipa--01"),
    ("/dev/rhel_ipa01/root", "ipa01"),
])
def test_an_installer_volume_group_named_after_the_host_is_pseudonymized(dev, short):
    host = "ipa-01.example.test" if "--" in short else "ipa01.example.test"
    out = _san(host=host).text(dev + " 91% used")
    assert short.replace("--", "-") not in out.replace("--", "-") and "91% used" in out


def test_a_bundle_from_a_default_rhel_disk_layout_is_written(tmp_path):
    d = tmp_path / "fx"
    shutil.copytree(ROOT / "directory-server" / "disk-space", d)
    fs = (d / "filesystem.json").read_text(encoding="utf-8").replace("/dev/mapper/vg-root", "/dev/mapper/rhel_ipa02-root")
    (d / "filesystem.json").write_text(fs, encoding="utf-8")
    ev, rep = diagnose_replay(d)
    b = build(ev, rep, created_at="2026-09-27T00:00:00Z")
    selftest.check(b.members, b.sanitizer.originals(), [str(d)], b.sanitizer.secret_values)
    text = all_text(b.members)
    assert "rhel_ipa02" not in text and "/dev/mapper/rhel_HOST-" in text
