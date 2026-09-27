"""Reproductions from the seventh fresh privacy review of the support bundle."""

from __future__ import annotations

import pytest

from ipa_diagnose.bundle import selftest
from ipa_diagnose.bundle.sanitize import Sanitizer


def _san(*texts, host="ipa01.example.test"):
    s = Sanitizer()
    s.add_host(host, force=True)
    s.add_domain(host.split(".", 1)[1], force=True)
    s.add_realm(host.split(".", 1)[1].upper(), force=True)
    for t in texts:
        s.discover(t)
    return s


@pytest.mark.parametrize("text,secret", [
    ("{uri: ldaps://u:ZqCanary1@db.acme.com:636}", "ZqCanary1"),
    ("use `ldaps://u:ZqCanary1@db.acme.com:636`", "ZqCanary1"),
    ("ldaps://u:ZqCanary1@db.acme.com:636|ok", "ZqCanary1"),
    ("ldaps://u:ZqCanary1@db.acme.com:636!", "ZqCanary1"),
    ("ldaps://admin:ZqCanary1@ipa02.example.test:636&timeout=30", "ZqCanary1"),
    ("GET ldap://u:ZqCanary1@db.acme.com&b=1", "ZqCanary1"),
    ("https://p.acme.com/?u=http://u:ZqCanary1@db.acme.com&b=1", "ZqCanary1"),
    ("The password for Directory Manager is ZqCanary1", "ZqCanary1"),
    ("password for user admin is ZqCanary1.", "ZqCanary1"),
    ("passwords are ZqCanary1", "ZqCanary1"),
    ("ldapexop -x -D 'cn=Directory Manager' -w ZqCanary1 whoami", "ZqCanary1"),
    ("ldapvc -x -D cn=dm -w ZqCanary1 cn=x", "ZqCanary1"),
    ("dsidm -D 'cn=Directory Manager' -w ZqCanary1 slapd-X user list", "ZqCanary1"),
])
def test_round_seven_credential_shapes(text, secret):
    assert secret not in _san(text).text(text)


@pytest.mark.parametrize("text,label", [
    ("trust DCs zqdc1.ad.acme.corp and zqdc2.ad.acme.corp down", "zqdc2"),
    ("zqa.acme.com replicates to zqsecret.sub.acme.com", "zqsecret"),
    ("answers 0 100 389 zqa.acme.com. 0 100 389 zqhost07.acme.com.", "zqhost07"),
])
def test_every_host_of_a_domain_learned_in_the_same_text_is_pseudonymized(text, label):
    assert label not in _san(text).text(text)


def test_agreement_and_peer_in_a_new_domain_keep_their_relationship():
    text = "cn=meTozqpeer9.acme.corp,cn=replica failed; zqpeer9.acme.corp unreachable"
    out = _san(text).text(text)
    peer = out.rsplit("; ", 1)[1].split()[0]
    assert "zqpeer9" not in out and f"cn=meTo{peer}," in out


def test_the_self_test_catches_a_host_label_left_next_to_a_domain_pseudonym():
    members = {"report.json": b'{"note": "peer zqleft.DOMAIN-002 down"}'}
    with pytest.raises(selftest.LeakDetected) as e:
        selftest.check(members, [])
    assert ("report.json", "host name label next to a domain pseudonym") in e.value.problems
    ok = {"report.json": b'{"note": "_kerberos._udp.DOMAIN-001 and ipa-ca.DOMAIN-001"}'}
    selftest.check(ok, [])
