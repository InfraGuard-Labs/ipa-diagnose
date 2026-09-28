"""Reproductions from the thirteenth fresh privacy review of the support bundle."""

from __future__ import annotations

import pytest

from ipa_diagnose.bundle.sanitize import Sanitizer


def _deployment(host):
    s = Sanitizer()
    s.own_public_parent(host)
    s.add_host(host, force=True)
    domain = host.split(".", 1)[1]
    s.add_domain(domain, force=True)
    s.add_realm(domain.upper(), force=True)
    return s


def _out(s, *texts):
    for t in texts:
        s.discover(t)
    return [s.text(t) for t in texts]


@pytest.mark.parametrize("host,text,leaked", [
    ("ipa01.iad2.fedoraproject.org", "Replication to cn=meToipa02.rdu3.fedoraproject.org failed", "ipa02"),
    ("ipa01.iad2.fedoraproject.org", "ldap://ipa02.rdu3.fedoraproject.org:389/o=ipaca", "ipa02"),
    ("ipa01.iad2.fedoraproject.org", "_kerberos._udp.fedoraproject.org SRV lookup failed", "fedoraproject"),
    ("ipa01.iad2.fedoraproject.org", 'agmt="cn=meTozqpar.fedoraproject.org" (zqpar:389)', "zqpar"),
    ("ipa01.iad2.fedoraproject.org", "uid=zqbob,cn=users,cn=accounts,dc=fedoraproject,dc=org", "fedoraproject"),
    ("idm01.corp.redhat.com", "peer zqidm02.zqlab.redhat.com unreachable", "zqidm02"),
    ("idm01.corp.redhat.com", "peer zqidm02.zqlab.redhat.com unreachable", "zqlab"),
])
def test_a_deployment_inside_a_public_listed_domain_is_pseudonymized(host, text, leaked):
    s = _deployment(host)
    out = _out(s, "principal HTTP/%s@%s" % (host, host.split(".", 1)[1].upper()), text)[1]
    assert leaked not in out.lower()


def test_public_domains_stay_readable_for_other_deployments():
    s = _deployment("ipa01.example.test")
    out = _out(s, "see https://www.freeipa.org/page/Troubleshooting and docs.fedoraproject.org")[0]
    assert "freeipa.org" in out and "docs.fedoraproject.org" in out


def test_an_email_in_a_public_domain_is_pseudonymized():
    s = _deployment("ipa01.example.test")
    assert "zqcarol" not in _out(s, "SAN contains zqcarol@redhat.com")[0]


@pytest.mark.parametrize("text", [
    'key "ddns" { algorithm hmac-md5; secret "ZqCanary7AbCdEfGh1234=="; };',
    "secret 'ZqCanary7 with spaces'",
])
def test_a_quoted_value_after_the_word_secret_is_redacted(text):
    assert "ZqCanary7" not in _out(_deployment("ipa01.example.test"), text)[0]
