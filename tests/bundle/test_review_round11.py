"""Reproductions from the eleventh fresh privacy review of the support bundle."""

from __future__ import annotations

import json

import pytest

from ipa_diagnose.bundle.build import build
from ipa_diagnose.bundle.sanitize import Sanitizer
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.model import EnvironmentInfo, EvidenceBundle, EvidenceItem, Finding, Provenance, Severity

from tests.bundle.helpers import all_text


def _san(*texts, host="ipa01.example.test"):
    s = Sanitizer()
    s.add_host(host, force=True)
    s.add_domain(host.split(".", 1)[1], force=True)
    s.add_realm(host.split(".", 1)[1].upper(), force=True)
    for t in texts:
        s.discover(t)
    return s


@pytest.mark.parametrize("text,leaked", [
    ("cn=zqfinance-admins+nsuniqueid=66446001-1dd211b2-a527ce8b-8fa47d35,cn=groups,cn=accounts,dc=example,dc=test",
     "zqfinance"),
    ("cn=zqpayroll-servers+nsuniqueid=66446002-1dd211b2-a527ce8b-8fa47d35,cn=hostgroups,cn=accounts,dc=example,dc=test",
     "zqpayroll"),
    ("cn=Zq Gina Smith+nsuniqueid=1-2-3-4,cn=users,cn=accounts,dc=example,dc=test", "Gina"),
    ('Replication agreement "meTozqpeer9.zqacme.intra" failed', "zqpeer9"),
    ("Principal zqsvc2/zqapp2.example.test not found", "zqsvc2"),
])
def test_round_eleven_identities(text, leaked):
    assert leaked.lower() not in _san(text).text(text).lower()


@pytest.mark.parametrize("text", [
    "retry via http://svcproxy:ZqCanaryPwAlongsecretvalu",          # cut before the '@' upstream
    "at ldaps://svc_lookup:ZqCanaryPwClongsecretvalue... and more",
])
def test_a_url_password_cut_before_its_at_sign_is_redacted(text):
    assert "ZqCanaryPw" not in _san().text(text)


@pytest.mark.parametrize("text", ["ldap://ipa01.example.test:389", "http://proxy:3128/", "https://[fd00::1]:443/"])
def test_urls_with_a_port_are_not_mistaken_for_cut_credentials(text):
    assert "REDACTED" not in _san().text(text)


def test_the_bundle_uses_unshortened_text_where_the_report_shortened_it():
    long_line = "x " * 150 + "ldaps://svc:ZqCanaryPwLongValue@ad.example.test/ failed"
    ev = EvidenceBundle(
        hostname="ipa01.example.test", collected_at="2026-09-27T00:00:00Z",
        environment=EnvironmentInfo(distro="fedora", distro_version="43"),
        findings=[Finding("t1", "ipahealthcheck.ipa.trust", "IPATrustDomainsCheck", Severity.WARNING,
                          "Lookup failed: {error}", keywords={"error": long_line},
                          provenance=Provenance(source="ipa-healthcheck", live=True)),
                  Finding("s1", "ipahealthcheck.ds.replication", "ReplicationCheck", Severity.SUCCESS, "", {}),
                  Finding("s2", "ipahealthcheck.ipa.certs", "IPACertmongerExpirationCheck", Severity.SUCCESS, "", {})],
        items=[EvidenceItem("journal_pki.1", "pki_journal_line", long_line[:200], data={"line": long_line})])
    report = run_diagnosis(ev)
    b = build(ev, report, created_at="2026-09-27T00:00:00Z")
    text = all_text(b.members)
    assert "ZqCanaryPw" not in text
    item = json.loads(b.members["evidence.json"])["items"][0]
    assert item["summary"].startswith("[shortened by the collector")
