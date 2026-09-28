"""Reproductions from the third fresh security review of the support bundle (credential shapes and identities)."""

from __future__ import annotations

import gzip
import io
import json
import tarfile

import pytest

from ipa_diagnose.bundle import archive
from ipa_diagnose.bundle.build import build
from ipa_diagnose.bundle.sanitize import Sanitizer, find_secrets
from ipa_diagnose.evidence.model import EnvironmentInfo, EvidenceBundle, Finding, Provenance, Severity
from ipa_diagnose.engine.run import run_diagnosis

from tests.bundle.helpers import all_text


def _san(*texts, host="ipa01.example.test"):
    s = Sanitizer()
    s.add_host(host, force=True)
    s.add_domain(host.split(".", 1)[1], force=True)
    s.add_realm(host.split(".", 1)[1].upper(), force=True)
    for t in texts:
        s.discover(t)
    return s


@pytest.mark.parametrize("text,secret", [
    ("ldapsearch -x -D 'cn=Directory Manager' -w 'zqhorse zqbattery zqstaple' -b cn=config", "zqbattery"),
    ("ldapsearch -x -b cn=" + "a" * 320 + " -w ZqFarPw9 uid", "ZqFarPw9"),
    ("com.example.application.database.connection.primary.password=ZqLongKey1", "ZqLongKey1"),
    ("password_for_the_directory_manager_account_on_this_replica=ZqLongKey2", "ZqLongKey2"),
    ("password: no ZqBool5 is the answer", "ZqBool5"),
    ("ldaps://admin:Zq@Pw3xyz@db.corp.example.com", "Pw3xyz"),
    ("https://admin:Zq/Pw4xyz@db.corp.example.com/x", "Pw4xyz"),
    ("ipa-replica-install --bindpw ZqBindPw9", "ZqBindPw9"),
    ("Enter Password (again): ZqPrompt6", "ZqPrompt6"),
    ("pássword=ZqComb12", "ZqComb12"),
    ("keytab data: BQIAAABHAAIADEVYQU1QTEU", "BQIAAABH"),
])
def test_credential_shapes_from_round_three_are_redacted(text, secret):
    assert secret not in _san().text(text)


@pytest.mark.parametrize("key", ["PINCODE", "Kennwort", "session_id", "pássword"])
def test_more_secret_field_names_are_removed(key):
    assert list(_san().transform({key: "ZqKey8"}).values()) == ["[REMOVED]"]


@pytest.mark.parametrize("text", [
    "_kpasswd._tcp.example.test.:ipa01.example.test.", "krbPasswordExpiration: 20270101000000Z",
    "IPAProxySecretCheck: the proxy secret matches", "Password expired: user must change it",
])
def test_the_line_rule_leaves_metadata_alone(text):
    assert not [f for f in find_secrets(text) if f[0] == "secret_line"], text


def test_ips_with_leading_zeros_or_after_an_underscore():
    texts = ["peer 010.066.077.088 down", "host_10.1.2.3 up"]
    s = _san(*texts)
    out = " ".join(s.text(t) for t in texts)
    assert "066" not in out and "10.1.2.3" not in out and "IP-" in out


def test_lab_style_top_level_labels_are_hosts():
    s = _san("replica ipa02.corp.lab unreachable")
    assert "corp.lab" not in s.text("replica ipa02.corp.lab unreachable")


def test_a_diagnosed_host_inside_a_well_known_public_domain_is_still_pseudonymized():
    host = "ipa01.iad2.fedoraproject.org"
    ev = EvidenceBundle(hostname=host, collected_at="2026-09-27T00:00:00Z",
                        environment=EnvironmentInfo(distro="fedora", distro_version="43"),
                        findings=[Finding("f1", "ipahealthcheck.ds.replication", "ReplicationCheck", Severity.ERROR,
                                          f"replica ipa02.iad2.fedoraproject.org unreachable from {host}",
                                          keywords={}, provenance=Provenance(source="ipa-healthcheck", live=True))])
    report = run_diagnosis(ev)
    b = build(ev, report, created_at="2026-09-27T00:00:00Z")
    text = all_text(b.members)
    assert "iad2" not in text and "ipa01" not in text and "ipa02" not in text
    assert json.loads(b.members["environment.json"])["host"] == "HOST-001"


def _archive(entries):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, data in entries:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def test_validate_refuses_deeply_nested_json_without_crashing(tmp_path):
    deep = ("[" * 900 + "]" * 900).encode()
    p = tmp_path / "deep.tar.gz"
    p.write_bytes(_archive([("ipa-diagnose-bundle/manifest.json", deep)]))
    v = archive.validate(str(p))
    assert not v.valid and any("manifest.json is not valid JSON" in x for x in v.problems)
