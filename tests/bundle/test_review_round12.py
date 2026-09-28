"""Reproductions from the twelfth fresh privacy review of the support bundle."""

from __future__ import annotations

import json
import shutil

import pytest

from ipa_diagnose.bundle import selftest
from ipa_diagnose.bundle.build import build
from ipa_diagnose.evidence.collectors.ldap_query import _parse_conflict_ldif
from ipa_diagnose.evidence.model import Provenance

from tests.bundle.helpers import ROOT, all_text, diagnose_replay


def _bundle_with(tmp_path, fixture, extra_findings=(), conflicts=None):
    d = tmp_path / "fx"
    shutil.copytree(ROOT / fixture, d)
    hc = json.loads((d / "healthcheck.json").read_text(encoding="utf-8"))
    hc.extend(extra_findings)
    (d / "healthcheck.json").write_text(json.dumps(hc), encoding="utf-8")
    if conflicts is not None:
        lq = json.loads((d / "ldap_query.json").read_text(encoding="utf-8"))
        lq["conflicts"] = conflicts
        (d / "ldap_query.json").write_text(json.dumps(lq), encoding="utf-8")
    ev, rep = diagnose_replay(d)
    b = build(ev, rep, created_at="2026-09-27T00:00:00Z")
    selftest.check(b.members, b.sanitizer.originals(), [str(d)], b.sanitizer.secret_values)
    return all_text(b.members)


def _ownership(check, kind, got, uuid):
    what = "Ownership" if kind == "owner" else "Group"
    return {"source": "ipahealthcheck.ipa.files" if check != "TomcatFileCheck" else "ipahealthcheck.dogtag.ca",
            "check": check, "result": "WARNING", "uuid": uuid, "when": "20260101120000Z", "duration": "0.1",
            "kw": {"key": "_etc_ipa_ca.crt_" + kind, "path": "/etc/ipa/ca.crt", "type": kind, "expected": "root",
                   "got": got, "msg": f"{what} of /etc/ipa/ca.crt is {got} and should be root"}}


@pytest.mark.parametrize("check,kind,name", [
    ("IPAFileCheck", "owner", "zqalicez"),
    ("IPAFileCheck", "group", "zqfinops"),
    ("TomcatFileCheck", "owner", "jdoe7"),
    ("IPAFileNSSDBCheck", "group", "hr-payroll"),
])
def test_the_owner_or_group_of_a_file_finding_is_pseudonymized(tmp_path, check, kind, name):
    text = _bundle_with(tmp_path, "directory-server/permissions", [_ownership(check, kind, name, "own1")])
    assert name not in text


def test_several_expected_owners_are_each_pseudonymized(tmp_path):
    f = _ownership("IPAFileCheck", "owner", "zqowner1", "own2")
    f["kw"]["expected"] = "root,zqowner2"
    text = _bundle_with(tmp_path, "directory-server/permissions", [f])
    assert "zqowner1" not in text and "zqowner2" not in text
    assert "root" in text  # a system account keeps its name


def _fold(line, width=76):
    out, rest = [line[:width]], line[width:]
    while rest:
        out.append(" " + rest[:width - 1])
        rest = rest[width - 1:]
    return "\n".join(out)


def test_folded_conflict_ldif_is_unfolded():
    dn = ("cn=linux-server-administrators+nsuniqueid=66446001-1dd211b2-a527ce8b-8fa47d35,"
          "cn=groups,cn=accounts,dc=zqacme,dc=test")
    msg = "namingConflict (ADD) uid=zqa,cn=users,cn=accounts,dc=zqacme,dc=test"
    ldif = _fold("dn: " + dn) + "\n" + _fold("nsds5ReplConflict: " + msg) + "\n\n"
    items = _parse_conflict_ldif(ldif, Provenance(source="ldapsearch", live=True))
    assert items[0].data == {"dn": dn, "message": msg}


def test_base64_conflict_dn_is_decoded():
    import base64

    dn = "cn=Zq Grüppe+nsuniqueid=1-2-3-4,cn=groups,cn=accounts,dc=example,dc=test"
    ldif = "dn:: " + base64.b64encode(dn.encode()).decode() + "\n\n"
    assert _parse_conflict_ldif(ldif, Provenance(source="ldapsearch", live=True))[0].data["dn"] == dn


def test_a_long_conflict_group_name_is_pseudonymized(tmp_path):
    dn = ("cn=linux-server-administrators+nsuniqueid=66446001-1dd211b2-a527ce8b-8fa47d35,"
          "cn=groups,cn=accounts,dc=example,dc=test")
    ldif = _fold("dn: " + dn) + "\n\n"
    item = _parse_conflict_ldif(ldif, Provenance(source="ldapsearch", live=True))[0]
    text = _bundle_with(tmp_path, "replication/conflicting", conflicts=[item.data])
    assert "linux-server-administrators" not in text
