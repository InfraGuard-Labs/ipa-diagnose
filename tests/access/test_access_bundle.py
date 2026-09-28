"""`ipa-diagnose bundle --access USER HOST SERVICE`: the access answer as an optional, pseudonymized bundle member."""

from __future__ import annotations

import json
import shutil

import pytest

from ipa_diagnose.bundle.archive import validate
from ipa_diagnose.cli import main
from tests.access.helpers import World
from tests.bundle.helpers import ROOT, members_of

NAMES = ("zqjohnuser", "zqwebfarm", "zqbackendteam", "zqdevsgroup", "zqapp03host", "zqsecretrule", "zqcustomsvc",
         "zqcanary-dom")


def fixture(tmp_path):
    """A recorded diagnosis fixture plus recorded access answers, all on canary names."""

    d = tmp_path / "fx"
    shutil.copytree(ROOT / "replication" / "peer-unreachable", d)
    w = (World().user("zqjohnuser", ["zqbackendteam"]).group("zqbackendteam", ["zqdevsgroup"]).group("zqdevsgroup")
         .host("zqapp03host.zqcanary-dom.test", ["zqwebfarm"]).hostgroup("zqwebfarm").service("zqcustomsvc")
         .rule("zqsecretrule", groups=["zqdevsgroup"], hostgroups=["zqwebfarm"], services=["zqcustomsvc"]))
    w.meta.update(server="ipa01.zqcanary-dom.test", domain="zqcanary-dom.test", realm="ZQCANARY-DOM.TEST",
                  principal="admin@ZQCANARY-DOM.TEST")
    w.write(d, "zqjohnuser", "zqapp03host.zqcanary-dom.test", "zqcustomsvc")
    return d


def test_bundle_with_access_is_pseudonymized_valid_and_commandless(tmp_path, capsys):
    d = fixture(tmp_path)
    out = tmp_path / "b.tar.gz"
    code = main(["bundle", "--replay", str(d), "--output", str(out), "--access", "zqjohnuser",
                 "zqapp03host.zqcanary-dom.test", "zqcustomsvc"])
    assert code == 0, capsys.readouterr().out
    members = members_of(out.read_bytes())
    assert "access.json" in members
    blob = "\n".join(m.decode("utf-8") for m in members.values())
    for name in NAMES:
        assert name not in blob.lower(), name
    acc = json.loads(members["access.json"])
    assert acc["source_mode"] == "REPLAY"
    assert acc["hbac_policy_decision"] == {"state": "PASS", "decided_by": "FreeIPA hbactest"}
    assert acc["resolution"] == {"status": "NONE", "commands_included": False}
    side = acc["rules"][0]["sides"]["user"][0]
    assert side["how"] == "nested_group" and len(side["chain"]) == 3 and all(
        c.startswith(("USER-", "GROUP-")) for c in side["chain"])
    assert acc["authoritative_evaluation"]["matched_rules"] == [acc["rules"][0]["rule"]]
    assert "ipa hbactest" not in blob and "sssctl" not in blob
    v = validate(str(out))
    assert v.valid, v.problems


def test_bundle_without_access_has_no_access_member_and_stays_valid(tmp_path, capsys):
    d = fixture(tmp_path)
    out = tmp_path / "b.tar.gz"
    assert main(["bundle", "--replay", str(d), "--output", str(out)]) == 0
    members = members_of(out.read_bytes())
    assert "access.json" not in members
    assert validate(str(out)).valid


def test_bundle_access_targets_are_validated(tmp_path, capsys):
    d = fixture(tmp_path)
    with pytest.raises(SystemExit) as e:
        main(["bundle", "--replay", str(d), "--preview", "--access", "all", "h.zqcanary-dom.test", "sshd"])
    assert e.value.code == 2


def test_validate_refuses_an_access_member_with_a_changed_checksum(tmp_path, capsys):
    import gzip
    import io
    import tarfile

    d = fixture(tmp_path)
    out = tmp_path / "b.tar.gz"
    assert main(["bundle", "--replay", str(d), "--output", str(out), "--access", "zqjohnuser",
                 "zqapp03host.zqcanary-dom.test", "zqcustomsvc"]) == 0
    raw = gzip.decompress(out.read_bytes())
    src = tarfile.open(fileobj=io.BytesIO(raw))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as dst:
        for ti in src:
            data = src.extractfile(ti).read()
            if ti.name.endswith("access.json"):
                data = data.replace(b'"PASS"', b'"FAIL"', 1)
                ti.size = len(data)
            dst.addfile(ti, io.BytesIO(data))
    bad = tmp_path / "bad.tar.gz"
    bad.write_bytes(gzip.compress(buf.getvalue()))
    v = validate(str(bad))
    assert not v.valid and any("access.json" in p for p in v.problems)
