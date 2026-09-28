"""Reproductions from the sixth fresh reviews: privacy (patterns, withheld free text) and archive/runtime safety."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import tarfile

import pytest

from ipa_diagnose import cli
from ipa_diagnose.bundle import archive
from ipa_diagnose.bundle.build import MEMBERS, TOP_DIR, build
from ipa_diagnose.bundle.sanitize import Sanitizer

from tests.bundle.helpers import ROOT, all_text, diagnose_replay
from tests.bundle.test_review_round5 import _bundle_with_kw

T0 = "2026-09-27T00:00:00Z"
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX ownership")


def _san(*texts, host="ipa01.example.test"):
    s = Sanitizer()
    s.add_host(host, force=True)
    s.add_domain(host.split(".", 1)[1], force=True)
    s.add_realm(host.split(".", 1)[1].upper(), force=True)
    for t in texts:
        s.discover(t)
    return s


# --- privacy -------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("text,leaked", [
    ("kinit failed for zqalice7@EXAMPLE.TEST.", "zqalice7"),
    ("zqalice10@EXAMPLE.TEST-issued", "zqalice10"),
    ("mail sent to zqbob11@ZQFIRMA11.COM.", "zqbob11"),
    ("cache at redis://:ZqCanary1x@cache.example.test:6379/0 failed", "ZqCanary1x"),
    ("vars:\npassword: |-\n  ZqCanary60x\nnext: 1", "ZqCanary60x"),
    ("bind_password: >-\n  ZqCanary61x", "ZqCanary61x"),
    ("pk12util -i /tmp/a.p12 -d /etc/pki/nssdb -K ZqCanary63x failed", "ZqCanary63x"),
    ("ran ldappasswd -x -W -s ZqCanary62x failed", "ZqCanary62x"),
    ("connecting...10.44.55.66 failed", "10.44.55.66"),
    ("keytab lacks HTTP/zqweb9.zqcorp9.com entry", "zqweb9"),
    ("missing /etc/pki/tls/zqweb17.zqcorp17.com.pem", "zqweb17"),
    ("see https://ipa01.example.test/ipa owner:zqbob8@zqfirma8.com", "zqbob8"),
    ("sent Bearer ZqCanaryOpaqueTokenValue", "ZqCanaryOpaqueTokenValue"),
    ("bindpw Change.ZqCanary2x", "ZqCanary2x"),
    ("echo -n ZqCanary70x | kinit admin", "ZqCanary70x"),
    ("uid: zqalice16", "zqalice16"),
])
def test_round_six_shapes(text, leaked):
    out = _san(text).text(text)
    assert leaked.lower() not in out.lower(), out


def test_basic_authentication_prose_is_not_redacted():
    assert _san().text("uses Basic authentication") == "uses Basic authentication"


def test_a_host_prefixed_like_an_agreement_is_its_own_host():
    text = "zqdb15.example.test and metozqdb15.example.test"
    out = _san(text).text(text)
    a, b = out.split(" and ")
    assert a != b and "zqdb15" not in out


@pytest.mark.parametrize("kw", [{"pincode": "4821"}, {"userPIN": "4821"}, {"otp_code": "48213"}])
def test_short_secret_field_values_are_tracked(tmp_path, kw):
    b = _bundle_with_kw(tmp_path, kw)
    # as a whole token, like the self-test: a 4-digit value can occur by chance inside a SHA-256 digest
    value = list(kw.values())[0]
    assert not re.search(r"(?<![0-9A-Za-z])" + value + r"(?![0-9A-Za-z])", all_text(b.members))


def test_free_text_of_unknown_checks_is_withheld_and_quoting_prose_regenerated(tmp_path):
    b = _bundle_with_kw(tmp_path, {"msg": "zqsecretwordzz plain", "note": "zqotherzz"})
    text = all_text(b.members)
    assert "zqsecretwordzz" not in text and "zqotherzz" not in text
    hc = json.loads(b.members["healthcheck.json"])
    probe = [f for f in hc["findings"] if f["check"] == "ProbeCheck"][0]
    assert probe["message"].startswith("[WITHHELD") and probe["keywords"] == {"withheld_field_names": ["note"]}
    rep = json.loads(b.members["report.json"])
    why = [d["why"] for d in rep["diagnoses"] if d["rule_id"] == "unexplained-findings"][0]
    assert "ipahealthcheck.zzz.probe.ProbeCheck (ERROR)" in why and "Rewritten for the bundle" in why


# --- archive / runtime ---------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def good():
    ev, report = diagnose_replay(ROOT / "replication" / "peer-unreachable")
    b = build(ev, report, created_at=T0)
    return b.members


def _raw_tar(members):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for n in MEMBERS:
            ti = tarfile.TarInfo(f"{TOP_DIR}/{n}")
            ti.size = len(members[n])
            tar.addfile(ti, io.BytesIO(members[n]))
    return raw.getvalue()


def _header(name, typ=tarfile.REGTYPE, data=b"", link=""):
    ti = tarfile.TarInfo(name)
    ti.type, ti.size, ti.linkname = typ, len(data), link
    blk = ti.tobuf(format=tarfile.USTAR_FORMAT)
    return blk + data + b"\0" * ((512 - len(data) % 512) % 512)


@pytest.mark.parametrize("gap", [b"X" * 512, b"\0" * 512])
def test_entries_hidden_after_an_unreadable_or_zero_block_are_refused(tmp_path, good, gap):
    body = _raw_tar(good).rstrip(b"\0")
    body += b"\0" * ((512 - len(body) % 512) % 512)
    evil = body + gap + _header(f"{TOP_DIR}/evil-link", tarfile.SYMTYPE, link="/etc/shadow") + b"\0" * 1024
    p = tmp_path / "hidden.tgz"
    p.write_bytes(gzip.compress(evil, mtime=0))
    v = archive.validate(str(p))
    assert not v.valid and any("after the last readable archive entry" in x for x in v.problems)


def test_a_manifest_member_name_that_is_not_a_string_does_not_crash(tmp_path, good):
    m = json.loads(good["manifest.json"])
    m["members"][0]["name"] = ["x"]
    members = dict(good, **{"manifest.json": json.dumps(m).encode()})
    members["SHA256SUMS"] = "".join(f"{hashlib.sha256(members[n]).hexdigest()}  {n}\n"
                                    for n in MEMBERS if n != "SHA256SUMS").encode()
    p = tmp_path / "b.tgz"
    p.write_bytes(gzip.compress(_raw_tar(members), mtime=0))
    v = archive.validate(str(p))
    assert not v.valid


def test_validation_work_is_bounded(tmp_path, good, monkeypatch):
    monkeypatch.setattr(archive, "MAX_SCAN_STRINGS", 1000)
    ev = json.loads(good["evidence.json"])
    ev["x"] = ["ab"] * 5000
    members = dict(good, **{"evidence.json": json.dumps(ev).encode()})
    p = tmp_path / "b.tgz"
    p.write_bytes(gzip.compress(_raw_tar(members), mtime=0))
    v = archive.validate(str(p))
    assert not v.valid and any("too large to check within the validation limits" in x for x in v.problems)


def test_an_infinite_number_is_not_valid_json(tmp_path, good):
    m = json.loads(good["manifest.json"])
    text = json.dumps(m).replace('"overall_status": "DEGRADED"', '"overall_status": 1e999')
    members = dict(good, **{"manifest.json": text.encode()})
    p = tmp_path / "b.tgz"
    p.write_bytes(gzip.compress(_raw_tar(members), mtime=0))
    v = archive.validate(str(p))
    assert not v.valid and not v.summary


@posix_only
def test_an_unwritable_output_is_refused_with_exit_5(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))

    def boom(*a, **k):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(archive.tempfile, "mkstemp", boom)
    assert cli.main(["bundle", "--replay", str(ROOT / "replication" / "peer-unreachable"),
                     "-o", str(tmp_path / "b.tgz")]) == 5
    assert "Permission denied" in capsys.readouterr().out and not (tmp_path / "b.tgz").exists()


@posix_only
@pytest.mark.skipif(os.name != "nt" and os.geteuid() != 0, reason="needs root to hand a directory to another uid")
def test_a_directory_owned_by_another_user_is_refused(tmp_path, monkeypatch):
    other = tmp_path / "other"
    other.mkdir()
    os.chown(other, 4242, 4242)
    monkeypatch.delenv("SUDO_UID", raising=False)
    with pytest.raises(archive.OutputRefused, match="belongs to another user"):
        archive.write_new_file(other / "b.tgz", b"x")
    monkeypatch.setenv("SUDO_UID", "4242")  # the user who ran sudo, in their own directory
    assert archive.write_new_file(other / "b.tgz", b"x").exists()


def test_dash_dash_bundle_keeps_replay(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("IPA_DIAGNOSE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.chdir(tmp_path)
    assert cli.main(["--replay", str(ROOT / "replication" / "peer-unreachable"), "--json", "--", "bundle"]) == 0
    assert json.loads(capsys.readouterr().out)["source_mode"] == "REPLAY"
