"""Bundle archives: safe output-file creation, and validation that treats a received bundle as hostile."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import stat
import tarfile

import pytest

from ipa_diagnose.bundle import archive
from ipa_diagnose.bundle.build import MEMBERS, TOP_DIR, build

from tests.bundle.helpers import ROOT, diagnose_replay

T0 = "2026-09-26T12:00:00Z"
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes and links")


@pytest.fixture(scope="module")
def good():
    ev, report = diagnose_replay(ROOT / "replication" / "peer-unreachable")
    b = build(ev, report, created_at=T0)
    return b.members, archive.make_archive(b.members, T0)


def _tar(entries, gz=True):
    """entries: list of (TarInfo-name, bytes, type) - builds a hostile archive by hand."""

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, data, typ in entries:
            ti = tarfile.TarInfo(name)
            ti.type = typ
            if typ in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                ti.linkname = "/etc/passwd"
                tar.addfile(ti)
            elif typ == tarfile.DIRTYPE:
                tar.addfile(ti)
            else:
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0) if gz else raw.getvalue()


def _rebuild(members, **changes):
    members = dict(members)
    members.update(changes)
    return _tar([(f"{TOP_DIR}/{n}", members[n], tarfile.REGTYPE) for n in MEMBERS if n in members])


def _resum(members):
    """Recompute SHA256SUMS and manifest checksums, as an attacker editing the bundle could."""

    members = dict(members)
    m = json.loads(members["manifest.json"])
    for e in m["members"]:
        e["sha256"] = hashlib.sha256(members[e["name"]]).hexdigest()
        e["bytes"] = len(members[e["name"]])
    members["manifest.json"] = (json.dumps(m, indent=2) + "\n").encode()
    members["SHA256SUMS"] = "".join(f"{hashlib.sha256(members[n]).hexdigest()}  {n}\n"
                                    for n in MEMBERS if n != "SHA256SUMS").encode()
    return members


def _validate(tmp_path, data, name="b.tar.gz"):
    p = tmp_path / name
    p.write_bytes(data)
    return archive.validate(str(p))


# --- writing ----------------------------------------------------------------------------------------------------
@posix_only
def test_written_bundle_is_0600_and_never_overwrites(tmp_path, good):
    _, data = good
    path = archive.write_new_file(tmp_path / "b.tar.gz", data)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600 and path.read_bytes() == data
    with pytest.raises(archive.OutputRefused, match="already exists"):
        archive.write_new_file(tmp_path / "b.tar.gz", b"other")
    assert path.read_bytes() == data
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".partial")]


@posix_only
def test_a_symlink_at_the_output_path_is_refused_and_its_target_untouched(tmp_path, good):
    _, data = good
    target = tmp_path / "victim"
    target.write_text("keep")
    (tmp_path / "out.tar.gz").symlink_to(target)
    (tmp_path / "dangling.tar.gz").symlink_to(tmp_path / "nowhere")
    for name in ("out.tar.gz", "dangling.tar.gz"):
        with pytest.raises(archive.OutputRefused):
            archive.write_new_file(tmp_path / name, data)
    assert target.read_text() == "keep" and not (tmp_path / "nowhere").exists()


@posix_only
def test_world_writable_non_sticky_directory_is_refused_sticky_is_fine(tmp_path, good):
    _, data = good
    open_dir = tmp_path / "open"
    open_dir.mkdir()
    os.chmod(open_dir, 0o777)
    with pytest.raises(archive.OutputRefused, match="writable by every user"):
        archive.write_new_file(open_dir / "b.tar.gz", data)
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    os.chmod(sticky, 0o1777)
    assert archive.write_new_file(sticky / "b.tar.gz", data).exists()


def test_missing_parent_is_refused(tmp_path, good):
    with pytest.raises(archive.OutputRefused, match="does not exist"):
        archive.write_new_file(tmp_path / "no" / "such" / "b.tar.gz", good[1])


def test_output_resolution(tmp_path):
    assert archive.resolve_output(None, T0).name == "ipa-diagnose-bundle-20260926T120000Z.tar.gz"
    assert archive.resolve_output(str(tmp_path), T0) == tmp_path / "ipa-diagnose-bundle-20260926T120000Z.tar.gz"
    assert archive.resolve_output(str(tmp_path / "x.tgz"), T0) == tmp_path / "x.tgz"
    assert archive.resolve_output("sub/", T0).parent.name == "sub"


def test_an_interrupted_write_leaves_nothing_behind(tmp_path, good, monkeypatch):
    calls = []

    def boom(fd, data):
        calls.append(1)
        raise KeyboardInterrupt

    monkeypatch.setattr(archive.os, "write", boom)
    with pytest.raises(KeyboardInterrupt):
        archive.write_new_file(tmp_path / "b.tar.gz", good[1])
    assert calls and list(tmp_path.iterdir()) == []


@posix_only
def test_a_filesystem_without_hard_links_still_gets_an_exclusive_0600_file(tmp_path, good, monkeypatch):
    def no_link(src, dst):
        raise OSError(1, "Operation not permitted")

    monkeypatch.setattr(archive.os, "link", no_link)
    path = archive.write_new_file(tmp_path / "b.tar.gz", good[1])
    assert path.read_bytes() == good[1] and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["b.tar.gz"]


# --- validation ---------------------------------------------------------------------------------------------------
def test_a_genuine_bundle_validates(tmp_path, good):
    v = _validate(tmp_path, good[1])
    assert v.valid, v.problems
    assert v.summary["source_mode"] == "REPLAY" and v.summary["bundle_schema_version"] == 1


def test_a_changed_member_is_detected(tmp_path, good):
    members, _ = good
    tampered = members["report.json"].replace(b"DEGRADED", b"HEALTHY!")
    v = _validate(tmp_path, _rebuild(members, **{"report.json": tampered}))
    assert not v.valid and any("checksum mismatch for report.json" in p for p in v.problems)


def test_recomputed_checksums_are_consistent_but_prove_nothing(tmp_path, good):
    members, _ = good
    forged = _resum(dict(members, **{"report.json": members["report.json"].replace(b"DEGRADED", b"HEALTHY!")}))
    v = _validate(tmp_path, _rebuild(forged))
    assert v.valid  # checksums are integrity against accidents, not authenticity - documented, not claimed


@pytest.mark.parametrize("name", [
    "../evil.json", "/etc/cron.d/evil", f"{TOP_DIR}/../../evil", f"{TOP_DIR}/sub/report.json", "evil.json",
    f"{TOP_DIR}\\report.json", f"{TOP_DIR}/report.json\x00x", f"{TOP_DIR}/répört.json", f"{TOP_DIR}/extra.json",
])
def test_unexpected_or_traversing_names_are_refused(tmp_path, good, name):
    members, _ = good
    entries = [(f"{TOP_DIR}/{n}", members[n], tarfile.REGTYPE) for n in MEMBERS] + [(name, b"{}", tarfile.REGTYPE)]
    v = _validate(tmp_path, _tar(entries))
    assert not v.valid


@pytest.mark.parametrize("typ", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE])
def test_links_devices_and_directories_are_refused(tmp_path, good, typ):
    members, _ = good
    entries = [(f"{TOP_DIR}/{n}", members[n], tarfile.REGTYPE) for n in MEMBERS if n != "report.json"]
    entries.append((f"{TOP_DIR}/report.json", b"", typ))
    v = _validate(tmp_path, _tar(entries))
    assert not v.valid and any("not a regular file" in p for p in v.problems)


def test_duplicate_members_are_refused(tmp_path, good):
    members, _ = good
    entries = [(f"{TOP_DIR}/{n}", members[n], tarfile.REGTYPE) for n in MEMBERS]
    entries.append((f"{TOP_DIR}/report.json", b'{"source_mode": "LIVE"}', tarfile.REGTYPE))
    v = _validate(tmp_path, _tar(entries))
    assert not v.valid and any("duplicate entry" in p for p in v.problems)


def test_decompression_bomb_is_stopped(tmp_path):
    bomb = gzip.compress(b"\0" * (archive.MAX_UNCOMPRESSED + 10), mtime=0)
    assert len(bomb) < 1024 * 1024
    v = _validate(tmp_path, bomb)
    assert not v.valid and any("decompresses to more than" in p for p in v.problems)


def test_oversized_file_is_not_read(tmp_path):
    p = tmp_path / "big.tar.gz"
    with open(p, "wb") as fh:
        fh.truncate(archive.MAX_ARCHIVE_BYTES + 1)
    v = archive.validate(str(p))
    assert not v.valid and any("larger than" in pr for pr in v.problems)


@pytest.mark.parametrize("mutate,expect", [
    (lambda d: d + gzip.compress(b"more", mtime=0), "extra data"),
    (lambda d: d + b"trailing", "extra data"),
    (lambda d: d[: len(d) // 2], "truncated"),
    (lambda d: b"PK\x03\x04" + d, "not a gzip"),
    (lambda d: gzip.compress(b"not a tar at all" * 10, mtime=0), "not a readable tar"),
])
def test_damaged_or_appended_archives_are_refused(tmp_path, good, mutate, expect):
    v = _validate(tmp_path, mutate(good[1]))
    assert not v.valid and any(expect in p for p in v.problems), v.problems


@pytest.mark.parametrize("manifest,expect", [
    (b"{not json", "not valid JSON"),
    (b'{"a": 1, "a": 2}', "not valid JSON"),
    (b'{"bundle_format": "ipa-diagnose-support-bundle", "bundle_schema_version": NaN}', "not valid JSON"),
    (b"[]", "not a JSON object"),
    (b'{"bundle_format": "something-else"}', "does not describe"),
    (b'{"bundle_format": "ipa-diagnose-support-bundle", "bundle_schema_version": 2}', "schema 2 is not supported"),
    (b'{"bundle_format": "ipa-diagnose-support-bundle", "bundle_schema_version": true}', "no valid bundle_schema_version"),
])
def test_malformed_or_future_manifests_are_refused(tmp_path, good, manifest, expect):
    members, _ = good
    v = _validate(tmp_path, _rebuild(dict(members, **{"manifest.json": manifest})))
    assert not v.valid and any(expect in p for p in v.problems), v.problems


def test_unknown_manifest_fields_are_a_warning_only(tmp_path, good):
    members, _ = good
    m = json.loads(members["manifest.json"])
    m["future_field"] = {"x": 1}
    changed = dict(members, **{"manifest.json": (json.dumps(m) + "\n").encode()})
    changed["SHA256SUMS"] = "".join(f"{hashlib.sha256(changed[n]).hexdigest()}  {n}\n"
                                    for n in MEMBERS if n != "SHA256SUMS").encode()
    v = _validate(tmp_path, _rebuild(changed))
    assert v.valid and v.warnings


def test_a_member_claiming_a_different_source_mode_is_refused(tmp_path, good):
    members, _ = good
    rep = json.loads(members["report.json"])
    rep["source_mode"] = "LIVE"
    v = _validate(tmp_path, _rebuild(_resum(dict(members, **{"report.json": json.dumps(rep).encode()}))))
    assert not v.valid and any("source_mode" in p for p in v.problems)


def test_a_received_bundle_with_credentials_or_escapes_is_flagged(tmp_path, good):
    members, _ = good
    rep = json.loads(members["report.json"])
    rep["note"] = "password=Hunter2xyz \x1b]0;title\x07"
    v = _validate(tmp_path, _rebuild(_resum(dict(members, **{"report.json": json.dumps(rep).encode()}))))
    assert not v.valid
    assert any("credential pattern" in p for p in v.problems) and any("control or format" in p for p in v.problems)
    assert not any("Hunter2xyz" in p for p in v.problems)  # the value itself is never echoed


def test_nested_archives_are_refused(tmp_path, good):
    members, _ = good
    v = _validate(tmp_path, _rebuild(_resum(dict(members, **{"evidence.json": gzip.compress(b"{}")}))))
    assert not v.valid and any("nested archive" in p for p in v.problems)


def test_missing_members_are_refused(tmp_path, good):
    members, _ = good
    entries = [(f"{TOP_DIR}/{n}", members[n], tarfile.REGTYPE) for n in MEMBERS if n != "topology.json"]
    v = _validate(tmp_path, _tar(entries))
    assert not v.valid and any("missing members: topology.json" in p for p in v.problems)


@posix_only
def test_non_regular_paths_are_not_opened(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert not archive.validate(str(fifo)).valid
    assert not archive.validate(str(tmp_path)).valid
    assert not archive.validate(str(tmp_path / "missing")).valid
