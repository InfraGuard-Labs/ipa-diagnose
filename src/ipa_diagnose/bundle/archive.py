"""Bundle archive: deterministic tar.gz writing, safe output-file creation, and validation of received bundles.

Format: a gzip-compressed USTAR tar (Python standard library only) holding exactly the members in build.MEMBERS
under one fixed directory, ipa-diagnose-bundle/. Every entry is a regular file with mode 0644, uid/gid 0, empty
user/group names and the bundle's creation time as mtime; the gzip header carries no file name and mtime 0. Nothing
about the creating user, host, working directory or source files is recorded in archive metadata.

Validation treats a received bundle as hostile: it never extracts anything to disk, decompresses within fixed limits,
accepts only the expected member names as regular files, and checks structure, checksums and content.
"""

from __future__ import annotations

import calendar
import dataclasses
import errno
import gzip
import hashlib
import io
import json
import os
import pathlib
import stat
import tarfile
import tempfile
import time
import zlib
from typing import Any, Dict, List, Optional

from ipa_diagnose.bundle.build import BUNDLE_FORMAT, BUNDLE_SCHEMA_VERSION, LIMITS, MEMBERS, TOP_DIR
from ipa_diagnose.bundle.selftest import scan_text

MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_UNCOMPRESSED = LIMITS["total_bytes"] + 1024 * 1024
MAX_ENTRIES = 64
_MAGIC = (b"\x1f\x8b", b"PK\x03\x04", b"BZh", b"\xfd7zXZ", b"7z\xbc\xaf", b"\x28\xb5\x2f\xfd")


class OutputRefused(Exception):
    pass


def _epoch(created_at: str) -> int:
    try:
        return calendar.timegm(time.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError):
        return 0


def make_archive(members: Dict[str, bytes], created_at: str) -> bytes:
    mtime = _epoch(created_at)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in MEMBERS:
            data = members[name]
            ti = tarfile.TarInfo(f"{TOP_DIR}/{name}")
            ti.size, ti.mtime, ti.mode, ti.type = len(data), mtime, 0o644, tarfile.REGTYPE
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            tar.addfile(ti, io.BytesIO(data))
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def default_name(created_at: str) -> str:
    return "ipa-diagnose-bundle-" + created_at.replace("-", "").replace(":", "") + ".tar.gz"


def resolve_output(output: Optional[str], created_at: str) -> pathlib.Path:
    """The path to create: --output as given, or the default name inside it when it is a directory (or ends in a
    separator), or the default name in the current directory."""

    name = default_name(created_at)
    if not output:
        return pathlib.Path(name)
    if output.endswith(("/", os.sep)) or (os.path.isdir(output) and not os.path.islink(output)):
        return pathlib.Path(output) / name
    return pathlib.Path(output)


def _check_parent(parent: pathlib.Path) -> None:
    try:
        st = os.stat(parent)
    except OSError as e:
        raise OutputRefused(f"the directory {parent} does not exist or cannot be read ({e.strerror})")
    if not stat.S_ISDIR(st.st_mode):
        raise OutputRefused(f"{parent} is not a directory")
    if os.name != "nt" and st.st_mode & stat.S_IWOTH and not st.st_mode & stat.S_ISVTX:
        raise OutputRefused(f"{parent} is writable by every user and not sticky: another user could replace the "
                            "bundle after it is written. Choose another directory.")


def write_new_file(path: pathlib.Path, data: bytes) -> pathlib.Path:
    """Creates `path` with mode 0600 and the given content, atomically where the filesystem allows. Never
    overwrites and never follows a symlink at `path`. On any failure nothing is left at `path`."""

    parent = path.parent if str(path.parent) else pathlib.Path(".")
    _check_parent(parent)
    if os.path.lexists(path):
        raise OutputRefused(f"{path} already exists; it was not overwritten")
    fd, tmp = tempfile.mkstemp(prefix=".ipa-diagnose-bundle-", suffix=".partial", dir=str(parent))
    try:
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(tmp, path)  # atomic, and fails if anything (even a dangling symlink) exists at path
        except FileExistsError:
            raise OutputRefused(f"{path} already exists; it was not overwritten")
        except OSError as e:
            if e.errno not in (errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV, errno.EMLINK, errno.ENOSYS):
                raise
            _write_exclusive(path, data)  # filesystem without hard links
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    if hasattr(os, "O_DIRECTORY"):
        try:
            dfd = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    return path


def _write_exclusive(path: pathlib.Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError:
        raise OutputRefused(f"{path} already exists; it was not overwritten")
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        os.close(fd)
    except BaseException:
        os.close(fd)
        os.unlink(str(path))
        raise


# --- validation of a received bundle --------------------------------------------------------------------------------
@dataclasses.dataclass
class Validation:
    problems: List[str] = dataclasses.field(default_factory=list)
    warnings: List[str] = dataclasses.field(default_factory=list)
    summary: Dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def valid(self) -> bool:
        return not self.problems


def _strict_json(data: bytes) -> Any:
    def no_dupes(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError("duplicate key")
            out[k] = v
        return out

    def no_constants(_name):
        raise ValueError("non-standard number")

    return json.loads(data.decode("utf-8"), object_pairs_hook=no_dupes, parse_constant=no_constants)


def _read_limited(path: pathlib.Path, v: Validation) -> Optional[bytes]:
    try:
        st = os.stat(path)
    except OSError as e:
        v.problems.append(f"cannot read the file ({e.strerror})")
        return None
    if not stat.S_ISREG(st.st_mode):
        v.problems.append("not a regular file")
        return None
    if st.st_size > MAX_ARCHIVE_BYTES:
        v.problems.append(f"larger than {MAX_ARCHIVE_BYTES} bytes")
        return None
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_ARCHIVE_BYTES + 1)
    except OSError as e:
        v.problems.append(f"cannot read the file ({e.strerror})")
        return None
    if len(data) > MAX_ARCHIVE_BYTES:
        v.problems.append(f"larger than {MAX_ARCHIVE_BYTES} bytes")
        return None
    return data


def _gunzip(data: bytes, v: Validation) -> Optional[bytes]:
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(data, MAX_UNCOMPRESSED + 1)
    except zlib.error:
        v.problems.append("not a gzip-compressed bundle (or the compressed data is damaged)")
        return None
    if len(out) > MAX_UNCOMPRESSED or d.unconsumed_tail:
        v.problems.append(f"decompresses to more than {MAX_UNCOMPRESSED} bytes; not read further")
        return None
    if not d.eof:
        v.problems.append("the compressed data is truncated")
        return None
    if d.unused_data:
        v.problems.append("extra data after the compressed bundle (appended or concatenated content)")
        return None
    return out


def _json_strings(value, key=""):
    if isinstance(value, dict):
        for k, val in value.items():
            yield "", str(k)
            yield from _json_strings(val, str(k))
    elif isinstance(value, list):
        for val in value:
            yield from _json_strings(val, key)
    elif isinstance(value, str):
        yield key, value


def validate(path: str) -> Validation:
    v = Validation()
    data = _read_limited(pathlib.Path(path), v)
    if data is None:
        return v
    raw = _gunzip(data, v)
    if raw is None:
        return v
    contents: Dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            for count, ti in enumerate(tar, 1):
                if count > MAX_ENTRIES:
                    v.problems.append(f"more than {MAX_ENTRIES} archive entries")
                    return v
                name = ti.name
                shown = repr(name[:80])
                if ti.pax_headers:
                    v.problems.append(f"entry {shown} carries extended (pax) headers, which this format never uses")
                    continue
                if not (ti.type in (tarfile.REGTYPE, tarfile.AREGTYPE)):
                    v.problems.append(f"entry {shown} is not a regular file (links, devices and directories are "
                                      "refused)")
                    continue
                if (not name.isascii() or "\\" in name or "\x00" in name or name.startswith("/")
                        or ".." in name.split("/") or not name.startswith(TOP_DIR + "/")
                        or name[len(TOP_DIR) + 1:] not in MEMBERS):
                    v.problems.append(f"unexpected entry name {shown}")
                    continue
                member = name[len(TOP_DIR) + 1:]
                if member in contents:
                    v.problems.append(f"duplicate entry {shown}")
                    continue
                if ti.size > LIMITS["member_bytes"]:
                    v.problems.append(f"entry {shown} is larger than {LIMITS['member_bytes']} bytes")
                    continue
                fh = tar.extractfile(ti)
                contents[member] = fh.read(LIMITS["member_bytes"] + 1) if fh else b""
    except (tarfile.TarError, EOFError, OSError, ValueError) as e:
        v.problems.append(f"not a readable tar archive ({type(e).__name__})")
        return v
    missing = [m for m in MEMBERS if m not in contents]
    if missing:
        v.problems.append("missing members: " + ", ".join(missing))
    for name, content in contents.items():
        if content.startswith(_MAGIC):
            v.problems.append(f"{name} contains a nested archive or compressed data")
    _check_sums(contents, v)
    manifest = _check_manifest(contents, v)
    _check_content(contents, manifest, v)
    return v


def _check_sums(contents: Dict[str, bytes], v: Validation) -> None:
    sums = contents.get("SHA256SUMS")
    if sums is None:
        return
    listed: Dict[str, str] = {}
    try:
        lines = sums.decode("ascii").split("\n")
    except UnicodeDecodeError:
        v.problems.append("SHA256SUMS is not plain ASCII")
        return
    if lines[-1] != "":
        v.problems.append("SHA256SUMS does not end with a newline")
    for ln in lines[:-1]:
        parts = ln.split("  ", 1)
        if (len(parts) != 2 or len(parts[0]) != 64 or any(c not in "0123456789abcdef" for c in parts[0])
                or parts[1] not in MEMBERS or parts[1] == "SHA256SUMS"):
            v.problems.append("SHA256SUMS has a malformed line")
            return
        if parts[1] in listed:
            v.problems.append(f"SHA256SUMS lists {parts[1]} twice")
            return
        listed[parts[1]] = parts[0]
    for name in MEMBERS:
        if name == "SHA256SUMS" or name not in contents:
            continue
        if name not in listed:
            v.problems.append(f"SHA256SUMS does not list {name}")
        elif hashlib.sha256(contents[name]).hexdigest() != listed[name]:
            v.problems.append(f"checksum mismatch for {name} (changed after the bundle was created)")


def _check_manifest(contents: Dict[str, bytes], v: Validation) -> Optional[Dict[str, Any]]:
    data = contents.get("manifest.json")
    if data is None:
        return None
    try:
        m = _strict_json(data)
    except (ValueError, RecursionError, UnicodeDecodeError):
        v.problems.append("manifest.json is not valid JSON (duplicate keys and NaN/Infinity are refused)")
        return None
    if not isinstance(m, dict):
        v.problems.append("manifest.json is not a JSON object")
        return None
    if m.get("bundle_format") != BUNDLE_FORMAT:
        v.problems.append("manifest.json does not describe an ipa-diagnose support bundle")
        return None
    ver = m.get("bundle_schema_version")
    if not isinstance(ver, int) or isinstance(ver, bool):
        v.problems.append("manifest.json has no valid bundle_schema_version")
        return None
    if ver != BUNDLE_SCHEMA_VERSION:
        v.problems.append(f"bundle schema {ver} is not supported by this ipa-diagnose (it reads schema "
                          f"{BUNDLE_SCHEMA_VERSION})")
        return None
    if m.get("source_mode") not in ("LIVE", "REPLAY"):
        v.problems.append("manifest.json source_mode is neither LIVE nor REPLAY")
    known = {"bundle_format", "bundle_schema_version", "created_at", "created_by", "source_mode", "source_description",
             "report_schema_version", "overall_status", "evidence_completeness", "evidence_tiers", "counts",
             "sanitization", "truncation", "content_complete", "limits", "volatile_fields", "integrity", "members"}
    unknown = sorted(k for k in m if k not in known)
    if unknown:
        v.warnings.append(f"manifest.json has {len(unknown)} field(s) this version does not know; ignored")
    entries = m.get("members")
    expected = [n for n in MEMBERS if n not in ("manifest.json", "SHA256SUMS")]
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        v.problems.append("manifest.json members list is malformed")
        return m
    names = [e.get("name") for e in entries]
    if sorted(n for n in names if isinstance(n, str)) != sorted(expected) or len(names) != len(expected):
        v.problems.append("manifest.json members do not match the archive")
    for e in entries:
        n = e.get("name")
        if n in contents and (e.get("sha256") != hashlib.sha256(contents[n]).hexdigest()
                              or e.get("bytes") != len(contents[n])):
            v.problems.append(f"manifest.json checksum or size mismatch for {n}")
    return m


def _check_content(contents: Dict[str, bytes], manifest: Optional[Dict[str, Any]], v: Validation) -> None:
    mode = manifest.get("source_mode") if manifest else None
    for name in MEMBERS:
        data = contents.get(name)
        if data is None or name == "SHA256SUMS":
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            v.problems.append(f"{name} is not valid UTF-8")
            continue
        found = set()
        if name.endswith(".json"):
            try:
                obj = _strict_json(data)
            except (ValueError, RecursionError):
                v.problems.append(f"{name} is not valid JSON (duplicate keys and NaN/Infinity are refused)")
                continue
            if not isinstance(obj, dict):
                v.problems.append(f"{name} is not a JSON object")
                continue
            if name != "manifest.json" and mode and obj.get("source_mode") != mode:
                v.problems.append(f"{name} says source_mode {str(obj.get('source_mode'))[:10]!r}, the manifest says "
                                  f"{mode}")
            for key, s in _json_strings(obj):
                found.update(scan_text(s, key))
        else:
            found.update(scan_text(text, multiline=True))
        for cat in sorted(found):
            v.problems.append(f"{name}: {cat} - do not share this bundle")
    if manifest:
        v.summary = {k: manifest.get(k) for k in ("created_at", "source_mode", "overall_status",
                                                   "evidence_completeness", "bundle_schema_version")}
        by = manifest.get("created_by")
        v.summary["ipa_diagnose_version"] = by.get("version") if isinstance(by, dict) else None
        v.summary["content_complete"] = manifest.get("content_complete")
