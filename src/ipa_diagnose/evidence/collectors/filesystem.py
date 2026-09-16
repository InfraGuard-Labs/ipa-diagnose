"""Filesystem usage collector for the directory-server pack.

Read-only wrapper around ``df -Pk <path>`` (POSIX output format - avoids the
device-name line-wrapping that plain ``df -h`` does for long device names) for
the specific paths ipa-healthcheck itself monitors around Directory Server:
``ipahealthcheck.system.filesystemspace``'s hardcoded thresholds
(/var/lib/dirsrv/ 1024MB, /var/lib/ipa/backup/ 512MB, /var/log/ 1024MB,
/var/tmp and /tmp 512MB, plus a 20% minimum-free floor) and
``ipahealthcheck.ds.disk_space``'s lib389 ``MonitorDiskSpace`` check (which
additionally watches /dev/shm and /var/log/dirsrv/, since DS needs
/dev/shm/slapd-<instance> for its shared-memory region).

This collector never changes system state - it only runs ``df``.

Fixture format (tests/fixtures/directory-server/<scenario>/filesystem.json):
a JSON array of objects, one per monitored path::

    [
      {
        "path": "/dev/shm",
        "filesystem": "tmpfs",
        "mounted_on": "/dev/shm",
        "size_bytes": 536870912,
        "used_bytes": 520093696,
        "avail_bytes": 16777216,
        "used_percent": 97
      }
    ]

Only ``path`` is required. Missing numeric fields default to 0, and
``used_percent`` is recomputed from size/used when omitted.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
from typing import Any, Dict, List

from ipa_diagnose.evidence.collectors.base import Collector, CollectorError
from ipa_diagnose.evidence.collectors.registry import register
from ipa_diagnose.evidence.model import EvidenceItem, Provenance, Severity

MONITORED_PATHS: List[str] = [
    "/var/lib/dirsrv/",
    "/var/log/dirsrv/",
    "/dev/shm",
    "/var/lib/ipa/backup/",
    "/var/log/",
    "/tmp",
    "/var/tmp",
]


def _severity_for_usage(used_percent: float) -> Severity:
    """A local heuristic only - NOT authoritative.

    The authoritative severity for disk space comes from ipa-healthcheck's
    FileSystemSpaceCheck / DiskSpaceCheck findings already in the bundle;
    this just gives a rule enough signal to corroborate/detail those
    findings with a live reading, using round thresholds loosely modeled on
    ipa-healthcheck's own 20%-minimum-free floor.
    """
    if used_percent >= 95:
        return Severity.CRITICAL
    if used_percent >= 90:
        return Severity.ERROR
    if used_percent >= 80:
        return Severity.WARNING
    return Severity.SUCCESS


def _slug(path: str) -> str:
    return path.strip("/").replace("/", "-") or "root"


def _make_item(path: str, data: Dict[str, Any], *, provenance: Provenance) -> EvidenceItem:
    size_bytes = int(data.get("size_bytes") or 0)
    used_bytes = int(data.get("used_bytes") or 0)
    avail_bytes = int(data.get("avail_bytes") or 0)
    used_percent = data.get("used_percent")
    if used_percent is None:
        used_percent = round(100.0 * used_bytes / size_bytes, 1) if size_bytes else 0.0
    used_percent = float(used_percent)
    filesystem = str(data.get("filesystem") or "unknown")
    mounted_on = str(data.get("mounted_on") or path)
    summary = f"{path}: {used_percent:.0f}% used, {avail_bytes:,} bytes free on {mounted_on} ({filesystem})"
    return EvidenceItem(
        item_id=f"disk-usage-{_slug(path)}",
        kind="disk_usage",
        summary=summary,
        data={
            "path": path,
            "filesystem": filesystem,
            "mounted_on": mounted_on,
            "size_bytes": size_bytes,
            "used_bytes": used_bytes,
            "avail_bytes": avail_bytes,
            "used_percent": used_percent,
        },
        severity=_severity_for_usage(used_percent),
        provenance=provenance,
    )


class FilesystemCollector(Collector):
    name = "filesystem"
    timeout_seconds = 15.0

    def collect_live(self) -> List[EvidenceItem]:
        if shutil.which("df") is None:
            raise CollectorError("df is not available on PATH", permission_related=False)

        items: List[EvidenceItem] = []
        for path in MONITORED_PATHS:
            if not pathlib.Path(path).exists():
                # Not every monitored path exists on every deployment (e.g. a
                # non-default dirsrv log location) - skip quietly rather than
                # failing the whole collector over one path.
                continue
            command = f"df -Pk {path}"
            try:
                proc = subprocess.run(
                    ["df", "-Pk", path],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as e:
                raise CollectorError(f"df failed for {path}: {e}") from e
            if proc.returncode != 0:
                continue
            lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
            if len(lines) < 2:
                continue
            fields = lines[-1].split()
            if len(fields) < 6:
                continue
            filesystem, size_kb, used_kb, avail_kb, capacity = fields[0], fields[1], fields[2], fields[3], fields[4]
            mounted_on = " ".join(fields[5:])
            try:
                size_bytes = int(size_kb) * 1024
                used_bytes = int(used_kb) * 1024
                avail_bytes = int(avail_kb) * 1024
            except ValueError:
                continue
            capacity_digits = capacity.rstrip("%")
            used_percent = float(capacity_digits) if capacity_digits.isdigit() else None
            items.append(
                _make_item(
                    path,
                    {
                        "filesystem": filesystem,
                        "mounted_on": mounted_on,
                        "size_bytes": size_bytes,
                        "used_bytes": used_bytes,
                        "avail_bytes": avail_bytes,
                        "used_percent": used_percent,
                    },
                    provenance=Provenance(source="collector:filesystem", command=command, live=True),
                )
            )
        return items

    def collect_replay(self, fixture_dir: pathlib.Path) -> List[EvidenceItem]:
        fixture_file = fixture_dir / "filesystem.json"
        if not fixture_file.exists():
            return []
        try:
            raw = json.loads(fixture_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise CollectorError(f"malformed fixture {fixture_file}: {e}") from e
        if not isinstance(raw, list):
            raise CollectorError(f"fixture {fixture_file} is not a JSON array")
        items: List[EvidenceItem] = []
        for entry in raw:
            if not isinstance(entry, dict) or "path" not in entry:
                continue
            items.append(
                _make_item(
                    str(entry["path"]),
                    entry,
                    provenance=Provenance(
                        source="collector:filesystem", command=f"--replay {fixture_file}", live=False
                    ),
                )
            )
        return items


register(FilesystemCollector())
