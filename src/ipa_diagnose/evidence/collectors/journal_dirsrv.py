"""journalctl collector for dirsrv units, scoped to the directory-server pack.

Read-only wrapper around::

    journalctl -u "dirsrv@*" --since -30min --no-pager

(a glob unit pattern, since we don't necessarily know the concrete instance
name at collection time). Only lines that actually mention "dirsrv" and match
one of a small set of known failure signatures are surfaced as
EvidenceItems - this collector does not ingest the raw journal, per the
"do not blindly ingest massive logs" collector contract.

Items use kind ``"dirsrv_journal_line"`` rather than the generic
``"journal_line"``: other packs' journal collectors (e.g. certificates'
journal_pki) use their own distinct kind for the same reason - a shared
generic kind would let one pack's journal evidence leak into another pack's
rules as false corroboration.

Fixture format (tests/fixtures/directory-server/<scenario>/journal_dirsrv.json):
a JSON array of objects::

    [
      {
        "unit": "dirsrv@EXAMPLE-TEST.service",
        "timestamp": "Jan 15 09:12:03",
        "message": "chown_dir_files: file (.../cert8.db) chown failed (13) Permission denied",
        "category": "permission_denied"
      }
    ]

``category`` is one of: "disk_space", "permission_denied", "selinux",
"nss_tls", "startup_failure", "other". It may be omitted, in which case it is
re-derived from "message" using the same keyword matching collect_live()
uses; a fixture entry whose message matches none of the known patterns and
has no explicit category is dropped, exactly like an uninteresting live
journal line would be.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

from ipa_diagnose.evidence.collectors.base import Collector, CollectorError
from ipa_diagnose.evidence.collectors.registry import register
from ipa_diagnose.evidence.model import EvidenceItem, Provenance, Severity

JOURNAL_COMMAND = ["journalctl", "-u", "dirsrv@*", "--since", "-30min", "--no-pager"]

# (category, severity, [substrings to match, case-insensitive]) - order
# matters: first match wins.
_PATTERNS: List[Tuple[str, Severity, List[str]]] = [
    ("disk_space", Severity.CRITICAL, ["no space left on device"]),
    ("selinux", Severity.ERROR, ["selinux", "avc:", "denied by selinux", " avc "]),
    ("permission_denied", Severity.ERROR, ["permission denied", "chown failed", "chown_dir_files"]),
    (
        "nss_tls",
        Severity.ERROR,
        [
            "cert8.db",
            "cert9.db",
            "key3.db",
            "key4.db",
            "sec_error",
            "nss error",
            "ssl alert",
            "tls alert",
            "unable to load certificate",
            "handshake",
        ],
    ),
    (
        "startup_failure",
        Severity.ERROR,
        ["failed to start", "unable to access nsslapd-rundir", "core dumped", "segfault"],
    ),
]

_CATEGORY_SEVERITY = {category: severity for category, severity, _ in _PATTERNS}

_LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d\d:\d\d:\d\d)\s+\S+\s+(?P<unit>[\w@.\-]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)


def _classify(message: str) -> Optional[Tuple[str, Severity]]:
    lowered = message.lower()
    for category, severity, substrings in _PATTERNS:
        if any(s in lowered for s in substrings):
            return category, severity
    return None


def _parse_line(line: str) -> Optional[Dict[str, str]]:
    m = _LINE_RE.match(line)
    if m:
        return {"timestamp": m.group("ts"), "unit": m.group("unit"), "message": m.group("msg")}
    if "dirsrv" not in line.lower():
        return None
    return {"timestamp": "", "unit": "dirsrv", "message": line.strip()}


def _make_item(
    index: int,
    unit: str,
    timestamp: str,
    message: str,
    category: Optional[str],
    *,
    provenance: Provenance,
) -> Optional[EvidenceItem]:
    if category is None:
        classification = _classify(message)
        if classification is None:
            return None
        category, severity = classification
    else:
        severity = _CATEGORY_SEVERITY.get(category, Severity.WARNING)
    summary = f"{unit}: {message}"[:300]
    return EvidenceItem(
        item_id=f"journal-dirsrv-{index}",
        kind="dirsrv_journal_line",
        summary=summary,
        data={"unit": unit, "timestamp": timestamp, "message": message, "category": category},
        severity=severity,
        provenance=provenance,
    )


class JournalDirsrvCollector(Collector):
    name = "journal_dirsrv"
    timeout_seconds = 15.0

    def collect_live(self) -> List[EvidenceItem]:
        if shutil.which("journalctl") is None:
            raise CollectorError("journalctl is not available on PATH", permission_related=False)
        try:
            proc = subprocess.run(
                JOURNAL_COMMAND,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            raise CollectorError(f"journalctl failed: {e}") from e
        if proc.returncode != 0:
            stderr = (proc.stderr or "").lower()
            permission_related = "permission" in stderr or "root" in stderr or "access denied" in stderr
            raise CollectorError(
                f"journalctl exited {proc.returncode}: {(proc.stderr or '').strip()[:300]}",
                permission_related=permission_related,
            )
        provenance = Provenance(source="collector:journal_dirsrv", command=" ".join(JOURNAL_COMMAND), live=True)
        items: List[EvidenceItem] = []
        for idx, raw_line in enumerate(proc.stdout.splitlines()):
            if not raw_line.strip() or "dirsrv" not in raw_line.lower():
                continue
            parsed = _parse_line(raw_line)
            if parsed is None:
                continue
            item = _make_item(
                idx, parsed["unit"], parsed["timestamp"], parsed["message"], None, provenance=provenance
            )
            if item is not None:
                items.append(item)
        return items

    def collect_replay(self, fixture_dir: pathlib.Path) -> List[EvidenceItem]:
        fixture_file = fixture_dir / "journal_dirsrv.json"
        if not fixture_file.exists():
            return []
        try:
            raw = json.loads(fixture_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise CollectorError(f"malformed fixture {fixture_file}: {e}") from e
        if not isinstance(raw, list):
            raise CollectorError(f"fixture {fixture_file} is not a JSON array")
        provenance = Provenance(source="collector:journal_dirsrv", command=f"--replay {fixture_file}", live=False)
        items: List[EvidenceItem] = []
        for idx, entry in enumerate(raw):
            if not isinstance(entry, dict) or "message" not in entry:
                continue
            item = _make_item(
                idx,
                str(entry.get("unit", "dirsrv")),
                str(entry.get("timestamp", "")),
                str(entry["message"]),
                entry.get("category"),
                provenance=provenance,
            )
            if item is not None:
                items.append(item)
        return items


register(JournalDirsrvCollector())
