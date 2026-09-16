"""Read-only journal collector surfacing recent named/bind-dyndb-ldap errors.

ipa-healthcheck has no check at all for bind-dyndb-ldap startup/sync
problems, forwarder reachability, or DNSSEC - the DNS pack fills part of
that gap by grepping the last 30 minutes of the named/named-pkcs11 journal
for lines that look like startup failures, crashes, or bind-dyndb-ldap
zone-loading problems, and surfacing only those matching lines as
EvidenceItems (not the full log - "do not blindly ingest massive logs").

This collector does NOT interpret what the lines mean (that is dns.py rule
logic); it only filters for relevance and normalizes each matching line into
an EvidenceItem so the same keyword-matching rule code can run against both
live journal output and --replay fixtures.

Strictly read-only: ``journalctl --no-pager ...`` only, never a state change.

Fixture format (tests/fixtures/dns/<scenario>/journal_named.json): a JSON
array of objects shaped like::

    {
      "item_id": "journal_named.0001",
      "kind": "named_journal_line",
      "summary": "named-pkcs11[1842]: could not configure any DNS interfaces",
      "data": {
        "unit": "named-pkcs11",
        "raw_line": "Sep 15 10:02:11 ipa01 named-pkcs11[1842]: could not configure any DNS interfaces",
        "timestamp": "Sep 15 10:02:11"
      },
      "severity": "ERROR"                 # SUCCESS | WARNING | ERROR | CRITICAL | null
    }

An empty array is a valid fixture meaning "collector ran, found nothing
relevant in the window" - distinct from a missing file, which this collector
treats as "the collector itself could not run" (e.g. to simulate permission
denied reading the journal).
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
from typing import Any, List, Optional

from ipa_diagnose.evidence.collectors.base import Collector, CollectorError
from ipa_diagnose.evidence.collectors.registry import register
from ipa_diagnose.evidence.model import EvidenceItem, Provenance, Severity

_SEVERITY_ALIASES = {s.value: s for s in Severity}

JOURNAL_COMMAND = [
    "journalctl",
    "-u",
    "named-pkcs11",
    "-u",
    "named",
    "--since",
    "-30min",
    "--no-pager",
]

# Lines are kept only if they mention named/bind-dyndb-ldap trouble - this is
# a relevance filter, not a diagnosis. dns.py rules do their own, stricter
# pattern matching on top of whatever this filter keeps.
_RELEVANT_KEYWORDS = (
    "error",
    "fail",
    "denied",
    "cannot",
    "can't",
    "critical",
    "fatal",
    "dyndb",
    "bind-dyndb-ldap",
    "zone",
    "unload",
    "empty zone",
    "conflict",
    "sync",
    "shutting down",
    "exiting",
)

_UNIT_PATTERN = re.compile(r"\b(named-pkcs11|named)\b")


def _parse_severity(raw: Any) -> Optional[Severity]:
    if isinstance(raw, str) and raw.upper() in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[raw.upper()]
    return None


def _guess_severity(line: str) -> Severity:
    lowered = line.lower()
    if any(k in lowered for k in ("fatal", "critical", "failed to start", "could not configure")):
        return Severity.CRITICAL
    if any(k in lowered for k in ("error", "denied", "cannot", "can't", "fail")):
        return Severity.ERROR
    return Severity.WARNING


def _guess_unit(line: str) -> str:
    m = _UNIT_PATTERN.search(line)
    return m.group(1) if m else "named"


def _filter_relevant_lines(raw_text: str) -> List[str]:
    lines = []
    for line in raw_text.splitlines():
        lowered = line.lower()
        if any(keyword in lowered for keyword in _RELEVANT_KEYWORDS):
            lines.append(line)
    return lines


class JournalNamedCollector(Collector):
    name = "journal_named"
    timeout_seconds = 15.0

    def collect_live(self) -> List[EvidenceItem]:
        if shutil.which("journalctl") is None:
            raise CollectorError("journalctl is not installed or not on PATH")
        try:
            proc = subprocess.run(
                JOURNAL_COMMAND, capture_output=True, text=True, timeout=self.timeout_seconds, check=False
            )
        except (OSError, subprocess.SubprocessError) as e:
            raise CollectorError(f"failed to run journalctl: {e}") from e
        if proc.returncode != 0 and not proc.stdout.strip():
            stderr = proc.stderr.lower()
            permission_related = "permission" in stderr or "root" in stderr or "denied" in stderr
            raise CollectorError(
                f"journalctl exited {proc.returncode}: {proc.stderr.strip()[:300]}",
                permission_related=permission_related,
            )

        items: List[EvidenceItem] = []
        for idx, line in enumerate(_filter_relevant_lines(proc.stdout)):
            items.append(
                EvidenceItem(
                    item_id=f"journal_named.{idx:04d}",
                    kind="named_journal_line",
                    summary=line.strip()[:300],
                    data={"unit": _guess_unit(line), "raw_line": line, "timestamp": line[:15]},
                    severity=_guess_severity(line),
                    provenance=Provenance(
                        source="journal_named", command=" ".join(JOURNAL_COMMAND), live=True
                    ),
                )
            )
        return items

    def collect_replay(self, fixture_dir: pathlib.Path) -> List[EvidenceItem]:
        fixture_file = fixture_dir / "journal_named.json"
        if not fixture_file.exists():
            raise CollectorError(
                f"no journal_named fixture at {fixture_file} "
                "(simulating the collector being unable to run, e.g. permission denied reading the journal)",
                permission_related=True,
            )
        try:
            raw = json.loads(fixture_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise CollectorError(f"malformed fixture {fixture_file}: {e}") from e
        if not isinstance(raw, list):
            raise CollectorError(f"fixture {fixture_file} is not a JSON array")

        items: List[EvidenceItem] = []
        for idx, entry in enumerate(raw):
            if not isinstance(entry, dict):
                continue
            items.append(
                EvidenceItem(
                    item_id=str(entry.get("item_id") or f"journal_named.{idx:04d}"),
                    kind=str(entry.get("kind", "named_journal_line")),
                    summary=str(entry.get("summary", "")),
                    data=dict(entry.get("data") or {}),
                    severity=_parse_severity(entry.get("severity")),
                    provenance=Provenance(
                        source="journal_named", command=f"--replay {fixture_file}", live=False
                    ),
                )
            )
        return items


register(JournalNamedCollector())
