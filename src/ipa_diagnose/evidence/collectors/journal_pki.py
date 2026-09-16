"""journalctl collector for the CA (pki-tomcatd) and certmonger units.

Wraps ``journalctl -u pki-tomcatd -u certmonger --since -30min --no-pager``
(read-only) and surfaces only lines that look like they matter - errors,
failures, timeouts, refused/denied connections, or CA agent authorization
failures (Dogtag's HTTP 4301 "Authorization Error") - as EvidenceItems of
kind ``"pki_journal_line"`` (deliberately not the generic ``"journal_line"`` -
other packs' journal collectors, e.g. directory-server's journal_dirsrv, use
their own distinct kind for the same reason: a shared generic kind would let
one pack's journal evidence leak into another pack's rules as false
corroboration). This intentionally does not ingest the full journal
window; only the small set of lines a diagnostic rule could plausibly cite.

EvidenceItem.data for each match:

    {
      "unit": str,   # "certmonger" | "pki-tomcatd" | "unknown" (best-effort,
                      # detected from the line's own process tag since
                      # journalctl interleaves multiple -u units together)
      "line": str,   # the raw journal line, verbatim
    }

Fixture format (``<fixture_dir>/journal_pki.json``): a JSON array whose
elements are either a plain string (the raw line; unit is inferred the same
way as in collect_live) or an object ``{"unit": "...", "line": "..."}`` when
the test wants to pin the unit explicitly. Every element in the fixture is
treated as already-relevant (no keyword re-filtering), since fixtures are
meant to express only what the test actually wants collected.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
from typing import List

from ipa_diagnose.evidence.collectors.base import Collector, CollectorError
from ipa_diagnose.evidence.collectors.registry import register
from ipa_diagnose.evidence.model import EvidenceItem, Provenance, Severity

JOURNALCTL_COMMAND = [
    "journalctl",
    "-u",
    "pki-tomcatd",
    "-u",
    "certmonger",
    "--since",
    "-30min",
    "--no-pager",
]

_ISSUE_KEYWORDS = (
    "error",
    "fail",
    "unreachable",
    "refused",
    "denied",
    "timeout",
    "timed out",
    "unable",
    "warn",
    "4301",
)
_ERROR_KEYWORDS = ("error", "fail", "unreachable", "refused", "denied")


def _detect_unit(line: str) -> str:
    lower = line.lower()
    if "certmonger" in lower:
        return "certmonger"
    if "pki-tomcatd" in lower or "pkidaemon" in lower or "pki-tomcat" in lower:
        return "pki-tomcatd"
    return "unknown"


def _severity_for_line(line: str) -> Severity:
    lower = line.lower()
    if any(k in lower for k in _ERROR_KEYWORDS):
        return Severity.ERROR
    return Severity.WARNING


def _to_item(idx: int, line: str, *, unit: str, provenance: Provenance) -> EvidenceItem:
    trimmed = line.strip()
    return EvidenceItem(
        item_id=f"journal_pki.{idx}",
        kind="pki_journal_line",
        summary=trimmed[:200],
        data={"unit": unit, "line": trimmed},
        severity=_severity_for_line(trimmed),
        provenance=provenance,
    )


class JournalPkiCollector(Collector):
    name = "journal_pki"
    timeout_seconds = 15.0

    def collect_live(self) -> List[EvidenceItem]:
        if shutil.which("journalctl") is None:
            raise CollectorError("journalctl is not available on this host")
        try:
            proc = subprocess.run(
                JOURNALCTL_COMMAND,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            raise CollectorError(f"failed to run journalctl: {e}") from e
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            permission_related = "permission" in stderr.lower() or "root" in stderr.lower()
            raise CollectorError(f"journalctl exited {proc.returncode}: {stderr[:300]}", permission_related=permission_related)

        command = " ".join(JOURNALCTL_COMMAND)
        provenance = Provenance(source="journal_pki", command=command, live=True)
        items: List[EvidenceItem] = []
        idx = 0
        for raw_line in proc.stdout.splitlines():
            if not raw_line.strip():
                continue
            lower = raw_line.lower()
            if not any(k in lower for k in _ISSUE_KEYWORDS):
                continue
            items.append(_to_item(idx, raw_line, unit=_detect_unit(raw_line), provenance=provenance))
            idx += 1
        return items

    def collect_replay(self, fixture_dir: pathlib.Path) -> List[EvidenceItem]:
        fixture_file = fixture_dir / "journal_pki.json"
        if not fixture_file.exists():
            return []
        try:
            data = json.loads(fixture_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise CollectorError(f"malformed fixture {fixture_file}: {e}") from e
        if not isinstance(data, list):
            raise CollectorError(f"fixture {fixture_file} must be a JSON array of journal lines")

        provenance = Provenance(source="journal_pki", command=f"--replay {fixture_file}", live=False)
        items: List[EvidenceItem] = []
        for idx, entry in enumerate(data):
            if isinstance(entry, str):
                line, unit = entry, _detect_unit(entry)
            elif isinstance(entry, dict):
                line = str(entry.get("line", ""))
                unit = str(entry.get("unit") or _detect_unit(line))
            else:
                continue
            if not line.strip():
                continue
            items.append(_to_item(idx, line, unit=unit, provenance=provenance))
        return items


register(JournalPkiCollector())
