"""journal_krb5kdc collector: recent krb5kdc journal errors, read-only.

Wraps ``journalctl -u krb5kdc --since -30min --no-pager``. Per the "do not
blindly ingest massive logs" principle, this collector does not surface
every line - only lines matching a small set of known-interesting patterns
become EvidenceItems, each with ``kind="krb5kdc_journal_line"`` (deliberately
NOT the generic ``"journal_line"`` kind some other packs' journal collectors
use, so that filtering `bundle.items_by_kind(...)` in the kerberos pack can
never accidentally pick up another pack's unrelated journal evidence just
because it happens to share a kind string):

  - ``clock_skew``: an explicit clock-skew rejection from the KDC (see MIT
    Kerberos's documented default 300-second/5-minute skew window). This is
    the one direct, unambiguous signal for the kerberos pack's clock-skew
    rule - as opposed to inferring skew indirectly from this host's own NTP
    state (see kerberos_client.py).
  - ``preauth_failed``: a preauthentication-failure rejection. NOTE: this is
    a generic error bucket the KDC uses for clock skew, wrong
    keytab/password, AND salt mismatches - by itself it is deliberately NOT
    treated as sufficient evidence for any specific root cause anywhere in
    the kerberos pack.
  - ``kdc_error``: any other explicit KDC-side error/rejection, kept for
    --details visibility but not otherwise used to drive a specific rule.

IMPORTANT LIMITATION encoded in the kerberos pack: a DNS-caused KDC
discovery failure (the client can't resolve or reach any KDC at all)
produces NO line here, because the request never arrives at the KDC in the
first place. Absence of journal_krb5kdc evidence is therefore itself a
(weak, non-exclusive) signal consistent with a discovery/reachability
problem rather than a KDC-side rejection - the kerberos pack's DNS rule
relies on the client-side error text (surfaced via ipa-healthcheck's
IPAHostKeytab check) for that hypothesis instead.

Fixture format (tests/fixtures/kerberos/<scenario>/journal_krb5kdc.json): a
JSON array of raw log entries, each classified independently by this
collector using the same pattern matching as collect_live (so fixtures only
need to supply realistic-looking raw text, not pre-classified labels)::

    [
      {"timestamp": "2026-09-15T09:58:03Z", "line": "krb5kdc[1234](Error): TGS_REQ ... Clock skew too great"}
    ]

Lines that do not match any known pattern are simply not surfaced (no
EvidenceItem is produced for them), matching collect_live's behavior.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from ipa_diagnose.evidence.collectors.base import Collector, CollectorError, raise_if_journal_limited
from ipa_diagnose.evidence.collectors.registry import register
from ipa_diagnose.evidence.model import EvidenceItem, Provenance, Severity

_CLOCK_SKEW_RE = re.compile(r"clock skew", re.IGNORECASE)
_PREAUTH_RE = re.compile(r"preauth(entication)?\s*failed|KRB5KDC_ERR_PREAUTH_FAILED", re.IGNORECASE)
_GENERIC_ERROR_RE = re.compile(r"\(Error\)|KDC_ERR_|KRB5KDC_ERR_", re.IGNORECASE)

JOURNAL_COMMAND = ["journalctl", "-u", "krb5kdc", "--since", "-30min", "--no-pager"]


def classify_line(line: str) -> Optional[str]:
    """Returns a matched_pattern label, or None if this line isn't one of
    the small set of patterns this collector cares about."""

    if _CLOCK_SKEW_RE.search(line):
        return "clock_skew"
    if _PREAUTH_RE.search(line):
        return "preauth_failed"
    if _GENERIC_ERROR_RE.search(line):
        return "kdc_error"
    return None


_SEVERITY_BY_PATTERN = {
    "clock_skew": Severity.ERROR,
    "preauth_failed": Severity.WARNING,
    "kdc_error": Severity.WARNING,
}


class JournalKrb5kdcCollector(Collector):
    name = "journal_krb5kdc"
    timeout_seconds = 15.0

    def collect_live(self) -> List[EvidenceItem]:
        if shutil.which("journalctl") is None:
            raise CollectorError("journalctl is not installed or not on PATH", permission_related=False)
        try:
            proc = subprocess.run(
                JOURNAL_COMMAND, capture_output=True, text=True, timeout=self.timeout_seconds, check=False
            )
        except (OSError, subprocess.SubprocessError) as e:
            raise CollectorError(str(e))
        raise_if_journal_limited(proc)
        if proc.returncode != 0:
            stderr = (proc.stderr or "").lower()
            permission_related = "permission" in stderr or "root" in stderr
            raise CollectorError(
                f"journalctl exited {proc.returncode}: {(proc.stderr or '').strip()[:300]}",
                permission_related=permission_related,
            )

        prov = Provenance(source="journal_krb5kdc", command=" ".join(JOURNAL_COMMAND), live=True)
        items: List[EvidenceItem] = []
        for idx, line in enumerate((proc.stdout or "").splitlines()):
            line = line.strip()
            if not line:
                continue
            pattern = classify_line(line)
            if pattern is None:
                continue
            items.append(
                EvidenceItem(
                    item_id=f"journal_krb5kdc.{idx}",
                    kind="krb5kdc_journal_line",
                    summary=line[:200],
                    data={"line": line, "matched_pattern": pattern},
                    severity=_SEVERITY_BY_PATTERN.get(pattern),
                    provenance=prov,
                )
            )
        return items

    def collect_replay(self, fixture_dir: pathlib.Path) -> List[EvidenceItem]:
        fixture_file = fixture_dir / "journal_krb5kdc.json"
        if not fixture_file.exists():
            return []
        try:
            data = json.loads(fixture_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise CollectorError(f"malformed fixture {fixture_file}: {e}")
        if not isinstance(data, list):
            raise CollectorError(f"fixture {fixture_file} must be a JSON array")

        prov = Provenance(source="journal_krb5kdc", command=f"--replay {fixture_file}", live=False)
        items: List[EvidenceItem] = []
        for idx, entry in enumerate(data):
            if not isinstance(entry, dict):
                continue
            line = str(entry.get("line", ""))
            if not line:
                continue
            pattern = classify_line(line)
            if pattern is None:
                continue
            timestamp = entry.get("timestamp")
            item_data: Dict[str, Any] = {"line": line, "matched_pattern": pattern}
            if timestamp:
                item_data["timestamp"] = timestamp
            items.append(
                EvidenceItem(
                    item_id=f"journal_krb5kdc.{idx}",
                    kind="krb5kdc_journal_line",
                    summary=line[:200],
                    data=item_data,
                    severity=_SEVERITY_BY_PATTERN.get(pattern),
                    provenance=prov,
                )
            )
        return items


register(JournalKrb5kdcCollector())
