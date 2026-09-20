"""kerberos_client collector: targeted, read-only Kerberos client-side checks.

ipa-healthcheck's own Kerberos coverage is thin by design (see
``ipahealthcheck.ipa.host``'s ``IPAHostKeytab`` check, which only runs
``kinit -kt /etc/krb5.keytab`` and reports pass/fail - no KVNO comparison, no
clock data). This collector fills that gap with three read-only checks:

1. ``klist`` - the current ticket cache state (what tickets, if any, this
   host currently holds).
2. A KVNO comparison: ``kvno <principal>`` (what the KDC currently thinks the
   key version is) vs the KVNO recorded in ``klist -kte /etc/krb5.keytab``
   (what this host's on-disk keytab has). A mismatch here is the direct,
   deterministic signal for a stale/out-of-sync keytab - see
   docs/research notes in engine/packs/kerberos.py for why the generic
   "Preauthentication failed" error string alone is NOT sufficient evidence
   for this.
3. A local clock/NTP-sync check, preferring ``chronyc tracking`` and falling
   back to just recording the local time via ``date`` when chrony isn't
   present.

LIMITATION: true Kerberos clock-skew detection requires comparing this
host's clock against the KDC's own clock. This collector can only observe
whether *this* host's clock is NTP-synchronized and its offset from its
configured NTP source - it cannot see the KDC's clock directly. That
limitation is surfaced in the kerberos pack's clock-skew rule.

Nothing here mutates system state: ``kinit`` is never invoked, only
``klist``/``kvno``/``chronyc``/``date`` are run.

Fixture format (tests/fixtures/kerberos/<scenario>/kerberos_client.json), a
single JSON object with three independent, all-optional top-level keys - a
missing key means that sub-check "did not run" for this scenario (mirroring
a live permission-denied/missing-binary failure), matching how
collect_replay returns [] entirely when the whole file is absent::

    {
      "klist": {
        "principal": "host/ipa01.example.test@EXAMPLE.TEST",
        "tickets": [
          {"principal": "krbtgt/EXAMPLE.TEST@EXAMPLE.TEST", "valid": true, "expires": "..."}
        ],
        "raw": "<verbatim klist output, for --details>"
      },
      "kvno_comparison": {
        "principal": "host/ipa01.example.test@EXAMPLE.TEST",
        "kdc_kvno": 3,
        "keytab_kvno": 2,
        "match": false,
        "error": null
      },
      "clock_sync": {
        "method": "chronyc" | "date",
        "ntp_synchronized": true,
        "offset_seconds": 0.012,
        "raw": "<verbatim chronyc/date output>"
      }
    }
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from ipa_diagnose.evidence.collectors.base import Collector, CollectorError
from ipa_diagnose.evidence.collectors.registry import register
from ipa_diagnose.evidence.model import EvidenceItem, Provenance, Severity

_KEYTAB_ENTRY_RE = re.compile(
    # Real `klist -kte` rows: "   2 05/17/2026 10:00:00 host/x@REALM (aes256-...)".
    r"^\s*(?P<kvno>\d+)\s+(?:\d{2}/\d{2}/\d{2,4}\s+\d{2}:\d{2}:\d{2}\s+)?(?P<principal>\S+@\S+)\s", re.MULTILINE
)
_KVNO_RESULT_RE = re.compile(r"kvno\s*=\s*(?P<kvno>\d+)", re.IGNORECASE)
_CHRONY_SYSTEM_TIME_RE = re.compile(
    r"System time\s*:\s*([\d.]+)\s*seconds\s*(fast|slow)", re.IGNORECASE
)
_CHRONY_LEAP_STATUS_RE = re.compile(r"Leap status\s*:\s*(.+)", re.IGNORECASE)


class KerberosClientCollector(Collector):
    name = "kerberos_client"
    timeout_seconds = 10.0

    # -- live -----------------------------------------------------------

    def collect_live(self) -> List[EvidenceItem]:
        if shutil.which("klist") is None:
            raise CollectorError("klist is not installed or not on PATH", permission_related=False)

        items: List[EvidenceItem] = []
        prov = Provenance(source="kerberos_client", live=True)
        self._failures: List[str] = []

        klist_item = self._collect_klist(prov)
        if klist_item is not None:
            items.append(klist_item)

        keytab_entries = self._read_keytab_entries()
        if keytab_entries and shutil.which("kvno") is not None:
            kvno_item = self._collect_kvno_comparison(keytab_entries, prov)
            if kvno_item is not None:
                items.append(kvno_item)

        clock_item = self._collect_clock_sync(prov)
        if clock_item is not None:
            items.append(clock_item)

        if self._failures:
            # Some sub-checks could not run (timeout / OS error): keep the
            # evidence that WAS collected but never present it as complete.
            raise CollectorError("; ".join(self._failures), partial_items=items)
        return items

    def _run(self, args: List[str]) -> "subprocess.CompletedProcess[str]":
        return subprocess.run(
            args, capture_output=True, text=True, timeout=self.timeout_seconds, check=False
        )

    def _collect_klist(self, prov: Provenance) -> Optional[EvidenceItem]:
        try:
            proc = self._run(["klist"])
        except (OSError, subprocess.SubprocessError) as e:
            self._failures.append(f"klist failed: {type(e).__name__}")
            return None
        # A non-zero exit here typically just means "no ticket cache found",
        # which is itself informative (not an error worth raising).
        raw = (proc.stdout or "") + (proc.stderr or "")
        principal = None
        m = re.search(r"Default principal:\s*(\S+)", raw)
        if m:
            principal = m.group(1)
        tickets = []
        for line in raw.splitlines():
            if re.match(r"^\d{2}/\d{2}/\d{2,4}", line.strip()):
                tickets.append(line.strip())
        data: Dict[str, Any] = {"principal": principal, "tickets": tickets, "raw": raw.strip()}
        return EvidenceItem(
            item_id="kerberos_client.klist",
            kind="klist_ticket",
            summary=f"klist ticket cache for {principal or 'unknown principal'} ({len(tickets)} ticket(s))",
            data=data,
            provenance=dataclasses_replace(prov, command="klist"),
        )

    def _read_keytab_entries(self) -> List[Tuple[str, int]]:
        try:
            proc = self._run(["klist", "-kte", "/etc/krb5.keytab"])
        except (OSError, subprocess.SubprocessError) as e:
            self._failures.append(f"keytab listing failed: {type(e).__name__}")
            return []
        if proc.returncode != 0:
            return []
        entries: List[Tuple[str, int]] = []
        for match in _KEYTAB_ENTRY_RE.finditer(proc.stdout or ""):
            principal = match.group("principal")
            # Defense in depth (security review finding): a principal is
            # passed as an argv element to `kvno` later, never through a
            # shell, so this isn't a shell-injection vector - but a
            # principal starting with "-" could still be misread as a flag
            # by the `kvno` binary itself. Requiring root write access to
            # /etc/krb5.keytab to influence this already implies
            # effectively-root already, but reject the shape anyway rather
            # than trust it.
            if principal.startswith("-"):
                continue
            entries.append((principal, int(match.group("kvno"))))
        return entries

    def _collect_kvno_comparison(
        self, keytab_entries: List[Tuple[str, int]], prov: Provenance
    ) -> Optional[EvidenceItem]:
        principal, keytab_kvno = keytab_entries[0]
        try:
            proc = self._run(["kvno", principal])
        except (OSError, subprocess.SubprocessError) as e:
            return EvidenceItem(
                item_id="kerberos_client.kvno_comparison",
                kind="kvno_comparison",
                summary=f"kvno lookup for {principal} failed: {e}",
                data={"principal": principal, "kdc_kvno": None, "keytab_kvno": keytab_kvno, "match": None, "error": str(e)},
                provenance=dataclasses_replace(prov, command=f"kvno {principal}"),
            )
        kdc_kvno = None
        m = _KVNO_RESULT_RE.search(proc.stdout or "")
        if m:
            kdc_kvno = int(m.group("kvno"))
        error = None if proc.returncode == 0 and kdc_kvno is not None else (proc.stderr or proc.stdout or "").strip()[:300]
        match = None if kdc_kvno is None else (kdc_kvno == keytab_kvno)
        return EvidenceItem(
            item_id="kerberos_client.kvno_comparison",
            kind="kvno_comparison",
            summary=f"kvno comparison for {principal}: KDC={kdc_kvno} keytab={keytab_kvno} match={match}",
            data={
                "principal": principal,
                "kdc_kvno": kdc_kvno,
                "keytab_kvno": keytab_kvno,
                "match": match,
                "error": error,
            },
            severity=Severity.ERROR if match is False else None,
            provenance=dataclasses_replace(prov, command=f"kvno {principal}"),
        )

    def _collect_clock_sync(self, prov: Provenance) -> Optional[EvidenceItem]:
        if shutil.which("chronyc") is not None:
            try:
                proc = self._run(["chronyc", "tracking"])
            except (OSError, subprocess.SubprocessError):
                proc = None
            if proc is not None and proc.returncode == 0:
                raw = proc.stdout or ""
                offset = None
                m = _CHRONY_SYSTEM_TIME_RE.search(raw)
                if m:
                    offset = float(m.group(1)) * (-1 if m.group(2).lower() == "slow" else 1)
                leap_m = _CHRONY_LEAP_STATUS_RE.search(raw)
                synchronized = bool(leap_m) and "not synchronised" not in leap_m.group(1).lower()
                return EvidenceItem(
                    item_id="kerberos_client.clock_sync",
                    kind="clock_sync",
                    summary=f"local clock sync via chronyc: synchronized={synchronized} offset={offset}",
                    data={"method": "chronyc", "ntp_synchronized": synchronized, "offset_seconds": offset, "raw": raw.strip()},
                    provenance=dataclasses_replace(prov, command="chronyc tracking"),
                )
        # Fallback: no NTP-comparison tooling available. We can only record
        # the local time, not a real offset - documented limitation.
        try:
            proc = self._run(["date", "-u"])
        except (OSError, subprocess.SubprocessError) as e:
            self._failures.append(f"clock reading failed: {type(e).__name__}")
            return None
        raw = (proc.stdout or "").strip()
        return EvidenceItem(
            item_id="kerberos_client.clock_sync",
            kind="clock_sync",
            summary="local clock reading only (chronyc unavailable; cannot determine NTP sync state)",
            data={"method": "date", "ntp_synchronized": None, "offset_seconds": None, "raw": raw},
            provenance=dataclasses_replace(prov, command="date -u"),
        )

    # -- replay -----------------------------------------------------------

    def collect_replay(self, fixture_dir: pathlib.Path) -> List[EvidenceItem]:
        fixture_file = fixture_dir / "kerberos_client.json"
        if not fixture_file.exists():
            return []
        try:
            data = json.loads(fixture_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise CollectorError(f"malformed fixture {fixture_file}: {e}")
        if not isinstance(data, dict):
            raise CollectorError(f"fixture {fixture_file} must be a JSON object")

        items: List[EvidenceItem] = []
        prov = Provenance(source="kerberos_client", command=f"--replay {fixture_file}", live=False)

        klist = data.get("klist")
        if isinstance(klist, dict):
            items.append(
                EvidenceItem(
                    item_id="kerberos_client.klist",
                    kind="klist_ticket",
                    summary=f"klist ticket cache for {klist.get('principal', 'unknown principal')}",
                    data=klist,
                    provenance=prov,
                )
            )

        kvno = data.get("kvno_comparison")
        if isinstance(kvno, dict):
            match = kvno.get("match")
            items.append(
                EvidenceItem(
                    item_id="kerberos_client.kvno_comparison",
                    kind="kvno_comparison",
                    summary=(
                        f"kvno comparison for {kvno.get('principal', '?')}: "
                        f"KDC={kvno.get('kdc_kvno')} keytab={kvno.get('keytab_kvno')} match={match}"
                    ),
                    data=kvno,
                    severity=Severity.ERROR if match is False else None,
                    provenance=prov,
                )
            )

        clock = data.get("clock_sync")
        if isinstance(clock, dict):
            items.append(
                EvidenceItem(
                    item_id="kerberos_client.clock_sync",
                    kind="clock_sync",
                    summary=(
                        f"local clock sync via {clock.get('method', '?')}: "
                        f"synchronized={clock.get('ntp_synchronized')} offset={clock.get('offset_seconds')}"
                    ),
                    data=clock,
                    provenance=prov,
                )
            )

        return items


def dataclasses_replace(prov: Provenance, **changes: Any) -> Provenance:
    """Small helper so each sub-check can stamp its own literal command onto
    an otherwise-shared Provenance."""

    return dataclasses.replace(prov, **changes)


register(KerberosClientCollector())
