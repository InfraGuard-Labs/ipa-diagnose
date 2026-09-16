"""Read-only collector for replication agreement and RUV state.

Wraps two read-only ``ipa-replica-manage`` subcommands (never anything that
mutates state):

  - ``ipa-replica-manage list <host>``   -> per-peer agreement status
  - ``ipa-replica-manage list-ruv``      -> Replica Update Vector entries

Produces :class:`EvidenceItem` objects of two kinds:

  - ``"replication_agreement"``: one per peer agreement.
    ``data`` = {
        "peer": str,                  # peer FQDN
        "status": str,                # e.g. "green" / "red" (collector-normalized)
        "last_update_status": str,    # raw "last update status" text
        "last_update_ended": str | None,
    }

  - ``"replication_ruv"``: one per RUV entry.
    ``data`` = {
        "replica_id": int,
        "ldap_url": str,
        "csn": str | None,
        "alive": bool,   # True if this RID's host corresponds to a peer we
                          # can currently see (self or an agreement peer).
                          # False means this snapshot has no corresponding
                          # live server for the RID - a *candidate*
                          # stale/orphaned RUV, not proof by itself (a single
                          # host's RUV list cannot fully confirm a replica is
                          # dead vs. merely slow to converge - see the
                          # ``stale-ruv`` rule in engine/packs/replication.py).
    }

Replay fixture: ``<fixture_dir>/replication_agreements.json``, shaped as::

    {
      "agreements": [
        {"peer": "ipa02.example.test", "status": "red",
         "last_update_status": "Error (-1) ...", "last_update_ended": "..."}
      ],
      "ruv": [
        {"replica_id": 4, "ldap_url": "ldap://ipa01.example.test:389",
         "csn": "...", "alive": true}
      ]
    }

A missing fixture file yields no items (not an error) - this mirrors how
``evidence/collect.py`` treats a missing ``healthcheck.json``: the pack's
trigger finding is still in the bundle, but this collector simply has
nothing to add, which is exactly the "collector didn't run / has nothing to
say" scenario the ``ambiguous`` replication fixture exercises. Malformed
JSON in an existing fixture file *is* treated as a genuine error.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import socket
import subprocess
from typing import Any, Dict, List, Optional

from ipa_diagnose.evidence.collectors.base import Collector, CollectorError
from ipa_diagnose.evidence.collectors.registry import register
from ipa_diagnose.evidence.model import EvidenceItem, Provenance

LIST_COMMAND_TEMPLATE = "ipa-replica-manage list {host}"
LIST_RUV_COMMAND = "ipa-replica-manage list-ruv"


class ReplicationAgreementsCollector(Collector):
    name = "replication_agreements"
    timeout_seconds = 30.0

    def collect_live(self) -> List[EvidenceItem]:
        if shutil.which("ipa-replica-manage") is None:
            raise CollectorError("ipa-replica-manage is not installed or not on PATH")

        hostname = socket.gethostname()
        items: List[EvidenceItem] = []

        agreements = self._run_list(hostname)
        items.extend(agreements)

        known_hosts = {hostname} | {a.data["peer"] for a in agreements}
        items.extend(self._run_list_ruv(known_hosts))
        return items

    def _run_list(self, hostname: str) -> List[EvidenceItem]:
        command = LIST_COMMAND_TEMPLATE.format(host=hostname)
        try:
            proc = subprocess.run(
                ["ipa-replica-manage", "list", hostname],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            raise CollectorError(f"{command} failed: {e}") from e
        if proc.returncode != 0:
            permission_related = "permission" in proc.stderr.lower() or "root" in proc.stderr.lower()
            raise CollectorError(
                f"{command} exited {proc.returncode}: {proc.stderr.strip()[:300]}",
                permission_related=permission_related,
            )
        return _parse_list_output(proc.stdout, command=command)

    def _run_list_ruv(self, known_hosts: "set[str]") -> List[EvidenceItem]:
        try:
            proc = subprocess.run(
                ["ipa-replica-manage", "list-ruv"],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            raise CollectorError(f"{LIST_RUV_COMMAND} failed: {e}") from e
        if proc.returncode != 0:
            permission_related = "permission" in proc.stderr.lower() or "root" in proc.stderr.lower()
            raise CollectorError(
                f"{LIST_RUV_COMMAND} exited {proc.returncode}: {proc.stderr.strip()[:300]}",
                permission_related=permission_related,
            )
        return _parse_list_ruv_output(proc.stdout, known_hosts=known_hosts, command=LIST_RUV_COMMAND)

    def collect_replay(self, fixture_dir: pathlib.Path) -> List[EvidenceItem]:
        fixture_file = fixture_dir / "replication_agreements.json"
        if not fixture_file.exists():
            return []
        try:
            data = json.loads(fixture_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise CollectorError(f"malformed fixture {fixture_file}: {e}") from e
        if not isinstance(data, dict):
            raise CollectorError(f"fixture {fixture_file} must be a JSON object")

        provenance = Provenance(
            source="collector:replication_agreements",
            command=f"--replay {fixture_file}",
            live=False,
        )
        items: List[EvidenceItem] = []
        for entry in data.get("agreements", []):
            items.append(_agreement_item(entry, provenance))
        for entry in data.get("ruv", []):
            items.append(_ruv_item(entry, provenance))
        return items


def _agreement_item(entry: Dict[str, Any], provenance: Provenance) -> EvidenceItem:
    peer = str(entry.get("peer", "unknown"))
    status = str(entry.get("status", "unknown"))
    last_update_status = str(entry.get("last_update_status", ""))
    return EvidenceItem(
        item_id=f"replication-agreement:{peer}",
        kind="replication_agreement",
        summary=f"Replication agreement to {peer}: {status} ({last_update_status or 'no status'})",
        data={
            "peer": peer,
            "status": status,
            "last_update_status": last_update_status,
            "last_update_ended": entry.get("last_update_ended"),
        },
        provenance=provenance,
    )


def _ruv_item(entry: Dict[str, Any], provenance: Provenance) -> EvidenceItem:
    replica_id = entry.get("replica_id")
    ldap_url = str(entry.get("ldap_url", "unknown"))
    alive = bool(entry.get("alive", True))
    return EvidenceItem(
        item_id=f"replication-ruv:{replica_id}",
        kind="replication_ruv",
        summary=f"RUV entry replica_id={replica_id} ({ldap_url}): {'alive' if alive else 'no corresponding live server'}",
        data={
            "replica_id": replica_id,
            "ldap_url": ldap_url,
            "csn": entry.get("csn"),
            "alive": alive,
        },
        provenance=provenance,
    )


_BLOCK_HEADER_RE = re.compile(r"^(\S[^:\s].*?):?\s*$")
_KV_RE = re.compile(r"^\s+([\w ]+?):\s*(.*)$")


def _parse_list_output(stdout: str, *, command: str) -> List[EvidenceItem]:
    """Parses ``ipa-replica-manage list <host>`` text output into agreement items.

    Real output is block-structured, one unindented peer hostname per block
    followed by indented "key: value" attribute lines, e.g.::

        ipa02.example.com
          last init status: None
          last update status: Error (0) Replica acquired successfully: ...
          last update ended: 2026-01-01 12:00:00+00:00

    This is a best-effort text parser (there is no machine-readable output
    mode for this legacy command); anything it cannot confidently parse is
    simply omitted rather than raising, so a slightly different ipa version's
    wording degrades to "fewer items" rather than a crash.
    """

    provenance = Provenance(source="collector:replication_agreements", command=command, live=True)
    items: List[EvidenceItem] = []
    current_peer: Optional[str] = None
    attrs: Dict[str, str] = {}

    def flush() -> None:
        if current_peer is None:
            return
        last_update_status = attrs.get("last update status", "")
        status = "red" if "error" in last_update_status.lower() and "error (0)" not in last_update_status.lower() else "green"
        items.append(
            EvidenceItem(
                item_id=f"replication-agreement:{current_peer}",
                kind="replication_agreement",
                summary=f"Replication agreement to {current_peer}: {status} ({last_update_status or 'no status'})",
                data={
                    "peer": current_peer,
                    "status": status,
                    "last_update_status": last_update_status,
                    "last_update_ended": attrs.get("last update ended"),
                },
                provenance=provenance,
            )
        )

    for raw_line in stdout.splitlines():
        if not raw_line.strip():
            continue
        kv_match = _KV_RE.match(raw_line)
        if kv_match:
            attrs[kv_match.group(1).strip().lower()] = kv_match.group(2).strip()
            continue
        header_match = _BLOCK_HEADER_RE.match(raw_line)
        if header_match:
            flush()
            current_peer = header_match.group(1).strip()
            attrs = {}
    flush()
    return items


_RUV_LINE_RE = re.compile(r"(ldap://\S+):\s*(\d+)")


def _parse_list_ruv_output(stdout: str, *, known_hosts: "set[str]", command: str) -> List[EvidenceItem]:
    """Parses ``ipa-replica-manage list-ruv`` text output into RUV items.

    Real output looks roughly like::

        Replica Update Vectors:
        ldap://ipa01.example.com:389: 4
        ldap://ipa02.example.com:389: 5

    ``alive`` is a heuristic: True when the URL's hostname is among the
    currently-known hosts (self + current agreement peers), False otherwise.
    """

    provenance = Provenance(source="collector:replication_agreements", command=command, live=True)
    items: List[EvidenceItem] = []
    for match in _RUV_LINE_RE.finditer(stdout):
        ldap_url, replica_id = match.group(1), int(match.group(2))
        host = ldap_url.split("//", 1)[-1].split(":", 1)[0]
        alive = host in known_hosts
        items.append(
            EvidenceItem(
                item_id=f"replication-ruv:{replica_id}",
                kind="replication_ruv",
                summary=f"RUV entry replica_id={replica_id} ({ldap_url}): {'alive' if alive else 'no corresponding live server'}",
                data={"replica_id": replica_id, "ldap_url": ldap_url, "csn": None, "alive": alive},
                provenance=provenance,
            )
        )
    return items


register(ReplicationAgreementsCollector())
