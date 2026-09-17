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
        "suffix": "domain" | "ca",  # which list-ruv section this came from -
                          # "Replica Update Vectors:" vs. "Certificate Server
                          # Replica Update Vectors:" - kept distinct so a CA
                          # RUV entry and a domain RUV entry that happen to
                          # share a replica_id are never conflated into one
                          # item.
        "csn": str | None,
        "alive": bool | None,  # True if this RID's host corresponds to a
                          # peer we can currently see (self or an agreement
                          # peer). False means this snapshot has no
                          # corresponding live server for the RID - a
                          # *candidate* stale/orphaned RUV, not proof by
                          # itself (a single host's RUV list cannot fully
                          # confirm a replica is dead vs. merely slow to
                          # converge - see the ``stale-ruv`` rule in
                          # engine/packs/replication.py). None means this
                          # host's own agreement-list could not be collected
                          # reliably, so we cannot confidently say either
                          # way - treated as "not stale" (never as a false
                          # "stale") by the rule, deliberately: an incomplete
                          # peer list must never manufacture a false stale
                          # RUV.
    }

Replay fixture: ``<fixture_dir>/replication_agreements.json``, shaped as::

    {
      "agreements": [
        {"peer": "ipa02.example.test", "status": "red",
         "last_update_status": "Error (-1) ...", "last_update_ended": "..."}
      ],
      "ruv": [
        {"replica_id": 4, "ldap_url": "ipa01.example.test:389",
         "suffix": "domain", "csn": "...", "alive": true}
      ]
    }

``alive`` may be omitted or explicitly ``null`` in a fixture to represent
"could not be determined" (see above) rather than defaulting to either
True or False.

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

        # `list` (agreements) and `list-ruv` are independent, both
        # individually read-only commands. They used to be coupled - a
        # failure in `list` prevented `list-ruv` from ever running at all,
        # which meant a transient/permission failure in agreement listing
        # silently hid RUV evidence too. They're now collected independently
        # so a problem with one never blocks the other; a total failure of
        # both is still surfaced as a CollectorError (see below).
        agreements, list_error = self._try_run_list(hostname)
        items.extend(agreements)

        # hosts_known_complete=False (when `list` failed) makes
        # _parse_list_ruv_output classify every non-self RUV entry as
        # "cannot determine" (alive=None) rather than "not alive" (False) -
        # an incomplete peer list must never manufacture a false stale RUV.
        known_hosts = {hostname} | {a.data["peer"] for a in agreements}
        ruv_items, ruv_error = self._try_run_list_ruv(known_hosts, hosts_known_complete=list_error is None)
        items.extend(ruv_items)

        if list_error is not None and ruv_error is not None:
            raise CollectorError(f"{list_error}; {ruv_error}", permission_related=True)
        return items

    def _try_run_list(self, hostname: str) -> "tuple[List[EvidenceItem], Optional[str]]":
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
            return [], f"{command} failed: {e}"
        if proc.returncode != 0:
            return [], f"{command} exited {proc.returncode}: {proc.stderr.strip()[:300]}"
        return _parse_list_output(proc.stdout, command=command), None

    def _try_run_list_ruv(
        self, known_hosts: "set[str]", *, hosts_known_complete: bool
    ) -> "tuple[List[EvidenceItem], Optional[str]]":
        try:
            proc = subprocess.run(
                ["ipa-replica-manage", "list-ruv"],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            return [], f"{LIST_RUV_COMMAND} failed: {e}"
        if proc.returncode != 0:
            return [], f"{LIST_RUV_COMMAND} exited {proc.returncode}: {proc.stderr.strip()[:300]}"
        items = _parse_list_ruv_output(
            proc.stdout,
            known_hosts=known_hosts,
            hosts_known_complete=hosts_known_complete,
            command=LIST_RUV_COMMAND,
        )
        return items, None

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
    suffix = entry.get("suffix") if entry.get("suffix") in ("domain", "ca") else "domain"
    raw_alive = entry.get("alive", True)
    alive = None if raw_alive is None else bool(raw_alive)
    return EvidenceItem(
        item_id=f"replication-ruv:{suffix}:{replica_id}",
        kind="replication_ruv",
        summary=f"RUV entry replica_id={replica_id} ({ldap_url}, {suffix}): {_alive_label(alive)}",
        data={
            "replica_id": replica_id,
            "ldap_url": ldap_url,
            "suffix": suffix,
            "csn": entry.get("csn"),
            "alive": alive,
        },
        provenance=provenance,
    )


def _alive_label(alive: Optional[bool]) -> str:
    if alive is None:
        return "could not be determined"
    return "alive" if alive else "no corresponding live server"


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


_CS_RUV_HEADER_RE = re.compile(r"^certificate server replica update vectors\s*:?\s*$", re.IGNORECASE)
_RUV_HEADER_RE = re.compile(r"^replica update vectors\s*:?\s*$", re.IGNORECASE)
# Real `ipa-replica-manage list-ruv` output (confirmed against current
# upstream FreeIPA source) never includes an "ldap://" scheme - each line is
# plain `host:port: replica_id`. The scheme prefix is accepted anyway, as an
# optional group, purely for tolerance of any older/variant output or
# hand-written fixture that does include one - it is not the expected real
# shape.
_RUV_LINE_RE = re.compile(r"^\s*(?:ldap://)?([\w.-]+):(\d+):\s*(\d+)\s*$")


def _parse_list_ruv_output(
    stdout: str, *, known_hosts: "set[str]", hosts_known_complete: bool, command: str
) -> List[EvidenceItem]:
    """Parses ``ipa-replica-manage list-ruv`` text output into RUV items.

    Real output looks roughly like::

        Replica Update Vectors:
        ipa01.example.com:389: 4
        ipa02.example.com:389: 5

        Certificate Server Replica Update Vectors:
        ipa01.example.com:389: 6

    The two sections are tracked separately (``data["suffix"]``) so a domain
    RUV and a CA RUV that happen to share a replica_id are never conflated
    into one item. Lines outside either recognized header (e.g. a stray
    warning line from an older ipa-replica-manage) are simply not matched by
    ``_RUV_LINE_RE`` rather than misread as a RUV entry - a strict
    ``host:port: id`` shape is required, not a loose substring search.

    ``alive`` is a heuristic: True when the URL's hostname is among the
    currently-known hosts (self + current agreement peers), False when it
    isn't AND the known-hosts set is itself reliable (``hosts_known_complete``
    - i.e. agreement listing succeeded), and None (cannot determine) when
    agreement listing failed, since an incomplete known-hosts set must never
    manufacture a false "not alive" for a replica that is actually fine.
    """

    provenance = Provenance(source="collector:replication_agreements", command=command, live=True)
    items: List[EvidenceItem] = []
    seen: "set[tuple[str, int]]" = set()
    suffix = "domain"
    for raw_line in stdout.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if _CS_RUV_HEADER_RE.match(stripped):
            suffix = "ca"
            continue
        if _RUV_HEADER_RE.match(stripped):
            suffix = "domain"
            continue
        match = _RUV_LINE_RE.match(raw_line)
        if not match:
            continue
        host, port, replica_id_str = match.group(1), match.group(2), match.group(3)
        replica_id = int(replica_id_str)
        dedup_key = (suffix, replica_id)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        ldap_url = f"{host}:{port}"
        if host in known_hosts:
            alive: Optional[bool] = True
        elif hosts_known_complete:
            alive = False
        else:
            alive = None
        items.append(
            EvidenceItem(
                item_id=f"replication-ruv:{suffix}:{replica_id}",
                kind="replication_ruv",
                summary=f"RUV entry replica_id={replica_id} ({ldap_url}, {suffix}): {_alive_label(alive)}",
                data={"replica_id": replica_id, "ldap_url": ldap_url, "suffix": suffix, "csn": None, "alive": alive},
                provenance=provenance,
            )
        )
    return items


register(ReplicationAgreementsCollector())
