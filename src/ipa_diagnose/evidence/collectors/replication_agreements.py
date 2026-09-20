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
import os
import pathlib
import re
import shutil
import socket
import subprocess
import urllib.parse
from typing import Any, Dict, List, Optional

from ipa_diagnose.evidence.collectors.base import Collector, CollectorError
from ipa_diagnose.evidence.collectors.registry import register
from ipa_diagnose.evidence.model import EvidenceItem, Provenance

LIST_COMMAND_TEMPLATE = "ipa-replica-manage list -v {host}"
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
        # so a problem with one never blocks the other.
        agreements, list_error = self._try_run_list(hostname)
        items.extend(agreements)

        # hosts_known_complete=False (when `list` failed) makes
        # _parse_list_ruv_output classify every non-self RUV entry as
        # "cannot determine" (alive=None) rather than "not alive" (False) -
        # an incomplete peer list must never manufacture a false stale RUV.
        # The authoritative list of servers in the topology (not just THIS
        # host's own agreements): in a 3+ server line topology a healthy peer
        # reachable only through another peer has no agreement with this host,
        # and must not look like a stale RUV entry.
        masters = _ldapi_masters(self.timeout_seconds) or self._try_list_masters()
        known_hosts = {hostname} | {a.data["peer"] for a in agreements} | (masters or set())
        hosts_complete = list_error is None or masters is not None
        ruv_items, ruv_error = self._try_run_list_ruv(known_hosts, hosts_known_complete=hosts_complete)
        items.extend(ruv_items)

        # Contradictory evidence: agreements to peers exist, yet the RUV read
        # concluded "no replication configured". Never present that as verified.
        if agreements and any(
            i.kind == "replication_topology" and i.data.get("state") == "no_replication_configured" for i in ruv_items
        ):
            items = [i for i in items if i.kind != "replication_topology"]
            ruv_items = []
            ruv_error = "replication agreements exist but no RUV was found (contradictory evidence)"

        # `list -v` (agreement health) is supplementary once the topology AND
        # the RUV were both read: ipa-healthcheck's own replication check covers
        # agreement health. It must not keep a healthy replica "unverified" just
        # because root has no Kerberos ticket.
        if list_error is not None and masters is not None and any(i.kind == "replication_ruv" for i in ruv_items):
            list_error = None

        # A single-server deployment has no RUV and no agreements. When the
        # authoritative LDAPI read proved that, an agreement-listing failure
        # (e.g. `list` needing a Kerberos ticket) is moot - there is nothing to
        # list - so it must not keep a healthy single server "unverified".
        if any(i.kind == "replication_topology" and i.data.get("state") == "no_replication_configured" for i in ruv_items):
            list_error = None

        # Found in live testing against a real FreeIPA server:
        # `ipa-replica-manage list-ruv` (and clean-ruv/abort-clean-ruv)
        # require the Directory Manager password specifically - a valid
        # admin Kerberos ticket is NOT sufficient, unlike `list`. This is a
        # real, common state: an administrator running ipa-diagnose with an
        # ordinary admin ticket (not the DM password, which this tool must
        # never ask for or store) will have `list` succeed while
        # `list-ruv` fails. That must never be silent - stale-RUV
        # detection depends entirely on `list-ruv`, so ANY failure in it is
        # reported, not just a total failure of both sub-calls. Whatever
        # WAS collected (e.g. agreements from a successful `list`) is
        # preserved via partial_items, not discarded.
        if list_error is not None or ruv_error is not None:
            message = "; ".join(m for m in (list_error, ruv_error) if m)
            lowered = message.lower()
            permission_related = any(
                w in lowered for w in ("permission", "password", "insufficient access", "not allowed", "denied", "root")
            )
            raise CollectorError(message, permission_related=permission_related, partial_items=items)
        return items

    def _try_run_list(self, hostname: str) -> "tuple[List[EvidenceItem], Optional[str]]":
        command = LIST_COMMAND_TEMPLATE.format(host=hostname)
        try:
            proc = subprocess.run(
                ["ipa-replica-manage", "list", "-v", hostname],
                capture_output=True,
                stdin=subprocess.DEVNULL,
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
                stdin=subprocess.DEVNULL,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            return self._ldapi_fallback(known_hosts, hosts_known_complete, f"{LIST_RUV_COMMAND} failed: {e}")
        if proc.returncode != 0:
            return self._ldapi_fallback(
                known_hosts,
                hosts_known_complete,
                f"{LIST_RUV_COMMAND} exited {proc.returncode}: {proc.stderr.strip()[:300]}",
            )
        items = _parse_list_ruv_output(
            proc.stdout,
            known_hosts=known_hosts,
            hosts_known_complete=hosts_known_complete,
            command=LIST_RUV_COMMAND,
        )
        if items and _count_unparsed_ruv_lines(proc.stdout):
            # Some RUV-looking lines were not understood (format drift): the
            # skipped entry could be the stale one - not a verified RUV.
            return self._ldapi_fallback(
                known_hosts, hosts_known_complete, f"{LIST_RUV_COMMAND} output could not be fully parsed"
            )
        if not items:
            # Exit 0 but nothing parseable (changed/localised wording, empty
            # output): NOT a verified RUV - fall through to the LDAPI read.
            return self._ldapi_fallback(
                known_hosts, hosts_known_complete, f"{LIST_RUV_COMMAND} returned no parseable RUV entries"
            )
        return items, None

    def _try_list_masters(self) -> "Optional[set]":
        """`ipa-replica-manage list` (no host) = every server in the topology
        (`host: master` lines). Needs a Kerberos ticket; None if unavailable."""

        try:
            proc = subprocess.run(
                ["ipa-replica-manage", "list"],
                capture_output=True,
                stdin=subprocess.DEVNULL,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0:
            return None
        hosts = {m.group(1) for line in (proc.stdout or "").splitlines() if (m := _ROLE_LINE_RE.match(line))}
        return hosts or None

    def _ldapi_fallback(
        self, known_hosts: "set[str]", hosts_known_complete: bool, primary_error: str
    ) -> "tuple[List[EvidenceItem], Optional[str]]":
        """`ipa-replica-manage list-ruv` insists on the Directory Manager
        password (tool policy - observed live on FreeIPA 4.13.3 even with a
        valid admin ticket), which this tool must never ask for or store.
        The same RUV data is readable, read-only, over the local LDAPI
        socket via SASL EXTERNAL when running as root (the same mechanism
        ipa-healthcheck's own RUV check uses) - no password of any kind is
        involved. If that is also unavailable the original error is kept,
        so the gap stays visible ("RUV state: NOT VERIFIED")."""

        items, fallback_error = _ldapi_read_ruv(known_hosts, hosts_known_complete, timeout=self.timeout_seconds)
        if items:
            return items, None
        if fallback_error is None:
            # The search SUCCEEDED as cn=Directory Manager (identity confirmed)
            # and no replica update vector exists: replication is not
            # configured (a single-server deployment). That is a verified
            # fact, not a gap - see _ldapi_read_ruv.
            return [_no_replication_item()], None
        return [], f"{primary_error}; read-only LDAPI fallback unavailable: {fallback_error}"

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


def _flag_duplicate_host_ids(items: List[EvidenceItem]) -> List[EvidenceItem]:
    """A replica that was removed and re-installed under the same hostname
    leaves its OLD replica id in the RUV next to the new one. Both map to a
    live host by name, so without this the old id looked alive. The highest id
    for a (suffix, host:port) is kept as the live one; older ids are marked
    "no corresponding live server" (a candidate, never proof)."""

    import dataclasses as _dc

    groups: "dict[tuple, List[EvidenceItem]]" = {}
    for it in items:
        groups.setdefault((it.data.get("suffix"), it.data.get("ldap_url")), []).append(it)
    replaced: "dict[str, EvidenceItem]" = {}
    for grp in groups.values():
        if len(grp) < 2:
            continue
        keep = max(grp, key=lambda i: i.data.get("replica_id") or 0)
        for it in grp:
            if it is keep:
                continue
            data = dict(it.data, alive=False, duplicate_host=True)
            replaced[it.item_id] = _dc.replace(
                it,
                data=data,
                summary=f"RUV entry replica_id={data.get('replica_id')} ({data.get('ldap_url')}, {data.get('suffix')}): "
                "same host also has a newer replica id - no corresponding live server for this one",
            )
    return [replaced.get(i.item_id, i) for i in items]


def _alive_label(alive: Optional[bool]) -> str:
    if alive is None:
        return "could not be determined"
    return "alive" if alive else "no corresponding live server"


_BLOCK_HEADER_RE = re.compile(r"^(\S[^:\s].*?):?\s*$")
# Real non-verbose `ipa-replica-manage list [host]` output is one line per
# server, `host: role` (captured from a real FreeIPA 4.13.3 two-node lab:
# `ipa-b.ruvlab.test: master`). Found live: without this, the generic block
# header regex swallowed the whole line as the peer NAME
# ("ipa-b.ruvlab.test: master"), so a healthy peer never matched its RUV
# host and was wrongly presented as a stale-RUV candidate.
_ROLE_LINE_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9.-]*):\s*(master|replica|hidden replica|hidden master)\s*$", re.IGNORECASE)
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
        if not last_update_status:
            status = "unknown"  # no health information in this output shape - never claimed green
        elif "error" in last_update_status.lower() and "error (0)" not in last_update_status.lower():
            status = "red"
        else:
            status = "green"
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

    for raw_line in (ln[:512] for ln in stdout.splitlines()):
        if not raw_line.strip():
            continue
        role_match = _ROLE_LINE_RE.match(raw_line)
        if role_match:
            # Real `ipa-replica-manage list -v <host>` output (captured from a
            # FreeIPA 4.13.3 lab) is `host: replica` followed by indented
            # "last update status: ..." attribute lines. Plain `list` (no -v)
            # is just the `host: role` line. Either way this line STARTS a block.
            flush()
            current_peer = role_match.group(1)
            attrs = {}
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


def _count_unparsed_ruv_lines(stdout: str) -> int:
    """Lines that look like RUV entries (host:port) but matched none of the
    known shapes."""

    count = 0
    for raw in (ln[:512] for ln in (stdout or "").splitlines()):
        stripped = raw.strip()
        if not stripped or _CS_RUV_HEADER_RE.match(stripped) or _RUV_HEADER_RE.match(stripped):
            continue
        if _RUV_LINE_RE.match(raw):
            continue
        if re.search(r"[\w.-]+:\d{2,5}\b", stripped):
            count += 1
    return count


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
    for raw_line in (ln[:512] for ln in stdout.splitlines()):
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
    return _flag_duplicate_host_ids(items)


IPA_DEFAULT_CONF = "/etc/ipa/default.conf"
_NSDS50RUV_RE = re.compile(r"\{replica\s+(\d+)\s+ldap://([\w.-]+):(\d+)\}\s*(\S*)")


def _read_ipa_conf() -> "tuple[Optional[str], Optional[str]]":
    """(realm, basedn) from /etc/ipa/default.conf - a plain, world-readable
    config file; returns (None, None) if it cannot be read."""

    realm = basedn = None
    try:
        with open(IPA_DEFAULT_CONF, encoding="utf-8") as fh:
            for line in fh:
                key, _, value = line.partition("=")
                key = key.strip().lower()
                if key == "realm" and realm is None:
                    realm = value.strip()
                elif key == "basedn" and basedn is None:
                    basedn = value.strip()
    except OSError:
        return None, None
    return realm, basedn


def _ldif_unfold(text: str) -> List[str]:
    lines: List[str] = []
    for raw in text.splitlines():
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    return lines


def _parse_ldapi_ruv_ldif(stdout: str, *, known_hosts: "set[str]", hosts_known_complete: bool, command: str) -> List[EvidenceItem]:
    """Parses `ldapsearch -LLL` LDIF containing ``nsds50ruv`` values such as
    ``{replica 3 ldap://ipa-b.example.test:389} <csn> <csn>`` (captured from a
    real FreeIPA 4.13.3 two-node topology). ``{replicageneration}`` and any
    other value shape are ignored, never misread as a replica."""

    provenance = Provenance(source="collector:replication_agreements", command=command, live=True)
    items: List[EvidenceItem] = []
    seen: "set[tuple[str, int]]" = set()
    suffix = "domain"
    for line in _ldif_unfold(stdout):
        if line.lower().startswith("dn:"):
            suffix = "ca" if "ipaca" in line.lower() else "domain"
            continue
        if not line.lower().startswith("nsds50ruv:"):
            continue
        match = _NSDS50RUV_RE.search(line)
        if not match:
            continue
        replica_id, host, port, csn = int(match.group(1)), match.group(2), match.group(3), match.group(4)
        if (suffix, replica_id) in seen:
            continue
        seen.add((suffix, replica_id))
        if host in known_hosts:
            alive: Optional[bool] = True
        elif hosts_known_complete:
            alive = False
        else:
            alive = None
        ldap_url = f"{host}:{port}"
        items.append(
            EvidenceItem(
                item_id=f"replication-ruv:{suffix}:{replica_id}",
                kind="replication_ruv",
                summary=f"RUV entry replica_id={replica_id} ({ldap_url}, {suffix}): {_alive_label(alive)}",
                data={
                    "replica_id": replica_id,
                    "ldap_url": ldap_url,
                    "suffix": suffix,
                    "csn": csn or None,
                    "alive": alive,
                    "method": "ldapi-external-read-only",
                },
                provenance=provenance,
            )
        )
    return _flag_duplicate_host_ids(items)


def _no_replication_item() -> EvidenceItem:
    return EvidenceItem(
        item_id="replication-topology:none",
        kind="replication_topology",
        summary="No replica update vector exists: replication is not configured (single-server deployment)",
        data={"state": "no_replication_configured", "identity": "cn=Directory Manager", "method": "ldapi-external-read-only"},
        provenance=Provenance(source="collector:replication_agreements", command="ldapsearch -Y EXTERNAL (ldapi)", live=True),
    )


def _ldapi_identity_is_directory_manager(uri: str, timeout: float) -> bool:
    """`ldapwhoami -Y EXTERNAL` (read-only). Only an authenticated
    cn=Directory Manager identity can be trusted to see every entry, so an
    EMPTY search result is only ever treated as "no RUV exists" when this
    holds - an ACL-restricted identity returns an empty result for entries it
    is merely not allowed to see (observed live: admin over GSSAPI)."""

    if shutil.which("ldapwhoami") is None:
        return False
    try:
        proc = subprocess.run(
            ["ldapwhoami", "-Y", "EXTERNAL", "-H", uri],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            check=False,
            cwd="/",
            env=_ldap_env(),
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and "cn=directory manager" in proc.stdout.lower()


def _ldap_env() -> "dict[str, str]":
    """Environment for the OpenLDAP tools: no LDAP* variables (LDAPRC, LDAPURI, ...)
    inherited from the caller, so they cannot redirect or reconfigure the read."""

    return {k: v for k, v in os.environ.items() if not k.startswith("LDAP")}


def _ldapi_context() -> "tuple[Optional[str], Optional[str], Optional[str]]":
    """(ldapi uri, basedn, error). Read-only LDAPI needs root (the socket
    peer-credential identity is the local uid)."""

    if os.name == "nt" or os.geteuid() != 0:
        return None, None, "not running as root (LDAPI EXTERNAL identity is the local uid)"
    if shutil.which("ldapsearch") is None:
        return None, None, "ldapsearch is not installed"
    realm, basedn = _read_ipa_conf()
    if not realm or not basedn:
        return None, None, f"could not read realm/basedn from {IPA_DEFAULT_CONF}"
    if not re.fullmatch(r"[A-Za-z0-9.-]+", realm):
        return None, None, "realm in /etc/ipa/default.conf has an unexpected format"
    socket_path = f"/run/slapd-{realm.replace('.', '-')}.socket"
    if not os.path.exists(socket_path):
        return None, None, f"directory server LDAPI socket {socket_path} not found"
    return "ldapi://" + urllib.parse.quote(socket_path, safe=""), basedn, None


def _ldapsearch(uri: str, base: str, scope: str, search_filter: str, attrs: "list[str]", timeout: float):
    argv = ["ldapsearch", "-LLL", "-Y", "EXTERNAL", "-H", uri, "-b", base, "-s", scope, search_filter, *attrs]
    proc = subprocess.run(
        argv,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
        cwd="/",
        env=_ldap_env(),
    )
    return argv, proc


_MASTER_DN_RE = re.compile(r"(?im)^dn:\s*cn=([A-Za-z0-9.-]+),cn=masters,")


def _ldapi_masters(timeout: float) -> "Optional[set]":
    """Every server registered in the topology (cn=masters), read-only over
    LDAPI as root; None when unavailable."""

    uri, basedn, err = _ldapi_context()
    if err:
        return None
    try:
        _, proc = _ldapsearch(uri, f"cn=masters,cn=ipa,cn=etc,{basedn}", "one", "(objectClass=*)", ["dn"], timeout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return set(_MASTER_DN_RE.findall(proc.stdout or "")) or None


def _ldapi_read_ruv(
    known_hosts: "set[str]", hosts_known_complete: bool, *, timeout: float
) -> "tuple[List[EvidenceItem], Optional[str]]":
    """Read-only SASL EXTERNAL search over the local LDAPI socket. Requires
    root (the socket peer-credential identity); never passes or prompts for
    any password, and never writes."""

    uri, basedn, err = _ldapi_context()
    if err:
        return [], err
    search_filter = "(&(nsuniqueid=ffffffff-ffffffff-ffffffff-ffffffff)(objectClass=nsTombstone))"
    all_items: List[EvidenceItem] = []
    errors: List[str] = []
    for base, required in ((basedn, True), ("o=ipaca", False)):
        try:
            argv, proc = _ldapsearch(uri, base, "sub", search_filter, ["nsds50ruv"], timeout)
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            errors.append(f"ldapsearch failed{'' if required else ' (CA suffix)'}: {type(e).__name__}")
            continue
        if proc.returncode != 0:
            if not required and proc.returncode == 32:
                continue  # no o=ipaca suffix: a CA-less deployment, nothing to read
            errors.append(
                f"ldapsearch exited {proc.returncode}{'' if required else ' (CA suffix)'}: {proc.stderr.strip()[:200]}"
            )
            continue
        parsed = _parse_ldapi_ruv_ldif(
            proc.stdout, known_hosts=known_hosts, hosts_known_complete=hosts_known_complete, command=" ".join(argv)
        )
        # Every returned {replica ...} value must have been understood: a
        # partly parsed RUV must never be presented as a complete one.
        if len(re.findall(r"\{replica\s", proc.stdout or "")) > len(_NSDS50RUV_RE.findall(proc.stdout or "")):
            errors.append("RUV entries were returned but could not all be parsed")
        elif required and not parsed and "nsds50ruv:" in (proc.stdout or "").lower():
            errors.append("RUV entries were returned but could not be parsed")
        all_items.extend(parsed)
    if errors:
        # A failed/unparseable read of the domain RUV is never masked by a
        # successful CA read: report the gap, discard the partial result.
        return [], "; ".join(errors)
    if not all_items:
        if _ldapi_identity_is_directory_manager(uri, timeout):
            return [], None  # authoritative: nothing exists to be read
        return [], "no RUV entry was returned and the LDAPI identity could not be confirmed as able to see it"
    return all_items, None


register(ReplicationAgreementsCollector())
