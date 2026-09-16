"""Read-only LDAP diagnostic collector: replication conflicts + keytab/bind sanity.

Two independent, read-only checks, both run under this one collector name:

  (a) Replication conflict entries, via::

        ldapsearch -Y GSSAPI -H ldap://localhost -b <suffix> \\
            "(nsds5ReplConflict=*)" dn nsds5ReplConflict

      Finding conflict entries is itself evidence that replication *is*
      transmitting writes between suppliers (see the "replication-conflicts"
      rule in engine/packs/replication.py for why this must never be read as
      "replication is down").

  (b) A keytab/bind sanity check equivalent to::

        kinit -kt /etc/dirsrv/ds.keytab ldap/<host>
        klist
        ldapsearch -Y GSSAPI -H ldap://<peer> -b "" -s base

      This mirrors the prerequisites freeipa.org's replication troubleshooting
      guide calls out explicitly: DNS must resolve bidirectionally and the
      replication keytab must produce a valid GSSAPI bind to the peer. Both
      steps are read-only / diagnostic; nothing here writes to the KDC,
      keytab, or directory.

Produces EvidenceItem objects of two kinds:

  - ``"replication_conflict"``: one per conflict entry.
    ``data`` = {"dn": str, "message": str}

  - ``"keytab_bind_check"``: at most one per run.
    ``data`` = {
        "principal": str,          # e.g. "ldap/ipa01.example.test@EXAMPLE.TEST"
        "kinit_ok": bool,          # local keytab produced a TGT
        "klist_ok": bool,          # klist confirmed a valid/unexpired ticket
        "bind_ok": bool,           # GSSAPI ldapsearch bind to the peer succeeded
        "target": str | None,      # peer host the bind was attempted against
        "error": str | None,       # first error message, if any step failed
    }

Replay fixture: ``<fixture_dir>/ldap_query.json``, shaped as::

    {
      "conflicts": [{"dn": "...", "message": "..."}],
      "keytab_bind": {"principal": "...", "kinit_ok": true, "klist_ok": true,
                       "bind_ok": false, "target": "ipa02.example.test",
                       "error": "..."}
    }

A missing fixture file yields no items (not an error), matching
replication_agreements.py's convention and the "collector didn't run"
scenario used by the ``ambiguous`` replication fixture. Malformed JSON in an
existing fixture file raises CollectorError.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import socket
import subprocess
from typing import Any, Dict, List, Optional

from ipa_diagnose.evidence.collectors.base import Collector, CollectorError
from ipa_diagnose.evidence.collectors.registry import register
from ipa_diagnose.evidence.model import EvidenceItem, Provenance

CONFLICT_FILTER = "(nsds5ReplConflict=*)"


class LdapQueryCollector(Collector):
    name = "ldap_query"
    timeout_seconds = 20.0

    def collect_live(self) -> List[EvidenceItem]:
        items: List[EvidenceItem] = []
        hostname = socket.gethostname()
        suffix = _suffix_from_fqdn(hostname)

        items.extend(self._search_conflicts(suffix))
        items.append(self._keytab_bind_check(hostname))
        return items

    def _search_conflicts(self, suffix: str) -> List[EvidenceItem]:
        if shutil.which("ldapsearch") is None:
            raise CollectorError("ldapsearch is not installed or not on PATH")
        command = f'ldapsearch -Y GSSAPI -H ldap://localhost -b {suffix} "{CONFLICT_FILTER}" dn nsds5ReplConflict'
        try:
            proc = subprocess.run(
                [
                    "ldapsearch",
                    "-Y",
                    "GSSAPI",
                    "-H",
                    "ldap://localhost",
                    "-b",
                    suffix,
                    "-LLL",
                    CONFLICT_FILTER,
                    "dn",
                    "nsds5ReplConflict",
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            raise CollectorError(f"{command} failed: {e}") from e
        if proc.returncode not in (0, 4):  # 4 = LDAP_SIZELIMIT_EXCEEDED, still usable partial results
            permission_related = "permission" in proc.stderr.lower() or "sasl" in proc.stderr.lower()
            raise CollectorError(
                f"{command} exited {proc.returncode}: {proc.stderr.strip()[:300]}",
                permission_related=permission_related,
            )
        provenance = Provenance(source="collector:ldap_query", command=command, live=True)
        return _parse_conflict_ldif(proc.stdout, provenance)

    def _keytab_bind_check(self, hostname: str) -> EvidenceItem:
        principal = f"ldap/{hostname}"
        provenance = Provenance(
            source="collector:ldap_query",
            command=f"kinit -kt /etc/dirsrv/ds.keytab {principal} && klist && ldapsearch -Y GSSAPI ...",
            live=True,
        )
        kinit_ok = False
        klist_ok = False
        bind_ok = False
        error: Optional[str] = None

        if shutil.which("kinit") is None:
            error = "kinit not on PATH"
        else:
            try:
                proc = subprocess.run(
                    ["kinit", "-kt", "/etc/dirsrv/ds.keytab", principal],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                kinit_ok = proc.returncode == 0
                if not kinit_ok:
                    error = proc.stderr.strip()[:300] or f"kinit exited {proc.returncode}"
            except (OSError, subprocess.SubprocessError) as e:
                error = f"kinit failed: {e}"

        if kinit_ok and shutil.which("klist") is not None:
            try:
                proc = subprocess.run(
                    ["klist"], capture_output=True, text=True, timeout=self.timeout_seconds, check=False
                )
                klist_ok = proc.returncode == 0 and "Valid starting" in proc.stdout
                if not klist_ok and error is None:
                    error = "klist reported no valid ticket"
            except (OSError, subprocess.SubprocessError) as e:
                if error is None:
                    error = f"klist failed: {e}"

        if kinit_ok and klist_ok and shutil.which("ldapsearch") is not None:
            try:
                proc = subprocess.run(
                    ["ldapsearch", "-Y", "GSSAPI", "-H", f"ldap://{hostname}", "-b", "", "-s", "base"],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                bind_ok = proc.returncode == 0
                if not bind_ok and error is None:
                    error = proc.stderr.strip()[:300] or f"ldapsearch exited {proc.returncode}"
            except (OSError, subprocess.SubprocessError) as e:
                if error is None:
                    error = f"ldapsearch failed: {e}"

        return EvidenceItem(
            item_id="keytab-bind-check",
            kind="keytab_bind_check",
            summary=f"Keytab/bind check for {principal}: {'ok' if bind_ok else 'failed'}",
            data={
                "principal": principal,
                "kinit_ok": kinit_ok,
                "klist_ok": klist_ok,
                "bind_ok": bind_ok,
                "target": hostname,
                "error": error,
            },
            provenance=provenance,
        )

    def collect_replay(self, fixture_dir: pathlib.Path) -> List[EvidenceItem]:
        fixture_file = fixture_dir / "ldap_query.json"
        if not fixture_file.exists():
            return []
        try:
            data = json.loads(fixture_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise CollectorError(f"malformed fixture {fixture_file}: {e}") from e
        if not isinstance(data, dict):
            raise CollectorError(f"fixture {fixture_file} must be a JSON object")

        provenance = Provenance(
            source="collector:ldap_query",
            command=f"--replay {fixture_file}",
            live=False,
        )
        items: List[EvidenceItem] = []
        for entry in data.get("conflicts", []):
            items.append(_conflict_item(entry, provenance))
        keytab_bind = data.get("keytab_bind")
        if isinstance(keytab_bind, dict):
            items.append(_keytab_bind_item(keytab_bind, provenance))
        return items


def _conflict_item(entry: Dict[str, Any], provenance: Provenance) -> EvidenceItem:
    dn = str(entry.get("dn", "unknown"))
    message = str(entry.get("message", ""))
    return EvidenceItem(
        item_id=f"replication-conflict:{dn}",
        kind="replication_conflict",
        summary=f"Replication conflict entry: {dn}" + (f" ({message})" if message else ""),
        data={"dn": dn, "message": message},
        provenance=provenance,
    )


def _keytab_bind_item(entry: Dict[str, Any], provenance: Provenance) -> EvidenceItem:
    bind_ok = bool(entry.get("bind_ok", True))
    principal = str(entry.get("principal", "unknown"))
    return EvidenceItem(
        item_id="keytab-bind-check",
        kind="keytab_bind_check",
        summary=f"Keytab/bind check for {principal}: {'ok' if bind_ok else 'failed'}",
        data={
            "principal": principal,
            "kinit_ok": bool(entry.get("kinit_ok", True)),
            "klist_ok": bool(entry.get("klist_ok", True)),
            "bind_ok": bind_ok,
            "target": entry.get("target"),
            "error": entry.get("error"),
        },
        provenance=provenance,
    )


def _parse_conflict_ldif(stdout: str, provenance: Provenance) -> List[EvidenceItem]:
    """Parses ``ldapsearch -LLL`` LDIF-ish output into conflict items.

    Each result block is separated by a blank line and starts with a ``dn:``
    line; a ``nsds5ReplConflict:`` line (if present) becomes the message.
    """

    items: List[EvidenceItem] = []
    current_dn: Optional[str] = None
    current_message = ""

    def flush() -> None:
        if current_dn is not None:
            items.append(
                EvidenceItem(
                    item_id=f"replication-conflict:{current_dn}",
                    kind="replication_conflict",
                    summary=f"Replication conflict entry: {current_dn}"
                    + (f" ({current_message})" if current_message else ""),
                    data={"dn": current_dn, "message": current_message},
                    provenance=provenance,
                )
            )

    for line in stdout.splitlines():
        if not line.strip():
            flush()
            current_dn = None
            current_message = ""
            continue
        if line.lower().startswith("dn:"):
            flush()
            current_dn = line.split(":", 1)[1].strip()
            current_message = ""
        elif line.lower().startswith("nsds5replconflict:"):
            current_message = line.split(":", 1)[1].strip()
    flush()
    return items


def _suffix_from_fqdn(hostname: str) -> str:
    """Heuristic: FreeIPA's base LDAP suffix is the domain portion of the
    server's FQDN turned into `dc=` components (e.g. "ipa01.example.test"
    -> "dc=example,dc=test"). This is the documented FreeIPA convention, not
    a guarantee for every possible deployment; live callers with a
    non-default suffix should override via configuration in a future pass.
    """

    labels = hostname.split(".")
    domain_labels = labels[1:] if len(labels) > 1 else labels
    if not domain_labels:
        return ""
    return ",".join(f"dc={label}" for label in domain_labels)


register(LdapQueryCollector())
