"""Deterministic causal knowledge for replication (Slice 5), written as code.

Two pieces, both small and explicit:

* :data:`DEPENDS_ON` - the capability DAG: which capability may depend on which. It says where a cause MAY be
  looked for; a dependency edge never proves causality by itself.
* :data:`DISCRIMINATORS` - the closed registry of rules that may establish ONE link of a cause chain. A link from
  capability A to capability B exists only when a registered discriminator for exactly (A, B) fired on established
  evidence. The rule functions live in :mod:`ipa_diagnose.replication.diagnose`; this registry is what a test holds
  them (and the plan's step dependencies) to.

A cause chain is: symptom -> failing subsystem -> intermediate cause(s) -> deepest proven cause. The deepest
ESTABLISHED link is the actionable root. When the next link cannot be proven the chain stops there, says why
(``boundary``) and names the precise next action (``next_action``), for example a handoff to the peer.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, FrozenSet, List, Optional, Tuple

SYMPTOM = "SYMPTOM"

# capability -> capabilities it may depend on (never transitive by itself; each hop needs its own discriminator)
DEPENDS_ON: Dict[str, FrozenSet[str]] = {
    "REPLICATION": frozenset({"LOCAL_DS", "DNS", "NETWORK", "PEER_DS", "TLS", "KERBEROS", "AUTHORIZATION",
                              "REPLICA_DATA"}),
    "KERBEROS": frozenset({"LOCAL_KDC", "TIME", "PRINCIPAL", "KEYTAB", "DNS", "NETWORK"}),
    "PEER_DS": frozenset({"NETWORK"}),
    "NETWORK": frozenset({"DNS"}),
    "LOCAL_DS": frozenset({"STORAGE"}),
    "LOCAL_KDC": frozenset({"LOCAL_DS"}),
    "AUTHORIZATION": frozenset({"PRINCIPAL"}),
    "TLS": frozenset({"TIME"}),
    "DNS": frozenset(),
    "TIME": frozenset(),
    "PRINCIPAL": frozenset(),
    "KEYTAB": frozenset(),
    "STORAGE": frozenset(),
    "REPLICA_DATA": frozenset(),
    "TOPOLOGY": frozenset({"LOCAL_DS"}),
}
CAPABILITIES = frozenset(DEPENDS_ON)


@dataclasses.dataclass(frozen=True)
class Discriminator:
    disc_id: str
    source: str
    """capability the link starts from (SYMPTOM for the first link of a chain)."""
    target: str
    rule: str
    """the deterministic rule, in words (shown by --details)."""


def _d(disc_id: str, source: str, target: str, rule: str) -> Discriminator:
    return Discriminator(disc_id, source, target, rule)


DISCRIMINATORS: Dict[str, Discriminator] = {d.disc_id: d for d in [
    _d("agreement-status", SYMPTOM, "REPLICATION",
       "the agreement's last update status (389-DS text/JSON) falls in a failing class of replication.status"),
    _d("local-ds-down", SYMPTOM, "LOCAL_DS",
       "this server's Directory Server unit is not active (systemd), so its agreements cannot run or be read"),
    _d("local-kdc-down", SYMPTOM, "LOCAL_KDC", "this server's krb5kdc unit is not active (systemd)"),
    _d("local-storage", SYMPTOM, "STORAGE",
       "the Directory Server's file system is read-only or has less free space than the threshold"),
    _d("ds-keytab-local", SYMPTOM, "KEYTAB",
       "the Directory Server keytab is missing, not readable by the dirsrv user, or lacks this server's ldap/ key"),
    _d("pair-clock-skew", SYMPTOM, "TIME",
       "this host's clock differs from the peer's root DSE currentTime by at least the 300 s Kerberos tolerance"),
    _d("peer-name-unresolved-now", SYMPTOM, "DNS",
       "the peer's name does not resolve through this host's resolver now (the agreement's recorded status may still "
       "show its last session as successful)"),
    _d("peer-ds-refused-now", SYMPTOM, "PEER_DS",
       "the agreement's LDAP port is refused now while 443 on the same peer accepts connections (the recorded status "
       "may still show the last session as successful)"),
    _d("peer-no-ldap-answer-now", SYMPTOM, "PEER_DS",
       "this host's own read of the peer's root DSE gets no LDAP answer now (the recorded status may still show the "
       "last session as successful)"),
    _d("peer-tls-fails-now", SYMPTOM, "TLS",
       "this host's own TLS connection to the agreement's port fails at the TLS layer now"),
    _d("reverse-acceptor-kerberos", "REPLICATION", "KERBEROS",
       "the peer's agreement towards this server fails with LDAP 49 or a GSSAPI class: its GSSAPI bind fails, and "
       "this server is the side that accepts it"),
    _d("acceptor-keytab-unusable", "KERBEROS", "KEYTAB",
       "this server, the accepting side of that GSSAPI bind, cannot use its own Directory Server keytab (missing, "
       "not readable by dirsrv, or without its ldap/ key)"),
    _d("status-transport", "REPLICATION", "PEER_DS",
       "status class TRANSPORT and this host's own read of the peer's root DSE gets no LDAP answer"),
    _d("peer-ds-refused-host-up", "REPLICATION", "PEER_DS",
       "status class TRANSPORT, the agreement's LDAP port is REFUSED while 443 on the same peer accepts connections: "
       "the host is up and reachable; its Directory Server is not accepting connections on that port"),
    _d("peer-name-unresolved", "REPLICATION", "DNS",
       "status class TRANSPORT and the peer's name does not resolve through this host's resolver (getent)"),
    _d("peer-unreachable", "PEER_DS", "NETWORK",
       "TCP to the agreement's port AND to 443 on the peer time out or are unreachable from this host"),
    _d("status-gssapi", "REPLICATION", "KERBEROS",
       "status class is a GSSAPI/Kerberos class, or this host's reproduction of the supplier's GSSAPI bind fails "
       "with one"),
    _d("kerberos-no-kdc-local-down", "KERBEROS", "LOCAL_KDC",
       "the Kerberos error is 'cannot contact any KDC' and this server's own krb5kdc is not active"),
    _d("kdc-needs-local-ds", "LOCAL_KDC", "LOCAL_DS",
       "krb5kdc is not active and this server's Directory Server (the KDC's database back end) is not active either"),
    _d("kerberos-clock-skew", "KERBEROS", "TIME",
       "a Kerberos clock-skew error and this host's clock differs from the peer's root DSE currentTime by at least "
       "the 300 s Kerberos tolerance"),
    _d("kerberos-server-principal-absent", "KERBEROS", "PRINCIPAL",
       "'server not found in Kerberos database' and the peer's ldap/ service principal is absent from this "
       "server's complete list of ldap/ principals"),
    _d("kerberos-local-credentials", "KERBEROS", "KEYTAB",
       "a Kerberos credentials error and the Directory Server keytab is missing, unreadable for dirsrv, lacks the "
       "ldap/ key of this server, or the KDC rejects that key (kinit -k)"),
    _d("status-invalid-credentials-gssapi", "REPLICATION", "KERBEROS",
       "status LDAP 49 on a SASL/GSSAPI agreement, and this host's reproduction obtains its ticket but the peer "
       "rejects the GSSAPI bind with LDAP 49 as well (the failure is on the accepting side)"),
    _d("status-access", "REPLICATION", "AUTHORIZATION",
       "status class INSUFFICIENT_ACCESS (LDAP 50 / replication permission denied)"),
    _d("access-not-a-manager", "AUTHORIZATION", "PRINCIPAL",
       "this server's ldap/ principal is not a member of cn=replication managers in this server's copy of the "
       "directory (the peer's copy may differ)"),
    _d("status-data", "REPLICATION", "REPLICA_DATA",
       "status class says the consumer's data needs administrator action (changelog purged, generation ID "
       "mismatch, replica ID conflict, re-initialization required)"),
    _d("status-tls", "REPLICATION", "TLS",
       "status class TLS, or the status says the connection failed and this host's own TLS connection to the "
       "agreement's port fails at the TLS layer"),
    _d("kerberos-49-with-measured-skew", "KERBEROS", "TIME",
       "a GSSAPI bind refused with LDAP 49 (this host obtained its ticket) and a clock difference of at least the "
       "300 s Kerberos tolerance measured between the two servers"),
    _d("storage-under-ds", "LOCAL_DS", "STORAGE",
       "the Directory Server is not active and its file system is read-only or nearly full"),
]}


@dataclasses.dataclass
class Link:
    claim: str
    subject: str
    capability: str
    evidence: List[str]
    discriminator: str
    scope: str = "local"
    """where the cause lives: local (this server) | peer (another server) | pair (between them) | unknown."""

    def as_dict(self) -> Dict[str, object]:
        return {"claim": self.claim, "subject": self.subject, "capability": self.capability,
                "evidence": list(self.evidence), "discriminator": self.discriminator, "scope": self.scope}


@dataclasses.dataclass
class Chain:
    chain_id: str
    subject: str
    links: List[Link]
    boundary: str = ""
    """why the chain stops where it does (what could not be proven next)."""
    next_action: List[str] = dataclasses.field(default_factory=list)
    handoff: Optional[Dict[str, str]] = None
    """{host, command, why} when the remaining evidence is local to another server."""

    @property
    def root(self) -> Link:
        return self.links[-1]

    def as_dict(self) -> Dict[str, object]:
        return {"chain_id": self.chain_id, "subject": self.subject, "links": [x.as_dict() for x in self.links],
                "deepest_proven": self.root.as_dict(), "boundary": self.boundary, "next_action": list(self.next_action),
                "handoff": dict(self.handoff) if self.handoff else None}


class ChainError(ValueError):
    pass


def check_chain(chain: Chain) -> None:
    """Every link must come from a registered discriminator whose (source, target) is exactly the step the link
    takes, and every step must be an edge of the capability DAG. Raises ChainError otherwise (a programming error:
    such a chain is never reported)."""

    prev = SYMPTOM
    for i, link in enumerate(chain.links):
        d = DISCRIMINATORS.get(link.discriminator)
        if d is None:
            raise ChainError(f"link {i} of {chain.chain_id}: unknown discriminator {link.discriminator}")
        if d.source != prev or d.target != link.capability:
            raise ChainError(f"link {i} of {chain.chain_id}: {d.disc_id} is for {d.source}->{d.target}, not "
                             f"{prev}->{link.capability}")
        if prev != SYMPTOM and link.capability not in DEPENDS_ON.get(prev, frozenset()):
            raise ChainError(f"link {i} of {chain.chain_id}: {prev}->{link.capability} is not in the capability DAG")
        if not link.evidence:
            raise ChainError(f"link {i} of {chain.chain_id}: no evidence")
        prev = link.capability


def edges() -> List[Tuple[str, str]]:
    return sorted((a, b) for a, bs in DEPENDS_ON.items() for b in bs)
