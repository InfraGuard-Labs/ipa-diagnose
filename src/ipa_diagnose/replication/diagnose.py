"""L4 for replication: explicit cause chains per subject, diagnoses with causal roles, peer handoffs.

Principles (docs/replication-mode.md):

1. **Direction and suffix are part of the identity.** A replication relationship is (supplier, consumer, suffix); its
   subject is ``<suffix>:<supplier>><consumer>``. This server sees its own OUTBOUND agreements; the reverse direction
   is only what was read from the peer, never inferred.
2. **A link needs a discriminator.** Every step of a chain comes from a registered rule
   (:data:`ipa_diagnose.replication.causal.DISCRIMINATORS`) that fired on established evidence. A dependency never
   proves a cause. When the next link cannot be proven the chain STOPS, says why (``boundary``) and names the precise
   next action - for a cause local to another server, a handoff to that server.
3. **No story is forced.** Independent causes are separate chains (PRIMARY + INDEPENDENT); chains may share a root
   (one stopped KDC explains both suffixes' agreements); a failure nothing explains is UNDIAGNOSED; evidence that
   disagrees is CONTRADICTING; a transient state (busy, backoff, no session yet) is never green and never a root.
4. **No deeper claim than the evidence.** A 900 s clock difference is reported as that; "chronyd stopped" on the peer
   is never claimed from here. A refused port with the host up is "not accepting connections", not "stopped". A
   timeout is "unreachable from <this host> at <time>", never "dead".
"""

from __future__ import annotations

import dataclasses
import datetime
import shlex
from typing import Any, Dict, List, Optional, Tuple

from ipa_diagnose.planner.core import Outcome, Trace
from ipa_diagnose.replication import status as S
from ipa_diagnose.replication.causal import Chain, Link, check_chain

P, W, F, U, SK = Outcome.PASS, Outcome.WARN, Outcome.FAIL, Outcome.UNKNOWN, Outcome.SKIPPED
PASSISH = (P, W)
PRIMARY, INDEPENDENT, RELATED, UNDIAGNOSED, CONTRADICTING, WARNING = (
    "PRIMARY", "INDEPENDENT", "RELATED", "UNDIAGNOSED", "CONTRADICTING", "WARNING")
TRANSIENT = "TRANSIENT"
KRB_TOLERANCE = 300
CLOCK_WARN = 60
LONG_SESSION_SECONDS = 1800

LAYER = {"STORAGE": 0, "LOCAL_DS": 1, "LOCAL_KDC": 2, "KEYTAB": 3, "TIME": 4, "PRINCIPAL": 5, "DNS": 6,
         "NETWORK": 7, "PEER_DS": 8, "TLS": 9, "KERBEROS": 10, "AUTHORIZATION": 11, "REPLICA_DATA": 12,
         "REPLICATION": 13, "TOPOLOGY": 14}


@dataclasses.dataclass
class ReplDiagnosis:
    code: str
    subject: str
    title: str
    capability: str
    severity: str  # FAIL | WARN
    confidence: str  # HIGH | MEDIUM | LOW
    detail: str
    impact: str
    evidence: List[str]
    scope: str = "local"  # local | peer | pair | directory | unknown
    kind: Optional[str] = None  # None | UNDIAGNOSED | CONTRADICTING | TRANSIENT
    chain_ids: List[str] = dataclasses.field(default_factory=list)
    related_to: Optional[str] = None
    """the key (code@subject) of the diagnosis that explains this one."""
    explains: List[str] = dataclasses.field(default_factory=list)
    next_steps: List[str] = dataclasses.field(default_factory=list)
    handoff: Optional[Dict[str, str]] = None
    resolution_key: Optional[str] = None
    variant: Optional[str] = None
    bindings: Dict[str, Any] = dataclasses.field(default_factory=dict)
    role: str = ""

    @property
    def key(self) -> str:
        return f"{self.code}@{self.subject}"


def rel(suffix: str, supplier: str, consumer: str) -> str:
    return f"{suffix}:{supplier}>{consumer}"


def _q(v: Any) -> str:
    return shlex.quote(str(v))


class _T:
    def __init__(self, trace: Trace):
        self.trace = trace

    def rec(self, sid: str, subject: Optional[str] = None):
        return self.trace.get(sid, subject=subject)

    def o(self, sid: str, subject: Optional[str] = None) -> Optional[Outcome]:
        r = self.rec(sid, subject)
        return r.outcome if r else None

    def f(self, sid: str, name: str, default: Any = None, subject: Optional[str] = None) -> Any:
        r = self.rec(sid, subject)
        if r is None or r.outcome == SK:
            return default
        return r.facts.get(name, r.fields.get(name, default))


class _Builder:
    def __init__(self) -> None:
        self.diags: Dict[str, ReplDiagnosis] = {}
        self.chains: List[Chain] = []

    def add(self, d: ReplDiagnosis) -> ReplDiagnosis:
        if d.key in self.diags:
            old = self.diags[d.key]
            old.evidence = sorted(set(old.evidence) | set(d.evidence))
            return old
        self.diags[d.key] = d
        return d

    def get(self, code: str, subject: str) -> Optional[ReplDiagnosis]:
        return self.diags.get(f"{code}@{subject}")

    def chain(self, subject: str, links: List[Link], boundary: str = "", next_action: Optional[List[str]] = None,
              handoff: Optional[Dict[str, str]] = None) -> Chain:
        c = Chain(f"chain-{len(self.chains) + 1}:{subject}", subject, links, boundary, list(next_action or []), handoff)
        check_chain(c)  # a link without a registered discriminator for exactly that step is a programming error
        self.chains.append(c)
        return c


def handoff(peer: str, me: str, why: str) -> Dict[str, str]:
    return {"host": peer, "command": f"sudo ipa-diagnose replication --peer {_q(me)}",
            "why": why + f" Nothing was changed on {me} or {peer}; ipa-diagnose never changes another server."}


def _ago(iso: Optional[str]) -> Optional[float]:
    if not iso:
        return None
    try:
        t = datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    return (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds()


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- local prerequisites


def _local(t: _T, b: _Builder, me: str) -> Dict[str, Optional[ReplDiagnosis]]:
    here = f"server:{me}"
    roots: Dict[str, Optional[ReplDiagnosis]] = {"ds": None, "kdc": None, "storage": None, "keytab": None}
    storage_bad = t.o("local.storage") == F
    ds_down = t.o("local.ds") == F
    kdc_down = t.o("local.kdc") == F
    inst = t.f("server", "ds_instance") or "INSTANCE"
    if storage_bad:
        st = t.f("local.storage", "state")
        what = "read-only" if st == "read_only" else "nearly full"
        c = b.chain(here, [Link(f"the Directory Server's file system on {me} is {what}", here, "STORAGE",
                                ["local.storage"], "local-storage", "local")],
                    boundary="ipa-diagnose does not print commands that free space or remount file systems",
                    next_action=["df -h /var/lib/dirsrv   (read-only)", "findmnt -T /var/lib/dirsrv   (read-only)"])
        roots["storage"] = b.add(ReplDiagnosis(
            "DS_STORAGE_PROBLEM", here, f"The Directory Server's file system on {me} is {what}", "STORAGE", "FAIL",
            "HIGH", t.rec("local.storage").summary + ".",
            "The Directory Server cannot write its database or changelog: replication of this server stops.",
            ["local.storage"], "local", chain_ids=[c.chain_id], next_steps=c.next_action))
    if ds_down:
        links = [Link(f"this server's Directory Server (dirsrv@{inst}) is not running", here, "LOCAL_DS",
                      ["local.ds"], "local-ds-down", "local")]
        if storage_bad:
            links.append(Link(roots["storage"].title, here, "STORAGE", ["local.storage", "local.ds"],
                              "storage-under-ds", "local"))
        c = b.chain(here, links, boundary="" if storage_bad else "why it stopped is in its own log",
                    next_action=[f"systemctl status dirsrv@{inst}   (read-only)",
                                 f"journalctl -u dirsrv@{inst} -n 50   (read-only)"])
        d = b.add(ReplDiagnosis(
            "LOCAL_DS_NOT_RUNNING", here, f"This server's Directory Server is not running", "LOCAL_DS", "FAIL", "HIGH",
            t.rec("local.ds").summary + ". Its agreements cannot run, and its agreements, topology and RUV cannot be "
            "read (they are read over its LDAPI socket).",
            "No replication to or from this server; IPA on this server (LDAP, KDC, API) does not work.",
            ["local.ds"], "local", chain_ids=[c.chain_id], next_steps=c.next_action,
            related_to=roots["storage"].key if storage_bad else None,
            # the start is offered only when the file system under it is established fine (UNKNOWN withholds)
            resolution_key="healthcheck.service-not-running" if t.o("local.storage") in (P, W) else None,
            bindings={"service": "dirsrv"} if t.o("local.storage") in (P, W) else {}))
        if storage_bad:
            roots["storage"].explains.append(d.key)
        roots["ds"] = d
    if kdc_down:
        links = [Link(f"this server's KDC (krb5kdc) is not running", here, "LOCAL_KDC", ["local.kdc"],
                      "local-kdc-down", "local")]
        if ds_down:
            links.append(Link("the KDC's database back end, this server's Directory Server, is not running", here,
                              "LOCAL_DS", ["local.ds", "local.kdc"], "kdc-needs-local-ds", "local"))
        c = b.chain(here, links, next_action=["systemctl status krb5kdc   (read-only)",
                                              "journalctl -u krb5kdc -n 50   (read-only)"])
        d = b.add(ReplDiagnosis(
            "LOCAL_KDC_NOT_RUNNING", here, "This server's KDC (krb5kdc) is not running", "LOCAL_KDC", "FAIL", "HIGH",
            t.rec("local.kdc").summary + ".",
            "No Kerberos ticket is issued by this server. Its GSSAPI replication agreements fail once the Directory "
            "Server's current tickets expire (if this server's Kerberos configuration names only itself); clients "
            "and other servers that use this KDC fail over to others or fail.",
            ["local.kdc"], "local", chain_ids=[c.chain_id], next_steps=c.next_action,
            related_to=roots["ds"].key if ds_down else None,
            resolution_key=None if ds_down else "healthcheck.service-not-running",
            bindings={} if ds_down else {"service": "krb5kdc"}))
        if ds_down:
            roots["ds"].explains.append(d.key)
        roots["kdc"] = d
    kt = t.f("local.keytab", "state")
    if t.o("local.keytab") == F:
        what = {"missing": "is missing", "not_regular": "is not a plain regular file (symlink or hard link)",
                "unreadable_for_dirsrv": "cannot be read by the dirsrv user",
                "unreadable": "cannot be listed", "principal_missing": "has no key for this server's ldap/ principal"}
        c = b.chain(here, [Link(f"/etc/dirsrv/ds.keytab {what.get(kt, 'is not usable')}", here, "KEYTAB",
                                ["local.keytab"], "ds-keytab-local", "local")],
                    boundary="ipa-diagnose does not print keytab replacement or ownership changes for ds.keytab in "
                             "this version",
                    next_action=["ls -lZ /etc/dirsrv/ds.keytab   (read-only)",
                                 "klist -k /etc/dirsrv/ds.keytab   (read-only; principals only)",
                                 "ipa-healthcheck --source ipahealthcheck.ipa.files   (read-only; checks the owner and "
                                 "mode IPA expects)"])
        roots["keytab"] = b.add(ReplDiagnosis(
            "DS_KEYTAB_PROBLEM", here, f"The Directory Server keytab {what.get(kt, 'is not usable')}", "KEYTAB",
            "FAIL", "HIGH", t.rec("local.keytab").summary + ".",
            "The Directory Server cannot authenticate with Kerberos: this server's GSSAPI agreements (and GSSAPI binds "
            "to it) fail once current tickets expire or the Directory Server restarts.", ["local.keytab"], "local",
            chain_ids=[c.chain_id], next_steps=c.next_action, resolution_key="replication.ds-keytab-problem",
            variant=kt))
    elif t.o("local.keytab") == W and kt == "world_readable":
        b.add(ReplDiagnosis("DS_KEYTAB_EXPOSED", here, "The Directory Server keytab is world-readable", "KEYTAB",
                            "WARN", "HIGH", t.rec("local.keytab").summary + ".",
                            "Anyone on this host can read the key of this server's LDAP service (a security problem, "
                            "not a replication failure).", ["local.keytab"], "local",
                            next_steps=["ls -l /etc/dirsrv/ds.keytab   (read-only)"]))
    if t.o("local.storage") == W:
        b.add(ReplDiagnosis("DS_STORAGE_LOW", here, "The Directory Server's file system is running out of space",
                            "STORAGE", "WARN", "HIGH", t.rec("local.storage").summary + ".",
                            "Replication and the Directory Server stop when it is full.", ["local.storage"], "local",
                            next_steps=["df -h /var/lib/dirsrv   (read-only)"]))
    return roots


# ---------------------------------------------------------------- one outbound agreement


def _gssapi_chain(t: _T, b: _Builder, me: str, realm: str, item: Dict[str, Any], subj: str, rel_key: str,
                  eff: str, base_links: List[Link], roots: Dict[str, Optional[ReplDiagnosis]], where: str = ""
                  ) -> Tuple[Optional[ReplDiagnosis], Chain]:
    consumer = item["consumer"]
    here = f"server:{me}"
    gs = t.rec("gssapi", subj)
    ev_gs = ["agreements"] + ([gs.step_id] if gs and gs.outcome != SK else [])
    L1 = Link(f"the GSSAPI (Kerberos) bind of {me} to {consumer} fails: {S.MEANING.get(eff, eff)}"
              + (f" (shown by {where})" if where else ""), rel_key, "KERBEROS", ev_gs, "status-gssapi", "local")
    links = base_links + [L1]
    if eff == S.GSSAPI_NO_KDC:
        if roots["kdc"] is not None:
            links.append(Link("this server's KDC (krb5kdc) is not running", here, "LOCAL_KDC",
                              ev_gs + ["local.kdc"], "kerberos-no-kdc-local-down", "local"))
            if roots["ds"] is not None:
                links.append(Link("the KDC's database back end, this server's Directory Server, is not running", here,
                                  "LOCAL_DS", ["local.ds", "local.kdc"], "kdc-needs-local-ds", "local"))
            c = b.chain(rel_key, links)
            root = roots["ds"] if roots["ds"] is not None and roots["kdc"].related_to else roots["kdc"]
            return root, c
        c = b.chain(rel_key, links, boundary=(f"this server's krb5kdc is running, yet no KDC was reached: which KDCs "
                                              f"this host's Kerberos configuration names for {realm} is not checked"),
                    next_action=[f"grep -A6 '^ *{realm} *=' /etc/krb5.conf   (read-only)",
                                 "systemctl status krb5kdc   (read-only)"])
        return None, c
    if eff == S.GSSAPI_CLOCK_SKEW:
        off, orec, where = peer_offset(t, subj)
        if isinstance(off, (int, float)) and abs(off) >= KRB_TOLERANCE:
            pair = f"pair:{me}>{consumer}"
            links.append(Link(f"{me}'s clock is {abs(off):.0f} s {'ahead of' if off >= 0 else 'behind'} {consumer}'s "
                              f"(measured from {consumer}'s {where})", pair, "TIME",
                              ev_gs + [orec.step_id], "kerberos-clock-skew", "pair"))
            root = _pair_skew(t, b, me, consumer, subj, off, via_chain=True)
            c = b.chain(rel_key, links, boundary=(f"which clock is wrong is not established from here: {consumer}'s "
                                                  f"time service can only be checked on {consumer}"),
                        next_action=root.next_steps, handoff=root.handoff)
            root.chain_ids.append(c.chain_id)
            return root, c
        c = b.chain(rel_key, links, boundary=(
            "the clock difference measured now is under the Kerberos tolerance or could not be read: the skew may "
            "have been corrected since the last session, or another KDC's clock is wrong"),
            next_action=["chronyc tracking   (read-only, here and on " + consumer + ")"])
        return None, c
    if eff == S.GSSAPI_SERVER_NOT_FOUND:
        principals = t.f("principals", "ldap_principals")
        complete = t.f("principals", "complete") is True
        pname = f"ldap/{consumer}@{realm}"
        if complete and isinstance(principals, list) and consumer not in principals:
            links.append(Link(f"{pname} is not in this server's copy of the directory", f"principal:{pname}",
                              "PRINCIPAL", ev_gs + ["principals"], "kerberos-server-principal-absent", "directory"))
            c = b.chain(rel_key, links, boundary=("re-creating a server's service principal and its keys is not "
                                                  "printed by ipa-diagnose (it affects the whole topology)"),
                        next_action=[f"ipa service-show {_q(pname)}   (read-only, with an admin ticket)",
                                     f"ipa server-show {_q(consumer)}   (read-only)"])
            root = b.add(ReplDiagnosis(
                "PEER_LDAP_PRINCIPAL_MISSING", f"principal:{pname}", f"The service principal {pname} does not exist",
                "PRINCIPAL", "FAIL", "HIGH",
                f"The KDC answers 'server not found in Kerberos database' for {pname}, and this server's copy of the "
                "directory has no such principal.",
                f"No server can obtain a Kerberos ticket for {consumer}'s LDAP service: GSSAPI replication to "
                f"{consumer} fails from every supplier.", ev_gs + ["principals"], "directory",
                next_steps=c.next_action, resolution_key="replication.peer-principal-missing"))
            return root, c
        c = b.chain(rel_key, links, boundary=(
            f"{pname} exists in this server's copy of the directory" if complete and isinstance(principals, list)
            else "whether the principal exists could not be established") +
            ": the KDC that answered may hold another copy (replication lag), or the agreement names the consumer "
            "differently", next_action=[f"ipa service-show {_q(pname)}   (read-only)"])
        return None, c
    if eff == S.GSSAPI_CREDENTIALS or (gs and gs.facts.get("kinit_class") in ("key_rejected", "keytab_no_entry",
                                                                                "principal_unknown")):
        if roots["keytab"] is not None:
            links.append(Link(roots["keytab"].title, here, "KEYTAB", ev_gs + ["local.keytab"],
                              "kerberos-local-credentials", "local"))
            c = b.chain(rel_key, links, boundary=("ipa-diagnose does not print keytab replacement or ownership changes "
                                                  "for ds.keytab in this version"),
                        next_action=roots["keytab"].next_steps)
            return roots["keytab"], c
        kc = gs.facts.get("kinit_class") if gs else None
        if kc in ("key_rejected", "keytab_no_entry", "principal_unknown"):
            what = {"key_rejected": "the KDC rejects the key in /etc/dirsrv/ds.keytab",
                    "keytab_no_entry": "/etc/dirsrv/ds.keytab has no usable key for it",
                    "principal_unknown": "the KDC does not know the principal"}[kc]
            principal = f"ldap/{me}@{realm}"
            links.append(Link(f"kinit as {principal}: {what}", here, "KEYTAB", ev_gs + ["local.keytab"],
                              "kerberos-local-credentials", "local"))
            c = b.chain(rel_key, links, boundary=("replacing the Directory Server's keytab is not printed by "
                                                  "ipa-diagnose in this version"),
                        next_action=["klist -k /etc/dirsrv/ds.keytab   (read-only; key versions)",
                                     f"kvno {_q(principal)}   (read-only; with an admin ticket: the KDC's key "
                                     "version)"])
            root = b.add(ReplDiagnosis(
                "DS_KEY_REJECTED", here, f"The KDC does not accept this server's LDAP service key", "KEYTAB", "FAIL",
                "HIGH", f"kinit with {principal} from /etc/dirsrv/ds.keytab fails ({kc.replace('_', ' ')}): {what}.",
                "The Directory Server cannot obtain Kerberos tickets: its GSSAPI agreements fail.", ev_gs, "local",
                next_steps=c.next_action, resolution_key="replication.ds-keytab-problem", variant=kc))
            return root, c
        got_ticket = gs is not None and gs.facts.get("kinit_ok") is True
        c = b.chain(rel_key, links, boundary=(
            "this host's reproduction obtained its own ticket: the credentials problem the Directory Server had "
            "could not be reproduced (it may use a cached ticket or have been fixed since)" if got_ticket else
            "the reproduction did not establish which credential fails"),
            next_action=["journalctl -u dirsrv@* -n 50 | grep -i gssapi   (read-only)"])
        return None, c
    c = b.chain(rel_key, links, boundary="the GSSAPI error is not one ipa-diagnose can take further",
                next_action=["journalctl -u dirsrv@* -n 50   (read-only)"])
    return None, c


def peer_offset(t: _T, subj: str):
    """The peer's clock offset as measured from this host (root DSE currentTime, else its HTTPS Date header):
    (offset or None, the step that measured it, where it came from)."""

    for base, where in (("peer.rootdse", "root DSE"), ("peer.time", "HTTPS Date header")):
        r = t.rec(base, subj)
        off = r.facts.get("offset") if r is not None and r.outcome != SK else None
        if isinstance(off, (int, float)):
            return off, r, where
    return None, None, None


_KINIT_TO_CLASS = {"kdc_unreachable": S.GSSAPI_NO_KDC, "kdc_unresolvable": S.GSSAPI_NO_KDC,
                   "clock_skew": S.GSSAPI_CLOCK_SKEW, "key_rejected": S.GSSAPI_CREDENTIALS,
                   "keytab_no_entry": S.GSSAPI_CREDENTIALS, "principal_unknown": S.GSSAPI_CREDENTIALS,
                   "principal_revoked": S.GSSAPI_CREDENTIALS}
_SPECIFIC = (S.GSSAPI_NO_KDC, S.GSSAPI_CLOCK_SKEW, S.GSSAPI_SERVER_NOT_FOUND, S.GSSAPI_CREDENTIALS)
NOT_REPRODUCED, PEER_REJECTS, SKEW_49, NO_REPRODUCTION = "NOT_REPRODUCED", "PEER_REJECTS", "SKEW_49", "NO_REPRODUCTION"


def kerberos_class(cls: str, gs: Any, off: Optional[float]) -> "tuple[str, str]":
    """What the Kerberos failure of a SASL/GSSAPI agreement is: 389-DS usually records only 'Local error
    (connection error)' or 'Invalid credentials' in the agreement status, so the specific class comes from the status
    when it names one, and otherwise from ipa-diagnose's own reproduction of the supplier's bind (kinit with the
    Directory Server's key, then the GSSAPI bind). Returns (class, where it came from)."""

    if cls in _SPECIFIC:
        return cls, "the agreement's status"
    if gs is None or gs.outcome in (SK, U):
        return NO_REPRODUCTION, ""
    if gs.outcome == P:
        return NOT_REPRODUCED, "reproduction"
    if gs.facts.get("kinit_ok") is False:
        return _KINIT_TO_CLASS.get(gs.facts.get("kinit_class"), S.GSSAPI_OTHER), "reproduction (kinit)"
    bce = gs.facts.get("error_class")
    if bce in _SPECIFIC:
        return bce, "reproduction (bind)"
    if bce == S.INVALID_CREDENTIALS:
        if isinstance(off, (int, float)) and abs(off) >= KRB_TOLERANCE:
            return SKEW_49, "reproduction (bind)"
        return PEER_REJECTS, "reproduction (bind)"
    return S.GSSAPI_OTHER, "reproduction (bind)"


def _pair_skew(t: _T, b: _Builder, me: str, consumer: str, subj: str, off: float, via_chain: bool) -> ReplDiagnosis:
    pair = f"pair:{me}>{consumer}"
    existing = b.get("PAIR_CLOCK_SKEW", pair)
    if existing is not None:
        return existing
    sync = t.f("time.local", "synchronized")
    local_off = t.f("time.local", "offset")
    local_note = ("" if t.o("time.local") in (None, SK, U) else
                  f" This host's own time service is {'synchronized' if sync else 'NOT synchronized'}"
                  + (f" (offset {local_off:+.3f} s to its source)" if isinstance(local_off, (int, float)) else "")
                  + (": this host's clock may be the wrong one." if not sync else "."))
    _o, rec, where = peer_offset(t, subj)
    detail = (f"{me}'s clock is {abs(off):.0f} s {'ahead of' if off >= 0 else 'behind'} {consumer}'s, measured from "
              f"{consumer}'s {where}; Kerberos refuses more than {KRB_TOLERANCE} s.{local_note} Which clock is wrong "
              f"is not established from here: {consumer}'s time service can only be checked on {consumer}")
    ev = [rec.step_id] + (["time.local"] if t.o("time.local") not in (None, SK) else [])
    c = None
    if not via_chain:
        c = b.chain(pair, [Link(f"{me}'s clock differs from {consumer}'s by {abs(off):.0f} s", pair, "TIME", ev,
                                "pair-clock-skew", "pair")],
                    boundary=f"which clock is wrong is not established from here", next_action=[
                        "chronyc tracking; chronyc sources   (read-only, here)"],
                    handoff=handoff(consumer, me, f"{consumer}'s time service can only be checked on {consumer}."))
    return b.add(ReplDiagnosis(
        "PAIR_CLOCK_SKEW", pair, f"The clocks of {me} and {consumer} are {abs(off):.0f} s apart", "TIME", "FAIL",
        "HIGH", detail + ".",
        "Kerberos (GSSAPI) replication between them fails whenever a new ticket is needed; logins that cross them "
        "fail too.", ev, "pair", chain_ids=[c.chain_id] if c else [],
        next_steps=["chronyc tracking; chronyc sources   (read-only, here)",
                    f"on {consumer}: chronyc tracking; timedatectl   (read-only)"],
        handoff=handoff(consumer, me, f"{consumer}'s time service can only be checked on {consumer}."),
        resolution_key="replication.pair-clock-skew"))


# discriminator for each peer-path link: after a failing agreement status (REPLICATION -> ...) or, when the recorded
# status is still green but this host's own checks of the peer fail now, as the first link of a chain (SYMPTOM -> ...)
_PEER_DISC = {
    False: {"dns": "peer-name-unresolved", "refused": "peer-ds-refused-host-up", "noanswer": "status-transport",
            "tls": "status-tls"},
    True: {"dns": "peer-name-unresolved-now", "refused": "peer-ds-refused-now", "noanswer": "peer-no-ldap-answer-now",
           "tls": "peer-tls-fails-now"},
}


def _peer_path(t: _T, b: _Builder, me: str, item: Dict[str, Any], subj: str, rel_key: str, base: List[Link],
               now: bool):
    """Name resolution, port, root DSE and host reachability of the consumer as observed from this host now.
    Returns (root, chain), "ANSWERS" when the peer answers LDAP now, or None when nothing could be established."""

    consumer = item["consumer"]
    port = item.get("port") or "?"
    status_text = item.get("status_text") or "(no status)"
    disc = _PEER_DISC[now]
    rd = t.rec("peer.rootdse", subj)
    dns, prt, https = t.rec("peer.dns", subj), t.rec("peer.port", subj), t.rec("peer.https", subj)
    pstate = prt.facts.get("state") if prt and prt.outcome in (P, F) else None
    hstate = https.facts.get("state") if https and https.outcome in (P, F) else None
    peer_here = f"server:{consumer}"
    stale = (f" The agreement's own status still shows its last session as successful (ended "
             f"{item.get('last_update_end') or 'at an unknown time'}); it has not recorded this yet."
             if now else "")
    if dns is not None and dns.outcome == F:
        pair = f"pair:{me}>{consumer}"
        chain = b.chain(rel_key, base + [Link(f"{consumer} does not resolve through {me}'s resolver", pair, "DNS",
                                              [dns.step_id], disc["dns"], "local")],
                        boundary=("why the name does not resolve on this host (a missing or stale record, the "
                                  "resolvers this host uses, /etc/hosts) is not established"),
                        next_action=[f"getent ahosts {_q(consumer)}   (read-only)", "cat /etc/resolv.conf",
                                     f"dig {_q(consumer)}   (if bind-utils is installed; read-only)"])
        root = b.add(ReplDiagnosis(
            "PEER_NAME_UNRESOLVED", pair, f"{consumer} does not resolve from {me}", "DNS", "FAIL", "HIGH",
            dns.summary + f" (observed from {me})." + stale,
            f"{me} cannot reach {consumer} by the name its agreements use: replication {me} -> {consumer} stops.",
            [dns.step_id], "local", next_steps=chain.next_action))
        return root, chain
    if rd is None or rd.outcome == SK or rd.outcome == U:
        return None
    if rd.outcome in PASSISH:
        return "ANSWERS"
    if rd.facts.get("error_class") == S.TLS:
        return _tls_root(b, me, consumer, rel_key, base, [rd.step_id], port, disc["tls"])
    if pstate == "refused" and hstate == "open":
        chain = b.chain(rel_key, base + [Link(
            f"{consumer} is up (443 answers) but refuses connections on port {port}: its Directory Server is "
            "not accepting connections", peer_here, "PEER_DS", [prt.step_id, https.step_id, rd.step_id],
            disc["refused"], "peer")],
            boundary=(f"whether the Directory Server on {consumer} is stopped, has failed or listens "
                      f"elsewhere can only be seen on {consumer}"),
            handoff=handoff(consumer, me, f"The remaining evidence is local to {consumer}."),
            next_action=[f"on {consumer}: systemctl status dirsrv@{t.f('server', 'ds_instance') or '*'}; "
                         "ipactl status   (read-only)"])
        root = b.add(ReplDiagnosis(
            "PEER_DS_NOT_ACCEPTING", peer_here, f"{consumer}'s Directory Server does not accept connections",
            "PEER_DS", "FAIL", "HIGH",
            f"From {me}: TCP {port} on {consumer} is refused while 443 answers ({prt.summary}; "
            f"{https.summary}); an anonymous LDAP read gets no answer." + stale,
            f"No replication to {consumer} (from any supplier that sees the same); LDAP clients of {consumer} "
            "fail over or fail.", [prt.step_id, https.step_id, rd.step_id], "peer",
            next_steps=chain.next_action, handoff=chain.handoff))
        return root, chain
    if pstate in ("timeout", "unreachable", "error") and hstate in ("timeout", "unreachable", "error"):
        pair = f"pair:{me}>{consumer}"
        when = ("an unrecorded time (recorded evidence)" if rd.source == "REPLAY"
                else rd.collected_at or _now())
        chain = b.chain(rel_key, base + [
            Link(f"{consumer}'s Directory Server gives no LDAP answer to {me}", peer_here, "PEER_DS",
                 [rd.step_id], disc["noanswer"], "peer"),
            Link(f"{consumer} is unreachable from {me} at {when} (TCP {port}: {pstate}, TCP 443: {hstate})",
                 pair, "NETWORK", [prt.step_id, https.step_id], "peer-unreachable", "pair")],
            boundary=("a host that is down and a network path that blocks this host look the same from here; "
                      f"nothing here says {consumer} is gone for good"),
            handoff=handoff(consumer, me, f"Whether {consumer} is running can only be seen on {consumer} "
                                          "(or its console)."),
            next_action=[f"on {me}: ip route get $(getent ahosts {_q(consumer)} | awk 'NR==1{{print $1}}')   "
                         "(read-only)", f"check whether {consumer} is running (its console) and the firewall "
                                        "between the two"])
        root = b.add(ReplDiagnosis(
            "PEER_UNREACHABLE", pair, f"{consumer} is unreachable from {me}", "NETWORK", "FAIL", "HIGH",
            f"Unreachable from {me} at {when}: TCP {port} {pstate}, TCP 443 {hstate}. The agreement's last "
            f"session ended {item.get('last_update_end') or 'at an unknown time'} with: {status_text}." + stale,
            f"No replication {me} -> {consumer}; changes pile up in {me}'s changelog until {consumer} is "
            "reachable again.", [prt.step_id, https.step_id, rd.step_id], "pair",
            next_steps=chain.next_action, handoff=chain.handoff))
        return root, chain
    confidence = "HIGH" if pstate == "open" else "MEDIUM"
    claim = (f"{consumer} accepts TCP on {port} but its Directory Server does not answer LDAP" if
             pstate == "open" else f"{consumer}'s Directory Server gives no LDAP answer to {me} "
             f"(TCP {port}: {pstate or 'not checked'}, 443: {hstate or 'not checked'})")
    chain = b.chain(rel_key, base + [Link(claim, peer_here, "PEER_DS", [x.step_id for x in (prt, rd) if x],
                                          disc["noanswer"], "peer")],
                    boundary=f"why it does not answer can only be seen on {consumer}",
                    handoff=handoff(consumer, me, f"The remaining evidence is local to {consumer}."),
                    next_action=[f"on {consumer}: ipactl status   (read-only)"])
    root = b.add(ReplDiagnosis(
        "PEER_DS_NOT_ANSWERING", peer_here, f"{consumer}'s Directory Server does not answer {me}",
        "PEER_DS", "FAIL", confidence, claim + "." + stale, f"No replication {me} -> {consumer}.",
        [x.step_id for x in (prt, rd) if x], "peer", next_steps=chain.next_action, handoff=chain.handoff))
    return root, chain


def _peer_now(t: _T, b: _Builder, me: str, item: Dict[str, Any], subj: str, rel_key: str) -> None:
    """The agreement's recorded status is green (or transient), but this host's own checks show the consumer does
    not answer NOW (389-DS keeps the last session's status until its next attempt is recorded - live lab, run
    36654176983): the peer-side cause is reported from those checks, without a failing-status link."""

    dns, rd = t.rec("peer.dns", subj), t.rec("peer.rootdse", subj)
    if (dns is not None and dns.outcome == F) or (rd is not None and rd.outcome == F):
        got = _peer_path(t, b, me, item, subj, rel_key, [], now=True)
        if isinstance(got, tuple):
            root, chain = got
            if chain.chain_id not in root.chain_ids:
                root.chain_ids.append(chain.chain_id)


def _agreement(t: _T, b: _Builder, me: str, realm: str, item: Dict[str, Any],
               roots: Dict[str, Optional[ReplDiagnosis]]) -> None:
    subj = item["subject"]
    consumer = item["consumer"]
    suffix = item["suffix_kind"]
    rel_key = rel(suffix, me, consumer)
    cls = item.get("status_class") or S.UNCLASSIFIED
    status_text = item.get("status_text") or "(no status)"
    ev0 = ["agreements"]
    port = item.get("port") or "?"
    if item.get("enabled") is False:
        b.add(ReplDiagnosis("AGREEMENT_DISABLED", rel_key, f"The {suffix} agreement {me} -> {consumer} is disabled",
                            "REPLICATION", "WARN", "HIGH", f"nsds5ReplicaEnabled is off on this agreement "
                            f"({item.get('name')}).", f"No {suffix} changes are sent from {me} to {consumer}.", ev0,
                            "local", next_steps=[f"ipa topologysegment-find {suffix}   (read-only)"]))
        return
    rd = t.rec("peer.rootdse", subj)
    off, orec, _where = peer_offset(t, subj)
    if cls == S.OK or cls in S.TRANSIENT:
        _peer_now(t, b, me, item, subj, rel_key)
    if cls == S.OK:
        age = _ago(item.get("last_update_start"))
        if item.get("update_in_progress") and age is not None and age > LONG_SESSION_SECONDS:
            b.add(ReplDiagnosis("LONG_RUNNING_SESSION", rel_key, f"A {suffix} session {me} -> {consumer} has been "
                                "running for a long time", "REPLICATION", "WARN", "MEDIUM",
                                f"UpdateInProgress is TRUE since {item.get('last_update_start')} ({age / 60:.0f} min).",
                                "Changes may be delayed.", ev0, "pair", kind=TRANSIENT))
        if isinstance(off, (int, float)) and abs(off) >= KRB_TOLERANCE:
            _pair_skew(t, b, me, consumer, subj, off, via_chain=False)
        elif isinstance(off, (int, float)) and abs(off) >= CLOCK_WARN:
            b.add(ReplDiagnosis("PAIR_CLOCK_DRIFT", f"pair:{me}>{consumer}", f"The clocks of {me} and {consumer} "
                                f"differ by {abs(off):.0f} s", "TIME", "WARN", "HIGH",
                                f"Measured from {consumer}'s {_where} (under the {KRB_TOLERANCE} s Kerberos "
                                "tolerance).", "No failure yet; Kerberos fails beyond 300 s.", [orec.step_id], "pair",
                                next_steps=["chronyc tracking   (read-only, here and on " + consumer + ")"]))
        return
    if cls in S.TRANSIENT:
        b.add(ReplDiagnosis(
            "REPLICATION_TRANSIENT", rel_key, f"The {suffix} agreement {me} -> {consumer} is not green yet "
            f"({cls.replace('_', ' ').lower()})", "REPLICATION", "WARN", "HIGH",
            f"{S.MEANING[cls]}. Status: {status_text}.",
            "Not a failure by itself, and not proof of health: 389-DS retries by itself. Run ipa-diagnose replication "
            "again after the next session.", ev0, "pair", kind=TRANSIENT,
            next_steps=[f"sudo ipa-diagnose replication --peer {_q(consumer)} --verify   (after a few minutes)"]))
        return
    L0 = Link(f"{me} -> {consumer} ({suffix} suffix) fails: {S.MEANING.get(cls, cls)}", rel_key, "REPLICATION", ev0,
              "agreement-status", "pair")
    root: Optional[ReplDiagnosis] = None
    chain: Optional[Chain] = None
    confidence = "HIGH"
    gs = t.rec("gssapi", subj)
    gssapi_agreement = str(item.get("bind_method") or "").upper() == "SASL/GSSAPI"
    if cls == S.TRANSPORT:
        got = _peer_path(t, b, me, item, subj, rel_key, [L0], now=False)
        if got == "ANSWERS":
            rd = t.rec("peer.rootdse", subj)
            b.add(ReplDiagnosis(
                "REPLICATION_NOT_REPRODUCED", rel_key, f"The last {suffix} session {me} -> {consumer} could not "
                "connect, but the peer answers now", "REPLICATION", "WARN", "MEDIUM",
                f"Status: {status_text}. {consumer}'s Directory Server answers LDAP from {me} now ({rd.summary}).",
                "389-DS retries by itself; the next session shows whether it is resolved.", ev0 + [rd.step_id], "pair",
                kind=TRANSIENT, next_steps=[f"sudo ipa-diagnose replication --peer {_q(consumer)} --verify   "
                                            "(after the next session)"]))
            return
        if got is not None:
            root, chain = got
    elif gssapi_agreement and (cls in S.GSSAPI or cls == S.INVALID_CREDENTIALS) \
            and kerberos_class(cls, gs, off)[0] in _SPECIFIC + (S.GSSAPI_OTHER,):
        eff, where = kerberos_class(cls, gs, off)
        root, chain = _gssapi_chain(t, b, me, realm, item, subj, rel_key, eff, [L0], roots, where)
    elif gssapi_agreement and kerberos_class(cls, gs, off)[0] == SKEW_49:
        pair = f"pair:{me}>{consumer}"
        root = _pair_skew(t, b, me, consumer, subj, off, via_chain=True)
        chain = b.chain(rel_key, [
            L0, Link(f"{me} obtains its Kerberos ticket, but {consumer} rejects the GSSAPI bind (LDAP 49)", rel_key,
                     "KERBEROS", ev0 + [gs.step_id], "status-invalid-credentials-gssapi", "peer"),
            Link(f"{me}'s clock is {abs(off):.0f} s {'ahead of' if off >= 0 else 'behind'} {consumer}'s: beyond the "
                 f"Kerberos tolerance, which explains a refused ticket", pair, "TIME",
                 [gs.step_id, orec.step_id], "kerberos-49-with-measured-skew", "pair")],
            boundary=(f"which clock is wrong is not established from here: {consumer}'s time service can only be "
                      f"checked on {consumer}"), next_action=root.next_steps, handoff=root.handoff)
        root.chain_ids.append(chain.chain_id)
    elif cls == S.INVALID_CREDENTIALS and gssapi_agreement and kerberos_class(cls, gs, off)[0] == PEER_REJECTS:
        peer_here = f"server:{consumer}"
        chain = b.chain(rel_key, [L0, Link(f"{me} obtains its Kerberos ticket, but {consumer} rejects the GSSAPI "
                                           "bind (LDAP 49)", peer_here, "KERBEROS", ev0 + [gs.step_id],
                                           "status-invalid-credentials-gssapi", "peer")],
                        boundary=(f"{consumer}'s side (its Directory Server keytab and key) can only be checked on "
                                  f"{consumer}"),
                        handoff=handoff(consumer, me, f"The remaining evidence is local to {consumer}."),
                        next_action=[f"on {consumer}: klist -k /etc/dirsrv/ds.keytab   (read-only)"])
        root = b.add(ReplDiagnosis(
            "PEER_REJECTS_GSSAPI", peer_here, f"{consumer} rejects {me}'s Kerberos bind", "KERBEROS", "FAIL", "MEDIUM",
            f"The agreement reports LDAP 49 and ipa-diagnose's own GSSAPI bind as ldap/{me}@{realm} is rejected the "
            f"same way ({gs.summary}), although {me} obtained its ticket.",
            f"No replication {me} -> {consumer}.", ev0 + [gs.step_id], "peer", next_steps=chain.next_action,
            handoff=chain.handoff))
    elif gssapi_agreement and (cls in S.GSSAPI or cls == S.INVALID_CREDENTIALS) \
            and kerberos_class(cls, gs, off)[0] == NOT_REPRODUCED:
        b.add(ReplDiagnosis(
            "REPLICATION_NOT_REPRODUCED", rel_key, f"The last {suffix} session {me} -> {consumer} failed to bind "
            f"({cls.replace('_', ' ').lower()}), but the same bind succeeds now", "REPLICATION", "WARN", "MEDIUM",
            f"Status: {status_text}. ipa-diagnose's own GSSAPI bind as this server succeeds now ({gs.summary}).",
            "389-DS retries by itself; the next session shows whether it is resolved.", ev0 + [gs.step_id], "pair",
            kind=TRANSIENT))
        return
    elif cls == S.INSUFFICIENT_ACCESS:
        L1 = Link(f"{consumer} does not let {me}'s identity send updates", rel_key, "AUTHORIZATION", ev0,
                  "status-access", "peer")
        managers = t.f("principals", "managers")
        if t.f("principals", "complete") is True and isinstance(managers, list) and me not in managers:
            chain = b.chain(rel_key, [L0, L1, Link(f"ldap/{me}@{realm} is not in cn=replication managers (this "
                                                   "server's copy of the directory)", "group:replication managers",
                                                   "PRINCIPAL", ["principals"], "access-not-a-manager", "directory")],
                            boundary=("adding a member to cn=replication managers is an LDAP write ipa-diagnose never "
                                      f"prints; {consumer}'s copy of the group may differ"),
                            next_action=["ipa-replica-manage list   (read-only)"])
            root = b.add(ReplDiagnosis(
                "NOT_A_REPLICATION_MANAGER", "group:replication managers",
                f"This server is not a replication manager in its own copy of the directory", "PRINCIPAL", "FAIL",
                "MEDIUM", f"cn=replication managers does not list ldap/{me}@{realm} here.",
                f"{consumer} refuses updates from {me}.", ["principals"], "directory", next_steps=chain.next_action,
                resolution_key="replication.not-a-manager"))
        else:
            chain = b.chain(rel_key, [L0, L1], boundary=(f"who may send updates is decided by {consumer}'s replica "
                                                         f"configuration, which can only be read on {consumer}"),
                            handoff=handoff(consumer, me, f"The remaining evidence is local to {consumer}."))
    elif cls in S.NEEDS_ADMIN:
        pair = rel_key
        chain = b.chain(rel_key, [L0, Link(f"{consumer}'s {suffix} data needs administrator action: "
                                           f"{S.MEANING[cls]}", pair, "REPLICA_DATA", ev0, "status-data", "pair")],
                        boundary=("re-initializing a replica overwrites its data; ipa-diagnose never prints it or any "
                                  "RUV clean-up: decide with the topology's owner which server holds the right data"),
                        next_action=[f"ipa-replica-manage list -v {_q(me)}   (read-only, with an admin ticket)",
                                     "ipa-healthcheck --source ipahealthcheck.ds.replication   (read-only)"])
        root = b.add(ReplDiagnosis(
            "REPLICA_NEEDS_ADMIN_ACTION", rel_key, f"{me} and {consumer} hold {suffix} data that needs administrator "
            "action (which side is right is not established)",
            "REPLICA_DATA", "FAIL", "HIGH", f"Status: {status_text}.",
            f"{suffix} changes from {me} do not reach {consumer} until an administrator acts.", ev0, "pair",
            next_steps=chain.next_action, resolution_key="replication.needs-admin-action", variant=cls))
    elif cls == S.TLS:
        root, chain = _tls_root(b, me, consumer, rel_key, [L0], ev0, port)
    if isinstance(off, (int, float)) and abs(off) >= KRB_TOLERANCE and b.get("PAIR_CLOCK_SKEW",
                                                                               f"pair:{me}>{consumer}") is None:
        _pair_skew(t, b, me, consumer, subj, off, via_chain=False)  # established, whatever else fails
    if chain is None:
        chain = b.chain(rel_key, [L0], boundary=(
            "the status is not one ipa-diagnose recognizes" if cls == S.UNCLASSIFIED else
            "the evidence needed to go further could not be collected"),
            next_action=[f"ipa-replica-manage list -v {_q(me)}   (read-only, with an admin ticket)"])
    symptom_kind = None
    if root is None and cls == S.UNCLASSIFIED:
        symptom_kind = UNDIAGNOSED
    elif root is None and not chain.handoff and len(chain.links) <= 2 and chain.boundary:
        symptom_kind = UNDIAGNOSED if chain.links[-1].capability in ("REPLICATION", "KERBEROS") else None
    d = b.add(ReplDiagnosis(
        "REPLICATION_FAILING", rel_key, f"{suffix} replication {me} -> {consumer} fails", "REPLICATION", "FAIL",
        confidence if root else ("LOW" if symptom_kind else "MEDIUM"),
        f"{S.MEANING.get(cls, cls)}. Last session status: {status_text}"
        + (f" (ended {item['last_update_end']})" if item.get("last_update_end") else "") + ".",
        f"{suffix} changes made on {me} (and the ones it relays) do not reach {consumer}.", ev0, "pair",
        kind=symptom_kind, chain_ids=[chain.chain_id], related_to=root.key if root else None,
        next_steps=chain.next_action, handoff=chain.handoff))
    if root is not None:
        if chain.chain_id not in root.chain_ids:
            root.chain_ids.append(chain.chain_id)
        if d.key not in root.explains:
            root.explains.append(d.key)


def _tls_root(b: _Builder, me: str, consumer: str, rel_key: str, base: List[Link], ev: List[str], port: str,
              disc: str = "status-tls"):
    pair = f"pair:{me}>{consumer}"
    chain = b.chain(rel_key, base + [Link(f"the TLS layer of {me}'s connection to {consumer}:{port} fails", pair,
                                          "TLS", ev, disc, "pair")],
                    boundary="which certificate or trust setting fails is not established",
                    next_action=[f"openssl s_client -connect {_q(consumer)}:{port} -CAfile /etc/ipa/ca.crt "
                                 "</dev/null   (read-only)"],
                    handoff=handoff(consumer, me, f"{consumer}'s certificate can be checked on {consumer}."))
    root = b.add(ReplDiagnosis(
        "PEER_TLS_FAILED", pair, f"TLS from {me} to {consumer}:{port} fails", "TLS", "FAIL", "MEDIUM",
        f"The connection fails at the TLS layer (observed from {me}); the Directory Server itself may be answering.",
        f"No replication {me} -> {consumer} over this agreement.", ev, "pair", next_steps=chain.next_action,
        handoff=chain.handoff))
    return root, chain


def _dropped(b: _Builder, me: str, item: Dict[str, Any]) -> None:
    """An agreement the budget left out is still reported when its own status (already read) is failing."""

    cls = item.get("status_class") or S.UNCLASSIFIED
    if cls == S.OK or cls in S.TRANSIENT or item.get("enabled") is False:
        return
    rel_key = rel(item["suffix_kind"], me, item["consumer"])
    c = b.chain(rel_key, [Link(f"{me} -> {item['consumer']} ({item['suffix_kind']} suffix) fails: "
                               f"{S.MEANING.get(cls, cls)}", rel_key, "REPLICATION", ["agreements"],
                               "agreement-status", "pair")],
                boundary="not investigated: the per-run agreement budget was used up",
                next_action=[f"sudo ipa-diagnose replication --peer {_q(item['consumer'])}"])
    b.add(ReplDiagnosis(
        "REPLICATION_FAILING", rel_key, f"{item['suffix_kind']} replication {me} -> {item['consumer']} fails (not "
        "investigated)", "REPLICATION", "FAIL", "LOW", f"{S.MEANING.get(cls, cls)}. Last session status: "
        f"{item.get('status_text') or '?'}. Not investigated in this run (agreement budget).",
        "Changes do not reach this consumer.", ["agreements"], "pair", kind=UNDIAGNOSED, chain_ids=[c.chain_id],
        next_steps=c.next_action))


def _reverse(t: _T, b: _Builder, me: str, realm: str, item: Dict[str, Any],
             roots: Optional[Dict[str, Optional[ReplDiagnosis]]] = None) -> str:
    """The reverse direction (consumer -> this server): only what was READ from the peer. Returns its state."""

    subj = item["subject"]
    consumer = item["consumer"]
    suffix = item["suffix_kind"]
    r = t.rec("reverse", subj)
    if r is None or r.outcome in (SK, U):
        return "UNKNOWN"
    if r.outcome == P:
        return "OK"
    classes = r.facts.get("classes") or []
    cls = next((c for c in classes if c != S.OK), S.UNCLASSIFIED)
    rel_key = rel(suffix, consumer, me)
    if cls in S.TRANSIENT:
        b.add(ReplDiagnosis("REPLICATION_TRANSIENT", rel_key, f"The {suffix} agreement {consumer} -> {me} is not "
                            f"green yet ({cls.replace('_', ' ').lower()})", "REPLICATION", "WARN", "HIGH",
                            f"Read from {consumer}: {r.facts.get('status_text') or '?'}.",
                            "389-DS retries by itself.", [r.step_id], "peer", kind=TRANSIENT))
        return "TRANSIENT"
    L0 = Link(f"{consumer} -> {me} ({suffix} suffix) fails: {S.MEANING.get(cls, cls)} (read from {consumer})",
              rel_key, "REPLICATION", [r.step_id], "agreement-status", "peer")
    kt = (roots or {}).get("keytab")
    if kt is not None and (cls in (S.INVALID_CREDENTIALS,) or cls in S.GSSAPI):
        # this server ACCEPTS that bind: with its own Directory Server keytab unusable it cannot accept Kerberos
        c = b.chain(rel_key, [L0, Link(f"the GSSAPI bind of {consumer} to {me} fails on the accepting side ({me})",
                                       rel_key, "KERBEROS", [r.step_id], "reverse-acceptor-kerberos", "local"),
                              Link(f"{me} accepts it with its own Directory Server keytab, which "
                                   f"{kt.title.split('keytab ', 1)[-1]}", f"server:{me}", "KEYTAB",
                                   [r.step_id, "local.keytab"], "acceptor-keytab-unusable", "local")],
                    boundary="ipa-diagnose does not print keytab replacement or ownership changes for ds.keytab in "
                             "this version", next_action=kt.next_steps)
        d = b.add(ReplDiagnosis(
            "REVERSE_REPLICATION_FAILING", rel_key, f"{suffix} replication {consumer} -> {me} fails (read from "
            f"{consumer})", "REPLICATION", "FAIL", "HIGH",
            f"{S.MEANING.get(cls, cls)}. {consumer}'s own status: {r.facts.get('status_text') or '?'}.",
            f"{suffix} changes made on {consumer} (and the ones it relays) do not reach {me}.", [r.step_id], "peer",
            chain_ids=[c.chain_id], related_to=kt.key, next_steps=kt.next_steps))
        kt.chain_ids.append(c.chain_id)
        kt.explains.append(d.key)
        return "FAILING"
    why = (f"the supplier of this direction is {consumer}: its Directory Server, KDC, keytab and clock can only be "
           f"checked on {consumer}.")
    c = b.chain(rel_key, [L0], boundary=why, handoff=handoff(consumer, me, "The remaining evidence is local to "
                                                                          f"{consumer}."))
    b.add(ReplDiagnosis(
        "REVERSE_REPLICATION_FAILING", rel_key, f"{suffix} replication {consumer} -> {me} fails (read from "
        f"{consumer})", "REPLICATION", "FAIL", "HIGH",
        f"{S.MEANING.get(cls, cls)}. {consumer}'s own status: {r.facts.get('status_text') or '?'}.",
        f"{suffix} changes made on {consumer} (and the ones it relays) do not reach {me}.", [r.step_id], "peer",
        chain_ids=[c.chain_id], next_steps=[f"on {consumer}: sudo ipa-diagnose replication --peer {_q(me)}"],
        handoff=c.handoff))
    return "FAILING"


# ---------------------------------------------------------------- topology consistency and RUV context


def _topology_checks(t: _T, b: _Builder, me: str, items: List[Dict[str, Any]], peer: Optional[str]) -> None:
    if peer or t.o("topology") != P or t.o("agreements") != P or t.f("agreements", "complete") is not True:
        return
    segs = t.f("topology", "segments") or []
    have = {(i["suffix_kind"], i["consumer"]) for i in t.f("agreements", "subjects") or [] if isinstance(i, dict)}
    expected = set()
    for s in segs:
        if not isinstance(s, dict) or s.get("suffix") not in ("domain", "ca"):
            continue
        if s.get("left") == me:
            expected.add((s["suffix"], s.get("right")))
        elif s.get("right") == me:
            expected.add((s["suffix"], s.get("left")))
    for suffix, other in sorted(x for x in expected - have if x[1]):
        b.add(ReplDiagnosis(
            "SEGMENT_WITHOUT_AGREEMENT", rel(suffix, me, other), f"A {suffix} topology segment connects {me} and "
            f"{other}, but {me} has no agreement to {other}", "TOPOLOGY", "WARN", "MEDIUM",
            "The topology (cn=topology) and this server's agreements (cn=mapping tree) disagree.",
            "Changes may not flow the way the topology says.", ["topology", "agreements"], "local",
            kind=CONTRADICTING, next_steps=[f"ipa topologysegment-find {suffix}   (read-only)"]))
    for suffix, other in sorted(x for x in have - expected if x[1]):
        b.add(ReplDiagnosis(
            "AGREEMENT_WITHOUT_SEGMENT", rel(suffix, me, other), f"{me} has a {suffix} agreement to {other} that no "
            "topology segment describes", "TOPOLOGY", "WARN", "MEDIUM",
            "The topology (cn=topology) and this server's agreements (cn=mapping tree) disagree.",
            "The topology plugin does not manage this agreement.", ["topology", "agreements"], "local",
            kind=CONTRADICTING, next_steps=[f"ipa topologysegment-find {suffix}   (read-only)"]))


def _ruv_context(t: _T, b: _Builder, me: str) -> List[str]:
    """Candidates only: an RUV element of THIS server whose host is not a current server in this server's complete
    topology view, with no clean task running. Never a global fact, never a clean-up command."""

    notes: List[str] = []
    if t.o("agreements") not in PASSISH or t.o("topology") != P or t.f("topology", "complete") is not True:
        return notes
    rec = t.rec("agreements")
    tasks = rec.fields.get("clean_tasks")
    if tasks is None:
        notes.append("whether a RUV clean task is running could not be read: RUV elements were not classified")
        return notes
    if tasks:
        notes.append(f"{tasks} RUV clean task(s) are running: RUV elements were not classified")
        return notes
    masters = set(t.f("topology", "masters") or [])
    ruv = rec.fields.get("ruv") or {}
    for suffix in ("domain", "ca"):
        for el in ruv.get(suffix) or []:
            if not isinstance(el, dict) or el.get("host") in masters:
                continue
            b.add(ReplDiagnosis(
                "RUV_ELEMENT_WITHOUT_SERVER", f"ruv:{suffix}:{el.get('rid')}", f"{me}'s {suffix} RUV names replica "
                f"{el.get('rid')} on {el.get('host')}, which is not a current IPA server", "REPLICA_DATA", "WARN",
                "MEDIUM", f"In {me}'s RUV only (other servers were not asked); no RUV clean task is running. A "
                "candidate, not proof: a server being installed or removed right now looks the same.",
                "A stale RUV element can keep old changes from being purged and confuse monitoring.", ["agreements",
                                                                                                         "topology"],
                "local", next_steps=["ipa-healthcheck --source ipahealthcheck.ds.ruv   (read-only; checks every "
                                     "server's RUV)"], resolution_key="replication.ruv-candidate"))
    return notes


# ---------------------------------------------------------------- entry point


def diagnose(trace: Trace, inputs: Dict[str, Any]) -> Tuple[List[ReplDiagnosis], List[Chain], Dict[str, Any]]:
    t = _T(trace)
    b = _Builder()
    extra: Dict[str, Any] = {"reverse": {}, "ruv_notes": []}
    if t.o("server") != P:
        return [], [], extra
    me = t.f("server", "host")
    realm = t.f("server", "realm") or "REALM"
    roots = _local(t, b, me)
    enum = trace.enumerations.get("agreement") or {}
    investigated = set(enum.get("subjects") or [])
    items = [i for i in (t.f("agreements", "subjects") or []) if isinstance(i, dict) and i.get("subject") in
             investigated]
    for item in sorted(items, key=lambda i: i["subject"]):
        _agreement(t, b, me, realm, item, roots)
        extra["reverse"][item["subject"]] = _reverse(t, b, me, realm, item, roots)
    for item in sorted((i for i in (t.f("agreements", "subjects") or []) if isinstance(i, dict)
                        and i.get("subject") in set(enum.get("dropped") or [])), key=lambda i: i["subject"]):
        _dropped(b, me, item)
    _topology_checks(t, b, me, items, inputs.get("peer"))
    extra["ruv_notes"] = _ruv_context(t, b, me)
    return _roles(list(b.diags.values())), b.chains, extra


def _roles(out: List[ReplDiagnosis]) -> List[ReplDiagnosis]:
    keys = {d.key for d in out}
    for d in out:
        if d.related_to and d.related_to not in keys:
            d.related_to = None
    primary_set = False
    scope_rank = {"local": 0, "directory": 1, "pair": 2, "peer": 3, "unknown": 4}
    for d in sorted(out, key=lambda x: (x.severity != "FAIL", scope_rank.get(x.scope, 9), LAYER.get(x.capability, 99),
                                        x.subject, x.code)):
        if d.kind == CONTRADICTING:
            d.role = CONTRADICTING
        elif d.severity == "WARN":
            d.role = WARNING
        elif d.related_to:
            d.role = RELATED
        elif d.kind == UNDIAGNOSED:
            d.role = UNDIAGNOSED
        elif not primary_set:
            d.role, primary_set = PRIMARY, True
        else:
            d.role = INDEPENDENT
    order = {PRIMARY: 0, INDEPENDENT: 1, UNDIAGNOSED: 2, CONTRADICTING: 3, RELATED: 4, WARNING: 5}
    return sorted(out, key=lambda x: (order[x.role], scope_rank.get(x.scope, 9), LAYER.get(x.capability, 99),
                                      x.subject, x.code))
