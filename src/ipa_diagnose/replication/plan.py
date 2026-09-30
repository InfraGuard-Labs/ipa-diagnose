"""The replication investigation plan (Slice 5): which checks exist, what each depends on, when each is worth running.

    this host an IPA server? ──► local Directory Server ──► topology (servers, roles, segments per suffix)
          │                      │                    └──► outbound agreements (+ replica config, RUV) ──► principals
          ├─► local KDC          │
          ├─► storage            └ (LDAPI needs the local Directory Server)
          └─► Directory Server keytab
    for_each outbound agreement (supplier = this host, consumer, suffix), bounded, sorted:
          peer name resolves (from this host) ──► agreement port answers ──► peer root DSE (LDAP answer + clock)
                                                   └─► 443 answers? (only when the LDAP port does not: is the host up?)
          GSSAPI bind as this server's ldap/ principal (only when the agreement is failing and uses SASL/GSSAPI)
          the peer's agreement towards this host (reverse direction; read-only, operator's own ticket)
    this host's NTP state (only when a clock difference is in view)

Replication is directional and per suffix: a subject is ONE outbound agreement of this server (``domain:<consumer>``
or ``ca:<consumer>``). The reverse direction is only ever read, never inferred from the outbound one.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ipa_diagnose.planner.core import Classified, Context, ForEach, Outcome, Req, Step
from ipa_diagnose.replication import status as S

P, W, F, U = Outcome.PASS, Outcome.WARN, Outcome.FAIL, Outcome.UNKNOWN
PASSISH = (P, W)
KRB_TOLERANCE = 300
CLOCK_WARN = 60
AGREEMENT_BUDGET = 8
MIN_FREE_BYTES = 100 * 1024 * 1024
WARN_FREE_PERCENT = 5.0
GSSAPI = "SASL/GSSAPI"


# ---------------------------------------------------------------- classifiers


def c_server(res, ctx) -> Classified:
    f = res.fields
    if not f.get("is_ipa_server"):
        return Classified(F, res.display, {"state": "not_server"})
    return Classified(P, res.display, {"state": "server"})


def c_unit(res, ctx) -> Classified:
    f = res.fields
    st = f.get("active_state")
    unit = f.get("unit") or "the unit"
    if f.get("load_state") not in (None, "", "loaded"):
        return Classified(F, f"{unit} is not a loaded unit ({f.get('load_state')})", {"state": st})
    if st == "active":
        return Classified(P, f"{unit} is running", {"state": st})
    if st in ("activating", "reloading", "deactivating"):
        return Classified(W, f"{unit} is {st}", {"state": st})
    return Classified(F, f"{unit} is {st or 'not running'}"
                      + (f" (last result {f.get('result')})" if f.get("result") not in (None, "", "success") else ""),
                      {"state": st})


def c_storage(res, ctx) -> Classified:
    f = res.fields
    if f.get("read_only"):
        return Classified(F, res.display, {"state": "read_only"})
    if isinstance(f.get("free_bytes"), int) and f["free_bytes"] < MIN_FREE_BYTES:
        return Classified(F, res.display, {"state": "full"})
    if isinstance(f.get("free_percent"), (int, float)) and f["free_percent"] < WARN_FREE_PERCENT:
        return Classified(W, res.display, {"state": "low"})
    return Classified(P, res.display, {"state": "ok"})


def c_ds_keytab(res, ctx) -> Classified:
    f = res.fields
    expected = ctx.fact("server.ldap_principal")
    if not f.get("present"):
        return Classified(F, "/etc/dirsrv/ds.keytab does not exist", {"state": "missing"})
    if f.get("is_symlink") or not f.get("is_regular") or (f.get("links") or 1) > 1:
        return Classified(F, res.display, {"state": "not_regular"})
    if f.get("dirsrv_can_read") is False:
        return Classified(F, f"/etc/dirsrv/ds.keytab is not readable by the dirsrv user (owner {f.get('owner')}:"
                          f"{f.get('group')}, mode {f.get('mode')})", {"state": "unreadable_for_dirsrv"})
    if f.get("klist_ok") is False:
        return Classified(F, f"/etc/dirsrv/ds.keytab cannot be listed ({f.get('error') or 'klist failed'})",
                          {"state": "unreadable"})
    principals = f.get("principals") or []
    if expected and f.get("klist_ok") and expected not in principals:
        return Classified(F, f"/etc/dirsrv/ds.keytab has no key for {expected}"
                          + (f" (it has {', '.join(principals[:2])})" if principals else " (it is empty)"),
                          {"state": "principal_missing"})
    if f.get("world_readable"):
        return Classified(W, f"/etc/dirsrv/ds.keytab is world-readable (mode {f.get('mode')})",
                          {"state": "world_readable"})
    return Classified(P, res.display, {"state": "ok"})


def c_topology(res, ctx) -> Classified:
    f = res.fields
    facts = {"masters": f.get("masters") or [], "complete": f.get("complete") is True}
    if not f.get("complete"):
        return Classified(W, res.display + " (not every part could be read with a confirmed identity)", facts)
    return Classified(P, res.display, facts)


def agreement_items(fields: Dict[str, Any], peer: Optional[str]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """The subjects of the per-agreement template: every outbound agreement (or only those towards --peer)."""

    items = []
    for a in fields.get("agreements") or []:
        if not isinstance(a, dict) or not a.get("subject"):
            continue
        if peer and a.get("consumer") != peer:
            continue
        st = S.parse_status(a.get("status_text"), a.get("status_json"))
        item = {k: a.get(k) for k in ("subject", "consumer", "port", "transport", "bind_method", "suffix_kind",
                                       "suffix_root", "enabled", "status_text", "last_update_start",
                                       "last_update_end", "update_in_progress", "last_init_status", "name")}
        item["status_class"] = st.cls
        item["ldap_rc"], item["repl_rc"] = st.ldap_rc, st.repl_rc
        items.append(item)
    consumers = sorted({a.get("consumer") for a in fields.get("agreements") or [] if isinstance(a, dict)
                        and a.get("consumer")})
    return items, consumers


def c_agreements(res, ctx) -> Classified:
    f = res.fields
    peer = ctx.input("peer")
    items, consumers = agreement_items(f, peer)
    facts: Dict[str, Any] = {"subjects": items, "complete": f.get("complete") is True, "consumers": consumers,
                             "peer_found": (peer in consumers) if peer else None,
                             "failing": sorted(i["subject"] for i in items if i["status_class"] != S.OK)}
    if peer and peer not in consumers:
        return Classified(W, f"this server has no outbound agreement towards {peer} "
                          f"(its agreements go to {', '.join(consumers) or 'no server'})", facts)
    if not f.get("complete"):
        return Classified(W, res.display + " (the read could not be confirmed complete)", facts)
    return Classified(P, res.display, facts)


def c_principals(res, ctx) -> Classified:
    f = res.fields
    facts = {"ldap_principals": f.get("ldap_principals") or [], "managers": f.get("replication_managers") or [],
             "complete": f.get("complete") is True}
    return Classified(P if facts["complete"] else W, res.display, facts)


def c_dns(res, ctx) -> Classified:
    return Classified(P if res.fields.get("resolved") else F, res.display,
                      {"resolved": bool(res.fields.get("resolved"))})


def c_tcp(res, ctx) -> Classified:
    st = res.fields.get("state")
    return Classified(P if st == "open" else F, res.display, {"state": st})


def c_rootdse(res, ctx) -> Classified:
    f = res.fields
    facts = {"answered": f.get("answered"), "offset": f.get("offset_seconds"), "error_class": f.get("error_class")}
    if f.get("ok"):
        off = f.get("offset_seconds")
        # the peer ANSWERED: that is what this step establishes; a clock difference is judged by the diagnosis
        if isinstance(off, (int, float)) and abs(off) >= KRB_TOLERANCE:
            return Classified(W, res.display + f": beyond Kerberos' {KRB_TOLERANCE} s tolerance", facts)
        if isinstance(off, (int, float)) and abs(off) >= CLOCK_WARN:
            return Classified(W, res.display, facts)
        return Classified(P, res.display, facts)
    if f.get("answered"):
        return Classified(W, res.display + " (the Directory Server answered, but the root DSE was not readable)", facts)
    return Classified(F, res.display, facts)


def c_peer_time(res, ctx) -> Classified:
    off = res.fields.get("offset_seconds")
    if not isinstance(off, (int, float)):
        return Classified(U, "the peer's clock could not be read over HTTPS", {"offset": None})
    txt = (f"this host's clock is {abs(off):.0f} s {'ahead of' if off >= 0 else 'behind'} the peer's "
           f"({res.fields.get('date_source') or 'HTTPS'} Date header)")
    return Classified(W if abs(off) >= CLOCK_WARN else P, txt, {"offset": off})


def c_gssapi(res, ctx) -> Classified:
    f = res.fields
    facts = {"kinit_ok": f.get("kinit_ok"), "kinit_class": f.get("kinit_class"), "bind_ok": f.get("bind_ok"),
             "error_class": f.get("bind_error_class"), "ccache_removed": f.get("ccache_removed")}
    if f.get("bind_ok"):
        return Classified(P, res.display, facts)
    return Classified(F, res.display, facts)


def c_reverse(res, ctx) -> Classified:
    f = res.fields
    kind = ctx.item.get("suffix_kind")
    same = [a for a in f.get("agreements") or [] if isinstance(a, dict) and a.get("suffix_kind") == kind]
    if not f.get("visible") or not same:
        return Classified(U, res.display if not f.get("visible") else
                          f"the peer's agreements towards this server are visible, but none for the {kind} suffix",
                          {"visible": False})
    classes = sorted({S.parse_status(a.get("status_text"), a.get("status_json")).cls for a in same})
    facts = {"visible": True, "classes": classes, "status_text": (same[0].get("status_text") or "")[:600],
             "last_update_end": same[0].get("last_update_end"), "update_in_progress": same[0].get("update_in_progress"),
             "enabled": same[0].get("enabled")}
    if classes == [S.OK]:
        return Classified(P, f"reverse direction ({ctx.item.get('consumer')} -> this server, {kind}): the last session "
                          "succeeded", facts)
    return Classified(F, f"reverse direction ({ctx.item.get('consumer')} -> this server, {kind}): "
                      f"{', '.join(classes)}", facts)


def c_chrony(res, ctx) -> Classified:
    f = res.fields
    if f.get("synchronized") and abs(f.get("offset_seconds") or 0) < 1:
        return Classified(P, res.display, {"synchronized": True, "offset": f.get("offset_seconds")})
    return Classified(W, res.display + ("" if f.get("synchronized") else "; chronyd is not synchronized"),
                      {"synchronized": bool(f.get("synchronized")), "offset": f.get("offset_seconds")})


# ---------------------------------------------------------------- gates


def stop_not_server(ctx) -> Optional[str]:
    if ctx.fact("server.state") == "not_server":
        return ("this host is not an IPA server: replication is investigated on the IPA servers themselves "
                "(nothing was guessed)")
    return None


def g_https(ctx) -> Tuple[bool, str]:
    if ctx.outcome("peer.port") == F:
        return True, "the agreement's LDAP port does not answer: is the peer host up at all (HTTPS, 443)?"
    return False, "the agreement's LDAP port answers"


def g_peer_time(ctx) -> Tuple[bool, str]:
    if ctx.outcome("peer.dns") != P:
        return False, "the peer's name does not resolve here"
    if isinstance(ctx.fact("peer.rootdse.offset"), (int, float)):
        return False, "the peer's root DSE already gave its clock"
    return True, ("the peer's root DSE gave no clock: read it from the peer's HTTPS Date header (for Kerberos, "
                  "clocks must agree within 300 s)")


def _failing(ctx) -> bool:
    return ctx.item.get("status_class") not in (S.OK,)


def g_gssapi_applies(ctx) -> Tuple[bool, str]:
    bm = str(ctx.item.get("bind_method") or "").upper()
    if bm != GSSAPI:
        return False, (f"the agreement binds with {bm or 'an unknown method'}, not SASL/GSSAPI"
                       + (" (its stored credential is never read)" if bm == "SIMPLE" else ""))
    kt = ctx.fact("server.krb5_ktname")
    if kt not in (None, "/etc/dirsrv/ds.keytab"):
        return False, (f"the Directory Server is configured with another keytab ({kt}); the reproduction would not "
                       "use the same key")
    return True, "the agreement binds with SASL/GSSAPI as this server's ldap/ principal"


def g_gssapi(ctx) -> Tuple[bool, str]:
    if _failing(ctx):
        return True, (f"the agreement's last session is {ctx.item.get('status_class')}: reproduce the supplier's "
                      "Kerberos bind to see what fails now")
    if ctx.outcome("local.kdc") == F:
        return True, "this server's KDC is not running: can the supplier still obtain new Kerberos tickets?"
    return False, "the agreement's last session succeeded (not probed further)"


def g_chrony(ctx) -> Tuple[bool, str]:
    for r in ctx.records.values():
        if r.base_step in ("peer.rootdse", "peer.time") and isinstance(r.facts.get("offset"), (int, float)) \
                and abs(r.facts["offset"]) >= CLOCK_WARN:
            return True, f"this host's clock differs from {r.subject}'s: is this host's NTP working?"
        if r.base_step == "gssapi" and r.facts.get("error_class") == S.GSSAPI_CLOCK_SKEW:
            return True, "Kerberos reported clock skew: is this host's NTP working?"
    for r in ctx.records.values():
        if r.step_id == "agreements":
            for it in r.facts.get("subjects") or []:
                if isinstance(it, dict) and it.get("status_class") == S.GSSAPI_CLOCK_SKEW:
                    return True, "an agreement reports Kerberos clock skew: is this host's NTP working?"
    return False, "no clock difference is in view"


def g_principals(ctx) -> Tuple[bool, str]:
    items = ctx.fact("agreements.subjects") or []
    if any(isinstance(i, dict) and i.get("status_class") != S.OK for i in items):
        return True, "an agreement is failing: which ldap/ principals and replication managers does this server know?"
    return False, "every agreement's last session succeeded"


# ---------------------------------------------------------------- the plan


def replication_plan() -> list:
    local_ds = Req("local.ds", PASSISH)
    per_agreement = ForEach(
        "agreement", "agreements.subjects", "agreement_subject", (
            Step("peer.dns", "DNS", "dns.address", "Peer name resolves (from this host)",
                 "The supplier reaches the consumer by the name in the agreement, through this host's resolver.",
                 params={"name": ("item", "consumer")}, classify=c_dns),
            Step("peer.port", "NETWORK", "net.tcp", "Agreement port answers (TCP)",
                 "The agreement connects to this port of the consumer.",
                 params={"host": ("item", "consumer"), "port": ("item", "port")}, requires=(Req("peer.dns"),),
                 classify=c_tcp),
            Step("peer.rootdse", "PEER_DS", "repl.peer_rootdse", "Peer Directory Server answers (root DSE)",
                 "An anonymous read of the consumer's root DSE shows whether its Directory Server answers LDAP, and "
                 "its clock (currentTime).",
                 params={"host": ("item", "consumer"), "port": ("item", "port"),
                         "transport": ("item", "transport")}, requires=(Req("peer.dns"),), after=("peer.port",),
                 classify=c_rootdse),
            Step("peer.time", "TIME", "ipa.https", "Peer clock (HTTPS Date header)",
                 "Only when the root DSE gives no time: the peer's clock from its HTTPS Date header (anonymous HEAD "
                 "request, TLS verified with /etc/ipa/ca.crt).", params={"server": ("item", "consumer")},
                 after=("peer.dns", "peer.rootdse"), when=g_peer_time, classify=c_peer_time),
            Step("peer.https", "NETWORK", "net.tcp", "Peer host answers on 443 (is it up?)",
                 "Only when the agreement's port does not answer: separates a stopped Directory Server on a running "
                 "host from a host that cannot be reached.", params={"host": ("item", "consumer"), "port": "443"},
                 requires=(Req("peer.dns"),), after=("peer.port",), when=g_https, classify=c_tcp),
            Step("gssapi", "KERBEROS", "repl.gssapi_bind", "Supplier's GSSAPI bind to the peer (reproduced)",
                 "The supplier authenticates with its own ldap/ key from /etc/dirsrv/ds.keytab and binds with SASL "
                 "GSSAPI; reproducing it separates KDC, clock, principal, key and peer-side failures.",
                 params={"host": ("item", "consumer"), "port": ("item", "port"), "transport": ("item", "transport"),
                         "principal": ("fact", "server.ldap_principal")},
                 requires=(Req("peer.port"),), after=("peer.rootdse",), applies=g_gssapi_applies, when=g_gssapi,
                 classify=c_gssapi, needs_root=True),
            Step("reverse", "REPLICATION", "repl.peer_agreement", "Reverse direction (peer -> this server)",
                 "The peer's own agreement towards this server, read from the peer (read-only, with your own "
                 "Kerberos ticket). Never inferred from the outbound direction.",
                 params={"host": ("item", "consumer"), "port": ("item", "port"), "transport": ("item", "transport"),
                         "self_host": ("fact", "server.host")},
                 requires=(Req("peer.rootdse", PASSISH),), after=("gssapi",), classify=c_reverse),
        ), AGREEMENT_BUDGET, "per outbound agreement", complete_fact="agreements.complete")
    return [
        Step("server", "TOPOLOGY", "repl.server", "This host is an IPA server",
             "Replication agreements live on IPA servers; the realm, suffix and this server's name come from here.",
             classify=c_server, stop=stop_not_server),
        Step("local.ds", "LOCAL_DS", "systemd.unit", "Local Directory Server running",
             "Every agreement of this server is run by its Directory Server; its data is read over its LDAPI socket.",
             params={"service": "dirsrv"}, requires=(Req("server"),), classify=c_unit),
        Step("local.kdc", "LOCAL_KDC", "systemd.unit", "Local KDC running",
             "The supplier obtains its Kerberos tickets for GSSAPI agreements from the KDC its Kerberos configuration "
             "names (on an IPA server: itself).", params={"service": "krb5kdc"}, requires=(Req("server"),),
             classify=c_unit),
        Step("local.storage", "STORAGE", "repl.storage", "Directory Server file system writable, with space",
             "A read-only or full file system stops the Directory Server and its changelog.",
             requires=(Req("server"),), classify=c_storage),
        Step("local.keytab", "KEYTAB", "repl.ds_keytab", "Directory Server keytab (ds.keytab)",
             "GSSAPI agreements authenticate with this server's ldap/ key from /etc/dirsrv/ds.keytab (metadata only).",
             requires=(Req("server"),), classify=c_ds_keytab, needs_root=True),
        Step("topology", "TOPOLOGY", "repl.topology", "Topology: servers, roles, segments",
             "Which servers exist, what roles they hold (CA, KRA, DNS, renewal master) and which segments connect "
             "them per suffix: context for impact and for what may never be changed lightly.",
             requires=(local_ds,), classify=c_topology, needs_root=True),
        Step("agreements", "REPLICATION", "repl.agreements", "Outbound replication agreements of this server",
             "Each agreement is one direction (this server -> consumer) of one suffix; its own status says how its "
             "last session ended.", requires=(local_ds,), after=("topology",), classify=c_agreements,
             needs_root=True),
        Step("principals", "PRINCIPAL", "repl.principals", "ldap/ principals and replication managers",
             "Only when an agreement fails: whether the peers' ldap/ service principals exist and this server is a "
             "replication manager (this server's copy of the directory).", requires=(local_ds,),
             after=("agreements",), when=g_principals, classify=c_principals, needs_root=True),
        per_agreement,
        Step("time.local", "TIME", "chrony.tracking", "This host's NTP synchronization",
             "Only when a clock difference is in view: is this host's own time service synchronized?",
             when=g_chrony, classify=c_chrony),
    ]


# Steps other steps depend on because they are the READ PATH of the evidence (not a capability dependency): the host's
# identity, and the local Directory Server whose LDAPI socket every local read uses. Every other hard dependency in the
# plan must follow the capability model (tests/replication/test_causal.py).
READ_PATH = {"server": "the identity of this host (realm, suffix, principal)",
             "local.ds": "every local read goes through the Directory Server's LDAPI socket"}


def plan_inputs(peer: Optional[str]) -> Dict[str, Any]:
    return {"peer": peer}
