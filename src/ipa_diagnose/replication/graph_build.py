"""Build the per-run EnvironmentGraph of a replication investigation from the evidence the planner collected.

Only evidenced entities and relations are added; observer-relative facts (name resolution, reachability, clock
offset) carry ``observed_from``; enumerations say whether they were COMPLETE. Nothing here decides anything.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ipa_diagnose.environment.graph import Enumeration, EnvironmentGraph, Kind, Rel, State, ref
from ipa_diagnose.planner.core import Outcome, Trace

SK, U = Outcome.SKIPPED, Outcome.UNKNOWN


def _ok(r) -> bool:
    return r is not None and r.outcome not in (SK, U)


def build(trace: Trace, me: Optional[str], freeipa: Optional[str]) -> EnvironmentGraph:
    g = EnvironmentGraph()
    if not me:
        return g
    src = "REPLAY" if any(r.source == "REPLAY" for r in trace.records) else "LIVE"
    ctx = {"freeipa": freeipa} if freeipa else {}

    def fact(subject, name, value, rec, state=State.ESTABLISHED, observed_from=None):
        g.add_fact(subject, name, value, state, [rec.step_id], rec.collected_at, src, observed_from, ctx)

    server_rec = trace.get("server")
    me_ref = g.add_entity(Kind.SERVER, me, owner=me, scope="host", evidence=["server"])
    topo = trace.get("topology")
    if _ok(topo):
        f = topo.fields
        for h in f.get("masters") or []:
            g.add_entity(Kind.SERVER, h, owner=h, scope="host", evidence=[topo.step_id])
        for h, roles in (f.get("roles") or {}).items():
            s = g.add_entity(Kind.SERVER, h, owner=h, scope="host", evidence=[topo.step_id])
            for role in roles:
                r = g.add_entity(Kind.SERVER_ROLE, f"{role}:{h}", owner=h, scope="topology", evidence=[topo.step_id])
                g.add_relation(Rel.HAS_ROLE, s, r, [topo.step_id])
        for suf in f.get("suffixes") or []:
            if suf.get("name") in ("domain", "ca"):
                g.add_entity(Kind.SUFFIX, suf["name"], scope=suf["name"], evidence=[topo.step_id])
        for seg in f.get("segments") or []:
            if seg.get("suffix") not in ("domain", "ca"):
                continue
            sref = g.add_entity(Kind.TOPOLOGY_SEGMENT, f"{seg['suffix']}:{seg['left']}~{seg['right']}",
                                scope=seg["suffix"], evidence=[topo.step_id])
            suf = g.add_entity(Kind.SUFFIX, seg["suffix"], scope=seg["suffix"], evidence=[topo.step_id])
            g.add_relation(Rel.SEGMENT_OF, sref, suf, [topo.step_id])
            for end in (seg["left"], seg["right"]):
                e = g.add_entity(Kind.SERVER, end, owner=end, scope="host", evidence=[topo.step_id])
                g.add_relation(Rel.CONNECTS, sref, e, [topo.step_id])
                g.add_relation(Rel.PARTICIPATES_IN, e, suf, [topo.step_id])
        g.set_enumeration("servers", Enumeration.COMPLETE if f.get("complete") and not g.truncated
                          else Enumeration.PARTIAL, Kind.SERVER,
                          [ref(Kind.SERVER, h) for h in f.get("masters") or []],
                          "" if f.get("complete") else "the topology read was not confirmed complete")
    else:
        g.set_enumeration("servers", Enumeration.FAILED if topo is not None and topo.outcome == U
                          else Enumeration.NOT_ASKED, Kind.SERVER)
    inst = server_rec.fields.get("ds_instance") if _ok(server_rec) else None
    ds = trace.get("local.ds")
    if inst:
        d = g.add_entity(Kind.DIRECTORY_SERVER_INSTANCE, f"{me}/slapd-{inst}", owner=me, scope="host",
                         evidence=["server"])
        g.add_relation(Rel.HOSTS, me_ref, d, ["server"])
        if _ok(ds):
            fact(d, "active_state", ds.fields.get("active_state"), ds)
    kdc = trace.get("local.kdc")
    if _ok(kdc):
        k = g.add_entity(Kind.KDC, f"{me}/krb5kdc", owner=me, scope="host", evidence=[kdc.step_id])
        g.add_relation(Rel.HOSTS, me_ref, k, [kdc.step_id])
        fact(k, "active_state", kdc.fields.get("active_state"), kdc)
    kt = trace.get("local.keytab")
    if _ok(kt) and kt.fields.get("present"):
        kref = g.add_entity(Kind.KEYTAB, f"{me}:/etc/dirsrv/ds.keytab", owner=me, scope="host", evidence=[kt.step_id])
        for name in ("owner", "group", "mode", "dirsrv_can_read"):
            fact(kref, name, kt.fields.get(name), kt)
        for p in kt.fields.get("principals") or []:
            pref = g.add_entity(Kind.PRINCIPAL, p, scope="directory", evidence=[kt.step_id])
            g.add_relation(Rel.CONTAINS, kref, pref, [kt.step_id])
    pr = trace.get("principals")
    if _ok(pr):
        realm = server_rec.fields.get("realm") if _ok(server_rec) else None
        members = []
        for h in pr.facts.get("ldap_principals") or []:
            pref = g.add_entity(Kind.PRINCIPAL, f"ldap/{h}@{realm}", scope="directory", evidence=[pr.step_id])
            s = g.add_entity(Kind.SERVER, h, owner=h, scope="host", evidence=[pr.step_id])
            g.add_relation(Rel.PRINCIPAL_OF, pref, s, [pr.step_id])
            members.append(pref)
        g.set_enumeration("ldap_principals", Enumeration.COMPLETE if pr.facts.get("complete") and None not in members
                          and not g.truncated else Enumeration.PARTIAL, Kind.PRINCIPAL, [m for m in members if m])
    ag = trace.get("agreements")
    enum = trace.enumerations.get("agreement") or {}
    if _ok(ag):
        members = []
        for item in ag.facts.get("subjects") or []:
            if not isinstance(item, dict):
                continue
            key = f"{item['suffix_kind']}:{me}>{item['consumer']}"
            a = g.add_entity(Kind.AGREEMENT, key, owner=me, scope=item["suffix_kind"], evidence=[ag.step_id])
            members.append(a)
            consumer = g.add_entity(Kind.SERVER, item["consumer"], owner=item["consumer"], scope="host",
                                    evidence=[ag.step_id])
            suf = g.add_entity(Kind.SUFFIX, item["suffix_kind"], scope=item["suffix_kind"], evidence=[ag.step_id])
            g.add_relation(Rel.SUPPLIER_OF, me_ref, a, [ag.step_id])
            g.add_relation(Rel.CONSUMER_OF, consumer, a, [ag.step_id])
            g.add_relation(Rel.REPLICATES, a, suf, [ag.step_id])
            for name in ("status_class", "transport", "bind_method", "port", "last_update_end", "update_in_progress",
                         "enabled"):
                fact(a, name, item.get(name), ag)
            subj = item.get("subject")
            for base, names in (("peer.dns", ("resolved",)), ("peer.port", ("state",)),
                                ("peer.rootdse", ("answered", "offset"))):
                r = trace.get(base, subject=subj)
                if _ok(r):
                    for n in names:
                        fact(consumer, f"{base}.{n}", r.facts.get(n), r, observed_from=me)
            rv = trace.get("reverse", subject=subj)
            rkey = f"{item['suffix_kind']}:{item['consumer']}>{me}"
            if _ok(rv) and rv.facts.get("visible"):
                ra = g.add_entity(Kind.AGREEMENT, rkey, owner=item["consumer"], scope=item["suffix_kind"],
                                  evidence=[rv.step_id])
                g.add_relation(Rel.SUPPLIER_OF, consumer, ra, [rv.step_id])
                g.add_relation(Rel.CONSUMER_OF, me_ref, ra, [rv.step_id])
                g.add_relation(Rel.REPLICATES, ra, suf, [rv.step_id])
                fact(ra, "status_classes", rv.facts.get("classes"), rv)
        status = {"COMPLETE": Enumeration.COMPLETE, "PARTIAL": Enumeration.PARTIAL, "FAILED": Enumeration.FAILED}.get(
            enum.get("status"), Enumeration.PARTIAL)
        scoped = ag.facts.get("peer_found") is not None
        if ag.facts.get("complete") is not True or None in members or g.truncated or scoped:
            status = Enumeration.PARTIAL  # never COMPLETE when cut by a bound or limited to --peer
        g.set_enumeration(f"outbound_agreements:{me}", status, Kind.AGREEMENT, [m for m in members if m],
                          enum.get("reason", "") or ("limited to --peer" if scoped else ""),
                          scope="--peer" if scoped else None)
    else:
        g.set_enumeration(f"outbound_agreements:{me}", Enumeration.FAILED if ag is not None and ag.outcome == U
                          else Enumeration.NOT_ASKED, Kind.AGREEMENT)
    return g


def summary(g: EnvironmentGraph) -> Dict[str, Any]:
    d = g.to_dict()
    return {"entities": len(d["entities"]), "facts": len(d["facts"]), "relations": len(d["relations"]),
            "enumerations": {k: v["status"] for k, v in d["enumerations"].items()}, "truncated": g.truncated}


def graph_dict(g: EnvironmentGraph) -> Dict[str, Any]:
    return g.to_dict()


def members(g: EnvironmentGraph, kind: Kind) -> List[str]:
    return [e.key for e in g.entities(kind)]
