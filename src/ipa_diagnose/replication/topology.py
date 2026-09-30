"""Topology context for replication (Slice 5): who holds which role, which segments connect whom per suffix, and
which servers are articulation points (removing one would split that suffix's topology).

This is CONTEXT for impact statements and for withholding topology-sensitive fixes. It is computed explicitly from a
topology read (never guessed) and says when that read was not complete. Slice 5 offers no topology change at all.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

MAX_NODES = 400


def articulation_points(nodes: List[str], edges: List[tuple]) -> List[str]:
    """Servers whose removal disconnects the others (undirected; iterative Tarjan, bounded)."""

    nodes = sorted(set(nodes))[:MAX_NODES]
    adj: Dict[str, Set[str]] = {n: set() for n in nodes}
    for a, b in edges:
        if a in adj and b in adj and a != b:
            adj[a].add(b)
            adj[b].add(a)
    disc: Dict[str, int] = {}
    low: Dict[str, int] = {}
    points: Set[str] = set()
    counter = 0
    for root in nodes:
        if root in disc:
            continue
        disc[root] = low[root] = counter
        counter += 1
        children = 0
        stack = [(root, None, iter(sorted(adj[root])))]
        while stack:
            node, parent, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                stack.pop()
                if parent is not None:
                    low[parent] = min(low[parent], low[node])
                    if stack and stack[-1][1] is not None and low[node] >= disc[parent]:
                        points.add(parent)
                continue
            if nxt == parent:
                continue
            if nxt in disc:
                low[node] = min(low[node], disc[nxt])
                continue
            disc[nxt] = low[nxt] = counter
            counter += 1
            if node == root:
                children += 1
            stack.append((nxt, node, iter(sorted(adj[nxt]))))
        if children > 1:
            points.add(root)
    return sorted(points)


def summarize(fields: Dict[str, Any], me: str) -> Dict[str, Any]:
    if not fields:
        return {"complete": False, "read": False}
    masters = list(fields.get("masters") or [])
    roles: Dict[str, List[str]] = dict(fields.get("roles") or {})
    flags: Dict[str, List[str]] = dict(fields.get("flags") or {})
    suffixes: Dict[str, Any] = {}
    for s in fields.get("suffixes") or []:
        name = s.get("name")
        if name not in ("domain", "ca"):
            continue
        segs = [x for x in fields.get("segments") or [] if x.get("suffix") == name]
        members = sorted({x["left"] for x in segs} | {x["right"] for x in segs})
        if name == "ca":
            members = sorted(set(members) | {h for h, rs in roles.items() if "CA" in rs})
        elif not segs:
            members = sorted(masters)
        suffixes[name] = {
            "root": s.get("root"), "servers": members,
            "segments": [{"left": x["left"], "right": x["right"], "direction": x.get("direction")} for x in segs],
            "articulation_points": articulation_points(members, [(x["left"], x["right"]) for x in segs]),
            "neighbours_of_this_server": sorted({x["right"] for x in segs if x["left"] == me}
                                                | {x["left"] for x in segs if x["right"] == me}),
        }

    def holders(role: str) -> List[str]:
        return sorted(h for h, rs in roles.items() if role in rs)

    renewal = [h for h, f in flags.items() if "caRenewalMaster" in f]
    dnssec = [h for h, f in flags.items() if "dnssecKeyMaster" in f]
    return {
        "read": True, "complete": fields.get("complete") is True, "servers": sorted(masters),
        "roles": {h: sorted(r) for h, r in sorted(roles.items())}, "hidden": list(fields.get("hidden") or []),
        "suffixes": suffixes,
        "holders": {r: holders(r) for r in ("CA", "KRA", "DNS", "KDC")},
        "sole_role_holder": {r: holders(r)[0] for r in ("CA", "KRA", "DNS") if len(holders(r)) == 1},
        "renewal_master": renewal[0] if len(renewal) == 1 else None,
        "dnssec_key_master": dnssec[0] if len(dnssec) == 1 else None,
        "crl_generation_master": None,
        "not_collected": ["CRL generation master (a setting in each CA server's own CS.cfg; not read)"],
    }
