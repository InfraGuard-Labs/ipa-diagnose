"""L2: a small, bounded, typed relationship index for ONE access question.

It holds only what the question needs: the user, the host and the service being asked about, the groups/hostgroups/
service groups they belong to, and the HBAC rules that were inspected. Nothing is persisted, nothing else in the
directory is mirrored, and there is no planner here: `evaluate.py` runs a fixed, bounded sequence of read-only calls.

The index EXPLAINS FreeIPA's decision; it never makes or overrides it. When the explanation cannot be completed
(missing data, bounds reached) or disagrees with FreeIPA's evaluator, that is reported as such.

Semantics mirrored from FreeIPA (ipaserver/plugins/hbactest.py, FreeIPA 4.13.3) and SSSD's libipa_hbac:
- a rule side matches when its category is ``all``, or the object is listed by name, or one of the object's groups is
  listed. For users and hosts "the object's groups" are its direct AND indirect (nested) groups, as FreeIPA's
  ``memberof``/``memberofindirect`` report them; an HBAC service's groups are its direct service groups (service
  groups do not nest).
- a rule must be enabled to count (hbactest evaluates only enabled rules by default, as SSSD does).
- a request is allowed when at least one rule matches on all three sides.
"""

from __future__ import annotations

import collections
import dataclasses
import enum
from typing import Dict, Iterable, List, Optional, Set, Tuple

MAX_NODES = 2000
MAX_EDGES = 5000
MAX_DEPTH = 12


class NodeKind(enum.Enum):
    USER = "USER"
    GROUP = "GROUP"
    HOST = "HOST"
    HOSTGROUP = "HOSTGROUP"
    HBAC_RULE = "HBAC_RULE"
    HBAC_SERVICE = "HBAC_SERVICE"
    HBAC_SERVICE_GROUP = "HBAC_SERVICE_GROUP"
    TRUSTED_DOMAIN = "TRUSTED_DOMAIN"


class EdgeKind(enum.Enum):
    MEMBER_OF = "MEMBER_OF"
    """child -> parent, a direct membership reported by FreeIPA."""
    MEMBER_OF_INDIRECT = "MEMBER_OF_INDIRECT"
    """child -> ancestor, reported by FreeIPA as indirect (nested); the chain between them may be unknown."""
    RULE_APPLIES_TO = "RULE_APPLIES_TO"
    """HBAC rule -> an object it lists on one of its sides (users, hosts, services)."""


@dataclasses.dataclass(frozen=True)
class Node:
    kind: NodeKind
    name: str

    @property
    def key(self) -> Tuple[str, str]:
        return (self.kind.value, self.name.lower())


@dataclasses.dataclass(frozen=True)
class Edge:
    src: Node
    dst: Node
    kind: EdgeKind
    source: str
    """Provenance: the read-only API call this edge came from, e.g. ``user_show john``."""
    side: Optional[str] = None  # for RULE_APPLIES_TO: user | host | service


class RelationshipIndex:
    def __init__(self, max_nodes: int = MAX_NODES, max_edges: int = MAX_EDGES):
        self.max_nodes, self.max_edges = max_nodes, max_edges
        self._nodes: Dict[Tuple[str, str], Node] = {}
        self._edges: Dict[Tuple, Edge] = {}
        self._out: Dict[Tuple[str, str], List[Edge]] = collections.defaultdict(list)
        self.truncated = False

    def node(self, kind: NodeKind, name: str) -> Optional[Node]:
        n = Node(kind, name)
        existing = self._nodes.get(n.key)
        if existing is not None:
            return existing
        if len(self._nodes) >= self.max_nodes:
            self.truncated = True
            return None
        self._nodes[n.key] = n
        return n

    def add_edge(self, src: Optional[Node], dst: Optional[Node], kind: EdgeKind, source: str,
                 side: Optional[str] = None) -> None:
        if src is None or dst is None:
            return
        key = (src.key, dst.key, kind.value, side)
        if key in self._edges:
            return  # deduplicated: the first provenance is kept
        if len(self._edges) >= self.max_edges:
            self.truncated = True
            return
        e = Edge(src, dst, kind, source, side)
        self._edges[key] = e
        self._out[src.key].append(e)

    def add_memberships(self, child: Optional[Node], parent_kind: NodeKind, direct: Iterable[str],
                        indirect: Iterable[str], source: str) -> None:
        for name in direct:
            self.add_edge(child, self.node(parent_kind, name), EdgeKind.MEMBER_OF, source)
        for name in indirect:
            self.add_edge(child, self.node(parent_kind, name), EdgeKind.MEMBER_OF_INDIRECT, source)

    def edges(self) -> List[Edge]:
        return list(self._edges.values())

    def nodes(self) -> List[Node]:
        return list(self._nodes.values())

    def parents(self, node: Node, direct_only: bool = True) -> List[Edge]:
        kinds = {EdgeKind.MEMBER_OF} if direct_only else {EdgeKind.MEMBER_OF, EdgeKind.MEMBER_OF_INDIRECT}
        return [e for e in self._out.get(node.key, []) if e.kind in kinds]

    def membership_path(self, start: Node, target: Node, max_depth: int = MAX_DEPTH) -> Optional[List[Edge]]:
        """Shortest chain of DIRECT memberships from start to target (breadth-first, cycle-safe, depth-bounded), or
        None when the index does not hold one."""

        if start.key == target.key:
            return []
        seen = {start.key}
        queue = collections.deque([(start, [])])
        while queue:
            cur, path = queue.popleft()
            if len(path) >= max_depth:
                continue
            for e in self.parents(cur):
                if e.dst.key in seen:
                    continue
                if e.dst.key == target.key:
                    return path + [e]
                seen.add(e.dst.key)
                queue.append((e.dst, path + [e]))
        return None


# ---------------------------------------------------------------- HBAC rules


def _first(v) -> Optional[object]:
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _names(v) -> List[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [x for x in v if isinstance(x, str)]
    return []


def _flag(v) -> Optional[bool]:
    v = _first(v)
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.upper() in ("TRUE", "FALSE"):
        return v.upper() == "TRUE"
    return None


@dataclasses.dataclass
class RuleSide:
    category_all: bool
    names: List[str]
    groups: List[str]


@dataclasses.dataclass
class HbacRule:
    name: str
    enabled: Optional[bool]
    user: RuleSide
    host: RuleSide
    service: RuleSide
    source: str

    @classmethod
    def from_api(cls, result: dict, source: str) -> Optional["HbacRule"]:
        if not isinstance(result, dict):
            return None
        name = _first(result.get("cn"))
        if not isinstance(name, str) or not name:
            return None

        def side(prefix: str, member: str, obj: str, grp: str) -> RuleSide:
            cat = _first(result.get(f"{prefix}category"))
            return RuleSide(category_all=isinstance(cat, str) and cat.lower() == "all",
                            names=_names(result.get(f"{member}_{obj}")), groups=_names(result.get(f"{member}_{grp}")))

        return cls(name=name, enabled=_flag(result.get("ipaenabledflag")),
                   user=side("user", "memberuser", "user", "group"),
                   host=side("host", "memberhost", "host", "hostgroup"),
                   service=side("service", "memberservice", "hbacsvc", "hbacsvcgroup"), source=source)


@dataclasses.dataclass
class SideExplanation:
    side: str  # user | host | service
    how: str
    """``all`` (the rule's category is all), ``direct`` (the object is listed by name), ``group`` (through a direct
    group), ``nested_group`` (through an indirect group), or ``none`` (the index holds no reason this side matches)."""
    via: Optional[str] = None
    """The listed group/hostgroup/service group the object matched through."""
    chain: List[str] = dataclasses.field(default_factory=list)
    """Object -> ... -> listed group, when the chain of direct memberships is known."""
    chain_complete: bool = True


@dataclasses.dataclass
class Membership:
    """What FreeIPA reported for one object: its own canonical name and its direct / indirect groups."""

    node: Node
    direct: Set[str]
    indirect: Set[str]

    def all_groups(self) -> Set[str]:
        return {g.lower() for g in self.direct | self.indirect}


def explain_side(index: RelationshipIndex, side: str, rule_side: RuleSide, member: Optional[Membership],
                 object_name: str, group_kind: NodeKind) -> List[SideExplanation]:
    """Every reason (there may be several) why ``rule_side`` covers the object; ``[how=none]`` when there is none."""

    if rule_side.category_all:
        return [SideExplanation(side, "all")]
    out: List[SideExplanation] = []
    if object_name.lower() in {n.lower() for n in rule_side.names}:
        out.append(SideExplanation(side, "direct"))
    if member is not None:
        direct = {g.lower() for g in member.direct}
        groups = member.all_groups()
        for g in sorted(rule_side.groups, key=str.lower):
            if g.lower() not in groups:
                continue
            if g.lower() in direct:
                out.append(SideExplanation(side, "group", via=g, chain=[member.node.name, g]))
                continue
            target = index.node(group_kind, g)
            path = index.membership_path(member.node, target) if target is not None else None
            if path:
                out.append(SideExplanation(side, "nested_group", via=g,
                                           chain=[member.node.name] + [e.dst.name for e in path]))
            else:
                out.append(SideExplanation(side, "nested_group", via=g, chain=[member.node.name, "...", g],
                                           chain_complete=False))
    return out or [SideExplanation(side, "none")]
