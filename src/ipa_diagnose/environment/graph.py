"""L2: a bounded, read-only, per-run model of the FreeIPA environment around an investigation.

The EnvironmentGraph is CONTEXT. It is built from evidence that was already collected (never collects anything
itself), and it is not a reasoner:

* it holds entities (closed kinds), facts about them, and evidenced relations between them;
* every fact carries its state (ESTABLISHED / UNKNOWN / CONTRADICTED), the evidence it came from, when it was
  collected, whether it is LIVE or REPLAY, and - for observer-relative facts such as a DNS answer, a clock offset or
  reachability - the host it was observed FROM. Two different answers observed from different hosts are two facts,
  never a contradiction;
* an enumeration (for example "the agreements of this server") records whether it was COMPLETE, PARTIAL,
  NOT_ASKED or FAILED. Absence may be read as "not present" ONLY from a COMPLETE enumeration (:meth:`absent`);
* the API is lookup-only: an entity, the facts about it, the relations of one kind from or to it. There is no
  traversal, no transitive closure and no inference. A dependency edge never proves causality;
* it is bounded (entities, facts, relations); anything beyond a bound is dropped and the graph says so.

It does not decide anything: diagnoses, root causes and fixes are decided elsewhere (L4/L5) by explicit rules.
"""

from __future__ import annotations

import dataclasses
import enum
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ipa_diagnose.textsafe import sanitize_text

MAX_ENTITIES = 400
MAX_FACTS = 3000
MAX_RELATIONS = 1500


class Kind(enum.Enum):
    SERVER = "SERVER"
    REPLICA = "REPLICA"
    CLIENT = "CLIENT"
    SUFFIX = "SUFFIX"
    AGREEMENT = "AGREEMENT"
    TOPOLOGY_SEGMENT = "TOPOLOGY_SEGMENT"
    SERVER_ROLE = "SERVER_ROLE"
    DIRECTORY_SERVER_INSTANCE = "DIRECTORY_SERVER_INSTANCE"
    KDC = "KDC"
    PRINCIPAL = "PRINCIPAL"
    KEYTAB = "KEYTAB"


class State(enum.Enum):
    ESTABLISHED = "ESTABLISHED"
    UNKNOWN = "UNKNOWN"
    CONTRADICTED = "CONTRADICTED"


class Enumeration(enum.Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    NOT_ASKED = "NOT_ASKED"
    FAILED = "FAILED"


class Rel(enum.Enum):
    HOSTS = "HOSTS"                    # SERVER -> DIRECTORY_SERVER_INSTANCE | KDC
    HAS_ROLE = "HAS_ROLE"              # SERVER -> SERVER_ROLE
    PARTICIPATES_IN = "PARTICIPATES_IN"  # SERVER -> SUFFIX
    SUPPLIER_OF = "SUPPLIER_OF"        # SERVER -> AGREEMENT
    CONSUMER_OF = "CONSUMER_OF"        # SERVER -> AGREEMENT
    REPLICATES = "REPLICATES"          # AGREEMENT -> SUFFIX
    CONNECTS = "CONNECTS"              # TOPOLOGY_SEGMENT -> SERVER
    SEGMENT_OF = "SEGMENT_OF"          # TOPOLOGY_SEGMENT -> SUFFIX
    PRINCIPAL_OF = "PRINCIPAL_OF"      # PRINCIPAL -> SERVER
    CONTAINS = "CONTAINS"              # KEYTAB -> PRINCIPAL
    SELECTS = "SELECTS"                # CLIENT -> SERVER


# which entity kinds a relation may connect (anything else is refused: no nonsense edges)
_ENDPOINTS: Dict[Rel, Tuple[Tuple[Kind, ...], Tuple[Kind, ...]]] = {
    Rel.HOSTS: ((Kind.SERVER,), (Kind.DIRECTORY_SERVER_INSTANCE, Kind.KDC)),
    Rel.HAS_ROLE: ((Kind.SERVER,), (Kind.SERVER_ROLE,)),
    Rel.PARTICIPATES_IN: ((Kind.SERVER,), (Kind.SUFFIX,)),
    Rel.SUPPLIER_OF: ((Kind.SERVER,), (Kind.AGREEMENT,)),
    Rel.CONSUMER_OF: ((Kind.SERVER,), (Kind.AGREEMENT,)),
    Rel.REPLICATES: ((Kind.AGREEMENT,), (Kind.SUFFIX,)),
    Rel.CONNECTS: ((Kind.TOPOLOGY_SEGMENT,), (Kind.SERVER,)),
    Rel.SEGMENT_OF: ((Kind.TOPOLOGY_SEGMENT,), (Kind.SUFFIX,)),
    Rel.PRINCIPAL_OF: ((Kind.PRINCIPAL,), (Kind.SERVER,)),
    Rel.CONTAINS: ((Kind.KEYTAB,), (Kind.PRINCIPAL,)),
    Rel.SELECTS: ((Kind.CLIENT,), (Kind.SERVER,)),
}


class GraphError(ValueError):
    pass


def ref(kind: Kind, key: str) -> str:
    return f"{kind.value}:{key}"


def _kind_of(r: str) -> Optional[Kind]:
    k, _, _ = r.partition(":")
    try:
        return Kind(k)
    except ValueError:
        return None


@dataclasses.dataclass(frozen=True)
class Entity:
    kind: Kind
    key: str
    owner: Optional[str]
    """the host this entity lives on (None when it is not host-local, e.g. a suffix)."""
    scope: Optional[str]
    """domain | ca | host | topology ..."""
    evidence: Tuple[str, ...]

    @property
    def ref(self) -> str:
        return ref(self.kind, self.key)


@dataclasses.dataclass(frozen=True)
class Fact:
    subject: str
    name: str
    value: Any
    state: State
    evidence: Tuple[str, ...]
    collected_at: Optional[str]
    source: str
    """LIVE | REPLAY"""
    observed_from: Optional[str] = None
    """the observer host, for observer-relative facts (DNS answer, clock offset, reachability)."""
    context: Tuple[Tuple[str, str], ...] = ()
    """applicability context (for example ('freeipa', '4.13.3'))."""
    conflicting: Tuple[Any, ...] = ()


@dataclasses.dataclass(frozen=True)
class Relation:
    kind: Rel
    src: str
    dst: str
    evidence: Tuple[str, ...]


def _clean(v: Any) -> Any:
    if isinstance(v, str):
        return sanitize_text(v, 300)
    if isinstance(v, bool) or v is None or isinstance(v, (int, float)):
        return v
    if isinstance(v, (list, tuple)):
        return [_clean(x) for x in list(v)[:64]]
    if isinstance(v, dict):
        return {sanitize_text(str(k), 80): _clean(x) for k, x in list(v.items())[:64]}
    return sanitize_text(str(v), 300)


class EnvironmentGraph:
    def __init__(self) -> None:
        self._entities: Dict[str, Entity] = {}
        self._facts: Dict[Tuple[str, str, Optional[str]], Fact] = {}
        self._relations: Dict[Tuple[Rel, str, str], Relation] = {}
        self._enumerations: Dict[str, Dict[str, Any]] = {}
        self.dropped: Dict[str, int] = {"entities": 0, "facts": 0, "relations": 0}

    # ---------------------------------------------------------------- building (from collected evidence only)

    def add_entity(self, kind: Kind, key: str, owner: Optional[str] = None, scope: Optional[str] = None,
                   evidence: Iterable[str] = ()) -> Optional[str]:
        if not isinstance(kind, Kind) or not isinstance(key, str) or not key:
            raise GraphError("an entity needs a closed kind and a key")
        key = sanitize_text(key, 300)
        r = ref(kind, key)
        ev = tuple(sorted(set(evidence)))
        if r in self._entities:
            old = self._entities[r]
            self._entities[r] = dataclasses.replace(old, evidence=tuple(sorted(set(old.evidence) | set(ev))))
            return r
        if len(self._entities) >= MAX_ENTITIES:
            self.dropped["entities"] += 1
            return None
        self._entities[r] = Entity(kind, key, owner, scope, ev)
        return r

    def add_fact(self, subject: Optional[str], name: str, value: Any, state: State = State.ESTABLISHED,
                 evidence: Iterable[str] = (), collected_at: Optional[str] = None, source: str = "LIVE",
                 observed_from: Optional[str] = None, context: Optional[Dict[str, str]] = None) -> None:
        if subject is None:
            return  # its entity was dropped by a bound: the fact goes with it
        if subject not in self._entities:
            raise GraphError(f"fact about an unknown entity {subject}")
        if source not in ("LIVE", "REPLAY"):
            raise GraphError("a fact is LIVE or REPLAY")
        k = (subject, name, observed_from)
        value = _clean(value)
        if value is None and state == State.ESTABLISHED:
            state = State.UNKNOWN  # an established fact has a value
        new = Fact(subject, name, value, state, tuple(sorted(set(evidence))), collected_at, source, observed_from,
                   tuple(sorted((context or {}).items())))
        old = self._facts.get(k)
        if old is not None:
            if old.state == State.ESTABLISHED and new.state == State.ESTABLISHED and old.value != new.value:
                # the SAME observer reported two different values for the same thing: contradicted, both kept
                self._facts[k] = dataclasses.replace(old, state=State.CONTRADICTED,
                                                     conflicting=old.conflicting + (new.value,),
                                                     evidence=tuple(sorted(set(old.evidence) | set(new.evidence))))
            elif old.state == State.UNKNOWN and new.state == State.ESTABLISHED:
                self._facts[k] = new
            return
        if len(self._facts) >= MAX_FACTS:
            self.dropped["facts"] += 1
            return
        self._facts[k] = new

    def add_relation(self, kind: Rel, src: Optional[str], dst: Optional[str], evidence: Iterable[str] = ()) -> None:
        if src is None or dst is None:
            return
        if src not in self._entities or dst not in self._entities:
            raise GraphError(f"relation between unknown entities ({src} -> {dst})")
        srcs, dsts = _ENDPOINTS[kind]
        if _kind_of(src) not in srcs or _kind_of(dst) not in dsts:
            raise GraphError(f"{kind.value} cannot connect {src} to {dst}")
        k = (kind, src, dst)
        if k in self._relations:
            return
        if len(self._relations) >= MAX_RELATIONS:
            self.dropped["relations"] += 1
            return
        self._relations[k] = Relation(kind, src, dst, tuple(sorted(set(evidence))))

    def set_enumeration(self, name: str, status: Enumeration, kind: Optional[Kind] = None,
                        members: Iterable[str] = (), reason: str = "", scope: Optional[str] = None) -> None:
        self._enumerations[name] = {"status": status, "kind": kind, "members": sorted(set(members)),
                                    "reason": sanitize_text(reason, 300), "scope": scope}

    # ---------------------------------------------------------------- lookups (no traversal, no inference)

    def entity(self, r: str) -> Optional[Entity]:
        return self._entities.get(r)

    def entities(self, kind: Kind) -> List[Entity]:
        return sorted((e for e in self._entities.values() if e.kind == kind), key=lambda e: e.key)

    def facts(self, subject: str, name: Optional[str] = None) -> List[Fact]:
        out = [f for (s, n, _), f in self._facts.items() if s == subject and (name is None or n == name)]
        return sorted(out, key=lambda f: (f.name, f.observed_from or ""))

    def fact(self, subject: str, name: str, observed_from: Optional[str] = None) -> Optional[Fact]:
        return self._facts.get((subject, name, observed_from))

    def relations(self, kind: Optional[Rel] = None, src: Optional[str] = None,
                  dst: Optional[str] = None) -> List[Relation]:
        out = [r for r in self._relations.values()
               if (kind is None or r.kind == kind) and (src is None or r.src == src) and (dst is None or r.dst == dst)]
        return sorted(out, key=lambda r: (r.kind.value, r.src, r.dst))

    def enumeration(self, name: str) -> Enumeration:
        e = self._enumerations.get(name)
        return e["status"] if e else Enumeration.NOT_ASKED

    def absent(self, enumeration: str, kind: Kind, key: str) -> Optional[bool]:
        """True when `key` is NOT among the members of a COMPLETE enumeration; False when present; None (unknown)
        when the enumeration is not complete - absence is never read from partial evidence."""

        e = self._enumerations.get(enumeration)
        r = ref(kind, key)
        if e is not None and r in e["members"]:
            return False
        if e is None or e["status"] != Enumeration.COMPLETE or e["kind"] != kind:
            return None
        return True

    @property
    def truncated(self) -> bool:
        return any(self.dropped.values())

    # ---------------------------------------------------------------- serialization (deterministic)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entities": [{"ref": e.ref, "kind": e.kind.value, "key": e.key, "owner": e.owner, "scope": e.scope,
                          "evidence": list(e.evidence)} for e in sorted(self._entities.values(), key=lambda x: x.ref)],
            "facts": [{"subject": f.subject, "name": f.name, "value": f.value, "state": f.state.value,
                       "evidence": list(f.evidence), "collected_at": f.collected_at, "source": f.source,
                       "observed_from": f.observed_from, "context": dict(f.context),
                       **({"conflicting": list(f.conflicting)} if f.conflicting else {})}
                      for _, f in sorted(self._facts.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2] or ""))],
            "relations": [{"kind": r.kind.value, "src": r.src, "dst": r.dst, "evidence": list(r.evidence)}
                          for r in self.relations()],
            "enumerations": {n: {"status": e["status"].value, "kind": e["kind"].value if e["kind"] else None,
                                 "members": list(e["members"]), "reason": e["reason"], "scope": e["scope"]}
                             for n, e in sorted(self._enumerations.items())},
            "bounds": {"max_entities": MAX_ENTITIES, "max_facts": MAX_FACTS, "max_relations": MAX_RELATIONS,
                       "dropped": dict(self.dropped)},
        }
