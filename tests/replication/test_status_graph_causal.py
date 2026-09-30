"""Discriminators (agreement status), the EnvironmentGraph and the causal model."""

from __future__ import annotations

import json

import pytest

from ipa_diagnose.environment.graph import (
    MAX_ENTITIES, Enumeration, EnvironmentGraph, GraphError, Kind, Rel, State, ref,
)
from ipa_diagnose.planner.core import ForEach, Step
from ipa_diagnose.replication import causal
from ipa_diagnose.replication import status as S
from ipa_diagnose.replication.causal import Chain, ChainError, Link, check_chain
from ipa_diagnose.replication.plan import READ_PATH, replication_plan
from tests.replication import scenarios as SC

# ---------------------------------------------------------------- status discriminators


@pytest.mark.parametrize("text,cls", [
    (SC.OK_TEXT, S.OK),
    (SC.NO_SESSIONS_TEXT, S.NO_SESSIONS),
    (SC.TRANSPORT_TEXT, S.TRANSPORT),
    (SC.NO_KDC_TEXT, S.GSSAPI_NO_KDC),
    (SC.SKEW_TEXT, S.GSSAPI_CLOCK_SKEW),
    (SC.NOT_FOUND_TEXT, S.GSSAPI_SERVER_NOT_FOUND),
    (SC.CREDS_TEXT, S.GSSAPI_CREDENTIALS),
    (SC.INVALID_TEXT, S.INVALID_CREDENTIALS),
    (SC.DENIED_TEXT, S.INSUFFICIENT_ACCESS),
    (SC.GENERATION_TEXT, S.GENERATION_MISMATCH),
    (SC.BUSY_TEXT, S.BUSY),
    (SC.WEIRD_TEXT, S.UNCLASSIFIED),
    (SC.LOCAL_ERROR_TEXT, S.GSSAPI_OTHER),
    ("Error (18) Replication error acquiring replica: Incremental update transient error.  Backing off, will retry "
     "update later. (transient error)", S.BACKOFF),
    ("Error (-2) Problem connecting to replica - LDAP error: Local error (connection error)", S.GSSAPI_OTHER),
    ("Error (-11) Problem connecting to replica - LDAP error: Connect error (TLS: hostname does not match CN in "
     "peer certificate)", S.TLS),
    ("Error (8) Replication error acquiring replica: Data required to update replica has been purged from the "
     "changelog. If the error persists the replica must be reinitialized. (csn below purge point)",
     S.CHANGELOG_PURGED),
    ("Error (19) Replication error acquiring replica: Replica has the same Replica ID as this one. Replication is "
     "aborting. (duplicate replica ID detected)", S.REPLICA_ID_CONFLICT),
    ("Error (0) Replica acquired successfully: Incremental update started", S.OK),
])
def test_status_classes(text, cls):
    assert S.parse_status(text).cls == cls


def test_json_status_is_used_when_present_and_green_needs_success():
    j = json.dumps({"state": "green", "ldap_rc": "0", "ldap_rc_text": "Success", "repl_rc": "0",
                    "repl_rc_text": "replica acquired", "date": "2026-09-29T00:00:00Z",
                    "message": "Error (0) Replica acquired successfully: Incremental update succeeded"})
    st = S.parse_status("garbage", j)
    assert st.cls == S.OK and st.source == "json"
    red = json.dumps({"state": "red", "ldap_rc": "-1", "ldap_rc_text": "Can't contact LDAP server",
                      "repl_rc": "0", "message": "Error (-1) Problem connecting to replica"})
    assert S.parse_status(None, red).cls == S.TRANSPORT
    amber = json.dumps({"state": "amber", "ldap_rc": "0", "repl_rc": "1", "repl_rc_text": "replica busy",
                        "message": "Error (1) Replication error acquiring replica: replica busy"})
    assert S.parse_status(None, amber).cls == S.BUSY


@pytest.mark.parametrize("bad", [None, "", "{", "[]", "Error (x)", "\x00\x1b[31m", "Error (0)" * 2000,
                                 json.dumps({"state": "green"})])
def test_malformed_status_is_never_green(bad):
    st = S.parse_status(bad if bad and not bad.startswith("{") else None, bad if bad and bad.startswith("{") else None)
    assert st.cls != S.OK


def test_green_json_without_a_success_message_is_not_ok_unless_rc_zero():
    st = S.parse_status(None, json.dumps({"state": "green", "ldap_rc": "0", "repl_rc": "0", "message": ""}))
    assert st.cls == S.OK  # 389-DS says green with both codes 0: that is its own success record
    st = S.parse_status(None, json.dumps({"state": "green", "ldap_rc": "49", "repl_rc": "0", "message": ""}))
    assert st.cls == S.INVALID_CREDENTIALS


def test_bind_error_classification_of_the_reproduction():
    assert S.classify_bind_error("ldap_sasl_interactive_bind: Local error (-2)\n\tadditional info: SASL(-1): generic "
                                 "failure: GSSAPI Error: Unspecified GSS failure.  Minor code may provide more "
                                 "information (Server not found in Kerberos database)", 254) == \
        S.GSSAPI_SERVER_NOT_FOUND
    assert S.classify_bind_error("ldap_sasl_interactive_bind: Can't contact LDAP server (-1)", 255) == S.TRANSPORT
    assert S.classify_bind_error("ldap_sasl_interactive_bind: Invalid credentials (49)", 49) == S.INVALID_CREDENTIALS
    assert S.classify_bind_error("", 3) == S.UNCLASSIFIED


def test_every_class_has_a_meaning():
    assert set(S.MEANING) == set(S.CLASSES)


# ---------------------------------------------------------------- EnvironmentGraph


def g3():
    g = EnvironmentGraph()
    a = g.add_entity(Kind.SERVER, "a.lab.test", owner="a.lab.test", evidence=["topology"])
    b = g.add_entity(Kind.SERVER, "b.lab.test", owner="b.lab.test", evidence=["topology"])
    s = g.add_entity(Kind.SUFFIX, "domain", scope="domain")
    return g, a, b, s


def test_absence_is_only_read_from_a_complete_enumeration():
    g, a, b, _ = g3()
    g.set_enumeration("servers", Enumeration.PARTIAL, Kind.SERVER, [a, b])
    assert g.absent("servers", Kind.SERVER, "c.lab.test") is None
    assert g.absent("servers", Kind.SERVER, "a.lab.test") is False
    g.set_enumeration("servers", Enumeration.COMPLETE, Kind.SERVER, [a, b])
    assert g.absent("servers", Kind.SERVER, "c.lab.test") is True
    assert g.absent("nothing", Kind.SERVER, "c.lab.test") is None
    assert g.enumeration("nothing") == Enumeration.NOT_ASKED
    g.set_enumeration("failed", Enumeration.FAILED, Kind.SERVER)
    assert g.absent("failed", Kind.SERVER, "c.lab.test") is None


def test_observer_relative_answers_are_separate_facts_not_contradictions():
    g, a, b, _ = g3()
    g.add_fact(b, "resolves", True, observed_from="a.lab.test", evidence=["peer.dns@x"])
    g.add_fact(b, "resolves", False, observed_from="c.lab.test", evidence=["other"])
    facts = g.facts(b, "resolves")
    assert [f.state for f in facts] == [State.ESTABLISHED, State.ESTABLISHED]
    assert {f.observed_from for f in facts} == {"a.lab.test", "c.lab.test"}


def test_the_same_observer_disagreeing_with_itself_is_contradicted_and_keeps_both():
    g, a, *_ = g3()
    g.add_fact(a, "active_state", "active", evidence=["local.ds"])
    g.add_fact(a, "active_state", "inactive", evidence=["verify"])
    f = g.fact(a, "active_state")
    assert f.state == State.CONTRADICTED and f.conflicting == ("inactive",)
    assert f.evidence == ("local.ds", "verify")


def test_provenance_is_kept_and_an_established_fact_needs_a_value():
    g, a, *_ = g3()
    g.add_fact(a, "freeipa", None, evidence=["server"], collected_at="2026-09-29T00:00:00Z", source="REPLAY")
    f = g.fact(a, "freeipa")
    assert f.state == State.UNKNOWN and f.source == "REPLAY" and f.collected_at == "2026-09-29T00:00:00Z"
    with pytest.raises(GraphError):
        g.add_fact(a, "x", 1, source="MAYBE")
    with pytest.raises(GraphError):
        g.add_fact("SERVER:nope", "x", 1)


def test_relations_are_closed_typed_and_between_known_entities():
    g, a, b, s = g3()
    g.add_relation(Rel.PARTICIPATES_IN, a, s, ["topology"])
    with pytest.raises(GraphError):
        g.add_relation(Rel.PARTICIPATES_IN, s, a)  # wrong direction / kinds
    with pytest.raises(GraphError):
        g.add_relation(Rel.HOSTS, a, "KDC:unknown")
    assert [r.dst for r in g.relations(Rel.PARTICIPATES_IN, src=a)] == [s]


def test_the_graph_has_no_traversal_api():
    public = {n for n in dir(EnvironmentGraph) if not n.startswith("_")}
    assert public == {"add_entity", "add_fact", "add_relation", "set_enumeration", "entity", "entities", "facts",
                      "fact", "relations", "enumeration", "absent", "truncated", "to_dict"}


def test_the_graph_is_bounded_and_says_so():
    g = EnvironmentGraph()
    for i in range(MAX_ENTITIES + 5):
        g.add_entity(Kind.SERVER, f"h{i}.lab.test")
    assert len(g.entities(Kind.SERVER)) == MAX_ENTITIES and g.truncated and g.dropped["entities"] == 5


def test_serialization_is_deterministic():
    def build(order):
        g = EnvironmentGraph()
        for h in order:
            r = g.add_entity(Kind.SERVER, h)
            g.add_fact(r, "x", h, evidence=["e2", "e1"])
        return json.dumps(g.to_dict(), sort_keys=False)

    assert build(["b.lab.test", "a.lab.test"]) == build(["a.lab.test", "b.lab.test"])


def test_hostile_keys_are_sanitized():
    g = EnvironmentGraph()
    r = g.add_entity(Kind.SERVER, "evil\x1b[31m‮.lab.test")
    assert "\x1b" not in r and "‮" not in r
    g.add_fact(r, "note", "\x1b]52;c;x\x07")
    assert "\x1b" not in json.dumps(g.to_dict())


def test_graph_never_claims_complete_when_its_bound_or_scope_cut_the_list(monkeypatch):
    from ipa_diagnose.environment import graph as GR
    from tests.replication import helpers as H

    monkeypatch.setattr(GR, "MAX_ENTITIES", 12)
    g = H.run(SC.Lab().many_agreements(6)).graph
    assert g.truncated and g.enumeration(f"outbound_agreements:{SC.IPA01}") == Enumeration.PARTIAL
    assert g.enumeration("servers") == Enumeration.PARTIAL
    monkeypatch.setattr(GR, "MAX_ENTITIES", 400)
    scoped = H.run(SC.Lab(), peer=SC.IPA02).graph
    assert scoped.enumeration(f"outbound_agreements:{SC.IPA01}") == Enumeration.PARTIAL


def test_graph_built_from_a_run_marks_observer_relative_facts_and_enumerations():
    from tests.replication import helpers as H

    r = H.run(SC.Lab())
    d = r.graph.to_dict()
    dns = [f for f in d["facts"] if f["name"] == "peer.dns.resolved"]
    assert dns and all(f["observed_from"] == SC.IPA01 for f in dns)
    assert d["enumerations"][f"outbound_agreements:{SC.IPA01}"]["status"] == "COMPLETE"
    assert d["enumerations"]["servers"]["status"] == "COMPLETE"
    assert r.graph.absent("servers", Kind.SERVER, "ghost.lab.test") is True
    assert ref(Kind.AGREEMENT, f"ca:{SC.IPA02}>{SC.IPA01}") in {e["ref"] for e in d["entities"]}
    partial = H.run(SC.Lab().many_agreements(9)).graph
    assert partial.enumeration(f"outbound_agreements:{SC.IPA01}") == Enumeration.PARTIAL


# ---------------------------------------------------------------- causal model


def test_the_capability_model_is_a_dag():
    seen, stack = set(), set()

    def visit(n):
        assert n not in stack, f"cycle through {n}"
        if n in seen:
            return
        stack.add(n)
        for m in causal.DEPENDS_ON[n]:
            assert m in causal.CAPABILITIES
            visit(m)
        stack.discard(n)
        seen.add(n)

    for n in causal.CAPABILITIES:
        visit(n)


def test_every_discriminator_is_an_edge_of_the_dag_or_starts_a_chain():
    for d in causal.DISCRIMINATORS.values():
        assert d.target in causal.CAPABILITIES
        assert d.source == causal.SYMPTOM or d.target in causal.DEPENDS_ON[d.source], d.disc_id


def _reach(a, b):
    todo, seen = [a], set()
    while todo:
        n = todo.pop()
        if n == b:
            return True
        if n not in seen:
            seen.add(n)
            todo.extend(causal.DEPENDS_ON.get(n, ()))
    return False


def test_plan_dependencies_do_not_drift_from_the_capability_model():
    plan = replication_plan()
    caps = {}
    steps = []
    for item in plan:
        for s in (item.steps if isinstance(item, ForEach) else (item,)):
            caps[s.step_id] = s.capability
            steps.append(s)
    for s in steps:
        assert s.capability in causal.CAPABILITIES, s.step_id
        for req in s.requires:
            if req.step in READ_PATH:
                continue
            assert _reach(s.capability, caps[req.step]), f"{s.step_id} ({s.capability}) requires {req.step} " \
                                                         f"({caps[req.step]}) outside the capability model"


def test_a_link_without_its_registered_discriminator_is_refused():
    ok = Chain("c", "s", [Link("x", "s", "REPLICATION", ["agreements"], "agreement-status")])
    check_chain(ok)
    with pytest.raises(ChainError):
        check_chain(Chain("c", "s", [Link("x", "s", "REPLICATION", ["a"], "nope")]))
    with pytest.raises(ChainError):  # right discriminator, wrong step
        check_chain(Chain("c", "s", [Link("x", "s", "REPLICATION", ["a"], "agreement-status"),
                                     Link("y", "s", "LOCAL_KDC", ["b"], "status-gssapi")]))
    with pytest.raises(ChainError):  # skipping a level (REPLICATION -> TIME is not an edge)
        check_chain(Chain("c", "s", [Link("x", "s", "REPLICATION", ["a"], "agreement-status"),
                                     Link("y", "s", "TIME", ["b"], "kerberos-clock-skew")]))
    with pytest.raises(ChainError):  # no evidence
        check_chain(Chain("c", "s", [Link("x", "s", "REPLICATION", [], "agreement-status")]))


def test_every_registered_discriminator_is_used_by_the_diagnosis_code():
    import inspect

    from ipa_diagnose.replication import diagnose

    src = inspect.getsource(diagnose)
    unused = [d for d in causal.DISCRIMINATORS if f'"{d}"' not in src]
    assert not unused, unused


def test_step_ids_of_the_plan_are_valid_and_the_plan_validates():
    from ipa_diagnose.planner.core import validate_plan
    from ipa_diagnose.resolution.checks import REGISTRY

    validate_plan(replication_plan(), REGISTRY)
    assert isinstance(replication_plan()[0], Step)
