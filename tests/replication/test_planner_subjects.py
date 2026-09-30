"""L3 planner, Slice 5: subject identity and bounded for_each templates."""

from __future__ import annotations

import pytest

from ipa_diagnose.planner import core
from ipa_diagnose.planner.core import (
    Classified, ForEach, Outcome, PlanError, Req, Step, run_plan, validate_plan,
)
from ipa_diagnose.resolution.checks import NOT_RUN, OK, REGISTRY, CheckResult


class Runner:
    replay = True

    def __init__(self, answers=None, interrupt_on=None):
        self.answers = answers or {}
        self.interrupt_on = interrupt_on
        self.runs = 0
        self.calls = []

    def run(self, check_id, params, fresh=False):
        self.calls.append((check_id, dict(params)))
        if self.interrupt_on and self.interrupt_on(check_id, params):
            raise KeyboardInterrupt
        self.runs += 1
        a = self.answers.get(check_id)
        if callable(a):
            return a(params)
        return CheckResult(check_id, dict(params), OK, {"is_root": True, "resolved": True, "addresses": ["192.0.2.1"],
                                                        "state": "open"}, "fine")


def lister(subjects, complete=True, outcome=Outcome.PASS):
    def classify(res, ctx):
        return Classified(outcome, "listed", {"peers": subjects, "complete": complete})

    return Step("list", "TOPOLOGY", "host.privilege", "list peers", "test", classify=classify)


def tpl(steps, budget=4, source="list.peers", complete="list.complete", tid="per_peer"):
    return ForEach(tid, source, "fqdn", tuple(steps), budget, "per peer", complete_fact=complete)


def resolve_step(**kw):
    return Step("resolve", "DNS", "dns.address", "peer resolves", "test", params={"name": ("item", "subject")}, **kw)


def tcp_step(**kw):
    return Step("tcp", "NETWORK", "net.tcp", "peer answers", "test",
                params={"host": ("item", "subject"), "port": "389"}, **kw)


def go(plan, runner=None, **kw):
    return run_plan(plan, runner or Runner(), {}, is_root=True, registry=REGISTRY, **kw)


# ---------------------------------------------------------------- subjects, ordering, identity


def test_template_runs_once_per_subject_in_sorted_order_with_unique_instance_ids():
    trace, _ = go([lister(["ipa03.lab.test", "ipa02.lab.test"]), tpl([resolve_step(), tcp_step()])])
    ids = [r.step_id for r in trace.records]
    assert ids == ["list", "resolve@ipa02.lab.test", "tcp@ipa02.lab.test", "resolve@ipa03.lab.test",
                   "tcp@ipa03.lab.test"]
    assert len(set(ids)) == len(ids)
    r = trace.get("tcp", subject="ipa03.lab.test")
    assert (r.subject, r.template, r.base_step) == ("ipa03.lab.test", "per_peer", "tcp")
    assert r.params == {"host": "ipa03.lab.test", "port": "389"}
    assert trace.enumerations["per_peer"]["status"] == "COMPLETE"
    assert [x.step_id for x in trace.for_subject("ipa02.lab.test")] == ["resolve@ipa02.lab.test",
                                                                        "tcp@ipa02.lab.test"]


def test_subject_dicts_carry_their_item_and_duplicates_are_merged():
    items = [{"subject": "ipa02.lab.test", "port": "636"}, {"subject": "IPA02.lab.test", "port": "389"}]
    step = Step("tcp", "NETWORK", "net.tcp", "t", "t", params={"host": ("item", "subject"), "port": ("item", "port")})
    trace, _ = go([lister(items), tpl([step])])
    assert [r.step_id for r in trace.records[1:]] == ["tcp@ipa02.lab.test"]
    assert trace.get("tcp", subject="ipa02.lab.test").params["port"] == "636"  # first entry wins, deterministically


def test_the_same_evidence_gives_the_same_trace():
    plan = [lister(["b.lab.test", "a.lab.test", "c.lab.test"]), tpl([resolve_step(), tcp_step()], budget=2)]
    t1, _ = go(plan)
    t2, _ = go(plan)
    assert [(r.step_id, r.outcome, r.skip_reason) for r in t1.records] == \
        [(r.step_id, r.outcome, r.skip_reason) for r in t2.records]
    assert t1.enumerations == t2.enumerations


# ---------------------------------------------------------------- budgets and enumeration status


def test_budget_drops_are_named_and_make_the_enumeration_partial():
    peers = [f"ipa{i:02d}.lab.test" for i in range(1, 8)]
    trace, _ = go([lister(peers), tpl([resolve_step()], budget=3)])
    e = trace.enumerations["per_peer"]
    assert e["status"] == "PARTIAL"
    assert e["subjects"] == peers[:3] and e["dropped"] == peers[3:]
    assert "budget is 3" in e["reason"]
    assert [r.subject for r in trace.records[1:]] == peers[:3]


def test_invalid_subject_names_are_rejected_named_and_make_it_partial():
    trace, _ = go([lister(["ok.lab.test", "bad name; rm -rf /", "-x", 7]), tpl([resolve_step()])])
    e = trace.enumerations["per_peer"]
    assert e["status"] == "PARTIAL" and e["subjects"] == ["ok.lab.test"]
    assert "bad name; rm -rf /" in e["rejected"] and "(not a name)" in e["rejected"]


def test_source_that_did_not_read_the_whole_list_is_partial_even_without_drops():
    trace, _ = go([lister(["a.lab.test"], complete=False), tpl([resolve_step()])])
    assert trace.enumerations["per_peer"]["status"] == "PARTIAL"
    assert "whole list" in trace.enumerations["per_peer"]["reason"]


@pytest.mark.parametrize("outcome,status", [(Outcome.UNKNOWN, "FAILED"), (Outcome.FAIL, "FAILED")])
def test_an_enumeration_that_was_not_established_investigates_nothing(outcome, status):
    trace, _ = go([lister(["a.lab.test"], outcome=outcome), tpl([resolve_step()])])
    assert trace.enumerations["per_peer"]["status"] == status
    assert len(trace.records) == 1


def test_an_enumeration_that_did_not_run_is_not_asked():
    skip = Step("list", "T", "host.privilege", "list", "t", when=lambda c: (False, "not today"))
    trace, _ = go([skip, tpl([resolve_step()])])
    assert trace.enumerations["per_peer"]["status"] == "NOT_ASKED"


def test_empty_complete_list_is_complete_and_has_no_instances():
    trace, _ = go([lister([]), tpl([resolve_step()])])
    assert trace.enumerations["per_peer"] == {**trace.enumerations["per_peer"], "status": "COMPLETE", "subjects": []}


def test_global_step_budget_inside_a_template_leaves_it_partial_with_the_unfinished_subjects_named():
    peers = ["a.lab.test", "b.lab.test", "c.lab.test"]
    trace, _ = go([lister(peers), tpl([resolve_step(), tcp_step()])], max_steps=4)
    e = trace.enumerations["per_peer"]
    assert e["status"] == "PARTIAL" and set(e["unfinished"]) == {"b.lab.test", "c.lab.test"}
    assert "step budget" in trace.stop_reason


def test_static_expansion_bound_is_checked_before_running():
    steps = [Step(f"s{i}", "T", "host.privilege", "s", "s") for i in range(13)]
    with pytest.raises(PlanError, match="hard bound"):
        validate_plan([lister([]), tpl(steps, budget=16)], REGISTRY)
    with pytest.raises(PlanError, match="instance budget"):
        validate_plan([lister([]), tpl([resolve_step()], budget=core.MAX_INSTANCES + 1)], REGISTRY)
    with pytest.raises(PlanError, match="instance budget"):
        validate_plan([lister([]), tpl([resolve_step()], budget=0)], REGISTRY)


# ---------------------------------------------------------------- isolation between subjects


def _answers_by_host(bad_host):
    def dns(params):
        ok = params["name"] != bad_host
        return CheckResult("dns.address", params, OK, {"resolved": ok, "addresses": ["192.0.2.9"] if ok else []}, "x")

    return {"dns.address": dns}


def c_resolve(res, ctx):
    return Classified(Outcome.PASS if res.fields["resolved"] else Outcome.FAIL, "r", {"ok": res.fields["resolved"]})


def test_a_failure_of_one_subject_blocks_only_that_subjects_dependent_steps():
    plan = [lister(["a.lab.test", "b.lab.test"]),
            tpl([resolve_step(classify=c_resolve), tcp_step(requires=(Req("resolve"),))])]
    trace, _ = go(plan, Runner(_answers_by_host("a.lab.test")))
    a = trace.get("tcp", subject="a.lab.test")
    b = trace.get("tcp", subject="b.lab.test")
    assert a.outcome == Outcome.SKIPPED and a.blocked_by == "resolve@a.lab.test"
    assert b.outcome == Outcome.PASS


def test_gates_and_classifiers_read_their_own_subjects_facts_only():
    seen = []

    def gate(ctx):
        seen.append((ctx.subject, ctx.fact("resolve.ok"), ctx.item.get("subject")))
        return True, "x"

    plan = [lister(["a.lab.test", "b.lab.test"]), tpl([resolve_step(classify=c_resolve), tcp_step(when=gate)])]
    go(plan, Runner(_answers_by_host("b.lab.test")))
    assert seen == [("a.lab.test", True, "a.lab.test"), ("b.lab.test", False, "b.lab.test")]


def test_template_steps_may_depend_on_earlier_plan_steps():
    plan = [lister(["a.lab.test"]), Step("root", "T", "host.privilege", "root", "t"),
            tpl([tcp_step(requires=(Req("root"),))])]
    trace, _ = go(plan)
    assert trace.get("tcp", subject="a.lab.test").outcome == Outcome.PASS


def test_stop_subject_ends_only_that_subject():
    def stop(ctx):
        return "the peer does not resolve" if ctx.fact("resolve.ok") is False else None

    plan = [lister(["a.lab.test", "b.lab.test"]), tpl([resolve_step(classify=c_resolve, stop_subject=stop),
                                                     tcp_step()])]
    trace, _ = go(plan, Runner(_answers_by_host("a.lab.test")))
    assert "stopped for this subject" in trace.get("tcp", subject="a.lab.test").skip_reason
    assert trace.get("tcp", subject="b.lab.test").outcome == Outcome.PASS
    assert trace.stop_reason == "every relevant check in the plan was visited"
    assert trace.enumerations["per_peer"]["status"] == "COMPLETE"


def test_a_template_step_cannot_stop_the_whole_run_or_retry():
    with pytest.raises(PlanError, match="stop the whole run"):
        validate_plan([lister([]), tpl([resolve_step(stop=lambda c: "x")])], REGISTRY)
    with pytest.raises(PlanError, match="retry"):
        validate_plan([lister([]), tpl([resolve_step(retries=1)])], REGISTRY)
    with pytest.raises(PlanError, match="template steps only"):
        validate_plan([Step("x", "T", "host.privilege", "x", "x", stop_subject=lambda c: None)], REGISTRY)


def test_subjects_only_come_from_an_earlier_plan_step():
    with pytest.raises(PlanError, match="earlier plan step"):
        validate_plan([tpl([resolve_step()]), lister([])], REGISTRY)
    inner = ForEach("inner", "resolve.addresses", "fqdn", (Step("t2", "T", "host.privilege", "t", "t"),), 2)
    with pytest.raises(PlanError, match="earlier plan step"):
        validate_plan([lister([]), tpl([resolve_step()]), inner], REGISTRY)


def test_item_references_only_inside_templates_and_ids_cannot_collide():
    with pytest.raises(PlanError, match="bad parameter"):
        validate_plan([Step("x", "T", "dns.address", "x", "x", params={"name": ("item", "subject")})], REGISTRY)
    with pytest.raises(PlanError, match="duplicate"):
        validate_plan([lister([]), tpl([Step("list", "T", "host.privilege", "l", "l")])], REGISTRY)
    with pytest.raises(PlanError, match="reserved"):
        validate_plan([Step("a@b", "T", "host.privilege", "x", "x")], REGISTRY)
    with pytest.raises(PlanError, match="template"):
        validate_plan([lister([]), tpl([resolve_step()]), Step("after", "T", "host.privilege", "a", "a",
                                                               after=("per_peer",))], REGISTRY)


def test_unknown_subject_type_is_rejected():
    bad = ForEach("t", "list.peers", "shell", (resolve_step(),), 2)
    with pytest.raises(PlanError, match="subject type"):
        validate_plan([lister([]), bad], REGISTRY)


# ---------------------------------------------------------------- unknown propagation and cancellation


def test_a_check_that_did_not_answer_is_unknown_for_that_subject_and_blocks_its_dependents():
    def dns(params):
        if params["name"] == "a.lab.test":
            return CheckResult("dns.address", params, NOT_RUN, {}, "timed out after 15s")
        return CheckResult("dns.address", params, OK, {"resolved": True, "addresses": ["192.0.2.1"]}, "ok")

    plan = [lister(["a.lab.test", "b.lab.test"]), tpl([resolve_step(), tcp_step(requires=(Req("resolve"),))])]
    trace, _ = go(plan, Runner({"dns.address": dns}))
    assert trace.get("resolve", subject="a.lab.test").outcome == Outcome.UNKNOWN
    assert "UNKNOWN" in trace.get("tcp", subject="a.lab.test").skip_reason
    assert trace.get("tcp", subject="b.lab.test").outcome == Outcome.PASS


def test_cancellation_inside_a_template_stops_the_run_and_is_recorded():
    runner = Runner(interrupt_on=lambda c, p: c == "net.tcp" and p.get("host") == "b.lab.test")
    trace, _ = go([lister(["a.lab.test", "b.lab.test", "c.lab.test"]), tpl([tcp_step()])], runner)
    assert trace.cancelled and trace.stop_reason == "cancelled by the operator"
    assert trace.get("tcp", subject="c.lab.test").skip_reason.startswith("stopped:")
    assert trace.enumerations["per_peer"]["status"] == "PARTIAL"


def test_the_client_plan_summary_has_no_template_keys():
    trace, _ = go([Step("x", "T", "host.privilege", "x", "x")])
    assert "enumerations" not in trace.summary()
    assert "hard_max_steps" not in trace.summary()["bounds"]
