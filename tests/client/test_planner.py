"""L3 planner: structural guarantees (validated plan graph) and hard run-time bounds."""

from __future__ import annotations

import dataclasses

import pytest

from ipa_diagnose.client.plan import client_plan
from ipa_diagnose.planner import core
from ipa_diagnose.planner.core import Classified, Outcome, PlanError, Req, Step, run_plan, validate_plan
from ipa_diagnose.resolution.checks import OK, REGISTRY, CheckResult
from tests.client import helpers as H


class FakeRunner:
    replay = True

    def __init__(self, results=None, raise_on=None):
        self.results = results or {}
        self.raise_on = raise_on
        self.runs = 0
        self.calls = []
        self._cache = {}

    def run(self, check_id, params, fresh=False):
        key = (check_id, tuple(sorted(params.items())))
        if check_id == self.raise_on:
            raise KeyboardInterrupt
        self.calls.append((check_id, dict(params), fresh))
        if fresh or key not in self._cache:
            self.runs += 1
            r = self.results.get(check_id)
            self._cache[key] = r(params) if callable(r) else (r or CheckResult(check_id, params, OK,
                                                                                {"is_root": True}, "fine"))
        return self._cache[key]


def s(sid, check="host.privilege", **kw):
    return Step(sid, "TEST", check, sid, "test", **kw)


def test_the_client_plan_is_valid():
    validate_plan(client_plan(), REGISTRY)


def test_forward_or_unknown_dependency_is_rejected_so_no_cycle_can_exist():
    with pytest.raises(PlanError, match="not declared before"):
        validate_plan([s("a", requires=(Req("b"),)), s("b")], REGISTRY)
    with pytest.raises(PlanError, match="not declared before"):
        validate_plan([s("a", after=("a",))], REGISTRY)


def test_unregistered_check_and_wrong_parameters_are_rejected():
    with pytest.raises(PlanError, match="closed check registry"):
        validate_plan([s("a", check="shell.run")], REGISTRY)
    with pytest.raises(PlanError, match="parameters"):
        validate_plan([s("a", check="dns.address")], REGISTRY)


def test_root_check_must_be_declared_and_duplicates_rejected():
    with pytest.raises(PlanError, match="needs root"):
        validate_plan([s("a", check="krb.keytab")], REGISTRY)
    with pytest.raises(PlanError, match="duplicate"):
        validate_plan([s("a"), s("a")], REGISTRY)


def test_fanout_and_depth_are_bounded():
    many = [s("root")] + [s(f"x{i}", requires=(Req("root"),)) for i in range(core.MAX_FANOUT + 1)]
    with pytest.raises(PlanError, match="dependents"):
        validate_plan(many, REGISTRY)
    chain = [s("n0")] + [s(f"n{i}", requires=(Req(f"n{i - 1}"),)) for i in range(1, core.MAX_DEPTH + 1)]
    with pytest.raises(PlanError, match="depth"):
        validate_plan(chain, REGISTRY)


def test_parameter_reference_to_a_later_step_is_rejected():
    with pytest.raises(PlanError, match="later or unknown"):
        validate_plan([s("a", check="dns.address", params={"name": ("fact", "b.server")}), s("b")], REGISTRY)


def test_step_budget_stops_honestly_and_keeps_partial_evidence():
    plan = [s(f"n{i}") for i in range(6)]
    trace, _ = run_plan(plan, FakeRunner(), {}, is_root=True, registry=REGISTRY, max_steps=3)
    ran = [r for r in trace.records if r.outcome != Outcome.SKIPPED]
    assert len(ran) == 3
    assert "step budget" in trace.stop_reason
    assert all(r.skip_reason.startswith("stopped:") for r in trace.records[3:])


def test_wall_clock_budget_stops_the_run():
    t = [0.0]

    def clock():
        t[0] += 10.0
        return t[0]

    trace, _ = run_plan([s(f"n{i}") for i in range(5)], FakeRunner(), {}, is_root=True, registry=REGISTRY,
                        max_seconds=25, clock=clock)
    assert "time budget" in trace.stop_reason
    assert any(r.outcome == Outcome.SKIPPED for r in trace.records)


def test_cancellation_preserves_partial_trace():
    plan = [s("a"), s("b", check="client.versions"), s("c")]
    trace, _ = run_plan(plan, FakeRunner(raise_on="client.versions"), {}, is_root=True, registry=REGISTRY)
    assert trace.cancelled and trace.stop_reason == "cancelled by the operator"
    assert trace.get("a").outcome == Outcome.PASS
    assert trace.get("c").skip_reason.startswith("stopped:")


def test_duplicate_suppression_reuses_one_result():
    plan = [s("a"), s("b")]  # the same check and parameters
    runner = FakeRunner()
    trace, _ = run_plan(plan, runner, {}, is_root=True, registry=REGISTRY)
    assert runner.runs == 1 and trace.get("b").reused and trace.checks_reused == 1


def test_retry_is_bounded_and_fresh_only_on_timeout():
    calls = []

    def timed_out(params):
        calls.append(1)
        return CheckResult("host.privilege", params, "NOT_RUN", {}, "timed out after 10s")

    runner = FakeRunner({"host.privilege": timed_out})
    trace, _ = run_plan([s("a", retries=1)], runner, {}, is_root=True, registry=REGISTRY)
    assert len(calls) == 2 and trace.get("a").attempts == 2 and trace.get("a").outcome == Outcome.UNKNOWN
    with pytest.raises(PlanError):
        validate_plan([s("a", retries=2)], REGISTRY)


def test_blocked_privilege_and_gate_skips_are_recorded():
    plan = [
        s("a", classify=lambda r, c: Classified(Outcome.FAIL, "bad")),
        s("b", check="client.versions", requires=(Req("a"),)),
        s("c", check="krb.keytab", needs_root=True),
        s("d", check="dns.resolvers", when=lambda c: (False, "not relevant")),
    ]
    trace, _ = run_plan(plan, FakeRunner(), {}, is_root=False, registry=REGISTRY)
    assert trace.get("b").skip_reason.startswith("blocked:")
    assert trace.get("c").skip_reason.startswith("privilege:")
    assert trace.get("d").skip_reason == "not needed: not relevant"


def test_unexpected_evidence_shape_is_never_trusted():
    runner = FakeRunner({"client.versions": CheckResult("client.versions", {}, OK, {"os": "x"}, "partial")})
    trace, _ = run_plan([s("a", check="client.versions")], runner, {}, is_root=True, registry=REGISTRY)
    assert trace.get("a").outcome == Outcome.UNKNOWN and "unexpected evidence shape" in trace.get("a").summary


def test_not_recorded_replay_is_unknown_never_pass():
    r = H.run("healthy", data={})  # nothing recorded at all
    assert r.status == "PROBLEM_FOUND" or r.status == "NOT_FULLY_VERIFIED"
    assert all(x.outcome != Outcome.PASS for x in r.trace.records)


def test_same_evidence_gives_the_same_trace():
    a, b = H.run("dns-and-config"), H.run("dns-and-config")
    sig = lambda r: [(x.step_id, x.outcome, x.skip_reason) for x in r.trace.records]  # noqa: E731
    assert sig(a) == sig(b) and H.codes(a) == H.codes(b)


def test_planner_is_more_selective_than_running_everything():
    r = H.run("healthy")
    ran = [x.step_id for x in r.trace.records if x.outcome != Outcome.SKIPPED]
    assert len(ran) < len(r.trace.records)
    for not_needed in ("cache.entry", "sssd.logs", "cache.files", "ipa.user", "nss.switch", "time.local"):
        assert H.outcome(r, not_needed) == "SKIPPED", not_needed


def test_stop_rule_ends_the_run_for_a_non_client():
    r = H.run("not-enrolled")
    assert "not an IPA client" in r.trace.stop_reason
    assert [x.step_id for x in r.trace.records if x.outcome != Outcome.SKIPPED] == ["enroll"]


def test_trace_records_why_each_gated_step_ran():
    r = H.run("stale-cache")
    rec = r.trace.get("cache.entry")
    assert rec.outcome != Outcome.SKIPPED and "IPA has the user and SSSD is online" in rec.selected_because


def test_step_records_are_dataclasses_with_provenance():
    r = H.run("healthy")
    rec = r.trace.get("krb")
    assert rec.source == "REPLAY" and rec.collected_at and rec.side_effects != "none"
    assert dataclasses.is_dataclass(rec)
