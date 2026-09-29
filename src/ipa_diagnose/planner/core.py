"""L3: a bounded, deterministic investigation planner.

A *plan* is an explicit, ordered graph of steps written in code (``ipa_diagnose/client/plan.py``). Each step names ONE
check from the closed registry (:data:`ipa_diagnose.resolution.checks.REGISTRY`), the steps it depends on, a
relevance gate over the results already collected, and how its result is classified. The planner never invents a
step, a command or an argument: it only decides, from results already in hand, which of the declared steps are worth
running next, and it records why.

How the next check is chosen (all of it deterministic; the same evidence gives the same trace):

* a step runs only when every step it ``requires`` finished with an accepted outcome; otherwise it is SKIPPED as
  blocked (its question cannot be answered, or would only repeat the upstream failure);
* its ``when`` gate is evaluated on the facts gathered so far: a check that cannot change the conclusion is SKIPPED
  as not needed (this is what keeps a healthy client from being probed for cache corruption);
* privilege and version applicability are checked before running: a step that needs root, or a tool version this
  host does not have, is SKIPPED with that reason, never run half-way;
* a ``stop`` rule on a step can end the whole run (for example: this host is not an IPA client at all);
* hard bounds end the run honestly: steps, wall clock, per-check timeout (enforced by the check itself), retries.

What the planner guarantees structurally (validated when a plan is built, see :func:`validate_plan`):

* the graph is acyclic: a step may only depend on steps declared BEFORE it, so one ordered pass visits every step
  at most once (no loop is possible at run time);
* the dependency depth and fan-out are bounded;
* every step names a registry check whose parameters are typed; values from earlier results are validated by the
  registry's types before they reach a command.

AI never takes part: it does not choose steps, order, conclusions or anything else here.
"""

from __future__ import annotations

import dataclasses
import datetime
import enum
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ipa_diagnose.textsafe import sanitize_text

MAX_STEPS = 48
MAX_DEPTH = 12
MAX_FANOUT = 10
MAX_WALL_SECONDS = 180.0
MAX_RETRIES = 1


class Outcome(enum.Enum):
    PASS = "PASS"          # the expected, healthy state was observed
    WARN = "WARN"          # degraded or suspicious, not by itself a failure
    FAIL = "FAIL"          # a problem state was observed (with evidence)
    UNKNOWN = "UNKNOWN"    # ran, but gave no usable answer (tool error, permission, not recorded, malformed)
    SKIPPED = "SKIPPED"    # not run (see skip_reason)


class PlanError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class Req:
    step: str
    accept: Tuple[Outcome, ...] = (Outcome.PASS, Outcome.WARN)


@dataclasses.dataclass(frozen=True)
class Classified:
    outcome: Outcome
    summary: str
    facts: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class Step:
    step_id: str
    capability: str
    """DNS, TIME, NETWORK, TLS, ENROLLMENT, KERBEROS, KEYTAB, SSSD, IDENTITY, NSS, PAM, CACHE, ..."""
    check: str
    title: str
    """What the step answers, as shown in CHECKED FOR YOU (for example 'IPA server name resolves')."""
    why: str
    """Why this step is part of the plan (shown by --details)."""
    params: Dict[str, Any] = dataclasses.field(default_factory=dict)
    """param -> literal, or ("fact", "step.field"), or ("input", "name")."""
    requires: Tuple[Req, ...] = ()
    after: Tuple[str, ...] = ()
    """ordering only: these steps must have been visited first (any outcome)."""
    when: Optional[Callable[["Context"], Tuple[bool, str]]] = None
    """relevance gate: (run?, reason). The reason is recorded either way."""
    classify: Optional[Callable[[Any, "Context"], Classified]] = None
    stop: Optional[Callable[["Context"], Optional[str]]] = None
    """after this step: a reason to end the whole run, or None."""
    needs_root: bool = False
    applies: Optional[Callable[["Context"], Tuple[bool, str]]] = None
    """version/platform applicability: (applies?, reason)."""
    retries: int = 0


@dataclasses.dataclass
class Record:
    step_id: str
    capability: str
    check: str
    title: str
    why: str
    outcome: Outcome
    summary: str = ""
    selected_because: str = ""
    skip_reason: str = ""
    params: Dict[str, str] = dataclasses.field(default_factory=dict)
    command: str = ""
    seconds: float = 0.0
    collected_at: Optional[str] = None
    source: str = ""
    status: str = ""
    """the registry check's own status: OK | FAILED | NOT_RUN | DENIED (empty when skipped)."""
    reused: bool = False
    side_effects: str = "none"
    privilege: str = "any"
    facts: Dict[str, Any] = dataclasses.field(default_factory=dict)
    fields: Dict[str, Any] = dataclasses.field(default_factory=dict)
    attempts: int = 0
    blocked_by: Optional[str] = None


@dataclasses.dataclass
class Trace:
    records: List[Record]
    stop_reason: str
    started_at: str
    seconds: float
    bounds: Dict[str, Any]
    checks_run: int
    checks_reused: int
    cancelled: bool = False

    def get(self, step_id: str) -> Optional[Record]:
        return next((r for r in self.records if r.step_id == step_id), None)

    def summary(self) -> Dict[str, Any]:
        ran = [r for r in self.records if r.outcome != Outcome.SKIPPED]
        skipped: Dict[str, int] = {}
        for r in self.records:
            if r.outcome == Outcome.SKIPPED:
                kind = r.skip_reason.split(":", 1)[0]
                skipped[kind] = skipped.get(kind, 0) + 1
        return {"steps_in_plan": len(self.records), "steps_run": len(ran),
                "steps_skipped": len(self.records) - len(ran), "skipped_by_reason": skipped,
                "checks_executed": self.checks_run, "results_reused": self.checks_reused,
                "wall_seconds": round(self.seconds, 3), "stop_reason": self.stop_reason, "cancelled": self.cancelled,
                "bounds": self.bounds}


class Context:
    """What gates and classifiers may read: the inputs, and the facts/outcomes of steps already visited."""

    def __init__(self, inputs: Dict[str, Any], is_root: bool):
        self.inputs = dict(inputs)
        self.is_root = is_root
        self.records: Dict[str, Record] = {}

    def outcome(self, step_id: str) -> Optional[Outcome]:
        r = self.records.get(step_id)
        return r.outcome if r else None

    def ran(self, step_id: str) -> bool:
        r = self.records.get(step_id)
        return r is not None and r.outcome != Outcome.SKIPPED

    def fact(self, ref: str, default: Any = None) -> Any:
        step, _, name = ref.rpartition(".")  # step ids may contain dots; field names never do
        r = self.records.get(step)
        if r is None or r.outcome == Outcome.SKIPPED:
            return default
        if name in r.facts:
            return r.facts[name]
        return r.fields.get(name, default)

    def input(self, name: str, default: Any = None) -> Any:
        return self.inputs.get(name, default)


def _depth(plan: Sequence[Step]) -> int:
    depth: Dict[str, int] = {}
    for s in plan:
        deps = [r.step for r in s.requires] + list(s.after)
        depth[s.step_id] = 1 + max((depth[d] for d in deps), default=0)
    return max(depth.values(), default=0)


def validate_plan(plan: Sequence[Step], registry: Dict[str, Any]) -> None:
    """Structural guarantees, checked before anything runs (a bad plan is a programming error, never run)."""

    if len(plan) > MAX_STEPS:
        raise PlanError(f"plan has {len(plan)} steps (bound {MAX_STEPS})")
    seen: Dict[str, Step] = {}
    fanout: Dict[str, int] = {}
    for s in plan:
        if s.step_id in seen:
            raise PlanError(f"duplicate step {s.step_id}")
        spec = registry.get(s.check)
        if spec is None:
            raise PlanError(f"{s.step_id}: {s.check} is not in the closed check registry")
        if set(s.params) != set(spec.params):
            raise PlanError(f"{s.step_id}: parameters must be exactly {sorted(spec.params)}")
        for dep in [r.step for r in s.requires] + list(s.after):
            if dep not in seen:  # only earlier steps: this is what makes the graph acyclic
                raise PlanError(f"{s.step_id}: depends on {dep}, which is not declared before it")
            fanout[dep] = fanout.get(dep, 0) + 1
        for v in s.params.values():
            if isinstance(v, tuple):
                if len(v) != 2 or v[0] not in ("fact", "input"):
                    raise PlanError(f"{s.step_id}: bad parameter reference {v!r}")
                if v[0] == "fact" and v[1].rpartition(".")[0] not in seen:
                    raise PlanError(f"{s.step_id}: parameter refers to a later or unknown step ({v[1]})")
        if s.retries > MAX_RETRIES:
            raise PlanError(f"{s.step_id}: at most {MAX_RETRIES} retry")
        if spec.privilege == "root" and not s.needs_root:
            raise PlanError(f"{s.step_id}: {s.check} needs root; the step must declare needs_root")
        seen[s.step_id] = s
    worst = max(fanout.values(), default=0)
    if worst > MAX_FANOUT:
        raise PlanError(f"a step has {worst} dependents (bound {MAX_FANOUT})")
    if _depth(plan) > MAX_DEPTH:
        raise PlanError(f"dependency depth {_depth(plan)} exceeds {MAX_DEPTH}")


def _utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_params(step: Step, ctx: Context) -> Tuple[Optional[Dict[str, Any]], str]:
    out: Dict[str, Any] = {}
    for k, v in step.params.items():
        if isinstance(v, tuple):
            val = ctx.fact(v[1]) if v[0] == "fact" else ctx.input(v[1])
            if val in (None, ""):
                return None, f"no value for {k} ({v[1]} is unknown)"
            out[k] = val
        else:
            out[k] = v
    return out, ""


def _safe_gate(fn: Callable[["Context"], Tuple[bool, str]], ctx: "Context") -> Tuple[bool, str]:
    """A gate that cannot read the evidence it needs does not run its step (never runs it on a guess)."""

    try:
        return fn(ctx)
    except (TypeError, ValueError, AttributeError, KeyError, OverflowError, IndexError):
        return False, "the evidence this decision needs has an unexpected type or value"


def _default_classify(res: Any, ctx: Context) -> Classified:
    return Classified(Outcome.PASS if res.ok else Outcome.UNKNOWN, res.display)


def run_plan(plan: Sequence[Step], runner: Any, inputs: Dict[str, Any], *, is_root: bool,
             registry: Dict[str, Any], max_seconds: float = MAX_WALL_SECONDS, max_steps: int = MAX_STEPS,
             clock: Callable[[], float] = time.monotonic) -> Tuple[Trace, Context]:
    validate_plan(plan, registry)
    ctx = Context(inputs, is_root)
    start = clock()
    started_at = _utc()
    executed = 0
    stop_reason = ""
    cancelled = False
    runs_before = getattr(runner, "runs", 0)
    records: List[Record] = []
    source = "REPLAY" if getattr(runner, "replay", False) else "LIVE"

    for step in plan:
        spec = registry[step.check]
        rec = Record(step.step_id, step.capability, step.check, step.title, step.why, Outcome.SKIPPED,
                     side_effects=spec.side_effects, privilege=spec.privilege)
        records.append(rec)
        ctx.records[step.step_id] = rec
        if stop_reason:
            rec.skip_reason = f"stopped: {stop_reason}"
            continue
        blocked = [r for r in step.requires if ctx.outcome(r.step) not in r.accept]
        if blocked:
            b = blocked[0]
            got = ctx.outcome(b.step)
            rec.skip_reason = (f"blocked: needs '{ctx.records[b.step].title}' to pass first "
                               f"(it was {got.value if got else 'not visited'})")
            rec.blocked_by = b.step
            continue
        if step.applies is not None:
            ok, why = _safe_gate(step.applies, ctx)
            if not ok:
                rec.skip_reason = f"not applicable: {why}"
                continue
        if step.when is not None:
            ok, why = _safe_gate(step.when, ctx)
            rec.selected_because = why
            if not ok:
                # unusable evidence is a gap in what could be checked, not a check that was not needed
                rec.skip_reason = (f"not applicable: {why}" if why.startswith("the evidence this decision needs")
                                   else f"not needed: {why}")
                continue
        if step.needs_root and not is_root:
            rec.skip_reason = "privilege: needs root (run ipa-diagnose client as root)"
            continue
        if executed >= max_steps:
            stop_reason = f"step budget of {max_steps} checks used up"
            rec.skip_reason = f"stopped: {stop_reason}"
            continue
        if clock() - start > max_seconds:
            stop_reason = f"time budget of {max_seconds:.0f} s used up"
            rec.skip_reason = f"stopped: {stop_reason}"
            continue
        params, why = _resolve_params(step, ctx)
        if params is None:
            rec.skip_reason = f"blocked: {why}"
            continue
        executed += 1
        t0 = clock()
        try:
            res = None
            for attempt in range(1 + step.retries):
                rec.attempts = attempt + 1
                before = getattr(runner, "runs", 0)
                res = runner.run(step.check, params, fresh=attempt > 0)
                rec.reused = getattr(runner, "runs", 0) == before and attempt == 0
                if res.status != "NOT_RUN" or "timed out" not in (res.display or ""):
                    break
        except KeyboardInterrupt:
            cancelled = True
            stop_reason = "cancelled by the operator"
            rec.skip_reason = f"stopped: {stop_reason}"
            continue
        rec.seconds = round(clock() - t0, 3)
        rec.collected_at = _utc()
        rec.source = source
        rec.status = res.status
        rec.params = {k: sanitize_text(v, 253) for k, v in res.params.items()} if res.params else {}
        rec.command = res.command
        rec.fields = dict(res.fields)
        missing = [f for f in spec.evidence if res.ok and f not in res.fields]
        if missing:  # the evidence does not have the shape this check promises: never trusted
            rec.outcome, rec.summary = Outcome.UNKNOWN, f"unexpected evidence shape (missing {', '.join(missing)})"
        elif not res.ok:
            what = {"DENIED": "not permitted", "NOT_RUN": "could not run", "FAILED": "failed"}.get(res.status,
                                                                                               res.status)
            # A check that did not give an answer is UNKNOWN, never a failure of what it was checking (a systemctl
            # timeout is not "SSSD is stopped"). Classifiers only ever see successful results.
            rec.outcome, rec.summary = Outcome.UNKNOWN, f"{what}: {res.display}" if res.display else what
        else:
            try:
                c = (step.classify or _default_classify)(res, ctx)
            except (TypeError, ValueError, AttributeError, KeyError, OverflowError, IndexError):
                # evidence of an unexpected shape or type (recorded or live) is never interpreted: UNKNOWN
                c = Classified(Outcome.UNKNOWN, "the evidence has an unexpected type or value and was not interpreted")
            rec.outcome, rec.summary, rec.facts = c.outcome, sanitize_text(c.summary, 400), dict(c.facts)
        if step.stop is not None:
            try:
                why_stop = step.stop(ctx)
            except (TypeError, ValueError, AttributeError, KeyError, OverflowError, IndexError):
                why_stop = None
            if why_stop:
                stop_reason = why_stop
    if not stop_reason:
        stop_reason = "every relevant check in the plan was visited"
    trace = Trace(records, stop_reason, started_at, clock() - start,
                  {"max_steps": max_steps, "max_depth": MAX_DEPTH, "max_fanout": MAX_FANOUT,
                   "max_wall_seconds": max_seconds, "max_retries": MAX_RETRIES,
                   "per_check_timeout": "declared per check (CheckSpec.timeout)"},
                  getattr(runner, "runs", 0) - runs_before, sum(1 for r in records if r.reused), cancelled)
    return trace, ctx
