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

Subjects and bounded ``for_each`` templates (Slice 5):

* a :class:`ForEach` template repeats a small, fixed list of steps once per *subject* (for example one replication
  agreement). Subjects come ONLY from an earlier step's established list fact, each subject key is validated by a
  declared type, and they are visited in sorted (deterministic) order;
* every template has its own instance budget, under the hard global bound (:data:`HARD_MAX_STEPS`, checked
  statically when the plan is built); subjects dropped because of the budget are named, and the enumeration is then
  PARTIAL (never "healthy by omission");
* a record's identity is ``(step_id, subject)``: facts and outcomes a template step reads resolve to ITS OWN
  subject's instances first, so one subject's evidence never leaks into another's;
* template steps cannot stop the whole run (no ``stop``), cannot retry, and may only end their own subject's
  remaining steps (``stop_subject``).

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
# a relevance gate whose reason starts with this declines a check on purpose (for safety): its question is left
# open, so the skip is a gap in what was verified ("not applicable"), never "not needed"
NOT_RUN_ON_PURPOSE = "not run on purpose:"
MAX_INSTANCES = 16
"""per template: the most subjects one for_each may investigate."""
HARD_MAX_STEPS = 200
"""static ceiling: plan steps plus every template step times its instance budget."""


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
    stop_subject: Optional[Callable[["Context"], Optional[str]]] = None
    """template steps only: after this step, a reason to end THIS subject's remaining steps (never the run)."""


@dataclasses.dataclass(frozen=True)
class ForEach:
    """A bounded template: ``steps`` run once per subject listed in an earlier step's established list fact."""

    template_id: str
    source: str
    """"step.field" of an EARLIER plan step: a list of subject keys, or of dicts with a "subject" key."""
    subject_type: str
    """the validator (resolution.types.VALIDATORS) every subject key must pass."""
    steps: Tuple[Step, ...]
    max_instances: int
    title: str = ""
    complete_fact: Optional[str] = None
    """"step.field": True when the source step read the WHOLE list (otherwise the enumeration is PARTIAL)."""
    subject_seconds: Optional[float] = None
    """a time slice per subject: one slow subject ends only its own remaining steps, not the others'."""


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
    subject: Optional[str] = None
    """the subject of a template instance (None for an ordinary plan step)."""
    template: Optional[str] = None
    base_step: Optional[str] = None
    """the template step this instance was made from (its step_id is base_step@subject)."""


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
    enumerations: Dict[str, Dict[str, Any]] = dataclasses.field(default_factory=dict)
    """template_id -> {status COMPLETE|PARTIAL|FAILED|NOT_ASKED, subjects, dropped, rejected, reason}."""

    def get(self, step_id: str, subject: Optional[str] = None) -> Optional[Record]:
        if subject is not None:
            return next((r for r in self.records if r.base_step == step_id and r.subject == subject), None)
        return next((r for r in self.records if r.step_id == step_id), None)

    def for_subject(self, subject: str) -> List[Record]:
        return [r for r in self.records if r.subject == subject]

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
                "bounds": self.bounds, **({"enumerations": self.enumerations} if self.enumerations else {})}


class Context:
    """What gates and classifiers may read: the inputs, and the facts/outcomes of steps already visited."""

    def __init__(self, inputs: Dict[str, Any], is_root: bool):
        self.inputs = dict(inputs)
        self.is_root = is_root
        self.records: Dict[str, Record] = {}
        self.subject: Optional[str] = None
        self.item: Dict[str, Any] = {}

    def _key(self, step_id: str) -> str:
        return step_id

    def outcome(self, step_id: str) -> Optional[Outcome]:
        r = self.records.get(self._key(step_id))
        return r.outcome if r else None

    def ran(self, step_id: str) -> bool:
        r = self.records.get(self._key(step_id))
        return r is not None and r.outcome != Outcome.SKIPPED

    def fact(self, ref: str, default: Any = None) -> Any:
        step, _, name = ref.rpartition(".")  # step ids may contain dots; field names never do
        r = self.records.get(self._key(step))
        if r is None or r.outcome == Outcome.SKIPPED:
            return default
        if name in r.facts:
            return r.facts[name]
        return r.fields.get(name, default)

    def input(self, name: str, default: Any = None) -> Any:
        return self.inputs.get(name, default)


class SubjectContext(Context):
    """What a template step's gates and classifiers see: the run's context, with the template's own step ids
    resolved to THIS subject's instances first (no cross-subject reads), and the subject's item."""

    def __init__(self, base: Context, local_ids: "frozenset", subject: str, item: Dict[str, Any]):
        self._base = base
        self._local = local_ids
        self.subject = subject
        self.item = dict(item)
        self.inputs = base.inputs
        self.is_root = base.is_root
        self.records = base.records

    def _key(self, step_id: str) -> str:
        return f"{step_id}@{self.subject}" if step_id in self._local else step_id




PlanItem = Any  # Step | ForEach


def _deps(s: Step) -> List[str]:
    return [r.step for r in s.requires] + list(s.after)


def _depth(plan: Sequence[PlanItem]) -> int:
    depth: Dict[str, int] = {}
    for item in plan:
        if isinstance(item, ForEach):
            base = depth.get(item.source.rpartition(".")[0], 0)
            local: Dict[str, int] = {}
            for s in item.steps:
                local[s.step_id] = 1 + max([base] + [local[d] if d in local else depth.get(d, 0) for d in _deps(s)])
            depth[item.template_id] = max(local.values(), default=base)
            continue
        depth[item.step_id] = 1 + max((depth[d] for d in _deps(item)), default=0)
    return max(depth.values(), default=0)


def _validate_step(s: Step, spec: Any, seen: Dict[str, Any], local: Dict[str, Step], fanout: Dict[str, int],
                   in_template: bool) -> None:
    if "@" in s.step_id or not s.step_id:
        raise PlanError(f"{s.step_id!r}: '@' is reserved for template instances")
    if set(s.params) != set(spec.params):
        raise PlanError(f"{s.step_id}: parameters must be exactly {sorted(spec.params)}")
    for dep in _deps(s):
        if dep not in seen and dep not in local:  # only earlier steps: this is what makes the graph acyclic
            raise PlanError(f"{s.step_id}: depends on {dep}, which is not declared before it")
        if isinstance(seen.get(dep), ForEach):
            raise PlanError(f"{s.step_id}: depends on the template {dep}; depend on a plan step instead")
        fanout[dep] = fanout.get(dep, 0) + 1
    for v in s.params.values():
        if isinstance(v, tuple):
            kinds = ("fact", "input", "item") if in_template else ("fact", "input")
            if len(v) != 2 or v[0] not in kinds:
                raise PlanError(f"{s.step_id}: bad parameter reference {v!r}")
            if v[0] == "fact" and v[1].rpartition(".")[0] not in seen and v[1].rpartition(".")[0] not in local:
                raise PlanError(f"{s.step_id}: parameter refers to a later or unknown step ({v[1]})")
    if s.retries > MAX_RETRIES:
        raise PlanError(f"{s.step_id}: at most {MAX_RETRIES} retry")
    if spec.privilege == "root" and not s.needs_root:
        raise PlanError(f"{s.step_id}: {s.check} needs root; the step must declare needs_root")
    if in_template:
        if s.stop is not None:
            raise PlanError(f"{s.step_id}: a template step may not stop the whole run (use stop_subject)")
        if s.retries:
            raise PlanError(f"{s.step_id}: template steps do not retry")
    elif s.stop_subject is not None:
        raise PlanError(f"{s.step_id}: stop_subject is for template steps only")


def validate_plan(plan: Sequence[PlanItem], registry: Dict[str, Any]) -> None:
    """Structural guarantees, checked before anything runs (a bad plan is a programming error, never run)."""

    from ipa_diagnose.resolution import types as T

    declared = sum(len(i.steps) if isinstance(i, ForEach) else 1 for i in plan)
    if declared > MAX_STEPS:
        raise PlanError(f"plan has {declared} steps (bound {MAX_STEPS})")
    expanded = sum(len(i.steps) * i.max_instances if isinstance(i, ForEach) else 1 for i in plan)
    if expanded > HARD_MAX_STEPS:
        raise PlanError(f"plan can expand to {expanded} steps (hard bound {HARD_MAX_STEPS})")
    seen: Dict[str, Any] = {}
    fanout: Dict[str, int] = {}
    for item in plan:
        if isinstance(item, ForEach):
            if item.template_id in seen or "@" in item.template_id or not item.template_id:
                raise PlanError(f"duplicate or invalid template id {item.template_id}")
            if not 1 <= item.max_instances <= MAX_INSTANCES:
                raise PlanError(f"{item.template_id}: instance budget must be 1..{MAX_INSTANCES}")
            if item.subject_type not in T.VALIDATORS:
                raise PlanError(f"{item.template_id}: unknown subject type {item.subject_type}")
            for ref in (item.source, item.complete_fact):
                if ref is not None and (ref.rpartition(".")[0] not in seen
                                        or not isinstance(seen[ref.rpartition(".")[0]], Step)
                                        or any(ref.rpartition(".")[0] in (t.step_id for t in x.steps)
                                               for x in seen.values() if isinstance(x, ForEach))):
                    raise PlanError(f"{item.template_id}: subjects must come from an earlier plan step ({ref})")
            if not item.steps:
                raise PlanError(f"{item.template_id}: a template needs at least one step")
            local: Dict[str, Step] = {}
            for s in item.steps:
                if s.step_id in seen or s.step_id in local:
                    raise PlanError(f"duplicate step {s.step_id}")
                spec = registry.get(s.check)
                if spec is None:
                    raise PlanError(f"{s.step_id}: {s.check} is not in the closed check registry")
                _validate_step(s, spec, seen, local, fanout, in_template=True)
                local[s.step_id] = s
            for sid, s in local.items():
                seen[sid] = s
            seen[item.template_id] = item
            continue
        s = item
        if s.step_id in seen:
            raise PlanError(f"duplicate step {s.step_id}")
        spec = registry.get(s.check)
        if spec is None:
            raise PlanError(f"{s.step_id}: {s.check} is not in the closed check registry")
        _validate_step(s, spec, seen, {}, fanout, in_template=False)
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
            if v[0] == "fact":
                val = ctx.fact(v[1])
            elif v[0] == "item":
                val = ctx.item.get(v[1]) if isinstance(ctx.item, dict) else None
            else:
                val = ctx.input(v[1])
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


class _Run:
    """Mutable state of one plan run (budgets, stop reason), shared by plan steps and template instances."""

    def __init__(self, runner: Any, registry: Dict[str, Any], max_seconds: float, max_steps: int,
                 clock: Callable[[], float], is_root: bool, privilege_hint: str):
        self.runner, self.registry, self.max_seconds, self.max_steps, self.clock = (runner, registry, max_seconds,
                                                                                   max_steps, clock)
        self.is_root = is_root
        self.privilege_hint = privilege_hint
        self.start = clock()
        self.executed = 0
        self.stop_reason = ""
        self.cancelled = False
        self.source = "REPLAY" if getattr(runner, "replay", False) else "LIVE"

    def visit(self, step: Step, rec: Record, ctx: Context) -> Optional[str]:
        """Decide and (maybe) run one step into `rec`. Returns a subject-stop reason (template steps only)."""

        spec = self.registry[step.check]
        if self.stop_reason:
            rec.skip_reason = f"stopped: {self.stop_reason}"
            return None
        blocked = [r for r in step.requires if ctx.outcome(r.step) not in r.accept]
        if blocked:
            b = blocked[0]
            got = ctx.outcome(b.step)
            up = ctx.records.get(ctx._key(b.step))
            rec.skip_reason = (f"blocked: needs '{up.title if up else b.step}' to pass first "
                               f"(it was {got.value if got else 'not visited'})")
            rec.blocked_by = ctx._key(b.step)
            return None
        if step.applies is not None:
            ok, why = _safe_gate(step.applies, ctx)
            if not ok:
                rec.skip_reason = f"not applicable: {why}"
                return None
        if step.when is not None:
            ok, why = _safe_gate(step.when, ctx)
            rec.selected_because = why
            if not ok:
                # unusable evidence is a gap in what could be checked, not a check that was not needed
                # a gate may also decline a check on purpose (for safety) while its question stays open: that is
                # a gap too, never "not needed" (freeze re-review: the pam_faillock skip read as full coverage)
                gap = why.startswith(("the evidence this decision needs", NOT_RUN_ON_PURPOSE))
                rec.skip_reason = f"not applicable: {why}" if gap else f"not needed: {why}"
                return None
        if step.needs_root and not self.is_root:
            rec.skip_reason = f"privilege: needs root ({self.privilege_hint})"
            return None
        if self.executed >= self.max_steps:
            self.stop_reason = f"step budget of {self.max_steps} checks used up"
            rec.skip_reason = f"stopped: {self.stop_reason}"
            return None
        if self.clock() - self.start > self.max_seconds:
            self.stop_reason = f"time budget of {self.max_seconds:.0f} s used up"
            rec.skip_reason = f"stopped: {self.stop_reason}"
            return None
        params, why = _resolve_params(step, ctx)
        if params is None:
            rec.skip_reason = f"blocked: {why}"
            return None
        self.executed += 1
        t0 = self.clock()
        runner = self.runner
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
            self.cancelled = True
            self.stop_reason = "cancelled by the operator"
            rec.skip_reason = f"stopped: {self.stop_reason}"
            return None
        rec.seconds = round(self.clock() - t0, 3)
        rec.collected_at = _utc()
        rec.source = self.source
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
                self.stop_reason = why_stop
        if step.stop_subject is not None:
            try:
                return step.stop_subject(ctx)
            except (TypeError, ValueError, AttributeError, KeyError, OverflowError, IndexError):
                return None
        return None


def _subjects(item: ForEach, ctx: Context) -> Tuple[List[Tuple[str, Dict[str, Any]]], Dict[str, Any]]:
    """The subjects of a template, from an earlier step's ESTABLISHED list fact: validated, de-duplicated, sorted,
    cut to the instance budget. Returns (subjects, enumeration record)."""

    from ipa_diagnose.resolution import types as T

    src_step = item.source.rpartition(".")[0]
    enum: Dict[str, Any] = {"source": item.source, "status": "", "subjects": [], "dropped": [], "rejected": [],
                            "reason": "", "budget": item.max_instances}
    outcome = ctx.outcome(src_step)
    if outcome is None or outcome == Outcome.SKIPPED:
        enum.update(status="NOT_ASKED", reason="the step that lists the subjects did not run")
        return [], enum
    raw = ctx.fact(item.source)
    if outcome not in (Outcome.PASS, Outcome.WARN) or not isinstance(raw, list):
        enum.update(status="FAILED", reason="the list of subjects could not be established")
        return [], enum
    good: Dict[str, Dict[str, Any]] = {}
    for entry in raw[:1000]:
        key = entry.get("subject") if isinstance(entry, dict) else entry
        valid = T.validate(item.subject_type, key)
        if valid is None:
            enum["rejected"].append(sanitize_text(key, 120) if isinstance(key, str) else "(not a name)")
            continue
        if valid not in good:
            good[valid] = dict(entry) if isinstance(entry, dict) else {}
            good[valid]["subject"] = valid
    ordered = sorted(good)
    kept, dropped = ordered[:item.max_instances], ordered[item.max_instances:]
    enum["subjects"], enum["dropped"] = kept, dropped
    reasons = []
    if dropped:
        reasons.append(f"{len(dropped)} subject(s) not investigated: the budget is {item.max_instances}")
    if enum["rejected"]:
        reasons.append(f"{len(enum['rejected'])} listed subject(s) have a name that does not validate")
    if item.complete_fact is not None and ctx.fact(item.complete_fact) is not True:
        reasons.append("the source did not establish that it read the whole list")
    enum["status"] = "PARTIAL" if reasons else "COMPLETE"
    enum["reason"] = "; ".join(reasons)
    return [(k, good[k]) for k in kept], enum


def run_plan(plan: Sequence[PlanItem], runner: Any, inputs: Dict[str, Any], *, is_root: bool,
             registry: Dict[str, Any], max_seconds: float = MAX_WALL_SECONDS, max_steps: int = MAX_STEPS,
             clock: Callable[[], float] = time.monotonic,
             privilege_hint: str = "run ipa-diagnose client as root") -> Tuple[Trace, Context]:
    validate_plan(plan, registry)
    max_steps = min(max_steps, HARD_MAX_STEPS)
    ctx = Context(inputs, is_root)
    run = _Run(runner, registry, max_seconds, max_steps, clock, is_root, privilege_hint)
    started_at = _utc()
    runs_before = getattr(runner, "runs", 0)
    records: List[Record] = []
    enumerations: Dict[str, Dict[str, Any]] = {}

    for item in plan:
        if isinstance(item, ForEach):
            if run.stop_reason:
                subjects, enum = [], {"source": item.source, "status": "NOT_ASKED", "subjects": [], "dropped": [],
                                      "rejected": [], "reason": f"stopped: {run.stop_reason}",
                                      "budget": item.max_instances}
            else:
                subjects, enum = _subjects(item, ctx)
            local = frozenset(s.step_id for s in item.steps)
            unfinished: List[str] = []
            for subject, subj_item in subjects:
                view = SubjectContext(ctx, local, subject, subj_item)
                subject_stop = ""
                subject_start = clock()
                for step in item.steps:
                    spec = registry[step.check]
                    rec = Record(f"{step.step_id}@{subject}", step.capability, step.check, step.title, step.why,
                                 Outcome.SKIPPED, side_effects=spec.side_effects, privilege=spec.privilege,
                                 subject=subject, template=item.template_id, base_step=step.step_id)
                    records.append(rec)
                    ctx.records[rec.step_id] = rec
                    if not subject_stop and item.subject_seconds is not None \
                            and clock() - subject_start > item.subject_seconds:
                        subject_stop = f"its time slice of {item.subject_seconds:.0f} s is used up"
                        if subject not in unfinished:
                            unfinished.append(subject)
                        rec.skip_reason = f"stopped: {subject_stop} (this subject only)"
                        continue
                    if subject_stop:
                        rec.skip_reason = (f"stopped: {subject_stop} (this subject only)" if subject in unfinished
                                           else f"not needed: stopped for this subject: {subject_stop}")
                        continue
                    why = run.visit(step, rec, view)
                    if why:
                        subject_stop = sanitize_text(why, 300)
                    if rec.skip_reason.startswith("stopped:") and subject not in unfinished:
                        unfinished.append(subject)
            if unfinished:
                enum["status"] = "PARTIAL"
                enum["unfinished"] = unfinished
                enum["reason"] = "; ".join(x for x in (enum["reason"], "the run stopped before "
                                                       f"{len(unfinished)} subject(s) were fully investigated") if x)
            enumerations[item.template_id] = enum
            continue
        step = item
        spec = registry[step.check]
        rec = Record(step.step_id, step.capability, step.check, step.title, step.why, Outcome.SKIPPED,
                     side_effects=spec.side_effects, privilege=spec.privilege)
        records.append(rec)
        ctx.records[step.step_id] = rec
        run.visit(step, rec, ctx)
    stop_reason = run.stop_reason or "every relevant check in the plan was visited"
    bounds = {"max_steps": max_steps, "max_depth": MAX_DEPTH, "max_fanout": MAX_FANOUT,
              "max_wall_seconds": max_seconds, "max_retries": MAX_RETRIES,
              "per_check_timeout": "declared per check (CheckSpec.timeout)"}
    if enumerations:
        bounds.update(max_instances_per_template=MAX_INSTANCES, hard_max_steps=HARD_MAX_STEPS)
    trace = Trace(records, stop_reason, started_at, clock() - run.start, bounds,
                  getattr(runner, "runs", 0) - runs_before, sum(1 for r in records if r.reused), run.cancelled,
                  enumerations)
    return trace, ctx
