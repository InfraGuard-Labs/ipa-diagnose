"""Select, check and render a procedure for a diagnosis - or say why none is shown.

Order of gates (each one can only *withhold*, never force a procedure):

1. a procedure (or an explicit "no procedure") exists for this diagnosis + variant;
2. the diagnosis is DIAGNOSED with at least the procedure's ``min_confidence``;
3. every value the procedure needs from the diagnosis validates as its declared type;
4. applicability (FreeIPA version, server role) is established from collected facts;
5. the procedure's read-only checks ran; no contradicting evidence (``withhold_if``);
6. every prerequisite is checked and met;
7. every command argument resolves to a validated value.

Only then is the procedure OFFERED. Everything that ran is kept as "checked for you".
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import re
import shlex
from typing import Any, Dict, List, Optional, Tuple

from ipa_diagnose.engine.model import ConfidenceLevel, Diagnosis, DiagnosisStatus
from ipa_diagnose.evidence.model import EnvironmentInfo
from ipa_diagnose.resolution import types as T
from ipa_diagnose.resolution.checks import OK, CheckResult, Runner
from ipa_diagnose.resolution.knowledge import RISK_RANK, load_catalogue
from ipa_diagnose.textsafe import sanitize_text

OFFERED, WITHHELD, NONE = "OFFERED", "WITHHELD", "NONE"
_CONF_RANK = {ConfidenceLevel.HIGH: 2, ConfidenceLevel.MEDIUM: 1}
_TEMPLATE_RE = re.compile(r"\{(bind|item|ref)\.([A-Za-z0-9_]+)(?:\.([A-Za-z0-9_]+))?\}")


class _Unknown(Exception):
    """A value could not be established (its check did not run or has no such field)."""

    def __init__(self, why: str):
        super().__init__(why)
        self.why = why


@dataclasses.dataclass
class Prerequisite:
    text: str
    state: str
    """met | unmet | unknown | confirm"""


@dataclasses.dataclass
class Step:
    step_id: str
    text: str
    argv: List[str]
    risk: str
    changes: List[str]
    expected: str
    run_on: str

    @property
    def command(self) -> str:
        return shlex.join(self.argv)  # quoted exactly as it must be typed


@dataclasses.dataclass
class Resolution:
    diagnosis_id: str
    status: str
    procedure_id: Optional[str] = None
    title: str = ""
    reasons: List[str] = dataclasses.field(default_factory=list)
    checks: List[Tuple[str, CheckResult]] = dataclasses.field(default_factory=list)
    prerequisites: List[Prerequisite] = dataclasses.field(default_factory=list)
    steps: List[Step] = dataclasses.field(default_factory=list)
    what_changes: List[str] = dataclasses.field(default_factory=list)
    rollback: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    risk: str = "READ_ONLY"
    verify: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    tier: str = ""
    definitive: bool = False
    verification_label: str = ""
    applies_to: str = ""
    limitations: str = ""
    reference: Optional[str] = None
    impact_note: str = ""
    replay: bool = False
    """True when check results came from a replay fixture (recorded), not from this host now."""
    confirm_first: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    """Read-only commands to run right before the fix, with the output they must show (what was checked)."""
    baseline: Optional[Dict[str, Any]] = None
    """For an OFFERED fix: the minimal record `verify` needs (see rebuild_verify)."""


def _version(text: Optional[str]) -> Optional[Tuple[int, ...]]:
    if not text:
        return None
    m = re.fullmatch(r"\s*(\d+)\.(\d+)(?:\.(\d+))?(?:-[A-Za-z0-9._+~]+)?\s*", str(text))
    if not m:
        return None
    return tuple(int(g) for g in m.groups() if g is not None)


class _Scope:
    def __init__(self, bindings: Dict[str, Any], checks: Dict[str, CheckResult], item: Optional[Dict[str, Any]] = None,
                 item_checks: Optional[Dict[str, CheckResult]] = None):
        self.bindings = bindings
        self.checks = checks
        self.item = item
        self.item_checks = item_checks if item_checks is not None else {}

    def value(self, v: Any) -> Any:
        if not isinstance(v, dict):
            return v
        if "bind" in v:
            return self.bindings[v["bind"]]
        if "item" in v:
            if self.item is None or v["item"] not in self.item:
                raise _Unknown("missing item value")
            return self.item[v["item"]]
        res = self.item_checks.get(v["ref"]) or self.checks.get(v["ref"])
        if res is None or res.status != OK:
            raise _Unknown(res.display if res is not None and res.display else f"{v['ref']} could not be checked")
        if v["field"] not in res.fields:
            raise _Unknown(f"{v['ref']} did not report {v['field']}")
        return res.fields[v["field"]]


def _compare(op: str, a: Any, b: Any) -> bool:
    try:
        if op == "eq":
            return a == b
        if op == "ne":
            return a != b
        if op == "in":
            return a in (b or [])
        if op == "not_in":
            return a not in (b or [])
        if op == "is_true":
            return a is True
        if op == "is_false":
            return a is False
        if op == "is_empty":
            return a in (None, "", [], {})
        if a is None or b is None:
            raise _Unknown("value missing")
        if any(isinstance(x, float) and not math.isfinite(x) for x in (a, b)):
            raise _Unknown("value is not a finite number")
        if op == "lt":
            return a < b
        if op == "le":
            return a <= b
        if op == "gt":
            return a > b
        if op == "ge":
            return a >= b
        if op == "abs_lt":
            return abs(a) < b
        if op == "abs_ge":
            return abs(a) >= b
    except TypeError:
        raise _Unknown("values are not comparable")
    raise _Unknown(f"unknown operator {op}")


def _pred(p: Dict[str, Any], scope: _Scope) -> bool:
    """True/False, or raises _Unknown when it cannot be established."""

    if "all" in p:
        return all(_pred(q, scope) for q in p["all"])
    if "any" in p:
        unknown = None
        for q in p["any"]:
            try:
                if _pred(q, scope):
                    return True
            except _Unknown as e:
                unknown = e
        if unknown is not None:
            raise unknown
        return False
    if "not" in p:
        return not _pred(p["not"], scope)
    return _compare(p["op"], scope.value(p["left"]), scope.value(p.get("right")))


def _text(template: str, scope: _Scope) -> str:
    def rep(m: "re.Match") -> str:
        kind, name, field = m.group(1), m.group(2), m.group(3)
        try:
            ref = {kind: name}
            if field:
                ref["field"] = field
            return sanitize_text(scope.value(ref), 160)
        except (_Unknown, KeyError):
            return "?"

    return _TEMPLATE_RE.sub(rep, template)


def _text_strict(template: str, scope: _Scope) -> str:
    """Like _text, but every value must be known and is not shortened (an expected command output the
    administrator compares against must be exact, never '?' or cut)."""

    def rep(m: "re.Match") -> str:
        kind, name, field = m.group(1), m.group(2), m.group(3)
        ref = {kind: name}
        if field:
            ref["field"] = field
        value = sanitize_text(scope.value(ref), 4096)
        if not value:
            raise _Unknown(f"no value for {m.group(0)}")
        return value

    return _TEMPLATE_RE.sub(rep, template)


def _argv(argv: List[Any], scope: _Scope) -> List[str]:
    out = []
    for a in argv:
        if isinstance(a, str):
            out.append(a)
            continue
        raw = scope.value(a)
        v = T.validate(a["type"], raw)
        if v is None:
            raise _Unknown(f"a value needed for the command did not validate as {a['type']}")
        out.append(v)
    return out


def _concrete(v: Any, scope: _Scope) -> Any:
    """Replace bind/item/ref references by their values (keep references to the verify check itself)."""

    if isinstance(v, dict) and v.get("ref") == "this":
        return v
    if isinstance(v, dict) and ({"bind", "item", "ref"} & set(v)):
        return scope.value(v)
    return v


def _concrete_pred(p: Dict[str, Any], scope: _Scope) -> Dict[str, Any]:
    if "all" in p or "any" in p:
        k = "all" if "all" in p else "any"
        return {k: [_concrete_pred(q, scope) for q in p[k]]}
    if "not" in p:
        return {"not": _concrete_pred(p["not"], scope)}
    out = {"left": _concrete(p["left"], scope), "op": p["op"]}
    if "right" in p:
        out["right"] = _concrete(p["right"], scope)
    return out


def _bindings(proc: Dict[str, Any], d: Diagnosis, reasons: List[str]) -> Optional[Dict[str, Any]]:
    out: Dict[str, Any] = {}
    for name, spec in proc["bindings"].items():
        raw = (d.bindings or {}).get(name)
        if spec["type"] == "list":
            items = []
            for it in raw if isinstance(raw, list) else []:
                if not isinstance(it, dict):
                    continue
                good = {}
                bad_field = None
                for f, t in spec["item"].items():
                    val = it.get(f)
                    good[f] = sanitize_text(val, 64) if t == "any_text" and isinstance(val, str) else T.validate(t, val)
                    if good[f] in (None, ""):
                        good, bad_field = None, f
                        break
                if good is None:
                    where = sanitize_text(it.get("path", "a reported item"), 120)
                    if isinstance(it.get("withhold_reason"), str):
                        reasons.append(f"Skipped {where}: {sanitize_text(it['withhold_reason'], 200)}.")
                    else:
                        # name the value that actually failed (truth review: "nobody" is the problem, not "root")
                        label = {"got": "current", "expected": "expected"}.get(bad_field, bad_field or "reported")
                        shown = sanitize_text(it.get(bad_field, "") if bad_field else "", 60)
                        why = ("is not one of the IPA service accounts" if spec["item"].get(bad_field) == "ipa_account"
                               else "is not a single value that can be used safely")
                        reasons.append(f"Skipped {where}: the {label} value" + (f" ({shown})" if shown else "") + f" {why}.")
                else:
                    items.append(good)
            out[name] = items
        else:
            v = T.validate(spec["type"], raw)
            if v is None:
                return None
            out[name] = v
    list_names = [n for n, sp in proc["bindings"].items() if sp["type"] == "list"]
    if list_names and not any(out[n] for n in list_names):
        return None
    return out


def _dedupe(items: List[Any], key) -> List[Any]:
    seen, out = set(), []
    for x in items:
        k = key(x)
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def _label(proc: Dict[str, Any], env: Optional[EnvironmentInfo]) -> Tuple[bool, str]:
    prov = proc["provenance"]
    live = [v for v in prov.get("verified_on") or [] if v.get("tier") == "LIVE"]
    here = _version(env.freeipa_version) if env else None
    os_here = f"{(env.distro or '').lower()}-{(env.distro_version or '').lower()}" if env else ""
    # exact: same FreeIPA version (major.minor.patch) and same OS release as the live record (round-9 review)
    matched = [
        v for v in live
        if here is not None and _version(v["freeipa"]) is not None and _version(v["freeipa"])[:3] == here[:3]
        and str(v["os"]).lower() == os_here
    ]
    where = ", ".join(f"FreeIPA {v['freeipa']} / {v['os']}" for v in live)
    if prov["tier"] == "BUILT_IN_VERIFIED" and matched:
        return True, f"Verified in a live lab on {where}; independently reviewed."
    if live and not matched:
        return False, f"Verified in a live lab on {where} only - not yet on this FreeIPA version/OS. Check each step before running it."
    if live:
        return False, (f"Verified in a live lab on {where} (the maintainer has not promoted it to built-in verified). "
                       "Check each step before running it.")
    return False, "Not yet verified on a live FreeIPA server (tested against recorded evidence only). Check each step before running it."


def resolve_diagnosis(d: Diagnosis, env: Optional[EnvironmentInfo], runner: Runner,
                      catalogue: Optional[List[Dict[str, Any]]] = None) -> Optional[Resolution]:
    key = getattr(d, "resolution_key", None)
    if not key:
        return None
    cat = catalogue if catalogue is not None else load_catalogue()[0]
    matches = [p for p in cat if p["resolves"]["diagnosis"] == key and p["resolves"].get("variant") == d.variant]
    if not matches:
        return None
    proc = sorted(matches, key=lambda p: p["id"])[0]
    if proc.get("kind") == "no_procedure":
        return Resolution(diagnosis_id=d.diagnosis_id, status=NONE, procedure_id=proc["id"],
                          reasons=[proc["reason"]], reference=proc.get("reference"))

    r = Resolution(diagnosis_id=d.diagnosis_id, status=WITHHELD, procedure_id=proc["id"], title=proc["title"],
                   tier=proc["provenance"]["tier"], limitations=proc.get("limitations", ""),
                   impact_note=proc.get("impact_note", ""), replay=bool(getattr(runner, "replay", False)))
    fmin = proc["applies_to"].get("freeipa_min")
    fbel = proc["applies_to"].get("freeipa_below")
    r.applies_to = ("FreeIPA server " + (f"{fmin} or later" if fmin else "") + (f", below {fbel}" if fbel else "")).strip()

    # 1b. a symptom gets no fix of its own: its cause is reported above and must be fixed first (for example
    # dirsrv stopped because its database disk is full - starting it again is not the fix; red-team round 4)
    if getattr(d.priority, "value", "") == "RELATED_SYMPTOM":
        causes = "; ".join(d.related_to_titles) or "another problem reported above"
        r.reasons.append(f"This is reported as a symptom of: {sanitize_text(causes, 200)}. Fix that first, then run "
                         "ipa-diagnose again.")
        return r
    # 2. confidence
    need = 2 if proc["min_confidence"] == "HIGH" else 1
    if d.status != DiagnosisStatus.DIAGNOSED or _CONF_RANK.get(d.confidence.level, 0) < need:
        r.reasons.append(f"The cause is not established with {proc['min_confidence'].lower()} confidence, so no fix is shown.")
        return r
    # 3. bindings
    bindings = _bindings(proc, d, r.reasons)
    if bindings is None:
        r.reasons.append("No reported item can be changed safely (see above)." if r.reasons
                         else "The evidence does not name values that can be used safely in a command.")
        return r
    # 4. applicability
    # "ipa-server" role = the freeipa-server package is installed (its version is what we read).
    here = _version(env.freeipa_version) if env else None
    if here is None:
        if r.replay:
            r.reasons.append("This recorded evidence does not include the FreeIPA version or the checks a fix needs, "
                             "so no fix can be confirmed from it.")
        else:
            r.reasons.append("Could not read the FreeIPA server version (rpm -q freeipa-server), so it is not "
                             "established that this procedure applies here.")
        return r
    if fmin and here < _version(fmin):
        r.reasons.append(f"This procedure applies to FreeIPA {fmin} or later; this server runs {env.freeipa_version}.")
        return r
    fbelow = proc["applies_to"].get("freeipa_below")
    if fbelow and here >= _version(fbelow):
        r.reasons.append(f"This procedure has not been established for FreeIPA {fbelow} or later "
                         f"(this server runs {env.freeipa_version}).")
        return r

    # 5. automatic read-only checks (lists: one entry per reported target, e.g. per file)
    lists: Dict[str, List[Dict[str, Any]]] = {n: list(bindings[n]) for n, sp in proc["bindings"].items() if sp["type"] == "list"}
    lchecks: Dict[str, List[Dict[str, CheckResult]]] = {n: [{} for _ in v] for n, v in lists.items()}
    global_checks: Dict[str, CheckResult] = {}
    base = _Scope(bindings, global_checks)

    def item_scopes(name: str) -> List[_Scope]:
        return [_Scope(bindings, global_checks, it, ic) for it, ic in zip(lists[name], lchecks[name])]

    for inv in proc.get("investigate", []):
        scopes_ = item_scopes(inv["for_each"]) if inv.get("for_each") else [base]
        for sc in scopes_:
            try:
                params = {k: sc.value(v) for k, v in inv["params"].items()}
            except _Unknown as e:
                r.reasons.append(f"Could not check {_text(inv['label'], sc)}: {e.why}")
                return r
            res = runner.run(inv["check"], params)
            (sc.item_checks if inv.get("for_each") else global_checks)[inv["id"]] = res
            r.checks.append((_text(inv["label"], sc), res))

    # 5b. Two reported items that reach the same real target (check field "target") must not disagree, whether or
    # not a later rule would drop one of them (round-9 review): a dropped contradicting finding still contradicts.
    for n, items in lists.items():
        by_target: Dict[Tuple[str, str], set] = {}
        for it, ic in zip(items, lchecks[n]):
            tgt = next((c.fields.get("target") for c in ic.values() if c.status == OK and c.fields.get("target")), None)
            if tgt:
                by_target.setdefault((n, str(tgt)), set()).add(json.dumps({k: v for k, v in it.items() if k != "path"}, sort_keys=True))
        clash = [t for (ln, t), vals in by_target.items() if len(vals) > 1]
        if clash:
            r.reasons.append(f"Two findings expect different values for the same file ({sanitize_text(clash[0], 160)}), "
                             "so ipa-diagnose cannot tell which one is right.")
            return r

    # 6. contradicting / changed evidence: withhold (or drop the one affected target)
    for w in proc.get("withhold_if", []):
        name = w.get("for_each")
        if name:
            keep, keep_checks = [], []
            for it, ic in zip(lists[name], lchecks[name]):
                sc = _Scope(bindings, global_checks, it, ic)
                try:
                    hit = _pred(w["when"], sc)
                    if hit:
                        r.reasons.append(_text(w["reason"], sc))
                except _Unknown as e:
                    r.reasons.append(f"Could not establish the current state of {sanitize_text(it.get('path', 'a target'), 120)}: {e.why}")
                    hit = True
                if not hit:
                    keep.append(it)
                    keep_checks.append(ic)
            lists[name], lchecks[name] = keep, keep_checks
        else:
            try:
                hit = _pred(w["when"], base)
            except _Unknown as e:
                r.reasons.append(f"Could not establish the current state: {e.why}")
                return r
            if hit:
                r.reasons.append(_text(w["reason"], base))
                return r
    if lists and not any(lists.values()):
        r.reasons.append("Nothing left to fix after checking the current state.")
        return r
    for n in lists:
        bindings[n] = lists[n]

    # 7. prerequisites
    unmet = False
    for pr in proc.get("prerequisites", []):
        text = _text(pr["text"], base)
        if pr.get("kind") == "confirm_by_admin":
            r.prerequisites.append(Prerequisite(text, "confirm"))
            continue
        try:
            ok = _pred(pr["when"], base)
            r.prerequisites.append(Prerequisite(text, "met" if ok else "unmet"))
            unmet = unmet or not ok
        except _Unknown as e:
            r.prerequisites.append(Prerequisite(f"{text} (could not check: {e.why})", "unknown"))
            unmet = True
    if unmet:
        r.reasons.append("A prerequisite is not met or could not be checked, so the fix is not shown.")
        return r

    # 8. steps, what changes, rollback, verify - every command argument validated by type
    def scopes(entry):
        return item_scopes(entry["for_each"]) if entry.get("for_each") else [base]

    try:
        for c in proc.get("confirm_first", []):
            for sc in scopes(c):
                r.confirm_first.append({"text": _text(c["text"], sc), "argv": _argv(c["command"], sc),
                                        "expect": _text_strict(c["expect"], sc)})
        r.confirm_first = _dedupe(r.confirm_first, lambda x: tuple(x["argv"]))
        for s in proc["steps"]:
            for sc in scopes(s):
                if "only_if" in s and not _pred(s["only_if"], sc):
                    continue
                r.steps.append(Step(s["id"], _text(s["text"], sc), _argv(s["command"], sc), s["risk"], list(s["changes"]),
                                    _text(s["expected"], sc), s["run_on"]))
        for key_name in ("what_changes", "rollback"):
            for entry in proc[key_name]:
                for sc in scopes(entry):
                    if "only_if" in entry and not _pred(entry["only_if"], sc):
                        continue
                    text = _text(entry["text"], sc)
                    if key_name == "what_changes":
                        r.what_changes.append(text)
                    else:
                        r.rollback.append({"text": text, "argv": _argv(entry["command"], sc) if "command" in entry else None})
        r.verify = _build_verify(proc, scopes)
    except _Unknown as e:
        r.steps, r.what_changes, r.rollback, r.verify, r.confirm_first = [], [], [], [], []
        r.reasons.append(f"A value needed for the fix could not be established safely: {e.why}")
        return r
    if not r.steps:
        r.reasons.append("No step applies to the current state.")
        return r
    # Two findings that reach the same target through different names must agree: the same step on the
    # same target with different arguments is contradictory evidence, so nothing is shown.
    seen: Dict[Tuple[str, str], List[str]] = {}
    for st in r.steps:
        k = (st.step_id, st.argv[-1])
        if k in seen and seen[k] != st.argv:
            r.steps, r.what_changes, r.rollback, r.verify, r.confirm_first = [], [], [], [], []
            r.reasons.append(f"Two findings expect different values for the same file ({sanitize_text(st.argv[-1], 160)}), "
                             "so ipa-diagnose cannot tell which one is right.")
            return r
        seen[k] = st.argv
    r.steps = _dedupe(r.steps, lambda s: (s.step_id, tuple(s.argv)))
    r.what_changes = _dedupe(r.what_changes, lambda x: x)
    r.rollback = _dedupe(r.rollback, lambda x: tuple(x["argv"]) if x["argv"] else x["text"])
    r.risk = max((s.risk for s in r.steps), key=lambda x: RISK_RANK[x])
    r.definitive, r.verification_label = _label(proc, env)
    # Minimal verify baseline: which procedure (and exact definition), the typed values it was filled with, and
    # a digest of the criteria they produced. `verify` rebuilds the criteria from the CURRENT catalogue and
    # FRESH read-only checks; it never runs criteria, commands or statuses read back from the saved report.
    r.baseline = {"procedure_id": proc["id"], "procedure_digest": procedure_digest(proc),
                  "bindings": json.loads(json.dumps(bindings)), "criteria_digest": criteria_digest(r.verify, d.diagnosis_id)}
    r.status = OFFERED
    return r


def _build_verify(proc: Dict[str, Any], scopes) -> List[Dict[str, Any]]:
    out = []
    for v in proc["verify"]:
        for sc in scopes(v):
            out.append({
                "text": _text(v["text"], sc), "check": v["check"],
                "params": {k: _concrete(val, sc) for k, val in v["params"].items()},
                "when": _concrete_pred(v["when"], sc),
            })
    return _dedupe(out, lambda x: json.dumps({k: x[k] for k in ("check", "params", "when")}, sort_keys=True))


def procedure_digest(proc: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(proc, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def criteria_digest(criteria: List[Dict[str, Any]], diagnosis_id: str = "") -> str:
    """Digest of what a fix's verification checks, bound to the diagnosis it was shown for. The rendered text is
    included because it names the concrete target (unit, file, certificate) even where the check parameters
    do not (e.g. a service check resolves the DS instance itself)."""

    core = [{k: c[k] for k in ("text", "check", "params", "when")} for c in criteria]
    return hashlib.sha256(json.dumps([diagnosis_id, core], sort_keys=True, ensure_ascii=True).encode()).hexdigest()


# outcomes of rebuild_verify besides success
REBUILD_UNKNOWN = "UNKNOWN"      # cannot rebuild: no such procedure, changed definition, invalid values, check failed
REBUILD_CHANGED = "CHANGED"      # rebuilt, but the fix now points at something else than when it was offered


def rebuild_verify(fix: Any, runner: Runner) -> Tuple[Optional[List[Dict[str, Any]]], str, str]:
    """Rebuild a fix's verification criteria from the CURRENT catalogue, the saved typed values and FRESH
    read-only checks: (criteria or None, "" / REBUILD_UNKNOWN / REBUILD_CHANGED, reason)."""

    try:
        if not isinstance(fix, dict):
            return None, REBUILD_UNKNOWN, "the saved fix record is malformed"
        catalogue, _ = load_catalogue()
        proc = next((p for p in catalogue if p.get("id") == fix.get("procedure_id") and p.get("kind") != "no_procedure"), None)
        if proc is None:
            return None, REBUILD_UNKNOWN, "this version of ipa-diagnose has no such fix procedure"
        if fix.get("procedure_digest") != procedure_digest(proc):
            return None, REBUILD_UNKNOWN, ("the fix procedure is not the one that was shown (ipa-diagnose or its "
                                           "procedure catalogue changed since)")
        saved = fix.get("bindings")
        reasons: List[str] = []
        bindings = _bindings(proc, _SavedValues(saved if isinstance(saved, dict) else {}), reasons)
        list_names = [n for n, sp in proc["bindings"].items() if sp["type"] == "list"]
        if bindings is None or reasons or any(len(bindings[n]) != len(saved.get(n) or []) for n in list_names):
            return None, REBUILD_UNKNOWN, "the values saved for the fix are not valid values of their type"
        lists = {n: list(bindings[n]) for n in list_names}
        lchecks: Dict[str, List[Dict[str, CheckResult]]] = {n: [{} for _ in v] for n, v in lists.items()}
        global_checks: Dict[str, CheckResult] = {}
        base = _Scope(bindings, global_checks)

        def item_scopes(name: str) -> List[_Scope]:
            return [_Scope(bindings, global_checks, it, ic) for it, ic in zip(lists[name], lchecks[name])]

        for inv in proc.get("investigate", []):
            for sc in item_scopes(inv["for_each"]) if inv.get("for_each") else [base]:
                params = {k: sc.value(v) for k, v in inv["params"].items()}
                (sc.item_checks if inv.get("for_each") else global_checks)[inv["id"]] = runner.run(inv["check"], params)
        criteria = _build_verify(proc, lambda e: item_scopes(e["for_each"]) if e.get("for_each") else [base])
    except _Unknown as e:
        return None, REBUILD_UNKNOWN, f"a fresh check needed to rebuild the fix's criteria failed: {e.why}"
    except Exception as e:  # noqa: BLE001 - a corrupt baseline must never crash verify or pass
        return None, REBUILD_UNKNOWN, f"the saved fix record could not be used ({type(e).__name__})"
    if criteria_digest(criteria, str(fix.get("diagnosis_id", ""))) != fix.get("criteria_digest"):
        return criteria, REBUILD_CHANGED, ("the fix's checks no longer match what was saved when the fix was shown: "
                                           "either its target changed (for example another file location or "
                                           "instance) or the saved diagnosis was modified")
    return criteria, "", ""


class _SavedValues:
    def __init__(self, bindings: Dict[str, Any]):
        self.bindings = bindings


def resolve_report(report, runner: Runner) -> Dict[str, Resolution]:
    """Attach resolutions to every diagnosis that has a procedure key. Never raises."""

    out: Dict[str, Resolution] = {}
    catalogue, error = load_catalogue()
    if error:
        report.collection_errors.append(sanitize_text(error, 300))
    for d in report.diagnoses:
        try:
            res = resolve_diagnosis(d, report.environment, runner, catalogue)
        except Exception as e:  # noqa: BLE001 - resolution must never break the diagnosis report
            res = Resolution(diagnosis_id=d.diagnosis_id, status=WITHHELD,
                             reasons=[f"Internal error while preparing the fix ({type(e).__name__}); nothing is shown."])
        if res is not None:
            out[d.diagnosis_id] = res
    report.resolutions = out
    return out


_VERIFY_OPS = {"eq", "ne", "in", "not_in", "lt", "le", "gt", "ge", "abs_lt", "abs_ge", "is_true", "is_false"}


def _refers_to_this(p: Any) -> bool:
    """A verify criterion must actually test the fresh check result (not only literals)."""

    if not isinstance(p, dict) or len(p) == 0:
        return False
    if set(p) in ({"all"}, {"any"}):
        subs = p.get("all") if "all" in p else p.get("any")
        return isinstance(subs, list) and bool(subs) and all(_refers_to_this(q) for q in subs)
    if set(p) == {"not"}:
        return _refers_to_this(p["not"])
    if not set(p) <= {"left", "op", "right"} or p.get("op") not in _VERIFY_OPS:
        return False
    left, right = p.get("left"), p.get("right")
    # left: the fresh check's field; right: a literal (never another reference, so x == x cannot pass).
    return (isinstance(left, dict) and set(left) == {"ref", "field"} and left["ref"] == "this"
            and isinstance(left["field"], str) and not isinstance(right, dict))


def evaluate_verify(criteria: List[Dict[str, Any]], runner: Runner) -> List[Tuple[str, Optional[bool], str]]:
    """Run stored verification criteria with FRESH read-only checks: (text, True/False/None, detail)."""

    results = []
    for c in criteria if isinstance(criteria, list) else []:
        try:
            if not isinstance(c, dict):
                raise _Unknown("malformed criterion")
            if not _refers_to_this(c.get("when")) or not isinstance(c.get("params", {}), dict):
                raise _Unknown("criterion is malformed or does not test the fresh check result")
            res = runner.run(str(c.get("check")), dict(c.get("params") or {}))
            if res.status != OK:
                raise _Unknown(res.display or "the check could not run")
            scope = _Scope({}, {"this": res})
            ok = _pred(c["when"], scope)
            results.append((sanitize_text(c.get("text", ""), 200), ok, res.display))
        except Exception as e:  # noqa: BLE001 - a corrupt state file must never crash verify or pass
            why = e.why if isinstance(e, _Unknown) else "malformed criterion"
            results.append((sanitize_text(c.get("text", "") if isinstance(c, dict) else "", 200), None, why))
    return results

