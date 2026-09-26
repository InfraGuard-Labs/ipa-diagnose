"""Load and strictly validate the compiled procedure catalogue (``procedures.json``).

The catalogue is authored as YAML (``knowledge/procedures/*.yaml``) and compiled
to JSON at build time by ``scripts/compile_knowledge.py``; the runtime needs no
YAML library and never evaluates anything from the data. Validation fails
closed: an invalid catalogue yields **no procedures at all** (the tool then
behaves exactly like v0.1.3) and the error is reported, never a partial catalogue.

Owner decision O-10 is enforced here, not by convention: a procedure may only
claim ``BUILT_IN_VERIFIED`` if it has an authoritative source, version
constraints, regression tests, an independent review record, and - if any step
changes state (risk MEDIUM or higher) - a live-lab verification record.
"""

from __future__ import annotations

import json
import re
from importlib import resources
from typing import Any, Dict, List, Optional, Tuple

from ipa_diagnose.resolution import types as T
from ipa_diagnose.resolution.checks import REGISTRY

RISKS = ["READ_ONLY", "LOW", "MEDIUM", "HIGH"]
RISK_RANK = {r: i for i, r in enumerate(RISKS)}
# What a step changes -> the minimum risk it may be labelled with.
CHANGES_MIN_RISK = {
    "file-permission": "LOW",
    "certmonger-request": "LOW",
    "service-start": "MEDIUM",
    "service-restart": "MEDIUM",
    "time-resync": "MEDIUM",
}
TIERS = ("BUILT_IN_VERIFIED", "LIVE_VERIFIED", "FIXTURE_ONLY")
AUTHORITATIVE_SOURCES = ("upstream-code", "upstream-docs", "vendor-docs")
RUN_ON = ("local",)
OPS = ("eq", "ne", "in", "not_in", "lt", "le", "gt", "ge", "abs_lt", "abs_ge", "is_true", "is_false", "is_empty")
CONFIDENCE = ("HIGH", "MEDIUM")
_ARG_LITERAL_RE = re.compile(r"^[A-Za-z0-9@._/=:+%-]{1,128}$")
# Programs a CONFIRM FIRST command may use: read-only inspection only.
CONFIRM_PROGRAMS = {"stat": None, "readlink": {"-f"}}
# Programs a fix step or rollback may run. Anything else (even well-formed) makes the catalogue invalid.
FIX_PROGRAMS = frozenset({"systemctl", "chmod", "chown", "chgrp", "chronyc", "getcert"})
_ID_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,80}$")
_TEMPLATE_RE = re.compile(r"\{(bind|item|ref)\.([A-Za-z0-9_]+)(?:\.([A-Za-z0-9_]+))?\}")


class KnowledgeError(ValueError):
    pass


def _fail(pid: str, msg: str) -> None:
    raise KnowledgeError(f"{pid}: {msg}")


def _only(pid: str, obj: Any, where: str, allowed: set, required: set = frozenset()) -> None:
    if not isinstance(obj, dict):
        _fail(pid, f"{where} must be an object")
    extra = set(obj) - allowed
    if extra:
        _fail(pid, f"{where}: unknown field(s) {sorted(extra)}")
    missing = set(required) - set(obj)
    if missing:
        _fail(pid, f"{where}: missing field(s) {sorted(missing)}")


def _check_text(pid: str, text: Any, where: str, ctx: "_Ctx") -> None:
    if not isinstance(text, str) or not text.strip():
        _fail(pid, f"{where} must be non-empty text")
    for kind, name, field in _TEMPLATE_RE.findall(text):
        ctx.check_ref(pid, {kind: name, **({"field": field} if field else {})}, where)
    stripped = _TEMPLATE_RE.sub("", text)
    if "{" in stripped or "}" in stripped:
        _fail(pid, f"{where}: only {{bind.x}}, {{item.x}} and {{ref.id.field}} placeholders are allowed")


class _Ctx:
    def __init__(self, pid: str, bindings: Dict[str, Any], checks: Dict[str, Any]):
        self.pid = pid
        self.bindings = bindings
        self.checks = checks
        self.item: Optional[str] = None

    def check_ref(self, pid: str, ref: Any, where: str) -> None:
        if not isinstance(ref, dict) or len(set(ref) & {"bind", "item", "ref"}) != 1:
            _fail(pid, f"{where}: a value reference needs exactly one of bind/item/ref")
        if "bind" in ref:
            if ref["bind"] not in self.bindings or self.bindings[ref["bind"]].get("type") == "list":
                _fail(pid, f"{where}: unknown scalar binding {ref['bind']!r}")
        elif "item" in ref:
            if self.item is None:
                _fail(pid, f"{where}: item reference outside for_each")
            fields = self.bindings[self.item].get("item", {})
            if ref["item"] not in fields:
                _fail(pid, f"{where}: unknown item field {ref['item']!r}")
        else:
            if ref["ref"] not in self.checks:
                _fail(pid, f"{where}: unknown check reference {ref['ref']!r}")
            if not ref.get("field"):
                _fail(pid, f"{where}: a check reference needs a field")


def _check_value(pid: str, v: Any, where: str, ctx: _Ctx) -> None:
    if isinstance(v, dict):
        allowed = {"bind", "item", "ref", "field", "type"}
        if set(v) - allowed:
            _fail(pid, f"{where}: unknown value fields {sorted(set(v) - allowed)}")
        ctx.check_ref(pid, v, where)
    elif isinstance(v, str):
        # Guard against string expressions sneaking in where a predicate belongs.
        if any(tok in v for tok in (" and ", " or ", "==", "!=", ">=", "<=", "now+", "(")):
            _fail(pid, f"{where}: expressions are not allowed in knowledge ({v!r})")
    elif not isinstance(v, (int, float, bool, list)) and v is not None:
        _fail(pid, f"{where}: unsupported value type")


def _check_pred(pid: str, p: Any, where: str, ctx: _Ctx) -> None:
    if isinstance(p, str):
        _fail(pid, f"{where}: predicates must be structured, not strings")
    if not isinstance(p, dict):
        _fail(pid, f"{where}: predicate must be an object")
    if "all" in p or "any" in p:
        key = "all" if "all" in p else "any"
        _only(pid, p, where, {key})
        if not isinstance(p[key], list) or not p[key]:
            _fail(pid, f"{where}.{key} must be a non-empty list")
        for i, sub in enumerate(p[key]):
            _check_pred(pid, sub, f"{where}.{key}[{i}]", ctx)
        return
    if "not" in p:
        _only(pid, p, where, {"not"})
        _check_pred(pid, p["not"], f"{where}.not", ctx)
        return
    _only(pid, p, where, {"left", "op", "right"}, {"left", "op"})
    if p["op"] not in OPS:
        _fail(pid, f"{where}: unknown operator {p['op']!r}")
    _check_value(pid, p["left"], f"{where}.left", ctx)
    if p["op"] not in ("is_true", "is_false", "is_empty"):
        if "right" not in p:
            _fail(pid, f"{where}: operator {p['op']} needs 'right'")
        _check_value(pid, p["right"], f"{where}.right", ctx)


def _check_argv(pid: str, argv: Any, where: str, ctx: _Ctx) -> None:
    if not isinstance(argv, list) or not argv:
        _fail(pid, f"{where}: command must be a non-empty argv list")
    if not isinstance(argv[0], str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", argv[0]):
        _fail(pid, f"{where}: argv[0] must be a literal program name")
    for i, a in enumerate(argv):
        if isinstance(a, str):
            if not _ARG_LITERAL_RE.fullmatch(a):
                _fail(pid, f"{where}[{i}]: literal argument contains characters that are not allowed: {a!r}")
        elif isinstance(a, dict):
            if "type" not in a or a["type"] not in T.VALIDATORS:
                _fail(pid, f"{where}[{i}]: a placeholder argument must declare a known type")
            _check_value(pid, a, f"{where}[{i}]", ctx)
        else:
            _fail(pid, f"{where}[{i}]: unsupported argument")


def _max_risk(proc: Dict[str, Any]) -> str:
    risks = [s["risk"] for s in proc.get("steps", [])] or ["READ_ONLY"]
    return max(risks, key=lambda r: RISK_RANK[r])


_URL_RE = re.compile(r"https://[A-Za-z0-9.-]+/[^\s]{1,400}")
_EVIDENCE_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]{5,}(/job/[0-9]+)?")
_VERSION_RE = re.compile(r"[0-9]{1,3}(\.[0-9]{1,4}){1,3}")
_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9 ._-]{1,60}")
_DATE_RE = re.compile(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]")
_TEST_RE = re.compile(r"tests/[A-Za-z0-9_/]+\.py")


def _validate_provenance(pid: str, proc: Dict[str, Any]) -> None:
    prov = proc["provenance"]
    _only(pid, prov, "provenance", {"tier", "sources", "verified_on", "reviews", "tests"}, {"tier", "sources", "tests"})
    tier = prov["tier"]
    if tier not in TIERS:
        _fail(pid, f"unknown tier {tier!r}")
    sources = prov.get("sources") or []
    for s in sources:
        _only(pid, s, "provenance.sources[]", {"kind", "ref", "title"}, {"kind", "ref"})
        if not isinstance(s["ref"], str) or not _URL_RE.fullmatch(s["ref"]):
            _fail(pid, "provenance.sources[].ref must be an https URL")
    live = [v for v in prov.get("verified_on") or [] if isinstance(v, dict) and v.get("tier") == "LIVE" and v.get("evidence")]
    for v in prov.get("verified_on") or []:
        _only(pid, v, "provenance.verified_on[]", {"freeipa", "os", "tier", "evidence", "date"}, {"freeipa", "os", "tier", "evidence"})
        if not (isinstance(v["freeipa"], str) and _VERSION_RE.fullmatch(v["freeipa"])):
            _fail(pid, "provenance.verified_on[].freeipa must be a FreeIPA version")
        if not (isinstance(v["os"], str) and _NAME_RE.fullmatch(v["os"])):
            _fail(pid, "provenance.verified_on[].os must name the OS")
        if v["tier"] == "LIVE" and not (isinstance(v["evidence"], str) and _EVIDENCE_RE.fullmatch(v["evidence"])):
            _fail(pid, "a LIVE verification record needs evidence: the URL of the CI run that applied and verified it")
        if "date" in v and not (isinstance(v["date"], str) and _DATE_RE.fullmatch(v["date"])):
            _fail(pid, "provenance.verified_on[].date must be YYYY-MM-DD")
    for r in prov.get("reviews") or []:
        _only(pid, r, "provenance.reviews[]", {"by", "date", "scope", "independent"}, {"by", "date", "scope", "independent"})
        if not (isinstance(r["by"], str) and r["by"].strip() and isinstance(r["scope"], str) and r["scope"].strip()
                and isinstance(r["date"], str) and _DATE_RE.fullmatch(r["date"]) and isinstance(r["independent"], bool)):
            _fail(pid, "provenance.reviews[] needs who (by), what (scope), a YYYY-MM-DD date and independent: true/false")
    if not prov.get("tests") or not all(isinstance(t, str) and _TEST_RE.fullmatch(t) for t in prov["tests"]):
        _fail(pid, "provenance.tests must list the regression test files (tests/...py)")
    if tier in ("BUILT_IN_VERIFIED", "LIVE_VERIFIED") and not live:
        _fail(pid, f"{tier} requires a live-lab verification record (verified_on with tier LIVE and evidence)")
    if tier == "BUILT_IN_VERIFIED":
        if not any(s.get("kind") in AUTHORITATIVE_SOURCES for s in sources):
            _fail(pid, "BUILT_IN_VERIFIED requires an authoritative source (upstream code/docs or vendor docs)")
        if not proc.get("applies_to", {}).get("freeipa_min"):
            _fail(pid, "BUILT_IN_VERIFIED requires a version constraint (applies_to.freeipa_min)")
        if not any(r.get("independent") is True for r in prov.get("reviews") or []):
            _fail(pid, "BUILT_IN_VERIFIED requires an independent review record")


def _validate_procedure(proc: Dict[str, Any]) -> None:
    pid = proc.get("id", "<no id>")
    if not isinstance(pid, str) or not _ID_RE.fullmatch(pid):
        _fail(str(pid), "invalid id")
    if proc.get("kind") == "no_procedure":
        _only(pid, proc, "no_procedure", {"kind", "id", "resolves", "reason", "reference", "provenance"},
              {"kind", "id", "resolves", "reason"})
        _only(pid, proc["resolves"], "resolves", {"diagnosis", "variant"}, {"diagnosis"})
        if not isinstance(proc["reason"], str) or not proc["reason"].strip():
            _fail(pid, "reason must be text")
        return
    _only(
        pid, proc, "procedure",
        {"kind", "id", "title", "resolves", "min_confidence", "bindings", "applies_to", "provenance", "investigate",
         "withhold_if", "prerequisites", "confirm_first", "steps", "what_changes", "rollback", "verify", "impact_note",
         "limitations"},
        {"kind", "id", "title", "resolves", "min_confidence", "bindings", "applies_to", "provenance", "steps",
         "what_changes", "rollback", "verify"},
    )
    if proc["kind"] != "procedure":
        _fail(pid, "kind must be procedure or no_procedure")
    _only(pid, proc["resolves"], "resolves", {"diagnosis", "variant"}, {"diagnosis"})
    if proc["min_confidence"] not in CONFIDENCE:
        _fail(pid, "min_confidence must be HIGH or MEDIUM")
    bindings = proc["bindings"]
    if not isinstance(bindings, dict):
        _fail(pid, "bindings must be an object")
    for name, spec in bindings.items():
        _only(pid, spec, f"bindings.{name}", {"type", "item"}, {"type"})
        if spec["type"] == "list":
            if not isinstance(spec.get("item"), dict) or not spec["item"]:
                _fail(pid, f"bindings.{name}: list bindings need item field types")
            for f, t in spec["item"].items():
                if t not in T.VALIDATORS and t != "any_text":
                    _fail(pid, f"bindings.{name}.item.{f}: unknown type {t!r}")
        elif spec["type"] not in T.VALIDATORS:
            _fail(pid, f"bindings.{name}: unknown type {spec['type']!r}")
    _only(pid, proc["applies_to"], "applies_to", {"freeipa_min", "freeipa_below", "roles"}, {"roles"})
    for k in ("freeipa_min", "freeipa_below"):
        v = proc["applies_to"].get(k)
        if v is not None and not (isinstance(v, str) and _VERSION_RE.fullmatch(v) and int(v.split(".")[0]) >= 4):
            _fail(pid, f"applies_to.{k} must be a FreeIPA version (4.x or later)")
    if proc["applies_to"]["roles"] != ["ipa-server"]:
        _fail(pid, "applies_to.roles: only ipa-server is supported in this version")
    _validate_provenance(pid, proc)

    checks = {}
    ctx = _Ctx(pid, bindings, checks)
    for inv in proc.get("investigate", []):
        _only(pid, inv, "investigate[]", {"id", "check", "params", "label", "for_each"}, {"id", "check", "params", "label"})
        spec = REGISTRY.get(inv["check"])
        if spec is None:
            _fail(pid, f"investigate {inv['id']}: unknown check {inv['check']!r}")
        if set(inv["params"]) != set(spec.params):
            _fail(pid, f"investigate {inv['id']}: parameters must be exactly {sorted(spec.params)}")
        ctx.item = inv.get("for_each")
        if ctx.item is not None and bindings.get(ctx.item, {}).get("type") != "list":
            _fail(pid, f"investigate {inv['id']}: for_each must name a list binding")
        for pname, v in inv["params"].items():
            _check_value(pid, v, f"investigate {inv['id']}.{pname}", ctx)
        checks[inv["id"]] = inv
        ctx.item = None
    for i, w in enumerate(proc.get("withhold_if", [])):
        _only(pid, w, "withhold_if[]", {"when", "reason", "for_each"}, {"when", "reason"})
        ctx.item = w.get("for_each")
        _check_pred(pid, w["when"], f"withhold_if[{i}]", ctx)
        _check_text(pid, w["reason"], f"withhold_if[{i}].reason", ctx)
        ctx.item = None
    for i, pr in enumerate(proc.get("prerequisites", [])):
        _only(pid, pr, "prerequisites[]", {"id", "text", "when", "kind"}, {"id", "text"})
        kind = pr.get("kind", "check")
        if kind not in ("check", "confirm_by_admin"):
            _fail(pid, "prerequisite kind must be check or confirm_by_admin")
        if kind == "check":
            if "when" not in pr:
                _fail(pid, f"prerequisite {pr['id']} needs 'when'")
            _check_pred(pid, pr["when"], f"prerequisites[{i}]", ctx)
        _check_text(pid, pr["text"], f"prerequisites[{i}].text", ctx)
    for j, c in enumerate(proc.get("confirm_first", [])):
        _only(pid, c, "confirm_first[]", {"text", "command", "expect", "for_each"}, {"text", "command", "expect"})
        ctx.item = c.get("for_each")
        _check_argv(pid, c["command"], f"confirm_first[{j}].command", ctx)
        prog = c["command"][0]
        if prog not in CONFIRM_PROGRAMS:
            _fail(pid, f"confirm_first[{j}]: {prog!r} is not a read-only inspection program")
        flags = [a for a in c["command"][1:] if isinstance(a, str) and a.startswith("-")]
        if CONFIRM_PROGRAMS[prog] is not None and not set(flags) <= CONFIRM_PROGRAMS[prog]:
            _fail(pid, f"confirm_first[{j}]: option not allowed for {prog}")
        _check_text(pid, c["text"], f"confirm_first[{j}].text", ctx)
        _check_text(pid, c["expect"], f"confirm_first[{j}].expect", ctx)
        ctx.item = None
    if not proc["steps"]:
        _fail(pid, "a procedure needs at least one step")
    for s in proc["steps"]:
        _only(pid, s, "steps[]", {"id", "text", "run_on", "command", "risk", "changes", "expected", "for_each", "only_if"},
              {"id", "text", "run_on", "command", "risk", "changes", "expected"})
        if s["run_on"] not in RUN_ON:
            _fail(pid, f"step {s['id']}: run_on must be one of {RUN_ON}")
        if s["risk"] not in RISKS or s["risk"] == "READ_ONLY":
            _fail(pid, f"step {s['id']}: a fix step must be LOW, MEDIUM or HIGH")
        if not s["changes"]:
            _fail(pid, f"step {s['id']}: changes must be declared")
        for c in s["changes"]:
            if c not in CHANGES_MIN_RISK:
                _fail(pid, f"step {s['id']}: unknown change {c!r}")
            if RISK_RANK[s["risk"]] < RISK_RANK[CHANGES_MIN_RISK[c]]:
                _fail(pid, f"step {s['id']}: risk {s['risk']} is lower than required for {c!r}")
        ctx.item = s.get("for_each")
        _check_argv(pid, s["command"], f"step {s['id']}.command", ctx)
        if s["command"][0] not in FIX_PROGRAMS:
            _fail(pid, f"step {s['id']}: {s['command'][0]!r} is not an allowed fix program")
        if "only_if" in s:
            _check_pred(pid, s["only_if"], f"step {s['id']}.only_if", ctx)
        _check_text(pid, s["text"], f"step {s['id']}.text", ctx)
        _check_text(pid, s["expected"], f"step {s['id']}.expected", ctx)
        ctx.item = None
    for key in ("what_changes", "rollback"):
        for j, entry in enumerate(proc[key]):
            _only(pid, entry, f"{key}[]", {"text", "command", "for_each", "only_if"}, {"text"})
            ctx.item = entry.get("for_each")
            _check_text(pid, entry["text"], f"{key}[{j}].text", ctx)
            if "command" in entry:
                _check_argv(pid, entry["command"], f"{key}[{j}].command", ctx)
                if entry["command"][0] not in FIX_PROGRAMS:
                    _fail(pid, f"{key}[{j}]: {entry['command'][0]!r} is not an allowed fix program")
            if "only_if" in entry:
                _check_pred(pid, entry["only_if"], f"{key}[{j}].only_if", ctx)
            ctx.item = None
    if not proc["verify"]:
        _fail(pid, "verify criteria are required")
    for j, v in enumerate(proc["verify"]):
        _only(pid, v, "verify[]", {"text", "check", "params", "when", "for_each"}, {"text", "check", "params", "when"})
        spec = REGISTRY.get(v["check"])
        if spec is None or set(v["params"]) != set(spec.params):
            _fail(pid, f"verify[{j}]: unknown check or wrong parameters")
        ctx.item = v.get("for_each")
        vctx_checks = dict(checks)
        vctx_checks["this"] = v
        ctx.checks = vctx_checks
        for pname, val in v["params"].items():
            _check_value(pid, val, f"verify[{j}].{pname}", ctx)
        _check_pred(pid, v["when"], f"verify[{j}].when", ctx)
        _check_text(pid, v["text"], f"verify[{j}].text", ctx)
        ctx.checks = checks
        ctx.item = None


def validate_catalogue(data: Any) -> List[Dict[str, Any]]:
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("procedures"), list):
        raise KnowledgeError("catalogue: expected {schema: 1, procedures: [...]}")
    seen, targets = set(), set()
    for proc in data["procedures"]:
        _validate_procedure(proc)
        if proc["id"] in seen:
            raise KnowledgeError(f"duplicate id {proc['id']}")
        seen.add(proc["id"])
        target = (proc["resolves"]["diagnosis"], proc["resolves"].get("variant"))
        if target in targets:
            raise KnowledgeError(f"{proc['id']}: more than one entry for {target} (selection must be unambiguous)")
        targets.add(target)
    return data["procedures"]


_CACHE: Optional[Tuple[List[Dict[str, Any]], Optional[str]]] = None


def _no_duplicate_keys(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise KnowledgeError(f"duplicate key {k!r} in procedures.json")
        out[k] = v
    return out


def load_catalogue() -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """(procedures, error). On any error the catalogue is empty: fail closed."""

    global _CACHE
    if _CACHE is None:
        try:
            text = resources.files("ipa_diagnose.resolution").joinpath("procedures.json").read_text(encoding="utf-8")
            _CACHE = (validate_catalogue(json.loads(text, object_pairs_hook=_no_duplicate_keys)), None)
        except Exception as e:  # noqa: BLE001 - any malformed catalogue disables every fix, never the report
            _CACHE = ([], f"procedure catalogue rejected: {type(e).__name__}: {e}")
    return _CACHE


def reset_cache() -> None:
    global _CACHE
    _CACHE = None
