"""`ipa-diagnose client --verify`: did the client problems found last time clear? Fresh evidence only.

The saved state is a minimal, validated record (diagnosis codes, the symptom step each rests on, the typed values of
an offered fix). Nothing from it is executed or trusted as a result: every check runs again now, fix criteria are
rebuilt from the CURRENT procedure catalogue (Slice 1's rebuild_verify) and evaluated with fresh checks.

Outcomes per earlier diagnosis:
- RESOLVED            the symptom check passes now, the diagnosis is gone, and any fix criteria pass;
- STILL_PRESENT       the same diagnosis is found again;
- PARTIALLY_RESOLVED  the diagnosis is gone but a fix criterion still fails;
- CHANGED             the diagnosis is gone but another failure appeared in the same place;
- UNABLE_TO_VERIFY    the symptom check could not run or pass now, or a criterion could not be checked.
A check that fails to run is never counted as resolved.
"""

from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import re
from typing import Any, Dict, List, Optional

from ipa_diagnose.client.run import ClientResult
from ipa_diagnose.planner.core import Outcome

STATE_VERSION = 1
# symptom steps whose answer depends on --user / --service (their result for another name proves nothing)
_INPUT_DEPENDENT = ("id", "ipa", "nss", "pam", "cache")
_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,60}$")
_STEP_RE = re.compile(r"^[a-z][a-z0-9_.]{0,40}$")


class UnreadableState(Exception):
    pass


@dataclasses.dataclass
class VerifyItem:
    code: str
    title: str
    outcome: str
    detail: str


def state_path(replay: bool) -> pathlib.Path:
    from ipa_diagnose.verify import default_state_path

    base = default_state_path()
    return base.with_name("client_last.replay.json" if replay else "client_last.json")


def to_state(r: ClientResult) -> Dict[str, Any]:
    fixes = {}
    for code, res in r.resolutions.items():
        if code.startswith("_") or getattr(res, "status", "") != "OFFERED" or not res.baseline:
            continue
        fixes[code] = dict(res.baseline, diagnosis_id=f"client.{code}")
    return {"state_version": STATE_VERSION, "kind": "ipa-diagnose.client.state", "generated_at": r.generated_at,
            "mode": r.mode, "inputs": r.inputs, "host": r.environment.get("host"),
            "diagnoses": [{"code": d.code, "title": d.title, "capability": d.capability, "severity": d.severity,
                           "symptom_step": d.evidence[0] if d.evidence else None} for d in r.diagnoses],
            "fixes": fixes}


def save(path: pathlib.Path, r: ClientResult) -> None:
    """The same hardened write as the diagnosis baseline (verify.save_report): never through a symlink or into a
    directory another user owns; a per-process O_EXCL temporary file; fsync; atomic replace."""

    from ipa_diagnose.verify import _state_location_ok

    if not _state_location_ok(path):
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        data = json.dumps(to_state(r), indent=1).encode("utf-8")
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(str(tmp), str(path))
        finally:
            if tmp.exists():
                tmp.unlink()
    except OSError:
        pass  # a baseline that cannot be written only means --verify has nothing to compare with


def load(path: pathlib.Path) -> Optional[Dict[str, Any]]:
    from ipa_diagnose.verify import _state_location_ok

    if not path.exists() and not os.path.islink(path):
        return None
    if not _state_location_ok(path):
        raise UnreadableState("the saved result is in a location this user does not own, or behind a symlink")
    try:
        if path.stat().st_size > 1024 * 1024:
            raise UnreadableState("too large")
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, RecursionError, UnicodeDecodeError):
        raise UnreadableState("unreadable")
    if not isinstance(doc, dict) or doc.get("state_version") != STATE_VERSION or not isinstance(doc.get("diagnoses"),
                                                                                                 list):
        raise UnreadableState("not a client state record")
    diags = []
    for d in doc["diagnoses"][:100]:
        if not isinstance(d, dict) or not isinstance(d.get("code"), str) or not _CODE_RE.fullmatch(d["code"]):
            raise UnreadableState("malformed diagnosis record")
        step = d.get("symptom_step")
        if step is not None and not (isinstance(step, str) and _STEP_RE.fullmatch(step)):
            raise UnreadableState("malformed diagnosis record")
        diags.append({"code": d["code"], "title": str(d.get("title", d["code"]))[:300],
                      "capability": str(d.get("capability", ""))[:40], "symptom_step": step,
                      "severity": d.get("severity") if d.get("severity") in ("FAIL", "WARN") else "FAIL"})
    fixes = doc.get("fixes") if isinstance(doc.get("fixes"), dict) else {}
    inputs = doc.get("inputs") if isinstance(doc.get("inputs"), dict) else {}
    return {"generated_at": str(doc.get("generated_at", ""))[:40], "diagnoses": diags,
            "fixes": {k: v for k, v in list(fixes.items())[:20] if isinstance(k, str) and _CODE_RE.fullmatch(k)},
            "inputs": {k: inputs.get(k) if isinstance(inputs.get(k), str) else None for k in ("user", "service")}}


def compare(previous: Dict[str, Any], fresh: ClientResult, runner: Any) -> Dict[str, Any]:
    from ipa_diagnose.resolution.engine import evaluate_verify, rebuild_verify

    now_codes = {d.code: d for d in fresh.diagnoses}
    items: List[VerifyItem] = []
    changed_inputs = [k for k in ("user", "service") if (previous.get("inputs") or {}).get(k) != fresh.inputs.get(k)]
    for old in previous["diagnoses"]:
        code, title = old["code"], old["title"]
        if changed_inputs and (old["symptom_step"] or "").split(".")[0] in _INPUT_DEPENDENT:
            items.append(VerifyItem(code, title, "UNABLE_TO_VERIFY",
                                    "it was found for another " + " and ".join(changed_inputs) + " than this run asks "
                                    "about; run --verify with the same --user and --service"))
            continue
        if code in now_codes:
            items.append(VerifyItem(code, title, "STILL_PRESENT", "found again with fresh evidence"))
            continue
        step = fresh.trace.get(old["symptom_step"]) if old["symptom_step"] else None
        if step is None or step.outcome != Outcome.PASS:
            why = ("the check it rests on did not run now" if step is None or step.outcome == Outcome.SKIPPED
                   else f"the check it rests on is {step.outcome.value} now ({step.summary})")
            items.append(VerifyItem(code, title, "UNABLE_TO_VERIFY", why))
            continue
        same_place = [d for d in fresh.diagnoses if d.capability == old["capability"] and d.severity == "FAIL"]
        if same_place:
            items.append(VerifyItem(code, title, "CHANGED", "gone, but now: " + same_place[0].title))
            continue
        fix = previous["fixes"].get(code)
        if fix is not None:
            criteria, problem, why = rebuild_verify(fix, runner)
            if criteria is None or problem:
                items.append(VerifyItem(code, title, "UNABLE_TO_VERIFY", f"the fix's checks cannot be rebuilt: {why}"))
                continue
            results = evaluate_verify(criteria, runner)
            if any(ok is None for _t, ok, _d in results):
                bad = next(t for t, ok, _d in results if ok is None)
                items.append(VerifyItem(code, title, "UNABLE_TO_VERIFY", f"could not check: {bad}"))
                continue
            if not all(ok for _t, ok, _d in results):
                bad = next(t for t, ok, _d in results if not ok)
                items.append(VerifyItem(code, title, "PARTIALLY_RESOLVED", f"still failing: {bad}"))
                continue
        items.append(VerifyItem(code, title, "RESOLVED", f"'{step.title}' passes now"
                                + ("; the fix's checks pass" if fix is not None else "")))
    old_codes = {d["code"] for d in previous["diagnoses"]}
    new = [d for d in fresh.diagnoses if d.code not in old_codes and d.severity == "FAIL"]
    return {"previous_generated_at": previous["generated_at"], "items": items, "new_conditions": new}


def exit_code(result: Dict[str, Any], fresh_code: int) -> int:
    outs = {i.outcome for i in result["items"]}
    if outs & {"STILL_PRESENT", "PARTIALLY_RESOLVED"} or result["new_conditions"]:
        return 1
    if outs & {"UNABLE_TO_VERIFY", "CHANGED"}:
        return 4
    return fresh_code
