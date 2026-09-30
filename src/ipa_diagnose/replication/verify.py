"""`ipa-diagnose replication --verify`: is the replication incident found last time actually gone? Fresh evidence only.

"The command succeeded" is never "the incident is resolved". For each earlier finding:

- RESOLVED            not found again; for an agreement: it reports success for a session that ENDED AFTER the saved
                      result, with no update in progress; for a cause: the checks it rested on answer now and any fix
                      criteria pass; every agreement it explained is resolved too;
- PENDING             not failing any more, but no fresh successful session yet (or a transient state: busy, backoff,
                      no session): time-bounded (:data:`CONVERGENCE_WINDOW` from the first PENDING), with a next recheck
                      time; afterwards it becomes STILL_PRESENT or UNABLE_TO_VERIFY. PENDING never exits 0;
- STILL_PRESENT       found again with fresh evidence (or still failing after the window);
- CHANGED             gone, but another failure appeared on the same subject;
- PARTIALLY_RESOLVED  gone, but a fix criterion still fails;
- UNABLE_TO_VERIFY    what it rests on could not be observed now (a collector failed, the agreement or the reverse
                      direction is not visible, another host or scope) - never counted as resolved.

Exact RUV equality is NOT required (active multi-master topologies keep changing); a fresh successful session after
the baseline is. A direction that cannot be observed is never reported as verified.
"""

from __future__ import annotations

import dataclasses
import datetime
import json
import os
import pathlib
import re
from typing import Any, Dict, List, Optional

from ipa_diagnose.planner.core import Outcome
from ipa_diagnose.replication import status as S
from ipa_diagnose.replication.run import ReplicationResult

STATE_VERSION = 1
CONVERGENCE_WINDOW = 600  # seconds from the first PENDING observation
RECHECK = 60
_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,60}$")
_SUBJECT_RE = re.compile(r"^[a-z]{2,12}:[A-Za-z0-9 .:>|/@_-]{1,300}$")
_STEP_RE = re.compile(r"^[a-z][a-z0-9_.]{0,40}(?:@[a-z]{2,8}:[a-z0-9.-]{1,253})?$")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class UnreadableState(Exception):
    pass


@dataclasses.dataclass
class VerifyItem:
    key: str
    code: str
    subject: str
    title: str
    outcome: str
    detail: str
    recheck_after: Optional[str] = None
    pending_since: Optional[str] = None


def state_path(replay: bool) -> pathlib.Path:
    from ipa_diagnose.verify import default_state_path

    base = default_state_path()
    return base.with_name("replication_last.replay.json" if replay else "replication_last.json")


def _iso(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(iso: Optional[str]) -> Optional[datetime.datetime]:
    if not isinstance(iso, str) or not _ISO_RE.fullmatch(iso):
        return None
    return datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def to_state(r: ReplicationResult, pending: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    fixes = {}
    for key, res in r.resolutions.items():
        if key.startswith("_") or getattr(res, "status", "") != "OFFERED" or not res.baseline:
            continue
        fixes[key] = dict(res.baseline, diagnosis_id=f"replication.{key}")
    return {"state_version": STATE_VERSION, "kind": "ipa-diagnose.replication.state", "generated_at": r.generated_at,
            "mode": r.mode, "host": r.environment.get("host"), "inputs": r.inputs,
            "diagnoses": [{"key": d.key, "code": d.code, "subject": d.subject, "title": d.title, "severity": d.severity,
                           "kind": d.kind, "related_to": d.related_to, "explains": list(d.explains),
                           "evidence": list(d.evidence)} for d in r.diagnoses],
            "relationships": {x["subject"]: {"state": x.get("state"), "last_update_end": x.get("last_update_end")}
                              for x in r.relationships},
            "fixes": fixes, "pending": dict(pending or {})}


def save(path: pathlib.Path, doc: Dict[str, Any]) -> None:
    """The same hardened write as the other baselines (no symlink, no foreign directory, O_EXCL temp, atomic)."""

    from ipa_diagnose.verify import _state_location_ok

    if not _state_location_ok(path):
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        data = json.dumps(doc, indent=1).encode("utf-8")
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
        pass


def load(path: pathlib.Path) -> Optional[Dict[str, Any]]:
    from ipa_diagnose.verify import _state_location_ok

    if not path.exists() and not os.path.islink(path):
        return None
    if not _state_location_ok(path):
        raise UnreadableState("the saved result is in a location this user does not own, or behind a symlink")
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            raise UnreadableState("too large")
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, RecursionError, UnicodeDecodeError):
        raise UnreadableState("unreadable")
    if not isinstance(doc, dict) or doc.get("state_version") != STATE_VERSION or \
            doc.get("kind") != "ipa-diagnose.replication.state" or not isinstance(doc.get("diagnoses"), list):
        raise UnreadableState("not a replication state record")
    if _parse(doc.get("generated_at")) is None:
        raise UnreadableState("no valid timestamp")
    diags = []
    for d in doc["diagnoses"][:200]:
        if not isinstance(d, dict) or not isinstance(d.get("code"), str) or not _CODE_RE.fullmatch(d["code"]) \
                or not isinstance(d.get("subject"), str) or not _SUBJECT_RE.fullmatch(d["subject"]):
            raise UnreadableState("malformed diagnosis record")
        ev = [e for e in d.get("evidence") or [] if isinstance(e, str) and _STEP_RE.fullmatch(e)][:20]
        diags.append({"key": f"{d['code']}@{d['subject']}", "code": d["code"], "subject": d["subject"],
                      "title": str(d.get("title", d["code"]))[:300],
                      "severity": d.get("severity") if d.get("severity") in ("FAIL", "WARN") else "FAIL",
                      "kind": d.get("kind") if d.get("kind") in (None, "UNDIAGNOSED", "CONTRADICTING", "TRANSIENT")
                      else None,
                      "explains": [x for x in d.get("explains") or [] if isinstance(x, str)][:50], "evidence": ev})
    rels = doc.get("relationships") if isinstance(doc.get("relationships"), dict) else {}
    pending = doc.get("pending") if isinstance(doc.get("pending"), dict) else {}
    inputs = doc.get("inputs") if isinstance(doc.get("inputs"), dict) else {}
    return {"generated_at": doc["generated_at"], "host": doc.get("host") if isinstance(doc.get("host"), str) else None,
            "diagnoses": diags,
            "relationships": {k: v for k, v in list(rels.items())[:200] if isinstance(k, str) and isinstance(v, dict)},
            "fixes": {k: v for k, v in list((doc.get("fixes") or {}).items())[:20] if isinstance(k, str)},
            "pending": {k: v for k, v in list(pending.items())[:200] if isinstance(k, str) and _parse(v)},
            "inputs": {"peer": inputs.get("peer") if isinstance(inputs.get("peer"), str) else None},
            "raw": doc}


def _is_agreement(subject: str) -> bool:
    return bool(re.fullmatch(r"(domain|ca):[a-z0-9.-]+>[a-z0-9.-]+", subject))


def compare(previous: Dict[str, Any], fresh: ReplicationResult, runner: Any,
            now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    from ipa_diagnose.resolution.engine import evaluate_verify, rebuild_verify

    now = now or datetime.datetime.now(datetime.timezone.utc)
    base_time = _parse(previous["generated_at"])
    fresh_keys = {d.key: d for d in fresh.diagnoses}
    rels = {x["subject"]: x for x in fresh.relationships}
    items: List[VerifyItem] = []
    pending_out: Dict[str, str] = {}
    collector_ok = (fresh.trace.get("server") is not None and fresh.trace.get("server").outcome == Outcome.PASS
                    and fresh.trace.get("agreements") is not None
                    and fresh.trace.get("agreements").outcome in (Outcome.PASS, Outcome.WARN))
    host_changed = previous.get("host") and previous["host"] != fresh.environment.get("host")
    scope_changed = previous["inputs"].get("peer") != fresh.inputs.get("peer")

    def pending(key: str, code: str, subject: str, title: str, why: str, still: str) -> VerifyItem:
        since = _parse(previous["pending"].get(key)) or now
        deadline = since + datetime.timedelta(seconds=CONVERGENCE_WINDOW)
        if now >= deadline:
            return VerifyItem(key, code, subject, title, still,
                              f"{why}; still so after the {CONVERGENCE_WINDOW // 60}-minute convergence window "
                              f"(PENDING since {_iso(since)})")
        pending_out[key] = _iso(since)
        nxt = min(now + datetime.timedelta(seconds=RECHECK), deadline)
        return VerifyItem(key, code, subject, title, "PENDING", f"{why}; recheck after {_iso(nxt)} (window ends "
                          f"{_iso(deadline)})", recheck_after=_iso(nxt), pending_since=_iso(since))

    def agreement_state(subject: str) -> "tuple[str, str]":
        x = rels.get(subject)
        if x is None:
            return "UNOBSERVED", "the agreement is not visible now"
        st = x.get("state")
        if st in (None, "UNKNOWN"):
            return "UNOBSERVED", ("the reverse direction cannot be observed from this server now"
                                  if x["direction"] == "inbound" else "its state could not be read now")
        if st in S.TRANSIENT or st == "TRANSIENT":
            return "TRANSIENT", f"it is not green yet ({st})"
        if st != S.OK:
            return "FAILING", f"it reports {st} now"
        end = _parse(x.get("last_update_end"))
        if end is None or base_time is None or end <= base_time:
            return "NO_FRESH", (f"its last successful session ended {x.get('last_update_end') or 'at an unknown time'}"
                                f", not after the saved result ({previous['generated_at']})")
        if x.get("update_in_progress"):
            return "NO_FRESH", "a session is in progress now"
        return "OK", f"a session ended successfully at {x.get('last_update_end')}, after the saved result"

    results: Dict[str, str] = {}
    old_items = [d for d in previous["diagnoses"] if d["severity"] == "FAIL" or d["kind"] == "TRANSIENT"]
    # agreements (symptoms) first: causes are only resolved when every agreement they explained is
    for d in sorted(old_items, key=lambda x: not _is_agreement(x["subject"])):
        key, code, subject, title = d["key"], d["code"], d["subject"], d["title"]
        if host_changed:
            it = VerifyItem(key, code, subject, title, "UNABLE_TO_VERIFY",
                            f"the saved result is from {previous['host']}, this is {fresh.environment.get('host')}")
        elif scope_changed:
            it = VerifyItem(key, code, subject, title, "UNABLE_TO_VERIFY",
                            "the saved result was for another --peer scope; run --verify with the same --peer")
        elif not collector_ok:
            it = VerifyItem(key, code, subject, title, "UNABLE_TO_VERIFY",
                            "this server's own agreements could not be read now (a collector failed)")
        elif key in fresh_keys and fresh_keys[key].kind != "TRANSIENT":
            it = VerifyItem(key, code, subject, title, "STILL_PRESENT", "found again with fresh evidence")
        elif _is_agreement(subject):
            st, why = agreement_state(subject)
            if st == "OK":
                same = [x for x in fresh.diagnoses if x.subject == subject and x.severity == "FAIL"]
                it = (VerifyItem(key, code, subject, title, "CHANGED", "gone, but now: " + same[0].title) if same
                      else VerifyItem(key, code, subject, title, "RESOLVED", why))
            elif st in ("NO_FRESH", "TRANSIENT"):
                it = pending(key, code, subject, title, why, "UNABLE_TO_VERIFY" if st == "NO_FRESH" else
                             "STILL_PRESENT")
            elif st == "FAILING":
                same = [x for x in fresh.diagnoses if x.subject == subject and x.severity == "FAIL"]
                it = VerifyItem(key, code, subject, title, "CHANGED" if same and key not in fresh_keys else
                                "STILL_PRESENT", why)
            else:
                it = VerifyItem(key, code, subject, title, "UNABLE_TO_VERIFY", why)
        else:
            answered = True
            for sid in d["evidence"]:
                r = fresh.trace.get(sid)
                # a check skipped as NOT NEEDED now (what prompted it is gone) answered; any other skip did not
                if r is None or r.outcome == Outcome.UNKNOWN or (
                        r.outcome == Outcome.SKIPPED and not r.skip_reason.startswith("not needed")):
                    answered = False
                    why = f"the check it rested on ({sid}) did not answer now"
                    break
            if answered and code.startswith("PAIR_CLOCK"):
                # a clock diagnosis is only gone when a clock difference was actually MEASURED again
                measured = [fresh.trace.get(sid) for sid in d["evidence"]
                            if sid.split("@", 1)[0] in ("peer.rootdse", "peer.time")]
                if not any(r is not None and isinstance(r.facts.get("offset"), (int, float)) for r in measured):
                    subj = next((sid.split("@", 1)[1] for sid in d["evidence"] if "@" in sid), None)
                    again = [fresh.trace.get(b, subject=subj) for b in ("peer.rootdse", "peer.time")] if subj else []
                    if not any(r is not None and isinstance(r.facts.get("offset"), (int, float)) for r in again):
                        answered, why = False, "the clock difference could not be measured now"
            same = [x for x in fresh.diagnoses if x.subject == subject and x.severity == "FAIL" and x.key != key]
            if not answered:
                it = VerifyItem(key, code, subject, title, "UNABLE_TO_VERIFY", why)
            elif same:
                it = VerifyItem(key, code, subject, title, "CHANGED", "gone, but now: " + same[0].title)
            else:
                it = VerifyItem(key, code, subject, title, "RESOLVED", "not found again; the checks it rested on "
                                "answer now")
                fix = previous["fixes"].get(key)
                if fix is not None:
                    criteria, problem, why2 = rebuild_verify(fix, runner)
                    if criteria is None or problem:
                        it = VerifyItem(key, code, subject, title, "UNABLE_TO_VERIFY",
                                        f"the fix's checks cannot be rebuilt: {why2}")
                    else:
                        res = evaluate_verify(criteria, runner)
                        if any(ok is None for _t, ok, _d in res):
                            it = VerifyItem(key, code, subject, title, "UNABLE_TO_VERIFY",
                                            "could not check: " + next(t for t, ok, _d in res if ok is None))
                        elif not all(ok for _t, ok, _d in res):
                            it = VerifyItem(key, code, subject, title, "PARTIALLY_RESOLVED",
                                            "still failing: " + next(t for t, ok, _d in res if not ok))
                if it.outcome == "RESOLVED":
                    open_ = [x for x in d["explains"] if results.get(x) not in (None, "RESOLVED")]
                    if open_:
                        worst = results[open_[0]]
                        it = VerifyItem(key, code, subject, title, "PENDING" if worst == "PENDING" else worst,
                                        f"its own checks pass now, but the incident it caused is {worst} ({open_[0]})")
                        if worst == "PENDING":
                            it.recheck_after = next((i.recheck_after for i in items if i.key == open_[0]), None)
        results[key] = it.outcome
        items.append(it)
    old_keys = {d["key"] for d in previous["diagnoses"]}
    new = [x for x in fresh.diagnoses if x.key not in old_keys and x.severity == "FAIL"]
    unobserved = [x["subject"] for x in fresh.relationships if x["direction"] == "inbound" and x.get("state") == "UNKNOWN"]
    return {"previous_generated_at": previous["generated_at"], "items": items, "new_conditions": new,
            "pending": pending_out, "reverse_not_verified": unobserved,
            "ruv_equality_required": False}


def exit_code(result: Dict[str, Any], fresh_code: int) -> int:
    outs = {i.outcome for i in result["items"]}
    if outs & {"STILL_PRESENT", "PARTIALLY_RESOLVED"} or result["new_conditions"]:
        return 1
    if "PENDING" in outs:
        return 3
    if outs & {"UNABLE_TO_VERIFY", "CHANGED"}:
        return 4
    return fresh_code
