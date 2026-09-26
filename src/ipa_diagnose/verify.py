"""`ipa-diagnose verify`: did the problem actually clear, based on fresh
evidence and a fresh diagnosis run - never merely "the remediation command
exited 0" (see docs/verification.md for why that's explicitly insufficient,
per real documented FreeIPA cases where an error message didn't mean the
underlying operation failed).

Flow: the main `ipa-diagnose` run persists its DiagnosisReport as JSON to a
small state file. `verify` re-collects evidence (same live/--replay mode),
re-runs the engine, and diffs the previous diagnoses against the new ones by
diagnosis_id (pack_id.rule_id) - not by re-checking the remediation command.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import os
import pathlib
import re
from typing import Any, Dict, List, Optional

from ipa_diagnose.engine.model import Diagnosis, DiagnosisReport, DiagnosisStatus, PriorityBucket
from ipa_diagnose.render.json_output import report_to_dict
from ipa_diagnose.textsafe import sanitize_text

_ROOT_TIER = {PriorityBucket.PRIMARY, PriorityBucket.SECONDARY_INDEPENDENT}


class VerifyOutcome(enum.Enum):
    RESOLVED = "RESOLVED"
    STILL_PRESENT = "STILL_PRESENT"
    PARTIALLY_RESOLVED = "PARTIALLY_RESOLVED"
    UNABLE_TO_VERIFY = "UNABLE_TO_VERIFY"
    CHANGED = "CHANGED"
    """The problem as diagnosed is gone, but what the fix pointed at is no longer the same - re-diagnose."""


@dataclasses.dataclass
class VerifyItem:
    diagnosis_id: str
    title: str
    outcome: VerifyOutcome
    detail: str


@dataclasses.dataclass
class VerifyResult:
    items: List[VerifyItem]
    new_conditions: List[Diagnosis]
    previous_generated_at: Optional[str]
    current_report: DiagnosisReport

    @property
    def keep_baseline(self) -> bool:
        """Something previously found was neither confirmed resolved nor is it in the fresh report: the saved
        baseline must be kept, or the next verify would silently lose it (round-6 review)."""

        fresh = {d.diagnosis_id for d in self.current_report.diagnoses} if self.current_report else set()
        return any(i.outcome != VerifyOutcome.RESOLVED and i.diagnosis_id not in fresh for i in self.items)


def default_state_path() -> pathlib.Path:
    override = os.environ.get("IPA_DIAGNOSE_STATE_DIR")
    if override:
        return pathlib.Path(override) / "last_report.json"
    system_dir = pathlib.Path("/var/lib/ipa-diagnose")
    if system_dir.exists() and os.access(system_dir, os.W_OK):
        return system_dir / "last_report.json"
    return pathlib.Path.home() / ".cache" / "ipa-diagnose" / "last_report.json"


def save_report(state_path: pathlib.Path, report: DiagnosisReport) -> None:
    # The report embeds hostnames, replication peer names, and other
    # infrastructure-reconnaissance-shaded evidence (it is not run through
    # the AI-redaction pipeline, which only applies to outbound AI payloads)
    # - restricted to owner-only, not left at the default-umask 0644/0755
    # (found in security review).
    if os.path.islink(state_path) or os.path.islink(state_path.parent):
        return  # never follow a symlink when writing as root (best-effort state only)
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(state_path.parent, 0o700)
        data = json.dumps(report_to_dict(report), indent=2).encode("utf-8")
        # Atomic: a full disk or a crash leaves the previous file intact, never a truncated one (round-7 review).
        tmp = state_path.with_name(f".{state_path.name}.{os.getpid()}.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(str(tmp), str(state_path))
        finally:
            if tmp.exists():
                tmp.unlink()
    except OSError:
        pass  # Saving state is best-effort; `verify` degrades to UNABLE_TO_VERIFY without it.


def carry_forward_fixes(previous: Optional[Dict[str, Any]], report: DiagnosisReport) -> List[Dict[str, Any]]:
    """Fix records to keep in the next baseline: a fix shown earlier whose diagnosis is still present now but is
    not shown again this run (for example a check could not run). Without this, a later verify would compare
    without the fix's own checks (round-7 review). Only from a usable baseline of this same host and mode."""

    if previous is None or _baseline_problem(previous, report) or _baseline_damage(previous):
        return []
    fresh_ids = {d.diagnosis_id for d in report.diagnoses}
    shown_now = {rid for rid, r in (report.resolutions or {}).items() if getattr(r, "status", None) == "OFFERED"}
    return [f for did, f in _baseline_fixes(previous).items() if did in fresh_ids and did not in shown_now]


class UnreadableBaseline(Exception):
    """The saved diagnosis exists but cannot be read: verification is impossible, not "nothing to verify"."""


def load_previous_report(state_path: pathlib.Path, strict: bool = False) -> Optional[Dict[str, Any]]:
    if not state_path.exists():
        return None
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, ValueError, RecursionError):
        if strict:
            raise UnreadableBaseline(str(state_path))
        return None
    # A corrupt/hand-edited state file must degrade to "no baseline", never crash.
    if not isinstance(data, dict) or not isinstance(data.get("diagnoses", []), list):
        return None
    data["diagnoses"] = [
        d for d in data.get("diagnoses", []) if isinstance(d, dict) and isinstance(d.get("diagnosis_id"), str)
    ]
    for d in data["diagnoses"]:
        # Hand-edited values are never printed as multi-line text and never reach comparisons as non-strings.
        d["diagnosis_id"] = sanitize_text(d["diagnosis_id"], 160)
        d["title"] = sanitize_text(d["title"], 160) if isinstance(d.get("title"), str) else d["diagnosis_id"]
        for key in ("pack_id", "priority", "status"):
            if not isinstance(d.get(key), str):
                d[key] = ""
    if not isinstance(data.get("generated_at"), str):
        data["generated_at"] = "an unknown time"
    return data


def _baseline_fixes(previous: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """diagnosis_id -> the minimal fix record saved for verify (v2.verify_baseline). Nothing else about a fix
    (its status, commands, risk, criteria or expected results) is read back from the saved report."""

    v2 = previous.get("v2") if isinstance(previous.get("v2"), dict) else {}
    base = v2.get("verify_baseline") if isinstance(v2.get("verify_baseline"), dict) else {}
    out = {}
    for f in base.get("fixes", []) if isinstance(base.get("fixes"), list) else []:
        if isinstance(f, dict) and isinstance(f.get("diagnosis_id"), str):
            out[f["diagnosis_id"]] = f
    return out


def _baseline_damage(previous: Dict[str, Any]) -> Optional[str]:
    """A report written by this schema always carries a well-formed verify baseline; one without it is damaged."""

    if previous.get("report_schema_version") != 2 and "v2" not in previous:
        return None  # a v0.1.3 report: compared exactly as v0.1.3 did
    v2 = previous.get("v2")
    base = v2.get("verify_baseline") if isinstance(v2, dict) else None
    if not isinstance(base, dict) or base.get("schema") != 1 or not isinstance(base.get("fixes"), list):
        return "The saved diagnosis is damaged (its verification data is missing or malformed). Run ipa-diagnose again."
    if not isinstance(previous.get("hostname"), str) or not previous["hostname"].strip():
        return "The saved diagnosis is damaged (it does not say which host it is from). Run ipa-diagnose again."
    return None


def _offered_without_record(previous: Dict[str, Any], fixes: Dict[str, Dict[str, Any]]) -> set:
    v2 = previous.get("v2") if isinstance(previous.get("v2"), dict) else {}
    shown = v2.get("resolutions") if isinstance(v2.get("resolutions"), list) else []
    return {r["diagnosis_id"] for r in shown if isinstance(r, dict) and r.get("status") == "OFFERED"
            and isinstance(r.get("diagnosis_id"), str) and r["diagnosis_id"] not in fixes}


def known_diagnosis_id(diag_id: str) -> bool:
    """A diagnosis this version of ipa-diagnose can produce (so its absence from fresh results means something)."""

    from ipa_diagnose.engine import unexplained
    from ipa_diagnose.engine.registry import all_packs

    known = {f"{p.pack_id}.{r.rule_id}" for p in all_packs() for r in p.rules}
    known |= {f"{unexplained.PACK_ID}.healthcheck-check-failed", f"{unexplained.PACK_ID}.unexplained-findings"}
    if diag_id in known:
        return True
    prefix = f"{unexplained.PACK_ID}.service-not-running-"
    return diag_id.startswith(prefix) and bool(_SERVICE_NAME_RE.fullmatch(diag_id[len(prefix):]))


_SERVICE_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,80}")


def _baseline_problem(previous: Dict[str, Any], current: DiagnosisReport) -> Optional[str]:
    """Why the saved report cannot be a baseline for this run at all (other host, other mode), or None."""

    prev_host = previous.get("hostname")
    if isinstance(prev_host, str) and prev_host and current.hostname and prev_host != current.hostname:
        return (f"The saved diagnosis is from host {sanitize_text(prev_host, 80)}, not this host "
                f"({sanitize_text(current.hostname, 80)}). Run ipa-diagnose here first.")
    prev_replay = bool(previous.get("replay_source"))
    if prev_replay != bool(current.replay_source):
        return ("The saved diagnosis came from " + ("a replay fixture" if prev_replay else "a live run")
                + ", but this run is " + ("a replay" if current.replay_source else "live") + ". Run ipa-diagnose again.")
    return None


def compare(previous: Optional[Dict[str, Any]], current: DiagnosisReport, runner=None) -> VerifyResult:
    if previous is None:
        return VerifyResult(items=[], new_conditions=[], previous_generated_at=None, current_report=current)

    prev_by_id = {d["diagnosis_id"]: d for d in previous.get("diagnoses", [])}
    fixes = _baseline_fixes(previous)
    curr_by_id = {d.diagnosis_id: d for d in current.diagnoses}
    affected_packs_with_errors = {
        err.split(":", 1)[0].strip() for err in current.collection_errors
    }
    # Explicit collector -> pack mapping (from the packs' own declarations),
    # so a failed collector marks the right pack UNABLE_TO_VERIFY instead of
    # relying on a substring match between pack ids and collector names.
    from ipa_diagnose.engine.registry import all_packs

    pack_collectors = {
        p.pack_id: set(p.additional_collectors) | set(p.unconditional_collectors) for p in all_packs()
    }
    healthcheck_missing = not current.evidence_completeness.healthcheck_collected
    crashed_checks = any(d.rule_id == "healthcheck-check-failed" for d in current.diagnoses)
    not_a_baseline = _baseline_problem(previous, current) or _baseline_damage(previous)
    missing_record = _offered_without_record(previous, fixes)

    items: List[VerifyItem] = []
    for diag_id, prev_d in prev_by_id.items():
        title = prev_d.get("title", diag_id)
        if not_a_baseline:
            items.append(VerifyItem(diagnosis_id=diag_id, title=title, outcome=VerifyOutcome.UNABLE_TO_VERIFY,
                                    detail=not_a_baseline))
            continue
        if not known_diagnosis_id(diag_id):
            items.append(VerifyItem(
                diagnosis_id=diag_id, title=title, outcome=VerifyOutcome.UNABLE_TO_VERIFY,
                detail="This version of ipa-diagnose does not produce this diagnosis any more (or the saved report "
                       "is damaged), so its absence proves nothing. Run ipa-diagnose again."))
            continue
        pack_id = prev_d.get("pack_id", "")
        pack_gap = pack_id and (
            any(pack_id in err_source for err_source in affected_packs_with_errors)
            or bool(pack_collectors.get(pack_id, set()) & affected_packs_with_errors)
        )
        if healthcheck_missing or pack_gap:
            items.append(
                VerifyItem(
                    diagnosis_id=diag_id,
                    title=title,
                    outcome=VerifyOutcome.UNABLE_TO_VERIFY,
                    detail=(
                        "ipa-healthcheck could not run this time, so nothing can be confirmed resolved."
                        if healthcheck_missing
                        else "Fresh evidence for this pack could not be collected this run."
                    ),
                )
            )
            continue

        curr_d = curr_by_id.get(diag_id)
        if curr_d is None and crashed_checks:
            items.append(
                VerifyItem(
                    diagnosis_id=diag_id,
                    title=title,
                    outcome=VerifyOutcome.UNABLE_TO_VERIFY,
                    detail="Some ipa-healthcheck checks failed to run this time, so this cannot be confirmed resolved.",
                )
            )
            continue
        if curr_d is None and diag_id in missing_record:
            items.append(VerifyItem(
                diagnosis_id=diag_id, title=title, outcome=VerifyOutcome.UNABLE_TO_VERIFY,
                detail="A fix was shown for this, but the saved record needed to check it is missing. Run ipa-diagnose again."))
            continue
        if curr_d is None:
            outcome, detail = _fix_outcome(fixes.get(diag_id), runner)
            items.append(VerifyItem(diagnosis_id=diag_id, title=title, outcome=outcome, detail=detail))
            continue

        prev_root_tier = prev_d.get("priority") in {b.value for b in _ROOT_TIER}
        curr_root_tier = curr_d.priority in _ROOT_TIER
        prev_diagnosed = prev_d.get("status") == DiagnosisStatus.DIAGNOSED.value
        curr_diagnosed = curr_d.status == DiagnosisStatus.DIAGNOSED

        if prev_root_tier and not curr_root_tier:
            items.append(
                VerifyItem(
                    diagnosis_id=diag_id,
                    title=prev_d.get("title", diag_id),
                    outcome=VerifyOutcome.PARTIALLY_RESOLVED,
                    detail=f"Still detected, but no longer a primary problem (now {curr_d.priority.value}).",
                )
            )
        elif prev_diagnosed and not curr_diagnosed:
            items.append(
                VerifyItem(
                    diagnosis_id=diag_id,
                    title=prev_d.get("title", diag_id),
                    outcome=VerifyOutcome.PARTIALLY_RESOLVED,
                    detail="No longer confidently diagnosed, but related symptoms are still present.",
                )
            )
        else:
            items.append(
                VerifyItem(
                    diagnosis_id=diag_id,
                    title=prev_d.get("title", diag_id),
                    outcome=VerifyOutcome.STILL_PRESENT,
                    detail="Fresh evidence still shows this condition.",
                )
            )

    new_conditions = [
        d
        for diag_id, d in curr_by_id.items()
        if diag_id not in prev_by_id and d.priority in _ROOT_TIER
    ]

    return VerifyResult(
        items=items,
        new_conditions=new_conditions,
        previous_generated_at=previous.get("generated_at"),
        current_report=current,
    )


def _fix_outcome(fix: Optional[Dict[str, Any]], runner) -> "tuple":
    """Outcome for a diagnosis that is gone from fresh evidence. Without a saved fix record (or without a runner)
    this is the v0.1.3 comparison. With one, the fix's criteria are REBUILT from the current procedure catalogue,
    the saved typed values and fresh read-only checks, then evaluated with fresh checks."""

    gone = "The condition that triggered this diagnosis is no longer present in fresh evidence."
    if fix is None or runner is None:
        return VerifyOutcome.RESOLVED, gone
    from ipa_diagnose.resolution.engine import REBUILD_CHANGED, evaluate_verify, rebuild_verify

    criteria, problem, why = rebuild_verify(fix, runner)
    if criteria is None:
        return VerifyOutcome.UNABLE_TO_VERIFY, (
            f"The diagnosis is gone, but the fix that was shown cannot be checked: {why}. Run ipa-diagnose again.")
    if problem == REBUILD_CHANGED:
        return VerifyOutcome.CHANGED, f"The diagnosis is gone, but {why}. Run ipa-diagnose again."
    results = evaluate_verify(criteria, runner)
    lines = [f"{'✓' if ok else ('✗' if ok is False else '?')} {text}" for text, ok, _ in results]
    own = ("the fix's own checks (recorded in the replay fixture, not run now)" if getattr(runner, "replay", False)
           else "the fix's own checks")
    if not results or any(ok is None for _, ok, _ in results):
        return VerifyOutcome.UNABLE_TO_VERIFY, f"The diagnosis is gone, but {own} could not all be run: " + "; ".join(lines)
    if all(ok for _, ok, _ in results):
        return VerifyOutcome.RESOLVED, f"The diagnosis is gone and {own} pass: " + "; ".join(lines)
    return VerifyOutcome.PARTIALLY_RESOLVED, f"The diagnosis is gone, but not every one of {own} passes yet: " + "; ".join(lines)
