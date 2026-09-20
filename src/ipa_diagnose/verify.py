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
from typing import Any, Dict, List, Optional

from ipa_diagnose.engine.model import Diagnosis, DiagnosisReport, DiagnosisStatus, PriorityBucket
from ipa_diagnose.render.json_output import report_to_dict

_ROOT_TIER = {PriorityBucket.PRIMARY, PriorityBucket.SECONDARY_INDEPENDENT}


class VerifyOutcome(enum.Enum):
    RESOLVED = "RESOLVED"
    STILL_PRESENT = "STILL_PRESENT"
    PARTIALLY_RESOLVED = "PARTIALLY_RESOLVED"
    UNABLE_TO_VERIFY = "UNABLE_TO_VERIFY"


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
        state_path.write_text(json.dumps(report_to_dict(report), indent=2), encoding="utf-8")
        os.chmod(state_path, 0o600)
    except OSError:
        pass  # Saving state is best-effort; `verify` degrades to UNABLE_TO_VERIFY without it.


def load_previous_report(state_path: pathlib.Path) -> Optional[Dict[str, Any]]:
    if not state_path.exists():
        return None
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, ValueError, RecursionError):
        return None
    # A corrupt/hand-edited state file must degrade to "no baseline", never crash.
    if not isinstance(data, dict) or not isinstance(data.get("diagnoses", []), list):
        return None
    data["diagnoses"] = [
        d for d in data.get("diagnoses", []) if isinstance(d, dict) and isinstance(d.get("diagnosis_id"), str)
    ]
    return data


def compare(previous: Optional[Dict[str, Any]], current: DiagnosisReport) -> VerifyResult:
    if previous is None:
        return VerifyResult(items=[], new_conditions=[], previous_generated_at=None, current_report=current)

    prev_by_id = {d["diagnosis_id"]: d for d in previous.get("diagnoses", [])}
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

    items: List[VerifyItem] = []
    for diag_id, prev_d in prev_by_id.items():
        pack_id = prev_d.get("pack_id", "")
        pack_gap = pack_id and (
            any(pack_id in err_source for err_source in affected_packs_with_errors)
            or bool(pack_collectors.get(pack_id, set()) & affected_packs_with_errors)
        )
        if healthcheck_missing or pack_gap:
            items.append(
                VerifyItem(
                    diagnosis_id=diag_id,
                    title=prev_d.get("title", diag_id),
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
                    title=prev_d.get("title", diag_id),
                    outcome=VerifyOutcome.UNABLE_TO_VERIFY,
                    detail="Some ipa-healthcheck checks failed to run this time, so this cannot be confirmed resolved.",
                )
            )
            continue
        if curr_d is None:
            items.append(
                VerifyItem(
                    diagnosis_id=diag_id,
                    title=prev_d.get("title", diag_id),
                    outcome=VerifyOutcome.RESOLVED,
                    detail="The condition that triggered this diagnosis is no longer present in fresh evidence.",
                )
            )
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
