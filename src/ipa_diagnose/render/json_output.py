"""JSON serialization of a DiagnosisReport, for `--json` / automation use."""

from __future__ import annotations

import shlex
from typing import Any, Dict

from ipa_diagnose.engine.model import Action, Diagnosis, DiagnosisReport, EvidenceRef, VerificationCondition


def _action_to_dict(a: Action) -> Dict[str, Any]:
    return {
        "description": a.description,
        "risk": a.risk.value,
        "command": a.command,
        "rationale": a.rationale,
        "reference": a.reference,
    }


def _verification_to_dict(v: VerificationCondition) -> Dict[str, Any]:
    return {"description": v.description, "healthcheck_sources": v.healthcheck_sources}


def _ref_to_dict(r: EvidenceRef) -> Dict[str, Any]:
    return {"evidence_id": r.evidence_id, "kind": r.kind, "why_relevant": r.why_relevant}


def _diagnosis_to_dict(d: Diagnosis, ai_explanation: str = None) -> Dict[str, Any]:
    return {
        "diagnosis_id": d.diagnosis_id,
        "pack_id": d.pack_id,
        "rule_id": d.rule_id,
        "status": d.status.value,
        "priority": d.priority.value,
        "severity": d.severity.value,
        "title": d.title,
        "why": d.why,
        "ai_explanation": ai_explanation,
        "confidence": {
            "level": d.confidence.level.value,
            "rationale": d.confidence.rationale,
            "corroborating_evidence_count": d.confidence.corroborating_evidence_count,
            "contradicting_evidence_count": d.confidence.contradicting_evidence_count,
        },
        "evidence_for": [_ref_to_dict(r) for r in d.evidence_for],
        "evidence_against": [_ref_to_dict(r) for r in d.evidence_against],
        "impact": d.impact,
        "actions": [_action_to_dict(a) for a in d.actions],
        "verification": [_verification_to_dict(v) for v in d.verification],
        "limitations": d.limitations,
        "next_diagnostic_step": d.next_diagnostic_step,
        "upstream_candidates": d.upstream_candidates,
        "related_to_titles": d.related_to_titles,
    }


def _environment_to_dict(env) -> Dict[str, Any] | None:
    if env is None:
        return None
    return {
        "distro": env.distro,
        "distro_version": env.distro_version,
        "python_version": env.python_version,
        "freeipa_version": env.freeipa_version,
        "ipa_healthcheck_version": env.ipa_healthcheck_version,
        "directory_server_version": env.directory_server_version,
        "detected_live": env.detected_live,
    }


def _completeness_to_dict(c) -> Dict[str, Any]:
    return {
        "level": c.level,
        "healthcheck_collected": c.healthcheck_collected,
        "ruv_state": c.ruv_state,
        "ruv_reason": c.ruv_reason,
        "unverified": [
            {
                "capability": u.capability,
                "collector": u.collector,
                "reason": u.reason,
                "permission_related": u.permission_related,
                "hint": u.hint,
            }
            for u in c.unverified
        ],
    }


def report_to_dict(report: DiagnosisReport, ai_explanations: Dict[str, str] = None) -> Dict[str, Any]:
    ai_explanations = ai_explanations or {}
    return {
        "generated_at": report.generated_at,
        "hostname": report.hostname,
        "overall_status": report.overall_status.value,
        "packs_evaluated": report.packs_evaluated,
        "collection_errors": report.collection_errors,
        "unclaimed_warnings": report.unclaimed_warnings,
        "has_undiagnosed_findings": bool(report.undiagnosed_findings),
        "undiagnosed_count": len(report.undiagnosed_findings),
        "undiagnosed_findings": [
            {
                "source": u.source,
                "check": u.check,
                "severity": u.severity,
                "message": u.message,
                "key": u.key,
                "reason": u.reason,
                "check_crashed": u.crashed,
                "check_known_since_ipa_healthcheck": u.check_known_since,
                "ipa_healthcheck_version": u.ipa_healthcheck_version,
            }
            for u in report.undiagnosed_findings
        ],
        "fully_verified": report.evidence_completeness.level == "complete",
        "evidence_completeness": _completeness_to_dict(report.evidence_completeness),
        "replay_source": report.replay_source,
        "environment": _environment_to_dict(report.environment),
        "unknown_severity_findings": report.unknown_severity_findings,
        "diagnoses": [
            _diagnosis_to_dict(d, ai_explanations.get(d.diagnosis_id)) for d in report.diagnoses
        ],
        # 1.0 additions: v1 keys above are frozen; everything new lives under "v2".
        "report_schema_version": 2,
        "v2": {
            "resolutions": [resolution_to_dict(r) for r in (report.resolutions or {}).values()],
            # what `verify` may rely on later (see resolution.engine.rebuild_verify); display data above is not used
            "verify_baseline": {"schema": 1, "fixes": [
                dict(r.baseline, diagnosis_id=r.diagnosis_id)
                for r in (report.resolutions or {}).values() if r.status == "OFFERED" and r.baseline
            ]},
        },
    }


def resolution_to_dict(r) -> Dict[str, Any]:
    return {
        "diagnosis_id": r.diagnosis_id,
        "status": r.status,
        "procedure_id": r.procedure_id,
        "title": r.title,
        "reasons": list(r.reasons),
        "checked": [
            {"label": label, "check": c.check_id, "status": c.status, "result": c.display, "command": c.command,
             "source": "recorded" if r.replay else "live"}
            for label, c in r.checks
        ],
        "prerequisites": [{"text": p.text, "state": p.state} for p in r.prerequisites],
        "steps": [
            {"id": s.step_id, "text": s.text, "argv": list(s.argv), "command": s.command, "risk": s.risk,
             "changes": list(s.changes), "expected": s.expected, "run_on": s.run_on}
            for s in r.steps
        ],
        "what_changes": list(r.what_changes),
        "risk": r.risk if r.steps else None,
        "rollback": [dict(x, command=shlex.join(x["argv"]) if x.get("argv") else None) for x in r.rollback],
        "confirm_first": [{"text": c["text"], "argv": c["argv"], "command": shlex.join(c["argv"]), "expected": c["expect"]}
                          for c in r.confirm_first],
        "verify": list(r.verify),
        "applies_to": r.applies_to,
        "tier": r.tier,
        "definitive": r.definitive,
        "verification_label": r.verification_label,
        "limitations": r.limitations,
        "reference": r.reference,
        "impact_note": r.impact_note,
    }
