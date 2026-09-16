"""Top-level orchestration: evidence bundle -> DiagnosisReport."""

from __future__ import annotations

from ipa_diagnose.engine import correlate
from ipa_diagnose.engine.model import DiagnosisReport
from ipa_diagnose.engine.registry import all_packs
from ipa_diagnose.evidence.model import EvidenceBundle


def run_diagnosis(bundle: EvidenceBundle) -> DiagnosisReport:
    packs = all_packs()
    diagnoses = []
    for pack in packs:
        diagnoses.extend(pack.evaluate(bundle))
    return correlate.build_report(bundle, diagnoses, packs_evaluated=[p.pack_id for p in packs])
