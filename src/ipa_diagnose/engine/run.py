"""Top-level orchestration: evidence bundle -> DiagnosisReport."""

from __future__ import annotations

import dataclasses

from ipa_diagnose.engine import correlate, unexplained
from ipa_diagnose.engine.model import DiagnosisReport
from ipa_diagnose.engine.registry import all_packs
from ipa_diagnose.evidence.model import EvidenceBundle


def run_diagnosis(bundle: EvidenceBundle) -> DiagnosisReport:
    packs = all_packs()
    diagnoses = []
    # An ipa-healthcheck check that raised an exception (kw.exception/traceback)
    # produced NO statement about the system: e.g. with certmonger stopped the
    # certificate checks crash with "Failed to start certmonger", which a rule
    # must never read as "the certificate has expired" (live-discovered false
    # HIGH-confidence diagnosis). Rules see only real check results; crashed
    # checks go to the visibility safety net below.
    rule_findings = [f for f in bundle.findings if not unexplained.is_check_crash(f)]
    rule_bundle = dataclasses.replace(bundle, findings=rule_findings)
    for pack in packs:
        diagnoses.extend(pack.evaluate(rule_bundle))
    # Visibility safety net: ERROR/CRITICAL healthcheck findings no rule claimed must never vanish.
    diagnoses.extend(unexplained.unexplained_finding_diagnoses(bundle, diagnoses))
    return correlate.build_report(bundle, diagnoses, packs_evaluated=[p.pack_id for p in packs])
