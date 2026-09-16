"""Quick manual smoke test for the engine core. Not part of the pytest suite."""

from ipa_diagnose.engine.model import Confidence, ConfidenceLevel, Diagnosis, DiagnosisStatus
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.model import EvidenceBundle

bundle = EvidenceBundle(hostname="ipa01.example.test", collected_at=EvidenceBundle.now())
report = run_diagnosis(bundle)
print("overall_status:", report.overall_status)
print("packs_evaluated:", report.packs_evaluated)
print("diagnoses:", report.diagnoses)

print("--- guardrail test (should raise ValueError) ---")
try:
    Diagnosis(
        pack_id="x",
        rule_id="y",
        status=DiagnosisStatus.DIAGNOSED,
        title="t",
        why="w",
        confidence=Confidence(level=ConfidenceLevel.LOW, rationale="weak"),
    )
    print("BUG: no exception raised")
except ValueError as e:
    print("OK, guardrail fired:", e)
