"""Diagnostic pack plugin interface.

A pack is a small, versioned collection of rules for one problem family
(replication, certificates, kerberos, dns, directory-server). Rules are
plain Python, not a generic plugin/entry-point system - v1 deliberately
keeps this to an internal registry (see engine/registry.py) rather than
building a plugin ecosystem the product doesn't need yet.

Rule contract:
  - A rule must return None (NOT_APPLICABLE) when its trigger evidence isn't
    present at all - most rules, most runs, do this. Silence is the default.
  - A rule only returns a Diagnosis once its trigger evidence IS present.
    That Diagnosis may still have status UNKNOWN_* - "trigger fired, but I
    can't safely tell you which of N causes it is" is a valid, encouraged
    outcome (see engine/model.py: Diagnosis requires next_diagnostic_step
    for any non-DIAGNOSED status).
  - A rule must never consult an AI provider and must never invent a Finding
    or EvidenceItem that isn't in the bundle it was given.
"""

from __future__ import annotations

import abc
import dataclasses
from typing import List, Optional

from ipa_diagnose.engine.model import Diagnosis
from ipa_diagnose.evidence.model import EvidenceBundle


class DiagnosticRule(abc.ABC):
    """One root-cause hypothesis within a pack."""

    rule_id: str
    version: str = "1"
    summary: str = ""

    @abc.abstractmethod
    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        """Return None if not applicable, else a Diagnosis (possibly UNKNOWN_*)."""
        raise NotImplementedError


@dataclasses.dataclass
class DiagnosticPack:
    """A named, versioned group of rules for one problem family."""

    pack_id: str
    version: str
    display_name: str
    rules: List[DiagnosticRule]
    healthcheck_sources: List[str] = dataclasses.field(default_factory=list)
    """ipa-healthcheck --source values this pack's rules read from - lets the
    CLI request only the relevant subset when running live."""
    additional_collectors: List[str] = dataclasses.field(default_factory=list)
    """Names of targeted (non-healthcheck) collectors this pack can use,
    registered in evidence/collectors/. Collected only when this pack's
    trigger findings are present (see evidence/collect.py's staged-collection
    flow), not unconditionally on every run."""
    unconditional_collectors: List[str] = dataclasses.field(default_factory=list)
    """Collectors that must run on every invocation regardless of whether
    this pack's healthcheck_sources have a WARNING+ finding. This is a
    deliberate, narrow exception to the "collect only when triggered"
    default above - use it only when a real problem is otherwise
    structurally undiscoverable. Concretely: a stale RUV from a
    decommissioned replica does not itself make ipa-healthcheck's own
    RUVCheck/KnownRUVCheck report anything worse than SUCCESS (confirmed
    against upstream ipa-healthcheck source - full staleness analysis needs
    multi-master data healthcheck doesn't have), so gating the
    ``replication_agreements`` collector behind another replication/topology
    finding meant a topology that otherwise looked perfectly healthy could
    hide a real stale RUV entirely (reproduced: reported "Overall: HEALTHY"
    for exactly that scenario)."""

    def evaluate(self, bundle: EvidenceBundle) -> List[Diagnosis]:
        results: List[Diagnosis] = []
        for rule in self.rules:
            outcome = rule.evaluate(bundle)
            if outcome is not None:
                results.append(outcome)
        return results
