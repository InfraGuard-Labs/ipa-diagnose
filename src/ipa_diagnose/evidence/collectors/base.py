"""Targeted evidence collector interface.

Collectors are read-only by contract: they run diagnostic commands
(journalctl, getcert list, ipa-replica-manage list, dig, df, klist/kvno,
read-only ldapsearch) or read a fixture file, and produce EvidenceItem
objects. They MUST NOT change system state. By default they run
conditionally - only when a diagnostic pack's trigger findings are present
(see evidence/collect.py) - not unconditionally on every invocation, per the
"do not blindly ingest massive logs" requirement. A pack may instead list a
collector under DiagnosticPack.unconditional_collectors, a narrow,
deliberate exception for evidence that is structurally undiscoverable any
other way (see engine/packs/base.py).

Every concrete collector implements both collect_live() (subprocess-backed)
and collect_replay() (reads tests/fixtures/**/<collector_name>.json) so the
exact same pack/rule code runs in real deployments and in fixture-based
tests/screenshots.
"""

from __future__ import annotations

import abc
import pathlib
from typing import List

from ipa_diagnose.evidence.model import EvidenceItem


class CollectorError(Exception):
    """Raised by a collector when it cannot run; the caller turns this into a
    CollectionError on the bundle rather than letting the whole run crash.

    ``partial_items`` lets a collector that makes more than one independent
    sub-call (e.g. ``list`` and ``list-ruv``) still surface whatever it DID
    successfully collect even when reporting that one sub-call failed -
    found in live testing against a real FreeIPA server: a partial failure
    (one sub-call succeeds, the other doesn't) was previously invisible
    whenever at least one sub-call succeeded, since only a TOTAL failure of
    every sub-call raised at all. A partial RUV-collection failure must be
    visible - "unknown is better than wrong" applies to collection gaps,
    not just to diagnoses."""

    def __init__(
        self,
        message: str,
        *,
        permission_related: bool = False,
        partial_items: "list[EvidenceItem] | None" = None,
    ):
        super().__init__(message)
        self.permission_related = permission_related
        self.partial_items = partial_items or []


class Collector(abc.ABC):
    name: str
    """Registry key, e.g. "journal_dirsrv", "certmonger", "replication_agreements"."""
    timeout_seconds: float = 10.0

    @abc.abstractmethod
    def collect_live(self) -> List[EvidenceItem]:
        """Run real commands against the local host. Raise CollectorError on failure."""
        raise NotImplementedError

    @abc.abstractmethod
    def collect_replay(self, fixture_dir: pathlib.Path) -> List[EvidenceItem]:
        """Read pre-recorded evidence from fixture_dir for --replay mode."""
        raise NotImplementedError


def run_collector(collector: Collector, *, replay_dir: "pathlib.Path | None") -> List[EvidenceItem]:
    if replay_dir is not None:
        return collector.collect_replay(replay_dir)
    return collector.collect_live()
