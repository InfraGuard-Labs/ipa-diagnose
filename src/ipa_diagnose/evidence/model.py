"""Internal evidence model.

Every fact ipa-diagnose reasons about - whether it came from ipa-healthcheck's
JSON output or from a targeted collector (journalctl, getcert, dig, ...) - is
normalized into one of the two shapes below and carries a Provenance record.
Nothing enters the diagnostic engine without a traceable "where did this come
from" answer; that traceability is what lets the CLI answer "why do we
believe that?" and what the redaction pipeline anchors on before anything is
sent to an optional AI provider.
"""

from __future__ import annotations

import dataclasses
import datetime
import enum
from typing import Any, Dict, List, Optional


class Severity(enum.Enum):
    """Mirrors ipa-healthcheck's own severity scale so results compose directly.

    ``UNKNOWN`` is not part of ipa-healthcheck's own vocabulary - it is what
    a Finding gets when its raw ``result`` string does not match any of the
    four real values (a future ipa-healthcheck severity this build predates).
    It ranks alongside ERROR (not WARNING, and not CRITICAL): dropping an
    unrecognized severity to WARNING previously let a real, corroborated
    ERROR/CRITICAL-equivalent problem fall below the ``>= ERROR`` gate every
    rule uses and go completely unreported (reproduced with a real
    ``"result": "FATAL"`` value in adversarial testing) - "unknown is better
    than wrong" cuts both ways: an unrecognized severity must not silently
    become benign, but it also must not be manufactured into an automatic
    CRITICAL. See ``evidence/healthcheck.py::_parse_severity``.
    """

    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        return {
            Severity.SUCCESS: 0,
            Severity.WARNING: 1,
            Severity.ERROR: 2,
            Severity.UNKNOWN: 2,
            Severity.CRITICAL: 3,
        }[self]

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


@dataclasses.dataclass(frozen=True)
class Provenance:
    """Where a piece of evidence came from, and exactly how it was obtained.

    ``command`` is the literal command/API call used to collect the evidence
    (e.g. ``"ipa-healthcheck --output-type json"`` or ``"journalctl -u dirsrv
    --since -10min"``). It is what ``--details`` and ``ai-preview`` show the
    administrator so nothing is a black box.
    """

    source: str
    command: Optional[str] = None
    host: Optional[str] = None
    collected_at: Optional[str] = None
    live: bool = True
    """False when evidence came from --replay fixtures rather than the live host."""

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class Finding:
    """One ipa-healthcheck result, normalized.

    Maps 1:1 onto an ipa-healthcheck JSON array element:
    ``{source, check, result, uuid, when, duration, kw}``.
    """

    finding_id: str
    source: str
    """ipa-healthcheck source module, e.g. "ipahealthcheck.ds.replication"."""
    check: str
    """ipa-healthcheck check/class name, e.g. "ReplicationCheck"."""
    severity: Severity
    message: str
    keywords: Dict[str, Any] = dataclasses.field(default_factory=dict)
    provenance: Provenance = dataclasses.field(
        default_factory=lambda: Provenance(source="ipa-healthcheck")
    )
    raw: Dict[str, Any] = dataclasses.field(default_factory=dict)
    """Original JSON object, kept for --details / ai-preview, pre-redaction."""

    @property
    def qualified_check(self) -> str:
        return f"{self.source}.{self.check}"


@dataclasses.dataclass(frozen=True)
class EvidenceItem:
    """A normalized fact from a targeted (non-healthcheck) collector.

    Examples: a single certmonger tracking request from ``getcert list``, a
    replication agreement from ``ipa-replica-manage list``, a disk-usage
    reading, a matched line from ``journalctl``, a DNS SRV lookup result.
    """

    item_id: str
    kind: str
    """Collector-defined category, e.g. "certmonger_request", "journal_line",
    "replication_agreement", "dns_srv_record", "disk_usage", "kvno"."""
    summary: str
    data: Dict[str, Any] = dataclasses.field(default_factory=dict)
    severity: Optional[Severity] = None
    provenance: Provenance = dataclasses.field(default_factory=lambda: Provenance(source="collector"))


@dataclasses.dataclass(frozen=True)
class CollectionError:
    """Records a collector that could not run, so degradation is visible, not silent."""

    collector: str
    message: str
    permission_related: bool = False
    provenance: Optional[Provenance] = None


@dataclasses.dataclass(frozen=True)
class EnvironmentInfo:
    """Lightweight, best-effort environment/version metadata - safety context
    for --details/--json, not a compatibility-mapping engine. Every field is
    independently optional: detection failures never raise, they just leave
    the field None (see evidence/environment.py)."""

    distro: Optional[str] = None
    """e.g. "rhel", "rocky", "almalinux", "fedora" (/etc/os-release ID)."""
    distro_version: Optional[str] = None
    """e.g. "9.8" (/etc/os-release VERSION_ID)."""
    python_version: Optional[str] = None
    freeipa_version: Optional[str] = None
    ipa_healthcheck_version: Optional[str] = None
    directory_server_version: Optional[str] = None
    detected_live: bool = True
    """False when this came from a --replay fixture's meta.json rather than
    the live host."""


@dataclasses.dataclass
class EvidenceBundle:
    """Everything collected for one diagnostic run."""

    hostname: str
    collected_at: str
    findings: List[Finding] = dataclasses.field(default_factory=list)
    items: List[EvidenceItem] = dataclasses.field(default_factory=list)
    collection_errors: List[CollectionError] = dataclasses.field(default_factory=list)
    environment: Optional[EnvironmentInfo] = None
    replay_source: Optional[str] = None
    """Set to the fixture directory path when running under --replay."""

    def findings_by_source_prefix(self, prefix: str) -> List[Finding]:
        return [f for f in self.findings if f.source.startswith(prefix)]

    def findings_at_or_above(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity.rank >= severity.rank]

    def items_by_kind(self, kind: str) -> List[EvidenceItem]:
        return [i for i in self.items if i.kind == kind]

    @staticmethod
    def now() -> str:
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
