"""Directory Server / LDAP core diagnostic pack.

Directory Server is foundational under the rest of the documented causality
chain (DNS -> Kerberos -> Replication -> Certificates all ultimately depend
on a healthy 389-ds-base instance), so every rule in this pack declares an
empty ``upstream_candidates`` - nothing else in this product is normally
upstream of the directory server itself.

Four rules, one per well-documented root-cause cluster for this domain:

  1. ``disk-space-exhaustion``       - DiskSpaceExhaustionRule
  2. ``ownership-selinux-mismatch``  - OwnershipSelinuxMismatchRule
  3. ``nss-tls-db-format``           - NssTlsDbFormatRule
  4. ``missing-system-index``        - IndexBackendHealthRule
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ipa_diagnose.textsafe import safe_token
from ipa_diagnose.engine.model import (
    Action,
    Confidence,
    ConfidenceLevel,
    Diagnosis,
    DiagnosisStatus,
    EvidenceRef,
    RiskLevel,
    VerificationCondition,
)
from ipa_diagnose.engine.packs.base import DiagnosticPack, DiagnosticRule
from ipa_diagnose.evidence.model import EvidenceBundle, EvidenceItem, Finding, Severity

PACK_ID = "directory-server"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _findings(bundle: EvidenceBundle, *prefixes: str) -> List[Finding]:
    return [f for f in bundle.findings if any(f.source.startswith(p) for p in prefixes)]


def _exact(bundle: EvidenceBundle, source: str, *checks: str) -> List[Finding]:
    """Findings from specific ipa-healthcheck CHECKS (exact source + check name).

    Rules used to match a whole source by prefix, so a new/unknown check added
    upstream under the same source - or a differently-purposed check whose source
    name merely starts with the same text (ds.nss vs ds.nss_ssl) - was claimed and
    misdiagnosed. An unknown check is now left to the undiagnosed-findings path."""

    return [f for f in bundle.findings if f.source == source and f.check in checks]


def _at_least_warning(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if f.severity.rank >= Severity.WARNING.rank]


def _items_by_category(bundle: EvidenceBundle, kind: str, category: str) -> List[EvidenceItem]:
    return [i for i in bundle.items_by_kind(kind) if i.data.get("category") == category]


def _ref_f(f: Finding, why: str) -> EvidenceRef:
    return EvidenceRef(evidence_id=f.finding_id, kind="finding", why_relevant=why)


def _ref_i(i: EvidenceItem, why: str) -> EvidenceRef:
    return EvidenceRef(evidence_id=i.item_id, kind="item", why_relevant=why)


# ---------------------------------------------------------------------------
# Rule A: disk space exhaustion
# ---------------------------------------------------------------------------

_DISK_SOURCES: Tuple[str, ...] = ("ipahealthcheck.system.filesystemspace", "ipahealthcheck.ds.disk_space")


_DS_STORES = {"/var/lib/dirsrv", "/dev/shm", "/var/log/dirsrv", "/var/lib/ipa/backup"}


def _disk_findings(bundle: EvidenceBundle) -> List[Finding]:
    """DiskSpaceCheck (lib389 low-disk-space lint) and FileSystemSpaceCheck (free space
    below its threshold). FileSystemSpaceCheck also WARNs 'File system X is not mounted',
    which is not space exhaustion."""

    found = _exact(bundle, "ipahealthcheck.ds.disk_space", "DiskSpaceCheck")
    # FileSystemSpaceCheck's space results carry percent_free/free_space; anything else it emits is not a
    # usage reading and must not be presented as one.
    for f in _exact(bundle, "ipahealthcheck.system.filesystemspace", "FileSystemSpaceCheck"):
        kw = f.keywords if isinstance(f.keywords, dict) else {}
        store = str(kw.get("store", kw.get("key", ""))).rstrip("/")
        # Only the file systems Directory Server itself depends on (data, logs, /dev/shm, backups); a low /tmp
        # or /var/log/audit is not a Directory Server problem.
        if ("percent_free" in kw or "free_space" in kw) and store in _DS_STORES:
            found.append(f)
    return [f for f in found if "not mounted" not in (f.message or "").lower()]


def _recheck_disk_space(bundle: EvidenceBundle) -> bool:
    findings = _disk_findings(bundle)
    if any(f.severity.rank >= Severity.WARNING.rank for f in findings):
        return False
    for item in bundle.items_by_kind("disk_usage"):
        used_percent = item.data.get("used_percent")
        if isinstance(used_percent, (int, float)) and used_percent >= 85:
            return False
    return True


class DiskSpaceExhaustionRule(DiagnosticRule):
    rule_id = "disk-space-exhaustion"
    summary = "Disk space exhaustion on a Directory Server-critical path (data, logs, /dev/shm, backups)."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        relevant = _at_least_warning(_disk_findings(bundle))
        if not relevant:
            return None

        worst = max(relevant, key=lambda f: f.severity.rank)
        disk_space_journal = _items_by_category(bundle, "dirsrv_journal_line", "disk_space")
        disk_items = bundle.items_by_kind("disk_usage")

        evidence_for = [
            _ref_f(
                worst,
                f"ipa-healthcheck {worst.qualified_check} reported {worst.severity.value}"
                f"{': ' + worst.message if worst.message else ''}",
            )
        ]
        for extra in relevant:
            if extra is not worst:
                evidence_for.append(_ref_f(extra, f"{extra.qualified_check} also reported {extra.severity.value}"))
        for item in disk_items:
            used_percent = item.data.get("used_percent") or 0
            if used_percent >= 80:
                evidence_for.append(
                    _ref_i(item, f"live df reading shows {used_percent:.0f}% used on {item.data.get('path')}")
                )
        for item in disk_space_journal:
            evidence_for.append(_ref_i(item, 'journalctl shows dirsrv actually hit "No space left on device"'))

        hard_failure = worst.severity.rank >= Severity.ERROR.rank or bool(disk_space_journal)

        if hard_failure:
            corroborated = bool(disk_space_journal) and worst.severity.rank >= Severity.ERROR.rank
            confidence_level = ConfidenceLevel.HIGH if corroborated else ConfidenceLevel.MEDIUM
            rationale = (
                "[HIGH, 389-ds-base GitHub issue #5949 documents the exact /dev/shm/slapd-<instance> "
                "'no space left on device' failure mode] both the healthcheck finding and a live journal "
                "write-failure are present."
                if disk_space_journal
                else "[MED] ipa-healthcheck already reports ERROR/CRITICAL (at/near capacity); no journal "
                "write-failure was seen yet, but the finding itself is direct, sufficient evidence on its own."
            )
            diag_severity = Severity.CRITICAL if (worst.severity == Severity.CRITICAL or disk_space_journal) else Severity.ERROR
            return Diagnosis(
                pack_id=PACK_ID,
                rule_id=self.rule_id,
                status=DiagnosisStatus.DIAGNOSED,
                title="Disk space exhaustion on a Directory Server-critical path",
                why=(
                    f"ipa-healthcheck's {worst.qualified_check} reports {worst.severity.value}-level disk usage "
                    "on a path Directory Server depends on for its data, transaction logs, or its "
                    "/dev/shm-backed shared-memory region. "
                    + (
                        "journalctl corroborates this with an actual 'No space left on device' error from "
                        "dirsrv, not just a usage percentage."
                        if disk_space_journal
                        else "No corroborating hard-failure journal entry has been seen yet, but the healthcheck "
                        "finding itself is already at ERROR/CRITICAL severity, which is sufficient evidence on "
                        "its own."
                    )
                ),
                confidence=Confidence(
                    level=confidence_level,
                    rationale=rationale,
                    corroborating_evidence_count=len(evidence_for),
                ),
                severity=diag_severity,
                evidence_for=evidence_for,
                impact=(
                    "If the affected path is /var/lib/dirsrv/ or /dev/shm, Directory Server can fail to write "
                    "changes, fail to start, or crash outright. If it is /var/log/ or /var/lib/ipa/backup/, "
                    "logging/backups start failing but DS itself may keep running a while longer."
                ),
                actions=[
                    Action(
                        description=(
                            "Identify the largest consumers under the affected path and confirm whether a "
                            "backup or log-rotation job is currently running."
                        ),
                        risk=RiskLevel.SAFE,
                        command=(
                            "du -xhd1 <affected-path> | sort -h; "
                            "systemctl list-units --type=service --state=running | grep -Ei 'backup|logrotate'"
                        ),
                        rationale="Read-only triage before changing anything.",
                    ),
                    Action(
                        description=(
                            "Free space by removing old rotated logs / expired backups under the affected path, "
                            "or extend the underlying volume."
                        ),
                        risk=RiskLevel.CAUTION,
                        rationale=(
                            "Deletes/moves data; scope it to already-rotated logs and already-expired backups "
                            "under the specific reported path and your retention policy, not a blanket cleanup."
                        ),
                    ),
                    Action(
                        description=(
                            "If /dev/shm was the affected path, restart dirsrv once space is freed so it "
                            "recreates its shared-memory region cleanly."
                        ),
                        risk=RiskLevel.CAUTION,
                        command="systemctl restart dirsrv@<instance>",
                        rationale="A running dirsrv process can keep a stale/undersized shm mapping even after space is freed.",
                    ),
                ],
                verification=[
                    VerificationCondition(
                        description=(
                            "Re-run FileSystemSpaceCheck and DiskSpaceCheck across ALL monitored paths (not just "
                            "the one that alerted) and confirm SUCCESS with a real free-space margin, not merely "
                            ">0 bytes free."
                        ),
                        recheck=_recheck_disk_space,
                        healthcheck_sources=list(_DISK_SOURCES),
                    )
                ],
                limitations=(
                    "A single df/healthcheck snapshot cannot show growth rate; re-check after the fix to confirm "
                    "the trend, not just the instantaneous reading."
                ),
                upstream_candidates=[],
            )

        # WARNING-only, single snapshot, no corroborating hard failure - don't
        # over-claim a chronic problem from one reading.
        return Diagnosis(
            pack_id=PACK_ID,
            rule_id=self.rule_id,
            status=DiagnosisStatus.TRANSIENT_SUSPECTED,
            title="Elevated disk usage on a Directory Server-critical path (possibly transient)",
            why=(
                f"ipa-healthcheck's {worst.qualified_check} reported {worst.severity.value}-level usage, but "
                "this is a single snapshot with no journalctl evidence of an actual write/space failure yet. "
                "This matches a common transient pattern (an in-progress backup, a temporary log burst, or a "
                "log-rotation job) just as well as it matches chronic unbounded growth."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.LOW,
                rationale=(
                    "[MED] A single WARNING-level usage reading without a trend/history signal or a "
                    "hard-failure journal entry cannot distinguish transient from chronic growth."
                ),
                corroborating_evidence_count=len(evidence_for),
            ),
            severity=Severity.WARNING,
            evidence_for=evidence_for,
            impact="Low immediate impact today; if usage keeps growing unchecked this can escalate to write failures or a dirsrv crash.",
            actions=[
                Action(
                    description="Re-check disk usage on the affected path in 15-30 minutes and see whether it has grown, shrunk, or stayed flat.",
                    risk=RiskLevel.SAFE,
                    command="df -h <affected-path>",
                    rationale="Distinguishes a transient spike from chronic growth without changing anything.",
                ),
                Action(
                    description="Check for an active ipa-backup job or log-rotation cycle that would explain a temporary spike.",
                    risk=RiskLevel.SAFE,
                    command="systemctl list-units --type=service --state=running | grep -Ei 'backup|logrotate'; ps aux | grep -i backup",
                    rationale="Read-only.",
                ),
            ],
            verification=[
                VerificationCondition(
                    description="Re-run FileSystemSpaceCheck/DiskSpaceCheck across all monitored paths after the recheck window and confirm SUCCESS with real margin.",
                    recheck=_recheck_disk_space,
                    healthcheck_sources=list(_DISK_SOURCES),
                )
            ],
            limitations="This pack's collector takes one snapshot per run; it cannot itself observe a trend across time.",
            next_diagnostic_step=(
                "Re-check disk usage on the affected path in 15-30 minutes (or via a second ipa-diagnose run) "
                "and check for an active backup/log-rotation job before treating this as a hard failure."
            ),
            upstream_candidates=[],
        )


# ---------------------------------------------------------------------------
# Rule B: ownership / SELinux mismatch
# ---------------------------------------------------------------------------

_FILE_SOURCE = "ipahealthcheck.ipa.files"
_FILE_CHECKS = ("IPAFileCheck", "IPAFileNSSDBCheck", "TomcatFileCheck")


def _file_findings(bundle: EvidenceBundle) -> List[Finding]:
    """Owner/group/mode results only. The same checks also report the running umask being wrong
    (which makes upstream SKIP all mode checks), code-format and unknown uid/gid problems - none of
    which is an ownership/mode mismatch of a specific file, so they are left undiagnosed."""

    out = []
    for f in _exact(bundle, _FILE_SOURCE, *_FILE_CHECKS):
        kw = f.keywords if isinstance(f.keywords, dict) else {}
        # Allowlist: upstream's owner/group/mode results carry type, path, expected and got.
        if str(kw.get("type", "")).lower() not in ("owner", "group", "mode"):
            continue
        if not all(k in kw for k in ("path", "expected", "got")):
            continue
        if str(kw.get("got", "")).lower().startswith("unknown "):  # 'Unknown uid 1234': no such account, not a mismatch of a known owner
            continue
        out.append(f)
    return out


def _permission_targets(findings: List[Finding]) -> dict:
    """Structured (path, expected, got) from ipa-healthcheck's own owner/group/mode results, one list per kind.
    Values are passed on as-is; the resolution engine validates each one by type."""

    out: dict = {"targets_mode": [], "targets_owner": [], "targets_group": []}
    seen: dict = {}
    for f in findings:
        kw = f.keywords if isinstance(f.keywords, dict) else {}
        kind = str(kw.get("type", ""))
        if kind not in ("mode", "owner", "group"):
            continue
        item = {k: kw.get(k) for k in ("path", "expected", "got")}
        key = (kind, item["path"])
        if key in seen:
            # Two results for the same file and attribute: identical ones are merged; different expected
            # values make the item unusable (never pick one).
            if seen[key]["expected"] != item["expected"]:
                seen[key]["expected"] = f"(conflicting results: {seen[key]['expected']} / {item['expected']})"
            continue
        if kind == "mode":
            item.update(_mode_delta(item["got"], item["expected"]))
        elif _is_key_material(str(item["path"])):
            item["expected"] = "(ownership of key material is not changed automatically)"
        seen[key] = item
        out[f"targets_{kind}"].append(item)
    return out


_DS_PATH_PREFIXES = ("/etc/dirsrv/", "/var/lib/dirsrv/", "/var/log/dirsrv/", "/run/dirsrv/", "/usr/lib64/dirsrv/")


def _names_any(item: EvidenceItem, paths: List[str]) -> bool:
    text = str(item.data.get("message") or item.data.get("line") or item.summary or "")
    for p in paths:
        if p and (p in text or (p.rsplit("/", 1)[0] + "/") in text):
            return True
    return False


def _can_break_ds(f: Finding) -> bool:
    """A Directory Server file whose owner/group is wrong, or whose mode is too RESTRICTIVE, can stop DS from
    reading it. A too-permissive mode cannot (it is a security problem, not an outage cause)."""

    kw = f.keywords if isinstance(f.keywords, dict) else {}
    if not str(kw.get("path") or "").startswith(_DS_PATH_PREFIXES):
        return False
    kind = str(kw.get("type", "")).lower()
    if kind in ("owner", "group"):
        return True
    return kind == "mode" and _mode_delta(str(kw.get("got")), str(kw.get("expected"))).get("loosens") != "no"


def _is_key_material(path: str) -> bool:
    """Files whose ownership is never changed automatically (keys, key databases, stash and password files)."""

    # Deliberately broad and case-insensitive: a file wrongly treated as key material only means no ownership
    # fix is shown (a mode fix, which only removes permissions, is still possible).
    low = path.lower()
    parts = low.split("/")
    name = parts[-1]
    secret_dirs = {"private", "custodia", "dnssec", "backup", "passwds", "keys", "secrets", "tokens"}
    secret_words = ("key", "pass", "pwd", "pin", "secret", "token", "ccache", "cred", "stash", "authtok", "p12", "pfx")
    return (bool(secret_dirs & set(parts[:-1])) or name.startswith(".") or any(w in name for w in secret_words)
            or name.startswith("dse.ldif") or low.startswith("/etc/sssd/"))


def _mode_delta(got, expected) -> dict:
    """Symbolic chmod that only REMOVES permissions (never adds): chmod through a swapped symlink can then only
    tighten the target. ``loosens`` is "yes" when the expected mode would add any permission."""

    import re as _re

    if not (isinstance(got, str) and isinstance(expected, str) and _re.fullmatch(r"0?[0-7]{3}", got)
            and _re.fullmatch(r"0?[0-7]{3}", expected)):
        return {"remove": "none", "restore": "none", "loosens": "unknown"}
    g, e = int(got, 8), int(expected, 8)
    removed, added = g & ~e & 0o777, e & ~g & 0o777

    def symbolic(bits: int, sign: str) -> str:
        parts = []
        for who, shift in (("u", 6), ("g", 3), ("o", 0)):
            b = (bits >> shift) & 7
            letters = "".join(ch for ch, v in (("r", 4), ("w", 2), ("x", 1)) if b & v)
            if letters:
                parts.append(f"{who}{sign}{letters}")
        return ",".join(parts) or "none"

    return {"remove": symbolic(removed, "-"), "restore": symbolic(removed, "+"), "loosens": "yes" if added else "no"}


def _recheck_ownership(bundle: EvidenceBundle) -> bool:
    if _at_least_warning(_file_findings(bundle)):
        return False
    if _items_by_category(bundle, "dirsrv_journal_line", "permission_denied"):
        return False
    if _items_by_category(bundle, "dirsrv_journal_line", "selinux"):
        return False
    return True


class OwnershipSelinuxMismatchRule(DiagnosticRule):
    rule_id = "ownership-selinux-mismatch"
    summary = "dirsrv failing with permission-denied errors: plain ownership/mode mismatch vs. an SELinux AVC denial."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        permission_journal = _items_by_category(bundle, "dirsrv_journal_line", "permission_denied")
        selinux_journal = _items_by_category(bundle, "dirsrv_journal_line", "selinux")
        file_findings = _at_least_warning(_file_findings(bundle))

        if not permission_journal and not selinux_journal and not file_findings:
            return None

        evidence_for = [
            _ref_f(f, f"{f.qualified_check} reports a file ownership/mode problem: {f.message}") for f in file_findings
        ]
        evidence_for += [
            _ref_i(i, "journalctl shows dirsrv hitting a permission-denied error at startup") for i in permission_journal
        ]
        evidence_for += [
            _ref_i(i, "journalctl shows an SELinux-flavored denial around the same time") for i in selinux_journal
        ]

        if file_findings:
            # A dirsrv journal line only corroborates a reported file it actually names (or its directory); an
            # unrelated permission error must not vouch for, say, a Tomcat file (red-team round 2).
            paths = [str((f.keywords if isinstance(f.keywords, dict) else {}).get("path") or "") for f in file_findings]
            relevant = [i for i in permission_journal + selinux_journal if _names_any(i, paths)]
            evidence_for = [r for r in evidence_for if r.kind == "finding" or any(r.evidence_id == i.item_id for i in relevant)]
            corroborated = bool(relevant)
            worst = max(file_findings, key=lambda f: f.severity.rank)
            return Diagnosis(
                pack_id=PACK_ID,
                rule_id=self.rule_id,
                status=DiagnosisStatus.DIAGNOSED,
                title="File ownership/mode mismatch on an IPA-managed security-critical file",
                why=(
                    f"ipa-healthcheck's {worst.qualified_check} directly reports an incorrect owner, group, or "
                    f"mode on a security-critical file: {worst.message}. This finding is itself direct evidence "
                    "of a plain Unix ownership/permissions problem, independent of whether SELinux is also "
                    "involved."
                    + (
                        " It is corroborated by a permission-denied/SELinux-flavored error from dirsrv in the "
                        "same window."
                        if corroborated
                        else ""
                    )
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.HIGH if corroborated else ConfidenceLevel.MEDIUM,
                    rationale=(
                        "[HIGH, ipa-healthcheck's IPAFileCheck/IPAFileNSSDBCheck/TomcatFileCheck compare against "
                        "documented owner:group:mode targets] the healthcheck finding is direct evidence of the "
                        "exact wrong value"
                        + (", corroborated by a live permission-denied error." if corroborated else ".")
                    ),
                    corroborating_evidence_count=len(evidence_for),
                ),
                severity=Severity.CRITICAL if worst.severity == Severity.CRITICAL else Severity.ERROR,
                evidence_for=evidence_for,
                impact=(
                    "dirsrv (or the RA agent / Tomcat/PKI NSS DB it depends on) can fail to start or fail to "
                    "read its own certificate material until ownership/mode is corrected."
                ),
                actions=[
                    Action(
                        description="Confirm the current owner/group/mode and SELinux context of the reported path before changing anything.",
                        risk=RiskLevel.SAFE,
                        command="ls -lZ <path-from-finding>",
                        rationale="Read-only confirmation of the exact current state.",
                    ),
                    Action(
                        description="chown/chmod the file to the owner:group:mode ipa-healthcheck reports as correct.",
                        risk=RiskLevel.CAUTION,
                        command="chown <expected-owner>:<expected-group> <path>; chmod <expected-mode> <path>",
                        rationale=(
                            "Changes file state, but is scoped to exactly the file the finding names and the "
                            "value it already told us is correct - reversible and well-understood, not "
                            "exploratory."
                        ),
                    ),
                    Action(
                        description="If SELinux is enforcing, also restore the expected SELinux context on that same path (do not run this fleet-wide).",
                        risk=RiskLevel.CAUTION,
                        command="restorecon -Rv <path>",
                        rationale="Scoped relabel of the one affected path; broad/blind restorecon runs are out of scope for an automated suggestion.",
                    ),
                ],
                verification=[
                    VerificationCondition(
                        description=(
                            "Confirm dirsrv actually starts (not just that `ls -lZ` shows corrected labels), and "
                            "that no new AVC denials appear in journalctl in a subsequent window."
                        ),
                        recheck=_recheck_ownership,
                        healthcheck_sources=[_FILE_SOURCE],
                    )
                ],
                limitations=(
                    "This pack has no ausearch/AVC collector; 'no new AVC denials' can only be confirmed by the "
                    "administrator via `ausearch -m avc -ts recent`, not by this tool."
                ),
                upstream_candidates=[],
                resolution_key="directory-server.ipa-file-permissions",
                bindings=_permission_targets(file_findings),
                # Only Directory Server's own files (or dirsrv logging permission errors) can break DS and so
                # explain other packs' symptoms; a PKI/httpd/IPA file mode cannot.
                evidence_severity=worst.severity,
                explains_downstream=bool(relevant) or any(_can_break_ds(f) for f in file_findings),
            )

        # No IPAFileCheck-style finding naming an exact wrong value - just a
        # generic permission-denied and/or SELinux-flavored journal line.
        # This is genuinely ambiguous: plain Unix permissions and an SELinux
        # AVC denial need different fixes, and we cannot tell them apart from
        # this evidence alone.
        return Diagnosis(
            pack_id=PACK_ID,
            rule_id=self.rule_id,
            status=DiagnosisStatus.UNKNOWN_INSUFFICIENT_EVIDENCE,
            title="dirsrv permission-denied error: cause not yet distinguishable (Unix perms vs. SELinux)",
            why=(
                "journalctl shows dirsrv hitting a permission-denied style error, but there is no corroborating "
                "ipa-healthcheck IPAFileCheck/IPAFileNSSDBCheck finding naming a specific wrong owner/group/mode. "
                "A generic 'Permission denied' is ambiguous between a plain Unix ownership/mode problem and an "
                "SELinux AVC denial - they require different fixes (chown/chmod vs. restorecon/policy) - and "
                "this pack has no ausearch-based collector to disambiguate automatically."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.LOW,
                rationale=(
                    "[HIGH that the ambiguity itself is a well-documented failure mode, per 389-ds-base GitHub "
                    "#583 (rundir permissions) and #4714/#4717 (podman SELinux relabeling), and Red Hat KCS "
                    "2700931; LOW confidence in any specific root cause without ls -lZ / ausearch output.]"
                ),
                corroborating_evidence_count=len(evidence_for),
            ),
            severity=Severity.ERROR,
            evidence_for=evidence_for,
            impact="dirsrv may fail to start or fail to access its own rundir/NSS DB files until the underlying cause is identified and fixed.",
            actions=[
                Action(
                    description="Check both ownership/mode AND SELinux context on the paths dirsrv logged trouble with.",
                    risk=RiskLevel.SAFE,
                    command="ls -lZ /var/lib/dirsrv/slapd-*/ /etc/dirsrv/slapd-*/",
                    rationale="Read-only; shows owner:group:mode and SELinux label in one command.",
                ),
                Action(
                    description="Check for AVC denials in the same time window as the journal error.",
                    risk=RiskLevel.SAFE,
                    command="ausearch -m avc -ts recent",
                    rationale="Read-only; the only reliable way to confirm/rule out SELinux as the cause.",
                ),
            ],
            verification=[],
            limitations=(
                "Without an ausearch/AVC collector this pack cannot itself distinguish a Unix-permission cause "
                "from an SELinux cause; the two read-only commands above must be run and reviewed by an "
                "administrator."
            ),
            next_diagnostic_step=(
                "Run `ls -lZ` on the paths dirsrv logged trouble with and `ausearch -m avc -ts recent` to "
                "determine whether this is a plain ownership/mode problem or an SELinux denial before choosing a "
                "fix."
            ),
            upstream_candidates=[],
        )


# ---------------------------------------------------------------------------
# Rule C: NSS/TLS DB format issue
# ---------------------------------------------------------------------------

_NSS_SOURCE = "ipahealthcheck.ds.nss"
# ipahealthcheck.ds.nss_ssl.NssCheck is NOT an NSS-DB-format check: it reports Directory Server
# certificate EXPIRY (lib389 DSCERTLE0001/0002). The old rule matched it by source prefix and told
# administrators with an expired DS certificate that it was "not a certificate lifecycle problem".
_DS_CERT_SOURCE = "ipahealthcheck.ds.nss_ssl"
_DS_CERT_CHECK = "NssCheck"
_CERT_SOURCES: Tuple[str, ...] = ("ipahealthcheck.ipa.certs", "ipahealthcheck.dogtag.ca")


def _ds_cert_expiry_findings(bundle: EvidenceBundle) -> List[Finding]:
    """NssCheck results that are the documented lib389 expiry results (DSCERTLE0001/0002)."""

    out = []
    for f in _at_least_warning(_exact(bundle, _DS_CERT_SOURCE, _DS_CERT_CHECK)):
        key = str(f.keywords.get("key", "")) if isinstance(f.keywords, dict) else ""
        text = (f.message or "").lower()
        if key in ("DSCERTLE0001", "DSCERTLE0002") or "has expired" in text or "will expire" in text:
            out.append(f)
    return out


def _recheck_nss(bundle: EvidenceBundle) -> bool:
    if False:  # noqa: SIM223 - deliberately inert: ipa-healthcheck has no NSS DB-format check; journal evidence only
        return False
    if _items_by_category(bundle, "dirsrv_journal_line", "nss_tls"):
        return False
    return True


class NssTlsDbFormatRule(DiagnosticRule):
    rule_id = "nss-tls-db-format"
    summary = "NSS/TLS DB format mismatch (legacy cert8.db/key3.db vs. cert9.db/key4.db) masquerading as a certificate problem."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        nss_findings: List[Finding] = []  # no ipa-healthcheck check reports a DB-format problem
        tls_journal = _items_by_category(bundle, "dirsrv_journal_line", "nss_tls")
        if not nss_findings and not tls_journal:
            return None

        # A Directory Server certificate-expiry result (NssCheck) or any certs/dogtag finding contradicts a
        # pure DB-format explanation.
        # Any Directory Server certificate-check (NssCheck) result also counts: it is a certificate signal,
        # so a DB-format story is never asserted confidently next to it.
        cert_expiry_findings = _at_least_warning(
            _findings(bundle, *_CERT_SOURCES) + _exact(bundle, _DS_CERT_SOURCE, _DS_CERT_CHECK)
        )

        evidence_for = [_ref_f(f, f"{f.qualified_check} reported {f.severity.value}: {f.message}") for f in nss_findings]
        evidence_for += [_ref_i(i, "journalctl shows a TLS/NSS-flavored failure from dirsrv") for i in tls_journal]

        cross_pack_note = (
            "This can look exactly like an expired certificate or a broken CA trust chain, but a local NSS "
            "database format mismatch (legacy cert8.db/key3.db vs. modern cert9.db/key4.db SQLite format, "
            "typically surfacing after an NSS library upgrade or a restart) is a completely different, "
            "unrelated root cause. Check the certificates pack's output too before assuming this is a "
            "certificate lifecycle problem."
        )

        # A TLS handshake/alert line is routine (client aborts, scanners). Only an
        # ipa-healthcheck NSS result, or a journal line that actually names the
        # legacy/modern NSS DB files, supports a DB-format diagnosis.
        import re as _re

        db_format_journal = [
            i
            for i in tls_journal
            if _re.search(r"SEC_ERROR_BAD_DATABASE|SEC_ERROR_LEGACY_DATABASE|SEC_ERROR_NO_MODULE", f"{i.data.get('message', '')} {i.summary}", _re.I)
            or _re.search(
                r"(cert8|key3|secmod|cert9|key4)"+"\\"+"."+r"(db|sqlite).{0,120}(error|fail\w*|unable|cannot|could not|not found|missing|corrupt\w*)|(error|fail\w*|unable|cannot|could not|not found|missing|corrupt\w*).{0,120}(cert8|key3|secmod|cert9|key4)"+"\\"+"."+r"(db|sqlite)",
                f"{i.data.get('message', '')} {i.summary}",
                _re.I,
            )
        ]
        if nss_findings or (db_format_journal and not cert_expiry_findings):
            corroborated = bool(nss_findings and tls_journal)
            return Diagnosis(
                pack_id=PACK_ID,
                rule_id=self.rule_id,
                status=DiagnosisStatus.DIAGNOSED,
                title="Likely NSS/TLS DB format mismatch, not a certificate lifecycle problem",
                why=(
                    (
                        "ipa-healthcheck's ds.nss check reported a problem with the Directory Server NSS DB. "
                        if nss_findings
                        else (
                            "journalctl shows dirsrv hitting a TLS/NSS-flavored failure, and no "
                            "certificate-expiry finding is present anywhere in this run to explain it via "
                            "simple expiry. "
                        )
                    )
                    + cross_pack_note
                ),
                confidence=Confidence(
                    level=ConfidenceLevel.HIGH if corroborated else ConfidenceLevel.MEDIUM,
                    rationale=(
                        "[HIGH, 389-ds-base GitHub #2100 / Pagure #49041 document this exact cert8.db/key3.db "
                        "vs. cert9.db/key4.db mismatch causing certs to 'vanish' after a restart or NSS library "
                        "upgrade] "
                        + (
                            "both the NssCheck finding and a TLS journal error are present."
                            if corroborated
                            else "only one of the two signals (NssCheck finding or TLS journal error) is present."
                        )
                    ),
                    corroborating_evidence_count=len(evidence_for),
                ),
                severity=Severity.ERROR,
                evidence_for=evidence_for,
                impact="LDAPS/StartTLS binds to Directory Server fail until the NSS DB format issue is resolved, even though the certificate itself may be perfectly valid.",
                actions=[
                    Action(
                        description="Confirm which NSS DB format is actually on disk.",
                        risk=RiskLevel.SAFE,
                        command=(
                            "ls /etc/dirsrv/slapd-*/ | grep -E 'cert8\\.db|cert9\\.db|key3\\.db|key4\\.db'; "
                            "certutil -L -d sql:/etc/dirsrv/slapd-<instance>"
                        ),
                        rationale="Distinguishes legacy Berkeley-DB format from the modern SQLite format before touching anything.",
                    ),
                    Action(
                        description="Re-import the certificate/key into the SQL-format NSS DB with the proper sql: prefix.",
                        risk=RiskLevel.CAUTION,
                        command="certutil -A -d sql:/etc/dirsrv/slapd-<instance> -n <nickname> -t ',,' -a -i <cert-file>",
                        rationale="Reversible/scoped: re-imports known-good material into the correct DB format; does not touch certificate validity or CA trust.",
                        reference="389-ds-base GitHub #2100 / Pagure #49041",
                    ),
                    Action(
                        description="Restart dirsrv so it resyncs its in-memory certificate state with the on-disk NSS DB.",
                        risk=RiskLevel.CAUTION,
                        command="systemctl restart dirsrv@<instance>",
                        rationale="Easy to skip and looks like 'the fix didn't work' if missed - dirsrv does not pick up NSS DB changes without a restart.",
                    ),
                ],
                verification=[
                    VerificationCondition(
                        description=(
                            "After restarting dirsrv, confirm an actual LDAPS handshake succeeds (openssl "
                            "s_client / ldapsearch -H ldaps://), not just that certutil -L lists the "
                            "certificate."
                        ),
                        recheck=_recheck_nss,
                        healthcheck_sources=[_NSS_SOURCE],
                    )
                ],
                limitations=(
                    "This pack has no ldap-query/TLS-handshake collector in v1, so the LDAPS-handshake "
                    "verification step above must be run and confirmed manually; recheck() here can only "
                    "confirm the NssCheck finding cleared and no new TLS journal errors appeared."
                ),
                upstream_candidates=[],
            )

        # A generic TLS journal line WITHOUT a certificate finding is routine noise
        # (client aborts, scanners): it supports neither cause, so say nothing.
        if not cert_expiry_findings:
            return None
        # Both a TLS journal failure and a certificate-expiry finding are
        # present: either could explain the symptom and we cannot rank one
        # over the other from this evidence alone.
        return Diagnosis(
            pack_id=PACK_ID,
            rule_id=self.rule_id,
            status=DiagnosisStatus.UNKNOWN_CONFLICTING_EVIDENCE,
            title="TLS failure on Directory Server: certificate expiry and NSS DB format are both plausible",
            why=(
                "journalctl shows a TLS/NSS-flavored failure from dirsrv, but a certificate-expiry finding is "
                "also present elsewhere in this run. " + cross_pack_note
            ),
            confidence=Confidence(
                level=ConfidenceLevel.LOW,
                rationale="[MED] Two candidate explanations are present concurrently; evidence in this bundle cannot rank one over the other.",
                corroborating_evidence_count=len(evidence_for),
                contradicting_evidence_count=len(cert_expiry_findings),
            ),
            severity=Severity.ERROR,
            evidence_for=evidence_for,
            evidence_against=[
                _ref_f(
                    f,
                    f"{f.qualified_check} reports a certificate-expiry-flavored problem, which alone could also explain the TLS failure",
                )
                for f in cert_expiry_findings
            ],
            impact="LDAPS/StartTLS binds to Directory Server are failing; the fix differs completely depending on which cause is real.",
            actions=[
                Action(
                    description="Check actual certificate validity dates directly.",
                    risk=RiskLevel.SAFE,
                    command="certutil -L -d sql:/etc/dirsrv/slapd-<instance> -n <nickname> | grep -A2 Validity",
                    rationale="Read-only; rules expiry in or out.",
                ),
                Action(
                    description="Check on-disk NSS DB format alongside the certificates pack's own diagnosis.",
                    risk=RiskLevel.SAFE,
                    command="ls /etc/dirsrv/slapd-*/ | grep -E 'cert8\\.db|cert9\\.db|key3\\.db|key4\\.db'",
                    rationale="Read-only; rules the DB-format mismatch in or out.",
                ),
            ],
            verification=[],
            limitations="This pack cannot itself check certificate validity dates; see the certificates pack's diagnosis for that.",
            next_diagnostic_step=(
                "Check certificate validity dates (certutil -L ... | grep -A2 Validity) and on-disk NSS DB "
                "format together - and read the certificates pack's own diagnosis for this run - before "
                "deciding between a cert-lifecycle fix and an NSS DB format fix."
            ),
            upstream_candidates=[],
        )


# ---------------------------------------------------------------------------
# Rule D: index / backend health
# ---------------------------------------------------------------------------

_BACKENDS_SOURCE = "ipahealthcheck.ds.backends"


def _recheck_backends(bundle: EvidenceBundle) -> bool:
    return not _at_least_warning(_findings(bundle, _BACKENDS_SOURCE))


class IndexBackendHealthRule(DiagnosticRule):
    rule_id = "missing-system-index"
    summary = "Missing/misconfigured system index reported by ipa-healthcheck's BackendsCheck (DSBLE0007)."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        # BackendsCheck emits several different results; only the documented
        # DSBLE0007 (missing system index) supports this diagnosis. Any other
        # backend result is left to the unexplained-findings safety net.
        relevant = [
            f
            for f in _at_least_warning(_exact(bundle, _BACKENDS_SOURCE, "BackendsCheck"))
            if isinstance(f.keywords, dict) and f.keywords.get("key") == "DSBLE0007"
        ]
        if not relevant:
            return None

        worst = max(relevant, key=lambda f: f.severity.rank)
        attribute = (
            worst.keywords.get("attr")
            or worst.keywords.get("attribute")
            or worst.keywords.get("index")
            or "the affected attribute"
        )
        evidence_for = [
            _ref_f(worst, f"{worst.qualified_check} reports a missing/misconfigured system index: {worst.message}")
        ]
        evidence_for += [_ref_f(f, f"{f.qualified_check} also reported {f.severity.value}") for f in relevant if f is not worst]

        return Diagnosis(
            pack_id=PACK_ID,
            rule_id=self.rule_id,
            status=DiagnosisStatus.DIAGNOSED,
            title="Missing or misconfigured system index on a Directory Server backend",
            why=(
                f"ipa-healthcheck's {worst.qualified_check} reports a missing/misconfigured system index "
                f"({worst.message}), matching the well-documented DSBLE0007 error key for BackendsCheck (Red "
                "Hat KCS 7132895). Missing system indexes (entryrdn, parentId, objectClass, aci, nsUniqueId, "
                "nsds5ReplConflict, etc.) cause unindexed searches and degraded/failed operations on that "
                "backend."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.HIGH,
                rationale="[HIGH, Red Hat KCS 7132895 documents this exact ipa-healthcheck BackendsCheck/DSBLE0007 finding] the healthcheck finding directly names the missing index.",
                corroborating_evidence_count=len(evidence_for),
            ),
            severity=Severity.CRITICAL if worst.severity == Severity.CRITICAL else Severity.ERROR,
            evidence_for=evidence_for,
            impact="Searches relying on the missing index become unindexed (slow, resource-intensive, and subject to the server's unindexed-search size limit) until it is rebuilt.",
            actions=[
                Action(
                    description="Confirm exactly which backend/attribute is affected and its current index configuration.",
                    risk=RiskLevel.SAFE,
                    command="ipa-healthcheck --source ipahealthcheck.ds.backends --output-type json; dsconf <instance> backend index list <backend>",
                    rationale="Read-only confirmation before reindexing anything.",
                ),
                Action(
                    description=(
                        f"Reindex only the specific missing attribute ({attribute}); the attribute names are in the "
                        "finding's discrepancy details."
                    ),
                    risk=RiskLevel.CAUTION,
                    command=f"db2index.pl -Z <instance> -t {safe_token(attribute, '<attribute>')}",
                    rationale="Scoped to one attribute per port389.org guidance. db2index runs OFFLINE: plan a maintenance window for that Directory Server instance (newer 389-DS releases offer dsconf/dsctl equivalents). It does not touch replication state.",
                ),
                Action(
                    description="Avoid: do not run db2index.pl/db2index with no arguments/target attribute to 'reindex everything'.",
                    risk=RiskLevel.HIGH_RISK,
                    command="db2index.pl (bare, no -t)",
                    rationale="Never run without specifying a target attribute - running it bare can break replication (389-ds-base #1914) via RUV/tombstone side effects.",
                    reference="389-ds-base GitHub issue #1914",
                ),
            ],
            verification=[
                VerificationCondition(
                    description="Re-run BackendsCheck and confirm SUCCESS.",
                    recheck=_recheck_backends,
                    healthcheck_sources=[_BACKENDS_SOURCE],
                )
            ],
            limitations=(
                "Ideally you would also confirm no new 'unindexed search' warnings appear in the access log "
                "under normal query patterns after reindexing; that requires an access-log collector, which is "
                "out of this pack's collector scope in v1."
            ),
            upstream_candidates=[],
        )


def _recheck_ds_certificate(bundle: EvidenceBundle) -> bool:
    return not _at_least_warning(_exact(bundle, _DS_CERT_SOURCE, _DS_CERT_CHECK))


class DsCertificateExpiryRule(DiagnosticRule):
    rule_id = "ds-certificate-expiry"
    summary = "A Directory Server certificate has expired or expires within 30 days (ipa-healthcheck NssCheck)."

    def evaluate(self, bundle: EvidenceBundle) -> Optional[Diagnosis]:
        # Only the documented lib389 expiry results; any other NssCheck result stays undiagnosed.
        relevant = _ds_cert_expiry_findings(bundle)
        if not relevant:
            return None

        def _expired(f: Finding) -> bool:
            key = str(f.keywords.get("key", "")) if isinstance(f.keywords, dict) else ""
            return key == "DSCERTLE0002" or "has expired" in (f.message or "").lower()

        any_expired = any(_expired(f) for f in relevant)
        worst = max(relevant, key=lambda f: f.severity.rank)
        keys = {str(f.keywords.get("key", "")) if isinstance(f.keywords, dict) else "" for f in relevant}
        # The procedure variant is decided by lib389's own result key, never by message wording.
        variant = "expired" if "DSCERTLE0002" in keys else ("expiring" if keys == {"DSCERTLE0001"} else None)
        nickname = None
        if len(relevant) == 1:
            m = re.match(r"^\s*The certificate \(([^)]{1,64})\) (?:will expire|has expired)", relevant[0].message or "")
            nickname = m.group(1) if m else None
        state = "has EXPIRED" if any_expired else "expires within 30 days"
        return Diagnosis(
            pack_id=PACK_ID,
            rule_id=self.rule_id,
            status=DiagnosisStatus.DIAGNOSED,
            title="Directory Server certificate has expired" if any_expired else "Directory Server certificate expires within 30 days",
            why=(
                f"ipa-healthcheck ({worst.qualified_check}, lib389 certificate lint) directly reports that a Directory "
                f"Server certificate {state}: {' '.join((worst.message or '').split())[:200]}. This is the check's own "
                "statement about the certificate, not an inference."
            ),
            confidence=Confidence(
                level=ConfidenceLevel.HIGH,
                rationale="Direct report from ipa-healthcheck's Directory Server certificate check (DSCERTLE0001/0002).",
                corroborating_evidence_count=len(relevant),
            ),
            severity=worst.severity if worst.severity.rank >= Severity.WARNING.rank else Severity.ERROR,
            evidence_for=[_ref_f(f, f"{f.qualified_check} reports: {f.message}") for f in relevant],
            impact=(
                "TLS/LDAPS connections to this Directory Server can fail or be refused by clients once the certificate "
                "is expired; replication and other services that bind over TLS may be affected."
            ),
            actions=[
                Action(
                    description="List the certificates in the Directory Server NSS database and their validity dates.",
                    risk=RiskLevel.SAFE,
                    command="certutil -L -d /etc/dirsrv/slapd-<INSTANCE>",
                    rationale="Read-only: shows which certificate and its dates.",
                ),
                Action(
                    description="See whether certmonger tracks the certificate and what state its renewal is in.",
                    risk=RiskLevel.SAFE,
                    command="getcert list",
                    rationale="Read-only: shows tracking requests and their status/errors.",
                ),
            ],
            verification=[
                VerificationCondition(
                    description="Re-run the Directory Server certificate check and confirm it reports SUCCESS.",
                    recheck=_recheck_ds_certificate,
                    healthcheck_sources=[_DS_CERT_SOURCE],
                )
            ],
            limitations="This does not establish WHY the certificate was not renewed; check certmonger and the CA next.",
            upstream_candidates=[],
            resolution_key="directory-server.certificate-expiry",
            variant=variant,
            bindings={"nickname": nickname} if nickname else {},
        )


PACK = DiagnosticPack(
    pack_id=PACK_ID,
    version="1",
    display_name="Directory Server / LDAP",
    rules=[
        DiskSpaceExhaustionRule(),
        OwnershipSelinuxMismatchRule(),
        NssTlsDbFormatRule(),
        IndexBackendHealthRule(),
        DsCertificateExpiryRule(),
    ],
    healthcheck_sources=[
        "ipahealthcheck.ds.backends",
        "ipahealthcheck.ds.config",
        "ipahealthcheck.ds.dse",
        "ipahealthcheck.ds.encryption",
        "ipahealthcheck.ds.nss_ssl",
        "ipahealthcheck.ds.disk_space",
        "ipahealthcheck.system.filesystemspace",
        "ipahealthcheck.ipa.files",
    ],
    additional_collectors=["filesystem", "journal_dirsrv"],
)
