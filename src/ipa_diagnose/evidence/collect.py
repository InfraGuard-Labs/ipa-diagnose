"""Evidence collection orchestration: healthcheck + staged targeted collectors.

Flow:
  1. Always collect ipa-healthcheck JSON (live: subprocess; --replay: read
     <fixture_dir>/healthcheck.json if present).
  2. Determine which packs have at least one WARNING-or-worse finding among
     their declared healthcheck_sources.
  3. Only for those packs, run their declared additional_collectors - this is
     the "collect additional evidence based on detected conditions" behavior;
     a healthy system never triggers journalctl/getcert/dig collection at all.
  4. Every failure (subprocess error, missing binary, permission denied,
     missing/malformed fixture) becomes a CollectionError on the bundle
     rather than aborting the run - degrade visibly, don't crash.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import socket
import subprocess
from typing import Dict, List, Optional

from ipa_diagnose.evidence.collectors.base import CollectorError, run_collector
from ipa_diagnose.evidence.collectors.registry import get as get_collector
from ipa_diagnose.evidence.environment import detect_environment
from ipa_diagnose.evidence.healthcheck import parse_healthcheck_json_text, parse_healthcheck_results
from ipa_diagnose.evidence.model import CollectionError, EvidenceBundle, Severity
from ipa_diagnose.engine.registry import all_packs

HEALTHCHECK_COMMAND = ["ipa-healthcheck", "--output-type", "json"]


def collect_evidence(*, replay_dir: Optional[str] = None) -> EvidenceBundle:
    live = replay_dir is None
    fixture_path = pathlib.Path(replay_dir) if replay_dir else None
    hostname = _resolve_hostname(fixture_path)

    bundle = EvidenceBundle(
        hostname=hostname,
        collected_at=EvidenceBundle.now(),
        replay_source=str(fixture_path) if fixture_path else None,
    )

    # Best-effort; detect_environment() never raises - a detection failure
    # must never prevent diagnosis from running.
    bundle.environment = detect_environment(fixture_path=fixture_path)

    if fixture_path is not None and not fixture_path.is_dir():
        # A --replay of a directory that does not exist must never look healthy.
        bundle.collection_errors.append(
            CollectionError(collector="ipa-healthcheck", message=f"replay directory not found: {fixture_path}")
        )

    before = _unit_state("certmonger.service") if live else None
    _collect_healthcheck(bundle, live=live, fixture_path=fixture_path)
    if live and any(e.collector == "ipa-healthcheck" for e in bundle.collection_errors):
        bundle.service_states = _ipa_unit_states()
    _collect_staged(bundle, fixture_path=fixture_path)
    if live:
        # measured after every collector (getcert can activate certmonger over D-Bus too - round-9 review)
        after = _unit_state("certmonger.service")
        if before in ("inactive", "failed") and after == "active":
            # Upstream ipalib's certmonger client starts certmonger when it is not running, and ipa-healthcheck's
            # certificate checks use it. ipa-diagnose itself changed nothing, but the administrator must know.
            bundle.side_effects.append(
                "certmonger was not running when ipa-diagnose started and is running now: ipa-healthcheck's "
                "certificate checks (or getcert) start it (upstream FreeIPA behaviour). ipa-diagnose itself changed "
                "nothing.")
    return bundle


_STATE_RE = __import__("re").compile(r"^[a-z-]{1,20}$")


def _unit_state(unit: str) -> Optional[str]:
    """ActiveState of a unit that exists (`systemctl show`, read-only). None when it cannot be read or the unit is
    not loaded - systemd reports "inactive" for a unit that does not exist at all (round-9 review)."""

    if shutil.which("systemctl") is None:
        return None
    try:
        proc = subprocess.run(["systemctl", "show", "-p", "LoadState,ActiveState", unit], capture_output=True,
                              text=True, timeout=10, stdin=subprocess.DEVNULL, errors="replace")
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    fields = dict(ln.split("=", 1) for ln in (proc.stdout or "").splitlines() if "=" in ln)
    if fields.get("LoadState") != "loaded":
        return None
    state = fields.get("ActiveState", "")
    return state if _STATE_RE.fullmatch(state) else None


def _ipa_unit_states() -> Dict[str, str]:
    """When ipa-healthcheck produced nothing, ipa-diagnose still reads (never changes) the state of the IPA
    units itself, so a stopped service is named instead of hidden behind "could not be verified"."""

    units = ["krb5kdc.service", "kadmin.service", "httpd.service", "named.service", "named-pkcs11.service",
             "ipa-custodia.service", "pki-tomcatd@pki-tomcat.service", "certmonger.service", "sssd.service"]
    try:
        units = [f"dirsrv@{p.name[len('slapd-'):]}.service" for p in sorted(pathlib.Path("/etc/dirsrv").glob("slapd-*"))
                 if p.name != "slapd-snmp"] + units
    except OSError:
        pass
    out: Dict[str, str] = {}
    for u in units:
        state = _unit_state(u)
        if state is not None and state != "unknown":
            out[u] = state
    return out


def healthcheck_coverage_gap(findings) -> Optional[str]:
    """A full ipa-healthcheck run on a server always reports Directory Server (ipahealthcheck.ds.*) and IPA
    (ipahealthcheck.ipa.*) checks. Output without either family (for example restricted to the service
    checks) must not be read as a healthy server."""

    sources = {str(f.source) for f in findings}
    missing = [fam for fam in ("ipahealthcheck.ds.", "ipahealthcheck.ipa.") if not any(s.startswith(fam) for s in sources)]
    if missing:
        return ("ipa-healthcheck reported no " + " and no ".join(m + "* checks" for m in missing)
                + "; a full run always does, so health cannot be verified from this output")
    return None


def _resolve_hostname(fixture_path: Optional[pathlib.Path]) -> str:
    if fixture_path is not None:
        meta_file = fixture_path / "meta.json"
        if meta_file.exists():
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                if isinstance(meta, dict) and "hostname" in meta:
                    return str(meta["hostname"])
            except (json.JSONDecodeError, OSError, ValueError, RecursionError):
                pass
        return fixture_path.name
    return socket.gethostname()


def _collect_healthcheck(bundle: EvidenceBundle, *, live: bool, fixture_path: Optional[pathlib.Path]) -> None:
    if live:
        if shutil.which("ipa-healthcheck") is None:
            bundle.collection_errors.append(
                CollectionError(
                    collector="ipa-healthcheck",
                    message="ipa-healthcheck is not installed or not on PATH",
                )
            )
            return
        try:
            proc = subprocess.run(
                HEALTHCHECK_COMMAND,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                text=True,
                errors="replace",
                timeout=120,
                check=False,
            )
        except (OSError, ValueError, subprocess.SubprocessError) as e:
            bundle.collection_errors.append(CollectionError(collector="ipa-healthcheck", message=str(e)))
            return
        if proc.returncode not in (0, 1):
            permission_related = "permission" in proc.stderr.lower() or "root" in proc.stderr.lower()
            bundle.collection_errors.append(
                CollectionError(
                    collector="ipa-healthcheck",
                    message=f"exited {proc.returncode}: {proc.stderr.strip()[:300]}",
                    permission_related=permission_related,
                )
            )
            return
        if not (proc.stdout or "").strip():
            bundle.collection_errors.append(
                CollectionError(
                    collector="ipa-healthcheck",
                    message="ipa-healthcheck produced no output (it normally needs root)",
                    permission_related=True,
                )
            )
            return
        try:
            raw_results = parse_healthcheck_json_text(proc.stdout)
        except (ValueError, RecursionError, json.JSONDecodeError) as e:
            bundle.collection_errors.append(
                CollectionError(collector="ipa-healthcheck", message=f"could not parse output: {e}")
            )
            return
        # Zero usable results means NO check actually ran: that is not health.
        # (A real run always contains many SUCCESS entries.) Skipped entries
        # are recorded too, so a partly unreadable output is never "complete".
        usable = [r for r in raw_results if isinstance(r, dict)]
        if not usable:
            bundle.collection_errors.append(
                CollectionError(collector="ipa-healthcheck", message="ipa-healthcheck returned no usable results")
            )
            return
        if len(usable) != len(raw_results):
            bundle.collection_errors.append(
                CollectionError(
                    collector="ipa-healthcheck",
                    message=f"{len(raw_results) - len(usable)} ipa-healthcheck result entries could not be read",
                )
            )
        parsed = parse_healthcheck_results(
            raw_results, command=" ".join(HEALTHCHECK_COMMAND), live=True, host=bundle.hostname
        )
        bundle.findings.extend(parsed)
        # A real run always includes the core service checks. Output that ran
        # only some unrelated check is not evidence of health.
        if not any(f.source.endswith("meta.services") for f in parsed):
            bundle.collection_errors.append(
                CollectionError(
                    collector="ipa-healthcheck",
                    message="ipa-healthcheck did not report the core service checks (incomplete output)",
                )
            )
        gap = healthcheck_coverage_gap(parsed)
        if gap:
            # Not a collection failure (what was reported is still used), but health cannot be "complete".
            bundle.collection_errors.append(CollectionError(collector="ipa-healthcheck-coverage", message=gap))
    else:
        hc_file = fixture_path / "healthcheck.json"
        if not hc_file.exists():
            bundle.collection_errors.append(
                CollectionError(collector="ipa-healthcheck", message=f"no healthcheck.json in replay directory {fixture_path}")
            )
            return
        try:
            raw_results = json.loads(hc_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            bundle.collection_errors.append(
                CollectionError(collector="ipa-healthcheck", message=f"malformed fixture {hc_file}: {e}")
            )
            return
        if not isinstance(raw_results, list):
            bundle.collection_errors.append(
                CollectionError(collector="ipa-healthcheck", message=f"fixture {hc_file} is not a JSON array")
            )
            return
        # Same guards as the live path: zero usable results is not health, and unreadable entries are recorded.
        usable = [r for r in raw_results if isinstance(r, dict)]
        if not usable:
            bundle.collection_errors.append(
                CollectionError(collector="ipa-healthcheck", message=f"fixture {hc_file} contains no usable results")
            )
            return
        if len(usable) != len(raw_results):
            bundle.collection_errors.append(
                CollectionError(
                    collector="ipa-healthcheck",
                    message=f"{len(raw_results) - len(usable)} ipa-healthcheck result entries could not be read",
                )
            )
        replayed = parse_healthcheck_results(raw_results, command=f"--replay {hc_file}", live=False, host=bundle.hostname)
        bundle.findings.extend(replayed)
        # Same as the live path: output without the core service checks is not evidence of health.
        if not any(f.source.endswith("meta.services") for f in replayed):
            bundle.collection_errors.append(
                CollectionError(
                    collector="ipa-healthcheck",
                    message="ipa-healthcheck did not report the core service checks (incomplete output)",
                )
            )


def _collect_staged(bundle: EvidenceBundle, *, fixture_path: Optional[pathlib.Path]) -> None:
    collector_names: List[str] = []
    for pack in all_packs():
        # unconditional_collectors run every time, regardless of trigger
        # state - see DiagnosticPack.unconditional_collectors for why this
        # narrow exception exists (standalone stale-RUV discoverability).
        collector_names.extend(pack.unconditional_collectors)
        has_trigger = any(
            f.severity.rank >= Severity.WARNING.rank and any(f.source.startswith(s) for s in pack.healthcheck_sources)
            for f in bundle.findings
        )
        if has_trigger:
            collector_names.extend(pack.additional_collectors)

    for name in dict.fromkeys(collector_names):
        collector = get_collector(name)
        if collector is None:
            bundle.collection_errors.append(
                CollectionError(collector=name, message="collector is not registered (internal configuration error)")
            )
            continue
        try:
            items = run_collector(collector, replay_dir=fixture_path)
        except CollectorError as e:
            bundle.collection_errors.append(
                CollectionError(collector=name, message=str(e), permission_related=e.permission_related)
            )
            # A collector that makes more than one independent sub-call may
            # have partially succeeded even though it's reporting failure
            # overall (see CollectorError.partial_items) - don't discard
            # evidence that was genuinely collected just because a sibling
            # sub-call failed.
            bundle.items.extend(e.partial_items)
            continue
        except Exception as e:  # noqa: BLE001 - any collector bug must degrade visibly, never crash the run
            bundle.collection_errors.append(
                CollectionError(collector=name, message=f"unexpected {type(e).__name__} while collecting evidence")
            )
            continue
        bundle.items.extend(items)
