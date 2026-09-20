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
from typing import List, Optional

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

    _collect_healthcheck(bundle, live=live, fixture_path=fixture_path)
    _collect_staged(bundle, fixture_path=fixture_path)
    return bundle


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
