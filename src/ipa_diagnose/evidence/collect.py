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

    _collect_healthcheck(bundle, live=live, fixture_path=fixture_path)
    _collect_staged(bundle, fixture_path=fixture_path)
    return bundle


def _resolve_hostname(fixture_path: Optional[pathlib.Path]) -> str:
    if fixture_path is not None:
        meta_file = fixture_path / "meta.json"
        if meta_file.exists():
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                if "hostname" in meta:
                    return str(meta["hostname"])
            except (json.JSONDecodeError, OSError):
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
                HEALTHCHECK_COMMAND, capture_output=True, text=True, timeout=120, check=False
            )
        except (OSError, subprocess.SubprocessError) as e:
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
        try:
            raw_results = parse_healthcheck_json_text(proc.stdout)
        except (ValueError, json.JSONDecodeError) as e:
            bundle.collection_errors.append(
                CollectionError(collector="ipa-healthcheck", message=f"could not parse output: {e}")
            )
            return
        bundle.findings.extend(
            parse_healthcheck_results(
                raw_results, command=" ".join(HEALTHCHECK_COMMAND), live=True, host=bundle.hostname
            )
        )
    else:
        hc_file = fixture_path / "healthcheck.json"
        if not hc_file.exists():
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
        bundle.findings.extend(
            parse_healthcheck_results(raw_results, command=f"--replay {hc_file}", live=False, host=bundle.hostname)
        )


def _collect_staged(bundle: EvidenceBundle, *, fixture_path: Optional[pathlib.Path]) -> None:
    triggered_collector_names: List[str] = []
    for pack in all_packs():
        has_trigger = any(
            f.severity.rank >= Severity.WARNING.rank and any(f.source.startswith(s) for s in pack.healthcheck_sources)
            for f in bundle.findings
        )
        if has_trigger:
            triggered_collector_names.extend(pack.additional_collectors)

    for name in dict.fromkeys(triggered_collector_names):
        collector = get_collector(name)
        if collector is None:
            continue
        try:
            items = run_collector(collector, replay_dir=fixture_path)
        except CollectorError as e:
            bundle.collection_errors.append(
                CollectionError(collector=name, message=str(e), permission_related=e.permission_related)
            )
            continue
        bundle.items.extend(items)
