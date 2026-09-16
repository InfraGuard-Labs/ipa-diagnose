"""Central registry mapping collector name -> Collector instance.

Populated by each collector module at import time via `register()`. Kept as
a plain dict (not entry points) for the same reason engine/registry.py is a
plain list: v1 has a small, known set of collectors and does not need a
plugin ecosystem.
"""

from __future__ import annotations

from typing import Dict

from ipa_diagnose.evidence.collectors.base import Collector

_COLLECTORS: Dict[str, Collector] = {}


def register(collector: Collector) -> None:
    _COLLECTORS[collector.name] = collector


def get(name: str) -> "Collector | None":
    _ensure_loaded()
    return _COLLECTORS.get(name)


def all_names() -> "list[str]":
    _ensure_loaded()
    return list(_COLLECTORS.keys())


_loaded = False


def _ensure_loaded() -> None:
    """Imports every collector module so its register() call has run. Missing
    modules are skipped, not fatal - a pack may declare an additional_collectors
    entry for a collector that hasn't been implemented yet."""

    global _loaded
    if _loaded:
        return
    _loaded = True
    # Each diagnostic pack owns a distinct subset of these filenames (see
    # docs/diagnostic-packs.md) - this list only needs a new entry when a
    # pack introduces a genuinely new collector module.
    module_names = [
        "certmonger",
        "replication_agreements",
        "ldap_query",
        "dns_lookup",
        "filesystem",
        "kerberos_client",
        "journal_dirsrv",
        "journal_krb5kdc",
        "journal_named",
        "journal_pki",
    ]
    for name in module_names:
        try:
            __import__(f"ipa_diagnose.evidence.collectors.{name}")
        except ImportError:
            continue
