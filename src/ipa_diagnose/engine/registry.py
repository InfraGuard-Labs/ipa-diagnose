"""Internal registry of diagnostic packs.

Deliberately a plain list, not an entry-point/plugin discovery system - v1
has exactly five packs and does not need a plugin ecosystem. Adding a pack
means adding one import and one line here.
"""

from __future__ import annotations

from typing import List

from ipa_diagnose.engine.packs.base import DiagnosticPack


def all_packs() -> List[DiagnosticPack]:
    # Imported lazily so a syntax error in one pack module doesn't prevent
    # `import ipa_diagnose.engine.registry` itself from succeeding, and so
    # each pack module can freely import engine.model without a cycle.
    from ipa_diagnose.engine.packs import certificates, directory_server, dns, kerberos, replication

    return [
        directory_server.PACK,
        dns.PACK,
        kerberos.PACK,
        replication.PACK,
        certificates.PACK,
    ]


def pack_by_id(pack_id: str) -> DiagnosticPack:
    for pack in all_packs():
        if pack.pack_id == pack_id:
            return pack
    raise KeyError(f"no such diagnostic pack: {pack_id}")
