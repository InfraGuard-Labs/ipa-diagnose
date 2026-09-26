"""Build docs/truth/truth-matrix.md from live-lab truth rows (out/truth/results.jsonl in the lab artifacts).

    python scripts/truth_matrix.py OUT.md RUN_REF=results.jsonl [RUN_REF=results.jsonl ...]

RUN_REF is the GitHub Actions run URL (or id) the rows came from. Scenario metadata (what was injected, what the
true cause is, what was applied) lives in SCENARIOS below; everything ipa-diagnose reported comes from the rows.
Rows are LIVE evidence only: fixture/source evidence is listed separately in the matrix document.
"""

from __future__ import annotations

import json
import pathlib
import sys

# id -> (subsystem, topology, injected failure, true cause, applied by the lab)
SCENARIOS = {
    "S0-healthy-before-quirk-fix": ("baseline", "single", "none (fresh install; the Fedora image ships CS.cfg 0664)", "CS.cfg mode 0664 vs expected 0660 (real image quirk)", "-"),
    "P1-file-mode-fix": ("files", "single", "none (real CS.cfg 0664 quirk)", "CS.cfg too permissive", "printed chmod o-r (after CONFIRM FIRST)"),
    "P1-file-mode-fix-verify": ("files/verify", "single", "-", "fixed", "-"),
    "S0b-healthy-single-server": ("baseline", "single", "none", "healthy", "-"),
    "F1-group-mismatch": ("files", "single", "chgrp apache /etc/ipa/ca.crt", "group apache vs expected root", "printed chgrp -h root (after CONFIRM FIRST)"),
    "F1-group-fix-verify": ("files/verify", "single", "-", "fixed", "-"),
    "F2-non-ipa-group": ("files", "single", "chgrp nobody /etc/ipa/ca.crt", "group is not an IPA account", "lab restore only"),
    "F3-hard-link": ("files", "single", "chmod 0664 + second hard link to CS.cfg", "permissive mode, but another name for the file exists", "lab restore only"),
    "F4-key-material": ("files", "single", "chgrp root /var/lib/ipa/ra-agent.key", "wrong group on key material", "lab restore only"),
    "S1-healthcheck-missing": ("collection", "single", "ipa-healthcheck binary hidden", "no base evidence", "lab restore only"),
    "S1-ldapsearch-missing": ("collection", "single", "ldapsearch hidden", "replication/topology evidence missing", "lab restore only"),
    "S2-non-root": ("collection", "single", "run as nobody", "insufficient privilege", "-"),
    "S3-dirsrv-down": ("directory-server", "single", "systemctl stop dirsrv@INSTANCE", "Directory Server stopped", "printed systemctl start dirsrv@INSTANCE.service"),
    "S3-dirsrv-fix-verify": ("directory-server/verify", "single", "-", "fixed", "-"),
    "S4-named-down": ("dns", "single", "systemctl stop named", "named stopped", "lab restore (no fix is offered for named)"),
    "S4-named-restored": ("dns", "single", "named started again", "restored", "-"),
    "S5-krb5kdc-down": ("kerberos", "single", "systemctl stop krb5kdc", "KDC stopped", "printed systemctl start krb5kdc.service"),
    "S5-krb5kdc-fix-verify": ("kerberos/verify", "single", "-", "fixed", "-"),
    "V1-verify-problem-still-present": ("verify", "single", "krb5kdc stopped, nothing fixed", "still broken", "-"),
    "V2-verify-tampered-baseline": ("verify", "single", "saved criteria digest overwritten, then krb5kdc started", "fixed, but saved baseline damaged", "lab start"),
    "S6-certmonger-masked": ("certificates", "single", "certmonger masked + stopped", "certmonger deliberately masked", "lab unmask/start (fix correctly withheld)"),
    "S6-certmonger-restored-verify": ("certificates/verify", "single", "-", "restored", "-"),
    "S7-named-and-krb5kdc-down": ("multi", "single", "named + krb5kdc stopped", "two independent stopped services", "lab restore"),
    "S7-restored": ("multi", "single", "named + krb5kdc started again", "restored", "-"),
    "S7b-krb5kdc-and-certmonger-down": ("multi", "single", "krb5kdc + certmonger stopped", "two independent stopped services", "lab restore"),
    "S7b-certmonger-restart-disclosed": ("multi/side-effect", "single", "krb5kdc + certmonger stopped", "ipa-healthcheck restarts certmonger (upstream ipalib)", "-"),
    "S7b-restored-verify": ("multi/verify", "single", "-", "restored", "-"),
    "S10-healthy-after-all-restores": ("baseline", "single", "none (after all scenarios)", "healthy", "-"),
    "H1-single-server-fresh-install": ("baseline", "single", "none", "fresh install (CS.cfg quirk)", "-"),
    "H2-two-node-healthy-topology": ("replication", "two-node", "none", "healthy topology", "-"),
    "R1-replica-down-still-registered": ("replication", "two-node", "replica container removed, still registered", "peer unreachable", "-"),
    "R2-after-replica-removal": ("replication", "two-node", "replica removed from topology (lab)", "see run evidence (stale RUV not forced)", "-"),
}


def _cell(x) -> str:
    return str(x if x not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def _primary(row) -> str:
    p = [d for d in row.get("diagnoses") or [] if d.get("priority") == "PRIMARY_PROBLEM"]
    return "; ".join(f"{d.get('title')} ({d.get('status')}, {d.get('confidence')})" for d in p) or "-"


def _others(row) -> str:
    o = [d for d in row.get("diagnoses") or [] if d.get("priority") != "PRIMARY_PROBLEM"]
    return "; ".join(f"{d.get('priority').split('_')[0]}: {d.get('title')}" for d in o[:4]) or "-"


def _res(row) -> str:
    out = []
    for r in row.get("resolutions") or []:
        argv = " / ".join(" ".join(a) for a in r.get("argv") or [])
        out.append(f"{r.get('procedure')} {r.get('status')}" + (f" `{argv}`" if argv else "") + (f" [{r.get('tier')}]" if r.get("tier") else ""))
    return "; ".join(out) or "-"


def main(argv) -> int:
    out = pathlib.Path(argv[1])
    lines = ["| Scenario | Verdict | Subsystem | FreeIPA / OS / topology | Injected | True cause | Overall | Primary (status, confidence) | Other diagnoses | Resolution | Applied | Verify | Run |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for spec in argv[2:]:
        ref, path = spec.split("=", 1)
        for raw in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
            row = json.loads(raw)
            sid = row["scenario"]
            sub, topo, inj, cause, applied = SCENARIOS.get(sid, ("?", "?", "?", "?", "?"))
            verify = "; ".join(f"{v.get('outcome')}: {v.get('title')}" for v in row.get("verify") or []) or "-"
            fails = [t for ok, t in row.get("checks") or [] if not ok]
            verdict = row["verdict"] + (f" ({fails[0]})" if fails else "") + (f" ({row.get('skip_reason')})" if row.get("skip_reason") else "")
            lines.append("| " + " | ".join(_cell(x) for x in [
                sid, verdict, sub, f"{row.get('freeipa')} / {row.get('os')} / {topo}", inj, cause, row.get("overall"),
                _primary(row), _others(row), _res(row), applied, verify, ref]) + " |")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{len(lines) - 2} rows -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
