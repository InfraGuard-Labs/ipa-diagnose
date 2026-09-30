#!/usr/bin/env python3
"""Build docs/screenshots/1.0-candidate/ from REAL lab captures.

    python scripts/build_screenshots.py CAPTURE_DIR [CAPTURE_DIR ...]

CAPTURE_DIR holds NAME.txt / NAME.json pairs written by `scripts/lab_captures.py fetch RUN_ID DIR` (the exact text a
live lab run printed, published by that run as annotations) or by `scripts/lab_captures.py run` locally for REPLAY
captures. Nothing here runs ipa-diagnose or edits captured text: each image is drawn by
scripts/render_capture_svg.py from a stated line range of one capture, with a provenance banner. The raw captures are
copied next to the images (captures/) so every image can be checked against its source, and index.md is generated
with each image's command, commit, run, provenance, scenario, environment, safe claim and limitation.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from render_capture_svg import render  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "screenshots" / "1.0-candidate"

# lab environments, as recorded by each lab's "environment" step (env.txt / the environment annotation)
LABS = {
    "srv": "single FreeIPA server (integrated DNS + CA), freeipa-server 4.13.4-2.fc43, Fedora 43 container",
    "bundle": "single FreeIPA server (integrated DNS + CA), freeipa-server 4.13.4-2.fc43, Fedora 43 container",
    "access": "single FreeIPA server, freeipa-server 4.13.4-2.fc43, Fedora 43 container; fake LAB.TEST HBAC policy",
    "client": "FreeIPA server 4.13.4-2.fc43 + enrolled Fedora 43 client (freeipa-client 4.13.4-2.fc43, sssd 2.12.0)",
    "repl": "three FreeIPA 4.13.4 / 389-ds-base 3.1.5 / Fedora 43 servers in a line: ipa01 (CA, DNS) -- ipa02 (CA) "
            "-- ipa03",
}

def _m(image, capture, claim, limit, start=0, lines=70, prov="LIVE"):
    return {"image": image, "capture": capture, "claim": claim, "limit": limit, "start": start, "lines": lines,
            "prov": prov}


ONE_LAB = "one lab, one FreeIPA version (4.13.4) on Fedora 43; the fault was injected on purpose"
MANIFEST: list = [
    # --- used in the README
    _m("01_server_root_cause_and_fix.svg", "srv-03-dirsrv-stopped",
       "With the Directory Server stopped, ipa-diagnose named the stopped unit as the root cause and printed "
       "`systemctl start` for exactly that unit, never `ipactl start`.", ONE_LAB, 0, 66),
    _m("02_server_verify_resolved.svg", "srv-07-verify-after-fix",
       "After the printed command was run verbatim, `verify` reported RESOLVED from fresh evidence and the fix's own "
       "check.", "exit stays 4 in the lab: the container's MetaCheck warning is listed, not explained away"),
    _m("03_client_server_unreachable.svg", "client-03-server-unreachable-sssd-offline",
       "On a client whose IPA server ports were blocked, the unreachable server was the root cause and SSSD offline "
       "and the KDC failure were RELATED to it.", "one client, SSSD 2.12; no login was attempted", 0, 47),
    _m("04_access_policy_vs_runtime.svg", "client-04-access-runtime-hbac-pass-sssd-stopped",
       "FreeIPA's HBAC decision stayed PASS while the runtime side on the host failed (SSSD stopped): RUNTIME ACCESS "
       "FAIL, exit 5.", "run as root on the host itself; no login was attempted"),
    _m("05_replication_cause_chain_handoff.svg", "repl-02-peer-ds-stopped-from-ipa01",
       "Seen from ipa01, ipa02's stopped Directory Server was reported per suffix and direction, with a cause chain "
       "that stops at what ipa01 can prove and a handoff to ipa02; nothing was changed anywhere.",
       "three-server line topology, FreeIPA 4.13.4", 0, 31),
    _m("06_replication_complete_fix.svg", "repl-06-local-kdc-stopped-ipa01",
       "For this server's own stopped KDC, the printed fix showed host, expected result, failure handling, backup, "
       "rollback and incident verification, with a No-Google claim backed by a live replication record.",
       "No-Google is claimed only on FreeIPA 4.13.4 / Fedora 43 for this procedure", 0, 40),
    _m("07_server_unknown_no_guessing.svg", "srv-09-healthcheck-missing-unknown",
       "With ipa-healthcheck unavailable, the answer was UNKNOWN (exit 3), never healthy, and no cause was claimed.",
       "the binary was hidden on purpose"),
    # --- more real captures, index only
    _m("08_server_details.svg", "srv-04-dirsrv-stopped-details", "`--details` shows evidence, confidence and each "
       "check's command.", ONE_LAB, 0, 70),
    _m("09_server_json.svg", "srv-05-dirsrv-stopped-json", "`--json` is pure JSON with the same conclusion.",
       "first lines only; the full capture is in captures/", 0, 60),
    _m("10_server_ai_preview.svg", "srv-06-dirsrv-stopped-ai-preview", "`ai-preview` shows exactly what would be "
       "sent (after redaction); no provider is configured, nothing is sent.", "no live provider call was made"),
    _m("11_server_verify_still_present.svg", "srv-11-verify-still-present", "With the KDC left stopped, `verify` "
       "reported STILL_PRESENT, not RESOLVED.", ONE_LAB),
    _m("12_server_masked_fix_withheld.svg", "srv-12-certmonger-masked-fix-withheld", "A masked certmonger got no "
       "start command, and the report says why.", "certmonger only", 0, 45),
    _m("13_server_file_fix_confirm_first.svg", "srv-02-file-group-fix-confirm-first", "A wrong group on "
       "/etc/ipa/ca.crt got `chgrp -h root` after read-only CONFIRM FIRST commands with exact expected output.",
       "container /data layout", 11, 55),
    _m("14_server_dns_stopped_unknown.svg", "srv-10-dns-stopped-unknown", "With this server's named stopped, "
       "ipa-healthcheck did not finish; the answer was UNKNOWN and the stopped unit was listed, no cause claimed.",
       ONE_LAB),
    _m("15_server_kdc_stopped.svg", "srv-08-kdc-stopped", "A stopped KDC was the CRITICAL root cause with a scoped "
       "start command.", ONE_LAB, 0, 66),
    _m("16_server_healthy_container.svg", "srv-01-healthy-container-metacheck", "On a healthy lab server nothing was "
       "diagnosed; one container-only upstream warning is listed as undiagnosed (NOT_FULLY_VERIFIED).",
       "the warning is caused by the container kernel"),
    _m("17_bundle_preview.svg", "bundle-01-preview-dirsrv-stopped", "`bundle --preview` lists what a bundle would "
       "contain, what was pseudonymized and redacted, and writes nothing.", "review a bundle before sharing; it is "
       "not secret-free"),
    _m("18_bundle_validate.svg", "bundle-02-validate", "`bundle validate` checks a bundle without extracting it.",
       "checksums are not a signature"),
    _m("19_access_nested_group_allow.svg", "access-01-nested-group-allow", "An allow names the matched rule and the "
       "nested group chain (carol -> backend -> devs).", "fake lab policy with allow_all disabled"),
    _m("20_access_deny_is_policy.svg", "access-02-deny-is-policy", "A deny is reported as policy, with no grant "
       "suggestion.", "fake lab policy"),
    _m("21_access_disabled_user.svg", "access-03-disabled-user-authn-fail-authz-pass", "A disabled account with an "
       "allowing rule: AUTHENTICATION FAIL, AUTHORIZATION PASS.", "fake lab policy"),
    _m("22_access_no_ticket_unknown.svg", "access-04-no-ticket-unknown", "Without a Kerberos ticket the answer is "
       "UNKNOWN (exit 3).", "-"),
    _m("23_client_healthy.svg", "client-00-healthy", "A healthy enrolled client: HEALTHY, RUNTIME ACCESS NOT "
       "VERIFIED.", "no login was attempted", 0, 60),
    _m("24_client_sssd_stopped.svg", "client-01-sssd-stopped", "SSSD stopped: root cause and a printed `systemctl "
       "start sssd.service`.", "one client", 0, 60),
    _m("25_client_verify_resolved.svg", "client-02-verify-resolved", "`client --verify` after the printed fix: "
       "RESOLVED with fresh checks.", "one client", 0, 40),
    _m("26_client_host_refuses_contradicting.svg", "client-05-access-runtime-host-refuses", "HBAC allows but the "
       "host's SSSD refuses: CONTRADICTING, never rewritten as a policy deny.", "no login was attempted"),
    _m("27_client_identity_undiagnosed.svg", "client-06-identity-undiagnosed", "A lookup failure nothing explains is "
       "UNDIAGNOSED, with read-only next steps.", "the lab filtered the user in sssd.conf", 0, 50),
    _m("28_client_two_independent_causes.svg", "client-07-two-independent-causes", "A dead resolver and an sssd.conf "
       "typo at once: two independent causes.", "one client", 0, 50),
    _m("29_replication_healthy.svg", "repl-01-healthy-ipa02", "The middle server of a healthy line topology: every "
       "agreement per suffix and direction OK.", "with the operator's Kerberos ticket"),
    _m("30_replication_local_ds_stopped.svg", "repl-03-local-ds-stopped-ipa02", "On ipa02 itself the stopped "
       "Directory Server is the local root with a printed fix.", "three-server lab"),
    _m("31_replication_verify.svg", "repl-04-verify-resolved-ipa02", "`replication --verify` after the printed fix.",
       "three-server lab"),
    _m("32_replication_peer_unreachable.svg", "repl-05-peer-unreachable-from-ipa01", "A disconnected peer is "
       "'unreachable from ipa01 at <time>', never 'dead'.", "three-server lab"),
    _m("33_replication_two_causes.svg", "repl-07-two-causes-ipa02", "A local stopped KDC (PRIMARY, fix printed) and a "
       "peer's stopped Directory Server (INDEPENDENT, handoff).", "three-server lab", 0, 63),
    _m("34_replication_simulated_clock.svg", "repl-08-simulated-clock-offset-ipa01", "A measured clock difference "
       "stops at the measurement; no clock step is printed.", "SIMULATED: only ipa-diagnose's own process clock "
       "was shifted; the servers' clocks were not", prov="LIVE SIMULATED"),
    _m("35_replication_bundle_preview.svg", "repl-09-bundle-preview-ipa01", "`bundle --replication --preview`.",
       "review a bundle before sharing"),
]


def _load(dirs: list) -> dict:
    caps = {}
    for d in dirs:
        for meta in pathlib.Path(d).glob("*.json"):
            txt = meta.with_suffix(".txt")
            if txt.exists():
                caps[meta.stem] = (json.loads(meta.read_text(encoding="utf-8")), txt.read_text(encoding="utf-8"))
    return caps


def _banner(prov: str, meta: dict) -> str:
    where = f"commit {meta.get('commit', '')[:7]}" + (f", run {meta['run_id']}" if meta.get("run_id") else "")
    return {"LIVE": f"REAL LIVE CAPTURE - FreeIPA 4.13.4 / Fedora 43 lab - {where}",
            "LIVE SIMULATED": f"LIVE SIMULATED (only ipa-diagnose's own clock shifted) - FreeIPA 4.13.4 lab - {where}",
            "REPLAY": f"FIXTURE REPLAY (NOT live) - recorded evidence - {where}"}[prov]


def main(argv: list) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    caps = _load(argv[1:])
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "captures").mkdir(exist_ok=True)
    rows, missing = [], []
    for m in MANIFEST:
        if m["capture"] not in caps:
            missing.append(m["capture"])
            continue
        meta, text = caps[m["capture"]]
        title = f"$ {meta['command']}   (exit {meta['exit']})"
        svg = render(text, title, _banner(m["prov"], meta), m["lines"], m["start"], wrap=120)
        (OUT / m["image"]).write_text(svg, encoding="utf-8", newline="\n")
        (OUT / "captures" / f"{m['capture']}.txt").write_text(text, encoding="utf-8", newline="\n")
        (OUT / "captures" / f"{m['capture']}.json").write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n",
                                                                encoding="utf-8", newline="\n")
        total = len(text.splitlines())
        shown = f"lines {m['start'] + 1}-{min(total, m['start'] + m['lines'])} of {total}"
        rows.append((m, meta, shown))
    if missing:
        print(f"MISSING captures: {missing}")
        return 1
    _index(rows)
    print(f"{len(rows)} image(s) written to {OUT}")
    return 0


def _index(rows: list) -> None:
    lines = [
        "# 1.0-candidate screenshots: real CLI output only",
        "",
        "Every image is the exact text `ipa-diagnose` printed, drawn by `scripts/render_capture_svg.py` (ANSI colours "
        "stripped; a long output shows the stated line range, and some outputs are split over two images). Nothing is "
        "mocked, typed by hand or generated. The raw capture of each image, with its command, exit code, time, commit "
        "and run, is in [captures/](captures/). Images are built by `scripts/build_screenshots.py` from captures that "
        "the live lab runs published (`scripts/lab_captures.py`).",
        "",
        "**Provenance labels.** LIVE: a disposable FreeIPA lab on a free GitHub-hosted runner, the fault injected on "
        "purpose and confirmed independently, ipa-diagnose run blind. LIVE SIMULATED: a live lab where only "
        "ipa-diagnose's own process clock was shifted (libfaketime); no server clock was changed. REPLAY: recorded "
        "evidence, not a live system. **Pseudonymization:** the labs use only fake names (`lab.test`, `LAB.TEST`, "
        "`ipa01`-`ipa03`, `client1`, users `alice`/`bob`/`carol`/`dave`/`erin`, private 172.30/172.31 addresses); "
        "no real host, user, credential, ticket or key appears. Bundle output shows the bundle's own pseudonyms "
        "(`HOST-001`).",
        "",
        "Environment: " + "; ".join(f"**{k}**: {v}" for k, v in LABS.items()) + ". Only Fedora 43 and FreeIPA "
        "4.13.4 were used for these images; nothing here was captured on RHEL.",
        "",
        "| # | Image | Command (exit) | Provenance | Scenario | Safe public claim | Limitation |",
        "|---|---|---|---|---|---|---|",
    ]
    for i, (m, meta, shown) in enumerate(rows, 1):
        run = f"[{meta['run_id']}](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/{meta['run_id']})" \
            if meta.get("run_id") else "local"
        lines.append(
            f"| {i:02d} | [`{m['image']}`]({m['image']}) ({shown}) | `{meta['command']}` ({meta['exit']}) | "
            f"{m['prov']}, commit `{meta.get('commit', '')[:7]}`, run {run} | {meta['scenario']} | {m['claim']} | "
            f"{m['limit']} |")
    lines += ["", "Historical screenshot sets (earlier code, kept unchanged): [v0.1.2](../v0.1.2/index.md), "
              "[v0.1.3](../v0.1.3/index.md), Slice 2 bundle captures in [slice2](../slice2/), and the fixture-based set "
              "in `artifacts/screenshots/`.", ""]
    (OUT / "index.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
