# Platform compatibility

This is an evidence-backed support matrix, not an aspirational one. Every
row states exactly what was tested and how - "RHEL" itself was never
tested (no subscription was available); every RHEL-labeled row is actually
a UBI (Red Hat Universal Base Image, subscription-free), Rocky Linux, or
AlmaLinux test, and is labeled as such rather than as "RHEL tested."

## Support matrix

| Platform | Default/available Python | Core diagnosis | PyPI/pipx | RPM | Validation |
|---|---|---|---|---|---|
| RHEL 9 (via UBI9/Rocky9/Alma9) | 3.9 (system) | Supported | Works (EPEL needed for `pipx` itself) | `.el9.` RPM, EPEL+CRB needed for `rich` | CONTAINER TESTED (UBI9 + Rocky9 + Alma9, independently) + RPM INSTALL TESTED |
| RHEL 10 (via UBI10/Alma10) | 3.12 (system) | Supported | Works (EPEL needed for `pipx` itself) | `.el10.` RPM, EPEL+CRB needed for `rich` | CONTAINER TESTED (UBI10 + Alma10; **Rocky 10: NOT TESTED**, no Docker Hub image exists) + RPM INSTALL TESTED |
| RHEL 8 (via UBI8/Rocky8/Alma8) | 3.6.8 (system, never touched); `python39` module = 3.9.25 | Supported, via the `python39` module | Works, manual steps required (no EPEL `pipx` package on EL8; `python39` module install needed first) | `.el8.` RPM, uses `python39`, `rich` vendored (no EL8 `python39-rich` package exists anywhere) | CONTAINER TESTED (UBI8 + Rocky8 + Alma8, independently) + RPM INSTALL TESTED |
| Rocky Linux 8 | Same as RHEL 8 row | Supported | Works via `python39`; **Rocky8's own non-modular `python3.12` package is broken** (`pyexpat` ABI mismatch, confirmed, unrelated to this project) - use `python39` | Same `.el8.` RPM as above, independently installed and tested on Rocky8 | CONTAINER TESTED |
| Rocky Linux 9 | 3.9 (system) | Supported | Works | Same `.el9.` RPM, independently installed and tested on Rocky9 | CONTAINER TESTED |
| Rocky Linux 10 | - | - | - | - | **NOT TESTED** - no `rockylinux:10` image exists on Docker Hub (only `rockylinux/rockylinux:10` exists and was used for a secondary EL10 cross-distro install check, not full independent validation) |
| AlmaLinux 8 | 3.6.8 (system); `python39` = 3.9.25 | Supported | Works via `python39` (Alma8's `python3.12` package works fine, unlike Rocky8's) | Same `.el8.` RPM, independently installed and tested on Alma8 | CONTAINER TESTED |
| AlmaLinux 9 | 3.9 (system) | Supported | Works | Same `.el9.` RPM, independently installed and tested on Alma9 - a 5-package install (`ipa-diagnose` + `rich`/`pygments`/`CommonMark`/`setuptools`), clean uninstall | CONTAINER TESTED |
| AlmaLinux 10 | 3.12 (system) | Supported | Works | Same `.el10.` RPM, independently installed and tested on Alma10 | CONTAINER TESTED |
| Fedora (current stable, pinned to an exact tag - see `packaging/rpm/fedora/`) | 3.14 (current stable's default) | Supported | Works, no EPEL needed | `.fc44.` RPM, no dependency workarounds needed (Fedora's own toolchain is current) | RPM INSTALL TESTED + PYPI INSTALL TESTED |

Every platform above additionally passed: `--version`, `--help`, graceful
behavior with no FreeIPA present, `--replay` against the project's own
fixtures (including the `stale-ruv-removed-replica` regression fixture,
correctly showing `Overall: DEGRADED`, never `HEALTHY`), uninstall, and
reinstall.

**A note on the EL9/EL10 RPMs' lack of a `Recommends:` for `ipa-healthcheck`/
`ipa-server-common`** (the Fedora RPM still has one): fresh-user testing
found that on EL9 and EL10, resolving either package by name - even
`ipa-healthcheck` alone - pulls 300+ packages (the full 389-DS/Dogtag/
httpd/tomcat IdM server stack) via their own transitive weak dependencies,
reproduced on both Rocky and AlmaLinux, not an AlmaLinux-only quirk as
first suspected. Worse, it was also found to leave `dnf remove
ipa-diagnose` in a broken transaction state trying to clean up the
now-orphaned chain afterward. Since ipa-diagnose already degrades
gracefully with a clear message when `ipa-healthcheck` is genuinely
absent, and its real users already have FreeIPA/IdM installed as a
precondition of using the tool at all, these Recommends were removed from
the EL9/EL10 specs entirely rather than accept that risk. Fedora's
equivalent packages were independently confirmed to stay lean (11 packages
total) and keep their Recommends.

## Python interpreter support

The **core deterministic product** (no AI) installs and passes its full
test suite identically on Python 3.9, 3.10, 3.11, 3.12, 3.13, and 3.14 -
zero version-sensitive behavior found across that range. This was verified
directly, ad hoc, in `python:<version>-slim` Docker containers during this
compatibility round; `requires-python = ">=3.9"` in `pyproject.toml` is
accurate. **Note on reproducibility:** only 3.9 (EL8/EL9 RPM `%check`),
3.11 (the project's own dev/CI Docker image), and 3.12/3.14 (EL10/Fedora
RPM `%check`) are exercised by anything currently checked into this repo -
3.10 and 3.13 were verified this round but are not yet wired into any
committed script or CI job, so a future contributor cannot reproduce those
two without repeating the same manual Docker check. Adding that automation
is a reasonable follow-up, not done as part of this round.

**Optional AI extras** (`openai`, `anthropic`, `boto3`/bedrock) install
cleanly on the same 3.9-3.14 range - no extra imposes a stricter floor than
the core.

Python 3.6 and 3.8 do not work and will not be supported: the failure is in
the build toolchain (`setuptools>=77`, required for this project's PEP 639
SPDX `license = "Apache-2.0"` metadata form, has no release supporting
either interpreter), and 3.6 additionally fails on the application's own
source (`from __future__ import annotations`, PEP 563, requires 3.7+). This
is why RHEL 8's system Python is never used directly - see the RHEL 8 row
above.

## FreeIPA / `ipa-healthcheck` generation support

RESEARCHED (primary-source: `ipa-healthcheck` git history, cross-checked
against real package NVRs), not independently re-verified against every
possible point release:

| Generation | Ships on | FreeIPA | `ipa-healthcheck` |
|---|---|---|---|
| Older | RHEL/Rocky/AlmaLinux 8 (all, frozen at 8.10) | 4.9.13 | **0.12** (~Dec 2022) |
| Current | RHEL/Rocky/AlmaLinux 9, 10, current Fedora, upstream `main` | 4.13.x | **0.19** (Sep 2025) or later |

The real gap this project's real-FreeIPA validation found and fixed
(CRITICAL `ipa-healthcheck` results with no `msg` field, only
`exception`/`traceback`) has existed in every version since `ipa-healthcheck`
0.10 (Feb 2022) - i.e. it affects every currently-deployed generation
including RHEL 8's 0.12, and the fix already in this codebase covers all of
them, not just the newer generation it was found on.

RHEL/Rocky/AlmaLinux 8's `ipa-healthcheck` 0.12 is missing several checks
added in later releases: `CertmongerStuckCheck` (0.13), a FIPS-token check
(0.19), an externally-signed-cert flag (0.19), the MS-PAC check (0.18), and
role-based service-check filtering (0.13). Any rule keyed to one of these
correctly sees no evidence at all on EL8 - this is expected upstream
coverage thinness, not a parsing bug, and the affected rules' `UNKNOWN`
fallback paths handle it safely.

## Known gaps - not tested, not researched

- **Trust/AD integration** (cross-forest trust, `ipahealthcheck.ipa.trust`
  and related checks) - not exercised anywhere in this project's testing or
  fixtures.
- **CA-less deployments** - all fixtures and testing assume a
  certmonger/Dogtag CA is present; a CA-less install's certificate-pack
  behavior is unverified.
- **Real live FreeIPA replication testing** for the stale-RUV fix
  specifically was attempted but blocked by a Docker Desktop cgroup v1 /
  systemd incompatibility on the development machine (documented, not a
  product issue) - the fix is instead verified via a fixture built from real
  field shapes taken from this project's own genuine FreeIPA capture, which
  independently reproduced the same result two different ways (direct code
  trace + fixture replay, and a second fixture built by a separate review).
  This is HISTORICAL-FIXTURE-STYLE validation, not REAL-FREEIPA-TESTED - the
  distinction is kept explicit rather than blurred.

## A note on the EL8 `rich` vendoring

The EL8 RPM bundles `rich` (and its own small dependency chain: `pygments`,
`markdown-it-py`, `mdurl`) directly into the package, because no
EL8-compatible `python39-rich` package exists in any repository checked
(base, AppStream, EPEL8, CRB). This is a narrow, explicitly-documented
exception for EL8 only - EL9, EL10, and Fedora all depend on a real,
externally-updatable `rich` package. The practical consequence: a security
issue in `rich` itself would not reach EL8 users via a normal `dnf update`
and would require an `ipa-diagnose` package update instead. `rich` is a
terminal-rendering library with no network or cryptographic surface, which
is why this trade-off was judged acceptable specifically for the hardest,
most-constrained target rather than avoided across the board.
