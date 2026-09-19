%{!?version: %global version 0.1.0}
%{!?release: %global release 1}

# --- EL9-specific build notes -----------------------------------------
#
# This spec targets RHEL9/CentOS Stream 9/Rocky 9/AlmaLinux 9. It cannot be
# a straight copy of ../ipa-diagnose.spec (the Fedora spec) because EL9's
# *default* python3 is 3.9, and building this project's pyproject.toml
# against EL9's stock tooling hits two real, confirmed-in-Docker gaps:
#
#   1. %%generate_buildrequires needs stdlib `tomllib` (3.11+ only) to parse
#      pyproject.toml. EL9's default python3 is 3.9, which lacks it, and
#      has no tomllib itself - but AppStream directly carries a tomllib
#      backport (`python3-tomli`, confirmed available, no EPEL needed),
#      so this is a one-line BuildRequires fix.
#
#   2. pyproject.toml pins `requires = ["setuptools>=77", "wheel"]`,
#      needed upstream for the PEP 639 SPDX-string `license = "Apache-2.0"`
#      form. EL9's default python3's setuptools is exactly 53.0.0
#      (confirmed), which predates PEP 621 `[project]`-table support
#      entirely - not just too old for >=77, functionally unable to parse
#      this pyproject.toml at all, full stop. EL9 AppStream *does* offer
#      newer interpreters directly (`dnf install python3.11` / `python3.12`
#      - plain packages, no module-stream dance, confirmed), but their
#      setuptools tops out at 65.5.1 (python3.11) / 68.2.2 (python3.12) -
#      both understand PEP 621 but NOT the PEP 639 SPDX-string form
#      (confirmed empirically: setuptools 65.5.1 hard-rejects
#      `license = "Apache-2.0"` with "project.license must be valid
#      exactly by one definition", and builds cleanly the moment it's
#      switched to the classic `license = {text = "Apache-2.0"}` table
#      form). No EL9 repo - base, AppStream, CRB, or EPEL - carries
#      setuptools>=77 for ANY interpreter stream (confirmed), so there is
#      no dnf-resolvable BuildRequires that would satisfy the pin as
#      written; the honest fix is to stop asking for a feature this
#      build doesn't need, not to chase a version nothing here ships.
#
# The fix applied below (in %%prep, to a private build-time copy of
# pyproject.toml only - the canonical, PyPI-facing pyproject.toml at the
# repo root is untouched) is therefore two parts:
#
#   a. Patch `license = "Apache-2.0"` -> `license = {text = "Apache-2.0"}`
#      and drop the `setuptools>=77` floor to `setuptools>=61` (the real
#      functional requirement - PEP 621 table support). This lets the
#      wheel build with python3.11's real, repo-installed 65.5.1 with zero
#      network access and nothing bundled into the shipped RPM.
#
#   b. Build the wheel with python3.11 (BuildRequires'd directly from
#      AppStream), but INSTALL it with the system-default python3 (3.9).
#      The built wheel is pure-Python/noarch (py3-none-any) - it carries
#      no interpreter lock-in - so this is a legitimate split: python3.11
#      is a build-only bootstrap tool that never appears in the shipped
#      package's dependencies, while %%install/%%files run under python3.9
#      so the FINAL package's generated `Requires: python(abi) = 3.9` and
#      `python3.9dist(rich)` match a real EL9 admin's actual default
#      interpreter (per pyproject.toml's own `requires-python = ">=3.9"`)
#      - not the 3.11 used only to get past the broken build tooling.
#
# One more real gap, confirmed in Docker and worth being explicit about:
# EL9 (base+AppStream+EPEL9) packages `rich` only for the *default*
# python3 (3.9) stream, and only via EPEL9 (`python3-rich`, currently
# 13.1.0-1.el9) - not in base/AppStream. This is why %%install below uses
# python3.9, and why EPEL9 must be enabled at *install* time on the
# target host (documented in the top-level README's install section, not
# left for administrators to discover via a failed `dnf install`).
# EPEL9's rich (13.1.0) is also older than pyproject.toml's own declared
# floor (`rich>=13.7,<15`, chosen for freshness, not a specific API this
# project needs - it only imports Console/Panel/Text/Rule, all long-
# stable rich APIs). The %%prep patch below relaxes the EL9 build's
# private copy of that floor to `>=13.1,<15` to match what EPEL9 actually
# ships, so the RPM's auto-generated Requires is truthful and resolvable
# via `dnf install` instead of demanding a rich EPEL9 doesn't carry.
# ------------------------------------------------------------------------

Name:           ipa-diagnose
Version:        %{version}
Release:        %{release}%{?dist}
Summary:        Evidence-grounded diagnostic and correlation engine for FreeIPA / Red Hat IdM

License:        Apache-2.0
URL:            https://github.com/InfraGuard-Labs/ipa-diagnose
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

# Build-only bootstrap interpreter (see notes above) - never appears in
# the shipped package's Requires.
BuildRequires:  python3.11
BuildRequires:  python3.11-devel
BuildRequires:  python3.11-setuptools >= 61
BuildRequires:  python3.11-pip
BuildRequires:  python3.11-wheel

# Target interpreter: what the shipped package actually declares
# `Requires: python(abi) = ...` against, and what %%install/%%check run
# under. python3-devel pulls in the generic python-rpm-macros
# (%%python3_sitelib, %%py3_shebang_fix, the automatic Python
# Provides/Requires generator) that pyproject-rpm-macros' file-list/
# dependency-generation macros below rely on.
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  pyproject-rpm-macros
# tomllib backport - fixes gap #1 above (%%check's own test collection
# also runs under python3.9, so needed there too, not just conceptually
# for buildrequires generation).
BuildRequires:  python3-tomli
BuildRequires:  python3-pytest
# Needed at build time so %%check can actually import ipa_diagnose's
# rich-based CLI/render code, matching what %%install declares below.
BuildRequires:  python3-rich >= 13.1

# DELIBERATELY NO Recommends here, unlike the Fedora spec - found via
# fresh-user testing, not theorized: on EL9, BOTH `ipa-healthcheck` alone
# AND `ipa-healthcheck` + `ipa-server-common` together pull 300+ packages
# (the full IdM/389-DS/Dogtag/httpd/tomcat stack) via transitive weak
# dependencies of their own - confirmed on Rocky 9 (340 packages) AND
# AlmaLinux 9 (353 packages), so this is not an AlmaLinux-only quirk as
# first suspected; it reproduces identically on both EL9 clones once the
# EL9-correct package names (`ipa-healthcheck`/`ipa-server-common`, not
# Fedora's `freeipa-*` names) are used. Worse than the install footprint
# itself: a fresh-user test found `dnf remove ipa-diagnose` afterward can
# leave the system in a BROKEN state (a failed transaction trying to
# autoremove the now-unneeded `ipa-server` weak-dependency chain, reporting
# packages "needed by (installed) ipa-server" that were themselves already
# removed). A package recommendation must never risk leaving a host's
# package database inconsistent on a plain uninstall. Since ipa-diagnose
# already degrades gracefully with a clear message when `ipa-healthcheck`
# genuinely isn't installed (verified repeatedly in testing), and its real
# target audience already has FreeIPA/IdM installed as a precondition of
# using this tool at all, the Recommends' practical benefit does not
# justify this risk on EL9 - omitted here, present only on Fedora, where
# the same packages are confirmed to stay lean (11 packages).

%global _description %{expand:
ipa-diagnose sits on top of ipa-healthcheck and targeted, read-only system
evidence (journalctl, certmonger, replication agreements, DNS lookups) to
correlate related failures into a single deterministic root-cause diagnosis,
explain impact, and recommend safe next steps. AI (OpenAI/Anthropic/Bedrock)
is optional and only ever explains an already-computed diagnosis - it never
determines root cause, invents evidence, or invents remediation commands.
This base package works fully offline / --no-ai; AI provider support is
installed separately via pip extras (see /usr/share/doc/ipa-diagnose).

Note for EL9/RHEL9/Rocky9/AlmaLinux9 installs: the `rich` runtime
dependency is only available via EPEL9 on this platform
(`python3-rich`) - enable EPEL before `dnf install` (see this project's
top-level README).}

%description %_description

%prep
%autosetup -n %{name}-%{version}

# EL9-only build-time patch (see notes above) - does NOT touch the
# canonical, PyPI-facing pyproject.toml at the repo root, only this
# source tarball's private working copy used for the EL9 RPM build.
# 1) Classic license table form instead of the PEP 639 SPDX string form,
#    so setuptools 65.5.1 (python3.11, real EL9 AppStream package) can
#    parse this pyproject.toml at all.
# 2) setuptools floor relaxed to the real functional requirement (PEP 621
#    table support, landed in setuptools 61) instead of >=77, which
#    nothing in EL9's repos (any interpreter stream, any repo) provides.
# 3) rich floor relaxed to match what EPEL9 actually ships (13.1.0) -
#    this project only uses long-stable rich APIs (Console/Panel/Text/
#    Rule), so this is a packaging-metadata correction, not a functional
#    downgrade.
sed -i \
    -e 's/^requires = \["setuptools>=77", "wheel"\]$/requires = ["setuptools>=61", "wheel"]/' \
    -e 's/^license = "Apache-2.0"$/license = {text = "Apache-2.0"}/' \
    -e 's/^    "rich>=13\.7,<15",$/    "rich>=13.1,<15",/' \
    pyproject.toml
grep -n '^requires = \|^license = \|"rich' pyproject.toml

%build
# Build the wheel with python3.11 (see gap #2 above) - pure build-time
# bootstrap, no network access, no vendoring: python3.11 and its
# setuptools/wheel/pip are real, declared BuildRequires resolved from
# EL9's own AppStream repo. --no-build-isolation is intentional: it
# forces the build to use exactly the BuildRequires-resolved setuptools/
# wheel above rather than reaching out to PyPI for its own copies.
#
# The wheel is written directly into %%{_pyproject_wheeldir} (rather than
# a plain ./dist) so that the *standard* %%pyproject_install macro below
# can find and install it unmodified - see %%install for why that matters.
mkdir -p %{_pyproject_wheeldir}
python3.11 -m pip wheel --no-build-isolation --no-deps --wheel-dir %{_pyproject_wheeldir} .

%install
# Install with the standard %%pyproject_install macro, which internally
# invokes %%{__python3} (the system-default python3.9, NOT python3.11 -
# see gap #2 above / the split-interpreter note). This is a plain
# local-wheel install (--no-deps, --no-index - just unpacking the wheel
# %%build already produced), so python3.9's own broken setuptools never
# enters the picture here. Landing the files under python3.9's
# site-packages is what makes the automatic RPM Python-dependency
# generator below emit `Requires: python(abi) = 3.9` and
# `python3.9dist(rich)` - i.e. what a real EL9 admin's default
# interpreter actually needs, not python3.11's.
#
# Using the real %%pyproject_install macro (instead of a hand-rolled
# `pip install`) matters beyond consistency: it also writes the
# %%{_pyproject_record} file (via pyproject_preprocess_record.py) that
# %%pyproject_save_files below requires - a hand-rolled `pip install`
# skips that step and %%pyproject_save_files fails with a
# FileNotFoundError (confirmed).
%pyproject_install
%pyproject_save_files ipa_diagnose

%check
# Fixture-based tests only: fully offline, no live FreeIPA/network/root
# required, so they are safe and meaningful to run as part of the RPM
# build itself - a broken package should fail to build, not just fail at
# runtime. Runs under python3.9 (system default), matching %%install
# above and the package actually being shipped.
#
# Uses the standard %%pytest macro (not a bare `%%{python3} -m pytest`):
# it sets PYTHONPATH to %%{buildroot}'s sitelib/sitearch, which is the
# only place ipa_diagnose exists at this point in the build (nothing is
# installed into the container's real python3.9 site-packages) - a bare
# `%%{python3} -m pytest` fails here with `ModuleNotFoundError:
# No module named 'ipa_diagnose'` (confirmed).
%pytest tests/unit tests/packs

%files -f %{pyproject_files}
%license LICENSE
%doc README.md
%{_bindir}/ipa-diagnose

%changelog
* Sat Sep 19 2026 Azeem Siddiqui <azeemsidd509@gmail.com> - 0.1.2-1
- 0.1.2: evidence completeness (UNKNOWN / NOT_FULLY_VERIFIED, exit code 4),
  explicit RUV state with a read-only LDAPI read (no Directory Manager password),
  stopped-service findings no longer dropped, verify never reports RESOLVED
  without evidence. See docs/evidence-completeness.md.
* Thu Sep 17 2026 ipa-diagnose contributors <noreply@example.invalid> - 0.1.0-1
- EL9 spec: build with python3.11 (bootstrap only, for setuptools/PEP 621
  support EL9's default python3.9 lacks), install/ship against python3.9
  (EL9's real default interpreter) so Requires: python(abi) = 3.9 and
  python3.9dist(rich) - not python(abi) = 3.14 as in the Fedora build.
