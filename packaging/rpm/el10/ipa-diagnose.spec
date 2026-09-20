%{!?version: %global version 0.1.3}
%{!?release: %global release 1}

Name:           ipa-diagnose
Version:        %{version}
Release:        %{release}%{?dist}
Summary:        Evidence-grounded diagnostic and correlation engine for FreeIPA / Red Hat IdM

License:        Apache-2.0
URL:            https://github.com/InfraGuard-Labs/ipa-diagnose
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros
BuildRequires:  python3dist(pytest)

# DELIBERATELY NO Recommends here, unlike the Fedora spec - found via
# fresh-user testing, not theorized: on AlmaLinux 10, `ipa-healthcheck`
# alone (confirmed directly: 318 packages, 594 MB) and this same
# freeipa-healthcheck/freeipa-server-common Recommends pair both resolve
# (via a compatibility Provides) and pull the full IdM/389-DS/Dogtag/
# httpd/tomcat stack - over 100 packages from a plain `dnf install
# ipa-diagnose`. Worse than the footprint itself: a fresh-user test found
# `dnf remove ipa-diagnose` afterward can leave the system in a BROKEN
# state (a failed transaction trying to autoremove the now-unneeded
# `ipa-server` weak-dependency chain, reporting packages "needed by
# (installed) ipa-server" that were themselves already removed). A
# package recommendation must never risk leaving a host's package database
# inconsistent on a plain uninstall. Since ipa-diagnose already degrades
# gracefully with a clear message when `ipa-healthcheck` genuinely isn't
# installed (verified repeatedly in testing), and its real target audience
# already has FreeIPA/IdM installed as a precondition of using this tool
# at all, the Recommends' practical benefit does not justify this risk on
# EL10 - omitted here, present only on Fedora, where the same packages are
# confirmed to stay lean (11 packages).

%global _description %{expand:
ipa-diagnose sits on top of ipa-healthcheck and targeted, read-only system
evidence (journalctl, certmonger, replication agreements, DNS lookups) to
correlate related failures into a single deterministic root-cause diagnosis,
explain impact, and recommend safe next steps. AI (OpenAI/Anthropic/Bedrock)
is optional and only ever explains an already-computed diagnosis - it never
determines root cause, invents evidence, or invents remediation commands.
This base package works fully offline / --no-ai; AI provider support is
installed separately via pip extras (see /usr/share/doc/ipa-diagnose).}

%description %_description

%prep
%autosetup -n %{name}-%{version}

# EL10-only build-compat shim (does NOT touch the canonical, cross-distro
# pyproject.toml carried in the tarball for Fedora/EL9/etc - see
# packaging/rpm/el10/README or the packaging docs for why this differs by
# target). AlmaLinux/Rocky/RHEL 10's base+AppStream+CRB+EPEL10 repos all top
# out at python3-setuptools 69.0.3 (verified: EPEL10 does not carry a newer
# setuptools, and EL10 dropped module streams entirely, so there is no
# installable "newer Python" escape hatch either - see docs/packaging.md).
# The project's real >=77 requirement exists solely to parse the PEP 639
# SPDX-expression `license = "Apache-2.0"` string form; setuptools 69.0.3
# hard-fails on that exact string with:
#   ValueError: invalid pyproject.toml config: `project.license`.
#   configuration error: `project.license` must be valid exactly by one
#   definition (2 matches found) ...
# (reproduced independently with --no-build-isolation against the unmodified
# tarball before writing this patch). The fix below is metadata-form-only:
# it swaps to the older `license = {text = ...}` table form setuptools 69
# understands and lowers the pin to match what EL10 actually ships. The
# license itself is unchanged (still Apache-2.0, and independently declared
# via this spec's own License: tag), and no BuildRequires on a
# not-yet-existing "newer setuptools" package is introduced.
sed -i -E 's/^requires = \["setuptools>=77", "wheel"\]/requires = ["setuptools>=68", "wheel"]/' pyproject.toml
sed -i -E 's/^license = "Apache-2\.0"/license = {text = "Apache-2.0"}/' pyproject.toml

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files ipa_diagnose

%check
# Fixture-based tests only: fully offline, no live FreeIPA/network/root
# required, so they are safe and meaningful to run as part of the RPM build
# itself - a broken package should fail to build, not just fail at runtime.
%pytest tests/unit tests/packs

%files -f %{pyproject_files}
%license LICENSE
%doc README.md
%{_bindir}/ipa-diagnose

%changelog
* Sun Sep 20 2026 Azeem Siddiqui <azeemsidd509@gmail.com> - 0.1.3-1
- 0.1.3: every failed ipa-healthcheck finding is accounted for. Findings no rule
  explains are listed as UNDIAGNOSED and make the run NOT_FULLY_VERIFIED (exit 4),
  never HEALTHY. Fixes an inverted diagnosis of an expired Directory Server
  certificate and several rules that claimed checks they did not understand.
  See docs/healthcheck-coverage.md.
* Sat Sep 19 2026 Azeem Siddiqui <azeemsidd509@gmail.com> - 0.1.2-1
- 0.1.2: evidence completeness (UNKNOWN / NOT_FULLY_VERIFIED, exit code 4),
  explicit RUV state with a read-only LDAPI read (no Directory Manager password),
  stopped-service findings no longer dropped, verify never reports RESOLVED
  without evidence. See docs/evidence-completeness.md.
* Tue Sep 15 2026 ipa-diagnose contributors <noreply@example.invalid> - 0.1.0-1
- Initial EL10 package (AlmaLinux/Rocky/RHEL 10). Patches the vendored
  pyproject.toml at build time only to match EL10's setuptools 69.0.3
  (see %%prep for details); no change to the upstream/PyPI source.
