%{!?version: %global version 0.1.0}
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

# Not build-required, but strongly recommended at runtime - ipa-diagnose
# shells out to these rather than importing them, so they are Suggests, not
# hard Requires: the tool must remain installable (and partially useful, e.g.
# `--replay` against fixtures) even on a host that isn't a FreeIPA server yet.
Recommends:     freeipa-healthcheck
Recommends:     freeipa-server-common

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
* Sat Sep 19 2026 Azeem Siddiqui <azeemsidd509@gmail.com> - 0.1.2-1
- 0.1.2: evidence completeness (UNKNOWN / NOT_FULLY_VERIFIED, exit code 4),
  explicit RUV state with a read-only LDAPI read (no Directory Manager password),
  stopped-service findings no longer dropped, verify never reports RESOLVED
  without evidence. See docs/evidence-completeness.md.
* Tue Sep 15 2026 ipa-diagnose contributors <noreply@example.invalid> - 0.1.0-1
- Initial package.
