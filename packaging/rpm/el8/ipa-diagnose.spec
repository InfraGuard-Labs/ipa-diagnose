%{!?version: %global version 0.1.2}
%{!?release: %global release 1}

# --- EL8 / python39 AppStream module target ---------------------------------
#
# EL8's DEFAULT python3 is the python36 module stream (Python 3.6.8) - it is
# what /usr/bin/python3, dnf, yum, and other system tools use, and this spec
# never touches it: no BuildRequires, Requires, or macro here resolves
# against it. This spec instead targets EL8's `python39` AppStream module,
# a real, separately-installed Python 3.9.25 that lives alongside (never
# replaces) system python3.
#
# Installing `python39-devel` drops in /usr/lib/rpm/macros.d/macros.python39,
# which already redefines %%__python3 -> /usr/bin/python3.9 and
# %%python3_pkgversion -> 39 for the whole build root. The two lines below are
# set explicitly anyway, both to document intent and so this spec keeps
# working correctly even if that macros file's own defaults ever change.
# Because this redefinition is build-root-wide (not scoped to this one spec),
# packaging/rpm/el8/Dockerfile.build intentionally never installs EL8's
# default `python3`/`python3-devel` alongside `python39-devel`, to avoid any
# ambiguity about which interpreter a bare `%%{__python3}` resolves to.
%global __python3 /usr/bin/python3.9
%global python3_pkgversion 39

# Populated by packaging/rpm/el8/Dockerfile.build (see its comments): a
# `pip download`-populated local wheelhouse used ONLY with `pip install
# --no-index`, i.e. this spec never reaches out to the network during
# rpmbuild itself. Override with --define if the image places it elsewhere.
%{!?_vendor_wheeldir: %global _vendor_wheeldir /opt/el8-vendor-wheels}

Name:           ipa-diagnose
Version:        %{version}
Release:        %{release}%{?dist}
Summary:        Evidence-grounded diagnostic and correlation engine for FreeIPA / Red Hat IdM (EL8 / python39 build)

License:        Apache-2.0
URL:            https://github.com/InfraGuard-Labs/ipa-diagnose
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python39-devel
BuildRequires:  pyproject-rpm-macros

# --- Why this spec looks structurally different from packaging/rpm/ipa-diagnose.spec ---
#
# The Fedora/EL9 spec uses `%%generate_buildrequires` + `%%pyproject_buildrequires`
# to auto-discover build/test/runtime dependencies from pyproject.toml and
# auto-resolve them against real distro packages (python3-pytest,
# python3-rich, ...). None of that is available on EL8:
#
#   1. EPEL8's pyproject-rpm-macros (0.1.12.0) is explicitly the "minimal"
#      build - verified directly (`rpm -ql pyproject-rpm-macros`, then
#      inspecting /usr/lib/rpm/macros.d/macros.pyproject): it defines
#      %%pyproject_wheel, %%pyproject_install, %%pyproject_save_files, and
#      %%pyproject_check_import, but NOT %%generate_buildrequires's payload
#      macro %%pyproject_buildrequires. That's because dynamic/"two-pass"
#      BuildRequires generation is an RPM core feature EL8's rpm 4.14.3
#      does not implement (it landed later, in rpm 4.15+); EPEL8 ships
#      macros that don't assume it.
#   2. Even setting that aside: literal `BuildRequires: python3-devel` /
#      `python3dist(pytest)` (as in the unmodified spec) are checked by
#      `rpm`/`dnf` as ordinary package/virtual-provide names BEFORE any
#      %%prep/%%build/%%generate_buildrequires code ever runs, and they
#      resolve against the DEFAULT python3 (3.6) ABI regardless of any
#      `--define __python3 ...` override - confirmed directly: running
#      `rpmbuild --define '__python3 /usr/bin/python3.9' -ba` against the
#      unmodified spec on this python39-only image fails immediately with
#      "Failed build dependencies: python3-devel is needed ... /
#      python3dist(pytest) is needed ..." without ever reaching %%prep.
#   3. There is also no python39-prefixed pytest, rich, or modern-enough
#      setuptools package anywhere in EL8 (AppStream, BaseOS, Extras, or
#      EPEL8) to BuildRequire even if the macros above did exist -
#      `dnf repoquery --whatprovides 'python39dist(pytest)' 'python39dist(rich)'
#      'python39dist(setuptools)'` returns nothing on any enabled repo.
#      EL8's python39 module ships only the bare interpreter, pip, devel
#      headers, and setuptools 50.3.2 - which predates PEP 621 `[project]`
#      table support entirely (added in setuptools ~61), let alone the
#      SPDX `license = "Apache-2.0"` string form this project's
#      pyproject.toml requires setuptools>=77 for.
#
# The legitimate fix used here, given EL8 genuinely has no distro-native
# path for any of this: packaging/rpm/el8/Dockerfile.build pip-installs a
# pinned, modern setuptools/wheel/pytest/pytest-cov directly into
# /usr/bin/python3.9's own site-packages (specifically via `pip install
# --target /usr/lib/python3.9/site-packages`, NOT a plain `pip install
# --upgrade` - confirmed directly that a plain install lands in /usr/local,
# which rpm's own %%pyproject_wheel macro cannot see because it always runs
# the interpreter as `-Bs`; see Dockerfile.build's own comment for the full
# story) at Docker-IMAGE-build time, before rpmbuild ever runs. These are
# BUILD- and TEST-time-only tools - never shipped in the RPM, never a
# runtime Requires - exactly analogous to what `BuildRequires: python3-devel
# python3-setuptools` provides on Fedora; `%%pyproject_wheel` itself runs
# `pip wheel --no-build-isolation`, i.e. it already expects the build
# backend to be preinstalled rather than fetched per-build, so this matches
# the macros' own design, not a workaround of it.
#
# `rich`, unlike setuptools/pytest, is a genuine RUNTIME dependency of the
# installed CLI, so it cannot be handled as build-only tooling. It is
# vendored instead: pip-installed --target into this package's own
# site-packages tree from %%{_vendor_wheeldir} (itself populated by `pip
# download` at Docker-image-build time - see Dockerfile.build), fully
# offline at rpmbuild time. rich (MIT) and its own small dependency chain
# (pygments, markdown-it-py, mdurl - all pure Python, all permissively
# licensed) are shipped inside this RPM's own site-packages so the built
# package needs nothing beyond the `python39` module itself: no
# python39dist(rich) Requires is generated (nothing provides it on EL8),
# and none is needed.

# DELIBERATELY NO Recommends here (found in gate review: this spec still
# had `Recommends: freeipa-healthcheck`/`freeipa-server-common` after the
# EL9/EL10 specs had theirs removed for causing a 300+ package install and
# a broken `dnf remove` transaction - see packaging/rpm/el9/ipa-diagnose.spec
# for the full incident). Those exact Fedora-style names are not currently
# resolvable on EL8 (`dnf repoquery` confirms neither exists under those
# names in base/AppStream/EPEL8/CRB), so removing them changes nothing
# functional today - but leaving unresolvable Recommends in place would be
# a latent trap, not a safe no-op: AlmaLinux 9/10 were BOTH found to
# resolve the equivalent EL9/EL10 names via a compatibility Provides that
# neither this project nor EL8's own repos currently advertise. If EL8
# repos, a future IdM module stream, or a downstream rebuild ever exposes
# the same kind of compatibility Provides, an un-removed Recommends here
# would reintroduce the identical explosion/broken-uninstall risk with no
# guard against it. Omitted for consistency with EL9/EL10, not because
# EL8 was ever proven safe by design.

%global _description %{expand:
ipa-diagnose sits on top of ipa-healthcheck and targeted, read-only system
evidence (journalctl, certmonger, replication agreements, DNS lookups) to
correlate related failures into a single deterministic root-cause diagnosis,
explain impact, and recommend safe next steps. AI (OpenAI/Anthropic/Bedrock)
is optional and only ever explains an already-computed diagnosis - it never
determines root cause, invents evidence, or invents remediation commands.
This base package works fully offline / --no-ai; AI provider support is
installed separately via pip extras (see /usr/share/doc/ipa-diagnose).

This is the EL8 build: it targets the `python39` AppStream module (Python
3.9.25) rather than EL8's default python3 (3.6.8, python36 module), which
this package never touches. `rich` is bundled in this build (see the spec
header comment) because EL8 provides no distro-native python39-rich.}

%description %_description

%prep
%autosetup -n %{name}-%{version}

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files ipa_diagnose

# Vendor rich (+ pygments, markdown-it-py, mdurl) into this package's own
# site-packages - see the spec header comment for why. --no-index means
# this never touches the network here; it only ever reads
# %%{_vendor_wheeldir}, which Dockerfile.build populated (with exact,
# hash-verified pins - see that file's comment) at image-build time. The
# exact version here must match Dockerfile.build's pin exactly, not a
# range - a range would work today (only one candidate exists in the
# offline wheelhouse anyway) but would silently stop being an effective
# pin if the wheelhouse ever gained a second rich version.
%{__python3} -m pip install \
    --no-index --find-links %{_vendor_wheeldir} \
    --target %{buildroot}%{python3_sitelib} \
    --disable-pip-version-check --no-warn-script-location --no-compile \
    'rich==14.3.4'
# pip drops a console-script shim (rich's optional `pygmentize`-style entry
# points, if any) and __pycache__ dirs into --target; neither is wanted:
# the shims would reference the buildroot's own path, and bytecode is
# rebuilt/owned normally via the RPM's own %%{__python3} compile pass on
# the site-packages tree as a whole.
rm -rf %{buildroot}%{python3_sitelib}/bin
find %{buildroot}%{python3_sitelib} -name '__pycache__' -type d -exec rm -rf {} +

%check
# Fixture-based tests only: fully offline, no live FreeIPA/network/root
# required. Invoked directly via `-m pytest` (not the `%%pytest` macro):
# that macro calls %%{__pytest}, which macros.python39 points at
# /usr/bin/pytest-3.9 - a filename EL8's python39 module does not ship and
# that pip has no reason to create (pip's pytest console script lands at
# /usr/local/bin/pytest instead). `%%{__python3} -m pytest` is equivalent
# and does not depend on that filename.
#
# PYTHONPATH is required here (confirmed directly, in two stages):
#   1. `src` - this is a src-layout project (`[tool.setuptools.packages.find]
#      where = ["src"]`); %%check's cwd is the raw %%{_builddir} source tree,
#      and without it `import ipa_diagnose` resolves nowhere (fails on every
#      test with `ModuleNotFoundError: No module named 'ipa_diagnose'`).
#   2. %%{buildroot}%%{python3_sitelib} - `rich` (this build's vendored
#      runtime dependency - see %%install) is never installed into the
#      python39 module's own site-packages, only into %%{buildroot} by
#      %%install; with just `src` on PYTHONPATH, collection instead fails
#      with `ModuleNotFoundError: No module named 'rich'` importing
#      ipa_diagnose.cli. rpm's default scriptlet order runs %%install before
#      %%check (confirmed directly from build output), so %%{buildroot}'s
#      copy already exists by the time %%check runs; reusing it here avoids
#      installing rich a second time into the image just for testing.
PYTHONPATH=src:%{buildroot}%{python3_sitelib} %{__python3} -m pytest tests/unit tests/packs

%files -f %{pyproject_files}
%license LICENSE
%doc README.md
%{_bindir}/ipa-diagnose
# Vendored runtime dependency (see %%install) - not covered by
# %%{pyproject_files}, which only tracks the ipa_diagnose module itself.
# Each dist-info directory carries its own upstream license file, so no
# separate %%license entries are needed for them.
%{python3_sitelib}/rich/
%{python3_sitelib}/rich-*.dist-info/
%{python3_sitelib}/pygments/
%{python3_sitelib}/pygments-*.dist-info/
%{python3_sitelib}/markdown_it/
%{python3_sitelib}/markdown_it_py-*.dist-info/
%{python3_sitelib}/mdurl/
%{python3_sitelib}/mdurl-*.dist-info/

%changelog
* Sat Sep 19 2026 Azeem Siddiqui <azeemsidd509@gmail.com> - 0.1.2-1
- 0.1.2: evidence completeness (UNKNOWN / NOT_FULLY_VERIFIED, exit code 4),
  explicit RUV state with a read-only LDAPI read (no Directory Manager password),
  stopped-service findings no longer dropped, verify never reports RESOLVED
  without evidence. See docs/evidence-completeness.md.
* Thu Sep 17 2026 ipa-diagnose contributors <noreply@example.invalid> - 0.1.0-1
- Initial EL8 (python39 AppStream module) package.
