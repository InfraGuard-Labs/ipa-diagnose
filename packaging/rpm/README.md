# RPM packaging

This directory builds real, installable `ipa-diagnose` RPMs entirely inside
Docker - nothing here touches the host, and nothing here installs the RPM on
the host either. It targets the `sudo dnf install ./ipa-diagnose-*.rpm`
experience FreeIPA/Red Hat IdM administrators expect.

## Per-target builds

**A single spec does not build unmodified across RHEL 8/9/10 and Fedora** -
this was tried and disproven directly (EL9/EL10 fail on the project's own
`setuptools>=77` build requirement; EL8 additionally can't use its default
Python at all). Each target therefore has its own spec and build
Dockerfile, all producing a package with the same functionality:

| Directory | Target | Key difference from the Fedora spec |
|---|---|---|
| `fedora/` | Current Fedora (pinned to an exact tag, e.g. `fedora:44` - never `fedora:latest`, which is what caused the original `python(abi) = 3.14` surprise) | None - Fedora's own toolchain needs no workaround |
| `el9/` | RHEL/Rocky/AlmaLinux 9 | Split-interpreter build (bootstrap with AppStream `python3.11`, ship against system `python3.9`) plus a build-time-only `pyproject.toml` patch, since EL9's own `python3-setuptools` (53.0.0) predates PEP 621 entirely |
| `el10/` | RHEL/Rocky/AlmaLinux 10 | A build-time-only `pyproject.toml` patch (setuptools floor + license field form), since EL10's `python3-setuptools` (69.0.3) can build PEP 621 metadata but not this project's PEP 639 SPDX license string |
| `el8/` | RHEL/Rocky/AlmaLinux 8 | Builds against the `python39` AppStream module (system Python 3.6 is never used/touched); `rich` is vendored into the package since no EL8-compatible `python39-rich` exists anywhere |

Every per-target `pyproject.toml` patch is applied in the spec's `%prep`
section to a **copy** extracted from the source tarball - the canonical,
tracked `pyproject.toml` that ships to PyPI is never touched by any of
these builds. See each spec's own comments for the exact, independently-
verified failure it works around, and [docs/compatibility.md](../../docs/compatibility.md)
for the full cross-platform evidence.

The original top-level `ipa-diagnose.spec` / `Dockerfile.rpmbuild` /
`build-rpm.sh` / `install-test.sh` (below) remain as the Fedora-equivalent
reference implementation each per-target build was adapted from.

## What's here

| File | Purpose |
|---|---|
| `ipa-diagnose.spec` | The RPM spec. Uses `pyproject-rpm-macros` (Fedora/RHEL9+'s standard way to build a Python package as an RPM) so dependencies are generated automatically from `pyproject.toml` - `rich` becomes a real `Requires:`, and the `openai`/`anthropic`/`bedrock` extras are *not* pulled in as hard RPM dependencies (AI stays optional, installed via `pip install ipa-diagnose[openai]` etc. inside a venv if wanted - see the main README's AI configuration section). `%check` runs the full fixture-based test suite (`tests/unit`, `tests/packs`) as part of the build - a broken package fails to build. |
| `Dockerfile.rpmbuild` | A Fedora container with `rpm-build`, `pyproject-rpm-macros`, and everything needed to build the spec. **Historically used `fedora:latest`, which is how the published v0.1.0 RPM ended up with an unintentional `python(abi) = 3.14` requirement** - a moving base image silently changes what a rebuild produces. Prefer `fedora/Dockerfile.build` (pinned to an exact tag) for new builds; this file is kept as the original reference implementation. Confirmed directly (not assumed) that this spec does **not** build unmodified on RHEL9/RockyLinux9/AlmaLinux9 or 10/8 - see the per-target directories above for what each actually needs. |
| `build-rpm.sh` | Runs inside the container: tars the working tree, runs `rpmbuild -ba`. Supports `BUILD_VERSION`/`BUILD_RELEASE` env vars to build a bumped release without touching the tracked `pyproject.toml` (used for the upgrade test below). |
| `Dockerfile.install-test` + `install-test.sh` | A **separate, clean** Fedora container - `ipa-diagnose` is never baked into this image. The RPM is installed at container run time from a mounted file, exactly like a real `dnf install ./ipa-diagnose-*.rpm`, then the script verifies install, dependency resolution, CLI behavior (including graceful degradation with no FreeIPA present), a `--replay` demo run, upgrade to a newer build, and uninstall. |

## Building a specific target (EL8 / EL9 / EL10 / Fedora)

The commands below build the Fedora/reference target specifically. For any
other target, the same three steps apply with the directory name swapped
in - e.g. for EL8:

```bash
docker build -f packaging/rpm/el8/Dockerfile.build -t ipa-diagnose-rpmbuild-el8:local .
mkdir -p packaging/rpm/el8/rpmbuild
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$(pwd)/packaging/rpm/el8/rpmbuild:/rpmbuild" \
  ipa-diagnose-rpmbuild-el8:local
```

and identically for `el9`/`el10` (swap `el8` for `el9`/`el10` throughout;
each target's own `Dockerfile.build` and `build-rpm.sh` live in its own
directory). Each target's install-test Dockerfile, where one exists
(`el8/Dockerfile.install-test`), follows the same substitution against
step 4 below.

## Building and verifying locally (Docker only)

```bash
# Windows Git Bash / any POSIX shell with Docker Desktop:
# MSYS_NO_PATHCONV=1 is needed on Windows Git Bash so container-side paths
# in -v host:container mounts aren't rewritten as Windows paths.

# 1. Build the RPM builder image
docker build -f packaging/rpm/Dockerfile.rpmbuild -t ipa-diagnose-rpmbuild:local .

# 2. Build the RPM (runs the test suite as part of %check)
mkdir -p packaging/rpm/rpmbuild/v1
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$(pwd)/packaging/rpm/rpmbuild/v1:/rpmbuild" \
  ipa-diagnose-rpmbuild:local

# 3. (optional, for the upgrade test) build a second, bumped release
mkdir -p packaging/rpm/rpmbuild/v2
MSYS_NO_PATHCONV=1 docker run --rm -e BUILD_VERSION=0.1.1 \
  -v "$(pwd)/packaging/rpm/rpmbuild/v2:/rpmbuild" \
  ipa-diagnose-rpmbuild:local

# 4. Build the install-test image and run the full lifecycle check
docker build -f packaging/rpm/Dockerfile.install-test -t ipa-diagnose-install-test:local .
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$(pwd)/packaging/rpm/rpmbuild/v1/RPMS/noarch:/rpms/v1:ro" \
  -v "$(pwd)/packaging/rpm/rpmbuild/v2/RPMS/noarch:/rpms/v2:ro" \
  -v "$(pwd)/tests/fixtures:/fixtures:ro" \
  ipa-diagnose-install-test:local
```

The install-test container verifies, in order: fresh install from a local
RPM file, that `python3-rich` was pulled in automatically and is actually
importable, `ipa-diagnose --version`/`--help`, a live run on a host with no
FreeIPA installed (must degrade gracefully, not crash), a `--replay` demo
run against a bundled fixture, an upgrade to a newer release (version
actually changes, command still works), and a clean uninstall (package and
command both gone). Last run: **11/11 passed**.

## What's validated vs. what still requires a manual step

**Validated in Docker, right now, by the commands above:**
- The spec builds correctly with `pyproject-rpm-macros` and generates correct
  dependencies (`python3dist(rich)`) without hand-maintaining a `Requires:` list.
- `%check` runs the real fixture-based test suite during the build.
- Fresh install, dependency resolution, CLI behavior, upgrade, and uninstall
  all work via plain `dnf`, exactly as an administrator would experience them.
- `.copr/Makefile`'s `srpm` target (COPR's "Custom" source method entry
  point) produces a valid `.src.rpm` - verified locally with
  `rpm -qip` against the same rpmbuild image (see `.copr/Makefile`'s header
  comment for the exact command).

**The one remaining manual step - publishing so `dnf install ipa-diagnose`
works on a real machine without a locally-built RPM file:**

1. Create (or use) a Fedora account and log into
   [copr.fedorainfracloud.org](https://copr.fedorainfracloud.org/).
2. Create a new COPR project, e.g. `ipa-diagnose` under your username/group.
3. In the project's Build Settings, add a build with **Source type: Custom**:
   - Repository: this repo's URL (`https://github.com/InfraGuard-Labs/ipa-diagnose`)
   - Path to Makefile: `.copr/Makefile`
   - Makefile target: `srpm`
   - Builder host dependencies: `rpm-build tar gzip make`
4. Trigger a build. COPR checks out the repo, runs
   `make -f .copr/Makefile srpm outdir=<dir>`, and builds the resulting
   `.src.rpm` for each enabled chroot (e.g. `fedora-42-x86_64`,
   `epel-9-x86_64`).
5. Once it succeeds, administrators get the real target experience:

   ```bash
   sudo dnf copr enable <your-username>/ipa-diagnose
   sudo dnf install ipa-diagnose
   sudo ipa-diagnose
   ```

This requires a maintainer's personal Fedora account and cannot be performed
from this environment - everything up to that point (the spec, the Makefile,
and full local verification that both produce correct, installable RPMs) is
done and reusable as-is once that account exists.

Official Fedora/EPEL inclusion (making `dnf install ipa-diagnose` work with
zero extra repo configuration) is a further step on top of COPR, requiring a
formal Fedora package review - appropriate once the project has real users,
not before (this mirrors `ipa-healthcheck`'s own history: it started as a
COPR-distributed tool before landing in Fedora/RHEL directly).

## Design notes

- **AI extras are not RPM sub-packages in v1.** `openai`/`anthropic`/`boto3`
  are heavy transitive dependencies inappropriate to force onto every
  `dnf install ipa-diagnose`, and the core product is explicitly designed to
  be fully useful with `--no-ai`. Administrators who want AI-assisted
  explanations install the extras via pip into a venv (documented in the
  main README) - a v1.1 candidate is a `python3-ipa-diagnose-ai` sub-package
  once there's real demand.
- **`Recommends:` (not `Requires:`) `freeipa-healthcheck`/`freeipa-server-common`.**
  The package must remain installable (and partially useful via `--replay`)
  on a host that isn't a FreeIPA server yet - a hard dependency would prevent
  that and doesn't match how `ipa-healthcheck` itself is packaged.
