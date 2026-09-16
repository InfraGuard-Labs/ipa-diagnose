# RPM packaging

This directory builds a real, installable `ipa-diagnose` RPM entirely inside
Docker - nothing here touches the host, and nothing here installs the RPM on
the host either. It targets the eventual `sudo dnf install ipa-diagnose`
experience FreeIPA/Red Hat IdM administrators expect.

## What's here

| File | Purpose |
|---|---|
| `ipa-diagnose.spec` | The RPM spec. Uses `pyproject-rpm-macros` (Fedora/RHEL9+'s standard way to build a Python package as an RPM) so dependencies are generated automatically from `pyproject.toml` - `rich` becomes a real `Requires:`, and the `openai`/`anthropic`/`bedrock` extras are *not* pulled in as hard RPM dependencies (AI stays optional, installed via `pip install ipa-diagnose[openai]` etc. inside a venv if wanted - see the main README's AI configuration section). `%check` runs the full fixture-based test suite (`tests/unit`, `tests/packs`) as part of the build - a broken package fails to build. |
| `Dockerfile.rpmbuild` | A Fedora container with `rpm-build`, `pyproject-rpm-macros`, and everything needed to build the spec. Fedora is used (rather than RHEL/CentOS/Alma images) purely to avoid EPEL/CRB mirror configuration inside a container build - the spec itself is standard and builds unmodified on RHEL9/CentOS Stream 9/AlmaLinux 9/Rocky 9 with EPEL9 + CRB (or PowerTools on 8) enabled. |
| `build-rpm.sh` | Runs inside the container: tars the working tree, runs `rpmbuild -ba`. Supports `BUILD_VERSION`/`BUILD_RELEASE` env vars to build a bumped release without touching the tracked `pyproject.toml` (used for the upgrade test below). |
| `Dockerfile.install-test` + `install-test.sh` | A **separate, clean** Fedora container - `ipa-diagnose` is never baked into this image. The RPM is installed at container run time from a mounted file, exactly like a real `dnf install ./ipa-diagnose-*.rpm`, then the script verifies install, dependency resolution, CLI behavior (including graceful degradation with no FreeIPA present), a `--replay` demo run, upgrade to a newer build, and uninstall. |

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
