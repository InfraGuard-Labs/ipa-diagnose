# Installation in detail

The README has the short version. This page keeps the details: per-distribution steps, what the EL8 package does to
Python, checksums, and the pipx root/sudo caveat. What was tested where: [compatibility.md](compatibility.md).

`ipa-diagnose` runs where FreeIPA already is: on an IPA server (`ipa-diagnose`, `verify`, `bundle`, `replication`),
on an enrolled IPA client (`client`, `access --runtime`), or anywhere with `curl`, the IPA CA certificate and a
Kerberos ticket (`access`). The server and client commands need root. **If you run it routinely as root, prefer the
RPM**: it installs to `/usr/bin`, so plain `sudo ipa-diagnose` works. pipx suits development, testing and a quick
evaluation.

## RPM (RHEL / Rocky / AlmaLinux 8, 9, 10, and Fedora)

Each target has its own RPM, built and lifecycle-tested in Docker against a clean container of that distribution
(install, dependency resolution, `--version`, `--help`, CLI startup without FreeIPA, `--replay`, uninstall,
reinstall). **RHEL itself was never tested**: the EL rows are Rocky Linux, AlmaLinux and UBI containers. See
[packaging/rpm/README.md](../packaging/rpm/README.md) to build them yourself.

**RHEL/Rocky/AlmaLinux 9 or 10**: the `rich` runtime dependency comes from EPEL, so enable it first:

```bash
sudo dnf install -y epel-release dnf-plugins-core
sudo dnf config-manager --set-enabled crb    # "PowerTools" on some 8.x mirrors
sudo dnf install ./ipa-diagnose-<version>.el9.noarch.rpm   # or .el10.noarch.rpm
sudo ipa-diagnose
```

**RHEL/Rocky/AlmaLinux 8**: EL8's default Python (3.6) is too old; the RPM depends on the `python39` module stream,
installed alongside it, not replacing it:

```bash
sudo dnf install -y python39
sudo dnf install ./ipa-diagnose-<version>.el8.noarch.rpm
sudo ipa-diagnose
```

What "not replacing it" precisely means (tested on both Rocky and AlmaLinux 8, confirmed to differ):
`platform-python` (`/usr/libexec/platform-python`), the interpreter `dnf`/`rpm`/`yum` depend on, is never touched on
either distribution - verified with `rpm -V platform-python` showing zero drift before/after install, uninstall and
reinstall. The visible `/usr/bin/python3` symlink differs by distribution: on Rocky Linux 8 a pre-existing `python3.6`
alternative keeps `python3 --version` at 3.6 after installing `python39`; on a minimal AlmaLinux 8 host with no
`python3` symlink registered yet, installing `python39` creates it, pointing at 3.9. Either way nothing your system
tooling depends on is affected.

The `rich` runtime dependency is vendored into the EL8 package itself, since no EL8-compatible `python39-rich`
package exists anywhere to depend on (a security fix in `rich` then needs an `ipa-diagnose` package update; see
[compatibility.md](compatibility.md)).

**Fedora** (current stable):

```bash
sudo dnf install ./ipa-diagnose-<version>.fc44.noarch.rpm
sudo ipa-diagnose
```

Fedora 43 works too (tested), but only the `.fc44.` file is published; install it on 44, or use pipx.

Download the file for your platform from the
[latest release](https://github.com/InfraGuard-Labs/ipa-diagnose/releases/latest). Names look like
`ipa-diagnose-<version>-1.el9.el9.noarch.rpm` (the target - `.el8.`, `.el9.`, `.el10.`, `.fc44.` - is repeated by the
build; that is cosmetic). Verify the download, in the same directory as `SHA256SUMS`:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

`dnf` warns "skipped OpenPGP checks" for a local RPM file: the packages are not GPG-signed, which is why the checksum
step matters. The command is installed at `/usr/bin/ipa-diagnose` (`/usr/sbin` points to it on merged-`/usr`
systems).

## PyPI / pipx

```bash
pipx install ipa-diagnose
ipa-diagnose --version
```

On RHEL/Rocky/AlmaLinux 9 and 10, `pipx` itself comes from EPEL (`sudo dnf install -y epel-release && sudo dnf
install -y pipx`); on Fedora it is plain `sudo dnf install -y pipx`; on 8, EPEL has no `pipx` package, so use the
`python39` module:

```bash
sudo dnf install -y python39 && python3.9 -m pip install --user pipx
python3.9 -m pipx ensurepath      # then open a new shell so ~/.local/bin is on PATH
```

**Root/sudo caveat (tested, not assumed):** `pipx install` puts the executable in the installing user's
`~/.local/bin`, which is not on `sudo`'s `secure_path` by default on RHEL-family systems. After `pipx install
ipa-diagnose` as a regular user, plain `sudo ipa-diagnose` fails with `sudo: ipa-diagnose: command not found`, even
if pipx was run as root itself (root's own `~/.local/bin` is not on `secure_path` either). Two tested options,
neither of which touches `sudoers` or weakens `secure_path`:

```bash
# Option A: install and run as root directly (no further sudo needed)
sudo -i
pipx install ipa-diagnose
ipa-diagnose

# Option B: invoke through the absolute path (works from a normal login)
pipx install ipa-diagnose
sudo "$HOME/.local/bin/ipa-diagnose"
```

If you need unqualified `sudo ipa-diagnose` to work, use the RPM.

Optional AI provider SDKs are extras: `pip install ipa-diagnose[openai]`, `[anthropic]`, `[bedrock]` or `[ai]` for all
three. The base install has no AI dependency, and `--no-ai` needs none.

## Files it writes

ipa-diagnose is read-only towards FreeIPA (one upstream side effect: ipa-healthcheck's certificate checks start a
stopped, unmasked certmonger; the report says when that happened). It writes only its own saved results, used by the
verify commands (mode 0600, directory 0700): under `/var/lib/ipa-diagnose/` if that directory exists and is
writable, otherwise `~/.cache/ipa-diagnose/` (for root `/root/.cache/ipa-diagnose/`); `IPA_DIAGNOSE_STATE_DIR`
changes the location. `last_report.json` (diagnose), `client_last.json` (client), `replication_last.json`
(replication); `--replay` runs use separate `*.replay.json` files so a demo never overwrites a real baseline.
`access` saves nothing. `bundle` writes only the bundle file you asked for (mode 0600, never overwriting a file or
following a symlink). Removing the RPM does not delete the saved results.
