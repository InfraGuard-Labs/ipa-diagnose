# Troubleshooting ipa-diagnose itself

## "Evidence collection issues" listed at the bottom of a run

This is `ipa-diagnose` telling you a collector couldn't run - it degrades
visibly rather than silently, and rather than crashing. Common causes:

- **`ipa-healthcheck: ipa-healthcheck is not installed or not on PATH`** -
  either you're not on a FreeIPA server, or `ipa-healthcheck` genuinely
  isn't installed (`sudo dnf install freeipa-healthcheck`). The rest of the
  diagnosis still runs; it just has no `ipa-healthcheck` findings to work
  from. See `19_rpm_first_run.png` for exactly this case.
- **`exited N: ... permission ...` / "root"** - most collectors
  (`journalctl`, `getcert list`, `ipa-replica-manage`, keytab-based
  `ldapsearch`) need root. Run with `sudo`.
- **A specific collector name with a malformed-fixture-style message** - only
  relevant under `--replay`; means the fixture JSON for that collector
  doesn't parse. Real hosts don't hit this path.

## `sudo ipa-diagnose` reports HEALTHY but I know something's wrong

Check the "Diagnostic packs evaluated" and "Evidence collection issues"
lines at the bottom of the output first - if a relevant collector failed,
the engine may genuinely not have the evidence it would need. Beyond that,
v1 covers 5 diagnostic packs (see [docs/diagnostic-packs.md](diagnostic-packs.md));
if your problem is outside all five, `ipa-diagnose` won't produce a false
positive, but it also won't produce a diagnosis - `ipa-healthcheck --output-type
json` directly, or `--details`, may still surface something.

## I got `UNKNOWN_INSUFFICIENT_EVIDENCE` / `UNKNOWN_CONFLICTING_EVIDENCE`

This is working as intended, not a bug - see
[docs/architecture.md](architecture.md#diagnostic-packs-and-rules) and
`06_unknown_insufficient_evidence.png`. The `next_diagnostic_step` field
(always present for a non-`DIAGNOSED` result) is a safe, read-only command
to run to disambiguate further. Run it, then re-run `ipa-diagnose` - new
evidence may let a rule reach a confident diagnosis on the next pass.

## `verify` says "No previous diagnosis found"

`verify` compares against the last `diagnose` run's saved state
(`IPA_DIAGNOSE_STATE_DIR`, default `/var/lib/ipa-diagnose/last_report.json`
or `~/.cache/ipa-diagnose/`). Run `sudo ipa-diagnose` first.

## AI explanation isn't showing up even though I set `--ai-provider`

Check for a `(AI provider '...' is not configured - showing local
explanation)` or `(AI explanation unavailable for '...' - showing local
explanation)` line - both are printed deliberately when a provider can't run
(missing API key, timeout, rate limit, refusal, or a malformed/rejected
response). Run `sudo ipa-diagnose ai-preview` to see the exact payload that
would be sent, and check the provider's own credential/network setup (see
[docs/ai-configuration.md](ai-configuration.md)). The deterministic
diagnosis itself is never affected either way.

## Docker development environment

- **`docker compose run --rm dev <cmd>` fails with "cannot execute binary
  file"** - this was a real issue during development caused by a custom
  `entrypoint` intercepting the command; the shipped `docker-compose.yml`
  has no custom entrypoint, so `<cmd>` runs directly. If you've modified it
  and hit this again, that's the likely cause.
- **On Windows Git Bash**, `-v host:container` volume mounts can have their
  *container-side* path mangled into a Windows path by MSYS's automatic
  path conversion. Prefix the command with `MSYS_NO_PATHCONV=1` (see
  [packaging/rpm/README.md](../packaging/rpm/README.md) for worked
  examples) if a mount behaves unexpectedly.
