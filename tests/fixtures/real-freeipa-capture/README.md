# NOTE (0.1.3): the `healthy/` capture is a real, working FreeIPA server, but ipa-healthcheck reported a genuine CS.cfg file-mode WARNING and 13 warnings ipa-diagnose has no rule for, so it replays as DEGRADED with undiagnosed findings - not HEALTHY.

# Real FreeIPA server captures

Unlike every other directory under `tests/fixtures/`, the `healthcheck.json`
files here are **not hand-authored** - they are verbatim `ipa-healthcheck
--output-type json` output captured from an actual, real
`freeipa/freeipa-server:fedora-43` container (realm `IPADIAGNOSE.TEST`,
disposable test credentials, no production data), run as part of a bounded
real-FreeIPA validation pass. See [docs/limitations.md](../../../docs/limitations.md)
for what this tier of validation does and doesn't establish.

- **`healthy/healthcheck.json`** - 277 results from a freshly installed
  server (`ipa-server-install --no-ntp --skip-mem-check`, no `--setup-dns`):
  263 SUCCESS / 14 WARNING / 0 ERROR / 0 CRITICAL. The WARNINGs are
  legitimate and expected for this install (missing DNS SRV/URI records
  because DNS wasn't set up, and one real Tomcat `CS.cfg` file-permission
  warning).
- **`dirsrv-down/healthcheck.json`** - 186 results captured immediately
  after `systemctl stop dirsrv@IPADIAGNOSE-TEST.service` inside the same
  container: a genuine `dirsrv: not running` ERROR, plus a genuine CRITICAL
  from `IPAauthzdatapacCheck` (an uncaught `AttributeError: ldap2 is not
  connected` inside the healthcheck plugin itself, since LDAP was down) -
  this specific entry is what surfaced a real parsing gap (see below).

## What this validated

- The full evidence-collection -> diagnosis pipeline parses real
  `ipa-healthcheck` output end to end without crashing, on both a healthy
  server and one with a genuine, induced failure.
- `directory-server.ownership-selinux-mismatch` fired correctly against the
  real `TomcatFileCheck` file-permission finding, in both captures.

## What this found (and what was fixed as a direct result)

Real `ipa-healthcheck` output includes CRITICAL entries whose `kw` has **no
`msg` key at all** - only `exception`/`traceback` - when a check plugin
itself raises an uncaught exception (see the `IPAauthzdatapacCheck` entry
in `dirsrv-down/healthcheck.json`). `evidence/healthcheck.py`'s message
extraction originally only read `kw.msg`, silently turning this into an
empty string and discarding the only diagnostic content a CRITICAL result
had. Fixed in `evidence/healthcheck.py`'s `_extract_message()` (falls back
to `kw.exception`, then the traceback's last line) - see
`tests/unit/test_healthcheck.py`'s two new tests for this exact shape.

## What this did NOT find a rule for (a known, honest gap)

Neither the `dirsrv: not running` ERROR nor the `IPAauthzdatapacCheck`
CRITICAL triggered any additional diagnosis - only the same file-permission
finding both captures share. None of the directory-server pack's 4 rules
key off a generic "the dirsrv service itself is down" service-health
finding (`ipahealthcheck.meta.services`) - they're all more specific
(disk space, ownership/SELinux, NSS/TLS format, missing index). This is a
real, scoped v1 coverage gap, not a bug - see
[docs/limitations.md](../../../docs/limitations.md).


## Update (v0.1.2)

The "dirsrv down produced no additional diagnosis" gap noted above was closed in
v0.1.2 (`engine/unexplained.py`). Newer REAL LIVE CAPTURES (FreeIPA 4.13.3,
Fedora 43, GitHub Actions lab): `dirsrv-stopped/` and `certmonger-stopped/`.
