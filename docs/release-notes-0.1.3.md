# ipa-diagnose 0.1.3

A safety release from a full audit of how ipa-diagnose handles ipa-healthcheck output
(ipa-healthcheck 0.12, 0.16, 0.19 and master; 85 distinct check IDs; source-level and
synthetic - see [healthcheck-coverage.md](healthcheck-coverage.md)).

## What changed
- **Every failed finding is accounted for.** Every WARNING/ERROR/CRITICAL (or unrecognised
  severity) ipa-healthcheck finding is either diagnosed, used as supporting evidence, or listed as
  *undiagnosed*. Before: 57 check/level combinations in ipa-healthcheck master (41 in 0.12) were
  silently unhandled. After: 0.
- **Status policy.** A run whose only failed findings are undiagnosed is `NOT_FULLY_VERIFIED`
  (exit 4), not `HEALTHY`. `UNKNOWN` is now reserved for missing/insufficient base evidence. An
  unresolved primary problem with no established cause is `NOT_FULLY_VERIFIED` rather than `UNKNOWN`.
  A diagnosed problem still wins (`DEGRADED`/`CRITICAL`). **Behaviour change:** servers with benign
  upstream warnings that no rule explains now exit 4 instead of 0.
- **Expired Directory Server certificate** (`ds.nss_ssl` `NssCheck`, `DSCERTLE0001/2`) was
  wrongly reported as "NSS DB format mismatch, not a certificate lifecycle problem" (since v0.1.0).
  It is now a certificate-expiry diagnosis.
- **Rules match exact checks, not whole sources**, fixing wrong claims for: a wrong umask, an
  unmounted file system, non-expiry certificate-check errors, external certificates, a CA down
  (IPA error 4301) read as an RA-agent desync, hostnames containing "dns", unexpected DNS records,
  a missing keytab file, amber/unfetchable replication status, and a wrong reindex attribute.
  Dead paths now work: lib389 conflict warnings (`DSREPLLE0002`) and the real topology
  "can't contact servers" message.
- **JSON (additive):** `undiagnosed_findings`, `undiagnosed_count`, `has_undiagnosed_findings`.
  `unclaimed_warnings` is unchanged.

## What this does not mean
Not every finding is diagnosed, and this is ipa-healthcheck coverage, not complete FreeIPA
troubleshooting coverage. Live validation was on FreeIPA 4.13.3 (Fedora 43 image); no genuine RHEL
host was used; a real stale RUV was not reproduced.
