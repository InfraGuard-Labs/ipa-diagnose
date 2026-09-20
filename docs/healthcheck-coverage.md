# ipa-healthcheck coverage

ipa-diagnose does **not** re-implement ipa-healthcheck; it stays the primary deterministic
source. ipa-diagnose's job is to relate findings, name a likely root cause where the evidence
supports one, and say what to check next. The guarantee here is narrower and testable:

> **Every WARNING/ERROR/CRITICAL (or unrecognised-severity) finding ipa-healthcheck reports ends
> up DIAGNOSED, used as SUPPORTING evidence, or listed by name as UNDIAGNOSED. None disappears,
> and none is turned into a confident diagnosis just to improve coverage.**

This is *ipa-healthcheck coverage*. It is not the same as overall FreeIPA troubleshooting
coverage (see [limitations](limitations.md)), and it is not a percentage: many checks have no
deterministic root-cause logic, and saying so is the correct behaviour.

## The three outcomes

| Outcome | Meaning |
|---|---|
| **DIAGNOSED** | A rule recognises the specific result (check + key/message, not just the source) and explains it. |
| **SUPPORTING** | A rule cites the finding as evidence but the overall conclusion stays UNKNOWN. |
| **UNDIAGNOSED** | No rule explains it. It is listed under *UNDIAGNOSED ipa-healthcheck FINDINGS* (console), and in `--json` as `undiagnosed_findings`. Nothing is guessed. |

An UNDIAGNOSED finding is **not** a statement that it is harmless.

## Where it appears

* Console: a short *UNDIAGNOSED ipa-healthcheck FINDINGS* section (first 8 by default);
  `--details` lists all, with the reason, the upstream release the check first appeared in, and
  the installed ipa-healthcheck version.
* JSON: `undiagnosed_findings` — a list of `{source, check, severity, message, reason,
  check_crashed, check_known_since_ipa_healthcheck, ipa_healthcheck_version}`. All text is
  sanitised (terminal escapes removed, length bounded) and is never executed. The older
  `unclaimed_warnings` count is kept unchanged.
* ERROR/CRITICAL findings are also still grouped into one honest UNKNOWN diagnosis, and a
  stopped service is still a DIAGNOSED fact, exactly as before. Findings beyond that grouped
  diagnosis's shown limit are listed individually in `undiagnosed_findings`.
* AI never sees an undiagnosed finding as a cause: AI only explains an already-computed
  deterministic diagnosis, and an UNKNOWN stays UNKNOWN.

## Version awareness

The check inventory is generated from upstream source
([matrix](healthcheck-coverage-matrix.md)) for ipa-healthcheck 0.12 (EL8-era), 0.16
(EL9.4–9.7, EL10.0–10.1), 0.19 (EL9.8, EL10.2, Fedora) and master. Distro-to-version pairings
are inferred from package listings and are labelled as such; nothing was validated on real
RHEL. A check that does not exist in an older release simply never appears there; a check
absent from the output is **not** proof it passed (ipa-healthcheck skips dependent checks when
a service is down, and some checks are silent on some PKI versions).

## Known semantic differences the rules account for

* `ds.*` results are lib389 lint results (`key=DSxxLExxxx`); replication/RUV/topology findings
  have no `agreement` keyword and are matched by key/message.
* `ReplicationConflictCheck` no longer exists; conflicts are `ReplicationCheck` `DSREPLLE0002`.
* Since 0.15 keytab checks are split per service (`HTTPKeytab`, `DSKeytab`, …); only
  `IPAHostKeytab` is interpreted, the rest are surfaced as undiagnosed.
* Since 0.18 the file checks can report a wrong umask (which makes upstream skip mode checks)
  — surfaced, not treated as an ownership mismatch.
* `IPAUserProvidedExpirationCheck` (0.18) and external-certificate expiry ("not an IPA-issued
  certificate") are surfaced rather than given IPA-issued-certificate remediation.

## Reproducing the audit

```bash
python scripts/inventory_healthcheck.py inventory.json 0.12 0.16 0.19 master
PYTHONPATH=src python scripts/audit_healthcheck_coverage.py inventory.json audit.json 0.12 0.16 0.19 master
python scripts/gen_healthcheck_catalog.py inventory.json   # refresh the embedded catalog + test snapshot
```

`tests/adversarial/test_healthcheck_coverage.py` enforces the zero-silent invariant for every
check × failing level × documented key of the four snapshots, and asserts that made-up future
checks under every existing source (every result shape, including unknown severities) are
surfaced and never claimed by an existing rule.

## Not ipa-diagnose gaps: ipa-healthcheck detection gaps

ipa-healthcheck has no check for time drift vs NTP, inode exhaustion, memory/OOM, SELinux
denials, firewalld, half-finished upgrades, replication lag, ACME, or SSSD/HBAC/sudo state.
Those are gaps in the source, reported as such; ipa-diagnose does not invent findings for
them. See [limitations](limitations.md).
