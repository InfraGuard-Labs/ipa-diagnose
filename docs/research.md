# Research: what FreeIPA already does vs. what ipa-diagnose adds

This is the research that shaped `ipa-diagnose`'s scope, done before writing
any product code. It answers, explicitly: **what does `ipa-healthcheck`
already do, and where does `ipa-diagnose` genuinely add something new** -
not "first ever" or "nobody else does this" claims, just a direct
comparison against the primary sources.

## 1. What `ipa-healthcheck` is and does

`ipa-healthcheck` (`freeipa/freeipa-healthcheck` on GitHub, shipped in
Fedora/EPEL and RHEL 8.1.0+) compares the *expected* state of an IPA
installation against its *actual* state, on the local host only:
> "Healthcheck is designed only to be run on IPA servers. It only checks for
> issues on the server it is executed on." - [README](https://github.com/freeipa/freeipa-healthcheck/blob/master/README.md)

Run via `ipa-healthcheck --output-type json`, it emits a flat JSON array of
`{source, check, result, uuid, when, duration, kw}` objects, severities
`SUCCESS`/`WARNING`/`ERROR`/`CRITICAL`. `ipa_diagnose.evidence.healthcheck`
normalizes exactly this shape.

Its ~60+ checks span `ipahealthcheck.{ds,dogtag,ipa,meta,system}.*`:
replication (`ReplicationCheck`, `ReplicationConflictCheck`, `RUVCheck`,
`IPATopologyDomainCheck`), certificates (`IPACertmongerExpirationCheck`,
`IPACertTracking`, `DogtagCertsConnectivityCheck`, ...), Kerberos
(`IPAHostKeytab`, `KDCWorkersCheck` - notably thin), DNS
(`IPADNSSystemRecordsCheck` - the *only* DNS check), and Directory
Server/filesystem (`BackendsCheck`, `FileSystemSpaceCheck`, `IPAFileCheck`,
...). Sources: [freeipa.org/page/V4/Healthcheck](https://www.freeipa.org/page/V4/Healthcheck),
the `src/ipahealthcheck/*` source tree, and
[Red Hat's Healthcheck documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_idm_healthcheck_to_monitor_your_idm_environment/index).

## 2. What it does NOT do (confirmed, not assumed)

1. **No cross-check correlation.** Every check runs and reports
   independently. Nothing in the README, man page, or issue tracker
   describes linking two related failures.
2. **No cross-server analysis.** `RUVCheck`'s own docstring: *"Local
   analysis is not possible since it requires collecting the RUV from all
   masters and healthcheck is limited to only talking to itself."*
3. **No log/journal analysis anywhere in the codebase** - confirmed by
   reading every `src/ipahealthcheck/*` module. It inspects LDAP/NSS/
   filesystem/config state directly, never `journalctl`.
4. **No impact/blast-radius explanation** - `kw.msg` describes a state
   mismatch, not a consequence.
5. **No remediation command suggestions.**
6. **No real verify-after-fix loop** - `--source`/`--check` exist so an
   admin can re-run one check manually, per the
   [V4 design doc](https://www.freeipa.org/page/V4/Healthcheck), but there's
   no diffing or automation around it.
7. **Thin DNS (1 check) and Kerberos (2 checks) coverage.**

**A historical note on the name:** FreeIPA's own V4-era design process
proposed a tool literally named *"ipa-diagnose"* -
[freeipa.org/page/V4/Diagnostics_Tool](https://www.freeipa.org/page/V4/Diagnostics_Tool) -
with a Reporter/Doctor plugin architecture and SSH-based multi-host
gathering. It was never built; `ipa-healthcheck` (single-host, no SSH, no
correlation engine) shipped instead. This project's name overlaps with that
abandoned proposal but is architecturally unrelated (no SSH, no plugin
ecosystem, sits on top of `ipa-healthcheck` rather than replacing it) - worth
disclosing, not hiding.

**Existing third-party tools:** a search of GitHub, PyPI, and Red Hat's blog
found only [camptocamp/ipahealthcheck_exporter](https://github.com/camptocamp/ipahealthcheck_exporter),
a Prometheus exporter with no correlation or AI logic. No project combining
FreeIPA diagnostics with LLM-assisted explanation or cross-check correlation
was found.

## 3. Domain research behind the 5 diagnostic packs

Each pack's module docstring and rule-level comments in
`src/ipa_diagnose/engine/packs/*.py` cite the specific source and confidence
level ([HIGH] = primary vendor/project docs or source code, [MED] =
community-corroborated, [LOW] = single-source) behind that exact rule - that
level of detail belongs there, next to the code it justifies, not duplicated
here. The high-level findings that shaped pack *scope*:

- **Replication:** the replication+certificate cascade (a broken agreement
  stops `dogtag-ipa-*-renew-agent` from reading/writing CA renewal state in
  LDAP) is the canonical, well-documented example of one root cause
  producing several unrelated-looking `ipa-healthcheck` failures - see
  [freeipa.org/page/V4/CA_certificate_renewal](https://www.freeipa.org/page/V4/CA_certificate_renewal).
  Conflict entries (`nsds5ReplConflict`) are a documented reconciliation
  artifact, not proof of a broken link -
  [port389.org](https://www.port389.org/docs/389ds/design/managing-repl-conflict-entries.html).
- **Certificates:** `getcert list`'s state machine (`CA_REJECTED`,
  `CA_UNREACHABLE`, ...) is documented in the
  [`getcert-list` man page](https://www.mankier.com/1/getcert-list); the
  `CA_UNREACHABLE` state's several unrelated root causes (DNS/network, an
  expired CA cert, a missing trust anchor) sharing one state name is
  documented on [freeipa.org/page/Troubleshooting/PKI](https://www.freeipa.org/page/Troubleshooting/PKI).
- **Kerberos:** the 300-second clock-skew rejection window is MIT
  Kerberos's own documented default
  ([web.mit.edu/kerberos](https://web.mit.edu/kerberos/krb5-1.5/krb5-1.5.4/doc/krb5-admin/Clock-Skew.html)).
  "Preauthentication failed" being produced by clock skew, wrong
  keytab/password, *and* salt mismatches alike is corroborated across
  multiple Red Hat KCS articles (5576461, 3380341).
- **DNS:** `IPADNSSystemRecordsCheck`'s single-resolver blind spot is
  documented by freeipa.org itself; a known false-positive class
  (spurious WARNINGs for IPv6/`ipa-ca` records) is tracked as
  [freeipa-healthcheck issue #270](https://github.com/freeipa/freeipa-healthcheck/issues/270).
- **Directory Server:** the `/dev/shm` disk-exhaustion failure mode
  ([389-ds-base #5949](https://github.com/389ds/389-ds-base/issues/5949)),
  the NSS DB format mismatch that looks like a cert problem but isn't
  ([389-ds-base #2100](https://github.com/389ds/389-ds-base/issues/2100)),
  and the documented danger of running `db2index` with no target attribute
  ([389-ds-base #1914](https://github.com/389ds/389-ds-base/issues/1914)) are
  all real, cited GitHub issues against the actual 389-ds-base project.

## 4. AI provider research

OpenAI, Anthropic, and AWS Bedrock (`bedrock-runtime`'s `converse` API, the
current unified interface preferred over the legacy `invoke_model`) were
each researched for current SDK usage, auth, timeout handling, and error
taxonomy - see `src/ipa_diagnose/ai/{openai,anthropic,bedrock}_provider.py`
for the resulting adapters and inline citations. The decision to hand-roll
three thin adapters instead of taking a `litellm` dependency is explained in
[docs/ai-configuration.md](ai-configuration.md).

## 5. Packaging research

`ipa-healthcheck` itself ships as a native RPM (Fedora/EPEL, RHEL 8.1.0+),
not via PyPI - its README documents no pip install path for end users at
all. That precedent, plus the realistic constraints of a new project with no
existing user base, shaped the packaging decision in
[packaging/rpm/README.md](../packaging/rpm/README.md): PyPI/pipx now, a
real, Docker-validated RPM from day one, and COPR as the path to a public
`dnf install` once a maintainer registers a project there.
