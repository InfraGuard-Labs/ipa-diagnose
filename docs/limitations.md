# Limitations

Stated plainly, per this project's own standard: report what was actually
validated, at what tier, and don't claim more.

## Validation tiers actually performed

| Tier | What it means | Status |
|---|---|---|
| **Unit tested** | Core engine, correlation, redaction, healthcheck parsing | Done - `tests/unit/` |
| **Fixture validated** | Full evidence-collection → diagnosis pipeline, one scenario per fixture directory, with an expected outcome in `meta.json` | Done - `tests/packs/` (one file per pack) + `tests/adversarial/` (cross-pack, hostile-input, redaction scenarios) |
| **Container integration tested** | The *packaging* (RPM build, install, dependency resolution, upgrade, uninstall) end to end in a clean container | Done - see [packaging/rpm/README.md](../packaging/rpm/README.md), 11/11 checks passing |
| **Real FreeIPA behavior validated** | The pipeline runs against an actual live FreeIPA server's real `ipa-healthcheck` output, not fixtures | **Partially performed.** A real `freeipa/freeipa-server` container was provisioned, installed, and used to capture genuine `ipa-healthcheck --output-type json` output for both a healthy server and a real induced failure (`systemctl stop dirsrv`) - see [tests/fixtures/real-freeipa-capture/README.md](../tests/fixtures/real-freeipa-capture/README.md) for exactly what was captured and how. Both captures were run through the real pipeline successfully (`tests/unit/test_real_freeipa_capture.py`). |

**What this one validation pass covered, honestly, and what it didn't:**

- ✅ Confirmed the evidence normalizer parses real `ipa-healthcheck` output
  (not just hand-authored fixtures) without crashing, on both a healthy
  server and a genuinely failing one.
- ✅ Found and fixed a real gap this way: CRITICAL results where a check
  plugin itself raises an uncaught exception have **no `msg` key at all**
  (only `exception`/`traceback`) - `evidence/healthcheck.py` was silently
  turning these into an empty message before this was caught. Fixed, with
  a regression test using the exact real shape.
- ✅ Confirmed `directory-server.ownership-selinux-mismatch` fires correctly
  against a real `TomcatFileCheck` finding.
- ⚠️ **Found, and is NOT hiding, a real coverage gap**: the induced
  `dirsrv`-down failure (a real ERROR + a real CRITICAL from a different
  check plugin crashing when LDAP went down) did not trigger any
  *additional* diagnosis - none of the directory-server pack's 4 rules key
  off a generic "the dirsrv service itself is down"
  (`ipahealthcheck.meta.services`) finding; they're all more specific
  (disk space, ownership/SELinux, NSS/TLS format, missing index). A rule
  for this is a reasonable v1.1 candidate, not a defect being papered over.
- This was **one topology** (a single freshly-installed server, no
  `--setup-dns`, one induced failure) exercising **one pack** (directory-server,
  via the file-permission finding both captures share) - it is real,
  genuine signal that the pipeline works end-to-end against real output, not
  a claim that all 5 packs/17 rules have each been exercised against a real
  failure of the specific type they're designed to catch. The other 4
  packs' fixtures remain fixture-validated only, per the table above.

Every fixture's `meta.json` documents its scenario and expected outcome
in plain language specifically so closing more of this gap (more real
topologies, more induced failure types) is straightforward for a future
contributor without redesigning anything.

## Scope limitations (deliberate, not oversights)

- **Single-host by design**, same constraint `ipa-healthcheck` itself has.
  Full RUV convergence across every replica, or confirming every DNS server
  in a topology serves correct records, genuinely needs a multi-host view.
  Where a rule's confidence is capped for this reason, `--details` says so
  in that rule's `limitations` field (e.g. `stale-ruv`, `srv-autodiscovery`).
- **Five diagnostic packs, not full FreeIPA subsystem coverage.** AD-trust
  relationships, DNSSEC key-master issues, HSM/token-backed CA setups, and
  IPA-to-IPA cross-realm trust are all out of scope for v1 - not because
  they're unimportant, but because the packs chosen are where the research
  showed the clearest, best-documented, highest-value gap in
  `ipa-healthcheck`'s own coverage.
- **Diagnosis-first, not auto-remediation**, by design (see the master
  design brief this project was built against): `ipa-diagnose` never
  executes a CAUTION or HIGH_RISK action automatically, and has no "fix it
  for me" mode in v1.
- **The correlation model is a fixed 4-pack causality chain** (DNS →
  Kerberos → Replication → Certificates, Directory Server foundational under
  all) plus per-rule `upstream_candidates` - it's deterministic and testable
  ([docs/architecture.md](architecture.md#correlation-and-prioritization-enginecorrelatepy)),
  but it is not a general-purpose causal inference engine; a genuinely novel
  causal relationship not encoded in a rule's `upstream_candidates` will
  correctly surface as two independent problems rather than being
  discovered automatically.
- **RPM packaging validated locally in Docker, not yet published.** The spec
  builds, installs, upgrades, and uninstalls correctly in a clean container;
  making `sudo dnf install ipa-diagnose` work on a machine that hasn't built
  the RPM itself needs a COPR project registered under a maintainer's
  Fedora account - see [packaging/rpm/README.md](../packaging/rpm/README.md)
  for the exact remaining step.
- **AI explanation quality is bounded by what it's given, by design.** It
  can only rephrase the deterministic `why`/evidence/impact/actions already
  computed - it cannot add insight the engine didn't already have, and
  isn't meant to.

## What was not fabricated

No adoption numbers, user counts, stars, downloads, testimonials, or
benchmark comparisons appear anywhere in this project's documentation -
none exist yet, and none are claimed.
