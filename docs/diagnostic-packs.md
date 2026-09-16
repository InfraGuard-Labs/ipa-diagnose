# Diagnostic packs

A pack is a small, versioned group of rules for one problem family (see
[docs/architecture.md](architecture.md) for the plugin contract). v1 ships
five, chosen by the gap analysis in [docs/research.md](research.md) - not
"cover everything," but the families where `ipa-healthcheck`'s single-host,
no-correlation design leaves the most real value on the table.

Every rule below lives in `src/ipa_diagnose/engine/packs/<pack>.py`, with the
full sourcing and confidence rationale in the module's docstrings and each
rule's `Confidence.rationale` string - this page is the index, not a
duplicate of that detail.

## replication (`src/ipa_diagnose/engine/packs/replication.py`)

Reads `ipahealthcheck.ds.replication`, `ipahealthcheck.ipa.topology`; adds
the `replication_agreements` (`ipa-replica-manage list`/`list-ruv`) and
`ldap_query` (conflict search + keytab/GSSAPI bind check) collectors.

| Rule | Fires on | Refuses to guess when |
|---|---|---|
| `peer-connectivity-break` | `ReplicationCheck` ERROR/CRITICAL + a failed bind/agreement check | Neither collector produced corroborating evidence, or conflicts coexist with the connectivity signal (ambiguous between a real break and a conflict artifact) |
| `replication-conflicts` | `nsds5ReplConflict` entries directly enumerated | Only the healthcheck flag fired without direct enumeration |
| `stale-ruv` | An explicit `ds.ruv` ERROR naming a dead RID | Any weaker signal - `RUVCheck` itself documents it can't fully analyze this from one host |
| `topology-disconnected` | `IPATopologyDomainCheck` reports "is not connected" | (direct topology-graph fact - always confident when it fires) |

**Trap this pack explicitly does not fall into:** `nsds5ReplConflict` entries
mean replication *is* transmitting writes between suppliers - their mere
presence is not evidence the link is broken.

## certificates (`src/ipa_diagnose/engine/packs/certificates.py`)

Reads `ipahealthcheck.ipa.certs`, `ipahealthcheck.dogtag.ca`; adds the
`certmonger` (`getcert list`) and `journal_pki` (`journalctl -u pki-tomcatd
-u certmonger`) collectors.

| Rule | Fires on | Refuses to guess when |
|---|---|---|
| `certmonger-tracking-stuck` | A tracking request in `CA_REJECTED`/`CA_UNREACHABLE`/`CA_UNCONFIGURED`/`NEED_GUIDANCE` | The `ca-error` text is generic/empty - `CA_UNREACHABLE` alone has 3+ unrelated real causes |
| `cert-expired` | Expiration check ERROR/CRITICAL (actual expiry) vs. WARNING (heads-up only) | (direct notAfter-date reading - always confident) |
| `ra-agent-desync` | Dogtag/RA-agent connectivity or auth (4301-class) failures | Only a single thin signal - full confirmation needs an LDAP read this pack doesn't perform |
| `renewal-master-unreachable` | A cert aging toward expiry with a *clean* certmonger state (no error at all) | Always - this is a topology-wide fact (which host is the renewal master) unconfirmable from one host |

`certmonger-tracking-stuck` and `renewal-master-unreachable` cite
`upstream_candidates=["replication"]` - a broken replication topology is the
documented reason `dogtag-ipa-*-renew-agent` can't read/write CA renewal
state in LDAP. `ra-agent-desync` cites `["directory-server"]`.

## kerberos (`src/ipa_diagnose/engine/packs/kerberos.py`)

Reads `ipahealthcheck.ipa.host`, `ipahealthcheck.ipa.kdc`,
`ipahealthcheck.meta.services`; adds the `kerberos_client`
(`klist`/`kvno`/`chronyc`) and `journal_krb5kdc` collectors. `ipa-healthcheck`'s
own coverage here is thin by design (see research.md) - this pack exists
specifically to fill that gap.

| Rule | Fires on | Refuses to guess when |
|---|---|---|
| `clock-skew` | An explicit KDC journal clock-skew rejection (HIGH), or this host's own NTP desync correlated with a keytab failure (MEDIUM) | No direct clock evidence at all |
| `keytab-kvno-mismatch` | A direct `kvno` vs. `klist -kte` numeric mismatch | Only a generic "Preauthentication failed" string - that message alone is produced by clock skew, wrong keytab/password, *and* salt mismatches alike |
| `kdc-discovery-failure` | DNS-shaped kinit errors ("cannot resolve"/"cannot contact any KDC") | Clock/keytab explanations haven't been ruled out first |

`kdc-discovery-failure` always cites `upstream_candidates=["dns"]` - the
single clearest cross-pack causal link in the product (see
`04_correlated_findings.png`). `ktutil` is never offered as a remediation
action anywhere in this pack - it's documented as a common *cause* of salt
mismatches, not a fix; `ipa-getkeytab` is the CAUTION-rated correct tool.

## dns (`src/ipa_diagnose/engine/packs/dns.py`)

Reads `ipahealthcheck.ipa.idns` (the only DNS check ipa-healthcheck has);
adds the `dns_lookup` (`dig`) and `journal_named` collectors.

| Rule | Fires on | Refuses to guess when |
|---|---|---|
| `named-service-down` | `named`/bind-dyndb-ldap crashed or won't start | A generic crash signature that doesn't match the documented LDAP-ACI-permission-denied pattern specifically |
| `forward-zone-conflict` | The specific bind-dyndb-ldap zone-unload/collision log line | Only generic "forwarding is broken" symptoms - identical on the outside to forwarders simply being down, a completely different fix |
| `srv-autodiscovery` | `IPADNSSystemRecordsCheck` ERROR corroborated by a live `dig` | The finding is WARNING-only and uncorroborated - `freeipa-healthcheck` issue #270 documents spurious WARNINGs here |

`named-service-down` cites `upstream_candidates=["directory-server"]` only
when the journal shows the specific LDAP-ACI signature (a directory-server
regression), not on a generic crash. Every firing of `srv-autodiscovery`
states the documented single-resolver blind spot in `limitations`.

## directory-server (`src/ipa_diagnose/engine/packs/directory_server.py`)

Reads `ipahealthcheck.ds.backends`, `.config`, `.dse`, `.encryption`,
`.nss`, `.disk_space`, `ipahealthcheck.system.filesystemspace`,
`ipahealthcheck.ipa.files`; adds `filesystem` (`df`) and `journal_dirsrv`
collectors. Foundational under the rest of the causality chain, so every
rule here has empty `upstream_candidates`.

| Rule | Fires on | Refuses to guess when |
|---|---|---|
| `disk-space-exhaustion` | ERROR/CRITICAL usage and/or an actual "No space left on device" journal error | Only a WARNING-level single snapshot - uses `TRANSIENT_SUSPECTED` instead (could be an in-progress backup) |
| `ownership-selinux-mismatch` | `IPAFileCheck`/`IPAFileNSSDBCheck` naming an exact wrong owner/mode | Only a bare "Permission denied" with no file-check corroboration - can't tell Unix permissions from an SELinux AVC denial from that alone |
| `nss-tls-db-format` | The documented NSS DB format (cert8/9, key3/4) mismatch signature | A certificate-expiry finding is present concurrently - that's the certificates pack's domain, and this rule says so explicitly rather than misattributing |
| `missing-system-index` | `BackendsCheck`'s `DSBLE0007` missing-index error | (direct finding - always confident when it fires) |

**High-risk command this pack explicitly guards against:** `db2index`/
`db2index.pl` run with **no** target attribute is documented
([389-ds-base #1914](https://github.com/389ds/389-ds-base/issues/1914)) to
break replication via RUV/tombstone side effects. `missing-system-index`
only ever recommends the scoped, targeted form (CAUTION); the bare form only
ever appears as an explicit "do not run this" HIGH_RISK warning.

## Confidence, at a glance

Every rule's `Confidence.rationale` states its sourcing tier inline
([HIGH]/[MED]/[LOW] - see research.md's definitions), and the engine's own
`Diagnosis.__post_init__` guardrail makes it structurally impossible for a
rule to reach `DIAGNOSED` status without HIGH or MEDIUM confidence - LOW or
INSUFFICIENT confidence must produce an `UNKNOWN_*` status with a concrete
`next_diagnostic_step` instead. This is not a convention rules are trusted
to follow; it's enforced every time a `Diagnosis` is constructed.
