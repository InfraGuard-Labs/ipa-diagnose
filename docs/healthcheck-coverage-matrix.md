# ipa-healthcheck check matrix (generated)

Generated from the upstream source of ipa-healthcheck 0.12 (EL8-era), 0.16 (EL9.4-9.7 / EL10.0-10.1 era), 0.19 (EL9.8 / EL10.2 / Fedora) and master, by `scripts/inventory_healthcheck.py` (AST only; upstream code is never executed) and `scripts/audit_healthcheck_coverage.py`.

Class per check (worst-case across levels/keys, synthetic findings through the real engine, healthcheck evidence only): **A** a rule can DIAGNOSE it, **B** a rule uses it as supporting evidence but stays UNKNOWN, **C** surfaced as UNDIAGNOSED (named in `undiagnosed_findings`), **F** the check only ever reports SUCCESS. There is no D (silent) or E (not ingested).

`ds.*` checks are thin wrappers over lib389 lint (`key=DSxxLExxxx`), so their levels and wording follow the installed 389-ds-base, not the ipa-healthcheck release; this AST inventory therefore lists no levels for them and the audit exercises all three failing levels.

| Check | First seen | 0.12 | 0.16 | 0.19 | master | Class |
|---|---|---|---|---|---|---|
| `dogtag.ca.DogtagCertsConfigCheck` | 0.2 | yes | yes | yes | yes | C |
| `dogtag.ca.DogtagCertsConnectivityCheck` | 0.2 | yes | yes | yes | yes | B |
| `ds.backends.BackendsCheck` | 0.6 | yes | yes | yes | yes | C |
| `ds.config.ConfigCheck` | 0.6 | yes | yes | yes | yes | C |
| `ds.disk_space.DiskSpaceCheck` | 0.6 | yes | yes | yes | yes | A/B |
| `ds.ds_plugins.RIPluginCheck` | 0.6 | yes | yes | yes | yes | C |
| `ds.dse.DSECheck` | 0.6 | yes | yes | yes | yes | C |
| `ds.encryption.EncryptionCheck` | 0.6 | yes | yes | yes | yes | C |
| `ds.fs_checks.FSCheck` | 0.6 | yes | yes | yes | yes | C |
| `ds.nss_ssl.NssCheck` | 0.6 | yes | yes | yes | yes | C |
| `ds.replication.ReplicationChangelogCheck` | 0.6 | yes | yes | yes | yes | C |
| `ds.replication.ReplicationCheck` | 0.6 | yes | yes | yes | yes | B/C |
| `ds.replication.ReplicationConflictCheck` | 0.2 | - | - | - | - | (only in releases outside the four audited) |
| `ds.ruv.KnownRUVCheck` | 0.6 | yes | yes | yes | yes | F |
| `ds.ruv.RUVCheck` | 0.4 | yes | yes | yes | yes | F |
| `ipa.certs.CertmongerFIPSTokensCheck` | 0.19 | - | - | yes | yes | C |
| `ipa.certs.CertmongerStuckCheck` | 0.13 | - | yes | yes | yes | C |
| `ipa.certs.IPACAChainExpirationCheck` | 0.4 | yes | yes | yes | yes | C |
| `ipa.certs.IPACertDNSSAN` | 0.7 | yes | yes | yes | yes | C |
| `ipa.certs.IPACertMatchCheck` | 0.9 | yes | yes | yes | yes | C |
| `ipa.certs.IPACertNSSTrust` | 0.2 | yes | yes | yes | yes | C |
| `ipa.certs.IPACertRevocation` | 0.2 | yes | yes | yes | yes | C |
| `ipa.certs.IPACertTracking` | 0.2 | yes | yes | yes | yes | C |
| `ipa.certs.IPACertfileExpirationCheck` | 0.2 | yes | yes | yes | yes | C |
| `ipa.certs.IPACertmongerCA` | 0.2 | yes | yes | yes | yes | C |
| `ipa.certs.IPACertmongerExpirationCheck` | 0.2 | yes | yes | yes | yes | C |
| `ipa.certs.IPADogtagCertsMatchCheck` | 0.9 | yes | yes | yes | yes | C |
| `ipa.certs.IPAKRAAgent` | 0.9 | yes | yes | yes | yes | C |
| `ipa.certs.IPANSSChainValidation` | 0.2 | yes | yes | yes | yes | C |
| `ipa.certs.IPAOpenSSLChainValidation` | 0.2 | yes | yes | yes | yes | C |
| `ipa.certs.IPARAAgent` | 0.2 | yes | yes | yes | yes | B |
| `ipa.certs.IPAUserProvidedExpirationCheck` | 0.18 | - | - | yes | yes | C |
| `ipa.config.IPAkrbLastSuccessfulAuth` | 0.18 | - | - | yes | yes | C |
| `ipa.config.SSSDAllowedUids389Check` | 0.19 | - | - | yes | yes | C |
| `ipa.dna.IPADNARangeCheck` | 0.3 | yes | yes | yes | yes | C |
| `ipa.files.IPAFileCheck` | 0.2 | yes | yes | yes | yes | A |
| `ipa.files.IPAFileNSSDBCheck` | 0.2 | yes | yes | yes | yes | A |
| `ipa.files.TomcatFileCheck` | 0.2 | yes | yes | yes | yes | A |
| `ipa.host.DNSKeytab` | 0.15 | - | yes | yes | yes | C |
| `ipa.host.DNS_keysyncKeytab` | 0.15 | - | yes | yes | yes | C |
| `ipa.host.DSKeytab` | 0.15 | - | yes | yes | yes | C |
| `ipa.host.HTTPKeytab` | 0.15 | - | yes | yes | yes | C |
| `ipa.host.IPAHostKeytab` | 0.2 | yes | yes | yes | yes | B |
| `ipa.host.ODS_EXPORTERKeytab` | 0.15 | - | yes | yes | yes | C |
| `ipa.idns.IPADNSSystemRecordsCheck` | 0.4 | yes | yes | yes | yes | C |
| `ipa.kdc.KDCWorkersCheck` | 0.11 | yes | yes | yes | yes | C |
| `ipa.meta.IPAMetaCheck` | 0.6 | yes | yes | yes | yes | C |
| `ipa.nss.IPAGroupMemberCheck` | 0.10 | yes | yes | yes | yes | C |
| `ipa.proxy.IPAProxySecretCheck` | 0.10 | yes | yes | yes | yes | C |
| `ipa.roles.IPACRLManagerCheck` | 0.3 | yes | yes | yes | yes | F |
| `ipa.roles.IPARenewalMasterCheck` | 0.3 | yes | yes | yes | yes | C |
| `ipa.roles.IPARenewalMasterHasKRACheck` | 0.13 | - | yes | yes | yes | C |
| `ipa.topology.IPATopologyDomainCheck` | 0.2 | yes | yes | yes | yes | C |
| `ipa.trust.IPADomainCheck` | 0.4 | yes | yes | yes | yes | C |
| `ipa.trust.IPATrustAgentCheck` | 0.2 | yes | yes | yes | yes | C |
| `ipa.trust.IPATrustAgentMemberCheck` | 0.2 | yes | yes | yes | yes | C |
| `ipa.trust.IPATrustCatalogCheck` | 0.2 | yes | yes | yes | yes | C |
| `ipa.trust.IPATrustControllerAdminSIDCheck` | 0.7 | yes | yes | yes | yes | C |
| `ipa.trust.IPATrustControllerConfCheck` | 0.2 | yes | yes | yes | yes | C |
| `ipa.trust.IPATrustControllerGroupSIDCheck` | 0.2 | yes | yes | yes | yes | C |
| `ipa.trust.IPATrustControllerPrincipalCheck` | 0.2 | yes | yes | yes | yes | C |
| `ipa.trust.IPATrustControllerServiceCheck` | 0.2 | yes | yes | yes | yes | C |
| `ipa.trust.IPATrustDomainsCheck` | 0.2 | yes | yes | yes | yes | C |
| `ipa.trust.IPATrustPackageCheck` | 0.3 | yes | yes | yes | yes | C |
| `ipa.trust.IPAauthzdatapacCheck` | 0.18 | - | - | yes | yes | C |
| `ipa.trust.IPAsidgenpluginCheck` | 0.2 | yes | yes | yes | yes | C |
| `meta.core.MetaCheck` | 0.2 | yes | yes | yes | yes | C |
| `meta.services.certmonger` | 0.2 | yes | yes | yes | yes | C |
| `meta.services.chronyd` | 0.13 | - | yes | yes | yes | C |
| `meta.services.dirsrv` | 0.2 | yes | yes | yes | yes | C |
| `meta.services.gssproxy` | 0.2 | yes | yes | yes | yes | C |
| `meta.services.httpd` | 0.2 | yes | yes | yes | yes | C |
| `meta.services.ipa_custodia` | 0.3 | yes | yes | yes | yes | C |
| `meta.services.ipa_dnskeysyncd` | 0.3 | yes | yes | yes | yes | C |
| `meta.services.ipa_ods_exporter` | 0.13 | - | yes | - | - | C |
| `meta.services.ipa_otpd` | 0.3 | yes | yes | yes | yes | C |
| `meta.services.kadmin` | 0.3 | yes | yes | yes | yes | C |
| `meta.services.krb5kdc` | 0.2 | yes | yes | yes | yes | C |
| `meta.services.named` | 0.2 | yes | yes | yes | yes | A/C |
| `meta.services.ods_enforcerd` | 0.13 | - | yes | yes | yes | C |
| `meta.services.pki_tomcatd` | 0.2 | yes | yes | yes | yes | C |
| `meta.services.smb` | 0.13 | - | yes | yes | yes | C |
| `meta.services.sssd` | 0.3 | yes | yes | yes | yes | C |
| `meta.services.winbind` | 0.13 | - | yes | yes | yes | C |
| `system.filesystemspace.FileSystemSpaceCheck` | 0.2 | yes | yes | yes | yes | C |
