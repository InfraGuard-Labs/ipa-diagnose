# Article-claim evidence register (Slice 1)

This is **not** an article draft. It lists every claim about ipa-diagnose that could be published, with its
evidence tier and exact safe wording, so no claim is ever stronger than its evidence. Evidence rows are in
[truth-matrix.md](truth-matrix.md). Product commit for all LIVE rows: `46c844d` (runs 36258032392 and 36258035064). One maintainer; "independent review" means fresh AI reviewer agents that did not write the code.

**Evidence tiers:** LIVE (disposable real FreeIPA server in the free GitHub-hosted lab, current code) ·
FIXTURE (recorded or constructed evidence replayed through current code) · HISTORICAL (live evidence from an
earlier commit) · SOURCE_VERIFIED (upstream FreeIPA / ipa-healthcheck source read) · SYNTHETIC (unit test with
fake inputs) · RESEARCH_ONLY (documentation, not exercised).

**Environment of every LIVE claim:** FreeIPA 4.13.3 on Fedora 43, `freeipa/freeipa-server:fedora-43` container,
single server with integrated DNS and CA (two-node topology for the replication rows). Nothing else was
live-tested: the AlmaLinux 9 (FreeIPA 4.13.1) and AlmaLinux 8 (FreeIPA 4.9.13) container images did not complete
`ipa-server-install` on the free runner ("No valid Negotiate header" during on-master client enrolment), so
there is **no** live evidence for EL8/EL9/RHEL.

| ID | Claim | Tier | Evidence | Limits | Safe wording | Overclaim to avoid |
|---|---|---|---|---|---|---|
| C01 | Detects a stopped Directory Server and names the exact unit | LIVE | S3 | one instance, container | "In a live lab (FreeIPA 4.13.3/Fedora 43), with dirsrv stopped, ipa-diagnose named the stopped `dirsrv@LAB-TEST` unit as the primary problem." | "detects any Directory Server outage" |
| C02 | Prints a start command for exactly that unit, never `ipactl start` | LIVE + SOURCE_VERIFIED | S3, S5; upstream ipactl stops all services if one fails | print-only | "It printed `systemctl start dirsrv@LAB-TEST.service` (not `ipactl start`, which stops all IPA services when one fails to start)." | "fixes Directory Server outages" |
| C03 | The printed fix, run verbatim, was verified with fresh evidence | LIVE | S3/S5 apply + verify | two services, one version | "Running the printed command verbatim and then `ipa-diagnose verify` reported RESOLVED, with the fix's own check (the unit is active) re-run on fresh evidence." | "verified recovery on any FreeIPA" |
| C04 | Stopped KDC diagnosed, scoped fix, verified | LIVE | S5 | as C03 | same wording, krb5kdc | - |
| C05 | A masked service gets no "start it" advice | LIVE | S6 | certmonger only tested | "When certmonger was masked, ipa-diagnose withheld any start command and said why." | "never gives unsafe service advice" |
| C06 | File mode fix removes permissions only and is verified | LIVE | P1 (real CS.cfg 0664 quirk) | container `/data` layout | "On a fresh container install, ipa-healthcheck's CS.cfg 0664-vs-0660 finding got a permission-removing `chmod o-r`, preceded by read-only CONFIRM FIRST commands; verify reported it RESOLVED (overall exit 4 in the lab because of the container MetaCheck warning)." | "fixes file permission problems" |
| C07 | Group mismatch on a non-key file: fix applied and verified | LIVE | F1 (`/etc/ipa/ca.crt` chgrp) | one file | "A deliberately wrong group on /etc/ipa/ca.crt got `chgrp -h root`; verify reported it RESOLVED afterwards." | - |
| C08 | No fix for non-IPA accounts, hard-linked files, key material | LIVE (+ FIXTURE for the rest) | F2, F3, F4 | only these three live | "Changing a file's group to `nobody`, adding a second hard link, or changing the group of the RA agent key all produced no fix (the reasons printed name the non-IPA account, the hard link and the key material)." | "can never suggest an unsafe file change" |
| C09 | Symlink / swapped-parent / cross-component attacks are refused | FIXTURE + SYNTHETIC | tests/resolution round 3-7 | not live | "In tests, symlinked and swapped directory paths leading to another component's files were refused." | any live claim |
| C10 | verify is not fooled by a problem left in place | LIVE | V1 | one case | "With the KDC left stopped, verify reported STILL_PRESENT." | - |
| C11 | verify is not fooled by a damaged saved report | LIVE (one case) + FIXTURE | V2 + tests | root forgery out of scope | "When the saved fix record was altered, verify reported CHANGED instead of RESOLVED." | "tamper-proof" |
| C12 | Healthy server stays boring | LIVE | S0b, S10 | container MetaCheck FIPS warning makes it NOT_FULLY_VERIFIED, no diagnosis | "On a healthy lab server ipa-diagnose made no diagnosis; the only item was an ipa-healthcheck metadata warning caused by the container (listed, not explained away)." | "reports HEALTHY on healthy servers" |
| C13 | Missing ipa-healthcheck / ldapsearch / root never looks healthy | LIVE | S1, S2 | - | "Without ipa-healthcheck, ldapsearch or root, the report was never HEALTHY and no fix was offered." | - |
| C14 | named stopped | LIVE | S4 (named.service listed inactive) | ipa-healthcheck itself times out | "With this server's DNS stopped, ipa-healthcheck did not finish; ipa-diagnose reported UNKNOWN - not healthy - and listed the stopped unit (from its own read-only check)." | "diagnoses DNS outages" |
| C15 | Two simultaneous service failures | LIVE (partial) | S7 (named + krb5kdc: UNKNOWN, ipa-healthcheck timed out), S7b (krb5kdc diagnosed and fix offered; certmonger restarted by ipa-healthcheck and disclosed) | certmonger cannot be observed stopped | "With the KDC and certmonger stopped together, the KDC got its scoped fix and the report disclosed that ipa-healthcheck had restarted certmonger." | "diagnoses multiple simultaneous failures" |
| C16 | Healthy two-node topology, RUV verified | LIVE | H2 | one topology | "On a healthy two-server lab topology, the replica update vectors were read successfully and nothing was diagnosed." | - |
| C17 | Dead replica detection | LIVE (**negative**) | R1 | - | **Do not claim.** With the replica removed but still registered, neither ipa-healthcheck nor ipa-diagnose reported it at capture time. | "detects a failed replica" |
| C18 | Stale RUV detection live | not established | R2 | engineered state only | **Do not claim** a live stale-RUV detection. Fixture evidence only. | "detects stale RUVs" |
| C19 | Clock-skew fix | FIXTURE | tests | cannot be reproduced safely in containers (shared wall clock) | "Offered only when this host's clock is measured ≥240 s off and synchronized to a named source; tested on recorded evidence." | any live claim |
| C20 | Expiring DS certificate renewal | FIXTURE + LIVE capture of the tracking profile | tests; S6 getcert capture | no live near-expiry certificate | "Tested on recorded evidence; offered only with the standard IPA service profile, observed live as caIPAserviceCert." | any live renewal claim |
| C21 | Expired DS certificate gets no invented fix | FIXTURE + SOURCE/RESEARCH | tests; RHEL docs link | - | "For an already expired DS certificate it points to the documented recovery procedure instead of a command." | - |
| C22 | Print-only | SOURCE (code) + LIVE (lab ran commands itself; S7b disclosure) | all apply rows, S7b | ipa-healthcheck side effect | "ipa-diagnose never runs a fix; note that ipa-healthcheck, which it runs, starts a stopped certmonger (upstream behaviour), and ipa-diagnose reports when that happens." | "completely read-only" |
| C23 | AI cannot bring back a withheld command | SYNTHETIC + code | tests | filter not proof | "AI rewording is not requested for withheld fixes, and AI text containing any command is discarded." | "AI is safe" |
| C24 | Works across RHEL 8-10 | none | - | EL images did not install in the lab | **Do not claim.** Procedures are gated to FreeIPA 4.9-4.x and say "not verified on this version/OS" elsewhere. | "supports RHEL 8/9/10" |
| C25 | Independent review | process | review rounds 1-10 / red teams 1-8, fresh-user check | fresh AI agents, one maintainer | "Reviewed adversarially in several rounds by fresh reviewer agents that did not write the code (a one-maintainer project)." | "independently audited" |
| C26 | Secret redaction | SYNTHETIC | tests | pattern-based | "Common secret shapes are redacted from the log line it shows." | "never leaks secrets" |


When quoting commands: generalise the lab names (`LAB-TEST`, `/data/...`); present a rollback such as `chmod o+r` as "restores the state ipa-healthcheck flagged - normally not needed".
