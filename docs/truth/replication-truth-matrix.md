# Replication diagnosis truth matrix (Slice 5)

Evidence for `ipa-diagnose replication` (and `bundle --replication`). Claims about replication mode must come from
here, via [claim-register.md](claim-register.md) (section "Slice 5").

- **Workflow:** `.github/workflows/live-freeipa-replication.yml` running `scripts/lab_replication.py`. The artifact
  `live-replication-evidence-fedora-43` holds every JSON and `--details` answer, the lab command log and the rows
  (`out/truth/replication-results.jsonl`). Compact rows and cause chains are also published as check-run
  annotations.
- **Environment:** free GitHub-hosted runner; a private Docker network with three disposable
  `freeipa/freeipa-server:fedora-43` containers in a **line topology**: ipa01 (first server, CA, integrated DNS) --
  ipa02 (replica of ipa01 **with** CA) -- ipa03 (replica of ipa02 **without** CA). Domain suffix segments ipa01-ipa02
  and ipa02-ipa03; CA suffix (`o=ipaca`) segment ipa01-ipa02 only; ipa02 is the articulation point. Fake `LAB.TEST`
  identities only. Versions: see "Run history". **No other FreeIPA version, OS or topology shape was validated live.**
- **Method:** `lab_replication.py setup` proves the topology (segments per suffix, CA servers) and live replication
  (a change on ipa01 reaches ipa02 and ipa03) - row R00. Each scenario then injects ONE fault, **confirms it
  independently** (systemctl, getent, a TCP connect, and the agreement's own status read with `ldapsearch` over LDAPI
  - never through ipa-diagnose) and runs `ipa-diagnose replication --json` **blind** on the relevant server(s). A row
  records expected vs observed, every PRIMARY/INDEPENDENT root not in the expected set (**false root cause**), every
  expected root not found (**missed cause**), and any offered fix that is not `systemctl` on this server or contains
  a forbidden command (**unsafe resolution**). When a fix is offered, the lab runs exactly the printed argv, then
  `--verify` (repeated while it answers PENDING). After each scenario every agreement must report a fresh successful
  session again before the next one. A scenario without a row fails the job.

## Run history

| Run | Code commit | Result | What it showed |
|---|---|---|---|
| [36652068103](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36652068103) | b017648 | R00 FAIL (harness) | topology exactly as designed and a change replicated to all three servers, but the harness's "all green" gate waited for CA-suffix sessions it never triggered (a certificate-profile description change touches only the domain suffix). **Environment facts:** FreeIPA 4.13.4, 389-ds-base 3.1.5, krb5 1.22.2; every agreement LDAP/389 + SASL/GSSAPI; `krb5.conf` names no KDC (`dns_lookup_kdc = true`); `ds.keytab` dirsrv:dirsrv 0600 |
| [36654176983](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36654176983) | 274b6b6 | 7/20 | HEALTHY on all three servers; local KDC stopped -> printed `systemctl start krb5kdc.service` run verbatim -> `--verify` RESOLVED (first replication-context LIVE record). **Live findings:** (1) after the consumer's Directory Server stopped, or the consumer was disconnected, and a change was made, the supplier's agreement status STILL read "Incremental update succeeded" for the whole 4-minute wait - a diagnosis that starts only from a failing status misses it (it reported nothing); (2) with ipa03's Directory Server unable to read its keytab, ipa02's agreement towards ipa03 failed with LDAP 49 (ipa03 cannot accept Kerberos) and was reported as a second, independent root - a **false root cause**. Both fixed in e36e5e0 with regression tests |
| [36657552130](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36657552130) | e36e5e0 | 13/20, 0 false root causes, 0 missed causes, 0 unsafe fixes | both live findings confirmed fixed; local dirsrv stopped -> printed `systemctl start dirsrv@LAB-TEST.service` run verbatim -> `--verify` RESOLVED (second LIVE record); **389-DS's real status for a failed GSSAPI bind is `Error (-2) Problem connecting to replica - LDAP error: Local error (connection error)`** (no Kerberos detail: the cause comes from ipa-diagnose's own reproduction, as the correctness review predicted). Harness: an expectation of R02d was wrong (the peer-side root is the item that resolves); R07 aborted because `kinit` on a server whose own KDC is stopped fails (an IPA server's Kerberos library uses its own KDC) - lab changes now go through LDAPI |
| [36660487204](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36660487204) | 175cb7f | 16/20, 0 false root causes, 0 missed, 0 unsafe | peer KDC stopped (reverse direction read from the peer and handed off; this server's own direction stays OK - no "peer KDC required" assumption) and two independent causes on the middle server pass. **Live findings:** a NATURAL backoff (`Error (18) Can't acquire replica (Incremental update transient warning. Backing off, will retry update later.)`) was reported NOT_FULLY_VERIFIED, never green; after a restarted Directory Server came back, the PEER still recorded that it could not reach it - now TRANSIENT, not a new failure (e58c12f); `Error (-1) Unable to receive the response for a startReplication extended operation to consumer. Will retry later.` is classified TRANSPORT. Harness: a non-root user could not execute the tool under /root; libfaketime path |
| [36663200048](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36663200048) | e58c12f | **20/20 PASS**, 0 false root causes, 0 missed causes, 0 unsafe fixes | every scenario below |
| [36695043258](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36695043258) | 637eb8d | **20/20 PASS**, 0 / 0 / 0 | after the re-review fix: the reverse link to this server's keytab only for acceptor-side forms |
| [36696040195](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36696040195) | **54b5943 (final product code)** | **20/20 PASS**, 0 false root causes, 0 missed causes, 0 unsafe fixes | after the final re-review fixes (peer finding text, root ranking); the scenario table below holds on this run |

## Live scenarios (20/20 PASS on runs 36663200048 / e58c12f, 36695043258 / 637eb8d and 36696040195 / 54b5943, the final product code)

FreeIPA 4.13.4-2.fc43, 389-ds-base 3.1.5-4.fc43, krb5 1.22.2-4.fc43, Fedora 43 containers; every agreement LDAP/389
with SASL/GSSAPI. "Blind" = ipa-diagnose was not told the fault. A fix was run only as the exact printed argv.

| # | Fault (injected, independently confirmed) | Run on | Expected = observed | Fix | Verify |
|---|---|---|---|---|---|
| R00 | none: 2 domain + 1 CA segment, CA on ipa01+ipa02, a change reached all three | lab | - | - | - |
| R01 x3 | none (operator ticket) | ipa01, ipa02, ipa03 | HEALTHY (exit 0), both directions of every agreement read (the reverse one from the peer) | none | - |
| R01b | none, no Kerberos ticket | ipa01 | NOT_FULLY_VERIFIED (exit 4): reverse direction NOT OBSERVED, handoff to ipa02; outbound OK | none | - |
| R02 | dirsrv stopped on ipa02 (systemctl inactive; TCP 389 refused from ipa01) | ipa01 | PEER_DS_NOT_ACCEPTING@ipa02 (peer), handoff to ipa02, no local cause | none (peer side) | R02d: RESOLVED after the fix on ipa02 |
| R02b | same | ipa02 | LOCAL_DS_NOT_RUNNING@ipa02 | `systemctl start dirsrv@LAB-TEST.service`, No-Google | R02c: RESOLVED |
| R03 | ipa02 disconnected from the network | ipa01 | PEER_UNREACHABLE ipa01>ipa02 "unreachable from ipa01 at <time>", never "dead"; the agreement status still said "succeeded" | none | - |
| R04 | ipa01's resolver broken for ipa02 (getent rc=2) | ipa01 | PEER_NAME_UNRESOLVED observed from ipa01; the agreement status still said "succeeded" | none | - |
| R05 | krb5kdc stopped on ipa01 | ipa01 | LOCAL_KDC_NOT_RUNNING@ipa01 (agreements stayed OK on cached tickets) | `systemctl start krb5kdc.service`, No-Google | R05b: RESOLVED (exit 0) |
| R06 | ipa03's ds.keytab chowned root:root, dirsrv restarted (disposable replica, restored after) | ipa03 | DS_KEYTAB_PROBLEM@ipa03 ONLY; ipa02's LDAP 49 towards ipa03 RELATED to it; status `Local error (connection error)` | none (keytab changes are never printed) | - |
| R07 | krb5kdc stopped on ipa02 and its dirsrv restarted | ipa01 | REVERSE_REPLICATION_FAILING ipa02>ipa01 read from ipa02, handoff to ipa02; ipa01>ipa02 stays OK; no local cause | none | - |
| R08 | krb5kdc stopped on ipa02 AND dirsrv stopped on ipa03 | ipa02 | PRIMARY LOCAL_KDC_NOT_RUNNING@ipa02 + INDEPENDENT PEER_DS_NOT_ACCEPTING@ipa03, handoff to ipa03 | `systemctl start krb5kdc.service` (local only) | - |
| R09 | none, `--peer ipa03` on ipa02 | ipa02 | only the ipa02<->ipa03 relationships (a natural backoff is NOT_FULLY_VERIFIED) | none | - |
| R10 | none, non-root user | ipa01 | NOT_FULLY_VERIFIED (exit 4), nothing claimed | none | - |
| R11 | `bundle --replication` | ipa01 | replication.json present, the bundle validates, no lab host, domain, realm or IP inside | - | - |
| R12 | SIMULATED: only ipa-diagnose's own process 15 min ahead (libfaketime); servers untouched | ipa01 | PAIR_CLOCK_SKEW ipa01>ipa02, never "chronyd stopped"; no clock step printed | none | - |

Counts over the 20 rows: **0 false root causes, 0 missed expected causes, 0 unsafe resolutions** (a fix offered for
another server, or containing a forbidden operation). Not attempted live, on purpose: a CA-suffix-only failure (every
safe way needs LDAP or topology damage), stale RUV, changelog purge, generation-ID mismatch (see the fixture table).

Performance (live, runs 36663200048 and 36696040195): a healthy server 2.4-3.4 s; a stopped peer 3.4 s; an
unreachable peer 11.8-14.7 s (TCP and LDAP timeouts, bounded per peer); a broken resolver 3.2 s; `--peer` 1.9 s;
non-root 0.2-0.3 s. Slow or unreachable peers dominate the run time; the timeouts were not raised.


## Fixture and synthetic evidence (not live)

These are replayed through the current code (`tests/replication/`, `tests/fixtures/replication-mode/`; SYNTHETIC
data built by `tests/replication/scenarios.py` with 389-DS status strings in their documented formats). They are
**not** live claims.

| Case | Evidence | Expected and observed | Why not live |
|---|---|---|---|
| Kerberos clock skew between two servers | `clock-skew` fixture; `test_clock_skew_*`, `test_peer_clock_falls_back_*` | chain stops at "clocks 900 s apart (measured from the peer's root DSE / HTTPS Date header)"; never "chronyd stopped"; no clock step printed | containers share the host's kernel clock; only a simulated offset of ipa-diagnose's own process is live (R12) |
| `ldap/<peer>` principal missing | `test_server_not_found_*` | deeper link only with a COMPLETE principal list | deleting a server's service principal damages the lab |
| DS keytab key rejected by the KDC (LDAP 49 reproduced by kinit) | `test_ldap_49_*` | local key diagnosed, no keytab replacement printed; 49 with a working reproduction is "not reproduced", never "keytab mismatch" | replacing a live key breaks the replica |
| Peer rejects the GSSAPI bind (49, ticket obtained) | `test_ldap_49_reproduced_*` | peer-side, MEDIUM, handoff | as above |
| Insufficient access / not a replication manager | `test_insufficient_access_*` | MEDIUM, "this server's copy of the directory" | LDAP write to the managers group |
| Generation-ID mismatch, changelog purged, replica-ID conflict, re-init required | `ca-suffix-generation-mismatch` fixture; status discriminator tests | REPLICA_NEEDS_ADMIN_ACTION, nothing printed ("never prints re-initialization") | would need deliberately damaged 389-DS data |
| RUV element without a current server | `test_ruv_*` | WARN candidate only when the topology read is complete and no clean task runs; no clean-up printed | stale RUV would need an ungraceful removal |
| Busy / backoff / no sessions yet | `test_transient_states_*` | never green, never a root; `--verify` PENDING | not reliably reproducible on demand |
| Agreement budget (more than 8 agreements) | `test_budget_drops_*` | PARTIAL, dropped peers named, never HEALTHY | a 10-server lab does not fit a free runner |
| Topology segments and agreements disagree | `test_topology_and_agreements_*` | CONTRADICTING, withholds every fix | would need a topology-plugin inconsistency |
| TLS / LDAPS agreements | `test_tls_transports_*` | `-ZZ` / `ldaps://` with the IPA CA, `LDAPTLS_REQCERT=demand` | the lab's topology agreements use LDAP + GSSAPI on 389 |
| Unrecognized status | `test_unrecognized_status_*` | UNDIAGNOSED, no story forced | - |
| Verify: false-RESOLVED campaign | `tests/replication/test_verify.py` | old sessions, update in progress, transient, other host/scope, collector failure, vanished agreement, unobservable reverse, unrelated new failure: never RESOLVED; PENDING bounded | live verify rows: R02c, R02d, R05b |

## Freeze campaign re-run (final product code)

Replication scenarios R00-R12 plus the cross-mode rows J01-J03 re-run on the final freeze product code (b58f3d6), run [36742907976](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36742907976): **23/23 PASS, 0 false root causes, 0 missed causes, 0 unsafe resolutions**. J01/J03: the server diagnosis (`ipa-diagnose`) in the same injected state named the same local cause and printed the same argv as replication mode; J02: with ipa02's Directory Server stopped, the server diagnosis on ipa01 claimed no local cause. **Freeze finding:** in runs 36724948206 and 36729641548, R02d (`--verify` on ipa01 seconds after the fix on ipa02) answered STILL_PRESENT although ipa02 answered on 389 (independently confirmed) - the agreement still recorded the old failure; fixed (de93d10): such an agreement is PENDING, and in run 3 R02d answered PENDING, then RESOLVED. Details: [freeze-audit.md](freeze-audit.md).
