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
