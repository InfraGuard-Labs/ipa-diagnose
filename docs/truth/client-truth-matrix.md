# Client diagnosis truth matrix (Slice 4)

LIVE evidence for `ipa-diagnose client` and `ipa-diagnose access ... --runtime`. Claims about client mode must come
from here, via [claim-register.md](claim-register.md) (section "Slice 4").

- **Workflow:** `.github/workflows/live-freeipa-client.yml` running `scripts/lab_client.py`. The artifact
  `live-client-evidence-fedora-43` holds every JSON and `--details` answer, the lab command log and the rows
  (`out/truth/client-results.jsonl`). Compact rows are also published as check-run annotations.
- **Environment:** free GitHub-hosted runner; a private Docker network with two disposable containers:
  `freeipa/freeipa-server:fedora-43` (freeipa-server 4.13.3-2.fc43, integrated DNS and CA, 172.30.0.10) and a
  Fedora 43 client built in the job (freeipa-client 4.13.4-2.fc43, sssd 2.12.0-3.fc43, systemd), enrolled with
  `ipa-client-install` through DNS discovery. Fake `LAB.TEST` identities and fake canaries only. **No other FreeIPA,
  SSSD or OS version was validated live.**
- **Method:** `lab_client.py enroll` enrolls the client and proves it (E00: host keys in the keytab, SSSD online,
  `getent passwd admin`, host entry in IPA). `setup` seeds users `alice` (allowed), `bob`, `ghost` and one HBAC rule
  (`alice`, `client1.lab.test`, `sshd`) with `allow_all` disabled. Each scenario injects one fault on the disposable
  client, **confirms it independently** (systemctl, getent, kinit, `ipa hbactest`, sssctl) before ipa-diagnose runs,
  then runs ipa-diagnose **blind** (it is never told what was broken), records expected vs observed, whether a
  forbidden (wrong) root cause was reported as PRIMARY/INDEPENDENT (**false root cause**), what fix was offered, and
  restores the client. When a scenario applies a fix, it runs the exact argv ipa-diagnose printed. A scenario
  without a row fails the job.

## Run history

| Run | Product commit | Result | Notes |
|---|---|---|---|
| [36513399083](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36513399083) | 00fd9e5 | 14/19 | every healthy run with `--user/--service` came out NOT_FULLY_VERIFIED; cause not visible in annotations (debug added) |
| [36577169643](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36577169643) | 2a0a800 | 15/19 | **live finding:** `sssctl user-checks` prints its PAM result on **stderr** (SSSD 2.12); the parser read stdout only, so the PAM account check was UNKNOWN. Harness: repeated SSSD restarts hit systemd's start limit (C09b; ipa-diagnose correctly reported SSSD failed) |
| [36579279971](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36579279971) | 20d4d25 | **19/19 PASS**, 0 false root causes | parser reads both streams; lab resets the start limit |
| [36581496915](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36581496915) | 79081fc | **19/19 PASS**, 0 false root causes | after review round 2. Findings from its rows, fixed afterwards: in C13 the PAM account refusal while SSSD was offline was listed INDEPENDENT (now RELATED to the offline state, MEDIUM), and MIT krb5's "Cannot resolve servers for KDC" was not classified (now a name-resolution error tied to DNS) |
| [36583971262](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36583971262) | 3e85dea | **19/19 PASS**, 0 false root causes | after review round 3: online-path failures no longer claim RUNTIME FAIL |
| [36585281095](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36585281095) | 065ac2e | **19/19 PASS**, 0 false root causes | after review round 3b: online-path failures always make AUTHENTICATION FAIL |

## Scenarios (runs 36579279971 on 20d4d25 and 36581496915 on 79081fc: all PASS)

| # | Scenario | Fault (injected, independently confirmed) | Expected (and forbidden) | Fix | Verify |
|---|---|---|---|---|---|
| E00 | enrollment proven | - | keytab has `host/client1.lab.test`, SSSD online, `getent passwd admin`, host entry exists | - | - |
| C00 | healthy baseline | none (`--user alice --service sshd`) | HEALTHY, exit 0; RUNTIME NOT VERIFIED; PAM account phase PASS | none | - |
| C00b | healthy, no user | none | HEALTHY (group `admins` resolves) | none | - |
| C01 | SSSD stopped | `systemctl stop sssd` (is-active: inactive) | PRIMARY SSSD_NOT_RUNNING; no DNS/keytab/enrollment cause | `systemctl start sssd.service` (MEDIUM) | - |
| C02 | SSSD recovered | the printed argv run verbatim | - | - | `client --verify`: RESOLVED, exit 0 |
| C03 | DNS discovery failure | resolv.conf → dead resolver (`getent ahosts` exit 2) | PRIMARY DNS_RESOLVER_NOT_ANSWERING or DNS_SERVER_UNRESOLVABLE; not SSSD/keytab/clock | none | - |
| C04 | KDC unreachable | iptables REJECT 88/tcp+udp (kinit: cannot contact any KDC) | PRIMARY KDC_UNREACHABLE; not keytab, principal, clock, DNS, cache | none | - |
| C05 | clock skew (**simulated**) | libfaketime +2 h for ipa-diagnose's own process only | CLOCK_SKEW (MEDIUM: the KDC still accepted the host key); no keytab/KDC cause | none (no clock step on clients) | - |
| C06 | host keytab missing | `mv /etc/krb5.keytab` | PRIMARY HOST_KEYTAB_MISSING; not principal/enrollment/network | none (no keytab replacement) | - |
| C07 | identity lookup failure | `filter_users = ghost` (IPA has ghost; getent fails) | IDENTITY_LOOKUP_FAILS **UNDIAGNOSED** (honest); not USER_NOT_IN_IPA, not cache | none | - |
| C07b | user not in IPA | `--user nosuchuser7` | PRIMARY USER_NOT_IN_IPA (asked as the host); not cache | none | - |
| C08 | SSSD offline | REJECT 88/389/443/464/636 (not 53); SSSD Offline | PRIMARY SERVER_UNREACHABLE, SSSD_OFFLINE RELATED; not cache/keytab | none | - |
| C09 | HBAC PASS + SSSD stopped | `ipa hbactest` granted; SSSD stopped | `access --runtime`: AUTHORIZATION PASS (unchanged), RUNTIME FAIL, exit 5, client PRIMARY SSSD_NOT_RUNNING | - | - |
| C09b | HBAC PASS + host refuses | `access_provider = simple`, `simple_allow_users = bob`; `sssctl user-checks` denies | AUTHORIZATION PASS, RUNTIME FAIL, exit 5, RUNTIME_DENIED_HBAC_ALLOWS **CONTRADICTING** | none | - |
| C10 | recovery + verify | SSSD stopped → printed fix | - | `systemctl start sssd.service` | RESOLVED, exit 0; `access --runtime` exit 0, RUNTIME NOT VERIFIED |
| C11 | cache database damaged | domain cache file overwritten with random bytes while SSSD stopped | no false root cause; no generic delete; if cache removal is offered, the printed command must verify RESOLVED | **observed: SSSD 2.12 started and served lookups anyway; ipa-diagnose found nothing (exit 0) and offered nothing.** The cache-database diagnosis and `sssctl cache-remove` therefore stay FIXTURE_ONLY: a damaged cache that breaks lookups could not be produced safely | - |
| C12 | insufficient privilege | run as `nobody` | NOT_FULLY_VERIFIED, exit 4, no confident cause, no fix | none | - |
| C13 | two failures at once | dead resolver + `ipa_srever` typo in sssd.conf | both SSSD_CONFIG_INVALID and a DNS cause as PRIMARY/INDEPENDENT | none | - |
| C14 | support bundle | fake canary in the SSSD domain log; SSSD stopped | bundle created, `bundle validate` 0, `client.json` present, no raw user/host/realm or canary in the bundle, no canary in client output | - | - |

**Selectivity and time (run 36581496915):** healthy client 21 of 28 checks with `--user/--service` (18 without); failures 17-23; each run 0.3-0.8 s, except when the resolvers time out (C03 9.5 s, C13 29.5 s: DNS and SRV timeouts plus kinit). Exact outputs are in the run's artifact and annotations. **Limitations of this evidence:** one server, one client, one FreeIPA/SSSD version; C05 simulates the
clock of ipa-diagnose's own process only (a container cannot have its own kernel clock); the C11 outcome depends on
what SSSD 2.12 does with a damaged file and is recorded, not generalized; logins were never attempted.
