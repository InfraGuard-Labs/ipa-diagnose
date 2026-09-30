# Access diagnosis truth matrix (Slice 3)

LIVE evidence for `ipa-diagnose access USER HOST SERVICE`. Claims about access diagnosis must come from here, via
[claim-register.md](claim-register.md) (section "Slice 3").

- **Workflow:** `.github/workflows/live-freeipa-access.yml` running `scripts/lab_access.py`. The artifact
  `live-access-evidence-fedora-43` holds every JSON and text answer, the setup log, the raw hbactest of A14, the
  timing and the rows (`out/truth/access-results.jsonl`). Compact rows are also published as check-run annotations.
- **Environment:** free GitHub-hosted runner, disposable `freeipa/freeipa-server:fedora-43` container,
  freeipa-server 4.13.3-2.fc43, sssd-client 2.12.0-3.fc43, curl 8.15.0, Python 3.14.7. It was a single server with
  integrated DNS and CA, and the lab identities (`LAB.TEST`) were fake. **No other FreeIPA version or OS was
  validated live.** A local attempt on centos-9-stream (FreeIPA 4.13.3 EL9) did not finish `ipa-server-install`
  under Docker Desktop, so it is not evidence.
- **Method:** `scripts/lab_access.py setup` seeds a known HBAC policy as the administrator, with `allow_all`
  disabled. For every scenario, the EXPECTED result follows from that policy and is independently confirmed by
  FreeIPA's own `ipa hbactest`, run directly and not through ipa-diagnose. `ipa-diagnose access` then answers
  blind, as JSON and as text. A row records both answers, the exit code, the states, the explanation status, and
  whether the answer was a **false allow** (PASS where FreeIPA did not grant) or a **false deny** (FAIL where FreeIPA
  granted). A scenario without a row fails the job.

## Policy seeded

| Object | Setup |
|---|---|
| Rules | `r_direct` (alice, app01, sshd); `r_group` (group ops, hostgroup web, sshd); `r_nested` (group devs, app01, sshd); `r_hg_nested` (henry, hostgroup prod, sshd); `r_svcgroup` (gina, app01, service group Sudo); `r_frank_off` (frank, app01, sshd; **disabled**); `r_erin` (erin, app01, sshd); `r_ivan_off` (disabled) + `r_ivan_on` (both ivan, app01, sshd); `r_judy` (judy, app01, sshd); `r_cycle` (group cyc2, all hosts, all services); `r_perf` (group perfdeep11, all hosts, all services); a rule named with a bidi override and an escape sequence (user hostile, all hosts, all services); `allow_all` disabled |
| Memberships | bob ∈ ops; carol ∈ backend ∈ devs; app02 ∈ web ∈ prod; cyc ∈ cyc1 ∈ cyc2 (+ attempted cyc2 ∈ cyc1); perf ∈ perfdeep0 ∈ ... ∈ perfdeep11, plus 150 flat groups |
| Accounts | erin disabled (`ipa user-disable`); judy principal expired (2020-01-01); pres deleted with `--preserve` (still named by r_pres); alice has a password (non-admin caller) |
| Hosts | app01, app02 added with `--force` (no keytab); no host `nohost` |

## Rows (final run: product commit 1e3a4fd, run 36505832843)

Run: https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36505832843 (conclusion: success). Runs 36502681544 (0e13a0c) and 36504997796 (dc50e01) gave the same 25/25.

| # | Scenario | Query | Independent `ipa hbactest` | ipa-diagnose (exit, AUTHN / AUTHZ, explanation) | False decision? | Verdict |
|---|---|---|---|---|---|---|
| A01 | direct user allow | alice app01 sshd | granted (r_direct) | 0, NOT_VERIFIED / PASS, COMPLETE (user listed directly) | no | PASS |
| A02 | group + hostgroup allow | bob app02 sshd | granted | 0, NOT_VERIFIED / PASS, COMPLETE (via ops; via web) | no | PASS |
| A03 | nested group | carol app01 sshd | granted | 0, NOT_VERIFIED / PASS, COMPLETE (carol → backend → devs) | no | PASS |
| A04 | nested hostgroup | henry app02 sshd | granted | 0, NOT_VERIFIED / PASS, COMPLETE (app02 → web → prod) | no | PASS |
| A05 | HBAC service group | gina app01 sudo | granted | 0, NOT_VERIFIED / PASS, COMPLETE (sudo via Sudo) | no | PASS |
| A06 | no rule (deny) | dave app01 sshd | denied | 1, NOT_VERIFIED / FAIL; no fix, no grant suggestion, not called broken | no | PASS |
| A07 | only a disabled rule | frank app01 sshd | denied | 1, NOT_VERIFIED / FAIL; names r_frank_off as disabled, no enable suggestion | no | PASS |
| A08 | disabled user, policy allows | erin app01 sshd | granted | 1, **FAIL / PASS** (USER_DISABLED), no user-enable suggestion | no | PASS |
| A09 | missing user | nosuchuser app01 sshd | (not asked) | 1, FAIL / **UNKNOWN** (not evaluated) | no | PASS |
| A10 | missing host | alice nohost sshd | (not asked) | 3, NOT_VERIFIED / UNKNOWN (HOST_NOT_FOUND) | no | PASS |
| A11 | undefined HBAC service | alice app01 nosuchsvc | denied | 1, NOT_VERIFIED / FAIL (SERVICE_NOT_DEFINED) | no | PASS |
| A12 | no Kerberos ticket | alice app01 sshd | (not asked) | 3, UNKNOWN / UNKNOWN | no | PASS |
| A13 | non-admin caller (alice's ticket) | bob app02 sshd | granted | 0, NOT_VERIFIED / PASS, COMPLETE | no | PASS |
| A14 | `allow_all` enabled, missing user | nosuchuser app01 sshd | **granted** (hbactest evaluates the bare name) | 1, FAIL / **UNKNOWN**: the allow for a user that does not exist is not repeated | no | PASS |
| A15 | short host, upper-case user | ALICE APP01 sshd | granted (alice, app01.lab.test) | 0, PASS; FreeIPA was asked with alice / app01.lab.test | no | PASS |
| A16 | IPA API unreachable (httpd stopped) | alice app01 sshd | (not asked) | 3, UNKNOWN / UNKNOWN | no | PASS |
| A17 | trusted-domain form | someone@ad.example.com app01 sshd | (not asked) | 3, UNKNOWN / UNKNOWN (TRUSTED_IDENTITY_UNSUPPORTED) | no | PASS |
| A18 | hostile rule name (bidi + escape), accepted by FreeIPA | hostile app01 sshd | granted | 0, PASS; no escape, bidi or zero-width character in text or JSON | no | PASS |
| A19 | group cycle (FreeIPA **accepted** cyc1 ⊂ cyc2 ⊂ cyc1) | cyc app01 sshd | granted | 0, PASS, COMPLETE; terminates | no | PASS |
| A20 | disabled rule + enabled rule | ivan app01 sshd | granted (r_ivan_on) | 0, PASS; only r_ivan_on explains | no | PASS |
| A21 | `bundle --access` | alice app01 sshd | - | bundle written, `bundle validate` valid, access.json decision PASS, no lab identifier in any member | - | PASS |
| A22 | expired principal, policy allows | judy app01 sshd | granted | 1, **FAIL / PASS** (USER_PRINCIPAL_EXPIRED) | no | PASS |
| A23 | non-admin caller asks about a disabled user | erin app01 sshd (alice's ticket) | granted | 1, FAIL / PASS; the disabled flag is readable with an ordinary ticket (`Account disabled: True`) | no | PASS |
| A24 | preserved (deleted) user named by a rule | pres app01 sshd | (not asked) | 1, FAIL / UNKNOWN (USER_PRESERVED, not evaluated) | no | PASS |
| A25 | trusted-domain user on a missing host | someone@ad.example.com nohost sshd | (not asked) | 3, UNKNOWN / UNKNOWN; VERIFY has `ipa host-show`, never `ipa hbactest` | no | PASS |

**Final run: 25/25 PASS, 0 false allows, 0 false denies.**

### History (what the earlier runs found)

| Run | Commit | Result | Finding |
|---|---|---|---|
| 36483967139 | 7801f42 | 21/22 | A21: the `bundle --access` API time budget started before the bundle's diagnosis, so the answer was UNKNOWN. The budget now starts at the first call. |
| 36494758327 | a10a1bf | 21/22 | A21: a harness bug (the ticket cache variable applied only to the first command). The product correctly reported UNKNOWN without a ticket. The same bug meant the 150 "flat" groups of the performance user were **never created in runs 1-2**, so those timings are withdrawn. |
| 36500100173 | f76417b | 24/24 | With the 150 groups really present, the upward chain search hit its 40-read bound (45 API calls, explanation INCOMPLETE). It now walks down from the rule's group. |
| 36501684754 | f473d46 | 24/24 | Nested chain COMPLETE in 16 API calls. |
| 36502681544 | 0e13a0c | 25/25 | Adds A25. |
| 36504997796 | dc50e01 | 25/25 | - |
| 36505832843 | 1e3a4fd | 25/25 | Final (the pull request's product code). |

## Timing (final run, three runs each, in the container)

| Case | Wall time | API calls | Explanation |
|---|---|---|---|
| direct allow (alice) | 1.38-1.72 s | 5 | COMPLETE |
| nested chain 12 deep, user in 150 other groups (perf) | 3.87-4.13 s | 16 | COMPLETE |
| deny (dave) | 1.05-1.10 s | 4 | COMPLETE |
| IPA API unreachable | 0.22 s | - | - |

## Real API shapes (every run)

The fixtures' shapes match the real answers. `user_show --all` carries `nsaccountlock` (boolean), `preserved`,
`memberof_group`, `memberofindirect_group` and `memberofindirect_hbacrule`. `host_show` carries `has_keytab`,
`memberof_hostgroup` and `memberofindirect_hostgroup`. `hbacsvc_show` carries `memberof_hbacsvcgroup`.
`hbacrule_show` carries `ipaenabledflag: [true]`. `group_show` / `hostgroup_show` carry `member_*` and
`memberof_*`. `hbactest` returns `value`, `matched`, `notmatched`, `error`, `warning` and `messages`.

## Freeze campaign re-run (final product code)

Access scenarios A01-A25 re-run on the final freeze product code (b58f3d6), run [36742907967](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36742907967), **FreeIPA 4.13.4** / Fedora 43: **25/25 PASS, 0 false allows, 0 false denies** (every AUTHORIZATION answer compared with an independent ipa hbactest). Also 25/25 in freeze run 1 (36724948123). Details: [freeze-audit.md](freeze-audit.md).
