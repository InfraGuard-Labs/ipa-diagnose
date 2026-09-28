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
| Accounts | erin disabled (`ipa user-disable`); judy principal expired (2020-01-01); alice has a password (non-admin caller) |
| Hosts | app01, app02 added with `--force` (no keytab); no host `nohost` |

## Rows (run 1: product commit 7801f42, run 36483967139)

| # | Scenario | Query | Independent hbactest | ipa-diagnose (exit, AUTHN/AUTHZ, explanation) | False decision? | Verdict |
|---|---|---|---|---|---|---|
| A01 | direct user allow | alice app01 sshd | granted (r_direct) | 0, NOT_VERIFIED/PASS, COMPLETE (user listed directly) | no | PASS |
| A02 | group + hostgroup allow | bob app02 sshd | granted | 0, NOT_VERIFIED/PASS, COMPLETE (via ops; via web) | no | PASS |
| A03 | nested group | carol app01 sshd | granted | 0, NOT_VERIFIED/PASS, COMPLETE (carol → backend → devs) | no | PASS |
| A04 | nested hostgroup | henry app02 sshd | granted | 0, NOT_VERIFIED/PASS, COMPLETE (app02 → web → prod) | no | PASS |
| A05 | HBAC service group | gina app01 sudo | granted | 0, NOT_VERIFIED/PASS, COMPLETE (sudo via Sudo) | no | PASS |
| A06 | no rule (deny) | dave app01 sshd | denied | 1, NOT_VERIFIED/FAIL; no fix, no grant suggestion, not called broken | no | PASS |
| A07 | only a disabled rule | frank app01 sshd | denied | 1, NOT_VERIFIED/FAIL; names r_frank_off as disabled, no enable suggestion | no | PASS |
| A08 | disabled user, policy allows | erin app01 sshd | granted | 1, **FAIL/PASS** (USER_DISABLED), no user-enable suggestion | no | PASS |
| A09 | missing user | nosuchuser app01 sshd | (not asked) | 1, FAIL/**UNKNOWN** (not evaluated) | no | PASS |
| A10 | missing host | alice nohost sshd | (not asked) | 3, NOT_VERIFIED/UNKNOWN (HOST_NOT_FOUND) | no | PASS |
| A11 | undefined HBAC service | alice app01 nosuchsvc | denied | 1, NOT_VERIFIED/FAIL (SERVICE_NOT_DEFINED) | no | PASS |
| A12 | no Kerberos ticket | alice app01 sshd | (not asked) | 3, UNKNOWN/UNKNOWN | no | PASS |
| A13 | non-admin caller (alice's ticket) | bob app02 sshd | granted | 0, NOT_VERIFIED/PASS, COMPLETE (account state readable by a normal user) | no | PASS |
| A14 | `allow_all` enabled, missing user | nosuchuser app01 sshd | **granted** (FreeIPA's hbactest evaluates the bare name) | 1, FAIL/**UNKNOWN**: ipa-diagnose does not repeat hbactest's allow for a user that does not exist | no | PASS |
| A15 | short host, upper-case user | ALICE APP01 sshd | granted (alice, app01.lab.test) | 0, PASS; FreeIPA was asked with alice / app01.lab.test | no | PASS |
| A16 | IPA API unreachable (httpd stopped) | alice app01 sshd | (not asked) | 3, UNKNOWN/UNKNOWN | no | PASS |
| A17 | trusted-domain form | someone@ad.example.com app01 sshd | (not asked) | 3, UNKNOWN/UNKNOWN (TRUSTED_IDENTITY_UNSUPPORTED) | no | PASS |
| A18 | hostile rule name (bidi + escape) | hostile app01 sshd | granted | 0, PASS; no escape, bidi or zero-width character in text or JSON output | no | PASS |
| A19 | group membership cycle attempt | cyc app01 sshd | granted | 0, PASS, COMPLETE; terminates | no | PASS |
| A20 | disabled rule + enabled rule | ivan app01 sshd | granted (r_ivan_on) | 0, PASS; only r_ivan_on explains | no | PASS |
| A21 | `bundle --access` | alice app01 sshd | - | **FAIL** in run 1: access.json decision UNKNOWN. Cause: the API time budget started before the bundle's diagnosis. Fixed in a10a1bf (budget starts at the first call) | - | FAIL → re-run |
| A22 | expired principal, policy allows | judy app01 sshd | granted | 1, **FAIL/PASS** (USER_PRINCIPAL_EXPIRED) | no | PASS |

**Run 1: 21/22 PASS, 0 false allows, 0 false denies.**

## Timing (run 1, three runs each, in the container)

| Case | Wall time | API calls |
|---|---|---|
| direct allow (alice) | 1.22-1.37 s | 5 |
| nested chain 12 deep, user in 150 other groups (perf) | 3.95-4.85 s | 17 |
| deny (dave) | 0.68-1.18 s | 4 |
| IPA API unreachable | 0.21 s | - |

## Real API shapes (run 1)

The fixtures' shapes match the real answers. `user_show --all` carries `nsaccountlock` (boolean), `memberof_group`,
`memberofindirect_group` and `memberofindirect_hbacrule`. `host_show` carries `has_keytab`, `memberof_hostgroup`
and `memberofindirect_hostgroup`. `hbacsvc_show` carries `memberof_hbacsvcgroup`. `hbacrule_show` carries
`ipaenabledflag: [true]`. `hbactest` returns `value`, `matched`, `notmatched`, `error`, `warning` and `messages`.
