# Client mode: `ipa-diagnose client`

> Is this FreeIPA client correctly enrolled and able to resolve and authenticate IPA identities, and if not, why?

```
sudo ipa-diagnose client                                   # the client itself (identity lookup: group admins)
sudo ipa-diagnose client --user alice --service sshd       # and one user's login path through one PAM service
sudo ipa-diagnose client --user alice --service sshd --verify   # after a fix: fresh checks, compared with last time
     ipa-diagnose access alice app01.example.com sshd --runtime  # FreeIPA's HBAC decision + this host's runtime side
```

Run it **as root on the client**. Without root, the checks that need it (keytab, host key, sssd.conf, sssctl, logs)
are reported as *not verified*, never as passed. Nothing is changed and no AI is used. Every run is labelled LIVE, or
REPLAY for recorded evidence (`--replay DIR`, development and tests only).

## What it answers, and what it does not

Three states are always kept apart:

| State | Meaning in client mode | Never |
|---|---|---|
| **AUTHENTICATION** | *FAIL* when something on this host's authentication path to IPA is shown broken (clock, KDC, host key, SSSD, PAM auth stack); otherwise *NOT VERIFIED*. | PASS: no credential of any user is tested. |
| **AUTHORIZATION** | Not decided by client mode (*NOT VERIFIED*). With `access --runtime` it is FreeIPA's own `hbactest` decision, unchanged. | Rewritten by runtime evidence. |
| **RUNTIME ACCESS** | *FAIL* when a runtime prerequisite on this host is shown broken for the user/service asked (SSSD down, identity not resolvable, NSS or PAM not using SSSD, SSSD's PAM account phase refusing). Otherwise *NOT VERIFIED*, with what was checked. A broken *online* path (DNS, KDC, clock, host key, SSSD offline) makes AUTHENTICATION FAIL but not RUNTIME ACCESS: users with cached credentials or SSH keys may still log in. | PASS: no login is attempted and no session is opened. |

SSSD's account check on the host (`sssctl user-checks USER -a acct -s SERVICE`, the PAM **account** phase only, no
password) is runtime evidence. When it refuses a user that FreeIPA's `hbactest` authorizes, the result is
**CONTRADICTING** (the refusal comes from the host: another `access_provider`, a `simple_allow_*` list, SSSD's cached
HBAC rules, a different `ipa_hostname`, or another PAM module), never "HBAC denies".

## How it works: a bounded, deterministic planner (L3)

ipa-diagnose does not run a fixed checklist. A plan (`src/ipa_diagnose/client/plan.py`) declares every check it may
run, what each depends on and when each is worth running; the planner (`src/ipa_diagnose/planner/core.py`) chooses,
from the results already in hand, which declared check runs next.

```
enrollment config ──► DNS (server name) ──► TCP 443 / 389 / 88 ──► TLS trust + the server's clock
      │                    └─ SRV records (only when SSSD discovers servers through DNS)
      ├─► host keytab ──► the KDC accepts this host's key (kinit -k into a private, deleted cache)
      └─► sssd.conf ─┐
SSSD service ────────┴─► sssctl config-check ─► SSSD online? ─► user through SSSD
                                                                ├─► does IPA have it? (asked as this host)
                                                                ├─► system NSS stack ─► nsswitch.conf
                                                                ├─► PAM stack of the service
                                                                └─► PAM account phase (sssctl user-checks)
only when IPA has the user and SSSD is online but does not resolve it:
      SSSD cache entry ─► SSSD log signals ─► cache database file
```

**Why this order.** Kerberos depends on DNS and on the clock; SSSD's online state depends on DNS, the network, TLS
trust, the clock and the host key; identity lookups depend on SSSD; logins depend on NSS and PAM. The KDC's own
answer to the host key (`kinit -k`) is read before blaming anything Kerberos-related, because it separates the cases
that look alike from SSSD's side: *clock skew too great*, *cannot contact any KDC*, *client not found* (host
principal missing) and *preauthentication failed* (stale keytab). Local, independent checks (SSSD service,
configuration) run even when the network side is broken, so an independent second cause is still found.

**How the next check is chosen** (the same evidence always gives the same trace):

- a step runs only when the steps it *requires* finished with an accepted outcome; otherwise it is *blocked* (its
  question cannot be answered, or would only repeat the upstream failure);
- a *relevance gate* reads the facts gathered so far: a check that cannot change the conclusion is *not needed*
  (a healthy client is never probed for cache corruption; the SRV check is skipped when SSSD uses fixed servers);
- privilege and version applicability are checked first (*privilege*, *not applicable*): a check that needs root or
  an SSSD version this host does not have is not run half-way;
- a stop rule can end the run (for example: this host is not an IPA client at all).

**Step model.** Each step declares: id, capability, the registry check it runs, typed parameters (literals, inputs or
facts of earlier steps, validated again by the registry types before use), prerequisites, ordering, relevance gate,
privilege, version applicability, classification (PASS / WARN / FAIL / UNKNOWN), stop rule and retries. The check's
registry entry declares its argv/API, privilege, timeout, evidence shape, secret handling and side effects.
Provenance (command, time, LIVE/REPLAY, reused result) is recorded for every step.

**Hard bounds** (validated before anything runs, enforced while running):

| Bound | Value | When reached |
|---|---|---|
| steps in a plan | 48 | the plan is rejected (programming error) |
| dependency depth / fan-out | 12 / 10 | the plan is rejected |
| cycles | impossible: a step may only depend on steps declared before it | - |
| checks executed | 48 | the run stops; remaining steps are recorded as *stopped* |
| wall clock | 180 s | the run stops honestly with partial evidence |
| per-check timeout | declared per check (5-50 s) | the check is UNKNOWN |
| retries | at most 1, only after a timeout, with a fresh run | - |
| duplicates | the same check with the same parameters runs once per run (result reused, marked) | - |
| cancellation | Ctrl-C keeps the partial trace | exit 130 |
| freshness | evidence is never reused across runs; `--verify` re-runs every check | - |

When a bound is reached, the run stops, keeps the evidence it has, lists what is not verified and concludes nothing
it did not establish. A check that fails to run is **UNKNOWN**, never a failure of what it was checking (a `systemctl`
timeout is not "SSSD is stopped").

## Diagnoses and roles (L4)

Rules (`src/ipa_diagnose/client/diagnose.py`) turn the trace into diagnoses, each with the steps it rests on:

- **PRIMARY**: the most upstream established cause; **INDEPENDENT**: another cause on an unrelated path (for example
  DNS broken *and* sssd.conf invalid); **RELATED**: a symptom explained by another diagnosis (SSSD offline because
  the server is unreachable); **UNDIAGNOSED**: a failure nothing established explains (reported, with next read-only
  steps, never guessed); **CONTRADICTING**: evidence that disagrees (HBAC allows, the host refuses); **WARNING**.
- A downstream layer is never blamed while an upstream failure explains it: SSSD is blamed only when DNS, network,
  TLS, time and the host key passed; the cache is considered only when IPA has the user **and** SSSD is online.

## Resolution (L5, Slice 1's engine and gates)

A fix is shown only when the cause is established with enough confidence, the procedure applies to this IPA client
version, its fresh read-only checks pass, no contradicting evidence withholds it, its prerequisites are met and every
command argument validates. ipa-diagnose never runs a fix.

| Cause | What is shown |
|---|---|
| SSSD stopped | `systemctl start sssd.service` (MEDIUM). Withheld when `sssctl config-check` reports errors, the unit is masked/disabled/transitioning, the host has no systemd, or the cause is a symptom (for example of an invalid configuration). |
| One user's cache entry inconsistent (IPA has the user, SSSD online, entry cached, lookup fails) | `sss_cache -u USER` (LOW): marks the entry expired; nothing is deleted; cached passwords are kept. |
| Cache database errors proven (IPA has the user, SSSD online, DNS/time/host key fine, SSSD's log reports cache database errors, the entry cannot be read) | `sssctl cache-remove --stop --start` (HIGH), with an explicit admin confirmation: cached passwords are removed (no offline logins until users log in online again); sssctl first exports local overrides to `/var/lib/sss/backup` and removes nothing if that fails. |
| Clock skew, stale/missing/wrong keytab, host principal unknown, not enrolled | No fix: reasons shown (no clock step on clients, no keytab replacement, no re-enrollment). |
| Everything else | No fix; the next read-only steps. |

### The SSSD cache: why never `rm /var/lib/sss/db/*`

A long-standing field workaround is *stop sssd; remove /var/lib/sss/db/\*; start sssd*. ipa-diagnose never prints it:

- it removes every cached identity **and every cached password**: laptops and hosts that cannot reach IPA can no
  longer log anyone in offline;
- it also removes local overrides (`sss_override`) without a backup;
- it is usually applied to problems that are not the cache (DNS, time, a stale keytab, an unreachable server), where
  it only destroys the offline fallback.

Before any cache action the planner must have shown: the IPA server is reachable, DNS and time are healthy, the KDC
accepts the host key, SSSD runs with a valid configuration and is **online**, IPA itself has the user, and SSSD still
does not resolve it. Then the least destructive supported action is chosen: `sss_cache -u USER` for one inconsistent
entry; `sssctl cache-remove` (SSSD's supported tool, with its backup of local data) only when SSSD's own log reports
cache database errors. When SSSD fails to start and its log mentions the cache database, nothing is offered: the
evidence cannot be completed while SSSD is down.

### Upstart-era procedures

Old procedures use `/sbin/initctl stop sssd` / `/sbin/initctl start sssd` (Upstart, RHEL 6). Every OS ipa-diagnose
supports uses systemd; service commands are printed for systemd only, and on a host without systemd the start
procedure is withheld with that reason. `initctl` is never printed.

## Verify (L6)

`ipa-diagnose client --verify` re-runs every check now (the same user and service as last time, unless given) and
compares with the saved result (`client_last.json` in the state directory; replay runs use a separate file). Per
earlier diagnosis: **RESOLVED** (its symptom check passes now, the diagnosis is gone, and any fix criteria pass with
fresh checks), **STILL_PRESENT**, **PARTIALLY_RESOLVED**, **CHANGED** or **UNABLE_TO_VERIFY** (the check did not run
or pass now). A new failure is reported too. A check that cannot run is never counted as resolved; a damaged or
edited state file is refused.

## Exit codes

| | `client` | `client --verify` | `access --runtime` |
|---|---|---|---|
| 0 | healthy (warnings may be listed) | everything found last time resolved, nothing new | as `access` |
| 1 | a problem was found | something still present, partial, or new | as `access` |
| 4 | nothing wrong found, but not everything could be checked | something could not be verified | as `access` |
| 5 | - | - | FreeIPA policy authorizes it, but a runtime check on this host shows the login would fail |
| 2 / 70 / 130 | usage error / internal error / interrupted | | |

## JSON

`--json` prints `kind: ipa-diagnose.client`, `client_schema_version: "1.0"`: `environment`, `status`, `answer`,
`authentication`, `authorization`, `runtime_access`, `planner_summary` (steps run/skipped by reason, reused results,
wall time, stop reason, bounds), `steps` (every step: outcome, summary, why in plan, why selected or skipped,
command, privilege, side effects, provenance), `diagnoses` (code, role, confidence, evidence steps, next steps),
`ruled_out`, `resolution`, `verification`, `completeness`, `limitations`. `ipa-diagnose access` output without
`--runtime` is unchanged (access schema 1.0); with `--runtime` it is 1.1 (additive: `runtime_access.investigated`,
`note`, `checked_on`, `client`).

## Checks, privileges and side effects

| Check | Needs | May touch |
|---|---|---|
| read /etc/ipa/default.conf, /etc/resolv.conf, /etc/nsswitch.conf, /etc/pam.d/SERVICE; versions (rpm) | - | nothing |
| sssd.conf (fixed non-secret options only; `*authtok*`/password/secret/key options are never read) | root | nothing |
| `getent ahosts`, DNS SRV query to the configured resolvers | - | DNS queries |
| TCP connect to 443/389/88; one anonymous HTTPS HEAD to the server (TLS trust + the server's Date header) | - | the server's connection/access logs |
| `klist -k /etc/krb5.keytab` (principals and key versions; never `-K`) | root | nothing |
| `kinit -k` with the host key into a private temporary cache, deleted at once | root | one Kerberos AS request (as SSSD makes itself) |
| IPA API `user_show` asked as this host (host ticket in a private cache) | root | one AS request, one read-only API call |
| `systemctl show sssd`, `sssctl config-check`, `sssctl domain-status` (never `--start`), `sssctl user-show` | root, SSSD ≥ 2.0 | nothing (domain-status asks the running SSSD over InfoPipe) |
| `getent -s sss`, `getent` | - | SSSD may refresh its cache for that name (as any lookup) |
| `sssctl user-checks USER -a acct -s SERVICE` | root, SSSD ≥ 2.0 | the PAM **account** phase only (no password, no session); SSSD may refresh its cache and HBAC rules; `pam_faillock` does not reset counters without an auth phase |
| SSSD logs: recent journal + domain log tail, known signals only (counts and one redacted example) | root | nothing |

Unknown or older SSSD versions: every `sssctl` check is skipped (*not applicable*), never run on a version it is not
known to behave on.

## Privacy

Output (console and JSON) passes every string through secret redaction and then terminal/bidi sanitization. Key
material, tickets and passwords are never read into results. `ipa-diagnose bundle --client [--user U --service S]`
adds `client.json` to a support bundle: states, diagnosis codes and roles, step outcomes and a few enumerated facts
only, with names replaced by bundle pseudonyms; no check output, log lines, commands, principals or key versions. The
bundle's usual pipeline and fail-closed leak self-test apply.

## Limitations

- No login is attempted and no credential is tested: RUNTIME ACCESS and AUTHENTICATION are never PASS.
- Checks run on this host only. `access --runtime` investigates only when run on HOST itself (no remote execution).
- Trusted-domain (AD) users, ID views, sudo rules, SELinux maps, automount, smart cards and lockout are not diagnosed.
- A stale cached identity that still resolves (for example an old UID after a user was recreated) is not detected:
  only lookups that fail are investigated.
- SSSD logs are read only for known signals in recent lines; an unknown failure may not be recognized
  (UNDIAGNOSED).
- Validated live only on FreeIPA 4.13.3 / Fedora 43 (see `docs/truth/client-truth-matrix.md`).
