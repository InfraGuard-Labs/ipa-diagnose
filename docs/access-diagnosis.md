# Access diagnosis: `ipa-diagnose access USER HOST SERVICE`

> Does FreeIPA policy authorize USER to access HOST through SERVICE, and why?

```
ipa-diagnose access john app03.example.com sshd [--json] [--details] [--replay DIR]
```

`SERVICE` is the PAM service name that SSSD maps to an HBAC service (`sshd`, `login`, `sudo`, `gdm-password`...). It
is never a Kerberos service principal. The command is read-only, never uses AI, and never saves anything (the `verify`
baseline is untouched).

## What it answers, and what it does not

The answer has three separate parts. They are never merged into one "access OK".

| Part | States | Meaning |
|---|---|---|
| **AUTHENTICATION** | `FAIL`, `NOT_VERIFIED`, `UNKNOWN` (never `PASS`) | Can this IPA account authenticate at all, according to FreeIPA? `FAIL`: no such IPA user, a preserved (deleted) user, the account is disabled, or its Kerberos principal expired. For an expired principal, the KDC refuses Kerberos logins; whether an SSH-key login is refused depends on the host's SSSD. `NOT_VERIFIED`: nothing in FreeIPA blocks it, but **no credential was tested**, so a user existing is not an authentication pass. `UNKNOWN`: the account state could not be read. |
| **AUTHORIZATION** | `PASS`, `FAIL`, `UNKNOWN` | FreeIPA's HBAC policy decision, taken **only** from FreeIPA's own evaluator (`hbactest`) for an existing user and host, with a complete rule list and no rule errors. Anything else is `UNKNOWN`. |
| **RUNTIME ACCESS** | `NOT_VERIFIED`; with `--runtime` also `FAIL` (never `PASS`) | Whether a real login works. No login is ever attempted. Without `--runtime` the host's SSSD, PAM stack, network path and keytab are not checked, so it is always `NOT_VERIFIED`. With `--runtime`, run as root on HOST, client mode's read-only checks run there: `FAIL` when a runtime prerequisite is shown broken, otherwise still `NOT_VERIFIED` (see below). An HBAC `PASS` never means SSH works. |

Then: **ROOT CAUSE**, **WHY**, **CHECKED FOR YOU**, **IMPACT**, **RESOLUTION**, **RISK**, **VERIFY**, **LIMITATIONS**.

### A deny is policy, not a fault

`AUTHORIZATION: FAIL` means "FreeIPA HBAC policy does not authorize this request". That is often exactly what the policy
owner intended. ipa-diagnose never calls a deny broken or misconfigured, and **never suggests adding the user, host
or service to a rule, adding group members, or enabling a rule** to turn a deny into an allow. Who may log in where
is a security and business decision. The RESOLUTION for a deny is always "no fix suggested", with that reason. The
same applies to disabled or expired accounts: they are usually disabled on purpose.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | FreeIPA policy authorizes the request, and nothing in the account state blocks it (runtime still NOT VERIFIED) |
| 1 | A definite no: policy does not authorize it, or the account cannot authenticate |
| 3 | Unknown: no trustworthy policy decision (API unreachable, no ticket, missing user or host, evaluator errors, truncated rules, trusted-domain user) |
| 4 | Policy authorizes it, but the account state could not be read |
| 5 | Only with `--runtime`: policy authorizes it, but a runtime check on this host shows the login would fail |
| 2 | Usage error, including a refused USER/HOST/SERVICE; 70 internal error; 130 interrupted |

The existing commands (`diagnose`, `verify`, `ai-preview`, `bundle`) and their exit codes are unchanged.

### `--runtime`: continuing past the policy decision (Slice 4)

`sudo ipa-diagnose access USER HOST SERVICE --runtime`, run **on HOST itself** (its enrolled name in
`/etc/ipa/default.conf` must be HOST), continues into the runtime side with client mode's planner
([client-mode.md](client-mode.md)): SSSD, identity lookup, NSS, the service's PAM stack and SSSD's PAM account phase
for USER. AUTHORIZATION stays FreeIPA's `hbactest` decision, unchanged. RUNTIME ACCESS becomes FAIL when a runtime
prerequisite on this host is shown broken (exit 5); otherwise it stays NOT VERIFIED (no login is attempted). When
SSSD's account check refuses a user that `hbactest` authorizes, the answer is CONTRADICTING, never a rewritten
deny. It is not investigated when the policy or the account already refuses, and it never runs anything on another
host: elsewhere it prints the `ipa-diagnose client` command to run on HOST. Without `--runtime` the output is exactly
the Slice 3 answer (`access_schema_version` 1.0; with `--runtime` 1.1, additive).

## How the decision is made

FreeIPA's `hbactest` API command is the decision source. It evaluates HBAC rules with `pyhbac`, the Python binding of
SSSD's `libipa_hbac`, which is the library SSSD's IPA access provider enforces with. ipa-diagnose calls it through
FreeIPA's JSON-RPC API over HTTPS (`https://<server>/ipa/json`, server taken from `/etc/ipa/default.conf`),
authenticated with **the caller's own Kerberos ticket** (`curl --negotiate`). No root, no LDAPI and no host keytab
are used. Run `kinit` first. The answer is FreeIPA's view for that identity, and the JSON records whose view it is
(`query.asked_as`).

The call sequence is fixed and bounded. It is not a planner:

1. `user_show USER`: canonical name, `nsaccountlock`, principal and password expiry, direct and nested groups.
2. `host_show HOST`: canonical FQDN, direct and nested hostgroups, whether IPA holds a key for the host.
3. `hbacsvc_show SERVICE`: whether the HBAC service exists, and its service groups.
4. `hbactest` with the **canonical** user, FQDN and service from steps 1-3: **the decision**.
5. `hbacrule_show` for the matched rules (ALLOW), or for the rules that name this user (DENY). At most 10.
6. `group_show` / `hostgroup_show`, only to explain a nested chain. The search starts at the group the rule names
   and walks down through its member groups, keeping only the user's or host's own groups. Only groups on the path
   are read, however many other groups the user is in (at most 40 reads).

The only methods ever sent are these read-only ones. A method outside this allowlist is refused in code. There are
at most 60 calls, 20 s per call, and 120 s in total.

### Why ipa-diagnose checks existence and passes canonical names (researched, not assumed)

Reading FreeIPA 4.13.3's `ipaserver/plugins/hbactest.py` (SOURCE evidence; confirmed in the live lab, see
`docs/truth/access-truth-matrix.md`):

- **A missing user, host or service is evaluated anyway.** `hbactest` swallows `user_show`/`host_show`/`hbacsvc_show`
  failures and evaluates the bare name with no groups. A rule with `usercategory=all` (such as `allow_all`) still
  grants "access" to a user that does not exist. ipa-diagnose therefore checks existence first. For a missing user
  or host it reports `AUTHORIZATION: UNKNOWN` ("not evaluated"), never `PASS`.
- **Names are not canonicalized.** `hbactest` appends the IPA domain to a short host name, but passes any other
  spelling through unchanged, and passes the user name through unchanged. ipa-diagnose passes the canonical `uid` and
  `fqdn` returned by `user_show`/`host_show`, as SSSD on the host would.
- **The literal value `all`** means "skip this side" in `hbactest`. It is refused as a target.
- **Only enabled rules** are evaluated by default, through `hbacrule_find` with the server's search size limit. If
  that search is truncated (the message is propagated), the answer is `UNKNOWN`.
- **Rule errors:** in detail mode, a rule that fails to evaluate is listed under `error` and simply not counted.
  SSSD evaluates rules in order and stops with an error at such a rule, so the real outcome depends on rule order.
  Any error rule makes the answer `UNKNOWN`.
- **Membership semantics:** a rule side matches when its category is `all`, the object is listed by name, or one of
  the object's groups is listed. For users and hosts, "groups" means the direct **and** nested groups FreeIPA reports
  (`memberof_*` plus `memberofindirect_*`). For an HBAC service it means its direct service groups (HBAC service
  groups contain only services).
- **Trusted-domain users** (`name@ad.domain`, `DOMAIN\name`, `S-1-5-21-...` SIDs) take a separate path in `hbactest` (trust
  lookups, external groups). This version recognizes those forms and answers `UNKNOWN`. It prints FreeIPA's own
  command instead of guessing.

### How it explains (L2 relationship index)

The explanation uses a small, typed, per-question index (`src/ipa_diagnose/access/relations.py`):

- **Nodes:** `USER`, `GROUP`, `HOST`, `HOSTGROUP`, `HBAC_RULE`, `HBAC_SERVICE`, `HBAC_SERVICE_GROUP`,
  `TRUSTED_DOMAIN`.
- **Edges:** `MEMBER_OF` (direct), `MEMBER_OF_INDIRECT` (FreeIPA says nested, chain maybe unknown), and
  `RULE_APPLIES_TO` (with its side). Every edge carries the API call it came from.

Edges are deduplicated. The chain search is breadth-first and cycle-safe, limited to depth 50, 2000 nodes and
5000 edges. There is no graph database, no directory mirror, no persistent cache and no planner.

For an **ALLOW**, each matched rule is explained per side: `all`, `direct`, `group` (the object is a direct
member), or `nested_group` with the chain (for example `john -> backend -> devs`). For a **DENY**, the rules that
name this user are listed with the side each fails to cover, or "the rule is disabled". This is information, not
advice.

The explanation has its own status, and it **never changes the decision**:

- `COMPLETE`: every side of every rule is explained.
- `INCOMPLETE`: some memberships or rules could not be read, or bounds were reached. FreeIPA's decision stands.
- `CONTRADICTING`: the data read disagrees with FreeIPA. For example, FreeIPA matched a rule the data says cannot
  match, or a rule the data says matches was not matched. The decision stays FreeIPA's (an ALLOW stays ALLOW and a
  DENY stays DENY), and the report says a model gap or a concurrent change needs a look.

## Failure behaviour

Every failure is reported as a failure. None of them produces a PASS or a FAIL.

| Situation | AUTHORIZATION | Exit |
|---|---|---|
| no `/etc/ipa/default.conf`, no curl, no CA certificate, no Kerberos ticket, HTTP 401 | UNKNOWN | 3 |
| API timeout, network error, non-JSON or malformed answer, call budget used up | UNKNOWN | 3 |
| `hbactest` error (for example no permission), non-boolean verdict, inconsistent verdict | UNKNOWN | 3 |
| truncated rule list, rule evaluation errors | UNKNOWN | 3 |
| user or host does not exist, or the user is preserved (deleted) | UNKNOWN (not evaluated); VERIFY then points to `ipa user-show` / `ipa host-show`, never to `hbactest` | 1 (user: AUTHENTICATION FAIL) / 3 (host) |
| user or host cannot be read (timeout, no permission) | UNKNOWN (`OBJECT_UNREADABLE` names which) | 3 |
| HBAC service not defined | evaluated normally; only rules for all services can match | 0 / 1 |
| replay without a recorded answer for a call | UNKNOWN (never an empty success) | 3 |

## Privacy and privileges

- Only the three objects asked about, their own groups, and the rules needed for the answer are read and shown.
  On a deny, only rules that name this user are listed. Rules that only name the host or the service describe other
  people's access, so they are not listed. The names of the other rules FreeIPA evaluated are never shown, only
  their count.
- A rule that is read also lists its other members (other users, groups, hosts, hostgroups, services). None of those
  are kept or shown, in text, JSON or `--details`. Only the objects asked about and their own groups appear.
  FreeIPA rules that could not be evaluated are counted; they are named only when they name this user.
- Output is bounded. A side lists at most 20 matching groups plus "and N more", and group lists hold at most 200
  names plus a total count.
- Error messages name only the requested objects.
- The IPA API is called with `curl -q` (no `~/.curlrc`), HTTPS only, with a size limit.
- The identity used is the caller's own ticket. Any authenticated IPA user can normally read HBAC rules and run
  `hbactest`. An identity that cannot read an attribute (for example the account lock state) gets `UNKNOWN` for that
  part, never a guess.

## Support bundle

`ipa-diagnose bundle --access USER HOST SERVICE` adds this answer to a support bundle as `access.json`. It is
projected structurally, with user, host, group, hostgroup and rule names pseudonymized, and the leak self-test
applies as for every bundle member (see `docs/support-bundle.md`).

## Limitations (also printed with `--details`)

- No login is attempted. Without `--runtime`, the host's SSSD (and its offline cache), the PAM stack, the
  `access_provider` setting, the network path and the keytab are not checked. With `--runtime` (as root on HOST
  itself) they are checked read-only by client mode ([client-mode.md](client-mode.md)); a runtime result can make
  RUNTIME ACCESS `FAIL` or show CONTRADICTING evidence, never `PASS`, and never changes the HBAC decision.
- No credential is tested. Account lockout after failed logins (per-server counters) is not checked.
- Only HBAC is evaluated. Sudo rules, SELinux user maps and local `access.conf` are not.
- Trusted-domain users and ID views are not evaluated.
- Validated live only on the environments listed in `docs/truth/access-truth-matrix.md`.
