# Status words and exit codes, per command

One vocabulary across the product. **Interpret exit codes per command.** For `diagnose`, `client` and `replication`,
non-zero means a problem, incomplete evidence or pending verification. For `access`, exit 1 can simply mean FreeIPA
policy does not authorize the requested access; that is an answer, not necessarily an operational failure. "Could not
check" is never reported as healthy, passed or resolved, by any command.

## Exit codes

| Code | `ipa-diagnose` (diagnose) / `ai-preview` | `verify` | `access` | `client` | `client --verify` | `replication` | `replication --verify` | `bundle` |
|---|---|---|---|---|---|---|---|---|
| 0 | HEALTHY | everything found before is RESOLVED, fresh evidence complete, nothing unexplained | FreeIPA policy authorizes it (login not tested) | HEALTHY (warnings may be listed) | everything found last time RESOLVED, nothing new | every investigated agreement green in both directions | RESOLVED | done (the diagnosis inside may still be CRITICAL) |
| 1 | DEGRADED | a problem is still there (STILL_PRESENT, PARTIALLY_RESOLVED or new), same severity meaning as diagnose | not authorized by policy, or the account cannot authenticate | a problem was found | still present, partial or new | a problem was found | still present or new | - |
| 2 | CRITICAL | as 1 | usage error | usage error | usage error | usage error | usage error | usage error |
| 3 | UNKNOWN (no base evidence) | the fresh run is UNKNOWN (with or without a baseline) | UNKNOWN: no trustworthy policy decision | - | - | - | **PENDING** (time-bounded, never 0) | - |
| 4 | NOT_FULLY_VERIFIED | UNABLE_TO_VERIFY or CHANGED, fresh evidence incomplete, or everything resolved but the fresh run is NOT_FULLY_VERIFIED (an unexplained finding remains) | authorized, but the account state could not be read | nothing wrong found, not everything could be checked | UNABLE_TO_VERIFY or CHANGED | nothing failing found, not everything could be checked (or not an IPA server) | UNABLE_TO_VERIFY or CHANGED | - |
| 5 | - | - | only `--runtime`: authorized by policy, but a runtime check on this host shows the login would fail | - | - | - | - | the bundle was not created (leak self-test, output path, size limit) or is not valid |

For `diagnose` and `verify` a usage error is 2 as well; there it is distinguishable from CRITICAL only by the
message on stderr, which is why scripts should read `--json`. Every command also uses **70** (internal error, no
answer produced), **130** (interrupted) and **141** (output pipe closed). Warnings go to stderr, so
`--json` on stdout is always pure JSON. Every command's `--help` states its codes.

## Status words

| Word | Where | Meaning |
|---|---|---|
| HEALTHY | diagnose, client, replication | every expected piece of evidence was collected and nothing is wrong or unexplained |
| HEALTHY_WITH_WARNINGS | client, replication (JSON `status`) | healthy, with warnings listed (exit 0) |
| DEGRADED / CRITICAL | diagnose | a supported problem, by severity |
| PROBLEM_FOUND | client, replication (JSON `status`) | a failing cause, an undiagnosed failure or contradicting evidence (exit 1) |
| UNKNOWN | diagnose (overall), access (a state), client/replication steps | could not be established; never a guess |
| NOT_FULLY_VERIFIED | diagnose, client, replication | no supported cause found, but something relevant could not be checked or is unexplained |
| NOT_AN_IPA_SERVER | replication | stops honestly on a host that is not an IPA server (exit 4) |
| PASS / FAIL | access AUTHORIZATION; access and client AUTHENTICATION / RUNTIME ACCESS (FAIL only) | AUTHORIZATION PASS/FAIL comes only from FreeIPA's `hbactest`. AUTHENTICATION and RUNTIME ACCESS are never PASS: no credential or login is tested |
| NOT_VERIFIED | access, client, replication | not tested (for example RUNTIME ACCESS with no runtime failure shown, a reverse replication direction without a ticket) |
| PRIMARY | every surface | the deepest established cause (diagnose prints PRIMARY PROBLEM) |
| RELATED | every surface | a symptom explained by another diagnosis; never gets its own fix |
| INDEPENDENT | every surface | another established cause on an unrelated path (diagnose: SECONDARY INDEPENDENT) |
| UNDIAGNOSED | diagnose (undiagnosed findings), client, replication | a failure that nothing established explains; listed with read-only next steps, no cause claimed |
| CONTRADICTING | access (explanation), client, replication | evidence disagrees (for example HBAC allows and the host refuses); every fix is withheld where it matters |
| RESOLVED | every verify | the original condition is gone in fresh evidence and the fix's own checks pass |
| PARTIALLY_RESOLVED | every verify | still detected in part, or a fix check fails |
| STILL_PRESENT | every verify | fresh evidence still shows it |
| CHANGED | every verify | the fix now points at something else, or the failure changed form: never RESOLVED |
| UNABLE_TO_VERIFY | every verify | fresh evidence for it could not be collected, or the saved result cannot be trusted (another host, replay vs live, edited, other inputs) |
| PENDING | replication --verify | the failure is gone but no fresh successful replication session has happened yet; re-check time given; becomes STILL_PRESENT or UNABLE_TO_VERIFY after 10 minutes |

## Subjects

Every answer names what it is about, and a fix is printed only for a cause on the host it runs on:

- `ipa-diagnose` / `verify` / `bundle`: **this server** (a single-host view, like ipa-healthcheck).
- `access USER HOST SERVICE`: a **user**, a **host** and a PAM/HBAC **service**, asked of FreeIPA; with `--runtime`, the
  runtime side is checked on **this host**, which must be HOST.
- `client`: **this client**, optionally one **user** and one **service**.
- `replication`: **this server** and each **peer**, per **suffix** (domain and `o=ipaca` separately) and per
  **direction** (`supplier > consumer`, observed from this server); a peer-side cause gets a handoff
  (`On <peer> run: ...`), never a command.

## Provenance and privacy labels

- Every answer says whether its evidence is **LIVE** (collected now) or **REPLAY** (recorded fixtures, `--replay`,
  development and tests). A fix shown from replay evidence says not to run it here (server, client, access); replication
  mode shows none. A saved result from replay is never compared with a live run.
- `ai-preview` shows exactly what an AI provider would receive after redaction; `--no-ai` (the default when no
  provider is configured) contacts none.
- A support bundle is pseudonymized and redacted, **not** secret-free: review it before sharing.
