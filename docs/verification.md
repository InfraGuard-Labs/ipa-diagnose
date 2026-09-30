# Verification

`ipa-diagnose` doesn't stop at "try this fix" - `sudo ipa-diagnose verify`
tells you whether it actually worked, based on freshly re-collected
evidence and a full re-run of the diagnostic engine, never on whether a
remediation command happened to exit `0`.

That distinction is not theoretical: Red Hat Bugzilla 1441262 documents
`ipa group-del` returning "Insufficient access" while *still deleting the
group* - an error message (or, symmetrically, a clean exit code) is not
reliable proof of what actually happened. Several remediation paths this
tool recommends (a cert renewal, an NSS DB fix, a service restart) also
require a follow-up step - like a service restart to resync in-memory
state - that's easy to skip and would otherwise look like "the fix didn't
work" or, worse, silently look fine.

## How it works (`verify.py`)

1. The main `ipa-diagnose` run persists its `DiagnosisReport` as JSON to a
   small state file (`/var/lib/ipa-diagnose/last_report.json` if writable,
   else `~/.cache/ipa-diagnose/last_report.json`; override with
   `IPA_DIAGNOSE_STATE_DIR`).
2. `verify` re-collects evidence the same way the original run did (live, or
   the same `--replay` fixture) and re-runs the full engine - not a
   re-check of just the one thing that seemed broken.
3. `compare()` diffs the previous diagnoses against the new ones by
   `diagnosis_id` (`pack_id.rule_id`), producing one of:

| Outcome | Meaning |
|---|---|
| `RESOLVED` | The condition that triggered this diagnosis is no longer present in fresh evidence. |
| `STILL_PRESENT` | Fresh evidence still shows the same condition. |
| `PARTIALLY_RESOLVED` | Still detected, but no longer a primary problem, or no longer confidently diagnosed - related symptoms may remain. |
| `UNABLE_TO_VERIFY` | Fresh evidence for the relevant pack couldn't be collected this run (e.g. a collector failed), or the saved result cannot be trusted - reported honestly rather than guessed. |
| `CHANGED` | The fix shown last time now points at something else (another file, another instance), or its saved record was altered - never `RESOLVED` (exit 4). |

A genuinely new condition that wasn't present in the previous run is
reported separately, not folded into the old diagnosis's outcome. For a
diagnosis a fix was shown for, `RESOLVED` also needs the fix's own read-only
checks to pass with fresh evidence ([resolution.md](resolution.md#verify)).

Real captures from the live lab, `verify` after the printed fix (RESOLVED) and
`verify` with the problem left in place (STILL_PRESENT), are in
[screenshots/1.0-candidate/](screenshots/1.0-candidate/index.md).

## Client `--verify`

`ipa-diagnose client --verify` re-runs every client check now (same user and service as last time unless given) and
reports, per earlier diagnosis, RESOLVED (its symptom check passes again and any fix criteria pass), STILL_PRESENT,
PARTIALLY_RESOLVED, CHANGED or UNABLE_TO_VERIFY; a check that cannot run is never counted as resolved, and an edited
state file or other inputs give UNABLE_TO_VERIFY. Details: [client-mode.md](client-mode.md#verify-l6).

## Replication `--verify`

`ipa-diagnose replication --verify` holds a replication incident to a stricter standard than "the command
succeeded": each earlier failing agreement (identified by suffix, supplier and consumer) must report a successful
session that ENDED AFTER the saved result, with no update in progress, and the cause that explained it must no
longer be found. It answers RESOLVED, STILL_PRESENT, CHANGED, PARTIALLY_RESOLVED, UNABLE_TO_VERIFY or **PENDING**
(exit 3, never 0): the failure is gone but no fresh successful session has happened yet, or the agreement is busy,
backing off or has had no session. PENDING has a recheck time and a 10-minute bound from its first answer, then
becomes STILL_PRESENT or UNABLE_TO_VERIFY. Exact RUV equality is not required. A direction that cannot be observed
from this server is listed as not verified, never as resolved. Details:
[replication-mode.md](replication-mode.md#verification-and-pending).

## What this does not do

- It does not know a remediation was even attempted - `verify` is a
  stand-alone re-diagnosis, not tied to any specific action you ran. This is
  intentional: it means `verify` gives you the same honest answer whether
  you fixed the problem, fixed the wrong thing, or did nothing.
- Cross-host convergence (e.g. full RUV convergence across every replica) is
  outside what a single-host tool can fully confirm - where a pack's own
  verification is inherently partial for this reason, its `limitations`
  field says so (see [docs/limitations.md](limitations.md)).


## Exit codes and evidence completeness

`verify` prints `Evidence for this check: COMPLETE` when the fresh evidence was
complete, or the `Evidence: PARTIAL / INSUFFICIENT` block otherwise, so a
`RESOLVED` line is never shown without that context. `RESOLVED` means "the
condition is no longer reported by fresh, complete evidence".

| verify exit | Meaning |
|---|---|
| `0` | Everything previously found is `RESOLVED` and the fresh evidence is complete. |
| `1` / `2` | A problem still exists (`STILL_PRESENT` / `PARTIALLY_RESOLVED` / a new condition); same severity meaning as `diagnose`. |
| `3` | No baseline to compare against and the fresh run is `UNKNOWN`. |
| `4` | Could not confirm: some previous problem was `UNABLE_TO_VERIFY`, or the fresh evidence is incomplete. |

An incomplete run (for example `ipa-healthcheck` unavailable) never overwrites
the saved baseline that `verify` compares against.

## Undiagnosed findings and `verify` (0.1.3)

`verify` exits `0` only when everything previously found is resolved, evidence is complete **and** no failed
ipa-healthcheck finding is left unexplained. If the old problem is gone but some other finding no rule explains
remains, `verify` prints the resolved items and then a note that the overall status is `NOT_FULLY_VERIFIED`
(exit `4`); run `sudo ipa-diagnose` to list those findings.
