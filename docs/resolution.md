# Resolutions: from diagnosis to a verified fix

For a small set of **mature, deterministic diagnoses**, ipa-diagnose goes past "what is wrong" and shows
how to fix it, in a fixed order:

```
ROOT CAUSE -> WHY -> CHECKED FOR YOU -> IMPACT -> FIX -> PREREQUISITES -> WHAT THIS CHANGES -> RISK -> ROLLBACK -> VERIFY
```

**ipa-diagnose never runs a fix.** Its own checks are *read-only* (listed under CHECKED FOR YOU) so you are
not told to run troubleshooting commands the tool could run itself. Every step under FIX is printed for you
to run, after you have read it. It does run `ipa-healthcheck`, and upstream FreeIPA's certmonger client used by
its certificate checks starts certmonger if it is stopped and not masked; the report says when that happened.

A diagnosis shown as a RELATED symptom of another problem never gets a fix of its own: fix the cause first (for
example, Directory Server stopped because the disk holding its database is full - starting it again is not the
fix).

## When a fix is shown - and when it is not

A fix is shown only when **all** of these hold, checked on this host at the time of the run:

1. the diagnosis is confident enough (each procedure states its minimum confidence);
2. the values the command needs (service, path, mode, owner, request id...) come from structured evidence
   and validate as safe values of their type - free text never reaches a command;
3. applicability is established: this is a FreeIPA server (the `freeipa-server` package is installed) and its
   version is known and in the procedure's range (4.9 up to, not including, 5.0);
4. the read-only checks ran and found **no contradicting evidence** (for example: the service is running
   now, the unit is masked, the file already has the expected mode, the certificate has already expired);
5. every prerequisite was checked and is met (for example: running as root).

Otherwise the report says **"No fix is shown"** and lists the reason, and only read-only guidance remains. (The
older, general action list - which can include state-changing commands written for v0.1.3 - is then not printed
in the console; it is still in the JSON `actions` list.) For some diagnoses ipa-diagnose deliberately has **no
deterministic fix** and says so (for example an already expired Directory Server certificate: recovering it is
a high-risk procedure that ipa-diagnose has not verified, so it points to the documented procedure instead).

## Procedures in this version

| Diagnosis | Fix (printed, never run) | Risk | Shown only if |
|---|---|---|---|
| A required IPA service is not running | `systemctl start <that unit>` only (not `ipactl start`, which stops **all** IPA services if one fails to start), with `systemctl stop <unit>` as rollback | MEDIUM | the unit exists, is loaded, is not masked, is still stopped, and (for non-IPA-managed units such as sssd) is not disabled. Not offered for named/named-pkcs11, whose unit name differs by platform |
| ipa-healthcheck reports a wrong owner, group or mode on an IPA file | a `chmod` that only **removes** permissions (for example `chmod o-r <file>`), or `chown -h` / `chgrp -h` to the IPA service account ipa-healthcheck expects; each with a rollback command, preceded by read-only **CONFIRM FIRST** commands (below) | LOW | the file is in an IPA/PKI/389-DS/Kerberos/DNS location and still has the reported value; it is reached only through the symlinks PKI itself creates, each leading to its fixed destination (or the freeipa-container `/data` mirror), and is the same component's file as the reported path (a PKI finding never leads to a Directory Server file); it has no second hard link; no two findings expect different values for it; the expected value is a single value; the change does not add permissions; both the current and the expected owner/group are IPA service accounts; for an owner/group change, it is not key material or a secret (keys, NSS key databases, KDC stash, custodia, password and PIN files, backups, SSSD configuration - matched case-insensitively and deliberately broadly) |
| Kerberos clock skew, with *this host's* clock measured out of sync | `chronyc makestep` (you accept the one-time clock jump first) | MEDIUM | the skew is corroborated on this host (its own kinit fails with a clock-skew error, or the KDC rejects clients for skew while this host's offset is at least 300 s); chronyd runs and is synchronized to a named source; at least one source is reachable; the offset measured now is at least 240 s and less than a day |
| Directory Server certificate **expiring** (lib389 DSCERTLE0001) | `getcert resubmit -i <request>` | MEDIUM | certmonger runs and tracks the certificate with the IPA CA using IPA's standard service profile (`caIPAserviceCert`); the request is MONITORING with no error; it expires within 30 days but has not expired; its post-save command restarts Directory Server |
| Directory Server certificate **already expired** | none - documented procedure linked | - | - |
| Kerberos reports skew but this host's clock is fine | none - the wrong clock may be elsewhere | - | - |

### Verification status

- **Required service not running** and **IPA file permission mismatch**: `LIVE_VERIFIED`. In the free
  GitHub-hosted live lab (FreeIPA 4.13.3 on Fedora 43, a disposable container) the printed commands were run
  verbatim and `ipa-diagnose verify` reported RESOLVED with the fix's own checks. Live lab details, and exactly
  which cases were applied, are in [docs/truth/truth-matrix.md](truth/truth-matrix.md).
- **Clock skew** and **expiring DS certificate**: `FIXTURE_ONLY` - tested against recorded evidence. A
  container shares the runner's wall clock (Linux time namespaces cannot offset it), so stepping a lab clock
  would step the CI host; a near-expiry DS certificate needs a short-lived certificate profile. Neither has a
  proven safe disposable design yet.
- No procedure is `BUILT_IN_VERIFIED`: that promotion is left to the maintainer.

Each fix carries a verification label. **"Not yet verified on a live FreeIPA server"** means the procedure
has been tested against recorded evidence only; **"Verified in a live lab on FreeIPA X / OS Y"** names exactly
where it was applied and verified. On any other FreeIPA version or OS the label says so.

## CONFIRM FIRST: the file between the check and your command

ipa-diagnose checks the file when it runs; you run the printed command later. Between the two, the file (or a
directory on its path) can change. So the file fix first prints read-only commands with the **exact** output
they must show, for example:

```
First confirm (read-only) that nothing changed since the checks above; if the output differs, do not run the fix - run ipa-diagnose again:
     readlink -f /var/lib/pki/pki-tomcat/conf/ca/CS.cfg   expected: /data/etc/pki/pki-tomcat/ca/CS.cfg
     stat -c %a:%U:%G:%h /etc/pki/pki-tomcat/ca/CS.cfg   expected: 664:pkiuser:pkiuser:1
```

If any expected value cannot be rendered exactly, no fix is shown. This narrows the window; it does not remove
it (nothing that prints a command for later can): run the commands right after confirming. `chown -h` and
`chgrp -h` never follow a symlink at the file itself; directories on the way are followed.

## AI explanations

When an AI provider is configured, it may reword WHY. It never produces the FIX section, and it is not asked at
all for a diagnosis whose fix was withheld or has no procedure. Its text is shown only if the filter finds **no
command in it** - not even the diagnosis's own read-only ones: no backticks or code blocks, no known program
name, no word followed by an option or an absolute path, no redirect, pipe, `$(`, `&&`, backslash-split word
or `//` path, no instruction to run something ("run X Y"), no letters outside ASCII (look-alikes); invisible characters and terminal escapes are removed
first, and the text checked is exactly the text shown. Otherwise the deterministic WHY is shown. This is a
filter, not a proof: a command written as plain words for a program it does not know can still get through, so
never run a command that appears only in AI text.

## When ipa-healthcheck gives no results

If ipa-healthcheck cannot run or does not finish (for example this server's own DNS is stopped, so the checks
hang), the report says plainly that this is not a healthy result, and ipa-diagnose reads the state of the IPA
systemd units itself (`systemctl is-active`, read-only) and lists any that are not active. No cause is claimed
from that list.

## Journal redaction

The journal line under CHECKED FOR YOU is redacted before it is shortened: `key=value` / `key: value` secrets
(password, userPassword, bind_password, rootpw, authtok, token, pin, secret...), password options (`-w`,
`--password`...), Authorization and Cookie headers, credentials in URLs, private-key blocks, known token shapes,
and common prose forms ("the password is X", "with password X"). Detection is pattern-based and cannot be
perfect.

## VERIFY

After running the fix, `sudo ipa-diagnose verify` re-runs the diagnosis **and** the fix's own checks with fresh
read-only evidence. For a diagnosis a fix was shown for, it reports RESOLVED only when the diagnosis is gone *and* those checks pass (a
diagnosis with no fix is RESOLVED when fresh evidence no longer shows it); if a check
fails it reports PARTIALLY_RESOLVED; if a check cannot run, UNABLE_TO_VERIFY (exit 4); if the fix now points
at something else than when it was shown (another file, another instance), CHANGED (exit 4) - never RESOLVED.

What verify trusts:

- **fresh evidence** (ipa-healthcheck, collectors, read-only checks run now);
- **the current procedure definition** shipped with ipa-diagnose;
- from the saved report (`/var/lib/ipa-diagnose/last_report.json` or `~/.cache/ipa-diagnose/`, root-only 0600),
  only a **minimal baseline**: which diagnoses were found, and for each fix shown, the procedure id, a digest of
  its exact definition, the typed values it was filled with, and a digest of the checks it produced.

Verify rebuilds the fix's checks from those, never from saved criteria, statuses, commands or risk. The saved
report cannot be used, and every earlier finding is UNABLE_TO_VERIFY, when: it is from another host; it came
from a replay but this run is live (or the reverse); its verification data is missing or malformed; the
diagnosis is one this version no longer produces; a fix was shown but its record is missing; the procedure
was removed or changed (for example after a package upgrade); the saved values are not valid for their type; a
fix record has no diagnosis; the file is not a saved report, is not owned by the user running ipa-diagnose, or
is reached through a symlink. A saved report that exists but cannot be read gives exit 4, never "nothing to
verify". While anything is left unconfirmed, verify keeps the old baseline. A plain `ipa-diagnose` run keeps a
fix record (and its diagnosis) until a verify confirms it: while the diagnosis is still reported, or - if the
diagnosis is gone - while the fix's own read-only check still fails. A record that can no longer be checked at
all, or whose check now passes, is dropped, so a later verify neither forgets an unapplied fix nor keeps
reporting a damaged one.

Limits: a report written by v0.1.3 (no `v2` data) is compared the v0.1.3 way (the diagnosis is gone ->
RESOLVED). The digests detect corruption, catalogue changes and moved records; they are not a signature -
someone with root who deliberately rewrites the file consistently can still mislead verify (they could equally
change the tool itself).

## JSON

The v1 JSON report is unchanged, including the legacy per-diagnosis `actions` list (general guidance written
for v0.1.3); the reviewed, gated fix is only in `v2.resolutions`. New data is under `"v2"` (with
`"report_schema_version": 2`):

```json
"v2": {"resolutions": [{
  "diagnosis_id": "healthcheck.service-not-running-dirsrv",
  "status": "OFFERED",                     // OFFERED | WITHHELD | NONE
  "procedure_id": "proc.service.start-stopped-service",
  "reasons": [],                           // why a fix is withheld / absent, or notes
  "checked": [{"label": "...", "check": "systemd.unit", "status": "OK", "result": "...", "command": "...", "source": "live"}],
  "confirm_first": [{"text": "...", "argv": ["stat", "-c", "%a:%U:%G:%h", "/etc/..."], "command": "...", "expected": "664:pkiuser:pkiuser:1"}],
  "steps": [{"id": "start-unit", "text": "...", "argv": ["systemctl", "start", "dirsrv@EXAMPLE-TEST.service"], "risk": "MEDIUM", "changes": ["service-start"], "expected": "..."}],
  "prerequisites": [{"text": "...", "state": "met"}],
  "what_changes": ["..."], "risk": "MEDIUM", "rollback": [{"text": "...", "argv": null, "command": null}],
  "verify": [{"text": "...", "check": "systemd.unit", "params": {"service": "dirsrv"}, "when": {...}}],
  "tier": "LIVE_VERIFIED", "definitive": false, "verification_label": "...", "applies_to": "FreeIPA server 4.9 or later"
}],
 "verify_baseline": {"schema": 1, "fixes": [{"diagnosis_id": "...", "procedure_id": "...", "procedure_digest": "...", "bindings": {...}, "criteria_digest": "..."}]}}
```

Use `steps[].argv` (an argument list) rather than parsing the display string; `command` is the same argv
shell-quoted. `checked[].source` is `live` (run on this host now) or `recorded` (from a `--replay` fixture).
`v2.resolutions[].verify` is for display; verify itself uses `verify_baseline`.

## How procedures are maintained

Procedures are data (`knowledge/procedures/*.yaml`), compiled and validated into
`src/ipa_diagnose/resolution/procedures.json` by `scripts/compile_knowledge.py`. The loader rejects unknown
fields, expressions in place of structured conditions, shell metacharacters or untyped values in commands, fix
and rollback programs outside a fixed allowlist (systemctl, chmod, chown, chgrp, chronyc, getcert), CONFIRM
FIRST programs other than `stat`/`readlink -f`, and steps labelled with less risk than what they change. A
procedure can only claim `BUILT_IN_VERIFIED` with an authoritative source, a version constraint, regression
tests, an independent review record and - for any step that changes state - a live-lab verification record. An
invalid catalogue disables all fixes (the report then behaves like v0.1.3, with one "procedure catalogue
rejected" entry in `collection_errors`) rather than loading part of it. Provenance values are checked too:
https source URLs, a real FreeIPA version range, dated named reviews, existing test files and, for a live
record, the URL of the CI run that applied and verified the fix.
