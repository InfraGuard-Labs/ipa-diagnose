# Resolutions: from diagnosis to a verified fix

For a small set of **mature, deterministic diagnoses**, ipa-diagnose goes past "what is wrong" and shows
how to fix it, in a fixed order:

```
ROOT CAUSE -> WHY -> CHECKED FOR YOU -> IMPACT -> FIX -> PREREQUISITES -> WHAT THIS CHANGES -> RISK -> ROLLBACK -> VERIFY
```

**ipa-diagnose never runs a fix.** It runs only *read-only* checks (listed under CHECKED FOR YOU) so you are
not told to run troubleshooting commands the tool could run itself. Every step under FIX is printed for you
to run, after you have read it.

## When a fix is shown - and when it is not

A fix is shown only when **all** of these hold, checked on this host at the time of the run:

1. the diagnosis is confident enough (each procedure states its minimum confidence);
2. the values the command needs (service, path, mode, owner, request id...) come from structured evidence
   and validate as safe values of their type - free text never reaches a command;
3. applicability is established: this is a FreeIPA server (the `freeipa-server` package is installed) and its version is known and in the procedure's range (4.9 up to, not including, 5.0);
4. the read-only checks ran and found **no contradicting evidence** (for example: the service is running
   now, the unit is masked, the file already has the expected mode, the certificate has already expired);
5. every prerequisite was checked and is met (for example: running as root).

Otherwise the report says **"No fix is shown"** and lists the reason, and only read-only guidance remains. (The older, general action list - which can include state-changing commands written for v0.1.3 - is then not printed in the console; it is still in the JSON `actions` list.)
For some diagnoses ipa-diagnose deliberately has **no deterministic fix** and says so (for example an already
expired Directory Server certificate: recovering it is a high-risk procedure that ipa-diagnose has not
verified, so it points to the documented procedure instead of inventing one).

## Procedures in this version

| Diagnosis | Fix (printed, never run) | Risk | Shown only if |
|---|---|---|---|
| A required IPA service is not running | `systemctl start <that unit>` only (not `ipactl start`, which stops **all** IPA services if one fails to start), with `systemctl stop <unit>` as rollback | MEDIUM | the unit exists, is loaded, is not masked, is still stopped, and (for non-IPA-managed units such as sssd) is not disabled. Not offered for named/named-pkcs11, whose unit name differs by platform |
| ipa-healthcheck reports a wrong owner, group or mode on an IPA file | a `chmod` that only **removes** permissions (for example `chmod o-r <file>`), or `chown -h` / `chgrp -h` to the IPA service account ipa-healthcheck expects; each with a rollback command | LOW | the file is in an IPA/PKI/389-DS/Kerberos/DNS location, still has the reported value, is reached only through the symlinks PKI itself creates, each leading to its fixed destination (or the freeipa-container `/data` mirror), is the same component's file as the reported path (a PKI finding never leads to a Directory Server file), has no second hard link, no two findings expect different values for it, the expected value is a single value, the change does not add permissions, both the current and the expected owner/group are IPA service accounts, and it is not key material (keys, NSS key databases, KDC stash, custodia and password files) |
| Kerberos clock skew, with *this host's* clock measured out of sync | `chronyc makestep` (you accept the one-time clock jump first) | MEDIUM | chronyd runs and is synchronized to a named source, at least one source is reachable, this host's offset is at least 240 s (Kerberos tolerates 300 s, so a smaller local offset cannot explain the error) and less than a day |
| Directory Server certificate **expiring** (lib389 DSCERTLE0001) | `getcert resubmit -i <request>` | MEDIUM | certmonger runs and tracks the certificate with the IPA CA, the request is MONITORING with no error, it expires within 30 days but has not expired, and its post-save command restarts Directory Server |
| Directory Server certificate **already expired** | none - documented procedure linked | - | - |
| Kerberos reports skew but this host's clock is fine | none - the wrong clock may be elsewhere | - | - |

**Verification status in this version:** *required service not running* and *IPA file permission mismatch* are
`LIVE_VERIFIED`: in the free GitHub-hosted live lab (FreeIPA 4.13.3 on Fedora 43) the printed commands were run
verbatim and `ipa-diagnose verify` reported RESOLVED with the fix's own checks (dirsrv and krb5kdc started; the real
CS.cfg mode quirk fixed through the container's `/data` layout; a masked certmonger correctly withheld). *Clock
skew* and *expiring DS certificate* are `FIXTURE_ONLY` (tested against recorded evidence; they cannot be
reproduced safely in the container lab). No procedure is `BUILT_IN_VERIFIED` yet: that promotion is left to the
maintainer.

The journal line shown under CHECKED FOR YOU is redacted (`key=value`/`key: value` secrets, password options,
Authorization/Cookie headers, tokens) before it is shortened; a secret written as plain prose ("the password is
...") is not recognised.

Each fix carries a verification label. **"Not yet verified on a live FreeIPA server"** means the procedure
has been tested against recorded evidence only; **"Verified in a live lab on FreeIPA X / OS Y"** names exactly
where it was applied and verified. Outside those versions/OSes the label says so.

An AI explanation (when a provider is configured) can never bring a command back: it is shown only if every
command-shaped text it contains (from a broad list of programs, anywhere in the text, with any path prefix) is
one of the diagnosis's read-only (SAFE) commands, word for word. This is a filter, not a proof: the printed
FIX section never comes from AI text.

## VERIFY

After running the fix, `sudo ipa-diagnose verify` re-runs the diagnosis **and** the fix's own criteria with
fresh read-only checks (for example "`/var/lib/pki/pki-tomcat/conf/ca/CS.cfg` has mode 0660"). It reports
RESOLVED only when the diagnosis is gone *and* those checks pass; if a check fails it reports
PARTIALLY_RESOLVED, and if a check cannot run it reports UNABLE_TO_VERIFY (exit 4) - never RESOLVED.

The criteria are read back from the saved report (`/var/lib/ipa-diagnose/last_report.json`, root-only, mode
0600) and are run only if they have the form of the catalogue procedure's own criteria (same checks, fields and operators,
filled-in values of the declared type); anything else gives
UNABLE_TO_VERIFY. The saved report is otherwise trusted as ipa-diagnose's own earlier output. With `--replay`,
verify says that its fresh side is recorded evidence and nothing was checked on the host.

## JSON

The v1 JSON report is unchanged, including the legacy per-diagnosis `actions` list (general guidance written for v0.1.3); the reviewed, gated fix is only in `v2.resolutions`. New data is under `"v2"` (with `"report_schema_version": 2`):

```json
"v2": {"resolutions": [{
  "diagnosis_id": "healthcheck.service-not-running-dirsrv",
  "status": "OFFERED",                     // OFFERED | WITHHELD | NONE
  "procedure_id": "proc.service.start-stopped-service",
  "reasons": [],                           // why a fix is withheld / absent, or notes
  "checked": [{"label": "...", "check": "systemd.unit", "status": "OK", "result": "...", "command": "...", "source": "live"}],
  "steps": [{"id": "start-unit", "text": "...", "argv": ["systemctl", "start", "dirsrv@EXAMPLE-TEST.service"], "risk": "MEDIUM", "changes": ["service-start"], "expected": "..."}],
  "prerequisites": [{"text": "...", "state": "met"}],
  "what_changes": ["..."], "risk": "MEDIUM", "rollback": [{"text": "...", "argv": null, "command": null}],
  "verify": [{"text": "...", "check": "systemd.unit", "params": {"service": "dirsrv"}, "when": {...}}],
  "tier": "FIXTURE_ONLY", "definitive": false, "verification_label": "...", "applies_to": "FreeIPA server 4.9 or later"
}]}
```

Use `steps[].argv` (an argument list) rather than parsing the display string; `command` is the same argv shell-quoted. `checked[].source` is `live` (run on this host now) or `recorded` (from a `--replay` fixture).

## How procedures are maintained

Procedures are data (`knowledge/procedures/*.yaml`), compiled and validated into
`src/ipa_diagnose/resolution/procedures.json` by `scripts/compile_knowledge.py`. The loader rejects unknown
fields, expressions in place of structured conditions, shell metacharacters or untyped values in commands, and
steps labelled with less risk than what they change. A procedure can only claim `BUILT_IN_VERIFIED` with an
authoritative source, a version constraint, regression tests, an independent review record and - for any step
that changes state - a live-lab verification record. An invalid catalogue disables all fixes (the report then
behaves like v0.1.3, with one "procedure catalogue rejected" entry in `collection_errors`) rather than loading
part of it. Provenance values are checked too: https source URLs, a real FreeIPA version range, dated named
reviews, existing test files and, for a live record, the URL of the CI run that applied and verified the fix.
