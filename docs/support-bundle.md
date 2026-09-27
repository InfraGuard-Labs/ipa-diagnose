# Support bundle

`ipa-diagnose bundle` creates one file you can review and then hand to someone
helping you troubleshoot FreeIPA / IdM. The file holds a fresh ipa-diagnose
diagnosis in structured form, with identities pseudonymized and credential-like
text removed. It is created only when you ask for it, it stays on your disk, and
ipa-diagnose never uploads it anywhere.

It is **not** a sosreport, a backup, a log or configuration dump, or a copy of
LDAP data. It records what one host reported at one time.

## Commands

```bash
sudo ipa-diagnose bundle --preview            # what would be included; writes nothing
sudo ipa-diagnose bundle                      # ./ipa-diagnose-bundle-<UTC time>.tar.gz
sudo ipa-diagnose bundle --output /var/tmp/   # a directory: default file name inside it
sudo ipa-diagnose bundle --output case-123.tar.gz
ipa-diagnose bundle validate case-123.tar.gz  # check a bundle without extracting it (no root needed)
ipa-diagnose bundle --replay tests/fixtures/replication/peer-unreachable --preview   # recorded evidence
```

Add `--json` to any of them for machine-readable output. Nothing is interactive.

| Exit code | Meaning |
|---|---|
| 0 | bundle created, preview shown, or bundle valid |
| 5 | no bundle created (leak self-test fired, output path refused, size limit), or the bundle is not valid |
| 2 | usage error |
| 70 | internal error; nothing was written |
| 130 | interrupted; nothing was left behind |

The exit code does not reflect the diagnosis. A bundle of a CRITICAL server
exits 0: the bundle was created, and its `overall_status` says CRITICAL.

The bundle runs the same collection and diagnosis as `ipa-diagnose`, including
the read-only checks behind resolutions. It never runs a fix. It never saves or
changes the baseline that `ipa-diagnose verify` uses. It never contacts an AI
provider (`--ai-provider` is refused).

## Output file

- Default name: `ipa-diagnose-bundle-<UTC time>.tar.gz`. The host name is never used in the file name.
- Created with mode `0600`. It is written to a temporary file in the same directory and hard-linked into place, so it appears complete or not at all. On filesystems without hard links it is created exclusively with `O_EXCL|O_NOFOLLOW` instead.
- An existing file or symlink at the path is never overwritten or followed; the command refuses with exit 5.
- A directory writable by every user without the sticky bit is refused, because another user could replace the file after it is written.
- Under `sudo` the file belongs to root. Copy it with sudo to share it.

## Contents

A gzip-compressed tar holding exactly these files in one directory,
`ipa-diagnose-bundle/`:

| File | Content |
|---|---|
| `README.txt` | what the bundle is and is not, and how to inspect it |
| `manifest.json` | format and schema version, ipa-diagnose version, creation time, LIVE/REPLAY, evidence tiers, counts, sanitization status, truncation, limits, SHA-256 of every member |
| `environment.json` | OS and FreeIPA, ipa-healthcheck and 389-DS versions of the diagnosed host |
| `report.json` | overall status, evidence completeness, diagnoses (confidence, evidence references, impact, limitations), undiagnosed findings, resolutions, service states, side effects |
| `healthcheck.json` | ipa-healthcheck results: problems in full (source, check, severity, key, message, keywords, whether a rule explained it, whether this build knows the check); successes by name only |
| `evidence.json` | the targeted evidence items ipa-diagnose collected (certmonger requests, replication agreements, keytab/bind check, journal matches, and so on), with the collector and the diagnoses that cite each item |
| `collection-errors.json` | each collector that failed: category (permission, timeout, not available, unparseable output, other), message, and what it leaves unverified |
| `topology.json` | replication agreements and RUV entries as this host reported them |
| `verification.json` | whether a verify baseline exists and which fixes await a verify (context only) |
| `redaction-report.json` | counts only: identifiers pseudonymized by class, values redacted by category, fields removed, text truncated |
| `SHA256SUMS` | SHA-256 of every other file, in `sha256sum -c` format |

Every JSON file repeats `source_mode`, so a single file taken out of the bundle
still says whether it is LIVE or REPLAY evidence.

The files are chosen for how useful they are to whoever helps you:
- Relationships are kept. The same host has the same pseudonym in every file.
- Each diagnosis points at the finding and evidence IDs it relies on.
- Undiagnosed and unknown future ipa-healthcheck checks remain visible, marked as such.

## What is never included

Credentials of any kind:
- passwords, including the Directory Manager password;
- private keys;
- keytab contents;
- Kerberos tickets and credential caches;
- API, bearer and cloud tokens;
- cookies and authorization headers;
- AI provider credentials.

Raw data, even when ipa-diagnose read it:
- environment variables and shell history;
- raw journals and raw tool output (`klist`/`chronyc` output, ticket lists);
- full LDAP entries and configuration files;
- certificate serial numbers;
- the local `--replay` path and your home directory path.

Fix commands. Resolutions keep their procedure ID, status, knowledge tier, risk,
prerequisites, checks and withholding reasons, but every step's command, every
rollback command and every "confirm first" command is left out.
- A recorded fix was evaluated for the diagnosed host only. It is never a fix for the machine of whoever reads the bundle.
- Read-only diagnostic suggestions from the packs (for example `ipa-replica-manage list <host>`, with placeholders) are kept.
- State-changing ones are left out.

The pseudonym mapping is never written anywhere, and AI explanations are never included.

The first defence is **not collecting** secret material at all:
- The Kerberos collectors list keytab entries (`klist -kte`: principal, key version, encryption type; never the keys) and ticket metadata, and the bundle keeps only principals, counts and key versions from them.
- The keytab bind check uses a throw-away credential cache that is never read into evidence.
- No collector reads private keys, password files or environment variables.

## Sanitization pipeline

```
COLLECT (the normal diagnosis; nothing new)
  -> STRUCTURE (fixed projections; raw output, commands and secret-named fields left out)
  -> REDACT -> PSEUDONYMIZE -> BOUND (truncate)
  -> LEAK SELF-TEST -> WRITE
```

Every string and every JSON key passes through the same steps.

1. **Clean.** Terminal escapes and control characters are removed. Format characters such as zero-width spaces and bidi overrides are deleted, so they cannot split a keyword. Text is NFKC-normalized, so full-width letters become plain ones.
2. **Redact.** Values that look like credentials are replaced with `[REDACTED:<category>]`. Categories:
   - PEM blocks (complete, or cut before END or after BEGIN) and private-key markers;
   - JWTs; AWS, OpenAI, Anthropic, GitHub, Slack and Google keys;
   - credentials in URLs, Authorization and Cookie headers, Bearer/Negotiate/Basic tokens;
   - `--password` style options and `ldapsearch -w`-style flags;
   - `password=` / `pw:` / `pin=` style assignments;
   - "the password is ..." prose;
   - keytab hex;
   - long random-looking tokens.

   Matching runs on a copy where common Cyrillic/Greek look-alike letters are folded.

   Fields whose name says "secret" (password, token, credential, cookie, authorization, and so on) are replaced with `[REMOVED]`.

   **Redaction always runs on the full text.** Truncation happens afterwards, so it cannot cut a secret marker in half and expose the rest. Text over 64 KiB is omitted entirely rather than cut and then scanned.
3. **Pseudonymize.** See below.
4. **Bound.** Fixed caps apply (see Limits). Truncated text ends with `[truncated]` and is counted in the manifest.

## Pseudonymization

| Class | Example | Found from |
|---|---|---|
| `HOST` | `HOST-001` | the diagnosed host (`HOST-001`; `environment.json` names it), replication peers, RUV URLs, principals' host part, any name in a known IPA domain, host-like fields, and other FQDNs with a common or private top-level domain |
| `DOMAIN` | `DOMAIN-001` | the host's DNS domain; e-mail domains |
| `REALM` | `REALM-001` | Kerberos principals; the uppercase IPA domain |
| `SUFFIX` | `SUFFIX-001` | the LDAP suffix `dc=...,dc=...` (also in its `\3D`/`\2C` escaped form) |
| `INSTANCE` | `INSTANCE-001` | Directory Server instance names (`dirsrv@X.service`, `slapd-X`) |
| `IP` | `IP-001` | IPv4 and IPv6 addresses (loopback and `0.0.0.0` are kept) |
| `USER`, `GROUP`, `HOSTGROUP`, `SERVICE`, `EMAIL` | `USER-001` | principals, `uid=`, `cn=...,cn=groups`, `cn=...,cn=hostgroups`, unknown service principal names, `/home/<name>`, user and group fields |

- Pseudonyms are sequential and **bundle-local**. They are assigned in a fixed discovery order, not derived from the real value (no hash, no salt), so they cannot be reversed by guessing. Two different names never share one.
- Two bundles of the same evidence number identifiers the same way. That reveals nothing about the real names, and no stable identity is carried across different evidence.
- If the input already contains text shaped like a pseudonym (a host literally named `HOST-002`), that number is skipped, so no assigned pseudonym can be confused with it. Such a name is left as written (it reveals nothing beyond a pseudonym-shaped label).

Relationships survive:
- `cn=meToipa02.example.test,cn=replica,cn=dc\3Dexample\2Cdc\3Dtest,...` becomes `cn=meToHOST-002,cn=replica,cn=SUFFIX-001,...`;
- `ldap/ipa01.example.test@EXAMPLE.TEST` becomes `ldap/HOST-001@REALM-001`;
- `_kerberos._udp.example.test` becomes `_kerberos._udp.DOMAIN-001`;
- `dirsrv@EXAMPLE-TEST.service` becomes `dirsrv@INSTANCE-001.service`.

Constants that carry technical meaning are kept:
- service principal types (`ldap`, `HTTP`, `host`, `krbtgt`, ...);
- system accounts and IPA built-ins (`root`, `dirsrv`, `pkiuser`, `admin`, `admins`, ...);
- `ipa-ca`, `localhost`, and public documentation domains (`freeipa.org`, `redhat.com`, ...);
- Python and Java module names.

## Leak self-test (fail closed)

Before anything is written, every file is scanned for:
- every real identifier that was pseudonymized, in any case;
- the credential patterns above;
- control, escape and format characters;
- the local replay and home paths;
- malformed JSON, UTF-8 or checksum lines.

If anything is found, **no bundle is written**:
- The command lists the file and category (never the matched text) and exits 5.
- The archive is only built in memory after the self-test passes, so nothing partial or sensitive is left on disk.

The two halves of the self-test are not equally independent:
- **Identities.** It searches every file for every real identifier found anywhere in the evidence. This is independent of the replacement step, so a name that was discovered but not replaced stops the bundle.
- **Credentials.** It uses the same detectors as redaction. It therefore catches text that skipped redaction (a pipeline failure), not a credential in a format the detectors do not know.

It cannot find a name that appears only in free text and matches no known identifier or pattern. Such a name stays as written.

## Integrity

`manifest.json` and `SHA256SUMS` carry the SHA-256 of every file. They detect
accidental change or damage. **They are not a signature**: anyone who edits the
bundle can recompute them, so a valid checksum does not prove who made the
bundle. The archive metadata is fixed:
- mode 0644;
- uid/gid 0 with empty owner names;
- the creation time as mtime;
- no file name and mtime 0 in the gzip header.

Nothing about the creating user, host or working directory is in it.

## Validating a received bundle

`ipa-diagnose bundle validate FILE` treats the file as hostile and **never
extracts it**. It refuses:
- a non-regular file, or more than 16 MiB compressed or 33 MiB decompressed (decompression is capped as it goes);
- trailing or concatenated data after the gzip stream;
- entries that are not plain regular files (symlinks, hard links, devices, directories), pax headers, unexpected, traversing or non-ASCII names, duplicates, and missing files;
- nested archives, invalid UTF-8, malformed JSON (duplicate keys and NaN/Infinity are refused), a different or future schema version, or a file claiming a different `source_mode` than the manifest;
- checksum mismatches;
- credential patterns or control characters in any file. It reports the category, never the text, and says not to share the bundle.

Unknown extra fields in the manifest are only a warning.

Validation checks structure and integrity. **Its content is still recorded
evidence from another system**, never a diagnosis of the machine you are on. Do
not run anything from it. `ipa-diagnose verify` never reads a bundle.

If you extract a bundle to read it, do so as an unprivileged user in an empty
directory: `tar -xzf FILE`, then `sha256sum -c SHA256SUMS` inside
`ipa-diagnose-bundle/`. To read a single file without extracting:
`tar -xzOf FILE ipa-diagnose-bundle/report.json`.

## LIVE and REPLAY

- A bundle built on a server is `LIVE`: the evidence was collected from that host when the bundle was created.
- A bundle built with `--replay DIR` is `REPLAY`: read from recorded fixture files, describing no live system.

The mode appears in the manifest, in every JSON file and in the README, and the
fixture path is never included. Each resolution also says what it was evaluated
against (`evaluated_against`). Its knowledge tier (FIXTURE_ONLY, LIVE_VERIFIED,
BUILT_IN_VERIFIED) is explained in [resolution.md](resolution.md).

## Limits

| Limit | Value |
|---|---|
| ipa-healthcheck results | 1000; problems are kept first, then successes |
| evidence items | 500; items cited by a diagnosis first |
| collection errors / diagnoses / undiagnosed findings | 200 / 200 / 500 |
| text | 500 characters; prose fields (why, impact, ...) 2000 |
| text processed at all | 64 KiB per value (longer is omitted) |
| JSON structure | 60 keys per object, 200 items per list, depth 8 |
| each file / whole bundle (uncompressed) | 8 MiB / 32 MiB (over the limit: no bundle, exit 5) |
| sanitizing time | 300 seconds (evidence with tens of thousands of distinct names can reach it: no bundle, exit 5) |

When anything is shortened, `manifest.json` says `"content_complete": false`
and counts what was truncated or dropped (by kind, not by field). Collection time is the normal
diagnosis time: the bundle adds no collectors or network access.

## Known limitations

- Detection is **pattern-based and cannot be perfect**. Credentials in an unfamiliar format, a secret split across two separate fields, names that match no known identifier or pattern, and look-alike characters beyond the folded Cyrillic/Greek set can remain.
- Redaction errs towards removing too much: an unquoted value after `password=` or `password is` is removed to the end of its line, so nearby context can be lost.
- Validating a maximum-size bundle can take a few minutes, because every file is scanned for credential patterns.
- A bundle still contains **operational detail**: unit and service names, versions, file paths and modes, error text, timestamps (certmonger request IDs even reveal when the server was installed), certificate expiry dates, exact disk sizes, and the shape of the topology (how many replicas, which agreements fail). Several bundles from one server can be recognised as coming from the same server. Review it before sharing.
- The pseudonym mapping is not kept anywhere, so answers that name a pseudonym (`HOST-002`) must be translated back by the sender. `HOST-001` is the diagnosed host (only if the evidence itself contains the text `HOST-001` does it get the next free number; `environment.json` always names it); replicas can be matched through their replica IDs (`replica_id` in `topology.json`), which are kept.
- **Single-host view.** `topology.json` shows what the diagnosed host reported. It does not compare hosts or say which server is at fault.
- No encryption or signing. Share bundles over a channel you trust.
