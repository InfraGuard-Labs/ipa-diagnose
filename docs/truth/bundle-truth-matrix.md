# Support bundle truth matrix (Slice 2)

LIVE evidence for `ipa-diagnose bundle`. Claims about the bundle must come from here via
[claim-register.md](claim-register.md) (section "Slice 2").

- **Product code:** commit `01f181c` on `slice2/support-bundle` (recorded in the run's `env.txt` and every row).
- **Run:** https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36454126285 (workflow `live-freeipa-scenarios.yml`,
  `suite=bundle`). Artifact `live-bundle-evidence-fedora-43` holds every bundle, preview, validation and the raw rows.
- **Environment:** free GitHub-hosted runner, disposable `freeipa/freeipa-server:fedora-43` container, FreeIPA
  4.13.3-2.fc43, ipa-healthcheck 0.19-2.fc43, single server with integrated DNS and CA. No other OS or version was
  tested live.
- **Canaries (fake values only):** fake passwords, an SSH private key, AWS and AI keys in `~/.aws`, shell history and
  a note file; fake OpenAI/Anthropic/AWS keys and a configured AI provider in the bundle command's environment; an IPA
  user whose principal sits in root's ticket cache. Every bundle was searched for these, the lab password, and the
  lab host name, domain, realm, Directory Server instance and container IP.

Every bundle row checks, by `scripts/lab_bundle.py`: the exact member set; checksums (SHA256SUMS and manifest);
anonymous archive metadata; LIVE labels in every file; bundle status = diagnosis status; the diagnosis after the
bundle equals the one before; IPA unit states, verify baseline and files unchanged; mode 0600 and unreadable by
another user; no forbidden string; no fix command; preview wrote nothing; `bundle validate` (unprivileged) VALID; plus
the scenario's own expectations.

"Redacted" is empty in rows B0-B5: the lab evidence contains no credential-shaped text, so nothing was redacted and
nothing was redacted wrongly (an earlier run showed two false positives on DNS URI record names; fixed).

## Rows

| Scenario | Verdict | Overall / completeness | Resolutions in the bundle | Pseudonymized | Redacted | Bundle bytes | Checks | Run |
|---|---|---|---|---|---|---|---|---|
| B0-fresh-install-file-procedure | PASS | DEGRADED / complete | proc.files.restore-expected-permissions OFFERED [LIVE_VERIFIED] | DOMAIN 1, HOST 1, INSTANCE 1, REALM 1, SUFFIX 1 | - | 19109 | 17/17 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36454126285 |
| B1-healthy-baseline | PASS | NOT_FULLY_VERIFIED / complete | - | DOMAIN 1, HOST 1, INSTANCE 1, REALM 1, SUFFIX 1 | - | 16567 | 16/16 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36454126285 |
| B2-dirsrv-down | PASS | CRITICAL / partial | proc.service.start-stopped-service OFFERED [BUILT_IN_VERIFIED, definitive] | DOMAIN 1, HOST 1, INSTANCE 1, REALM 1, SUFFIX 1, USER 1 | - | 15882 | 17/17 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36454126285 |
| B3-krb5kdc-down | PASS | CRITICAL / complete | proc.service.start-stopped-service OFFERED [BUILT_IN_VERIFIED, definitive] | DOMAIN 1, HOST 1, INSTANCE 1, REALM 1, SUFFIX 1, USER 1 | - | 19309 | 17/17 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36454126285 |
| B4-healthcheck-missing | PASS | UNKNOWN / insufficient | - | DOMAIN 1, HOST 1, INSTANCE 1, REALM 1, SUFFIX 1 | - | 5602 | 18/18 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36454126285 |
| B5-non-root | PASS | UNKNOWN / insufficient | - | DOMAIN 1, HOST 1, INSTANCE 1, REALM 1, SUFFIX 1 | - | 5454 | 16/16 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36454126285 |
| B6-output-safety-PASS | SKIP (existing file and symlink refused (exit 5), neither touched) | - / - | - | - | - | - | 0/0 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36454126285 |
| B8-ca-journal | PASS | CRITICAL / complete | proc.service.start-stopped-service OFFERED [BUILT_IN_VERIFIED, definitive] | DOMAIN 1, HOST 2, INSTANCE 1, REALM 1, SUFFIX 1, USER 2 | certificate_serial 3, password_flag 2, tomcat_property_secret 2 | 25043 | 21/21 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36454126285 |

## CA journal (B8)

The CA runs as `pki-tomcatd@pki-tomcat.service` (FreeIPA's own `ipaplatform` mapping of `pki_tomcatd`). In this run
`journalctl -u pki-tomcatd` (the collector's old query) returned 0 lines and `-u pki-tomcatd@pki-tomcat.service`
176 (`docs/screenshots/slice2/live-b8-units.txt`). A fake attribute `zqLabSecret` on the AJP connector made Tomcat
echo its value in the journal (`live-b8-digester.txt`, value masked). With the CA stopped, the bundle carried 156 CA
journal lines, the host pseudonymized and the echoed value redacted
(`failed to set property [zqLabSecret] to [[REDACTED:tomcat_property_secret]]`); the canary appears nowhere.
The `password_flag` count comes from the engine's own advice text, which names `ldapsearch` on the same line
(deliberate over-redaction); `certificate_serial` from ipa-healthcheck's Dogtag connectivity messages.

## Timing (B7, healthy server, 3 runs each)

| Command | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| `ipa-diagnose --json` | 12.09 s | 13.66 s | 12.24 s |
| `ipa-diagnose bundle --preview` | 12.96 s | 11.38 s | 11.94 s |
| `ipa-diagnose bundle` | 13.37 s | 12.15 s | 12.20 s |

A bundle costs about the same as a diagnosis; runs that do not ask for a bundle are unchanged (nothing new is
collected). The KDC-stopped bundle (B3) took about 68 s, the time the existing collectors wait on the stopped KDC.

## Not live

| Claim area | Evidence |
|---|---|
| Hostile received bundles (traversal, links, bombs, duplicates, malformed JSON, schema) | SYNTHETIC: tests/bundle/test_archive.py |
| Secret shapes, unicode tricks, redaction before truncation, regex time bounds | SYNTHETIC: tests/bundle/test_sanitize.py |
| Canary fixture (planted credentials and identities in every replay file) | FIXTURE: tests/bundle/test_build.py, test_bundle_cli.py |
| Fail-closed self-test (redaction disabled -> nothing written) | SYNTHETIC: test_bundle_cli.py |
| Replication relationships after pseudonymization | FIXTURE: replication fixtures |
| RPM / wheel packaging | CI: release candidate 36454102379 (EL8/9/10, Fedora 43/44 lifecycle includes the bundle), Python matrix 36454116481 (Python 3.9-3.14) |

## Harness note

Live runs from commit `465b09f` up to `11fa82a` showed a green job while B3 wrote no bundle. The leak self-test
refused it: an ipa-healthcheck traceback quoting `api.env.host` was taken for a host, and the generic word `api`
became an identifier. That run failed closed and nothing leaked, but the harness wrote no result row for a missing
bundle, so the gap was silent. Since `38bdb0d` a missing bundle is a FAIL row, and the job fails when any expected
scenario has no row. The rows above come from the first run after both fixes.

## Freeze campaign re-run (final product code)

Bundle scenarios B0-B8 re-run on the final freeze product code (b58f3d6), run [36742907611](https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36742907611) (bundle job), FreeIPA 4.13.4 / Fedora 43: **8/8 PASS** (B0-B5, B6 output safety, B8 CA journal); no planted canary or lab identifier reached a bundle; timing: diagnose 12.8-13.8 s, preview 12.8-14.1 s, bundle 13.8-13.9 s. Details: [freeze-audit.md](freeze-audit.md).
