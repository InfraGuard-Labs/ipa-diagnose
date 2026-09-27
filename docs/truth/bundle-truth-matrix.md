# Support bundle truth matrix (Slice 2)

LIVE evidence for `ipa-diagnose bundle`. Claims about the bundle must come from here via
[claim-register.md](claim-register.md) (section "Slice 2").

- **Product code:** commit `0a5cf66` on `slice2/support-bundle` (recorded in the run's `env.txt` and every row).
- **Run:** https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36291228242 (workflow `live-freeipa-scenarios.yml`,
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

"Redacted" is empty in every row: the lab evidence contains no credential-shaped text, so nothing was redacted and
nothing was redacted wrongly (an earlier run showed two false positives on DNS URI record names; fixed).

## Rows

| Scenario | Verdict | Overall / completeness | Resolutions in the bundle | Pseudonymized | Redacted | Bundle bytes | Checks | Run |
|---|---|---|---|---|---|---|---|---|
| B0-fresh-install-file-procedure | PASS | DEGRADED / complete | proc.files.restore-expected-permissions OFFERED [LIVE_VERIFIED] | DOMAIN 1, HOST 1, INSTANCE 1, REALM 1, SUFFIX 1 | - | 19068 | 17/17 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36291228242 |
| B1-healthy-baseline | PASS | NOT_FULLY_VERIFIED / complete | - | DOMAIN 1, HOST 1, INSTANCE 1, REALM 1, SUFFIX 1 | - | 16540 | 16/16 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36291228242 |
| B2-dirsrv-down | PASS | CRITICAL / partial | proc.service.start-stopped-service OFFERED [BUILT_IN_VERIFIED, definitive] | DOMAIN 1, HOST 1, INSTANCE 1, REALM 1, SUFFIX 1, USER 1 | - | 15933 | 17/17 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36291228242 |
| B3-krb5kdc-down | PASS | CRITICAL / complete | proc.service.start-stopped-service OFFERED [BUILT_IN_VERIFIED, definitive] | DOMAIN 2, HOST 2, INSTANCE 1, REALM 1, SUFFIX 2, USER 1 | - | 19359 | 17/17 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36291228242 |
| B4-healthcheck-missing | PASS | UNKNOWN / insufficient | - | DOMAIN 1, HOST 1, INSTANCE 1, REALM 1, SUFFIX 1 | - | 5594 | 18/18 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36291228242 |
| B5-non-root | PASS | UNKNOWN / insufficient | - | DOMAIN 1, HOST 1, INSTANCE 1, REALM 1, SUFFIX 1 | - | 5443 | 16/16 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36291228242 |
| B6-output-safety-PASS | SKIP (existing file and symlink refused (exit 5), neither touched) | - / - | - | - | - | - | 0/0 | https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36291228242 |

## Timing (B7, healthy server, 3 runs each)

| Command | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| `ipa-diagnose --json` | 15.01 s | 16.16 s | 15.78 s |
| `ipa-diagnose bundle --preview` | 15.49 s | 15.77 s | 15.98 s |
| `ipa-diagnose bundle` | 15.93 s | 16.25 s | 15.97 s |

A bundle costs about the same as a diagnosis; runs that do not ask for a bundle are unchanged (nothing new is
collected). The KDC-stopped bundle (B3) took about 65 s, the time the existing collectors wait on the stopped KDC.

## Not live

| Claim area | Evidence |
|---|---|
| Hostile received bundles (traversal, links, bombs, duplicates, malformed JSON, schema) | SYNTHETIC: tests/bundle/test_archive.py |
| Secret shapes, unicode tricks, redaction before truncation, regex time bounds | SYNTHETIC: tests/bundle/test_sanitize.py |
| Canary fixture (planted credentials and identities in every replay file) | FIXTURE: tests/bundle/test_build.py, test_bundle_cli.py |
| Fail-closed self-test (redaction disabled -> nothing written) | SYNTHETIC: test_bundle_cli.py |
| Replication relationships after pseudonymization | FIXTURE: replication fixtures |
| RPM / wheel packaging | CI: release candidate 36291231569 (EL8/9/10, Fedora 43/44 lifecycle includes the bundle), Python matrix 36291234275 |
