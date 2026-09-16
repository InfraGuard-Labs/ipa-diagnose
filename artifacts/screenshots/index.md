# Screenshot index

All screenshots are real `rich`-recorded terminal output from the actual
`ipa-diagnose` engine and CLI rendering code, run against fixture evidence
under `tests/fixtures/` (or small hand-built evidence objects for the two
cases noted below) - none of these are hand-drawn mockups.

Two labeling notes:
- Screenshots 12-14 (OpenAI/Anthropic/Bedrock) use a stub `AIProvider` in
  place of a live network call, since no API credentials exist in this
  build environment. Every other part of the AI pipeline exercised -
  payload construction, minimum-evidence-selection, redaction, the
  command-injection sanitizer, and rendering - is the unmodified
  production code path.
- Screenshot 16 (`ai-preview`) uses a small hand-built Finding containing a
  synthetic secret (not from a real FreeIPA host) specifically to make the
  redaction behavior visible in one screenshot.
- Screenshot 20 is the exception to "all fixtures are hand-authored": it
  replays genuine `ipa-healthcheck` output captured from an actual
  freeipa/freeipa-server container, not synthetic data - see
  tests/fixtures/real-freeipa-capture/README.md and docs/limitations.md.

| # | Scenario | Fixture(s) | Expected / observed behavior |
|---|---|---|---|
| `01_healthy` | Normal healthy FreeIPA result | `replication/healthy` | Overall: HEALTHY, no diagnoses |
| `02_degraded` | Degraded environment (transient-suspected disk usage) | `directory-server/disk-space` | Overall: DEGRADED, TRANSIENT_SUSPECTED primary |
| `03_primary_root_cause` | Primary root-cause diagnosis with evidence and a safe first action | `replication/peer-unreachable` | PRIMARY PROBLEM: peer-connectivity-break, DIAGNOSED, SAFE first action |
| `04_correlated_findings` | Multiple healthcheck failures correlated into one problem (DNS -> Kerberos) | `dns/named-down + kerberos/dns-discovery (merged)` | dns.named-service-down PRIMARY; kerberos.kdc-discovery-failure demoted to RELATED SYMPTOM |
| `05_independent_problems` | Multiple independent problems (no causal link) shown separately | `certificates/expired + directory-server/disk-space (merged)` | Overall: CRITICAL (tracks the confidently-diagnosed primary, not the unrelated secondary's uncertainty); certificates.cert-expired PRIMARY, directory-server issue shown as its own independent problem, not merged |
| `06_unknown_insufficient_evidence` | UNKNOWN / insufficient-evidence result with a safe next diagnostic step | `kerberos/ambiguous-preauth` | ROOT CAUSE: unable to determine safely; DO THIS NEXT shown instead of a guess |
| `07_details_output` | --details output: full evidence, confidence rationale, all actions | `directory-server/index-health` | Confidence rationale and every action shown, not just the first |
| `08_caution_high_risk_action` | CAUTION and HIGH-RISK remediation both shown with explicit safety labels | `directory-server/index-health` | Scoped db2index (CAUTION) recommended first; bare/no-arg db2index explicitly HIGH RISK |
| `09_verify_resolved` | Verification: RESOLVED, based on fresh re-collected evidence | `replication/peer-unreachable -> replication/healthy` | RESOLVED - the original condition is no longer present in fresh evidence |
| `10_verify_still_present` | Verification: STILL PRESENT, based on fresh re-collected evidence | `replication/peer-unreachable -> replication/peer-unreachable (unchanged)` | STILL PRESENT - not just a re-read of the old report |
| `11_no_ai_operation` | Fully offline / --no-ai operation: identical deterministic diagnosis, no network use | `replication/peer-unreachable` | Same diagnosis quality with zero AI involvement |
| `12_ai_openai` | OpenAI-assisted explanation (stubbed network call - see index) | `replication/peer-unreachable` | Same deterministic diagnosis; WHY section reworded by AI, evidence/actions unchanged |
| `13_ai_anthropic` | Anthropic Claude-assisted explanation (stubbed network call - see index) | `replication/peer-unreachable` | Same deterministic diagnosis; WHY section reworded by AI, evidence/actions unchanged |
| `14_ai_bedrock` | AWS Bedrock-assisted explanation (stubbed network call - see index) | `replication/peer-unreachable` | Same deterministic diagnosis; WHY section reworded by AI, evidence/actions unchanged |
| `15_ai_unavailable_fallback` | AI provider timeout/failure: falls back to the local deterministic explanation, does not crash | `replication/peer-unreachable + a provider timeout` | Real ProviderTimeoutError caught; local `why` text shown instead, run continues normally |
| `16_ai_payload_redaction_preview` | ai-preview: exact outbound AI payload with secrets redacted before anything is sent | `synthetic evidence (hand-crafted secret) - see index note` | bindpw and AWS-style key both redacted; redaction summary shown |
| `17_malformed_input_handling` | Malformed healthcheck output: reported as a collection issue, not a crash | `synthetic malformed healthcheck.json` | Overall: HEALTHY (no findings parsed), collection issue listed explicitly |
| `18_rpm_install` | Real `dnf install` of the locally-built RPM in a clean Fedora container | `packaging/rpm/ (install-test.sh, captured verbatim)` | Package + 4 dependencies (incl. python3-rich) install cleanly via plain dnf |
| `19_rpm_first_run` | First real ipa-diagnose run immediately after RPM install, before FreeIPA is even set up | `packaging/rpm/ (install-test.sh, captured verbatim)` | Degrades gracefully (ipa-healthcheck absent is reported, not a crash) - matches the CLI's real output |
| `20_real_freeipa_server_capture` | Real ipa-healthcheck output from an actual freeipa/freeipa-server container (dirsrv stopped) | `real-freeipa-capture/dirsrv-down (captured, not hand-authored - see its README)` | Parses and diagnoses real output correctly; see docs/limitations.md for the coverage gap this run also found |
