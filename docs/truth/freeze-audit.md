# Integrated freeze audit (Slices 1-5 as one product)

This records the integrated validation of ipa-diagnose after Slices 1-5 were merged: the product tested end to end
as ONE product (DETECT → INVESTIGATE → CORRELATE → ROOT CAUSE → RESOLVE → VERIFY), not as five slices. Claims made
from it are in [claim-register.md](claim-register.md) (section "Freeze"). It is not a release: no version, tag or
package changed.

**Evidence classes, never blurred:** LIVE (disposable real FreeIPA in the free GitHub-hosted lab) · LIVE SIMULATED
(a live lab where only ipa-diagnose's own process clock was shifted) · FIXTURE / REPLAY (recorded or synthetic
evidence through the current code) · PACKAGING / CONTAINER (builds and installs in clean containers) · SOURCE REVIEW
ONLY.

## Runs on the freeze candidate

FREEZE_RUNS_TABLE

## End-to-end matrix

| Journey | LIVE | LIVE SIMULATED | FIXTURE / REPLAY | Result |
|---|---|---|---|---|
| Install / package | - | - | - | PACKAGING: Python 3.9-3.14 full suite + wheel/sdist; RPM lifecycle on Rocky/Alma 8 and 9, Alma 10, Fedora 43/44 (install, `--version`, `--help`, replay smoke, uninstall, reinstall); pipx paths on EL8/EL9/EL10/Fedora 44. Never "RHEL-tested" |
| Server diagnosis | healthy, Directory Server/KDC/named/certmonger stopped, certmonger masked, file mode/group faults, two services at once, ipa-healthcheck or ldapsearch missing, non-root, `--details`, `--json`, `--no-ai`, `ai-preview` (scenarios lab S0-S10, F1-F4, P1, V1-V2) | - | 124 recorded fixtures swept for product invariants (`tests/test_freeze_campaigns.py`), per-pack fixtures, 8 red-team rounds | see the scenarios run |
| Resolution + verify | printed fix run verbatim, then fresh verify: service start (S3, S5; replication R02b, R05), file group/mode (F1, P1), SSSD start (C02, C10) | - | every procedure's positive, look-alike, contradiction, hostile-value and fail-safe tests | see below |
| Access / HBAC | 25 scenarios (A01-A25) compared with an independent `ipa hbactest` | - | `tests/access/` | 0 false allows, 0 false denies |
| Access `--runtime` | C09 (HBAC PASS + SSSD stopped: RUNTIME FAIL, exit 5), C09b (host refuses: CONTRADICTING), C10 (after the fix: exit 0, RUNTIME NOT VERIFIED) | - | `tests/client/test_access_runtime.py` | AUTHORIZATION stayed FreeIPA's decision in every case |
| Client | 19 scenarios (E00, C00-C14) | C05 clock (+2 h, tool process only) | 29 scenarios x root/non-root swept | 0 false root causes |
| Replication | R00-R12 (20 rows) on three servers | R12 clock (+15 min, tool process only) | 25 scenarios swept replay + live-like; the Slice 5 fixture table | 0 false root causes, 0 missed, 0 unsafe |
| Cross-mode journey | J01-J03: the server diagnosis in the same injected state as replication mode | - | - | see the replication run |
| Topology / environment | three-server line: segments per suffix, CA holders, articulation point, handoffs | - | budget, partial topology, contradicting topology, RUV candidates | - |
| Support bundle | B0-B8 (canaries, output safety, CA journal), R11 (`--replication`), C14 (`--client`), A21 (`--access`) | - | `tests/bundle/` hostile archives, redaction, determinism | no canary or lab identifier reached a bundle |
| AI boundary | `ai-preview` on real evidence (S3, S8); `--no-ai` (S10) | - | adapter, failure-fallback, command-filter and payload tests | no live provider call (not needed) |

## Resolution / No-Google audit (every procedure in the catalogue)

The catalogue (`knowledge/procedures/*.yaml`, compiled to `src/ipa_diagnose/resolution/procedures.json`) has **7
procedures with steps** and **15 no-procedure entries** (a diagnosis for which ipa-diagnose deliberately prints no
fix and says why). Programs a fix may use are allowlisted (systemctl, chmod, chown, chgrp, chronyc, getcert,
sss_cache, sssctl); CONFIRM FIRST may only use `stat` and `readlink -f`; an invalid catalogue disables every fix.

| Procedure | Trigger diagnosis (min confidence) | Target / values | Risk | Tier / live record | Printed action | Expected result | If it fails | Backup | Rollback | Verify | Scope | Withheld when (examples) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `proc.service.start-stopped-service` | a required IPA service is not running (HIGH) | the unit from `systemctl` (typed `systemd_unit`) | MEDIUM | BUILT_IN_VERIFIED; LIVE apply+verify on FreeIPA 4.13.3 (Slice 1) and SERVICE_LIVE_NOTE | `systemctl start <unit>` (never `ipactl start`) | unit active | "it stays stopped and systemctl status shows why" (printed with the step since the freeze); replication mode adds `journalctl -u <unit> -n 50` and "do not use ipactl start" | none needed: no data changes (closed reason) | `systemctl stop <unit>` | the unit is active (fresh check) + the diagnosis gone | IPA server, FreeIPA 4.9 up to 5.0 | masked, not loaded, running now, transitioning, disabled (non-IPA-managed units), named/named-pkcs11, not root, version unknown or out of range; in replication also: not this server, not the deepest link, evidence older than 300 s, target changed |
| `proc.files.restore-expected-permissions` | ipa-healthcheck file owner/group/mode mismatch (MEDIUM) | path, mode, owner, group from structured findings (typed `ipa_path`, `chmod_remove`, `ipa_account`) | LOW | LIVE_VERIFIED; LIVE apply+verify on 4.13.3 (Slice 1) and FILES_LIVE_NOTE | `chmod <remove-only>` / `chown -h` / `chgrp -h`, after read-only CONFIRM FIRST commands with exact expected output | "no output; the file's mode/owner/group is X" | CONFIRM FIRST output differs → do not run, run ipa-diagnose again | CONFIRM FIRST + a rollback that restores the flagged state | restores the previous mode/owner/group | fresh `stat` of the target | IPA server | would add permissions, file gone or changed, second hard link, non-standard symlink, key material or secrets (ownership), non-IPA account, conflicting findings, not root |
| `proc.client.start-sssd` | SSSD is not running (HIGH), PRIMARY/INDEPENDENT | `sssd.service` | MEDIUM | LIVE_VERIFIED; LIVE apply+verify on freeipa-client 4.13.4 / Fedora 43 (C02, C10) and CLIENT_LIVE_NOTE | `systemctl start sssd.service` | active; "If it fails, it stays stopped and 'systemctl status sssd' shows why" | as expected-result text | none needed (no data changes) | `systemctl stop sssd.service` | active + `admins` resolves through SSSD | IPA client 4.9-5.0, SSSD >= 2.0 | invalid SSSD configuration, no systemd (never `initctl`), masked, disabled, transitioning, running now, not root, unknown/unsupported version, a symptom of another cause |
| `proc.client.expire-sssd-user-entry` | one user's SSSD cache entry inconsistent (MEDIUM) | user, domain | LOW | FIXTURE_ONLY | `sss_cache -u USER` | "prints nothing and returns 0" | lookup still fails → the cache is not the cause; run client again | nothing removed | nothing to roll back (closed) | user resolves through SSSD | IPA client | SSSD not running, offline, no cache entry, not root |
| `proc.client.remove-sssd-cache` | proven SSSD cache-database errors (HIGH) | domain | HIGH | FIXTURE_ONLY (the live C11 attempt did not break SSSD) | `sssctl cache-remove --stop --start`, after the admin accepts losing offline logins | sssctl backs up local data, removes, restarts | "if it cannot create the backup, nothing was removed; start SSSD" | sssctl's own backup of local overrides | cannot be undone; SSSD rebuilds from IPA (closed) | SSSD active + user resolves | IPA client | anything short of: IPA has the user, SSSD online, DNS/time/host key fine, SSSD's own log reports cache DB errors, entry unreadable; no systemd; never `rm /var/lib/sss/db/*` |
| `proc.time.step-clock-with-chrony` | Kerberos clock skew with this server's clock measured out of sync (MEDIUM) | - | MEDIUM | FIXTURE_ONLY (containers share the kernel clock) | `chronyc makestep`, after the admin accepts the jump | "200 OK", offset near 0 | - | not applicable | a clock step is not undone (closed) | offset < 1 s, synchronized | IPA server | chronyd down or unsynchronized, no reachable source, offset < 240 s or > 1 day, skew not corroborated on this host; never on clients |
| `proc.certs.renew-expiring-ds-certificate` | DS certificate expiring (HIGH) | certmonger request id (typed) | MEDIUM | FIXTURE_ONLY (no safe short-lived profile) | `getcert resubmit -i <request>` | new certificate, DS restarted by post-save, MONITORING | an error state withholds it beforehand | not kept (same renewal certmonger does itself) | not applicable (closed) | MONITORING, > 30 days valid | IPA server | already expired (no invented fix), not IPA CA, non-standard profile, error state, several DS instances, no post-save restart |

**No-procedure entries (15):** expired DS certificate (documented procedure linked), KDC-reported skew without local
desync, and client/replication causes where the only fixes are destructive or belong to another host or the
administrator: client clock skew, host principal unknown, host keytab missing / rejected / wrong principal, not
enrolled, cache DB suspected only; replication DS keytab problem, replica needing re-initialization or other admin
action, not a replication manager, pair clock skew, peer principal missing, RUV candidate.

**LIVE-tier procedures, followed blind:** for each, the lab injected the confirmed fault, ran ipa-diagnose without
telling it the fault, ran ONLY the printed argv (and, for the file procedure, first the printed CONFIRM FIRST commands,
whose output had to match), then ran the fresh verify, which had to answer RESOLVED. No other recovery guide was used
(the lab scripts contain no recovery knowledge: they only replay printed argv). Results on the freeze candidate: see
"Runs". **Gap found and closed in this campaign:** the server and client views printed the step without its expected
result (and so without the failure hint) unless `--details` was given; replication mode already showed it. Since
commit 70254c3 every surface prints it (regression tests in `tests/test_freeze_consistency.py`).

**No-Google claim:** only replication mode makes an explicit machine-checked No-Google claim (named target, exact
command, host per step, prerequisites met, what changes, expected result, what to do if a step fails, risk, backup
or closed-list reason, rollback or closed-list reason, verification tied to the incident, and a LIVE record in a
replication incident on the same FreeIPA version and OS). The server and client fixes carry the same parts in their
printed sections but make no No-Google label.

## Resolution Safety audit (attempts to force an inappropriate fix)

| Attempt | Server | Client | Replication | Live evidence |
|---|---|---|---|---|
| unsupported / unknown version | `test_unknown_future_or_malformed_versions_withhold`, `test_service_procedure_withheld_when_applicability_not_established` | `test_start_fix_is_withheld_on_an_unknown_client_version`, `test_start_fix_is_withheld_on_an_unsupported_client_version` | `test_unsupported_versions_withhold`, `test_unknown_version_withholds` | - |
| stale evidence | fresh read-only checks at diagnosis time ("running now (checked just now)") | re-run every check | `test_stale_evidence_withholds` (> 300 s) | - |
| replay where live is required | fix shown only labelled "Recorded evidence ... Do not run them here" (freeze) and never used by a live verify | same label (freeze) | `test_replay_evidence_never_offers_but_keeps_parity_with_live` | - |
| contradiction | `test_service_procedure_withheld_on_contradiction_or_missing_prerequisite` | `test_no_fix_for_undiagnosed_contradicting_or_related` | `test_topology_and_agreements_that_disagree_are_contradicting_and_withhold_fixes` | C09b (CONTRADICTING, no fix) |
| wrong subject / target | per-component path checks (`test_symlinked_parent_resolving_outside_ipa_locations_withholds_the_fix`) | host must be HOST for `--runtime` | `test_wrong_host_and_wrong_subject_withhold`, `test_peer_side_causes_never_get_a_command` | R02, R03, R07 (no command for the peer) |
| target changed after diagnosis | CONFIRM FIRST with exact expected output; "already has mode X now" | "running now (checked just now)" | `test_target_changed_after_the_diagnosis_withholds_with_a_fresh_check` | - |
| symlink / path attack | rounds 3-7 regressions (swapped parents, container mirror, hard links) | - | symlinked keytab not read | F3 (hard link: withheld) |
| masked / disabled service | `test_disabled_systemctl_unit_is_not_started_but_failed_ipa_unit_is_offered_scoped` | `test_start_is_withheld_when_masked_disabled_or_not_root` | `test_masked_unit_withholds` | S6 (certmonger masked: withheld) |
| malformed evidence | `tests/adversarial/test_malformed_input.py` | `test_hostile_recorded_output_is_neutralised` | `test_unexpected_evidence_types_are_never_interpreted` | - |
| partial topology | - | - | `test_topology_predicates_are_never_true_from_a_partial_read` | - |
| peer-side replication cause | - | - | `test_peer_side_causes_never_get_a_command` | R02, R07, R08 (handoff only) |
| dangerous RUV state | - | - | `test_ruv_element_without_server_is_a_candidate_never_a_cleanup` | never produced live (on purpose) |
| re-init required | - | - | generation-ID / changelog fixtures → REPLICA_NEEDS_ADMIN_ACTION, nothing printed | never produced live (on purpose) |
| already-expired certificate | `test_expired_ds_certificate_gets_no_invented_fix` | - | - | - |
| keytab uncertainty | - | `test_no_clock_step_on_a_client_and_no_keytab_replacement_or_reenrollment` | `test_ldap_49_is_not_jumped_to_a_keytab_mismatch` | R06 (DS keytab unreadable: diagnosed, no keytab command) |
| cache uncertainty | - | `test_cache_removal_is_not_offered_on_a_suspicion`, `test_one_log_line_and_an_absent_entry_do_not_justify_cache_removal` | - | C11 (damaged cache did not break SSSD: nothing offered) |
| product-wide sweep | 124 fixtures: no fix for a symptom or non-DIAGNOSED diagnosis, allowlisted programs only, `systemctl start` only, complete fixes | 29 scenarios x root/non-root: no fix without root, only PRIMARY/INDEPENDENT, no `/var/lib/sss`, no `initctl` | 25 scenarios: replay never offers, live offers only `systemctl start` for this server | `tests/test_freeze_campaigns.py` |

**Unsafe applicable mutating commands found: 0.**

## False root cause campaign

| Rule | Evidence |
|---|---|
| collector failure ≠ subsystem failure | server `test_every_subprocess_fails_is_never_healthy`, `test_unexpected_collector_exception_becomes_a_collection_error`; client "collector-timeout" (exit 4, no cause) and the sweep rule "a HIGH-confidence cause never rests only on checks that could not run"; replication `test_collector_failure_is_unable_to_verify`; live S1, S2, C12, R10 |
| upstream cause demotes downstream symptom | server `test_documented_causal_link_is_recognized`; client C08 live (SSSD offline RELATED to the unreachable server); replication `test_kdc_down_because_ds_down_is_related_to_the_ds`, live R06 (ipa02's LDAP 49 RELATED to ipa03's keytab) |
| independent causes stay independent | server `test_unrelated_simultaneous_failures_stay_independent`; client C13 live; replication R08 live |
| UNKNOWN stays UNKNOWN | live S1 (UNKNOWN, exit 3), S4 (named stopped: UNKNOWN, not "DNS broken"), C07 (UNDIAGNOSED), A12/A16/A17 (UNKNOWN) |
| stale status is not a current root cause | replication `test_transport_error_that_the_peer_no_longer_shows_is_transient_not_a_root_cause`; live R02-R04 (389-DS still said "succeeded"; the cause came from fresh checks) |
| DNS failure is not a KDC failure | client `test_kdc_unresolvable_with_missing_kerberos_srv_is_dns`, live C03; replication live R04 (PEER_NAME_UNRESOLVED, no KDC or DS cause) |
| generic LDAP/Kerberos error is not a keytab mismatch | client `test_keytab_is_not_blamed_when_the_kdc_is_unavailable`, live C04; replication `test_ldap_49_is_not_jumped_to_a_keytab_mismatch` |
| one timeout is not a dead replica | replication `test_unreachable_peer_is_never_called_dead_and_says_from_where_and_when`, live R03, sweep assertion |
| fixture-only stale RUV never becomes a live claim | RUV element is a *candidate* with a read-only next step; claim register Z11/C18: do not claim |
| cross-mode: no local cause invented for a peer fault | live J02 (server diagnosis on ipa01 while ipa02's DS is stopped) |

**Accepted false root causes: 0** (live rows: 0 in client, replication and the journey rows; server rows assert the
wrong causes absent).

## False resolution campaign

| Case | Evidence |
|---|---|
| similar symptom, wrong procedure | `test_file_look_alikes_never_get_a_fix`, `test_ds_certificate_look_alikes_get_no_fix`, `test_nss_db_format_and_other_diagnoses_never_get_a_procedure`, `test_named_is_never_given_a_start_command` |
| correct procedure, wrong target | `test_local_ds_fix_targets_this_servers_instance_only`, `test_command_target_only_follows_the_verified_container_mirror`, J01/J03 live (server and replication modes printed the same argv) |
| unmet prerequisites | `test_not_root_withholds_by_prerequisite`, client sweep (no fix without root) |
| stale procedure state | verify refuses a changed procedure digest (CHANGED / UNABLE_TO_VERIFY), live V2 |
| replay/live mismatch | saved results from replay are never compared with live runs (`test_replay_state_never_touches_the_live_baseline`) |
| unsupported environment | version gates above; labels say "not yet verified on this FreeIPA version/OS" |
| several causes, one fix | `test_only_one_fix_when_the_kdc_is_down_because_the_ds_is_down`; live R08 (fix only for the local KDC; peer DS handed off); S7b |

**Incorrect procedures presented as applicable: 0.**

## False RESOLVED campaign

| Case | Evidence |
|---|---|
| command succeeds but fault remains | live V1 (STILL_PRESENT); `test_verify_still_present_is_not_affected_by_criteria` |
| different user / service / peer / suffix | `test_verify_with_other_inputs_is_unable_not_resolved`, `test_a_baseline_from_another_host_or_scope_is_unable_to_verify`, `test_suffixes_with_the_same_peer_are_separate_subjects` |
| stale or edited state | live V2 (CHANGED); `test_tampered_state_is_refused`, `test_tampered_or_foreign_state_is_refused`, `test_state_behind_a_symlink_is_refused` |
| different procedure | procedure digest in the baseline; a changed catalogue gives UNABLE_TO_VERIFY |
| collector failure | `test_collector_failure_is_never_resolved`, `test_collector_failure_is_unable_to_verify`, `test_verify_never_says_resolved_when_healthcheck_returned_nothing` |
| partial evidence | `test_verify_incomplete_evidence_is_exit_4` |
| replication PENDING | `test_no_fresh_session_yet_is_pending_with_a_recheck_time_and_never_exit_zero`, `test_pending_is_time_bounded`; live R02d (PENDING seen, then RESOLVED) |
| reverse direction unknown | `test_a_failing_reverse_direction_that_cannot_be_observed_now_is_unable_to_verify` |
| new independent failure | `test_new_problem_blocks_a_clean_verify`, `test_an_unrelated_new_failure_blocks_exit_zero` |
| old success predating the baseline | `test_resolved_needs_a_fresh_successful_session_after_the_baseline` (its clock handling fixed in this campaign: commit 26f9549) |

**False RESOLVED: 0.**

## Access journey

Live A01-A25 (policy) and C09/C09b/C10 (runtime) on the freeze candidate; the README and docs now distinguish
AUTHENTICATION (never PASS), AUTHORIZATION (FreeIPA `hbactest` only) and RUNTIME ACCESS (NOT VERIFIED; FAIL only
with `--runtime` when a runtime prerequisite on HOST is shown broken; never PASS). The stale statement "RUNTIME ACCESS
is always NOT VERIFIED" was corrected in the README and `docs/access-diagnosis.md`.

## Bundle and privacy

Live B0-B8 on the freeze candidate (scenarios workflow, bundle job): planted fake credentials and the lab's real names
reached no bundle; existing file and symlink refused; `bundle validate` on a fresh bundle VALID. Client (C14),
replication (R11) and access (A21) bundle parts validated live. Hostile archives, bounded decompression, trailing
data, determinism and redaction-before-truncation: `tests/bundle/`. A bundle is never called secret-free.

## AI boundary

`ai-preview` on real evidence (live S3/S8) and `--no-ai` (live S10); in tests, for each of the three adapters
(OpenAI, Anthropic, Bedrock, with the network call stubbed): `test_ai_cannot_alter_the_deterministic_result`,
`test_ai_invented_or_extended_commands_are_rejected`, `test_provider_outage_leaves_diagnosis_fully_intact`,
`test_no_ai_flag_never_builds_a_provider`, `test_no_diagnosis_means_no_ai_call_and_no_invented_diagnosis`,
`test_ai_preview_shows_payload_but_no_collection_error_text` (`tests/unit/test_ai_completeness_regression.py`), plus
`tests/adversarial/test_prompt_injection.py` and `tests/adversarial/test_secret_leakage.py` (the privacy pipeline runs
before any payload is built; the preview and the real call share one code path). AI is used only by the server diagnosis; client, access and replication
never contact a provider. No paid live provider call was made for the freeze: the adapter, preview and failure paths
cover the boundary.

## Terminology and exit codes

Audited across every command: [../exit-codes.md](../exit-codes.md). Inconsistencies found and fixed: `access --help`
did not list exit 5 (`--runtime`); `bundle --help` and the top-level `--help` stated no exit codes; `client --help`
did not say what 1/4 mean with `--verify`. Regression: `test_every_command_help_states_its_exit_codes`.

## Known limitations (unchanged by the freeze)

Only Fedora 43 and FreeIPA 4.13.3/4.13.4 live; no RHEL, no EL-hosted FreeIPA, no FreeIPA 4.9, no AD trust or
CA-less; real clock skew, stale RUV, CA-suffix-only failures, generation-ID mismatch, DS certificate expiry, the clock
and cache procedures are fixture-only; no login is ever attempted; privacy redaction is pattern-based; reviews are
fresh model reviewer agents, not independent humans.
