# v0.1.3 screenshots - real captures only

Every image is the **exact text** a real run printed (ANSI colours stripped; long outputs show a stated line
range in the footer), rendered to SVG by `scripts/render_capture_svg.py`, which only draws captured text. Each image
carries a banner naming its provenance. **No fixture output is presented as live, and nothing is mocked.**

Provenance labels:

- **REAL LIVE CAPTURE** - a real FreeIPA 4.13.3 server (`freeipa/freeipa-server:fedora-43`, Fedora 43,
  ipa-healthcheck 0.19, 389-ds-base 3.1.4) on a free GitHub Actions runner, running the exact 0.1.3 release-candidate
  source (commit `9860e98`; workflow `live-freeipa-scenarios.yml`, run 35543980087). Not genuine RHEL.
- **FIXTURE REPLAY (NOT live)** - constructed, upstream-shaped input under `tests/fixtures/coverage/` replayed through
  the 0.1.3 code with `--replay`.
- **REAL CONTAINER CAPTURE** - the 0.1.3 candidate RPM installed in a clean Rocky 9.3 container (a RHEL stand-in).

| # | File | Shows | Provenance |
|---|---|---|---|
| 01 | `01_live_undiagnosed_not_fully_verified.svg` | a working server whose only finding is one upstream `MetaCheck` WARNING no rule explains: `NOT_FULLY_VERIFIED`, exit 4, no cause claimed | REAL LIVE |
| 02 | `02_live_degraded_plus_undiagnosed.svg` | a real CS.cfg file-mode finding is the DEGRADED primary; other findings listed as undiagnosed | REAL LIVE |
| 03 | `03_live_unknown_healthcheck_unavailable.svg` | ipa-healthcheck missing: `UNKNOWN`, exit 3 | REAL LIVE |
| 04 | `04_live_not_fully_verified_ruv.svg` | `ldapsearch` hidden: RUV NOT VERIFIED, `NOT_FULLY_VERIFIED` | REAL LIVE |
| 05 | `05_live_directory_server_critical.svg` | Directory Server stopped: CRITICAL | REAL LIVE |
| 06 | `06_live_verify_after_restore.svg` | `verify` after restore: RESOLVED items, plus the note explaining why exit stays 4 | REAL LIVE |
| 07 | `07_live_kdc_critical.svg` | KDC stopped: CRITICAL | REAL LIVE |
| 08 | `08_live_certmonger_down.svg` | certmonger stopped: the stopped service is the primary problem, not a false "certificate expired" | REAL LIVE |
| 09 | `09_live_dns_down_unknown.svg` | DNS stopped: ipa-healthcheck times out, `UNKNOWN`, never healthy | REAL LIVE |
| 10 | `10_live_no_ai_details.svg` | `--no-ai --details` with the undiagnosed section and version context | REAL LIVE |
| 11 | `11_live_ai_preview.svg` | `ai-preview`: nothing to explain, nothing sent | REAL LIVE |
| 12 | `12_fixture_healthy.svg` | `HEALTHY` | FIXTURE |
| 13 | `13_fixture_undiagnosed_warning.svg` | undiagnosed WARNING only: `NOT_FULLY_VERIFIED` | FIXTURE |
| 14 | `14_fixture_undiagnosed_details.svg` | `--details` for the same | FIXTURE |
| 15 | `15_fixture_ds_certificate_expired.svg` | `DSCERTLE0002`: Directory Server certificate expired (not an NSS DB mismatch) | FIXTURE |
| 16 | `16_fixture_unknown_future_check.svg` | an unknown future check ERROR: surfaced, never diagnosed | FIXTURE |
| 17 | `17_fixture_json_undiagnosed.svg` | `--json` fields | FIXTURE |
| 18 | `18_el9_rpm_lifecycle.svg` | EL9 RPM install/version/replay in a clean container | REAL CONTAINER |

## Not shown (and why)

- A live **DS certificate expiry** and a live **DIAGNOSED** result for a not-yet-seen check were not reproduced on real
  FreeIPA; the DS-expiry image is a fixture.
- A real **stale RUV** was never reproduced (FreeIPA 4.13 removes it automatically); no claim is made.
- No genuine RHEL host, EL8-era FreeIPA (4.9 / ipa-healthcheck 0.12), Trust/AD, or 3+ replica topology was used.
- No live AI-provider call was made (recording stand-ins only).
