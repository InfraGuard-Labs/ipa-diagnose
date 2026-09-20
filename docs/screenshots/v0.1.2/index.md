# v0.1.2 screenshots - real captures only

Every image here is the **exact text** a real run of `ipa-diagnose` printed (ANSI
colour codes stripped; long outputs show a stated line range; the footer of each
image says which lines). They are rendered to SVG by
[`scripts/render_capture_svg.py`](https://github.com/InfraGuard-Labs/ipa-diagnose/blob/master/scripts/render_capture_svg.py),
which only draws the captured text - it does not run the tool or edit the text.
Each image carries a green banner naming its provenance. **No fixture output is
presented as a live FreeIPA capture, and nothing is mocked.**

Provenance labels used:

- **REAL LIVE CAPTURE** - a real FreeIPA server (`freeipa/freeipa-server:fedora-43`
  image: FreeIPA 4.13.3, Fedora 43, ipa-healthcheck 0.19, 389-ds-base 3.1.4,
  Python 3.14.7) on a free GitHub Actions runner, running the v0.1.2 source
  (see "Source used" below). Lab workflows: `.github/workflows/live-freeipa-scenarios.yml`
  (single server) and `live-freeipa-validation.yml` (two-node topology).
- **REAL CONTAINER CAPTURE** - an installation into a clean container of the named
  distribution (no FreeIPA present). Rocky/Alma images are **stand-ins** for RHEL;
  RHEL itself was never used.

**Source used for the live captures:** commit `bdac609`. The released code differs from it by
one guard in the NSS/TLS rule (routine TLS journal noise no longer produces a false UNKNOWN) and
one entry removed from the service-demotion map; neither affects any scenario shown here.
The clean-container install captures (13-17) were taken from the pre-final build of the same
package version; the final release artifacts were re-verified with the identical lifecycle.

The single-server scenario lab first corrects one known quirk of the container
image (`CS.cfg` shipped as mode 0664, which `ipa-healthcheck` flags) to obtain the
genuinely healthy capture (01); capture 02 is the same server *before* that
correction, which is why it is DEGRADED.

| # | File | What it shows | Provenance |
|---|---|---|---|
| 01 | `01_healthy_fully_verified.svg` | `HEALTHY`, `fully_verified`, RUV `NONE_CONFIGURED` (single server); notes the ipa-healthcheck warning no rule covers | REAL LIVE CAPTURE |
| 02 | `02_degraded.svg` | `DEGRADED`: real `CS.cfg` mode finding with a safe next step | REAL LIVE CAPTURE |
| 03 | `03_unknown_healthcheck_unavailable.svg` | `UNKNOWN` (exit 3) when `ipa-healthcheck` cannot run - "nothing can be reported healthy" | REAL LIVE CAPTURE |
| 04 | `04_not_fully_verified.svg` | `NOT_FULLY_VERIFIED` (exit 4) with `ldapsearch` genuinely hidden; RUV NOT VERIFIED with what to do | REAL LIVE CAPTURE |
| 05 | `05_ruv_verified_two_node.svg` | JSON excerpt on a real **two-node** topology: `ruv_state: VERIFIED`, evidence `complete`, no collection errors | REAL LIVE CAPTURE |
| 06 | `06_ruv_not_verified_during_outage.svg` | Directory Server stopped: CRITICAL, and the RUV honestly `NOT VERIFIED` (LDAP unreachable) | REAL LIVE CAPTURE |
| 07 | `07_directory_server_critical.svg` | Directory Server stopped: `Required service 'dirsrv' is not running` is the CRITICAL primary problem; crashed checks shown as RELATED | REAL LIVE CAPTURE |
| 08 | `08_directory_server_restored_verify_resolved.svg` | After restoring it: `verify` says `Evidence for this check: COMPLETE` and RESOLVED | REAL LIVE CAPTURE |
| 09 | `09_kdc_critical.svg` | KDC stopped: `Required service 'krb5kdc' is not running`, CRITICAL primary | REAL LIVE CAPTURE |
| 10 | `10_kdc_restored_verify_resolved.svg` | After restoring the KDC: `verify` RESOLVED | REAL LIVE CAPTURE |
| 11 | `11_details_evidence_completeness.svg` | `--details` output with the evidence-completeness block and "What to do" hints | REAL LIVE CAPTURE |
| 12 | `12_json_evidence_completeness.svg` | `--json` excerpt: `overall_status`, `fully_verified`, `evidence_completeness` | REAL LIVE CAPTURE |
| 13 | `13_el9_rpm_install.svg` | `dnf install` of the EL9 RPM (EPEL/CRB dependencies resolved) | REAL CONTAINER CAPTURE (Rocky 9.3, RHEL stand-in) |
| 14 | `14_el10_rpm_install.svg` | `dnf install` of the EL10 RPM | REAL CONTAINER CAPTURE (AlmaLinux 10, RHEL stand-in) |
| 15 | `15_el8_rpm_install.svg` | `dnf install` of the EL8 RPM (python39 module) | REAL CONTAINER CAPTURE (Rocky 8, RHEL stand-in) |
| 16 | `16_fedora_rpm_install.svg` | `dnf install` of the Fedora RPM | REAL CONTAINER CAPTURE (Fedora 44) |
| 17 | `17_wheel_pipx_install.svg` | `pipx install` of the candidate wheel, `ipa-diagnose --version` = 0.1.2 | REAL CONTAINER CAPTURE (Rocky 9.3) |
| 18 | `18_ai_preview_real_finding.svg` | `ai-preview` during a Directory Server outage: the exact (redacted) payload that would be sent; nothing is sent | REAL LIVE CAPTURE |
| 19 | `19_no_ai.svg` | `--no-ai` (no provider is ever contacted) | REAL LIVE CAPTURE |
| 20 | `20_dns_down_unknown.svg` | DNS genuinely stopped: `ipa-healthcheck` times out after 120 s, so `UNKNOWN` - never healthy | REAL LIVE CAPTURE |
| 21 | `21_certmonger_down.svg` | certmonger stopped: primary problem is the stopped service, **not** a false "certificate expired" | REAL LIVE CAPTURE |
| 22 | `22_non_root.svg` | Run as a non-root user: `UNKNOWN`, never healthy | REAL LIVE CAPTURE |

## What is NOT shown (and why)

- **A real stale RUV.** Not reproduced: on FreeIPA 4.13 the topology plugin
  removes a removed server's RUV automatically (`ipa server-del`, and direct
  removal of its topology segments, were both tried). The stale-RUV rule has
  fixture/regression coverage only. No 389-DS corruption was performed to
  manufacture one.
- **A genuine RHEL host**, EL8-era FreeIPA (4.9 / ipa-healthcheck 0.12),
  Trust/AD, CA-less, or 3+ replica topologies.
- **A live AI-provider call.** AI was tested with recording stand-ins for the
  three providers (no credentials); `ai-preview` (18) shows the real payload.
