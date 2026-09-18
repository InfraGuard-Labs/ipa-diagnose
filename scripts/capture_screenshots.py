"""Captures real terminal screenshots of the actual ipa-diagnose CLI output.

Runs entirely inside Docker (see docker compose run --rm dev python
scripts/capture_screenshots.py). Uses rich's own Console(record=True) to
export what was ACTUALLY rendered by the real render_report/render_verify/
render_preview functions - this is not a mockup: every diagnosis, every
piece of evidence, every action shown here was produced by running the real
engine against real (fixture) evidence through the unmodified rendering
code path.

Two scenarios intentionally use a stub AIProvider (clearly labeled, both here
and in the screenshot index) because no live OpenAI/Anthropic/Bedrock
credentials exist in this environment: the stub only replaces the network
call inside generate() - build_ai_payload, sanitize_explanation, and
render_report's AI-explanation rendering path are all the real production
code, unmodified.

Output: artifacts/screenshots/<NN>_<name>.svg (+ .png where cairosvg is
available) plus artifacts/screenshots/index.md.
"""

from __future__ import annotations

import pathlib
import sys

from rich.console import Console

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"
OUT_DIR = REPO_ROOT / "artifacts" / "screenshots"

from ipa_diagnose.ai.prompt import explain_diagnosis
from ipa_diagnose.ai.provider import AIProvider, AIRequest, AIResponse, ProviderTimeoutError
from ipa_diagnose.engine.model import (
    Action,
    Confidence,
    ConfidenceLevel,
    Diagnosis,
    DiagnosisStatus,
    EvidenceRef,
    PriorityBucket,
    RiskLevel,
)
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.evidence.model import EvidenceBundle, Finding, Provenance, Severity
from ipa_diagnose.privacy.minimize import build_ai_payload
from ipa_diagnose.privacy.preview import render_preview
from ipa_diagnose.render.console import render_report, render_verify
from ipa_diagnose.verify import VerifyItem, VerifyOutcome, VerifyResult, compare
from ipa_diagnose.render.json_output import report_to_dict

WIDTH = 104
INDEX_ROWS = []


def _console() -> Console:
    return Console(record=True, width=WIDTH, force_terminal=True, color_system="standard", highlight=False)


def _save(console: Console, name: str, scenario: str, fixture: str, expected: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    svg_path = OUT_DIR / f"{name}.svg"
    console.save_svg(str(svg_path), title="ipa-diagnose")
    png_note = ""
    try:
        import cairosvg

        png_path = OUT_DIR / f"{name}.png"
        cairosvg.svg2png(url=str(svg_path), write_to=str(png_path), scale=1.5)
        png_note = f"{name}.png"
    except Exception as e:  # pragma: no cover - best effort only
        png_note = f"(svg only: {e})"
    INDEX_ROWS.append((name, scenario, fixture, expected, png_note))
    print(f"wrote {svg_path.name}  ({png_note})")


def _bundle(fixture_rel: str) -> EvidenceBundle:
    return collect_evidence(replay_dir=str(FIXTURES / fixture_rel))


def _merged(*fixture_rels: str) -> EvidenceBundle:
    merged = EvidenceBundle(hostname="ipa01.example.test", collected_at=EvidenceBundle.now())
    for rel in fixture_rels:
        sub = _bundle(rel)
        merged.hostname = sub.hostname or merged.hostname
        merged.findings.extend(sub.findings)
        merged.items.extend(sub.items)
        merged.collection_errors.extend(sub.collection_errors)
    return merged


class StubProvider(AIProvider):
    """Stands in for a real provider SDK call ONLY - everything else in the
    AI explanation pipeline (payload building, redaction, sanitization,
    rendering) is the real production code. Used because no live API
    credentials exist in this environment; clearly labeled wherever used."""

    def __init__(self, provider_name: str, text: str):
        self.provider_name = provider_name
        self._text = text

    def is_configured(self) -> bool:
        return True

    def generate(self, request: AIRequest) -> AIResponse:
        return AIResponse(text=self._text, provider_name=self.provider_name, model="demo-model")


class TimeoutStubProvider(AIProvider):
    provider_name = "openai"

    def is_configured(self) -> bool:
        return True

    def generate(self, request: AIRequest) -> AIResponse:
        raise ProviderTimeoutError("request to the provider timed out after 12s")


def scenario_healthy():
    bundle = _bundle("replication/healthy")
    report = run_diagnosis(bundle)
    console = _console()
    render_report(report, console)
    _save(console, "01_healthy", "Normal healthy FreeIPA result", "replication/healthy", "Overall: HEALTHY, no diagnoses")


def scenario_degraded():
    bundle = _bundle("directory-server/disk-space")
    report = run_diagnosis(bundle)
    console = _console()
    render_report(report, console)
    _save(
        console,
        "02_degraded",
        "Degraded environment (transient-suspected disk usage)",
        "directory-server/disk-space",
        "Overall: DEGRADED, TRANSIENT_SUSPECTED primary",
    )


def scenario_primary_root_cause():
    bundle = _bundle("replication/peer-unreachable")
    report = run_diagnosis(bundle)
    console = _console()
    render_report(report, console)
    _save(
        console,
        "03_primary_root_cause",
        "Primary root-cause diagnosis with evidence and a safe first action",
        "replication/peer-unreachable",
        "PRIMARY PROBLEM: peer-connectivity-break, DIAGNOSED, SAFE first action",
    )


def scenario_correlated():
    bundle = _merged("dns/named-down", "kerberos/dns-discovery")
    report = run_diagnosis(bundle)
    console = _console()
    render_report(report, console, details=True)
    _save(
        console,
        "04_correlated_findings",
        "Multiple healthcheck failures correlated into one problem (DNS -> Kerberos)",
        "dns/named-down + kerberos/dns-discovery (merged)",
        "dns.named-service-down PRIMARY; kerberos.kdc-discovery-failure demoted to RELATED SYMPTOM",
    )


def scenario_independent_problems():
    bundle = _merged("certificates/expired", "directory-server/disk-space")
    report = run_diagnosis(bundle)
    console = _console()
    render_report(report, console)
    _save(
        console,
        "05_independent_problems",
        "Multiple independent problems (no causal link) shown separately",
        "certificates/expired + directory-server/disk-space (merged)",
        "Overall: CRITICAL (tracks the confidently-diagnosed primary, not the unrelated secondary's "
        "uncertainty); certificates.cert-expired PRIMARY, directory-server issue shown as its own "
        "independent problem, not merged",
    )


def scenario_unknown():
    bundle = _bundle("kerberos/ambiguous-preauth")
    report = run_diagnosis(bundle)
    console = _console()
    render_report(report, console)
    _save(
        console,
        "06_unknown_insufficient_evidence",
        "UNKNOWN / insufficient-evidence result with a safe next diagnostic step",
        "kerberos/ambiguous-preauth",
        "ROOT CAUSE: unable to determine safely; DO THIS NEXT shown instead of a guess",
    )


def scenario_details():
    bundle = _bundle("directory-server/index-health")
    report = run_diagnosis(bundle)
    console = _console()
    render_report(report, console, details=True)
    _save(
        console,
        "07_details_output",
        "--details output: full evidence, confidence rationale, all actions",
        "directory-server/index-health",
        "Confidence rationale and every action shown, not just the first",
    )


def scenario_caution_high_risk():
    bundle = _bundle("directory-server/index-health")
    report = run_diagnosis(bundle)
    console = _console()
    render_report(report, console, details=True)
    _save(
        console,
        "08_caution_high_risk_action",
        "CAUTION and HIGH-RISK remediation both shown with explicit safety labels",
        "directory-server/index-health",
        "Scoped db2index (CAUTION) recommended first; bare/no-arg db2index explicitly HIGH RISK",
    )


def scenario_verify_resolved():
    previous_bundle = _bundle("replication/peer-unreachable")
    previous_report = run_diagnosis(previous_bundle)
    previous_dict = report_to_dict(previous_report)

    fixed_bundle = _bundle("replication/healthy")
    fixed_report = run_diagnosis(fixed_bundle)
    result = compare(previous_dict, fixed_report)

    console = _console()
    render_verify(result, console)
    _save(
        console,
        "09_verify_resolved",
        "Verification: RESOLVED, based on fresh re-collected evidence",
        "replication/peer-unreachable -> replication/healthy",
        "RESOLVED - the original condition is no longer present in fresh evidence",
    )


def scenario_verify_still_present():
    previous_bundle = _bundle("replication/peer-unreachable")
    previous_report = run_diagnosis(previous_bundle)
    previous_dict = report_to_dict(previous_report)

    same_bundle = _bundle("replication/peer-unreachable")
    same_report = run_diagnosis(same_bundle)
    result = compare(previous_dict, same_report)

    console = _console()
    render_verify(result, console)
    _save(
        console,
        "10_verify_still_present",
        "Verification: STILL PRESENT, based on fresh re-collected evidence",
        "replication/peer-unreachable -> replication/peer-unreachable (unchanged)",
        "STILL PRESENT - not just a re-read of the old report",
    )


def scenario_no_ai():
    bundle = _bundle("replication/peer-unreachable")
    report = run_diagnosis(bundle)
    console = _console()
    console.print("[dim]$ ipa-diagnose --no-ai[/dim]\n")
    render_report(report, console)
    _save(
        console,
        "11_no_ai_operation",
        "Fully offline / --no-ai operation: identical deterministic diagnosis, no network use",
        "replication/peer-unreachable",
        "Same diagnosis quality with zero AI involvement",
    )


def _ai_explained_screenshot(name: str, provider_name: str, scenario_label: str) -> None:
    bundle = _bundle("replication/peer-unreachable")
    report = run_diagnosis(bundle)
    primary = next(d for d in report.diagnoses if d.priority == PriorityBucket.PRIMARY)

    canned = (
        "This looks like a replication problem between your servers, not a data issue. "
        "The evidence points to a broken connection or authentication link to the peer, rather than "
        "a conflict in the data itself. Because directory changes may not be replicating correctly, "
        "it's worth confirming connectivity before anything else. Start with the safe, read-only "
        "check listed above - it won't change anything on either server."
    )
    stub = StubProvider(provider_name, canned)
    explanation = explain_diagnosis(primary, bundle, stub)
    assert explanation, "stub explanation was rejected by the sanitizer - check the canned text"

    console = _console()
    render_report(report, console, ai_explanations={primary.diagnosis_id: explanation})
    _save(
        console,
        name,
        scenario_label,
        "replication/peer-unreachable",
        "Same deterministic diagnosis; WHY section reworded by AI, evidence/actions unchanged",
    )


def scenario_openai():
    _ai_explained_screenshot("12_ai_openai", "openai", "OpenAI-assisted explanation (stubbed network call - see index)")


def scenario_anthropic():
    _ai_explained_screenshot(
        "13_ai_anthropic", "anthropic", "Anthropic Claude-assisted explanation (stubbed network call - see index)"
    )


def scenario_bedrock():
    _ai_explained_screenshot(
        "14_ai_bedrock", "bedrock", "AWS Bedrock-assisted explanation (stubbed network call - see index)"
    )


def scenario_ai_failure_fallback():
    bundle = _bundle("replication/peer-unreachable")
    report = run_diagnosis(bundle)
    primary = next(d for d in report.diagnoses if d.priority == PriorityBucket.PRIMARY)

    console = _console()
    console.print("[dim]$ ipa-diagnose --ai-provider openai[/dim]\n")
    stub = TimeoutStubProvider()
    explanation = explain_diagnosis(primary, bundle, stub)
    assert explanation is None
    console.print(f"[dim](AI explanation unavailable for '{primary.title}' - showing local explanation)[/dim]")
    render_report(report, console, ai_explanations={})
    _save(
        console,
        "15_ai_unavailable_fallback",
        "AI provider timeout/failure: falls back to the local deterministic explanation, does not crash",
        "replication/peer-unreachable + a provider timeout",
        "Real ProviderTimeoutError caught; local `why` text shown instead, run continues normally",
    )


def scenario_ai_preview():
    finding = Finding(
        finding_id="demo-finding-1",
        source="ipahealthcheck.ds.config",
        check="ConfigCheck",
        severity=Severity.ERROR,
        message="bind failed for cn=replman,cn=config using bindpw hunter2-example and key AKIAABCDEFGHIJKLMNOP",
        keywords={"msg": "bind failed", "bindpw": "hunter2-example-secret"},
        provenance=Provenance(source="ipa-healthcheck"),
    )
    bundle = EvidenceBundle(hostname="ipa01.example.test", collected_at=EvidenceBundle.now(), findings=[finding])
    diagnosis = Diagnosis(
        pack_id="directory-server",
        rule_id="ownership-selinux-mismatch",
        status=DiagnosisStatus.DIAGNOSED,
        title="(synthetic demo) bind configuration error with embedded secrets",
        why="Demonstration diagnosis built for this screenshot to show redaction, not from a real fixture.",
        confidence=Confidence(level=ConfidenceLevel.HIGH, rationale="demo"),
        actions=[Action(description="Inspect the bind configuration", risk=RiskLevel.SAFE, command="ldapsearch ...")],
        evidence_for=[EvidenceRef(evidence_id="demo-finding-1", kind="finding", why_relevant="trigger finding")],
    )
    payload = build_ai_payload(bundle, diagnosis)
    console = _console()
    console.print(
        "[dim]$ ipa-diagnose ai-preview[/dim]  "
        "[dim](synthetic evidence with an embedded secret, crafted for this screenshot - see index)[/dim]\n"
    )
    render_preview(payload, console)
    _save(
        console,
        "16_ai_payload_redaction_preview",
        "ai-preview: exact outbound AI payload with secrets redacted before anything is sent",
        "synthetic evidence (hand-crafted secret) - see index note",
        "bindpw and AWS-style key both redacted; redaction summary shown",
    )


def scenario_malformed_input():
    import json
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        fixture_dir = pathlib.Path(tmp)
        (fixture_dir / "healthcheck.json").write_text("{this is not valid json at all", encoding="utf-8")
        bundle = collect_evidence(replay_dir=str(fixture_dir))
        report = run_diagnosis(bundle)
        console = _console()
        console.print(f"[dim]$ ipa-diagnose --replay {fixture_dir.name} diagnose[/dim]\n")
        render_report(report, console)
        _save(
            console,
            "17_malformed_input_handling",
            "Malformed healthcheck output: reported as a collection issue, not a crash",
            "synthetic malformed healthcheck.json",
            "Overall: HEALTHY (no findings parsed), collection issue listed explicitly",
        )


def _extract_section(full_text: str, start_marker: str, end_marker: str = None) -> str:
    start = full_text.index(start_marker)
    if end_marker:
        end = full_text.index(end_marker, start)
        return full_text[start:end].rstrip()
    return full_text[start:].rstrip()


def scenario_rpm_install():
    log_path = REPO_ROOT / "artifacts" / "rpm_lifecycle_output.txt"
    if not log_path.exists():
        print("skipping RPM install screenshots: artifacts/rpm_lifecycle_output.txt not found "
              "(run packaging/rpm/README.md's install-test steps first)")
        return
    full_text = log_path.read_text(encoding="utf-8")

    console = _console()
    console.print("[dim]$ sudo dnf install ./ipa-diagnose-0.1.0-1.fc44.noarch.rpm[/dim]\n")
    section = _extract_section(full_text, "=== 1. Fresh install", "=== 2.")
    console.print(section.split("\n", 1)[1])
    _save(
        console,
        "18_rpm_install",
        "Real `dnf install` of the locally-built RPM in a clean Fedora container",
        "packaging/rpm/ (install-test.sh, captured verbatim)",
        "Package + 4 dependencies (incl. python3-rich) install cleanly via plain dnf",
    )

    console = _console()
    console.print("[dim]$ sudo ipa-diagnose[/dim]  [dim](no FreeIPA installed on this host yet)[/dim]\n")
    section = _extract_section(
        full_text, "=== 4. First real run", "=== 5."
    ) if "=== 5." in full_text else _extract_section(full_text, "=== 4. First real run", "=== 6.")
    console.print(section.split("\n", 1)[1])
    _save(
        console,
        "19_rpm_first_run",
        "First real ipa-diagnose run immediately after RPM install, before FreeIPA is even set up",
        "packaging/rpm/ (install-test.sh, captured verbatim)",
        "Degrades gracefully (ipa-healthcheck absent is reported, not a crash) - matches the CLI's real output",
    )


def scenario_real_freeipa_capture():
    real_dir = FIXTURES / "real-freeipa-capture" / "dirsrv-down"
    if not (real_dir / "healthcheck.json").exists():
        print("skipping real-capture screenshot: tests/fixtures/real-freeipa-capture/dirsrv-down not found")
        return
    bundle = _bundle("real-freeipa-capture/dirsrv-down")
    report = run_diagnosis(bundle)
    console = _console()
    console.print(
        "[dim]$ ipa-diagnose --replay real-freeipa-capture/dirsrv-down diagnose --details[/dim]  "
        "[dim](real ipa-healthcheck output from an actual FreeIPA server - see fixture README)[/dim]\n"
    )
    render_report(report, console, details=True)
    _save(
        console,
        "20_real_freeipa_server_capture",
        "Real ipa-healthcheck output from an actual freeipa/freeipa-server container (dirsrv stopped)",
        "real-freeipa-capture/dirsrv-down (captured, not hand-authored - see its README)",
        "Parses and diagnoses real output correctly; see docs/limitations.md for the coverage gap this run also found",
    )


def scenario_stale_ruv():
    bundle = _bundle("replication/stale-ruv-removed-replica")
    report = run_diagnosis(bundle)
    console = _console()
    console.print(
        "[dim]$ ipa-diagnose --replay tests/fixtures/replication/stale-ruv-removed-replica "
        "--details diagnose[/dim]\n"
    )
    render_report(report, console, details=True)
    _save(
        console,
        "21_stale_ruv_degraded",
        "Stale-RUV regression fixture: a decommissioned replica left a stale RUV entry with no other "
        "visible replication symptoms",
        "replication/stale-ruv-removed-replica",
        "Overall: DEGRADED (never HEALTHY) - replication.stale-ruv PRIMARY, "
        "UNKNOWN_INSUFFICIENT_EVIDENCE, with a safe next diagnostic step",
    )


def scenario_environment_metadata():
    bundle = _bundle("replication/healthy-with-environment")
    report = run_diagnosis(bundle)
    console = _console()
    console.print(
        "[dim]$ ipa-diagnose --replay tests/fixtures/replication/healthy-with-environment "
        "--details diagnose[/dim]\n"
    )
    render_report(report, console, details=True)
    _save(
        console,
        "22_details_environment_metadata",
        "--details output including populated environment/version metadata",
        "replication/healthy-with-environment",
        "Environment (replayed): OS, Python, FreeIPA, ipa-healthcheck, and 389-ds versions all shown",
    )


def scenario_json_output():
    import json

    bundle = _bundle("replication/stale-ruv-removed-replica")
    report = run_diagnosis(bundle)
    payload = json.dumps(report_to_dict(report), indent=2)

    console = _console()
    console.print(
        "[dim]$ ipa-diagnose --replay tests/fixtures/replication/stale-ruv-removed-replica "
        "--json diagnose[/dim]\n"
    )
    # This is exactly cli.py's own `print(json.dumps(report_to_dict(report, explanations),
    # indent=2))` call, run through the same recorded Console so the terminal capture is
    # pixel-for-pixel what a real invocation would print - markup=False so the JSON's own
    # square brackets are never misread as rich markup tags.
    console.print(payload, markup=False)
    _save(
        console,
        "23_json_output",
        "--json pretty-printed output for a diagnosed scenario",
        "replication/stale-ruv-removed-replica",
        "Same DEGRADED / stale-ruv diagnosis as scenario 21, serialized as the exact `--json` "
        "machine-readable structure (unmodified report_to_dict output)",
    )


def scenario_el9_rpm_install():
    log_path = REPO_ROOT / "artifacts" / "el9_install_output.txt"
    if not log_path.exists():
        print("skipping EL9 RPM install screenshot: artifacts/el9_install_output.txt not found "
              "(run the EL9 install capture in a fresh rockylinux:9.3 container first)")
        return
    full_text = log_path.read_text(encoding="utf-8")

    console = _console()
    console.print("[dim]$ dnf install -y ./ipa-diagnose-0.1.0-1.el9.noarch.rpm[/dim]  "
                  "[dim](Rocky Linux 9.3, EPEL enabled for python3-rich)[/dim]\n")
    section = _extract_section(full_text, "=== 1. Fresh install", "=== 2.")
    console.print(section.split("\n", 1)[1], markup=False)
    _save(
        console,
        "24_el9_rpm_install",
        "Real `dnf install` of the locally-built EL9 RPM on a fresh Rocky Linux 9.3 container",
        "packaging/rpm/el9/ (build-rpm.sh output, captured verbatim)",
        "Package + python3-rich/pygments/CommonMark/setuptools install cleanly via plain dnf once "
        "EPEL *and* CRB are both enabled (matches docs/compatibility.md's EL9 row)",
    )

    console = _console()
    console.print("[dim]$ ipa-diagnose --version[/dim]  [dim](immediately after RPM install)[/dim]\n")
    section = _extract_section(full_text, "=== 2. First real run", "=== 3.")
    console.print(section.split("\n", 1)[1], markup=False)
    _save(
        console,
        "25_el9_first_run",
        "First real `ipa-diagnose --version` / run immediately after the EL9 RPM install",
        "packaging/rpm/el9/ (build-rpm.sh output, captured verbatim)",
        "Reports its version and degrades gracefully with no FreeIPA installed on this host yet",
    )


def scenario_pypi_pipx_install():
    log_path = REPO_ROOT / "artifacts" / "pipx_install_output.txt"
    if not log_path.exists():
        print("skipping pipx/PyPI install screenshot: artifacts/pipx_install_output.txt not found "
              "(run the pipx install capture in a fresh python:3.11-slim container first)")
        return
    full_text = log_path.read_text(encoding="utf-8")

    console = _console()
    console.print("[dim]$ pipx install ipa-diagnose[/dim]  "
                  "[dim](real, live PyPI - ipa-diagnose 0.1.0 is genuinely published there)[/dim]\n")
    section = _extract_section(full_text, "=== 2. pipx install from real PyPI", "=== 3.")
    console.print(section.split("\n", 1)[1], markup=False)
    _save(
        console,
        "26_pypi_pipx_install",
        "Real `pipx install ipa-diagnose` from live PyPI on a fresh, unmodified container",
        "live PyPI (pipx install capture, captured verbatim)",
        "pipx resolves and installs ipa-diagnose 0.1.0 and its dependencies cleanly",
    )

    console = _console()
    console.print("[dim]$ ipa-diagnose --version[/dim]  [dim](immediately after pipx install)[/dim]\n")
    section = _extract_section(full_text, "=== 3. First real run", "=== 4.")
    console.print(section.split("\n", 1)[1], markup=False)
    _save(
        console,
        "27_pypi_first_run",
        "First real `ipa-diagnose --version` / run immediately after the pipx/PyPI install",
        "live PyPI (pipx install capture, captured verbatim)",
        "Reports its version and degrades gracefully with no FreeIPA installed on this host yet",
    )


def write_index():
    lines = [
        "# Screenshot index",
        "",
        "All screenshots are real `rich`-recorded terminal output from the actual",
        "`ipa-diagnose` engine and CLI rendering code, run against fixture evidence",
        "under `tests/fixtures/` (or small hand-built evidence objects for the two",
        "cases noted below) - none of these are hand-drawn mockups.",
        "",
        "Two labeling notes:",
        "- Screenshots 12-14 (OpenAI/Anthropic/Bedrock) use a stub `AIProvider` in",
        "  place of a live network call, since no API credentials exist in this",
        "  build environment. Every other part of the AI pipeline exercised -",
        "  payload construction, minimum-evidence-selection, redaction, the",
        "  command-injection sanitizer, and rendering - is the unmodified",
        "  production code path.",
        "- Screenshot 16 (`ai-preview`) uses a small hand-built Finding containing a",
        "  synthetic secret (not from a real FreeIPA host) specifically to make the",
        "  redaction behavior visible in one screenshot.",
        "- Screenshot 20 is the exception to \"all fixtures are hand-authored\": it",
        "  replays genuine `ipa-healthcheck` output captured from an actual",
        "  freeipa/freeipa-server container, not synthetic data - see",
        "  tests/fixtures/real-freeipa-capture/README.md and docs/limitations.md.",
        "",
        "| # | Scenario | Fixture(s) | Expected / observed behavior |",
        "|---|---|---|---|",
    ]
    for name, scenario, fixture, expected, png in INDEX_ROWS:
        lines.append(f"| `{name}` | {scenario} | `{fixture}` | {expected} |")
    (OUT_DIR / "index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT_DIR / 'index.md'}")


def main():
    scenario_healthy()
    scenario_degraded()
    scenario_primary_root_cause()
    scenario_correlated()
    scenario_independent_problems()
    scenario_unknown()
    scenario_details()
    scenario_caution_high_risk()
    scenario_verify_resolved()
    scenario_verify_still_present()
    scenario_no_ai()
    scenario_openai()
    scenario_anthropic()
    scenario_bedrock()
    scenario_ai_failure_fallback()
    scenario_ai_preview()
    scenario_malformed_input()
    scenario_rpm_install()
    scenario_real_freeipa_capture()
    scenario_stale_ruv()
    scenario_environment_metadata()
    scenario_json_output()
    scenario_el9_rpm_install()
    scenario_pypi_pipx_install()
    write_index()


if __name__ == "__main__":
    sys.exit(main())
