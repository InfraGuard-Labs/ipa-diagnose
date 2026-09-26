"""The service procedure's promotion to BUILT_IN_VERIFIED (maintainer decision after the Slice 1 truth validation).

The promotion is a provenance change only: the definitive label applies to the exact live-verified environment
(FreeIPA 4.13.3 / Fedora 43); applicability gates are unchanged; the other procedures keep their tiers."""

from __future__ import annotations

import io
import json

import pytest
from rich.console import Console

from ipa_diagnose.evidence.model import EnvironmentInfo
from ipa_diagnose.render.console import render_report
from ipa_diagnose.render.json_output import report_to_dict
from ipa_diagnose.resolution import knowledge as K
from ipa_diagnose.resolution.engine import NONE, OFFERED, WITHHELD

from tests.resolution.test_procedures import DIRSRV_DOWN, ROOT_OK, SERVICE_OK, perm, report_for, res_of, stat

SVC = "healthcheck.service-not-running"
EXACT = EnvironmentInfo(distro="fedora", distro_version="43", freeipa_version="4.13.3-2.fc43")


def _cat():
    return {p["id"]: p for p in K.load_catalogue()[0]}


def test_catalogue_tiers_are_exactly_the_approved_ones():
    cat = _cat()
    assert cat["proc.service.start-stopped-service"]["provenance"]["tier"] == "BUILT_IN_VERIFIED"
    assert cat["proc.files.restore-expected-permissions"]["provenance"]["tier"] == "LIVE_VERIFIED"
    assert cat["proc.time.step-clock-with-chrony"]["provenance"]["tier"] == "FIXTURE_ONLY"
    assert cat["proc.certs.renew-expiring-ds-certificate"]["provenance"]["tier"] == "FIXTURE_ONLY"
    assert cat["none.certs.expired-ds-certificate"]["kind"] == "no_procedure"


def test_promotion_keeps_the_live_record_and_the_applicability():
    p = _cat()["proc.service.start-stopped-service"]
    assert p["applies_to"] == {"freeipa_min": "4.9", "freeipa_below": "5.0", "roles": ["ipa-server"]}
    live = [v for v in p["provenance"]["verified_on"] if v["tier"] == "LIVE"]
    assert live == [{"freeipa": "4.13.3", "os": "fedora-43", "tier": "LIVE", "date": "2026-09-26",
                     "evidence": "https://github.com/InfraGuard-Labs/ipa-diagnose/actions/runs/36258032392"}]
    assert any(r["independent"] is True for r in p["provenance"]["reviews"])


def test_exact_live_verified_environment_gets_the_definitive_label():
    r = res_of(report_for(DIRSRV_DOWN, SERVICE_OK, env=EXACT)[0], SVC)
    assert r.status == OFFERED and r.tier == "BUILT_IN_VERIFIED" and r.definitive
    assert r.verification_label == "Verified in a live lab on FreeIPA 4.13.3 / fedora-43; independently reviewed."


@pytest.mark.parametrize("env", [
    EnvironmentInfo(distro="fedora", distro_version="43", freeipa_version="4.13.2-1.fc43"),    # other patch level
    EnvironmentInfo(distro="fedora", distro_version="42", freeipa_version="4.13.3-1.fc42"),    # other OS release
    EnvironmentInfo(distro="rhel", distro_version="9.6", freeipa_version="4.12.2-15.el9"),     # other OS and version
    EnvironmentInfo(distro="almalinux", distro_version="8.10", freeipa_version="4.9.13-12.module_el8"),
])
def test_other_environments_in_range_are_offered_but_never_definitive(env):
    """Unchanged applicability (offered) - but the built-in-verified claim does not extend to them."""
    r = res_of(report_for(DIRSRV_DOWN, SERVICE_OK, env=env)[0], SVC)
    assert r.status == OFFERED and not r.definitive
    assert "only - not yet on this FreeIPA version/OS" in r.verification_label


@pytest.mark.parametrize("env", [
    EnvironmentInfo(distro="fedora", distro_version="43", freeipa_version="5.0.0-1.fc43"),     # at/above the range
    EnvironmentInfo(distro="rhel", distro_version="8.4", freeipa_version="4.8.10-1.el8"),      # below the range
    EnvironmentInfo(distro="fedora", distro_version="43", freeipa_version=None),               # unknown version
    EnvironmentInfo(distro="fedora", distro_version="43", freeipa_version="4.13.3; rm -rf /"),  # malformed
    None,                                                                                      # no environment
])
def test_wrong_or_unknown_version_still_withholds(env):
    r = res_of(report_for(DIRSRV_DOWN, SERVICE_OK, env=env)[0], SVC)
    assert r.status == WITHHELD and not r.steps and not r.definitive


def test_live_gates_still_apply_on_the_exact_environment():
    from tests.resolution.test_procedures import unit

    r = res_of(report_for(DIRSRV_DOWN, {**SERVICE_OK, "systemd.unit|service=dirsrv": unit(load="masked")}, env=EXACT)[0], SVC)
    assert r.status == WITHHELD and not r.steps


def test_json_carries_tier_definitive_and_label():
    report, _ = report_for(DIRSRV_DOWN, SERVICE_OK, env=EXACT)
    res = [x for x in report_to_dict(report)["v2"]["resolutions"] if x["procedure_id"] == "proc.service.start-stopped-service"][0]
    assert res["tier"] == "BUILT_IN_VERIFIED" and res["definitive"] is True
    assert res["steps"][0]["argv"] == ["systemctl", "start", "dirsrv@LAB-TEST.service"]
    other, _ = report_for(DIRSRV_DOWN, SERVICE_OK, env=EnvironmentInfo(distro="rhel", distro_version="9.6", freeipa_version="4.12.2-15.el9"))
    res2 = [x for x in report_to_dict(other)["v2"]["resolutions"] if x["procedure_id"] == "proc.service.start-stopped-service"][0]
    assert res2["tier"] == "BUILT_IN_VERIFIED" and res2["definitive"] is False and "not yet on this" in res2["verification_label"]


def test_console_shows_the_label_honestly():
    def text(env, details=False):
        report, _ = report_for(DIRSRV_DOWN, SERVICE_OK, env=env)
        buf = io.StringIO()
        render_report(report, Console(file=buf, width=200, color_system=None), details=details)
        return buf.getvalue()

    exact = text(EXACT, details=True)
    assert "systemctl start dirsrv@LAB-TEST.service" in exact
    assert "knowledge tier: BUILT_IN_VERIFIED" in exact and "independently reviewed" in exact
    assert "not yet on this FreeIPA version/OS" not in exact
    other = text(EnvironmentInfo(distro="rhel", distro_version="9.6", freeipa_version="4.12.2-15.el9"))
    assert "not yet on this FreeIPA version/OS" in other


def test_file_procedure_is_never_definitive_even_on_the_exact_environment():
    cs = "/var/lib/pki/pki-tomcat/conf/ca/CS.cfg"
    r = res_of(report_for([perm()], {**ROOT_OK, f"file.stat|path={cs}": stat()}, env=EXACT)[0], "directory-server.ipa-file-permissions")
    assert r.status == OFFERED and r.tier == "LIVE_VERIFIED" and not r.definitive
    assert "has not promoted it to built-in verified" in r.verification_label


def test_verify_of_the_promoted_fix_is_unchanged():
    from ipa_diagnose.verify import VerifyOutcome, compare

    from tests.resolution.test_procedures import FakeRunner, ok

    before, _ = report_for(DIRSRV_DOWN, SERVICE_OK, env=EXACT)
    prev = json.loads(json.dumps(report_to_dict(before)))
    after, _ = report_for([], {**ROOT_OK}, env=EXACT)
    running = ok({"unit": "dirsrv@LAB-TEST.service", "start_method": "ipactl", "load_state": "loaded", "active_state": "active",
                  "sub_state": "running", "unit_file_state": "enabled", "result": "success"})
    stopped = ok({"unit": "dirsrv@LAB-TEST.service", "start_method": "ipactl", "load_state": "loaded", "active_state": "inactive",
                  "sub_state": "dead", "unit_file_state": "enabled", "result": "success"})
    assert compare(prev, after, runner=FakeRunner({**SERVICE_OK, "systemd.unit|service=dirsrv": running})).items[0].outcome == VerifyOutcome.RESOLVED
    assert compare(prev, after, runner=FakeRunner({**SERVICE_OK, "systemd.unit|service=dirsrv": stopped})).items[0].outcome == VerifyOutcome.PARTIALLY_RESOLVED


def test_expired_ds_certificate_still_has_no_deterministic_fix():
    from tests.resolution.test_procedures import DS_OK, nss

    r = res_of(report_for([nss(key="DSCERTLE0002", verb="has expired")], DS_OK, env=EXACT)[0], "directory-server.certificate-expiry")
    assert r.status == NONE and not r.steps and r.procedure_id == "none.certs.expired-ds-certificate"
