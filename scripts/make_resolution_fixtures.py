"""Generate the Slice 1 replay fixtures under tests/fixtures/resolution/ (deterministic, reviewable output).

Each fixture is CONSTRUCTED: an upstream-shaped ipa-healthcheck result plus recorded results of the
read-only checks the procedure runs (resolution_checks.json). They exercise rendering, JSON and the
lifecycle/post-publish gates; the live lab is what proves the procedures on a real server.

Usage: python scripts/make_resolution_fixtures.py
"""

from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "resolution"
ENV = {"distro": "fedora", "distro_version": "43", "freeipa_version": "4.13.3-2.fc43",
       "ipa_healthcheck_version": "0.19-2.fc43", "directory_server_version": "3.1.4-9.fc43"}
SERVICES = ["dirsrv", "krb5kdc", "httpd", "certmonger", "chronyd"]


def hc(uid, source, check, result, **kw):
    return {"source": source, "check": check, "result": result, "uuid": f"res-{uid}", "when": "20260924120000Z",
            "duration": "0.01", "kw": kw}


def services(down=()):
    out = []
    for s in SERVICES:
        if s in down:
            out.append(hc(f"svc-{s}", "ipahealthcheck.meta.services", s, "ERROR", status=False, msg=f"{s}: not running"))
        else:
            out.append(hc(f"svc-{s}", "ipahealthcheck.meta.services", s, "SUCCESS", status=True))
    return out


def ok(fields, display, command=""):
    return {"status": "OK", "fields": fields, "display": display, "command": command}


ROOT_OK = {"host.privilege|": ok({"is_root": True}, "running as root")}


def write(name, scenario, expected_status, expected_procedure, healthcheck, checks):
    d = ROOT / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "healthcheck.json").write_text(json.dumps(healthcheck, indent=1) + "\n", encoding="utf-8")
    (d / "resolution_checks.json").write_text(json.dumps(checks, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    meta = {"hostname": "ipa01.lab.test", "scenario": f"CONSTRUCTED (upstream-shaped): {scenario}",
            "expected_overall_status": expected_status, "expected_resolution": expected_procedure,
            "environment": ENV, "expected_diagnoses": []}
    (d / "meta.json").write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")


def main():
    # 1. dirsrv stopped
    write("service-not-running", "Directory Server stopped", "CRITICAL", "proc.service.start-stopped-service",
          services(down=["dirsrv"]), {
              **ROOT_OK,
              "systemd.unit|service=dirsrv": ok({"unit": "dirsrv@LAB-TEST.service", "start_method": "ipactl", "load_state": "loaded",
                                                 "active_state": "inactive", "sub_state": "dead", "unit_file_state": "enabled",
                                                 "result": "success"}, "dirsrv@LAB-TEST.service: inactive (dead)",
                                                "systemctl show dirsrv@LAB-TEST.service"),
              "systemd.journal_tail|unit=dirsrv@LAB-TEST.service": ok({"lines": 12, "last_line": "Stopped 389 Directory Server LAB-TEST.."},
                                                                      "last log line: Stopped 389 Directory Server LAB-TEST.."),
              "binary.present|name=ipactl": ok({"present": True}, "ipactl: installed"),
          })
    # 2. CS.cfg mode 0664 (the real container-image quirk seen live in v0.1.3)
    path = "/var/lib/pki/pki-tomcat/conf/ca/CS.cfg"
    write("file-permissions", "CS.cfg mode 0664, expected 0660", "DEGRADED", "proc.files.restore-expected-permissions",
          services() + [hc("tomcat", "ipahealthcheck.ipa.files", "TomcatFileCheck", "WARNING",
                           key="_var_lib_pki_pki-tomcat_conf_ca_CS.cfg_mode", path=path, type="mode", expected="0660",
                           got="0664", msg=f"Permissions of {path} are too permissive: 0664 and should be 0660")], {
              **ROOT_OK,
              f"file.stat|path={path}": ok({"exists": True, "is_symlink": False, "is_regular": True, "is_dir": False,
                                            "mode": "0664", "owner": "pkiuser", "group": "pkiuser"},
                                           f"{path}: mode 0664, owner pkiuser, group pkiuser", f"stat {path}"),
          })
    # 3. clock skew: host keytab kinit fails with clock skew; chronyc shows +421 s
    write("clock-skew", "this host's clock 421 s fast; host keytab kinit fails with clock skew", "DEGRADED",
          "proc.time.step-clock-with-chrony",
          services() + [hc("keytab", "ipahealthcheck.ipa.host", "IPAHostKeytab", "ERROR",
                           msg="Failed to obtain host TGT: Clock skew too great while getting initial credentials")], {
              **ROOT_OK,
              "systemd.unit|service=chronyd": ok({"unit": "chronyd.service", "start_method": "systemctl", "load_state": "loaded",
                                                  "active_state": "active", "sub_state": "running", "unit_file_state": "enabled",
                                                  "result": "success"}, "chronyd.service: active (running)"),
              "chrony.tracking|": ok({"offset_seconds": 421.2, "leap_status": "Normal", "synchronized": True,
                                      "reference": "10.0.0.5"}, "clock offset +421.200 s, leap status Normal"),
              "chrony.sources|": ok({"total": 2, "reachable": 2}, "2 of 2 time source(s) reachable"),
          })
    # clock-skew needs this host's own clock evidence as a collector item
    (ROOT / "clock-skew" / "kerberos_client.json").write_text(json.dumps({
        "clock_sync": {"method": "chronyc", "ntp_synchronized": True, "offset_seconds": 421.2,
                       "raw": "System time     : 421.200000 seconds fast of NTP time"}},
        indent=1) + "\n", encoding="utf-8")
    # 4. DS certificate expiring
    write("ds-certificate-expiring", "Server-Cert expires in 12 days (DSCERTLE0001)", "DEGRADED",
          "proc.certs.renew-expiring-ds-certificate",
          services() + [hc("nss", "ipahealthcheck.ds.nss_ssl", "NssCheck", "ERROR", key="DSCERTLE0001",
                           items=["Expiring Certificate"], msg="The certificate (Server-Cert) will expire in less than 30 days")], {
              **ROOT_OK,
              "ds.instance|": ok({"count": 1, "instance": "LAB-TEST"}, "1 Directory Server instance(s): LAB-TEST"),
              "systemd.unit|service=certmonger": ok({"unit": "certmonger.service", "start_method": "systemctl", "load_state": "loaded",
                                                     "active_state": "active", "sub_state": "running", "unit_file_state": "enabled",
                                                     "result": "success"}, "certmonger.service: active (running)"),
              "certmonger.ds_cert|instance=LAB-TEST,nickname=Server-Cert": ok(
                  {"found": True, "request_id": "20260101120000", "state": "MONITORING", "ca": "IPA", "ca_error": "",
                   "not_after": "(12 days from now)", "not_after_in_days": 12, "post_save_restarts_dirsrv": True},
                  "request 20260101120000: MONITORING, CA IPA, expires in 12 days"),
              "binary.present|name=getcert": ok({"present": True}, "getcert: installed"),
          })
    print("fixtures written to", ROOT)


if __name__ == "__main__":
    main()
