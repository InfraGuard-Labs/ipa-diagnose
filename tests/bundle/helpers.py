"""Shared helpers for the support-bundle tests (fixtures are CONSTRUCTED; every secret is a fake canary)."""

from __future__ import annotations

import gzip
import io
import json
import pathlib
import shutil
import tarfile
from typing import Dict

from ipa_diagnose.cli import build_parser, _collect_and_diagnose

ROOT = pathlib.Path(__file__).resolve().parents[1] / "fixtures"


def diagnose_replay(fixture: str):
    return _collect_and_diagnose(build_parser().parse_args(["--replay", str(fixture)]))


def members_of(archive_bytes: bytes) -> Dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(archive_bytes)), mode="r:") as tar:
        return {ti.name.split("/", 1)[1]: tar.extractfile(ti).read() for ti in tar}


def all_text(members: Dict[str, bytes]) -> str:
    return "\n".join(m.decode("utf-8") for m in members.values())


def canary_fixture(tmp_path: pathlib.Path) -> pathlib.Path:
    """The peer-unreachable fixture, re-hosted on canary names, with canary secrets planted in every text path the
    bundle reads: ipa-healthcheck messages and keywords, collector items and errors."""

    dst = tmp_path / "canary-fixture"
    shutil.copytree(ROOT / "replication" / "peer-unreachable", dst)
    for f in dst.iterdir():
        text = f.read_text(encoding="utf-8")
        text = text.replace("ipa01.example.test", "zqcanaryhost01.zqcanary-dom.test")
        text = text.replace("ipa02.example.test", "zqcanarypeer02.zqcanary-dom.test")
        text = text.replace("EXAMPLE.TEST", "ZQCANARY-DOM.TEST").replace("example.test", "zqcanary-dom.test")
        text = text.replace("dc\\\\3Dexample\\\\2Cdc\\\\3Dtest", "dc\\\\3Dzqcanary-dom\\\\2Cdc\\\\3Dtest")
        f.write_text(text, encoding="utf-8")
    hc = json.loads((dst / "healthcheck.json").read_text(encoding="utf-8"))
    hc[0]["kw"]["msg"] += (" retrying with password=ZQCANARYPW1 and header Authorization: Bearer ZQCANARYTOK2abc123=="
                           " as user zqcanaryuser@ZQCANARY-DOM.TEST from 10.66.77.88"
                           " -----BEGIN RSA PRIVATE KEY-----\nMIIEZQCANARYKEY3AAKCAQEA\n-----END RSA PRIVATE KEY-----")
    hc[0]["kw"]["bind_password"] = "ZQCANARYPW4"
    hc[0]["kw"]["note"] = "the Directory Manager password is ZQCANARYPROSE5 (do not share)"
    hc.append({"source": "ipahealthcheck.zzz.future", "check": "FutureCheck", "result": "ERROR", "uuid": "fut-1",
               "when": "20260101120000Z", "duration": "0.1",
               "kw": {"key": "fut", "msg": "a check this build does not know failed \x1b[31mred\x1b[0m ‮txt",
                      "cmd": "ldapsearch -D cn=Directory\\ Manager -w ZQCANARYPW6 -H ldap://zqcanarypeer02.zqcanary-dom.test",
                      "detail": "keytab: 0123456789abcdef0123456789abcdef0123abcd",
                      "url": "see ldaps://u:ZQCANARYPW7@db.zqcanary-dom.test",
                      "cloud": "aws AKIAZQCANARY00000008 and sk-ant-ZQCANARYAIKEY9xxxxxxxx"}})
    (dst / "healthcheck.json").write_text(json.dumps(hc), encoding="utf-8")
    lq = json.loads((dst / "ldap_query.json").read_text(encoding="utf-8"))
    lq["keytab_bind"]["error"] = "kinit: Cookie: session=ZQCANARYCOOKIE10abc123 rejected for zqcanaryuser"
    (dst / "ldap_query.json").write_text(json.dumps(lq), encoding="utf-8")
    ra = json.loads((dst / "replication_agreements.json").read_text(encoding="utf-8"))
    ra["agreements"][0]["last_update_status"] += " (credentials: ZQCANARYPW11)"
    (dst / "replication_agreements.json").write_text(json.dumps(ra), encoding="utf-8")
    return dst


CANARIES = ["ZQCANARYPW1", "ZQCANARYTOK2", "ZQCANARYKEY3", "ZQCANARYPW4", "ZQCANARYPROSE5", "ZQCANARYPW6",
            "0123456789abcdef0123456789abcdef", "ZQCANARYPW7", "AKIAZQCANARY", "ZQCANARYAIKEY9", "ZQCANARYCOOKIE10",
            "ZQCANARYPW11", "zqcanaryhost01", "zqcanarypeer02", "zqcanary-dom", "ZQCANARY-DOM", "zqcanaryuser",
            "10.66.77.88", "BEGIN RSA PRIVATE KEY"]
