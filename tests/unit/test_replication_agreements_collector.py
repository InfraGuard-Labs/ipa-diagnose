"""Unit tests for the replication_agreements collector's live-mode text
parsers, independent of the diagnostic pack. These exercise real
``ipa-replica-manage list-ruv`` output shapes directly (no fixture
directory/--replay involved) since the bug this regresses (an over-strict
``ldap://`` prefix requirement that real output never has) was in that
parser, not in any pack rule."""

from __future__ import annotations

import subprocess

import pytest

from ipa_diagnose.evidence.collectors.base import CollectorError
from ipa_diagnose.evidence.collectors.replication_agreements import (
    ReplicationAgreementsCollector,
    _parse_list_ruv_output,
    _parse_list_output,
)


def test_real_list_ruv_format_has_no_scheme_prefix():
    """Confirmed against real `ipa-replica-manage list-ruv` output (and
    current upstream FreeIPA source): lines are `host:port: replica_id`,
    never `ldap://host:port: replica_id`. This was the live-mode bug - the
    old regex required a literal "ldap://" that never actually appears."""

    stdout = "Replica Update Vectors:\nipa01.example.test:389: 4\nipa02.example.test:389: 5\n"
    items = _parse_list_ruv_output(
        stdout, known_hosts={"ipa01.example.test", "ipa02.example.test"}, hosts_known_complete=True, command="test"
    )
    assert len(items) == 2
    assert {i.data["replica_id"] for i in items} == {4, 5}
    assert all(i.data["alive"] is True for i in items)
    assert all(i.data["suffix"] == "domain" for i in items)


def test_optional_ldap_scheme_prefix_still_tolerated():
    stdout = "Replica Update Vectors:\nldap://ipa01.example.test:389: 4\n"
    items = _parse_list_ruv_output(stdout, known_hosts={"ipa01.example.test"}, hosts_known_complete=True, command="test")
    assert len(items) == 1
    assert items[0].data["replica_id"] == 4
    assert items[0].data["alive"] is True


def test_unknown_host_with_complete_known_hosts_is_false_not_none():
    stdout = "Replica Update Vectors:\nipa01.example.test:389: 4\ngone.example.test:389: 9\n"
    items = _parse_list_ruv_output(
        stdout, known_hosts={"ipa01.example.test"}, hosts_known_complete=True, command="test"
    )
    stale = next(i for i in items if i.data["replica_id"] == 9)
    assert stale.data["alive"] is False


def test_incomplete_known_hosts_yields_none_not_false():
    """If agreement listing (the source of known_hosts) failed, an unknown
    host must be reported as "cannot determine" (None), never as a
    confident False - an incomplete peer list must not manufacture a false
    stale RUV for a replica that might be perfectly fine."""

    stdout = "Replica Update Vectors:\nipa01.example.test:389: 4\nunlisted.example.test:389: 9\n"
    items = _parse_list_ruv_output(
        stdout, known_hosts={"ipa01.example.test"}, hosts_known_complete=False, command="test"
    )
    uncertain = next(i for i in items if i.data["replica_id"] == 9)
    assert uncertain.data["alive"] is None
    # Self/known host is still confidently alive regardless.
    known = next(i for i in items if i.data["replica_id"] == 4)
    assert known.data["alive"] is True


def test_cs_ruv_section_is_tagged_separately_from_domain_ruv():
    stdout = (
        "Replica Update Vectors:\n"
        "ipa01.example.test:389: 4\n"
        "\n"
        "Certificate Server Replica Update Vectors:\n"
        "ipa01.example.test:389: 4\n"
    )
    items = _parse_list_ruv_output(stdout, known_hosts={"ipa01.example.test"}, hosts_known_complete=True, command="test")
    assert len(items) == 2
    suffixes = {i.data["suffix"] for i in items}
    assert suffixes == {"domain", "ca"}
    # Same replica_id in both sections must not collide into one item.
    item_ids = {i.item_id for i in items}
    assert len(item_ids) == 2


def test_duplicate_ruv_lines_are_deduplicated_not_double_counted():
    stdout = "Replica Update Vectors:\nipa01.example.test:389: 4\nipa01.example.test:389: 4\n"
    items = _parse_list_ruv_output(stdout, known_hosts={"ipa01.example.test"}, hosts_known_complete=True, command="test")
    assert len(items) == 1


def test_malformed_and_stray_lines_are_ignored_without_crashing():
    """A stray warning/log line mixed into the output (the EL8-era Python
    deprecation-warning risk flagged in review) must simply not match, not
    raise and not be misread as a bogus peer/RID pair."""

    stdout = (
        "Replica Update Vectors:\n"
        "ipa01.example.test:389: 4\n"
        "DeprecationWarning: something something\n"
        "not a ruv line at all\n"
        "ipa02.example.test:389: not-a-number\n"
        "ipa03.example.test: 6\n"  # missing port - not the real shape, must not match
    )
    items = _parse_list_ruv_output(stdout, known_hosts={"ipa01.example.test"}, hosts_known_complete=True, command="test")
    assert len(items) == 1
    assert items[0].data["replica_id"] == 4


def test_empty_output_yields_no_items_no_crash():
    assert _parse_list_ruv_output("", known_hosts=set(), hosts_known_complete=True, command="test") == []


class _FakeProc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_agreement_list_failure_does_not_block_ruv_collection(monkeypatch):
    """The core decoupling fix: `list <host>` failing (e.g. a transient
    permission issue) must not prevent `list-ruv` from running at all - RUV
    evidence is independently valuable and was previously lost entirely
    whenever the agreement listing failed for any reason."""

    collector = ReplicationAgreementsCollector()
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[:2] == ["ipa-replica-manage", "list"]:
            return _FakeProc(1, stderr="ipa: ERROR: Insufficient access")
        if args[:2] == ["ipa-replica-manage", "list-ruv"]:
            return _FakeProc(0, stdout="Replica Update Vectors:\nipa01.example.test:389: 4\n")
        raise AssertionError(f"unexpected command {args}")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/sbin/" + name)
    monkeypatch.setattr("socket.gethostname", lambda: "ipa01.example.test")

    items = collector.collect_live()
    ruv_items = [i for i in items if i.kind == "replication_ruv"]
    assert len(ruv_items) == 1
    # agreement listing failed, so known_hosts is incomplete for anything
    # other than self - but ipa01 (self) is still confidently alive.
    assert ruv_items[0].data["alive"] is True


def test_both_commands_failing_raises_collector_error(monkeypatch):
    collector = ReplicationAgreementsCollector()

    def fake_run(args, **kwargs):
        return _FakeProc(1, stderr="ipa: ERROR: Insufficient access")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("shutil.which", lambda name: "/usr/sbin/" + name)
    monkeypatch.setattr("socket.gethostname", lambda: "ipa01.example.test")

    with pytest.raises(CollectorError):
        collector.collect_live()


def test_agreement_list_parser_still_works_unchanged():
    """Sanity check that the unrelated `list <host>` parser (agreements, not
    RUVs) was not affected by the RUV-parser changes above."""

    stdout = "ipa02.example.test\n  last update status: Error (0) Replica acquired successfully: ...\n"
    items = _parse_list_output(stdout, command="test")
    assert len(items) == 1
    assert items[0].data["peer"] == "ipa02.example.test"
    assert items[0].data["status"] == "green"
