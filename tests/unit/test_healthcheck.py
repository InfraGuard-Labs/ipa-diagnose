from ipa_diagnose.evidence.healthcheck import parse_healthcheck_json_text, parse_healthcheck_results
from ipa_diagnose.evidence.model import Severity


def test_parses_known_severities():
    raw = parse_healthcheck_json_text(
        '[{"source": "ipahealthcheck.ds.replication", "check": "ReplicationCheck", '
        '"result": "CRITICAL", "uuid": "abc", "kw": {"msg": "broken"}}]'
    )
    findings = parse_healthcheck_results(raw, command="ipa-healthcheck", live=True)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].message == "broken"
    assert findings[0].qualified_check == "ipahealthcheck.ds.replication.ReplicationCheck"


def test_unknown_severity_defaults_to_warning_not_crash():
    raw = [{"source": "x", "check": "y", "result": "SOMETHING_NEW_FROM_2030", "kw": {}}]
    findings = parse_healthcheck_results(raw, command="test", live=False)
    assert findings[0].severity == Severity.WARNING


def test_ignores_non_dict_entries():
    raw = [{"source": "x", "check": "y", "result": "SUCCESS", "kw": {}}, "garbage", None, 42]
    findings = parse_healthcheck_results(raw, command="test", live=False)
    assert len(findings) == 1


def test_critical_result_with_no_msg_key_falls_back_to_exception():
    """Found via real FreeIPA server validation: a check plugin that itself
    raises an uncaught exception produces a CRITICAL result with NO `msg`
    key at all - only `kw.exception`/`kw.traceback`. Confirmed against a
    real capture (IPAauthzdatapacCheck raising AttributeError when LDAP was
    down). Without this fallback, the finding's message silently became an
    empty string, discarding the only diagnostic content it had."""

    raw = [
        {
            "source": "ipahealthcheck.ipa.trust",
            "check": "IPAauthzdatapacCheck",
            "result": "CRITICAL",
            "uuid": "real-capture-example",
            "kw": {
                "exception": "ldap2 is not connected (ldap2_140334627694848 in MainThread)",
                "traceback": "Traceback (most recent call last):\n  ...\nAttributeError: ldap2 is not connected\n",
            },
        }
    ]
    findings = parse_healthcheck_results(raw, command="test", live=False)
    assert findings[0].message == "ldap2 is not connected (ldap2_140334627694848 in MainThread)"


def test_critical_result_with_only_traceback_uses_last_line():
    raw = [
        {
            "source": "x",
            "check": "y",
            "result": "CRITICAL",
            "kw": {"traceback": "Traceback (most recent call last):\n  ...\nValueError: something broke\n"},
        }
    ]
    findings = parse_healthcheck_results(raw, command="test", live=False)
    assert findings[0].message == "ValueError: something broke"


def test_rejects_non_array_top_level():
    import pytest

    with pytest.raises(ValueError):
        parse_healthcheck_json_text('{"foo": 1}')
