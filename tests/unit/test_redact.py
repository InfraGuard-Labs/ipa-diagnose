from ipa_diagnose.privacy.redact import redact_mapping, redact_text


def test_redacts_aws_key():
    report = redact_text("access key is AKIAABCDEFGHIJKLMNOP in the log")
    assert "AKIAABCDEFGHIJKLMNOP" not in report.redacted_text
    assert "aws_access_key" in report.matches


def test_redacts_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ...\n-----END RSA PRIVATE KEY-----"
    report = redact_text(text)
    assert "MIIBogIBAAJ" not in report.redacted_text
    assert "private_key_block" in report.matches


def test_redacts_by_field_name_regardless_of_value_shape():
    data = {"password": "hunter2", "msg": "connection failed", "bindpw": "s3cr3t"}
    redacted, matches = redact_mapping(data)
    assert redacted["password"] == "[REDACTED]"
    assert redacted["bindpw"] == "[REDACTED]"
    assert redacted["msg"] == "connection failed"
    assert "field:password" in matches
    assert "field:bindpw" in matches


def test_clean_text_is_unmodified():
    report = redact_text("replication agreement to ipa02 is broken")
    assert report.redacted_text == "replication agreement to ipa02 is broken"
    assert not report.anything_redacted
