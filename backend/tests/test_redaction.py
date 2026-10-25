from app.utils.redaction import redact_secret_string, redact_text

def test_redact_secret_string():
    assert redact_secret_string("AKIA1234567890ABCDEF") == "AKI***REDACTED***"
    assert redact_secret_string("short") == "[REDACTED]"
    assert redact_secret_string("") == "[REDACTED]"

def test_redact_text_aws_key():
    snippet = "aws_key = 'AKIAIOSFODNN7EXAMPLE'"
    redacted = redact_text(snippet)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "REDACTED" in redacted

def test_redact_private_key():
    key_snippet = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----"
    redacted = redact_text(key_snippet)
    assert "MIIEowIBAAKCAQEA0" not in redacted
    assert "REDACTED PRIVATE KEY" in redacted

def test_redact_token_assignment():
    snippet = 'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";'
    redacted = redact_text(snippet)
    assert "1234567890abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "REDACTED" in redacted
