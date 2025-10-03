import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ai-service"))

from agents.redaction import redact_text, redact_dict


class TestRedactionUtils:
    def test_redact_bearer_token(self):
        text = "Authorization: Bearer sk-1234567890abcdef"
        result = redact_text(text)
        assert "[REDACTED]" in result
        assert "sk-1234567890abcdef" not in result

    def test_redact_api_key(self):
        text = "api_key=secret123456789"
        result = redact_text(text)
        assert "[REDACTED]" in result
        assert "secret123456789" not in result

    def test_redact_api_key_colon(self):
        text = "API-Key: sensitive_value_here"
        result = redact_text(text)
        assert "[REDACTED]" in result
        assert "sensitive_value_here" not in result

    def test_redact_authorization_header(self):
        text = "Authorization: Basic dXNlcjpwYXNzd29yZA=="
        result = redact_text(text)
        assert "[REDACTED]" in result
        assert "dXNlcjpwYXNzd29yZA==" not in result

    def test_redact_multiple_secrets(self):
        text = "Bearer token123 and api_key=secret456"
        result = redact_text(text)
        assert result.count("[REDACTED]") == 2
        assert "token123" not in result
        assert "secret456" not in result

    def test_redact_no_secrets(self):
        text = "This is a normal log message"
        result = redact_text(text)
        assert result == text
        assert "[REDACTED]" not in result

    def test_redact_truncation(self):
        long_text = "x" * 3000
        result = redact_text(long_text, max_len=2000)
        assert len(result) <= 2000
        assert "[TRUNCATED]" in result

    def test_redact_none_input(self):
        result = redact_text(None)
        assert result == ""

    def test_redact_empty_string(self):
        result = redact_text("")
        assert result == ""

    def test_redact_dict_simple(self):
        data = {"user": "john", "token": "Bearer secret123"}
        result = redact_dict(data)
        assert result["user"] == "john"
        assert "[REDACTED]" in result["token"]
        assert "secret123" not in result["token"]

    def test_redact_dict_nested(self):
        data = {
            "request": {
                "headers": {"Authorization": "Bearer token123"},
                "body": "normal data",
            },
            "response": {"status": 200},
        }
        result = redact_dict(data)
        assert "[REDACTED]" in result["request"]["headers"]["Authorization"]
        assert "token123" not in str(result)
        assert result["request"]["body"] == "normal data"
        assert result["response"]["status"] == 200

    def test_redact_dict_preserves_non_strings(self):
        data = {"count": 42, "active": True, "items": ["a", "b"]}
        result = redact_dict(data)
        assert result["count"] == 42
        assert result["active"] is True
        assert result["items"] == ["a", "b"]

    def test_redact_dict_empty(self):
        result = redact_dict({})
        assert result == {}

    def test_case_insensitive_bearer(self):
        variations = ["Bearer token", "bearer token", "BEARER token"]
        for text in variations:
            result = redact_text(text)
            assert "[REDACTED]" in result

    def test_case_insensitive_api_key(self):
        variations = ["api_key=secret", "API_KEY=secret", "Api-Key=secret"]
        for text in variations:
            result = redact_text(text)
            assert "[REDACTED]" in result
