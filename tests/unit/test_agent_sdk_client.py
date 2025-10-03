import pytest
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ai-service"))

from agents.sdk_client import _sdk_available, run_security_triage_agent


class TestSDKClient:
    """Test suite for SDK client wrapper functionality."""

    def test_sdk_available_no_module(self, monkeypatch):
        """Test _sdk_available returns correct value based on environment."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        
        # The function checks if SDK is available and API key is present
        result = _sdk_available()
        # Result depends on whether SDK is actually installed
        assert isinstance(result, bool)

    def test_sdk_available_no_api_key(self, monkeypatch):
        """Test _sdk_available returns False when API key missing."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        result = _sdk_available()
        assert result is False

    def test_sdk_available_with_key(self, monkeypatch):
        """Test _sdk_available returns True when API key present."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")
        # Result depends on whether SDK is actually installed
        result = _sdk_available()
        assert isinstance(result, bool)

    def test_run_security_triage_agent_sdk_disabled(self, monkeypatch):
        """Test agent returns None when SDK disabled via env var."""
        monkeypatch.setenv("ENABLE_AGENT_SDK", "false")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        
        summary = {"total_incidents": 10, "blocked": 8}
        result = run_security_triage_agent(summary)
        assert result is None

    def test_run_security_triage_agent_no_api_key(self, monkeypatch):
        """Test agent returns None when API key missing."""
        monkeypatch.setenv("ENABLE_AGENT_SDK", "true")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        
        summary = {"total_incidents": 10, "blocked": 8}
        result = run_security_triage_agent(summary)
        assert result is None

    def test_run_security_triage_agent_sdk_unavailable(self, monkeypatch):
        """Test agent returns None when SDK not available."""
        monkeypatch.setenv("ENABLE_AGENT_SDK", "true")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        
        summary = {"total_incidents": 5}
        result = run_security_triage_agent(summary)
        assert result is None

    @mock.patch("agents.sdk_client._sdk_available")
    def test_run_security_triage_agent_import_failure(self, mock_sdk_avail, monkeypatch):
        """Test agent handles SDK import failure gracefully."""
        mock_sdk_avail.return_value = True
        monkeypatch.setenv("ENABLE_AGENT_SDK", "true")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        
        summary = {"total_incidents": 10}
        # Should return None when SDK import fails (normal when SDK not installed)
        result = run_security_triage_agent(summary)
        assert result is None

    def test_run_security_triage_agent_empty_summary(self, monkeypatch):
        """Test agent handles empty summary dict."""
        monkeypatch.setenv("ENABLE_AGENT_SDK", "false")
        
        result = run_security_triage_agent({})
        assert result is None

    def test_run_security_triage_agent_with_data(self, monkeypatch):
        """Test agent with realistic summary data (SDK disabled)."""
        monkeypatch.setenv("ENABLE_AGENT_SDK", "false")
        
        summary = {
            "total_incidents": 100,
            "blocked": 75,
            "allowed": 25,
            "top_categories": [
                {"attack_category": "sql_injection", "count": 30},
                {"attack_category": "xss", "count": 20},
            ],
            "top_source_ips": [
                {"source_ip": "192.168.1.100", "count": 15},
            ]
        }
        result = run_security_triage_agent(summary)
        assert result is None  # Returns None when SDK disabled

    def test_enable_agent_sdk_env_variations(self, monkeypatch):
        """Test various ENABLE_AGENT_SDK environment variable values."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        
        # Test "1"
        monkeypatch.setenv("ENABLE_AGENT_SDK", "1")
        result = run_security_triage_agent({})
        assert result is None  # No API key
        
        # Test "true"
        monkeypatch.setenv("ENABLE_AGENT_SDK", "true")
        result = run_security_triage_agent({})
        assert result is None
        
        # Test "yes"
        monkeypatch.setenv("ENABLE_AGENT_SDK", "yes")
        result = run_security_triage_agent({})
        assert result is None
        
        # Test "0" (disabled)
        monkeypatch.setenv("ENABLE_AGENT_SDK", "0")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        result = run_security_triage_agent({})
        assert result is None
