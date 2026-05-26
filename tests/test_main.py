from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from mcpguard.main import ProxyConfig, SecurityEvent, redact_sensitive_args


class TestSecurityEvent:
    def test_to_dict(self):
        ev = SecurityEvent(
            event_type="test",
            severity="high",
            message="test message",
            details={"key": "value"},
        )
        d = ev.to_dict()
        assert d["event_type"] == "test"
        assert d["severity"] == "high"
        assert d["message"] == "test message"
        assert d["details"] == {"key": "value"}
        assert "timestamp" in d
        assert d["blocked"] is False

    def test_blocked_flag(self):
        ev = SecurityEvent(
            event_type="blocked",
            severity="high",
            message="blocked",
            details={},
            blocked=True,
        )
        assert ev.to_dict()["blocked"] is True


class TestRedactSensitiveArgs:
    def test_no_sensitive_keys(self):
        args = {"name": "test", "value": 123}
        assert redact_sensitive_args(args) == args

    def test_redacts_password(self):
        args = {"password": "secret", "name": "test"}
        result = redact_sensitive_args(args)
        assert result["password"] == "***REDACTED***"
        assert result["name"] == "test"

    def test_redacts_token(self):
        args = {"api_token": "abc123"}
        result = redact_sensitive_args(args)
        assert result["api_token"] == "***REDACTED***"

    def test_redacts_api_key(self):
        args = {"api_key": "secret"}
        result = redact_sensitive_args(args)
        assert result["api_key"] == "***REDACTED***"

    def test_redacts_authorization(self):
        args = {"authorization": "Bearer xyz"}
        result = redact_sensitive_args(args)
        assert result["authorization"] == "***REDACTED***"

    def test_non_dict_passthrough(self):
        assert redact_sensitive_args([1, 2, 3]) == [1, 2, 3]
        assert redact_sensitive_args("string") == "string"


class TestProxyConfigDefaults:
    def test_defaults(self):
        c = ProxyConfig()
        assert c.mode == "http"
        assert c.listen_host == "127.0.0.1"
        assert c.listen_port == 8080
        assert c.rate_limit == 100
        assert c.rate_window == 60
        assert c.block_on_injection is True
        assert c.block_on_poisoning is True
        assert c.max_sse_connections == 100
        assert c.request_timeout == 30.0
        assert c.max_body_size == 10 * 1024 * 1024
        assert c.api_key is None


class TestProxyConfigValidation:
    def test_valid_http(self):
        c = ProxyConfig()
        assert c.validate() == []

    def test_invalid_mode(self):
        c = ProxyConfig(mode="invalid")
        errors = c.validate()
        assert any("Invalid mode" in e for e in errors)

    def test_invalid_port_zero(self):
        c = ProxyConfig(listen_port=0)
        errors = c.validate()
        assert any("Invalid port" in e for e in errors)

    def test_invalid_port_high(self):
        c = ProxyConfig(listen_port=70000)
        errors = c.validate()
        assert any("Invalid port" in e for e in errors)

    def test_negative_rate_limit(self):
        c = ProxyConfig(rate_limit=-1)
        errors = c.validate()
        assert any("rate_limit must be positive" in e for e in errors)

    def test_negative_rate_window(self):
        c = ProxyConfig(rate_window=0)
        errors = c.validate()
        assert any("rate_window must be positive" in e for e in errors)

    def test_stdio_requires_command(self):
        c = ProxyConfig(mode="stdio")
        errors = c.validate()
        assert any("command required" in e for e in errors)

    def test_stdio_with_command_valid(self):
        c = ProxyConfig(mode="stdio", command=["echo", "hello"])
        assert c.validate() == []

    def test_allow_deny_overlap(self):
        c = ProxyConfig(
            allowlisted_tools={"read"},
            denylisted_tools={"read"},
        )
        errors = c.validate()
        assert any("both allow and deny" in e for e in errors)

    def test_negative_timeout(self):
        c = ProxyConfig(request_timeout=-1)
        errors = c.validate()
        assert any("request_timeout must be positive" in e for e in errors)


class TestProxyConfigFromDict:
    def test_basic(self):
        c = ProxyConfig.from_dict({"mode": "http", "listen_port": 9090})
        assert c.mode == "http"
        assert c.listen_port == 9090

    def test_string_command_split(self):
        c = ProxyConfig.from_dict({"mode": "stdio", "command": "python server.py"})
        assert c.command == ["python", "server.py"]

    def test_list_command_preserved(self):
        c = ProxyConfig.from_dict({"mode": "stdio", "command": ["python", "server.py"]})
        assert c.command == ["python", "server.py"]

    def test_allow_deny_aliases(self):
        c = ProxyConfig.from_dict({"allow": ["read"], "deny": ["delete"]})
        assert c.allowlisted_tools == {"read"}
        assert c.denylisted_tools == {"delete"}

    def test_host_alias(self):
        c = ProxyConfig.from_dict({"host": "0.0.0.0", "port": 3000})
        assert c.listen_host == "0.0.0.0"
        assert c.listen_port == 3000

    def test_target_alias(self):
        c = ProxyConfig.from_dict({"target": "http://example.com"})
        assert c.target_url == "http://example.com"

    def test_mcpscop_fields(self):
        c = ProxyConfig.from_dict(
            {
                "mcpscop_url": "http://mcpscop:8080",
                "mcpscop_api_key": "key123",
            }
        )
        assert c.mcpscop_url == "http://mcpscop:8080"
        assert c.mcpscop_api_key == "key123"

    def test_trusted_proxies(self):
        c = ProxyConfig.from_dict({"trusted_proxies": ["10.0.0.1", "10.0.0.2"]})
        assert c.trusted_proxies == {"10.0.0.1", "10.0.0.2"}


class TestProxyConfigFromFile:
    def test_yaml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"mode": "http", "listen_port": 7070}, f)
            f.flush()
            c = ProxyConfig.from_file(f.name)
            assert c.listen_port == 7070
            Path(f.name).unlink()

    def test_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"mode": "http", "listen_port": 6060}, f)
            f.flush()
            c = ProxyConfig.from_file(f.name)
            assert c.listen_port == 6060
            Path(f.name).unlink()

    def test_not_found(self):
        with pytest.raises(FileNotFoundError):
            ProxyConfig.from_file("/nonexistent/config.yaml")

    def test_unsupported_format(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("data")
            f.flush()
            with pytest.raises(ValueError, match="Unsupported"):
                ProxyConfig.from_file(f.name)
            Path(f.name).unlink()


class TestProxyConfigEnvApiKey:
    def test_env_api_key(self, monkeypatch):
        monkeypatch.setenv("MCPGUARD_API_KEY", "env-secret")
        c = ProxyConfig()
        assert c.api_key == "env-secret"

    def test_explicit_api_key_overrides_env(self, monkeypatch):
        monkeypatch.setenv("MCPGUARD_API_KEY", "env-secret")
        c = ProxyConfig(api_key="explicit-secret")
        assert c.api_key == "explicit-secret"
