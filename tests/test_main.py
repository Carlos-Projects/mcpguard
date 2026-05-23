import json
from datetime import datetime
from pathlib import Path

from mcpguard.main import AppState, ProxyConfig, SecurityEvent


class TestSecurityEvent:
    def test_to_dict(self):
        ev = SecurityEvent(
            event_type="test",
            severity="high",
            message="test event",
            details={"key": "value"},
            blocked=True,
        )
        d = ev.to_dict()
        assert d["event_type"] == "test"
        assert d["severity"] == "high"
        assert d["blocked"] is True
        assert "timestamp" in d

    def test_default_blocked(self):
        ev = SecurityEvent(
            event_type="test", severity="low", message="msg", details={}
        )
        assert ev.blocked is False


class TestProxyConfig:
    def test_defaults(self):
        config = ProxyConfig()
        assert config.listen_host == "127.0.0.1"
        assert config.listen_port == 8080
        assert config.target_url == "http://localhost:8000"

    def test_from_dict(self):
        config = ProxyConfig.from_dict({
            "port": 9090,
            "target": "http://example.com:8000",
            "allow": ["tool1", "tool2"],
            "deny": ["bad_tool"],
        })
        assert config.listen_port == 9090
        assert config.target_url == "http://example.com:8000"
        assert "tool1" in config.allowlisted_tools
        assert "bad_tool" in config.denylisted_tools


class TestAppState:
    def test_initial_metrics(self):
        state = AppState()
        assert state.metrics["total_requests"] == 0
        assert state.metrics["injections_detected"] == 0

    def test_log_event(self, tmp_path: Path):
        config = ProxyConfig(log_dir=tmp_path / "logs")
        state = AppState(config=config)
        ev = SecurityEvent(
            event_type="test", severity="info", message="test", details={}
        )
        state.log_event(ev)
        assert len(state.events) == 1
        log_files = list(config.log_dir.glob("*.jsonl"))
        assert len(log_files) == 1
        with open(log_files[0]) as f:
            data = json.loads(f.readline())
            assert data["event_type"] == "test"

    def test_get_events_since(self):
        state = AppState()
        state.log_event(SecurityEvent(
            event_type="a", severity="info", message="a", details={}
        ))
        recent = state.get_events_since()
        assert len(recent) == 1
