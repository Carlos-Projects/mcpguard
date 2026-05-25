from __future__ import annotations

from mcpguard.proxy.metrics import _sanitize_label, render_prometheus


class TestSanitizeLabel:
    def test_normal_string(self):
        assert _sanitize_label("tools/call") == "tools/call"

    def test_escapes_backslash(self):
        assert _sanitize_label("test\\value") == "test\\\\value"

    def test_escapes_quote(self):
        assert _sanitize_label('test"value') == 'test\\"value'

    def test_escapes_newline(self):
        assert _sanitize_label("test\nvalue") == "test\\nvalue"

    def test_non_ascii_replaced(self):
        assert _sanitize_label("test\u00e9value") == "invalid"


class TestRenderPrometheus:
    def test_basic_metrics(self):
        metrics = {
            "total_requests": 10,
            "blocked_requests": 2,
            "injections_detected": 1,
            "poisoning_detected": 0,
            "anomalies_detected": 0,
            "sse_connections": 3,
            "sse_total_connections": 5,
            "tool_calls": {"read_file": 4, "write_file": 2},
            "uptime_seconds": 120,
        }
        output = render_prometheus(metrics)
        assert "mcpguard_total_requests 10" in output
        assert "mcpguard_blocked_requests 2" in output
        assert 'mcpguard_tool_calls_total{tool="read_file"} 4' in output
        assert 'mcpguard_tool_calls_total{tool="write_file"} 2' in output
        assert "mcpguard_uptime_seconds 120" in output
        assert "mcpguard_active_sse_connections 3" in output

    def test_empty_tool_calls(self):
        metrics = {
            "total_requests": 0,
            "blocked_requests": 0,
            "injections_detected": 0,
            "poisoning_detected": 0,
            "anomalies_detected": 0,
            "sse_connections": 0,
            "sse_total_connections": 0,
            "tool_calls": {},
            "uptime_seconds": 0,
        }
        output = render_prometheus(metrics)
        assert "mcpguard_total_requests 0" in output

    def test_sanitize_in_tool_name(self):
        metrics = {
            "total_requests": 1,
            "blocked_requests": 0,
            "injections_detected": 0,
            "poisoning_detected": 0,
            "anomalies_detected": 0,
            "sse_connections": 0,
            "sse_total_connections": 0,
            "tool_calls": {"tool\nwith\nnewlines": 1},
            "uptime_seconds": 0,
        }
        output = render_prometheus(metrics)
        assert 'mcpguard_tool_calls_total{tool="tool\\nwith\\nnewlines"} 1' in output
