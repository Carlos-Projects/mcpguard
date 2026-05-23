from mcpguard.proxy.inspector import MessageInspector


class TestInspector:
    def setup_method(self):
        self.inspector = MessageInspector()

    def test_request(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        result = self.inspector.inspect(msg)
        assert result["type"] == "request"
        assert result["method"] == "tools/list"
        assert result["id"] == 1

    def test_notification(self):
        msg = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        result = self.inspector.inspect(msg)
        assert result["type"] == "notification"
        assert result["method"] == "notifications/initialized"

    def test_response(self):
        msg = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        result = self.inspector.inspect(msg)
        assert result["type"] == "response"

    def test_error(self):
        msg = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "Method not found"}}
        result = self.inspector.inspect(msg)
        assert result["type"] == "error"

    def test_get_tool_name(self):
        msg = {
            "method": "tools/call",
            "params": {"name": "get_weather", "arguments": {"city": "Tokyo"}},
        }
        assert self.inspector.get_tool_name(msg) == "get_weather"

    def test_get_tool_arguments(self):
        msg = {
            "method": "tools/call",
            "params": {"name": "get_weather", "arguments": {"city": "Tokyo"}},
        }
        args = self.inspector.get_tool_arguments(msg)
        assert args == {"city": "Tokyo"}
