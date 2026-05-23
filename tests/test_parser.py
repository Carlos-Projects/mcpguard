from mcpguard.utils.mcp_parser import (
    extract_batch_messages,
    format_message,
    is_known_method,
    is_mcp_request,
    is_mcp_response,
    parse_message,
)


class TestParser:
    def test_parse_message_dict(self):
        result = parse_message({"method": "ping"})
        assert result == {"method": "ping"}

    def test_parse_message_json_str(self):
        result = parse_message('{"method": "ping"}')
        assert result == {"method": "ping"}

    def test_parse_message_invalid(self):
        result = parse_message("not json")
        assert result is None

    def test_is_mcp_request(self):
        assert is_mcp_request({"method": "ping", "id": 1}) is True

    def test_is_mcp_notification(self):
        assert is_mcp_request({"method": "ping"}) is False

    def test_is_mcp_response(self):
        assert is_mcp_response({"result": {}}) is True
        assert is_mcp_response({"error": {}}) is True
        assert is_mcp_response({"method": "ping"}) is False

    def test_is_known_method(self):
        assert is_known_method({"method": "tools/list"}) is True
        assert is_known_method({"method": "tools/call"}) is True
        assert is_known_method({"method": "unknown/method"}) is False

    def test_format_message_compact(self):
        msg = {"method": "tools/list", "id": 1}
        result = format_message(msg, compact=True)
        assert "method=tools/list" in result
        assert "id=1" in result

    def test_extract_batch_messages_single(self):
        result = extract_batch_messages('{"method": "ping"}')
        assert len(result) == 1

    def test_extract_batch_messages_invalid(self):
        result = extract_batch_messages("")
        assert result == []
