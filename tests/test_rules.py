from mcpguard.main import ProxyConfig
from mcpguard.proxy.rules import RuleEngine


class TestAllowDeny:
    def setup_method(self):
        config = ProxyConfig(
            allowlisted_tools={"get_weather", "search"},
            denylisted_tools={"exec", "shell"},
        )
        self.engine = RuleEngine(config)

    def test_allowed_tool(self):
        assert self.engine.is_allowed("get_weather") is True

    def test_denied_tool(self):
        assert self.engine.is_allowed("exec_bash") is False

    def test_not_in_allowlist(self):
        assert self.engine.is_allowed("delete_all") is False

    def test_empty_method(self):
        assert self.engine.is_allowed("") is True

    def test_deny_overrides_allow(self):
        config = ProxyConfig(
            allowlisted_tools={"exec_bash"},
            denylisted_tools={"exec"},
        )
        engine = RuleEngine(config)
        assert engine.is_allowed("exec_bash") is False


class TestRateLimit:
    def setup_method(self):
        config = ProxyConfig(rate_limit=3, rate_window=60)
        self.engine = RuleEngine(config)

    async def test_under_limit(self):
        result = await self.engine.check_rate("tools/call")
        assert result is None
        result = await self.engine.check_rate("tools/call")
        assert result is None

    async def test_exceeds_limit(self):
        for _ in range(3):
            await self.engine.check_rate("tools/call")
        result = await self.engine.check_rate("tools/call")
        assert result is not None
        assert result.blocked is True
        assert result.event_type == "rate_limit"

    async def test_different_methods_separate(self):
        config = ProxyConfig(rate_limit=1, rate_window=60)
        engine = RuleEngine(config)

        await engine.check_rate("tools/call")
        r1 = await engine.check_rate("tools/call")
        assert r1 is not None

        r2 = await engine.check_rate("tools/list")
        assert r2 is None
