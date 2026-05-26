from __future__ import annotations

import pytest

from mcpguard.proxy.server import _AuthMiddleware


class FakeRequest:
    def __init__(self, path: str = "/test", headers: dict | None = None, query_params: dict | None = None):
        self.url = type("URL", (), {"path": path.split("?")[0]})()
        self._headers = headers or {}
        self._query_params = query_params or {}

    @property
    def headers(self):
        return self._headers

    @property
    def query_params(self):
        return self._query_params


class FakeResponse:
    def __init__(self, status_code: int = 200):
        self.status_code = status_code


class TestAuthMiddleware:
    @pytest.mark.asyncio
    async def test_no_api_key_allows_all(self):
        middleware = _AuthMiddleware(None, api_key=None)
        called = False

        async def call_next(request):
            nonlocal called
            called = True
            return FakeResponse()

        req = FakeRequest()
        await middleware.dispatch(req, call_next)
        assert called is True

    @pytest.mark.asyncio
    async def test_correct_bearer_token(self):
        middleware = _AuthMiddleware(None, api_key="secret123")

        async def call_next(request):
            return FakeResponse()

        req = FakeRequest(headers={"Authorization": "Bearer secret123"})
        resp = await middleware.dispatch(req, call_next)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_correct_raw_token(self):
        middleware = _AuthMiddleware(None, api_key="secret123")

        async def call_next(request):
            return FakeResponse()

        req = FakeRequest(headers={"Authorization": "secret123"})
        resp = await middleware.dispatch(req, call_next)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_wrong_token_rejected(self):
        middleware = _AuthMiddleware(None, api_key="secret123")

        async def call_next(request):
            return FakeResponse()

        req = FakeRequest(headers={"Authorization": "Bearer wrong"})
        resp = await middleware.dispatch(req, call_next)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_health_path_unprotected(self):
        middleware = _AuthMiddleware(None, api_key="secret123")

        async def call_next(request):
            return FakeResponse()

        req = FakeRequest(path="/health")
        resp = await middleware.dispatch(req, call_next)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_metrics_path_requires_auth(self):
        middleware = _AuthMiddleware(None, api_key="secret123")

        async def call_next(request):
            return FakeResponse()

        req = FakeRequest(path="/metrics")
        resp = await middleware.dispatch(req, call_next)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_metrics_path_with_query_param(self):
        middleware = _AuthMiddleware(None, api_key="secret123")

        async def call_next(request):
            return FakeResponse()

        req = FakeRequest(path="/metrics", query_params={"api_key": "secret123"})
        resp = await middleware.dispatch(req, call_next)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_metrics_path_with_bearer_token(self):
        middleware = _AuthMiddleware(None, api_key="secret123")

        async def call_next(request):
            return FakeResponse()

        req = FakeRequest(path="/metrics", headers={"Authorization": "Bearer secret123"})
        resp = await middleware.dispatch(req, call_next)
        assert resp.status_code == 200
