from __future__ import annotations

import asyncio
import hmac
import json
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from importlib.metadata import version as _pkg_version
from typing import Any

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

import mcpguard.detectors.prompt_injection  # noqa: F401
import mcpguard.detectors.resource_prompt  # noqa: F401
import mcpguard.detectors.tool_poisoning  # noqa: F401
from mcpguard.detectors.anomalies import AnomalyDetector
from mcpguard.detectors.base import registry
from mcpguard.main import AppState, ProxyConfig, SecurityEvent
from mcpguard.proxy.cache import ToolCache
from mcpguard.proxy.circuit_breaker import CircuitBreaker
from mcpguard.proxy.inspector import MessageInspector
from mcpguard.proxy.metrics import render_prometheus
from mcpguard.proxy.rules import RuleEngine
from mcpguard.proxy.session import SessionManager
from mcpguard.transport.http import HTTPTransport
from mcpguard.transport.stdio import StdioTransport

logger = logging.getLogger("mcpguard")

PROXY_VERSION = _pkg_version("mcpguard-proxy")
MAX_BODY_SIZE = 10 * 1024 * 1024

_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}


def _make_transport(config: ProxyConfig) -> HTTPTransport | None:
    if config.mode == "http":
        return HTTPTransport(
            target_url=config.target_url,
            sse_path=config.sse_path,
            messages_path=config.messages_path,
            timeout=config.request_timeout,
        )
    return None


def _make_stdio_transport(config: ProxyConfig) -> StdioTransport | None:
    if config.mode == "stdio" and config.command:
        return StdioTransport(command=config.command, env=config.env)
    return None


def _redact(value: Any) -> str:
    s = str(value)
    if len(s) > 80:
        return s[:40] + "...[redacted]" + s[-20:]
    return s


def _build_proxy_base(request: Request, config: ProxyConfig) -> str:
    scheme = request.url.scheme
    host = request.url.hostname
    port = config.listen_port
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _handle_sse_http(
    state: AppState,
    config: ProxyConfig,
    transport: HTTPTransport,
    request: Request,
) -> Response:
    current = state.metrics.get("sse_connections", 0)
    if current >= config.max_sse_connections:
        return JSONResponse({"error": "Too many SSE connections"}, status_code=503)

    await state.inc_metric("sse_connections")
    await state.inc_metric("sse_total_connections")
    state.log_event(SecurityEvent(
        event_type="sse_connect", severity="info",
        message=f"SSE via HTTP -> {config.target_url}",
        details={"mode": "http", "target": config.target_url},
    ))

    proxy_base = _build_proxy_base(request, config)

    async def stream() -> AsyncGenerator[bytes, None]:
        try:
            async for raw in transport.event_stream():
                decoded = raw.decode("utf-8", errors="replace").rstrip("\n")
                if decoded.startswith("data: "):
                    data_val = decoded[6:]
                    if data_val.startswith("/"):
                        decoded = f"data: {proxy_base}{data_val}"
                    elif config.target_url.rstrip("/") in data_val:
                        decoded = decoded.replace(config.target_url.rstrip("/"), proxy_base)
                yield (decoded + "\n").encode()
        except Exception as e:
            logger.warning("SSE HTTP stream error: %s", e, exc_info=True)
        finally:
            await state.dec_metric("sse_connections")

    return StreamingResponse(
        stream(), media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )


async def _handle_sse_stdio(
    state: AppState, config: ProxyConfig, session_manager: SessionManager, request: Request,
) -> Response:
    current = state.metrics.get("sse_connections", 0)
    if current >= config.max_sse_connections:
        return JSONResponse({"error": "Too many SSE connections"}, status_code=503)

    transport = _make_stdio_transport(config)
    if transport is None:
        return JSONResponse({"error": "No stdio command configured"}, status_code=500)
    await transport.connect()
    session = session_manager.create(transport)
    proxy_base = _build_proxy_base(request, config)
    messages_url = f"{proxy_base}{config.messages_path}?session_id={session.id}"

    await state.inc_metric("sse_connections")
    await state.inc_metric("sse_total_connections")
    state.log_event(SecurityEvent(
        event_type="sse_connect", severity="info",
        message=f"SSE via stdio session={session.id}",
        details={"mode": "stdio", "session_id": session.id},
    ))
    await session.start_event_loop()

    async def stream() -> AsyncGenerator[bytes, None]:
        try:
            yield f"event: endpoint\ndata: {messages_url}\n\n".encode()
            while True:
                try:
                    event = await session.get_event()
                except (asyncio.TimeoutError, Exception):
                    break
                decoded = event.decode("utf-8", errors="replace").strip()
                if not decoded:
                    continue
                try:
                    data = json.loads(decoded)
                    for plugin in registry.plugins:
                        ev = plugin.inspect_sse_event("message", data)
                        if ev:
                            await state.inc_metric("injections_detected")
                            state.log_event(ev)
                except json.JSONDecodeError:
                    pass
                yield f"event: message\ndata: {decoded}\n\n".encode()
        except Exception as e:
            logger.warning("SSE stdio stream error: %s", e, exc_info=True)
        finally:
            await session_manager.remove(session.id)
            await state.dec_metric("sse_connections")

    return StreamingResponse(
        stream(), media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )


def _inspect_response(
    method: str, resp_json: dict, tool_cache: ToolCache,
    state: AppState, config: ProxyConfig,
) -> Response | None:
    response_event = registry.inspect_response(method, resp_json)
    if response_event:
        state.metrics["poisoning_detected"] += 1
        state.log_event(response_event)
        if config.block_on_poisoning:
            state.metrics["blocked_requests"] += 1
            return JSONResponse({"error": "Blocked", "detail": response_event.message}, status_code=403)
    if method == "tools/list":
        tools = resp_json.get("result", {}).get("tools", [])
        if tools:
            tool_cache.set(tools)
    return None


async def _handle_message(
    state: AppState, config: ProxyConfig, inspector: MessageInspector,
    rule_engine: RuleEngine, anomaly_detector: AnomalyDetector,
    session_manager: SessionManager, transport_http: HTTPTransport | None,
    tool_cache: ToolCache, circuit_breaker: CircuitBreaker, request: Request,
) -> Response:
    body_bytes = await request.body()
    if len(body_bytes) > MAX_BODY_SIZE:
        return JSONResponse({"error": "Request body too large"}, status_code=413)

    body_str = body_bytes.decode("utf-8", errors="replace")
    if not body_str.strip():
        return JSONResponse({"error": "Empty body"}, status_code=400)

    ct = request.headers.get("content-type", "")
    if ct and "json" not in ct:
        return JSONResponse({"error": "Unsupported media type"}, status_code=415)

    try:
        msg = json.loads(body_str)
    except json.JSONDecodeError:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    state.metrics["total_requests"] += 1
    inspected = inspector.inspect(msg)
    method = inspected.get("method") or ""
    ip = _client_ip(request)

    plugin_event = registry.inspect_request(msg)
    if plugin_event:
        state.metrics["injections_detected"] += 1
        state.log_event(plugin_event)
        if plugin_event.blocked and config.block_on_injection:
            return JSONResponse({"error": "Blocked", "detail": plugin_event.message}, status_code=403)

    if not rule_engine.is_allowed(method):
        ev = SecurityEvent(
            event_type="tool_blocked", severity="high",
            message=f"Blocked: {method}", details={"method": method}, blocked=True,
        )
        state.metrics["blocked_requests"] += 1
        state.log_event(ev)
        return JSONResponse({"error": "Blocked", "detail": f"Method not allowed: {method}"}, status_code=403)

    rate_event = await rule_engine.check_rate(method, client_ip=ip)
    if rate_event:
        state.metrics["blocked_requests"] += 1
        state.log_event(rate_event)
        resp = JSONResponse({"error": "Rate limited", "detail": rate_event.message}, status_code=429)
        resp.headers["Retry-After"] = str(int(config.rate_window))
        resp.headers["X-RateLimit-Limit"] = str(config.rate_limit)
        resp.headers["X-RateLimit-Window"] = str(config.rate_window)
        return resp

    anomaly_detector.record(method)
    anomaly_event = anomaly_detector.check(method)
    if anomaly_event:
        state.metrics["anomalies_detected"] += 1
        state.log_event(anomaly_event)

    if method == "tools/call":
        tool_name = inspected.get("params", {}).get("name", "unknown")
        calls = state.metrics["tool_calls"]
        calls[tool_name] = calls.get(tool_name, 0) + 1

    if method == "tools/list":
        cached = tool_cache.get()
        if cached is not None:
            return JSONResponse({"result": {"tools": cached}})

    session_id = request.query_params.get("session_id", "")

    if config.mode == "stdio" and session_id:
        session = session_manager.get(session_id)
        if session is None:
            return JSONResponse({"error": "Session not found"}, status_code=404)
        try:
            resp_bytes = await session.transport.send_message(body_bytes)
        except Exception as e:
            logger.warning("Stdio upstream error: %s", e, exc_info=True)
            return JSONResponse({"error": "Upstream error", "detail": str(e)}, status_code=502)
        resp_str = resp_bytes.decode("utf-8", errors="replace")
        try:
            resp_json = json.loads(resp_str)
        except json.JSONDecodeError:
            resp_json = {}
        blocked_resp = _inspect_response(method, resp_json, tool_cache, state, config)
        if blocked_resp:
            return blocked_resp
        state.log_event(SecurityEvent(
            event_type="message", severity="info",
            message=f"{method} -> 200", details={"method": method, "session_id": session_id},
        ))
        return Response(content=resp_bytes, media_type="application/json")

    if config.mode == "http" and transport_http:
        client = transport_http._client
        if client is None:
            return JSONResponse({"error": "Transport not connected"}, status_code=502)
        session_id_param = f"?session_id={session_id}" if session_id else ""
        target_url = f"{transport_http._messages_url}{session_id_param}"
        try:
            resp = await circuit_breaker.call(
                client.post, target_url, content=body_bytes,
                headers={k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")},
            )
        except RuntimeError as e:
            if "Circuit breaker" in str(e):
                return JSONResponse({"error": "Upstream circuit breaker open"}, status_code=503)
            logger.warning("Upstream error: %s", e, exc_info=True)
            return JSONResponse({"error": "Upstream error"}, status_code=502)
        except httpx.RequestError as e:
            state.log_event(SecurityEvent(
                event_type="upstream_error", severity="error",
                message=f"Upstream error: {e}", details={"target": target_url},
            ))
            return JSONResponse({"error": "Upstream error"}, status_code=502)
        resp_body = resp.content
        try:
            resp_json = json.loads(resp_body) if resp_body.strip() else {}
        except json.JSONDecodeError:
            resp_json = {}
        blocked_resp = _inspect_response(method, resp_json, tool_cache, state, config)
        if blocked_resp:
            return blocked_resp
        state.log_event(SecurityEvent(
            event_type="message", severity="info",
            message=f"{method} -> {resp.status_code}",
            details={"method": method, "status_code": resp.status_code},
        ))
        return Response(
            content=resp_body, status_code=resp.status_code,
            headers={k: v for k, v in resp.headers.items() if k.lower() not in ("content-length",)},
        )

    return JSONResponse({"error": "No transport available"}, status_code=500)


async def _handle_health(state: AppState) -> JSONResponse:
    m = state.metrics
    return JSONResponse({
        "status": "ok", "version": PROXY_VERSION,
        "uptime_seconds": state.uptime,
        "active_sse_connections": m.get("sse_connections", 0),
        "metrics": {
            "total_requests": m["total_requests"], "blocked": m["blocked_requests"],
            "sse_total": m.get("sse_total_connections", 0), "injections": m["injections_detected"],
            "poisoning": m["poisoning_detected"], "tool_calls": m["tool_calls"],
        },
        "plugins": [p.name for p in registry.plugins],
    })


async def _handle_health_ready(state: AppState, transport_http: HTTPTransport | None) -> JSONResponse:
    if transport_http and transport_http._client:
        try:
            resp = await transport_http._client.get(
                f"{transport_http._target_url}/health", timeout=3.0
            )
            upstream_ok = resp.status_code < 500
        except Exception:
            upstream_ok = False
    else:
        upstream_ok = True

    status = "ready" if upstream_ok else "starting"
    code = 200 if upstream_ok else 503
    return JSONResponse({"status": status, "upstream": upstream_ok}, status_code=code)


_UNPROTECTED_PATHS = ("/health", "/metrics")


class _AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, api_key: str | None):
        super().__init__(app)
        self.api_key = api_key

    async def dispatch(self, request: Request, call_next):
        if self.api_key:
            path = request.url.path.rstrip("/")
            if not any(path.startswith(p) for p in _UNPROTECTED_PATHS):
                auth = request.headers.get("Authorization", "")
                expected_bearer = f"Bearer {self.api_key}"
                if not hmac.compare_digest(auth, expected_bearer) and not hmac.compare_digest(auth, self.api_key):
                    return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return await call_next(request)


def _app_factory(state: AppState) -> Starlette:
    config = state.config
    inspector = MessageInspector()
    rule_engine = RuleEngine(config)
    anomaly_detector = AnomalyDetector()
    session_manager = SessionManager()
    transport_http = _make_transport(config)
    tool_cache = ToolCache(ttl=60)
    circuit_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=30.0)

    @asynccontextmanager
    async def lifespan(app):
        if transport_http:
            await transport_http.connect()
        await session_manager.start_cleanup()
        yield
        await session_manager.stop_cleanup()
        await session_manager.close_all()
        if transport_http:
            await transport_http.close()

    async def sse_route(request: Request) -> Response:
        if config.mode == "stdio":
            return await _handle_sse_stdio(state, config, session_manager, request)
        elif config.mode == "http" and transport_http:
            return await _handle_sse_http(state, config, transport_http, request)
        return JSONResponse({"error": "No transport"}, status_code=500)

    async def msg_route(request: Request) -> Response:
        return await _handle_message(
            state, config, inspector, rule_engine, anomaly_detector,
            session_manager, transport_http, tool_cache, circuit_breaker, request,
        )

    async def health_route(request: Request) -> Response:
        return await _handle_health(state)

    async def health_ready_route(request: Request) -> Response:
        return await _handle_health_ready(state, transport_http)

    async def metrics_route(request: Request) -> Response:
        state.metrics["uptime_seconds"] = state.uptime
        return Response(
            content=render_prometheus(state.metrics),
            media_type="text/plain; charset=utf-8",
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )

    from mcpguard.dashboard.app import dashboard_routes

    routes = [
        Route(config.sse_path, sse_route, methods=["GET"]),
        Route(config.messages_path + "{path:path}", msg_route, methods=["POST"]),
        Route("/health", health_route, methods=["GET"]),
        Route("/health/ready", health_ready_route, methods=["GET"]),
        Route("/metrics", metrics_route, methods=["GET"]),
    ]
    routes.extend(dashboard_routes(state))

    middleware = [Middleware(_AuthMiddleware, api_key=config.api_key)]
    return Starlette(routes=routes, middleware=middleware, lifespan=lifespan)


def start_proxy(state: AppState) -> None:
    config = state.config
    app = _app_factory(state)

    from rich import print as rprint

    errors = config.validate()
    if errors:
        for err in errors:
            rprint(f"  [red]Config error: {err}[/red]")
        raise SystemExit(1)

    if config.hot_reload and config.config_path:
        from mcpguard.proxy.config_watcher import ConfigWatcher
        watcher = ConfigWatcher(config.config_path, state.reload_config)
        watcher.start()
        rprint(f"  Watch:  [green]{config.config_path.name}[/green]")

    rprint(f"\n[bold green]MCPGuard v{PROXY_VERSION}[/bold green]")
    rprint(f"  Mode:   [yellow]{config.mode}[/yellow]")
    if config.mode == "http":
        rprint(f"  Target: [yellow]{config.target_url}[/yellow]")
    elif config.mode == "stdio":
        cmd_str = " ".join(config.command) if config.command else "N/A"
        rprint(f"  Cmd:    [yellow]{cmd_str}[/yellow]")
    rprint(f"  Listen: [yellow]{config.listen_host}:{config.listen_port}[/yellow]")
    rprint(f"  SSE:    [yellow]{config.sse_path}[/yellow]  Msgs: [yellow]{config.messages_path}[/yellow]")
    protocol = "https" if config.tls_cert_path else "http"
    rprint(f"  Dash:   [blue]{protocol}://{config.listen_host}:{config.listen_port}/_mcpguard/[/blue]")
    rprint("  Health: [yellow]/health[/yellow]  Ready: [yellow]/health/ready[/yellow]  Metrics: [yellow]/metrics[/yellow]")
    rprint("  Auth:   [green]enabled[/green]" if config.api_key else "  Auth:   [dim]disabled[/dim]")
    if config.tls_cert_path:
        rprint(f"  TLS:    [green]enabled[/green] ({config.tls_cert_path.name})")
    if config.hot_reload:
        rprint("  Reload: [green]enabled[/green]")
    if config.allowlisted_tools:
        rprint(f"  Allow:  [green]{', '.join(sorted(config.allowlisted_tools))}[/green]")
    if config.denylisted_tools:
        rprint(f"  Deny:   [red]{', '.join(sorted(config.denylisted_tools))}[/red]")
    if registry.plugins:
        rprint(f"  Plugins: [cyan]{', '.join(p.name for p in registry.plugins)}[/cyan]")

    ssl_kwargs: dict[str, object] = {}
    if config.tls_cert_path:
        ssl_kwargs["ssl_certfile"] = str(config.tls_cert_path)
    if config.tls_key_path:
        ssl_kwargs["ssl_keyfile"] = str(config.tls_key_path)

    uvicorn.run(app, host=config.listen_host, port=config.listen_port, log_level="info", timeout_graceful_shutdown=10, **ssl_kwargs)  # type: ignore[arg-type]
