from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from mcpguard.detectors.base import registry
import mcpguard.detectors.prompt_injection  # noqa: F401
import mcpguard.detectors.tool_poisoning  # noqa: F401
import mcpguard.detectors.resource_prompt  # noqa: F401
from mcpguard.detectors.anomalies import AnomalyDetector
from mcpguard.main import AppState, ProxyConfig, SecurityEvent
from mcpguard.proxy.cache import ToolCache
from mcpguard.proxy.inspector import MessageInspector
from mcpguard.proxy.metrics import render_prometheus
from mcpguard.proxy.rules import RuleEngine
from mcpguard.proxy.session import Session, SessionManager
from mcpguard.transport.http import HTTPTransport
from mcpguard.transport.stdio import StdioTransport


def _make_transport(config: ProxyConfig) -> HTTPTransport | None:
    if config.mode == "http":
        return HTTPTransport(
            target_url=config.target_url,
            sse_path=config.sse_path,
            messages_path=config.messages_path,
        )
    return None


def _make_stdio_transport(config: ProxyConfig) -> StdioTransport | None:
    if config.mode == "stdio" and config.command:
        return StdioTransport(command=config.command, env=config.env)
    return None


def _build_proxy_base(request: Request, config: ProxyConfig) -> str:
    scheme = request.url.scheme
    host = request.url.hostname
    port = config.listen_port
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


async def _handle_sse_http(
    state: AppState,
    config: ProxyConfig,
    transport: HTTPTransport,
    request: Request,
) -> Response:
    proxy_base = _build_proxy_base(request, config)
    state.metrics["sse_connections"] += 1
    state.log_event(SecurityEvent(
        event_type="sse_connect", severity="info",
        message=f"SSE via HTTP → {config.target_url}",
        details={"mode": "http", "target": config.target_url},
    ))

    async def stream() -> AsyncGenerator[bytes, None]:
        async for raw in transport.event_stream():
            decoded = raw.decode("utf-8", errors="replace").rstrip("\n")
            if decoded.startswith("data: "):
                data_val = decoded[6:]
                if data_val.startswith("/"):
                    decoded = f"data: {proxy_base}{data_val}"
                elif config.target_url.rstrip("/") in data_val:
                    decoded = decoded.replace(config.target_url.rstrip("/"), proxy_base)
            yield (decoded + "\n").encode()

    return StreamingResponse(
        stream(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


async def _handle_sse_stdio(
    state: AppState, config: ProxyConfig, session_manager: SessionManager, request: Request,
) -> Response:
    transport = _make_stdio_transport(config)
    if transport is None:
        return JSONResponse({"error": "No stdio command configured"}, status_code=500)
    await transport.connect()
    session = session_manager.create(transport)
    proxy_base = _build_proxy_base(request, config)
    messages_url = f"{proxy_base}{config.messages_path}?session_id={session.id}"
    state.metrics["sse_connections"] += 1
    state.log_event(SecurityEvent(
        event_type="sse_connect", severity="info",
        message=f"SSE via stdio session={session.id}",
        details={"mode": "stdio", "session_id": session.id, "command": config.command},
    ))
    await session.start_event_loop()

    async def stream() -> AsyncGenerator[bytes, None]:
        try:
            yield f"event: endpoint\ndata: {messages_url}\n\n".encode()
            while True:
                try:
                    event = await session.get_event()
                    decoded = event.decode("utf-8", errors="replace").strip()
                    if not decoded:
                        continue
                    try:
                        data = json.loads(decoded)
                        for plugin in registry.plugins:
                            ev = plugin.inspect_sse_event("message", data)
                            if ev:
                                state.metrics["injections_detected"] += 1
                                state.log_event(ev)
                    except json.JSONDecodeError:
                        pass
                    yield f"event: message\ndata: {decoded}\n\n".encode()
                except Exception:
                    break
        finally:
            await session_manager.remove(session.id)

    return StreamingResponse(
        stream(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


async def _handle_message(
    state: AppState, config: ProxyConfig, inspector: MessageInspector,
    rule_engine: RuleEngine, anomaly_detector: AnomalyDetector,
    session_manager: SessionManager, transport_http: HTTPTransport | None,
    tool_cache: ToolCache, request: Request,
) -> Response:
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8", errors="replace")
    if not body_str.strip():
        return JSONResponse({"error": "Empty body"}, status_code=400)
    try:
        msg = json.loads(body_str)
    except json.JSONDecodeError:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    state.metrics["total_requests"] += 1
    inspected = inspector.inspect(msg)
    method = inspected.get("method") or ""
    anomaly_detector.record(method)

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

    rate_event = rule_engine.check_rate(method)
    if rate_event:
        state.metrics["blocked_requests"] += 1
        state.log_event(rate_event)
        return JSONResponse({"error": "Rate limited", "detail": rate_event.message}, status_code=429)

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
            return JSONResponse({"error": "Upstream error", "detail": str(e)}, status_code=502)
        resp_str = resp_bytes.decode("utf-8", errors="replace")
        try:
            resp_json = json.loads(resp_str)
        except json.JSONDecodeError:
            resp_json = {}
        response_event = registry.inspect_response(method, resp_json)
        if response_event:
            state.metrics["poisoning_detected"] += 1
            state.log_event(response_event)
        if method == "tools/list":
            tools = resp_json.get("result", {}).get("tools", [])
            if tools:
                tool_cache.set(tools)
        state.log_event(SecurityEvent(
            event_type="message", severity="info",
            message=f"{method} -> 200", details={"method": method, "session_id": session_id},
        ))
        return Response(content=resp_bytes, media_type="application/json")

    if config.mode == "http" and transport_http:
        session_id_param = f"?session_id={session_id}" if session_id else ""
        target_url = f"{transport_http._messages_url}{session_id_param}"
        try:
            resp = await transport_http._client.post(
                target_url, content=body_bytes,
                headers={k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")},
            )
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
        response_event = registry.inspect_response(method, resp_json)
        if response_event:
            state.metrics["poisoning_detected"] += 1
            state.log_event(response_event)
        if method == "tools/list":
            tools = resp_json.get("result", {}).get("tools", [])
            if tools:
                tool_cache.set(tools)
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
        "status": "ok", "version": "0.3.0",
        "metrics": {
            "total_requests": m["total_requests"], "blocked": m["blocked_requests"],
            "sse_connections": m["sse_connections"], "injections": m["injections_detected"],
            "poisoning": m["poisoning_detected"], "tool_calls": m["tool_calls"],
        },
        "plugins": [p.name for p in registry.plugins],
    })


class _AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, api_key: str | None):
        super().__init__(app)
        self.api_key = api_key

    async def dispatch(self, request: Request, call_next):
        if self.api_key and not request.url.path.startswith(("/health", "/_mcpguard/")):
            auth = request.headers.get("Authorization", "")
            if auth != f"Bearer {self.api_key}" and auth != self.api_key:
                if request.query_params.get("api_key") != self.api_key:
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
            session_manager, transport_http, tool_cache, request,
        )

    async def health_route(request: Request) -> Response:
        return await _handle_health(state)

    async def metrics_route(request: Request) -> Response:
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
        Route("/metrics", metrics_route, methods=["GET"]),
    ]
    routes.extend(dashboard_routes(state))

    middleware = [Middleware(_AuthMiddleware, api_key=config.api_key)]
    return Starlette(routes=routes, middleware=middleware, lifespan=lifespan)


def start_proxy(state: AppState) -> None:
    config = state.config
    app = _app_factory(state)

    if config.hot_reload and config.log_dir:
        from mcpguard.proxy.config_watcher import ConfigWatcher
        watcher = ConfigWatcher(config.log_dir.parent / "mcpguard.yaml", state.reload_config)
        watcher.start()

    from rich import print as rprint
    rprint(f"\n[bold green]MCPGuard v0.3.0[/bold green]")
    rprint(f"  Mode:   [yellow]{config.mode}[/yellow]")
    if config.mode == "http":
        rprint(f"  Target: [yellow]{config.target_url}[/yellow]")
    elif config.mode == "stdio":
        rprint(f"  Cmd:    [yellow]{' '.join(config.command) if config.command else 'N/A'}[/yellow]")
    rprint(f"  Listen: [yellow]{config.listen_host}:{config.listen_port}[/yellow]")
    rprint(f"  SSE:    [yellow]{config.sse_path}[/yellow]  Msgs: [yellow]{config.messages_path}[/yellow]")
    protocol = "https" if config.tls_cert_path else "http"
    rprint(f"  Dash:   [blue]{protocol}://{config.listen_host}:{config.listen_port}/_mcpguard/[/blue]")
    rprint(f"  Health: [yellow]/health[/yellow]  Metrics: [yellow]/metrics[/yellow]")
    if config.api_key:
        rprint(f"  Auth:   [green]enabled[/green]")
    else:
        rprint(f"  Auth:   [dim]disabled[/dim]")
    if config.tls_cert_path:
        rprint(f"  TLS:    [green]enabled[/green] ({config.tls_cert_path.name})")
    if config.hot_reload:
        rprint(f"  Reload: [green]enabled[/green]")
    if config.allowlisted_tools:
        rprint(f"  Allow:  [green]{', '.join(sorted(config.allowlisted_tools))}[/green]")
    if config.denylisted_tools:
        rprint(f"  Deny:   [red]{', '.join(sorted(config.denylisted_tools))}[/red]")
    if registry.plugins:
        rprint(f"  Plugins: [cyan]{', '.join(p.name for p in registry.plugins)}[/cyan]")

    ssl_kwargs = {}
    if config.tls_cert_path:
        ssl_kwargs["ssl_certfile"] = str(config.tls_cert_path)
    if config.tls_key_path:
        ssl_kwargs["ssl_keyfile"] = str(config.tls_key_path)

    uvicorn.run(app, host=config.listen_host, port=config.listen_port, log_level="info", **ssl_kwargs)
