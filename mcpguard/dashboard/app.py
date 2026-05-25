from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from mcpguard.main import AppState

_HERE = Path(__file__).resolve().parent
_TEMPLATE_DIR = _HERE.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

_timeline: deque[dict] = deque(maxlen=60)


def _active_rules(state: AppState) -> int:
    c = state.config
    return int(bool(c.allowlisted_tools)) + int(bool(c.denylisted_tools)) + 1


def dashboard_routes(state: AppState) -> list[Route]:
    async def page(request) -> Response:
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={"request": request, "uptime": state.uptime},
        )

    async def metrics(request) -> Response:
        m = state.metrics
        return templates.TemplateResponse(
            request=request,
            name="metrics.html",
            context={
                "request": request,
                "total_requests": m["total_requests"],
                "sse_connections": m.get("sse_connections", 0),
                "blocked": m["blocked_requests"],
                "injections": m["injections_detected"],
                "poisonings": m["poisoning_detected"],
                "anomalies": m["anomalies_detected"],
                "uptime": state.uptime,
                "active_rules": _active_rules(state),
            },
        )

    async def events(request) -> Response:
        recent = state.get_events_since(datetime.now(timezone.utc) - timedelta(minutes=15))
        return templates.TemplateResponse(
            request=request,
            name="events.html",
            context={"request": request, "events": recent[-50:]},
        )

    async def tools_api(request) -> JSONResponse:
        return JSONResponse(state.metrics["tool_calls"])

    async def timeline_api(request) -> JSONResponse:
        m = state.metrics
        point = {
            "total": m["total_requests"],
            "blocked": m["blocked_requests"],
            "injections": m["injections_detected"],
            "poisonings": m["poisoning_detected"],
        }
        _timeline.append(point)
        return JSONResponse(point)

    prefix = "/_mcpguard"
    return [
        Route(f"{prefix}/", page, methods=["GET"]),
        Route(f"{prefix}/metrics", metrics, methods=["GET"]),
        Route(f"{prefix}/events", events, methods=["GET"]),
        Route(f"{prefix}/api/tools", tools_api, methods=["GET"]),
        Route(f"{prefix}/api/timeline", timeline_api, methods=["GET"]),
    ]
