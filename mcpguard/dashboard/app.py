from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from mcpguard.main import AppState

_HERE = Path(__file__).resolve().parent
_TEMPLATE_DIR = _HERE.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

_timeline: list[dict] = []


def _uptime(state: AppState) -> int:
    for ev in reversed(state.events):
        if ev.event_type in ("sse_connect", "request", "message"):
            return int((datetime.now(timezone.utc).replace(tzinfo=None) - ev.timestamp).total_seconds())
    return 0


def _active_rules(state: AppState) -> int:
    c = state.config
    return int(bool(c.allowlisted_tools)) + int(bool(c.denylisted_tools)) + 1


def dashboard_routes(state: AppState) -> list[Route]:
    async def page(request):
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={"request": request, "uptime": _uptime(state)},
        )

    async def metrics(request):
        m = state.metrics
        return templates.TemplateResponse(
            request=request,
            name="metrics.html",
            context={
                "request": request,
                "total_requests": m["total_requests"],
                "sse_connections": m["sse_connections"],
                "blocked": m["blocked_requests"],
                "injections": m["injections_detected"],
                "poisonings": m["poisoning_detected"],
                "anomalies": m["anomalies_detected"],
                "uptime": _uptime(state),
                "active_rules": _active_rules(state),
            },
        )

    async def events(request):
        recent = state.get_events_since(datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=15))
        return templates.TemplateResponse(
            request=request,
            name="events.html",
            context={"request": request, "events": recent[-50:]},
        )

    async def tools_api(request):
        return JSONResponse(state.metrics["tool_calls"])

    async def timeline_api(request):
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
