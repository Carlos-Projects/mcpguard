from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

HERE = Path(__file__).resolve().parent
TEST_SERVER = HERE / "mcp_test_server.py"


@pytest.fixture(scope="module")
def proxy_port() -> int:
    return 19879


@pytest.fixture(scope="module")
def proxy_stdio_process(proxy_port: int):
    proc = subprocess.Popen(
        [
            "mcpguard", "proxy",
            "--mode", "stdio",
            "--cmd", sys.executable,
            "--cmd", str(TEST_SERVER),
            "--cmd", "--transport",
            "--cmd", "stdio",
            "--port", str(proxy_port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(4)
    yield
    proc.terminate()
    proc.wait()


@pytest.mark.asyncio
async def test_stdio_health(proxy_stdio_process, proxy_port: int):
    async with httpx.AsyncClient() as c:
        for i in range(15):
            try:
                r = await c.get(f"http://127.0.0.1:{proxy_port}/health", timeout=1.0)
                if r.status_code == 200:
                    assert r.json()["status"] == "ok"
                    return
            except Exception:
                pass
            await asyncio.sleep(0.5)
    pytest.fail("Stdio proxy health endpoint not ready")


@pytest.mark.asyncio
async def test_stdio_sse_flow(proxy_stdio_process, proxy_port: int):
    async with httpx.AsyncClient() as c:
        known_sids: list[str] = []

        async def read_sse():
            async with c.stream("GET", f"http://127.0.0.1:{proxy_port}/sse", timeout=30.0) as resp:
                async for line in resp.aiter_lines():
                    if "session_id=" in line:
                        sid = line.split("session_id=")[-1].split("&")[0].split(" ")[0].strip()
                        known_sids.append(sid)

        sse_task = asyncio.create_task(read_sse())
        await asyncio.sleep(2)
        assert len(known_sids) > 0, "No session_id from stdio SSE"
        session_id = known_sids[0]

        r = await c.post(
            f"http://127.0.0.1:{proxy_port}/messages/?session_id={session_id}",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"},
            }},
            timeout=5.0,
        )
        assert r.status_code in (200, 202), f"Stdio init failed: {r.status_code} {r.text[:200]}"
        data = r.json()
        assert "result" in data, f"No result in init: {data}"

        r = await c.post(
            f"http://127.0.0.1:{proxy_port}/messages/?session_id={session_id}",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            timeout=5.0,
        )
        assert r.status_code in (200, 202), f"Stdio list failed: {r.status_code} {r.text[:200]}"
        data = r.json()
        tools = data.get("result", {}).get("tools", [])
        names = [t["name"] for t in tools]
        assert "get_weather" in names
        assert "calculate" in names

        sse_task.cancel()
        try:
            await sse_task
        except (asyncio.CancelledError, Exception):
            pass
