#!/usr/bin/env python3
"""Minimal MCP test server for integration tests."""
from __future__ import annotations

import argparse

from mcp.server.mcpserver import MCPServer

server = MCPServer("MCPTestServer")


@server.tool()
def get_weather(city: str) -> str:
    return f"Weather in {city}: sunny, 22C"


@server.tool()
def calculate(a: float, b: float, op: str = "add") -> float:
    if op == "add":
        return a + b
    elif op == "subtract":
        return a - b
    elif op == "multiply":
        return a * b
    elif op == "divide":
        if b == 0:
            raise ValueError("Division by zero")
        return a / b
    raise ValueError(f"Unknown operation: {op}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--transport", choices=["stdio", "sse"], default="sse")
    args = parser.parse_args()
    if args.transport == "stdio":
        server.run(transport="stdio")
    else:
        server.run(transport="sse", host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
