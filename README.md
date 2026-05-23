# MCPGuard

[![CI](https://github.com/Carlos-Projects/mcpguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Carlos-Projects/mcpguard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/mcpguard/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Runtime security proxy for the **Model Context Protocol (MCP)** and **Agent-to-Agent (A2A)** protocols.

MCPGuard sits between MCP clients and servers, inspecting every JSON-RPC message in real time to detect and block security threats. Supports both **HTTP SSE** and **stdio** transport modes.

## Features

| Category | Feature | Description |
|----------|---------|-------------|
| **Detection** | Prompt Injection | Scans `tools/call` arguments for instruction override patterns (14 regexes) |
| | Tool Poisoning | Flags suspicious tool definitions in `tools/list` responses |
| | Resource Scanning | Detects sensitive URI access (`/etc/passwd`, `file:///`, metadata endpoints) |
| | Suspicious Prompts | Flags prompt names like `debug`, `admin`, `shell` |
| | Anomaly Detection | Burst, volume, and dominance-based anomaly alerts |
| **Control** | Rate Limiting | Per-method rate limits with configurable windows |
| | Allow/Deny Lists | Control which tools and methods are permitted |
| | Auth Middleware | Optional API key authentication (`--api-key`) |
| **Transport** | HTTP SSE | Proxies MCP Streamable HTTP (rewrites endpoint URLs) |
| | Stdio | Wraps local MCP server subprocesses (`--mode stdio`) |
| **Observability** | Live Dashboard | HTMX-powered dashboard mounted at `/_mcpguard/` |
| | Prometheus Metrics | `/metrics` endpoint with counters for all security events |
| | Audit Logging | All events logged to daily JSONL files |
| **Platform** | TLS | HTTPS support via `--tls-cert` / `--tls-key` |
| | Config File | YAML/JSON configuration via `--config` |
| | Hot-Reload | Watch config file for rule changes without restart |
| | Tool Cache | `tools/list` caching with configurable TTL |

## Installation

```bash
pip install mcpguard
```

From source:

```bash
git clone https://github.com/yourorg/mcpguard.git
cd mcpguard
pip install -e ".[dev]"
```

## Quick Start

```bash
# HTTP mode (intercept an upstream MCP server)
mcpguard proxy --target http://localhost:8000 --port 8080

# Stdio mode (wrap a local MCP server process)
mcpguard proxy --mode stdio --cmd python3 --cmd /path/to/server.py --port 8080

# With auth and TLS
mcpguard proxy --target http://localhost:8000 --port 8443 \
  --api-key my-secret --tls-cert cert.pem --tls-key key.pem
```

Clients connect to `http://localhost:8080` instead of the server directly. Dashboard at `/_mcpguard/`.

## CLI Reference

```
mcpguard proxy [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--target, -t` | `http://localhost:8000` | Upstream MCP server URL |
| `--host, -h` | `127.0.0.1` | Proxy listen address |
| `--port, -p` | `8080` | Proxy listen port |
| `--mode, -m` | `http` | Transport: `http` or `stdio` |
| `--cmd, -c` | `[]` | Stdio command (repeatable) |
| `--sse-path` | `/sse` | SSE endpoint path |
| `--messages-path` | `/messages/` | Messages endpoint path |
| `--log-dir, -l` | `./mcpguard_logs` | Log directory |
| `--config, -C` | — | Config file (YAML/JSON) |
| `--allow, -a` | `[]` | Allowlisted tools (repeatable) |
| `--deny, -d` | `[]` | Denylisted tools (repeatable) |
| `--rate-limit, -r` | `100` | Max requests per time window |
| `--rate-window, -w` | `60` | Rate limit window in seconds |
| `--api-key, -k` | — | API key for proxy auth |
| `--tls-cert` | — | TLS certificate file |
| `--tls-key` | — | TLS key file |
| `--hot-reload` | — | Watch config file for changes |

```
mcpguard analyze [LOG_DIR]
```

Analyze logged events with optional `--severity`, `--type`, `--limit` filters.

## Architecture

```
                          ┌──────────────────┐
                     ┌───▶│   MCPGuard Proxy  │───▶  MCP Server (HTTP/SSE)
                     │    │  (port 8080)      │
  MCP Client (Host)──┤    └──────────────────┘      ┌──────────────────┐
                     │           │                   │  MCP Server      │
                     │           ├──────────────────▶│  (stdio process) │
                     │           │                   └──────────────────┘
                     │    ┌──────────────────┐
                     └───▶│  /_mcpguard/      │
                          │  Dashboard        │
                          └──────────────────┘
                                     │
                          ┌──────────┴──────────┐
                          │   /metrics           │
                          │   /health            │
                          └─────────────────────┘
```

## Detection Plugins

| Plugin | Trigger | Action |
|--------|---------|--------|
| Prompt Injection | `tools/call` with instruction override keywords | Block (403) |
| Tool Poisoning | `tools/list` with suspicious tool names | Log |
| Resource Scanner | `resources/read` with sensitive URIs | Log |
| Suspicious Prompts | `prompts/get` with admin-like names | Log |
| Rate Limiter | Per-method threshold exceeded | Block (429) |
| Anomaly Detector | Burst, dominant-method, high-volume patterns | Log |

## Testing

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## Ecosystem

MCPGuard is a **runtime guard** — it complements:

- **[Cisco MCP Scanner](https://github.com/ciscomanufacturing/mcp-scanner)** — static analysis of MCP servers
- **[MCPwn](https://github.com/yourorg/mcpwn)** — active red teaming framework for MCP

## License

MIT
