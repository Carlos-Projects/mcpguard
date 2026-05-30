# MCPGuard 🛡️

[![CI](https://github.com/Carlos-Projects/mcpguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Carlos-Projects/mcpguard/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/Carlos-Projects/mcpguard/branch/main/graph/badge.svg)](https://codecov.io/gh/Carlos-Projects/mcpguard)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/mcpguard-proxy/)
[![PyPI](https://img.shields.io/pypi/v/mcpguard-proxy.svg)](https://pypi.org/project/mcpguard-proxy/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Star History](https://img.shields.io/badge/Star-History-blue?style=social)](https://api.star-history.com/svg?repos=Carlos-Projects/mcpguard&type=Date)

**Runtime security proxy for the Model Context Protocol (MCP) and Agent-to-Agent (A2A) protocols.**

MCPGuard sits between MCP clients and servers, inspecting every JSON-RPC message in real time to detect and block security threats. Supports **HTTP SSE**, **stdio**, and **WebSocket** transport modes.

---

## What makes MCPGuard unique

| Capability | MCPGuard | Raw proxy | Custom middleware |
|---|---|---|---|
| **Prompt injection detection** | ✅ 14 regex patterns | ❌ | Manual |
| **Tool poisoning detection** | ✅ flags suspicious `tools/list` | ❌ | ❌ |
| **SSRF protection** | ✅ redirect blocking + scheme validation | ❌ | Manual |
| **Rate limiting** | ✅ per-method + per-IP | ❌ | ❌ |
| **Live dashboard** | ✅ HTMX at `/_mcpguard/` | ❌ | ❌ |
| **Prometheus metrics** | ✅ `/metrics` | ❌ | ❌ |
| **All 3 transports** | ✅ HTTP SSE + stdio + WebSocket | Partial | Manual |
| **Hot-reload config** | ✅ | ❌ | ❌ |
| **Circuit breaker** | ✅ auto-recovers | ❌ | ❌ |

---

## Features

| Category | Feature | Description |
|----------|---------|-------------|
| **Detection** | Prompt Injection | Scans `tools/call` arguments for instruction override patterns (14 regexes) |
| | Tool Poisoning | Flags suspicious tool definitions in `tools/list` responses |
| | Resource Scanning | Detects sensitive URI access (`/etc/passwd`, `file:///`, metadata endpoints) |
| | Suspicious Prompts | Flags prompt names like `debug`, `admin`, `shell` |
| | Anomaly Detection | Burst, volume, and dominance-based anomaly alerts |
| **Control** | Rate Limiting | Per-method + per-IP rate limits with configurable windows |
| | Allow/Deny Lists | Control which tools and methods are permitted |
| | Auth Middleware | API key auth with timing-attack resistant comparison (`hmac.compare_digest`) |
| | Circuit Breaker | Auto-opens after 5 upstream failures, recovers after 30s |
| | Body Size Limit | Rejects requests >10MB (413) to prevent DoS |
| **Transport** | HTTP SSE | Proxies MCP Streamable HTTP (rewrites endpoint URLs) |
| | Stdio | Wraps local MCP server subprocesses with command validation |
| | WebSocket | WebSocket transport support for MCP servers |
| **Observability** | Live Dashboard | HTMX-powered dashboard at `/_mcpguard/` with JS event filtering |
| | Prometheus Metrics | `/metrics` with counters, gauges (uptime, active SSE) |
| | Audit Logging | All events logged to daily JSONL files |
| **Security** | SSRF Protection | `follow_redirects=False`, target URL scheme validation |
| | Subprocess Validation | Command existence + executable check before spawn |
| | Rate Limit Headers | `Retry-After`, `X-RateLimit-*` on 429 responses |
| **Platform** | TLS | HTTPS support via `--tls-cert` / `--tls-key` |
| | Config Validation | 10 validation rules on startup (port range, TLS paths, conflicts) |
| | Config File | YAML/JSON configuration via `--config` with auto-split for string commands |
| | Hot-Reload | Async config watcher (no blocking threads) |
| | Tool Cache | `tools/list` caching with configurable TTL |
| | Graceful Shutdown | 10s timeout for clean connection drain |

## Installation

```bash
pip install mcpguard-proxy
```

From source:

```bash
git clone https://github.com/Carlos-Projects/mcpguard.git
cd mcpguard
pip install -e ".[dev]"
```

## Quick Start

```bash
# HTTP mode (intercept an upstream MCP server)
mcpguard proxy --target http://localhost:8000 --port 8080

# Stdio mode (wrap a local MCP server process)
mcpguard proxy --mode stdio --cmd python3 --cmd /path/to/server.py --port 8080

# With auth, TLS, and circuit breaker
mcpguard proxy --target http://localhost:8000 --port 8443 \
  --api-key my-secret --tls-cert cert.pem --tls-key key.pem

# With config file (YAML/JSON)
mcpguard proxy --config mcpguard.yaml --hot-reload
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
| `--request-timeout` | `30.0` | Upstream request timeout in seconds |

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
                           │   /health/ready      │
                           └─────────────────────┘
```

## Detection Plugins

| Plugin | Trigger | Action |
|--------|---------|--------|
| Prompt Injection | `tools/call` with instruction override keywords | Block (403) |
| Tool Poisoning | `tools/list` with suspicious tool names | Block if `block_on_poisoning: true` |
| Resource Scanner | `resources/read` with sensitive URIs | Log |
| Suspicious Prompts | `prompts/get` with admin-like names | Log |
| Rate Limiter | Per-method + per-IP threshold exceeded | Block (429) with `Retry-After` |
| Anomaly Detector | Burst, dominant-method, high-volume patterns | Log |
| Circuit Breaker | 5 consecutive upstream failures | Block (503) for 30s recovery |

## Config File Example

```yaml
mode: http
target_url: http://localhost:8000
listen_host: 127.0.0.1
listen_port: 8080
rate_limit: 100
rate_window: 60
block_on_injection: true
block_on_poisoning: true
max_sse_connections: 50
request_timeout: 30.0
api_key: your-secret-key
allowlisted_tools:
  - get_weather
  - search
denylisted_tools:
  - execute_bash
  - delete_files
tls_cert_path: /path/to/cert.pem
tls_key_path: /path/to/key.pem
```

## Testing

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v --cov=mcpguard --cov-report=term-missing
```

## Ecosystem

MCPGuard is a **runtime guard** — it complements:

- **[Cisco MCP Scanner](https://github.com/ciscomanufacturing/mcp-scanner)** — static analysis of MCP servers
- **[MCPwn](https://github.com/Carlos-Projects/mcpwn)** — active red teaming framework for MCP

## Changelog

### v0.4.0 (2025-05-25)
- **Security:** Timing-attack resistant auth, body size limit (10MB), subprocess command validation, SSRF protection
- **Reliability:** Circuit breaker (5 failures/30s recovery), async config watcher, graceful shutdown (10s)
- **Features:** `/health/ready` endpoint, rate limit headers, configurable timeout, WebSocket transport
- **Dashboard:** JS event filtering, CDN fallback, uptime/active connections metrics
- **Config:** Validation on startup, auto-split string commands, `request_timeout` option
- **Tests:** 52 → 104 tests, coverage ~85%, 7 new test files, CI coverage reporting
- **Infra:** `.dockerignore`, stdio integration tests in CI, codecov integration

### v0.3.0 (2025-05-24)
- HTTP SSE + stdio transport modes
- Prompt injection, tool poisoning, resource scanning, anomaly detection
- Live HTMX dashboard, Prometheus metrics, JSONL audit logging
- Auth middleware, TLS support, rate limiting, allow/deny lists
- Docker support, CI/CD, PyPI publishing

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## License

MIT
