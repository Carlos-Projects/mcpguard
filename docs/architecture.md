# Architecture

## Purpose

MCPGuard is a runtime security proxy for MCP and A2A traffic. It sits between MCP clients and servers, inspects JSON-RPC messages, detects attacks, enforces policy, applies rate limits/auth, and emits audit/metrics.

## Boundaries

- In scope:
  - MCP/A2A runtime traffic inspection.
  - Prompt injection, tool poisoning, resource scanning, suspicious prompts, anomaly detection.
  - HTTP SSE, stdio, and WebSocket proxy modes.
  - Auth, rate limiting, circuit breaker, audit logging, dashboard, Prometheus metrics.
- Out of scope:
  - Replacing upstream MCP server business logic.
  - Guaranteeing safety without policy/configuration.
  - Acting as the only control for high-impact tool execution.

## Main Components

| Component | Path | Responsibility |
|---|---|---|
| Proxy/API | `mcpguard/proxy` | Interception and transport handling |
| Detectors | `mcpguard/detectors` | Prompt/resource/tool threat detection |
| Dashboard | `mcpguard/templates` | HTMX operator UI |
| CLI | `mcpguard/cli.py` | User-facing command surface |
| Integrations | `mcpguard/integrations` | Forwarding and ecosystem adapters |

## Data Flow

```text
MCP client -> MCPGuard transport -> detectors/policy/rate limit/auth -> upstream MCP server -> response scanning/audit -> MCP client
```

## Risk Surface

- Secrets: API keys, dashboard auth, upstream credentials.
- Network: upstream MCP servers, WebSocket/SSE endpoints, dashboard.
- User input: JSON-RPC params, tool definitions, prompt/resource names.
- File system: stdio subprocess commands and config files.
- LLM/tool calls: MCP tool calls must be inspected before forwarding.
