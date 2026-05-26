# MCPGuard

## [Unreleased]

### Added
- Body size configuration support
- Jailbreak patterns plugin
- Steganography detector
- MCPscop forwarder for event forwarding
- SSE (Server-Sent Events) inspection
- Configurable block flags for policy actions
- IP-based rate limiting

## [0.4.0] - 2025-08-01

### Added
- A2A protocol support (Agent-to-Agent)
- HTMX-based dashboard for real-time monitoring
- Prometheus metrics endpoint
- JSONL audit logging
- Policy engine with YAML-based rules
- Risk scoring for requests
- Session tracking via SSE
- Rate limiting middleware
- Honeypot endpoint detection

### Changed
- Migrated to MCP SDK v1.0+
- Restructured proxy transport layer

### Fixed
- Request/response body inspection for binary payloads
- Concurrent session handling

## [0.3.0] - 2025-05-15

### Added
- SSE transport inspection
- Tool call/result inspection
- Resource URI validation
- Prompt injection detection plugin

### Fixed
- Proxy connection pooling

## [0.2.0] - 2025-03-01

### Added
- HTTP SSE transport mode
- stdio transport mode
- Configurable block/allow lists
- Audit logging to file

## [0.1.0] - 2025-01-10

### Added
- Initial MCP proxy implementation
- Basic request/response forwarding
- Simple allow/deny policy rules
- CLI entry point with typer
