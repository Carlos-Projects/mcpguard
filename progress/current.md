# Current State

Status: active
Last updated: 2026-11-05

## Current Goal

Restore MCP Python SDK v2 compatibility while preserving the existing HTTP SSE and stdio proxy contracts.

## Known Good Commands

- setup: `python3 -m venv .venv && source .venv/bin/activate && pip install -e '.[dev]'`
- test: `python3 -m pytest tests/ -v`
- lint: `ruff check .`
- typecheck: `mypy mcpguard/`
- build: `python3 -m build`

## Open Risks

- MCP proxy and dashboard surfaces must fail closed when auth/policy is uncertain.
- Examples must not encourage passing secrets through committed configs.
- Findings should normalize to mcp-taxonomy so MCPscop, ThreatLens, and AgentForensics can consume them.
- The legacy SSE transport remains supported for compatibility, but new integrations should prefer streamable HTTP.

## Next Step

- Add streamable HTTP proxy coverage, then create an AGT MCP Security Gateway conformance map for MCPGuard.
