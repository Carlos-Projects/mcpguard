# Current State

Status: active
Last updated: 2026-05-26

## Current Goal

Install a portable Codex/OpenCode harness and align MCPGuard with the Microsoft AGT MCP Security Gateway pattern.

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

## Next Step

- Create an AGT MCP Security Gateway conformance map for MCPGuard.
