from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


@dataclass
class SecurityEvent:
    event_type: str
    severity: str
    message: str
    details: dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    blocked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "blocked": self.blocked,
        }


_SENSITIVE_KEYS = {"password", "token", "secret", "api_key", "authorization", "passwd", "credential", "auth", "api-key", "apikey"}


def redact_sensitive_args(args: dict) -> dict:
    if not isinstance(args, dict):
        return args
    redacted: dict[str, Any] = {}
    for k, v in args.items():
        if any(s in k.lower() for s in _SENSITIVE_KEYS):
            redacted[k] = "***REDACTED***"
        else:
            redacted[k] = v
    return redacted


@dataclass
class ProxyConfig:
    mode: str = "http"
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    target_url: str = "http://localhost:8000"
    sse_path: str = "/sse"
    messages_path: str = "/messages/"
    command: list[str] | None = None
    env: dict[str, str] | None = None
    log_dir: Path = Path("./mcpguard_logs")
    allowlisted_tools: set[str] = field(default_factory=set)
    denylisted_tools: set[str] = field(default_factory=set)
    rate_limit: int = 100
    rate_window: int = 60
    block_on_injection: bool = True
    block_on_poisoning: bool = True
    block_on_resource_scan: bool = True
    block_on_prompt_scan: bool = False
    api_key: str | None = None
    tls_cert_path: Path | None = None
    tls_key_path: Path | None = None
    hot_reload: bool = False
    config_path: Path | None = None
    max_sse_connections: int = 100
    request_timeout: float = 30.0
    mcpscop_url: str = ""
    mcpscop_api_key: str = ""
    max_body_size: int = 10 * 1024 * 1024
    trusted_proxies: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if not self.api_key:
            env_key = os.environ.get("MCPGUARD_API_KEY")
            if env_key:
                self.api_key = env_key

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.mode not in ("http", "stdio"):
            errors.append(f"Invalid mode: {self.mode}")
        if not (1 <= self.listen_port <= 65535):
            errors.append(f"Invalid port: {self.listen_port}")
        if self.rate_limit <= 0:
            errors.append("rate_limit must be positive")
        if self.rate_window <= 0:
            errors.append("rate_window must be positive")
        if self.max_sse_connections <= 0:
            errors.append("max_sse_connections must be positive")
        if self.request_timeout <= 0:
            errors.append("request_timeout must be positive")
        if self.mode == "stdio" and not self.command:
            errors.append("command required for stdio mode")
        if self.tls_cert_path and not self.tls_cert_path.exists():
            errors.append(f"TLS cert not found: {self.tls_cert_path}")
        if self.tls_key_path and not self.tls_key_path.exists():
            errors.append(f"TLS key not found: {self.tls_key_path}")
        if self.allowlisted_tools and self.denylisted_tools:
            overlap = self.allowlisted_tools & self.denylisted_tools
            if overlap:
                errors.append(f"Tools in both allow and deny lists: {overlap}")
        return errors

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProxyConfig:
        allow = set(data.get("allowlisted_tools", data.get("allow", [])))
        deny = set(data.get("denylisted_tools", data.get("deny", [])))
        cmd = data.get("command")
        if isinstance(cmd, str):
            cmd = cmd.split()
        return cls(
            mode=data.get("mode", "http"),
            listen_host=data.get("listen_host", data.get("host", "127.0.0.1")),
            listen_port=data.get("listen_port", data.get("port", 8080)),
            target_url=data.get("target_url", data.get("target", "http://localhost:8000")),
            sse_path=data.get("sse_path", "/sse"),
            messages_path=data.get("messages_path", "/messages/"),
            command=cmd,
            env=data.get("env"),
            log_dir=Path(data.get("log_dir", "./mcpguard_logs")),
            allowlisted_tools=allow,
            denylisted_tools=deny,
            rate_limit=data.get("rate_limit", 100),
            rate_window=data.get("rate_window", 60),
            block_on_injection=data.get("block_on_injection", True),
            block_on_poisoning=data.get("block_on_poisoning", True),
            block_on_resource_scan=data.get("block_on_resource_scan", True),
            block_on_prompt_scan=data.get("block_on_prompt_scan", False),
            api_key=data.get("api_key"),
            tls_cert_path=Path(data["tls_cert_path"]) if data.get("tls_cert_path") else None,
            tls_key_path=Path(data["tls_key_path"]) if data.get("tls_key_path") else None,
            hot_reload=data.get("hot_reload", False),
            config_path=Path(data["config_path"]) if data.get("config_path") else None,
            max_sse_connections=data.get("max_sse_connections", 100),
            request_timeout=data.get("request_timeout", 30.0),
            mcpscop_url=data.get("mcpscop_url", ""),
            mcpscop_api_key=data.get("mcpscop_api_key", ""),
            max_body_size=data.get("max_body_size", 10 * 1024 * 1024),
            trusted_proxies=set(data.get("trusted_proxies", [])),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> ProxyConfig:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        raw = path.read_text()
        if path.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(raw)
        elif path.suffix == ".json":
            data = json.loads(raw)
        else:
            raise ValueError(f"Unsupported config format: {path.suffix}")
        return cls.from_dict(data)


class AppState:
    def __init__(self, config: ProxyConfig | None = None) -> None:
        self.config = config or ProxyConfig()
        self.events: deque[SecurityEvent] = deque(maxlen=10000)
        self._start_time: datetime = datetime.now(timezone.utc)
        self._metrics_lock = asyncio.Lock()
        self.metrics: dict[str, Any] = {
            "total_requests": 0,
            "blocked_requests": 0,
            "injections_detected": 0,
            "poisoning_detected": 0,
            "anomalies_detected": 0,
            "sse_connections": 0,
            "sse_total_connections": 0,
            "ws_connections": 0,
            "tool_calls": {},
        }
        self.config.log_dir.mkdir(parents=True, exist_ok=True)
        self._setup_audit_logger()

    def _setup_audit_logger(self) -> None:
        self._audit_logger = logging.getLogger("mcpguard.audit")
        self._audit_logger.setLevel(logging.INFO)
        self._audit_logger.propagate = False
        self._audit_logger.handlers.clear()
        handler = logging.handlers.RotatingFileHandler(
            str(self.config.log_dir / "audit.jsonl"),
            maxBytes=100 * 1024 * 1024,
            backupCount=5,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._audit_logger.addHandler(handler)

    @property
    def uptime(self) -> int:
        return int((datetime.now(timezone.utc) - self._start_time).total_seconds())

    async def inc_metric(self, key: str, delta: int = 1) -> None:
        async with self._metrics_lock:
            self.metrics[key] = self.metrics.get(key, 0) + delta

    async def dec_metric(self, key: str, delta: int = 1) -> None:
        async with self._metrics_lock:
            self.metrics[key] = self.metrics.get(key, 0) - delta

    def log_event(self, event: SecurityEvent) -> None:
        self.events.append(event)
        try:
            self._audit_logger.info(json.dumps(event.to_dict()))
        except Exception as e:
            logging.getLogger("mcpguard").warning("Failed to write audit log: %s", e)
        if self.config.mcpscop_url:
            try:
                import asyncio

                from mcpguard.proxy.mcpscop import forward_event
                ev_dict = event.to_dict()
                ev_dict["source"] = "mcpguard"
                ev_dict["tool"] = event.details.get("tool")
                asyncio.create_task(forward_event(ev_dict))
            except Exception:
                pass

    def get_events_since(self, since: datetime | None = None) -> list[SecurityEvent]:
        if since is None:
            return list(self.events)[-100:]
        return [e for e in self.events if e.timestamp > since]

    def reload_config(self, data: dict[str, Any]) -> None:
        new_config = ProxyConfig.from_dict(data)
        self.config.allowlisted_tools = new_config.allowlisted_tools
        self.config.denylisted_tools = new_config.denylisted_tools
        self.config.rate_limit = new_config.rate_limit
        self.config.rate_window = new_config.rate_window
        self.config.block_on_injection = new_config.block_on_injection
        self.config.block_on_poisoning = new_config.block_on_poisoning
        self.config.block_on_resource_scan = new_config.block_on_resource_scan
        self.config.block_on_prompt_scan = new_config.block_on_prompt_scan
