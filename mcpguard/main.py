from __future__ import annotations

import json
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
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
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
    block_on_poisoning: bool = False
    api_key: str | None = None
    tls_cert_path: Path | None = None
    tls_key_path: Path | None = None
    hot_reload: bool = False
    config_path: Path | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProxyConfig:
        allow = set(data.get("allowlisted_tools", data.get("allow", [])))
        deny = set(data.get("denylisted_tools", data.get("deny", [])))
        return cls(
            mode=data.get("mode", "http"),
            listen_host=data.get("listen_host", data.get("host", "127.0.0.1")),
            listen_port=data.get("listen_port", data.get("port", 8080)),
            target_url=data.get("target_url", data.get("target", "http://localhost:8000")),
            sse_path=data.get("sse_path", "/sse"),
            messages_path=data.get("messages_path", "/messages/"),
            command=data.get("command"),
            env=data.get("env"),
            log_dir=Path(data.get("log_dir", "./mcpguard_logs")),
            allowlisted_tools=allow,
            denylisted_tools=deny,
            rate_limit=data.get("rate_limit", 100),
            rate_window=data.get("rate_window", 60),
            block_on_injection=data.get("block_on_injection", True),
            block_on_poisoning=data.get("block_on_poisoning", False),
            api_key=data.get("api_key"),
            tls_cert_path=Path(data["tls_cert_path"]) if data.get("tls_cert_path") else None,
            tls_key_path=Path(data["tls_key_path"]) if data.get("tls_key_path") else None,
            hot_reload=data.get("hot_reload", False),
            config_path=Path(data["config_path"]) if data.get("config_path") else None,
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
        self.events: list[SecurityEvent] = []
        self.metrics: dict[str, Any] = {
            "total_requests": 0,
            "blocked_requests": 0,
            "injections_detected": 0,
            "poisoning_detected": 0,
            "anomalies_detected": 0,
            "sse_connections": 0,
            "tool_calls": {},
        }
        self.config.log_dir.mkdir(parents=True, exist_ok=True)

    def log_event(self, event: SecurityEvent) -> None:
        self.events.append(event)
        log_file = self.config.log_dir / f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(event.to_dict()) + "\n")

    def get_events_since(self, since: datetime | None = None) -> list[SecurityEvent]:
        if since is None:
            return self.events[-100:]
        return [e for e in self.events if e.timestamp > since]

    def reload_config(self, data: dict[str, Any]) -> None:
        new_config = ProxyConfig.from_dict(data)
        self.config.listen_host = new_config.listen_host
        self.config.allowlisted_tools = new_config.allowlisted_tools
        self.config.denylisted_tools = new_config.denylisted_tools
        self.config.rate_limit = new_config.rate_limit
        self.config.rate_window = new_config.rate_window
        self.config.block_on_injection = new_config.block_on_injection
        self.config.block_on_poisoning = new_config.block_on_poisoning
