from __future__ import annotations

from pathlib import Path

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from mcpguard.main import AppState, ProxyConfig
from mcpguard.proxy.server import start_proxy

app = typer.Typer(name="mcpguard", help="Runtime security proxy for MCP and A2A protocols", no_args_is_help=True)
console = Console()


@app.command()
def proxy(
    target: str = typer.Option("http://localhost:8000", "--target", "-t", help="Upstream MCP server URL (HTTP mode)"),
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Proxy listen address"),
    port: int = typer.Option(8080, "--port", "-p", help="Proxy listen port"),
    mode: str = typer.Option("http", "--mode", "-m", help="Transport mode: http or stdio"),
    sse_path: str = typer.Option("/sse", "--sse-path", help="SSE endpoint path"),
    messages_path: str = typer.Option("/messages/", "--messages-path", help="Messages endpoint path"),
    command: list[str] = typer.Option([], "--cmd", "-c", help="Stdio mode command (repeatable)"),
    log_dir: Path = typer.Option(Path("./mcpguard_logs"), "--log-dir", "-l", help="Log directory"),
    config_file: Path | None = typer.Option(None, "--config", "-C", help="Config file (YAML/JSON)", exists=True),
    allowlist: list[str] = typer.Option([], "--allow", "-a", help="Allowlisted tools (repeatable)"),
    denylist: list[str] = typer.Option([], "--deny", "-d", help="Denylisted tools (repeatable)"),
    rate_limit: int = typer.Option(100, "--rate-limit", "-r", help="Max requests per time window"),
    rate_window: int = typer.Option(60, "--rate-window", "-w", help="Rate limit window in seconds"),
    api_key: str | None = typer.Option(None, "--api-key", "-k", help="API key for proxy auth"),
    tls_cert: Path | None = typer.Option(None, "--tls-cert", help="TLS certificate file", exists=True),
    tls_key: Path | None = typer.Option(None, "--tls-key", help="TLS key file", exists=True),
    hot_reload: bool = typer.Option(False, "--hot-reload", help="Watch config file for changes"),
) -> None:
    if config_file:
        config = ProxyConfig.from_file(config_file)
        rprint(f"[dim]Loaded config from[/dim] [yellow]{config_file}[/yellow]")
    else:
        config = ProxyConfig(
            mode=mode,
            target_url=target,
            listen_host=host,
            listen_port=port,
            sse_path=sse_path,
            messages_path=messages_path,
            command=list(command) if command else None,
            log_dir=log_dir,
            allowlisted_tools=set(allowlist),
            denylisted_tools=set(denylist),
            rate_limit=rate_limit,
            rate_window=rate_window,
            api_key=api_key,
            tls_cert_path=tls_cert,
            tls_key_path=tls_key,
            hot_reload=hot_reload,
        )
    state = AppState(config=config)
    start_proxy(state)


@app.command()
def analyze(
    log_dir: Path = typer.Argument(Path("./mcpguard_logs"), help="Log directory to analyze"),
    severity: str | None = typer.Option(None, "--severity", "-s", help="Filter by severity (high, medium, low, info)"),
    event_type: str | None = typer.Option(None, "--type", "-t", help="Filter by event type"),
    limit: int = typer.Option(100, "--limit", "-n", help="Max events to show"),
) -> None:
    if not log_dir.exists():
        rprint("[red]Log directory not found[/red]")
        raise typer.Exit(code=1)

    json_mod = __import__("json")
    events: list[dict] = []
    for f in sorted(log_dir.glob("*.jsonl")):
        with open(f) as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                ev = json_mod.loads(line)
                if severity and ev.get("severity") != severity:
                    continue
                if event_type and ev.get("event_type") != event_type:
                    continue
                events.append(ev)

    rprint(f"\n[bold]Found {len(events)} events[/bold]")

    table = Table(title="Security Events")
    table.add_column("Time", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Severity", style="magenta")
    table.add_column("Message")
    table.add_column("Blocked", style="red")

    for ev in events[-limit:]:
        table.add_row(
            ev.get("timestamp", "")[11:19],
            ev.get("event_type", ""),
            ev.get("severity", ""),
            ev.get("message", "")[:80],
            "YES" if ev.get("blocked") else "no",
        )
    console.print(table)


if __name__ == "__main__":
    app()
