#!/usr/bin/env python3
"""
Probe discovered OpenClaw instances to check gateway activity.

Usage:
    python scripts/probe.py                  # Probe all, show summary
    python scripts/probe.py --limit 5        # Probe first 5 only
    python scripts/probe.py --active-only    # Only show instances with active gateways
    python scripts/probe.py --deep           # Also enumerate accessible paths + data
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from clawmon.config import DB_PATH
from clawmon.db import get_active_instances, init_db

console = Console()


@dataclass
class ProbeResult:
    ip: str
    port: int
    reachable: bool = False
    gateway_online: bool = False
    version: str | None = None
    has_sessions: bool = False
    has_agents: bool = False
    has_channels: bool = False
    accessible_paths: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)


# Paths that indicate an active, connected gateway
# Based on the OpenClaw UI sidebar: Chat, Overview, Channels, Instances, Sessions, etc.
API_PATHS = [
    "/api/health",
    "/api/status",
    "/health",
    "/status",
    "/api/v1/health",
    "/api/v1/status",
    "/api/v1/sessions",
    "/api/v1/agents",
    "/api/v1/channels",
    "/api/v1/instances",
    "/api/v1/nodes",
    "/api/v1/config",
    "/api/sessions",
    "/api/agents",
    "/api/channels",
    "/api/instances",
    "/api/nodes",
    "/api/config",
]

# Patterns in the HTML/JS that reveal gateway status
ONLINE_PATTERNS = [
    re.compile(r"health[\"'\s:]+online", re.IGNORECASE),
    re.compile(r"status[\"'\s:]+connected", re.IGNORECASE),
    re.compile(r"gateway[\"'\s:]+online", re.IGNORECASE),
    re.compile(r'"connected"\s*:\s*true', re.IGNORECASE),
    re.compile(r'"healthy"\s*:\s*true', re.IGNORECASE),
]

OFFLINE_PATTERNS = [
    re.compile(r"health[\"'\s:]+offline", re.IGNORECASE),
    re.compile(r"disconnected from gateway", re.IGNORECASE),
    re.compile(r"connect to the gateway to start", re.IGNORECASE),
    re.compile(r'"connected"\s*:\s*false', re.IGNORECASE),
    re.compile(r'"healthy"\s*:\s*false', re.IGNORECASE),
]


async def probe_instance(
    client: httpx.AsyncClient,
    ip: str,
    port: int,
    deep: bool = False,
) -> ProbeResult:
    """Probe an instance to determine if its gateway is active."""
    result = ProbeResult(ip=ip, port=port)
    base = f"http://{ip}:{port}"

    # 1. Check main page
    try:
        resp = await client.get(f"{base}/", timeout=8, follow_redirects=True)
        result.reachable = True
        body = resp.text[:8000]

        # Check for offline indicators in the HTML
        for pat in OFFLINE_PATTERNS:
            if pat.search(body):
                result.gateway_online = False
                break
        else:
            # Check for online indicators
            for pat in ONLINE_PATTERNS:
                if pat.search(body):
                    result.gateway_online = True
                    break

        # Try to extract version from page
        ver_match = re.search(r"Version[:\s]+([v\d][.\d]+\S*)", body)
        if ver_match:
            result.version = ver_match.group(1)

    except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
        return result

    # 2. Check API endpoints for gateway health
    health_paths = ["/api/health", "/api/v1/health", "/health", "/api/status", "/status"]
    for path in health_paths:
        try:
            r = await client.get(f"{base}{path}", timeout=5)
            if r.status_code == 200:
                result.accessible_paths.append(f"{path} [{r.status_code}]")
                try:
                    data = r.json()
                    result.details[path] = data

                    # Check health response for gateway status
                    status = data.get("status", data.get("health", ""))
                    if isinstance(status, str) and status.lower() in ("ok", "healthy", "online", "connected"):
                        result.gateway_online = True
                    connected = data.get("connected", data.get("gateway_connected"))
                    if connected is True:
                        result.gateway_online = True
                    elif connected is False:
                        result.gateway_online = False
                except (json.JSONDecodeError, ValueError):
                    pass
            elif r.status_code != 404:
                result.accessible_paths.append(f"{path} [{r.status_code}]")
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            pass

    # 3. Check for active sessions/agents/channels
    data_paths = {
        "sessions": ["/api/v1/sessions", "/api/sessions"],
        "agents": ["/api/v1/agents", "/api/agents"],
        "channels": ["/api/v1/channels", "/api/channels"],
    }

    for resource, paths in data_paths.items():
        for path in paths:
            try:
                r = await client.get(f"{base}{path}", timeout=5)
                if r.status_code == 200:
                    result.accessible_paths.append(f"{path} [{r.status_code}]")
                    try:
                        data = r.json()
                        # Could be a list or {"data": [...]}
                        items = data if isinstance(data, list) else data.get("data", data.get("items", []))
                        if isinstance(items, list) and len(items) > 0:
                            if resource == "sessions":
                                result.has_sessions = True
                                result.gateway_online = True
                            elif resource == "agents":
                                result.has_agents = True
                                result.gateway_online = True
                            elif resource == "channels":
                                result.has_channels = True
                            result.details[path] = f"{len(items)} items"
                    except (json.JSONDecodeError, ValueError):
                        pass
                    break  # Found working path for this resource
                elif r.status_code != 404:
                    result.accessible_paths.append(f"{path} [{r.status_code}]")
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
                pass

    # 4. WebSocket upgrade check - the gateway often communicates over WS
    ws_paths = ["/ws", "/gateway", "/api/ws", "/api/v1/ws", "/socket", "/ws/gateway"]
    for path in ws_paths:
        try:
            r = await client.get(
                f"{base}{path}",
                timeout=5,
                headers={
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                },
            )
            # 101 = Switching Protocols (WS accepted)
            # 426 = Upgrade Required (WS endpoint exists but needs proper handshake)
            # 400 with specific text = WS endpoint exists
            if r.status_code in (101, 426):
                result.accessible_paths.append(f"{path} [WS:{r.status_code}]")
                result.gateway_online = True
                result.details[f"{path} (websocket)"] = f"WebSocket endpoint active (HTTP {r.status_code})"
            elif r.status_code == 400 and any(
                kw in r.text.lower() for kw in ("websocket", "upgrade", "handshake")
            ):
                result.accessible_paths.append(f"{path} [WS:400-upgrade]")
                result.gateway_online = True
                result.details[f"{path} (websocket)"] = "WebSocket endpoint detected (bad handshake)"
            elif r.status_code != 404:
                result.accessible_paths.append(f"{path} [{r.status_code}]")
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
            pass

    # 5. Deep probe: enumerate all accessible paths
    if deep:
        for path in API_PATHS:
            if any(path in ap for ap in result.accessible_paths):
                continue  # Already checked
            try:
                r = await client.get(f"{base}{path}", timeout=5)
                if r.status_code != 404:
                    result.accessible_paths.append(f"{path} [{r.status_code}]")
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            result.details[path] = (
                                data if len(json.dumps(data)) < 500
                                else f"({len(json.dumps(data))} chars)"
                            )
                        except (json.JSONDecodeError, ValueError):
                            result.details[path] = f"({len(r.text)} chars, non-JSON)"
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError):
                pass

    return result


def mask_ip(ip: str) -> str:
    parts = ip.rsplit(".", 1)
    return f"{parts[0]}.xxx" if len(parts) == 2 else ip


async def main(
    limit: int | None = None,
    active_only: bool = False,
    deep: bool = False,
) -> None:
    db = await init_db(DB_PATH)
    try:
        instances = await get_active_instances(db)
        if not instances:
            console.print("[yellow]No active instances in database. Run scan.py first.[/yellow]")
            return

        if limit:
            instances = instances[:limit]

        console.print(f"[bold]Probing {len(instances)} instance(s) for gateway activity...[/bold]\n")

        results: list[ProbeResult] = []
        async with httpx.AsyncClient(verify=False) as client:
            for inst in instances:
                result = await probe_instance(client, inst.ip, inst.port, deep=deep)
                results.append(result)

                # Live status indicator
                if result.gateway_online:
                    status = "[bold green]ACTIVE GATEWAY[/bold green]"
                elif result.reachable:
                    status = "[dim]idle (no gateway)[/dim]"
                else:
                    status = "[red]unreachable[/red]"
                console.print(f"  {mask_ip(inst.ip)}:{inst.port} -> {status}")

        # Summary table
        active = [r for r in results if r.gateway_online]
        idle = [r for r in results if r.reachable and not r.gateway_online]
        unreachable = [r for r in results if not r.reachable]

        console.print()
        console.print("[bold]Probe Summary:[/bold]")
        summary = Table(show_header=False)
        summary.add_column("Metric", style="bold")
        summary.add_column("Value", justify="right")
        summary.add_row("Total probed", str(len(results)))
        summary.add_row("Active gateway", f"[bold green]{len(active)}[/bold green]")
        summary.add_row("Idle (UI only)", str(len(idle)))
        summary.add_row("Unreachable", str(len(unreachable)))
        console.print(summary)

        # Show active instances in detail
        if active:
            console.print()
            console.print(f"[bold green]Active instances ({len(active)}):[/bold green]")
            active_table = Table()
            active_table.add_column("IP (masked)")
            active_table.add_column("Port")
            active_table.add_column("Version")
            active_table.add_column("Sessions")
            active_table.add_column("Agents")
            active_table.add_column("Channels")
            active_table.add_column("Accessible paths")

            for r in active:
                active_table.add_row(
                    mask_ip(r.ip),
                    str(r.port),
                    r.version or "-",
                    "yes" if r.has_sessions else "-",
                    "yes" if r.has_agents else "-",
                    "yes" if r.has_channels else "-",
                    str(len(r.accessible_paths)),
                )
            console.print(active_table)

            # Show details for active instances
            if deep:
                for r in active:
                    if r.details:
                        detail_lines = []
                        for path, data in r.details.items():
                            if isinstance(data, dict):
                                detail_lines.append(f"{path}:")
                                detail_lines.append(f"  {json.dumps(data, indent=2)[:500]}")
                            else:
                                detail_lines.append(f"{path}: {data}")

                        console.print(Panel(
                            "\n".join(detail_lines),
                            title=f"[bold]{mask_ip(r.ip)}:{r.port}[/bold] - API details",
                            border_style="green",
                        ))

        if active_only and not active:
            console.print("\n[yellow]No instances with active gateways found.[/yellow]")

    finally:
        await db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Probe OpenClaw instances for gateway activity")
    parser.add_argument("--limit", type=int, help="Max instances to probe")
    parser.add_argument("--active-only", action="store_true", help="Only show active gateway instances")
    parser.add_argument("--deep", action="store_true", help="Enumerate all API paths and show details")
    args = parser.parse_args()

    asyncio.run(main(limit=args.limit, active_only=args.active_only, deep=args.deep))
