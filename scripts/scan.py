#!/usr/bin/env python3
"""
OpenClaw exposure scanner CLI.

Usage:
    # Scan specific IP ranges (no paid APIs needed)
    python scripts/scan.py --targets 192.168.1.0/24 10.0.0.0/16

    # Scan targets from a file (one CIDR/IP per line)
    python scripts/scan.py --targets-file targets.txt

    # Use Censys free tier to discover targets first
    python scripts/scan.py --censys

    # Re-validate existing DB instances only
    python scripts/scan.py --revalidate

    # Combine: Censys discovery + manual ranges
    python scripts/scan.py --censys --targets 203.0.113.0/24
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Add src to path for direct script execution
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from clawmon.config import DB_PATH, OPENCLAW_PORT, SCAN_CONCURRENCY, SCAN_TIMEOUT_SECS
from clawmon.db import (
    get_active_instances,
    get_scan_summary,
    get_scanned_subnets,
    init_db,
    mark_stale_instances,
    mark_subnet_scanned,
    update_enrichment,
    upsert_instance,
)
from clawmon.models import DiscoveredInstance, SecurityStatus
from clawmon.scanner.fingerprinter import fingerprint_all, fingerprint_host
from clawmon.scanner.port_scanner import SubnetResult, scan_range

console = Console()
logger = logging.getLogger("clawmon")


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def mask_ip(ip: str) -> str:
    """Redact last octet: 1.2.3.4 -> 1.2.3.xxx"""
    parts = ip.rsplit(".", 1)
    return f"{parts[0]}.xxx" if len(parts) == 2 else ip


def load_targets_file(path: str) -> list[str]:
    """Load target IPs/CIDRs from a file, one per line."""
    targets = []
    filepath = Path(path)
    if not filepath.exists():
        console.print(f"[red]Targets file not found: {path}[/red]")
        sys.exit(1)

    for line in filepath.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line)

    return targets


async def run_scan(
    targets: list[str],
    use_censys: bool = False,
    revalidate: bool = False,
    fresh: bool = False,
) -> None:
    db = await init_db(DB_PATH)
    try:
        if revalidate:
            # Re-fingerprint existing instances
            console.print("[bold]Re-validating existing instances...[/bold]")
            active = await get_active_instances(db)
            if not active:
                console.print("No active instances in database.")
                return

            from clawmon.scanner.port_scanner import OpenPort

            hosts = [OpenPort(ip=inst.ip, port=inst.port) for inst in active]
            console.print(f"Re-checking {len(hosts)} active instances...")
            instances = await fingerprint_all(hosts)

            for inst in instances:
                await upsert_instance(db, inst, inst.secured, inst.http_status)

            console.print(f"Confirmed {len(instances)}/{len(hosts)} still active OpenClaw")
        else:
            if not targets and not use_censys:
                console.print(
                    "[red]No targets specified.[/red]\n"
                    "Use --targets <CIDR> or --targets-file <file> or --censys"
                )
                return

            all_candidates = []

            # Source 1: Censys free tier
            if use_censys:
                console.print("[bold]Querying Censys free tier...[/bold]")
                from clawmon.scanner.censys_client import censys_available, search_censys

                if not censys_available():
                    console.print(
                        "[yellow]Censys credentials not set. "
                        "Set CENSYS_API_ID and CENSYS_API_SECRET in .env[/yellow]"
                    )
                else:
                    censys_results = search_censys()
                    all_candidates.extend(censys_results)
                    console.print(f"  Censys found {len(censys_results)} candidates")

            # Source 2: Direct port scanning with inline fingerprinting
            # Each /24 subnet's open ports are fingerprinted immediately,
            # so the dashboard updates in real-time during the scan.
            if targets:
                console.print(f"[bold]Port scanning {len(targets)} target range(s)...[/bold]")
                for t in targets:
                    console.print(f"  {t}")

                # Load already-scanned subnets for resume
                if fresh:
                    await db.execute("DELETE FROM scanned_subnets")
                    await db.commit()
                    console.print("  [dim]Fresh scan: cleared all saved progress[/dim]")
                already_scanned = await get_scanned_subnets(db, OPENCLAW_PORT)
                if already_scanned:
                    console.print(
                        f"  [dim]Resuming: {len(already_scanned)} /24 subnets already scanned[/dim]"
                    )

                import httpx
                from clawmon.config import VALIDATION_RATE_LIMIT
                from clawmon.scanner.enricher import enrich_ip

                secured_count = 0
                unsecured_count = 0
                unknown_count = 0
                total_open_ports = 0
                fp_semaphore = asyncio.Semaphore(max(1, int(VALIDATION_RATE_LIMIT * 2)))

                async def on_subnet_done(result: SubnetResult) -> None:
                    nonlocal secured_count, unsecured_count, unknown_count, total_open_ports
                    await mark_subnet_scanned(
                        db, result.subnet, OPENCLAW_PORT, len(result.open_ports),
                    )
                    # Fingerprint this subnet's open ports immediately
                    if not result.open_ports:
                        return
                    total_open_ports += len(result.open_ports)
                    for host in result.open_ports:
                        inst = await fingerprint_host(http_client, host, fp_semaphore)
                        if inst is not None:
                            await upsert_instance(db, inst, inst.secured, inst.http_status)
                            # Enrich immediately so dashboard has geo data
                            enrichment = await enrich_ip(inst.ip, http_client)
                            if enrichment:
                                await update_enrichment(db, inst.ip, enrichment)
                            if inst.secured == SecurityStatus.SECURED:
                                secured_count += 1
                            elif inst.secured == SecurityStatus.UNSECURED:
                                unsecured_count += 1
                            else:
                                unknown_count += 1
                            location = ""
                            if enrichment:
                                parts = [enrichment.get("provider"), enrichment.get("country")]
                                location = f" ({', '.join(p for p in parts if p)})"
                            console.print(
                                f"  [bold]FOUND[/bold]: {mask_ip(inst.ip)}:{inst.port} "
                                f"[{'red' if inst.secured == SecurityStatus.UNSECURED else 'green'}]"
                                f"{inst.secured}[/]{location}  (saved to DB)"
                            )

                async with httpx.AsyncClient(follow_redirects=True, verify=False) as http_client:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TaskProgressColumn(),
                        console=console,
                    ) as progress:
                        task = progress.add_task("Scanning ports...", total=None)

                        def on_progress(scanned: int, total: int) -> None:
                            progress.update(task, completed=scanned, total=total)

                        await scan_range(
                            targets,
                            concurrency=SCAN_CONCURRENCY,
                            timeout=SCAN_TIMEOUT_SECS,
                            progress_callback=on_progress,
                            skip_subnets=already_scanned,
                            on_subnet_done=on_subnet_done,
                        )

                total_found = secured_count + unsecured_count + unknown_count
                if total_found == 0:
                    console.print("[yellow]No OpenClaw instances found.[/yellow]")
                else:
                    console.print(
                        f"\n  Found {total_found} OpenClaw instances "
                        f"from {total_open_ports} open ports  |  "
                        f"[red]Unsecured: {unsecured_count}[/red]"
                    )

            # Fingerprint any Censys-only candidates that weren't port-scanned
            if all_candidates:
                console.print(
                    f"[bold]Fingerprinting {len(all_candidates)} Censys candidates...[/bold]"
                )

                async def on_censys_found(inst: DiscoveredInstance) -> None:
                    await upsert_instance(db, inst, inst.secured, inst.http_status)
                    console.print(
                        f"  [bold]FOUND[/bold]: {mask_ip(inst.ip)}:{inst.port} "
                        f"[{'red' if inst.secured == SecurityStatus.UNSECURED else 'green'}]"
                        f"{inst.secured}[/]  (saved to DB)"
                    )

                await fingerprint_all(all_candidates, on_found=on_censys_found)

        # Mark stale
        stale = await mark_stale_instances(db)
        if stale > 0:
            console.print(f"Marked {stale} stale instances as inactive")

        # Print summary
        summary = await get_scan_summary(db)
        console.print()
        console.print("[bold]Database Summary:[/bold]")

        table = Table(show_header=False)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")
        table.add_row("Total records", str(summary["total"]))
        table.add_row("Active", str(summary["active"]))
        table.add_row("Unsecured", f"[red]{summary['unsecured']}[/red]")
        table.add_row("Secured", f"[green]{summary['secured']}[/green]")
        table.add_row("Unknown", str(summary["unknown"]))
        if summary["active"] > 0:
            pct = summary["unsecured"] / summary["active"] * 100
            table.add_row("Unsecured %", f"[red]{pct:.1f}%[/red]")
        console.print(table)

        # Show recent unsecured instances (masked)
        active = await get_active_instances(db)
        unsecured = [i for i in active if i.secured == SecurityStatus.UNSECURED]
        if unsecured:
            console.print()
            console.print(f"[bold red]Unsecured instances ({len(unsecured)}):[/bold red]")
            inst_table = Table()
            inst_table.add_column("IP (masked)")
            inst_table.add_column("Port")
            inst_table.add_column("Country")
            inst_table.add_column("Provider")
            inst_table.add_column("Version")
            for inst in unsecured[:20]:
                inst_table.add_row(
                    mask_ip(inst.ip),
                    str(inst.port),
                    inst.country or "-",
                    inst.provider or "-",
                    inst.version or "-",
                )
            console.print(inst_table)
            if len(unsecured) > 20:
                console.print(f"  ... and {len(unsecured) - 20} more")

    finally:
        await db.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OpenClaw exposure scanner - no paid APIs required",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/scan.py --targets 10.0.0.0/24
  python scripts/scan.py --targets-file my_ranges.txt
  python scripts/scan.py --censys
  python scripts/scan.py --censys --targets 203.0.113.0/24
  python scripts/scan.py --revalidate
        """,
    )
    parser.add_argument(
        "--targets", nargs="+", default=[],
        help="IP addresses or CIDR ranges to scan (e.g., 192.168.1.0/24)",
    )
    parser.add_argument(
        "--targets-file",
        help="File with IPs/CIDRs to scan, one per line",
    )
    parser.add_argument(
        "--censys", action="store_true",
        help="Use Censys free tier to discover targets (needs CENSYS_API_ID/SECRET)",
    )
    parser.add_argument(
        "--revalidate", action="store_true",
        help="Re-check existing instances in the database",
    )
    parser.add_argument(
        "--fresh", action="store_true",
        help="Ignore saved progress and rescan all subnets from scratch",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    setup_logging(args.verbose)

    targets = list(args.targets)
    if args.targets_file:
        targets.extend(load_targets_file(args.targets_file))

    asyncio.run(run_scan(
        targets=targets,
        use_censys=args.censys,
        revalidate=args.revalidate,
        fresh=args.fresh,
    ))


if __name__ == "__main__":
    main()
