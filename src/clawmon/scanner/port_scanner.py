"""
Async TCP port scanner for discovering open ports on target CIDR ranges.

Pure Python - no external tools or paid APIs needed.
Tracks progress at /24 subnet granularity for resume capability.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass
from typing import Callable

from clawmon.config import OPENCLAW_PORT

logger = logging.getLogger("clawmon.scanner.port")


@dataclass
class OpenPort:
    ip: str
    port: int


@dataclass
class SubnetResult:
    """Result of scanning a single /24 subnet."""
    subnet: str
    open_ports: list[OpenPort]


async def _check_port(
    ip: str,
    port: int,
    semaphore: asyncio.Semaphore,
    timeout: float = 3.0,
) -> OpenPort | None:
    """Try to connect to ip:port. Returns OpenPort if open, None if closed/filtered."""
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return OpenPort(ip=ip, port=port)
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            return None


def _ip_to_subnet(ip: str) -> str:
    """Convert an IP to its /24 subnet string: 1.2.3.4 -> 1.2.3.0/24"""
    addr = ipaddress.ip_address(ip)
    network = ipaddress.ip_network(f"{addr}/24", strict=False)
    return str(network)


def _group_by_subnet(ips: list[str]) -> dict[str, list[str]]:
    """Group IPs by their /24 subnet."""
    subnets: dict[str, list[str]] = {}
    for ip in ips:
        subnet = _ip_to_subnet(ip)
        if subnet not in subnets:
            subnets[subnet] = []
        subnets[subnet].append(ip)
    return subnets


async def scan_range(
    targets: list[str],
    ports: list[int] | None = None,
    concurrency: int = 500,
    timeout: float = 3.0,
    progress_callback: Callable[[int, int], None] | None = None,
    skip_subnets: set[str] | None = None,
    on_subnet_done: Callable[[SubnetResult], None] | None = None,
) -> list[OpenPort]:
    """
    Scan IP ranges for open ports, with /24 subnet-level resume.

    Args:
        targets: List of IPs, CIDR ranges, or IP ranges
        ports: Ports to scan (defaults to [OPENCLAW_PORT])
        concurrency: Max concurrent connections
        timeout: Connection timeout in seconds
        progress_callback: Called with (scanned_count, total_count)
        skip_subnets: Set of /24 subnet strings to skip (already scanned)
        on_subnet_done: Called when a /24 subnet finishes scanning

    Returns:
        List of OpenPort results
    """
    if ports is None:
        ports = [OPENCLAW_PORT]
    if skip_subnets is None:
        skip_subnets = set()

    all_ips = _expand_targets(targets)
    subnet_groups = _group_by_subnet(all_ips)

    # Filter out already-scanned subnets
    # Build skip check per (subnet, port) combination
    skippable = skip_subnets
    pending_subnets = {
        s: ips for s, ips in subnet_groups.items() if s not in skippable
    }
    skipped_count = len(subnet_groups) - len(pending_subnets)

    if skipped_count > 0:
        skipped_ips = sum(len(ips) for s, ips in subnet_groups.items() if s in skippable)
        logger.info(
            "Resuming: skipping %d already-scanned /24 subnets (%d IPs)",
            skipped_count, skipped_ips,
        )

    total_ips = sum(len(ips) for ips in pending_subnets.values())
    total_checks = total_ips * len(ports)

    if total_checks == 0:
        if skipped_count > 0:
            logger.info("All %d subnets already scanned, nothing to do", len(subnet_groups))
        else:
            logger.warning("No IPs to scan")
        return []

    logger.info(
        "Scanning %d IPs across %d /24 subnets on port(s) %s (concurrency=%d)",
        total_ips, len(pending_subnets), ports, concurrency,
    )

    semaphore = asyncio.Semaphore(concurrency)
    all_results: list[OpenPort] = []
    scanned = 0

    # Process subnet by subnet for tracking
    for subnet, ips in pending_subnets.items():
        ip_port_pairs = [(ip, port) for ip in ips for port in ports]
        subnet_results: list[OpenPort] = []

        # Scan this subnet in batches
        batch_size = concurrency * 4
        for batch_start in range(0, len(ip_port_pairs), batch_size):
            batch = ip_port_pairs[batch_start : batch_start + batch_size]
            tasks = [
                _check_port(ip, port, semaphore, timeout)
                for ip, port in batch
            ]
            batch_results = await asyncio.gather(*tasks)

            for result in batch_results:
                if result is not None:
                    subnet_results.append(result)
                    logger.info("  OPEN: %s:%d", result.ip, result.port)

            scanned += len(batch)
            if progress_callback:
                progress_callback(scanned, total_checks)

        all_results.extend(subnet_results)

        # Notify that this subnet is done
        if on_subnet_done:
            await on_subnet_done(SubnetResult(subnet=subnet, open_ports=subnet_results))

    logger.info(
        "Scan complete: %d open ports found out of %d checked (%d subnets skipped)",
        len(all_results), total_checks, skipped_count,
    )
    return all_results


def _expand_targets(targets: list[str]) -> list[str]:
    """Expand CIDR ranges, IP ranges, and individual IPs into a flat list."""
    ips: list[str] = []

    for target in targets:
        target = target.strip()
        if not target:
            continue

        if "/" in target:
            # CIDR notation: 192.168.1.0/24
            try:
                network = ipaddress.ip_network(target, strict=False)
                ips.extend(str(ip) for ip in network.hosts())
            except ValueError as e:
                logger.error("Invalid CIDR range '%s': %s", target, e)

        elif "-" in target:
            # IP range: 10.0.0.1-10.0.0.50
            try:
                start_str, end_str = target.split("-", 1)
                start_ip = ipaddress.ip_address(start_str.strip())
                end_ip = ipaddress.ip_address(end_str.strip())
                current = int(start_ip)
                end = int(end_ip)
                if current > end:
                    logger.error("Invalid range '%s': start > end", target)
                    continue
                if end - current >= 65536:
                    logger.error("Range '%s' too large (max 65536 IPs per range)", target)
                    continue
                while current <= end:
                    ips.append(str(ipaddress.ip_address(current)))
                    current += 1
            except ValueError as e:
                logger.error("Invalid IP range '%s': %s", target, e)

        else:
            # Single IP
            try:
                ipaddress.ip_address(target)
                ips.append(target)
            except ValueError as e:
                logger.error("Invalid IP '%s': %s", target, e)

    return ips
