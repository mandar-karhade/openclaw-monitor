"""
HTTP fingerprinter for identifying OpenClaw instances from open ports.

Sends a GET request and checks for known OpenClaw signatures:
- HTML title: "Clawdbot Control"
- Server header: "OpenClaw-Gateway"
- Specific response patterns
"""
from __future__ import annotations

import asyncio
import logging
import re

import httpx

from clawmon.config import (
    OPENCLAW_SERVER_HEADER,
    OPENCLAW_TITLE,
    VALIDATION_RATE_LIMIT,
    VALIDATION_TIMEOUT_SECS,
)
from clawmon.models import DiscoveredInstance, SecurityStatus
from clawmon.scanner.port_scanner import OpenPort

logger = logging.getLogger("clawmon.scanner.fingerprint")

# Regex to extract <title> from HTML
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
VERSION_RE = re.compile(r"OpenClaw-Gateway/(\S+)")


async def fingerprint_host(
    client: httpx.AsyncClient,
    host: OpenPort,
    semaphore: asyncio.Semaphore,
) -> DiscoveredInstance | None:
    """
    Check if an open port is an OpenClaw instance.

    Returns DiscoveredInstance if fingerprint matches, None otherwise.
    Also determines secured/unsecured status in the same request.
    """
    url = f"http://{host.ip}:{host.port}/"

    async with semaphore:
        try:
            response = await client.get(
                url,
                timeout=VALIDATION_TIMEOUT_SECS,
                follow_redirects=True,
            )

            server_header = response.headers.get("server", "")
            body = response.text[:4096]  # Only need the head

            # Extract title
            title_match = TITLE_RE.search(body)
            title = title_match.group(1).strip() if title_match else None

            # Check fingerprints
            is_openclaw = _matches_openclaw(title, server_header, body)

            if not is_openclaw:
                return None

            # Extract version from server header
            version = None
            ver_match = VERSION_RE.search(server_header)
            if ver_match:
                version = ver_match.group(1)

            # Determine security status from this same response
            if response.status_code == 200:
                secured = SecurityStatus.UNSECURED
            elif response.status_code in (401, 403):
                secured = SecurityStatus.SECURED
            else:
                secured = SecurityStatus.UNKNOWN

            logger.info(
                "  MATCH: %s:%d [%s] title=%r server=%r",
                host.ip, host.port, secured, title, server_header,
            )

            return DiscoveredInstance(
                ip=host.ip,
                port=host.port,
                server_header=server_header or None,
                title=title,
                version=version,
                http_status=response.status_code,
                secured=secured,
            )

        except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError) as e:
            logger.debug("  %s:%d -> %s", host.ip, host.port, type(e).__name__)
            return None

        finally:
            await asyncio.sleep(1.0 / VALIDATION_RATE_LIMIT)


def _matches_openclaw(
    title: str | None,
    server_header: str,
    body: str,
) -> bool:
    """Check if the response matches known OpenClaw fingerprints."""
    # Match on title
    if title and OPENCLAW_TITLE.lower() in title.lower():
        return True

    # Match on server header
    if OPENCLAW_SERVER_HEADER.lower() in server_header.lower():
        return True

    # Match on body content (fallback patterns)
    openclaw_patterns = [
        "openclaw",
        "clawdbot",
        "openclaw-gateway",
    ]
    body_lower = body.lower()
    for pattern in openclaw_patterns:
        if pattern in body_lower:
            return True

    return False


async def fingerprint_all(
    hosts: list[OpenPort],
    on_found: callable | None = None,
) -> list[DiscoveredInstance]:
    """
    Fingerprint all open ports, returning only confirmed OpenClaw instances.

    Args:
        hosts: Open ports to check.
        on_found: Optional async callback called immediately when an instance is confirmed.
                  Signature: async def on_found(instance: DiscoveredInstance) -> None
    """
    if not hosts:
        return []

    semaphore = asyncio.Semaphore(max(1, int(VALIDATION_RATE_LIMIT * 2)))
    instances: list[DiscoveredInstance] = []

    async with httpx.AsyncClient(
        follow_redirects=True,
        verify=False,
    ) as client:
        tasks = [
            fingerprint_host(client, host, semaphore)
            for host in hosts
        ]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result is not None:
                instances.append(result)
                if on_found:
                    await on_found(result)

    logger.info(
        "Fingerprinting complete: %d/%d hosts are OpenClaw instances",
        len(instances), len(hosts),
    )
    return instances
