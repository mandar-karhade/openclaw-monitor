"""
Optional Censys free-tier search client.

Free tier: 250 queries/month. Sign up at https://search.censys.io/register
Set CENSYS_API_ID and CENSYS_API_SECRET in your .env file.

This module is optional - the scanner works without it using direct port scanning.
"""
from __future__ import annotations

import logging

import httpx

from clawmon.config import (
    CENSYS_API_ID,
    CENSYS_API_SECRET,
    OPENCLAW_PORT,
    OPENCLAW_SERVER_HEADER,
    OPENCLAW_TITLE,
)
from clawmon.scanner.port_scanner import OpenPort

logger = logging.getLogger("clawmon.scanner.censys")

CENSYS_SEARCH_URL = "https://search.censys.io/api/v2/hosts/search"


def censys_available() -> bool:
    """Check if Censys credentials are configured."""
    return bool(CENSYS_API_ID and CENSYS_API_SECRET)


def search_censys() -> list[OpenPort]:
    """
    Query Censys free-tier API for OpenClaw instances.

    Returns list of OpenPort candidates to fingerprint.
    """
    if not censys_available():
        logger.warning("Censys API credentials not set - skipping Censys search")
        return []

    queries = [
        f'services.port={OPENCLAW_PORT} AND services.http.response.headers.server: "{OPENCLAW_SERVER_HEADER}"',
        f'services.http.response.html_title: "{OPENCLAW_TITLE}"',
    ]

    seen: set[tuple[str, int]] = set()
    results: list[OpenPort] = []

    for query in queries:
        logger.info("Censys query: %s", query)
        try:
            hosts = _censys_search(query)
            for host in hosts:
                ip = host.get("ip")
                # Extract ports from services
                for service in host.get("services", []):
                    port = service.get("port", OPENCLAW_PORT)
                    key = (ip, port)
                    if key not in seen:
                        seen.add(key)
                        results.append(OpenPort(ip=ip, port=port))

            logger.info("  Found %d candidates", len(results) - len(seen) + len(results))

        except Exception as e:
            logger.error("Censys API error for query '%s': %s", query, e)

    logger.info("Censys total unique candidates: %d", len(results))
    return results


def _censys_search(query: str, per_page: int = 100) -> list[dict]:
    """Execute a single Censys search query."""
    with httpx.Client() as client:
        response = client.get(
            CENSYS_SEARCH_URL,
            params={"q": query, "per_page": per_page},
            auth=(CENSYS_API_ID, CENSYS_API_SECRET),
            timeout=30,
        )

        if response.status_code == 401:
            logger.error("Censys authentication failed - check API credentials")
            return []

        if response.status_code == 429:
            logger.warning("Censys rate limit reached - try again later")
            return []

        response.raise_for_status()
        data = response.json()

        hits = data.get("result", {}).get("hits", [])
        total = data.get("result", {}).get("total", 0)
        logger.info("  %d results (showing first %d)", total, len(hits))
        return hits
