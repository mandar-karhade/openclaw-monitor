"""
IP geolocation enrichment using free ip-api.com batch endpoint.

Free tier: 45 requests/min for single, 15 requests/min for batch (up to 100 IPs per batch).
No API key needed.
"""
from __future__ import annotations

import asyncio
import logging

import httpx

logger = logging.getLogger("clawmon.scanner.enricher")

BATCH_URL = "http://ip-api.com/batch"
SINGLE_URL = "http://ip-api.com/json"
FIELDS = "status,country,countryCode,city,lat,lon,isp,org,query"


async def enrich_ip(ip: str, client: httpx.AsyncClient) -> dict | None:
    """
    Enrich a single IP with geolocation data. Returns enrichment dict or None on failure.

    Uses the single-IP endpoint (45 req/min free tier).
    """
    try:
        resp = await client.get(
            f"{SINGLE_URL}/{ip}",
            params={"fields": FIELDS},
            timeout=10,
        )
        if resp.status_code == 429:
            logger.warning("ip-api rate limit hit for %s, skipping", ip)
            return None
        if resp.status_code != 200:
            logger.warning("ip-api failed for %s: HTTP %d", ip, resp.status_code)
            return None

        item = resp.json()
        if item.get("status") != "success":
            return None

        return {
            "country": item.get("country"),
            "country_code": item.get("countryCode"),
            "city": item.get("city"),
            "latitude": item.get("lat"),
            "longitude": item.get("lon"),
            "provider": item.get("isp") or item.get("org"),
        }
    except (httpx.TimeoutException, httpx.RequestError) as e:
        logger.warning("ip-api error for %s: %s", ip, e)
        return None


async def enrich_ips(ips: list[str]) -> dict[str, dict]:
    """
    Batch-enrich IP addresses with geolocation data.

    Returns dict mapping IP -> enrichment data:
        {
            "country": "Germany",
            "country_code": "DE",
            "city": "Frankfurt",
            "latitude": 50.1109,
            "longitude": 8.6821,
            "provider": "Hetzner Online GmbH",
        }
    """
    if not ips:
        return {}

    results: dict[str, dict] = {}
    unique_ips = list(set(ips))

    # Process in batches of 100
    async with httpx.AsyncClient() as client:
        for batch_start in range(0, len(unique_ips), 100):
            batch = unique_ips[batch_start : batch_start + 100]

            try:
                payload = [{"query": ip, "fields": FIELDS} for ip in batch]
                resp = await client.post(
                    BATCH_URL,
                    json=payload,
                    timeout=15,
                )

                if resp.status_code == 429:
                    logger.warning("ip-api rate limit hit, waiting 60s...")
                    await asyncio.sleep(60)
                    resp = await client.post(BATCH_URL, json=payload, timeout=15)

                if resp.status_code != 200:
                    logger.error("ip-api batch request failed: HTTP %d", resp.status_code)
                    continue

                for item in resp.json():
                    if item.get("status") != "success":
                        continue

                    ip = item["query"]
                    results[ip] = {
                        "country": item.get("country"),
                        "country_code": item.get("countryCode"),
                        "city": item.get("city"),
                        "latitude": item.get("lat"),
                        "longitude": item.get("lon"),
                        "provider": item.get("isp") or item.get("org"),
                    }

            except (httpx.TimeoutException, httpx.RequestError) as e:
                logger.error("ip-api batch request error: %s", e)

            # Rate limit: 15 batch requests/min
            if batch_start + 100 < len(unique_ips):
                await asyncio.sleep(4.5)

    logger.info("Enriched %d/%d IPs with geolocation", len(results), len(unique_ips))
    return results
