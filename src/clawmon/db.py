from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import aiosqlite

from clawmon.config import STALE_THRESHOLD_HOURS
from clawmon.models import DiscoveredInstance, InstanceRecord, InstanceStatus, SecurityStatus

logger = logging.getLogger("clawmon.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS instances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_checked TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    secured TEXT NOT NULL DEFAULT 'unknown',
    http_status INTEGER,
    version TEXT,
    country TEXT,
    country_code TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    provider TEXT,
    server_header TEXT,
    title TEXT,
    UNIQUE(ip, port)
);

CREATE INDEX IF NOT EXISTS idx_instances_status ON instances(status);
CREATE INDEX IF NOT EXISTS idx_instances_secured ON instances(secured);
CREATE INDEX IF NOT EXISTS idx_instances_country ON instances(country_code);

CREATE TABLE IF NOT EXISTS scanned_subnets (
    subnet TEXT PRIMARY KEY,
    port INTEGER NOT NULL,
    scanned_at TEXT NOT NULL,
    open_ports_found INTEGER NOT NULL DEFAULT 0
);
"""


async def init_db(db_path: Path) -> aiosqlite.Connection:
    """Initialize database and return connection."""
    db = await aiosqlite.connect(str(db_path))
    db.row_factory = aiosqlite.Row
    await db.executescript(SCHEMA)
    await db.commit()
    logger.info("Database initialized at %s", db_path)
    return db


async def upsert_instance(
    db: aiosqlite.Connection,
    instance: DiscoveredInstance,
    secured: SecurityStatus = SecurityStatus.UNKNOWN,
    http_status: int | None = None,
) -> None:
    """Insert or update an instance. Updates last_seen and enrichment data on conflict."""
    now = datetime.now(timezone.utc).isoformat()

    await db.execute(
        """
        INSERT INTO instances (
            ip, port, first_seen, last_seen, last_checked,
            status, secured, http_status, version,
            country, country_code, city, latitude, longitude,
            provider, server_header, title
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip, port) DO UPDATE SET
            last_seen = excluded.last_seen,
            last_checked = excluded.last_checked,
            status = 'active',
            secured = excluded.secured,
            http_status = excluded.http_status,
            version = COALESCE(excluded.version, instances.version),
            country = COALESCE(excluded.country, instances.country),
            country_code = COALESCE(excluded.country_code, instances.country_code),
            city = COALESCE(excluded.city, instances.city),
            latitude = COALESCE(excluded.latitude, instances.latitude),
            longitude = COALESCE(excluded.longitude, instances.longitude),
            provider = COALESCE(excluded.provider, instances.provider),
            server_header = COALESCE(excluded.server_header, instances.server_header),
            title = COALESCE(excluded.title, instances.title)
        """,
        (
            instance.ip,
            instance.port,
            now,  # first_seen
            now,  # last_seen
            now,  # last_checked
            InstanceStatus.ACTIVE,
            secured,
            http_status,
            instance.version,
            instance.country,
            instance.country_code,
            instance.city,
            instance.latitude,
            instance.longitude,
            instance.provider,
            instance.server_header,
            instance.title,
        ),
    )
    await db.commit()


async def mark_stale_instances(db: aiosqlite.Connection) -> int:
    """Mark instances not seen in STALE_THRESHOLD_HOURS as inactive. Returns count."""
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=STALE_THRESHOLD_HOURS)
    ).isoformat()

    cursor = await db.execute(
        """
        UPDATE instances
        SET status = 'inactive'
        WHERE status = 'active' AND last_seen < ?
        """,
        (cutoff,),
    )
    await db.commit()
    count = cursor.rowcount
    if count > 0:
        logger.info("Marked %d instances as inactive (not seen since %s)", count, cutoff)
    return count


async def get_active_instances(db: aiosqlite.Connection) -> list[InstanceRecord]:
    """Return all active instances."""
    cursor = await db.execute(
        "SELECT * FROM instances WHERE status = 'active' ORDER BY last_seen DESC"
    )
    rows = await cursor.fetchall()
    return [InstanceRecord(**dict(row)) for row in rows]


async def update_enrichment(
    db: aiosqlite.Connection,
    ip: str,
    enrichment: dict,
) -> None:
    """Update geolocation/provider data for an instance."""
    await db.execute(
        """
        UPDATE instances SET
            country = COALESCE(?, country),
            country_code = COALESCE(?, country_code),
            city = COALESCE(?, city),
            latitude = COALESCE(?, latitude),
            longitude = COALESCE(?, longitude),
            provider = COALESCE(?, provider)
        WHERE ip = ?
        """,
        (
            enrichment.get("country"),
            enrichment.get("country_code"),
            enrichment.get("city"),
            enrichment.get("latitude"),
            enrichment.get("longitude"),
            enrichment.get("provider"),
            ip,
        ),
    )
    await db.commit()


async def get_unenriched_ips(db: aiosqlite.Connection) -> list[str]:
    """Return IPs that are missing geolocation data."""
    cursor = await db.execute(
        "SELECT DISTINCT ip FROM instances WHERE status = 'active' AND (country IS NULL OR provider IS NULL)"
    )
    rows = await cursor.fetchall()
    return [row[0] for row in rows]


async def get_scanned_subnets(db: aiosqlite.Connection, port: int) -> set[str]:
    """Return set of /24 subnet strings already scanned for this port."""
    cursor = await db.execute(
        "SELECT subnet FROM scanned_subnets WHERE port = ?",
        (port,),
    )
    rows = await cursor.fetchall()
    return {row[0] for row in rows}


async def mark_subnet_scanned(
    db: aiosqlite.Connection,
    subnet: str,
    port: int,
    open_ports_found: int,
) -> None:
    """Record a /24 subnet as scanned."""
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        """
        INSERT INTO scanned_subnets (subnet, port, scanned_at, open_ports_found)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(subnet) DO UPDATE SET
            scanned_at = excluded.scanned_at,
            open_ports_found = excluded.open_ports_found
        """,
        (subnet, port, now, open_ports_found),
    )
    await db.commit()


async def get_scan_summary(db: aiosqlite.Connection) -> dict:
    """Return summary counts for logging."""
    cursor = await db.execute(
        """
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
            SUM(CASE WHEN status = 'active' AND secured = 'unsecured' THEN 1 ELSE 0 END) as unsecured,
            SUM(CASE WHEN status = 'active' AND secured = 'secured' THEN 1 ELSE 0 END) as secured,
            SUM(CASE WHEN status = 'active' AND secured = 'unknown' THEN 1 ELSE 0 END) as unknown
        FROM instances
        """
    )
    row = await cursor.fetchone()
    return dict(row)
