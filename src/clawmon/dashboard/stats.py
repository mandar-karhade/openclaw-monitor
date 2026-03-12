"""Dashboard statistics aggregation queries."""
from __future__ import annotations

import aiosqlite


async def get_dashboard_data(db: aiosqlite.Connection) -> dict:
    """Return all data needed to render the dashboard."""
    return {
        "summary": await _summary(db),
        "by_country": await _by_country(db),
        "by_provider": await _by_provider(db),

        "heatmap_points": await _heatmap_points(db),
        "recent_instances": await _recent_instances(db),
    }


async def _summary(db: aiosqlite.Connection) -> dict:
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
    data = dict(row)
    active = data["active"] or 0
    unsecured = data["unsecured"] or 0
    data["unsecured_pct"] = round(unsecured / active * 100, 1) if active > 0 else 0
    return data


async def _by_country(db: aiosqlite.Connection) -> list[dict]:
    cursor = await db.execute(
        """
        SELECT
            COALESCE(country, 'Unknown') as country,
            COALESCE(country_code, '??') as country_code,
            COUNT(*) as count,
            SUM(CASE WHEN secured = 'unsecured' THEN 1 ELSE 0 END) as unsecured
        FROM instances
        WHERE status = 'active'
        GROUP BY country, country_code
        ORDER BY count DESC
        LIMIT 20
        """
    )
    return [dict(row) for row in await cursor.fetchall()]


async def _by_provider(db: aiosqlite.Connection) -> list[dict]:
    cursor = await db.execute(
        """
        SELECT
            COALESCE(provider, 'Unknown') as provider,
            COUNT(*) as count,
            SUM(CASE WHEN secured = 'unsecured' THEN 1 ELSE 0 END) as unsecured
        FROM instances
        WHERE status = 'active'
        GROUP BY provider
        ORDER BY count DESC
        LIMIT 15
        """
    )
    return [dict(row) for row in await cursor.fetchall()]


async def _heatmap_points(db: aiosqlite.Connection) -> list[dict]:
    cursor = await db.execute(
        """
        SELECT latitude, longitude, secured
        FROM instances
        WHERE status = 'active' AND latitude IS NOT NULL AND longitude IS NOT NULL
        """
    )
    return [dict(row) for row in await cursor.fetchall()]


async def _recent_instances(db: aiosqlite.Connection, limit: int = 100) -> list[dict]:
    """Return recent instances with IPs masked."""
    cursor = await db.execute(
        """
        SELECT
            ip, port, secured, http_status, version,
            country, country_code, city, provider,
            first_seen, last_seen, server_header, title
        FROM instances
        WHERE status = 'active'
        ORDER BY last_seen DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = []
    for row in await cursor.fetchall():
        d = dict(row)
        # Mask last octet
        parts = d["ip"].rsplit(".", 1)
        d["ip_masked"] = f"{parts[0]}.xxx" if len(parts) == 2 else d["ip"]
        del d["ip"]
        rows.append(d)
    return rows
