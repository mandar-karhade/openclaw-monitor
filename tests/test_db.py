"""Tests for the database module."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from clawmon.db import get_active_instances, get_scan_summary, init_db, mark_stale_instances, upsert_instance
from clawmon.models import DiscoveredInstance, SecurityStatus


@pytest.fixture
async def db(tmp_path: Path):
    conn = await init_db(tmp_path / "test.db")
    yield conn
    await conn.close()


def _make_instance(ip: str = "1.2.3.4", port: int = 18789, **kwargs) -> DiscoveredInstance:
    return DiscoveredInstance(ip=ip, port=port, **kwargs)


@pytest.mark.asyncio
async def test_upsert_insert(db):
    inst = _make_instance(country="US", provider="AWS")
    await upsert_instance(db, inst, SecurityStatus.UNSECURED, 200)

    active = await get_active_instances(db)
    assert len(active) == 1
    assert active[0].ip == "1.2.3.4"
    assert active[0].secured == SecurityStatus.UNSECURED
    assert active[0].http_status == 200
    assert active[0].provider == "AWS"


@pytest.mark.asyncio
async def test_upsert_update(db):
    inst = _make_instance()
    await upsert_instance(db, inst, SecurityStatus.UNKNOWN, None)
    await upsert_instance(db, inst, SecurityStatus.SECURED, 401)

    active = await get_active_instances(db)
    assert len(active) == 1
    assert active[0].secured == SecurityStatus.SECURED
    assert active[0].http_status == 401


@pytest.mark.asyncio
async def test_upsert_preserves_enrichment(db):
    inst = _make_instance(country="Germany", provider="Hetzner")
    await upsert_instance(db, inst, SecurityStatus.UNSECURED, 200)

    # Second upsert without enrichment data should keep original
    inst2 = _make_instance()
    await upsert_instance(db, inst2, SecurityStatus.SECURED, 401)

    active = await get_active_instances(db)
    assert active[0].country == "Germany"
    assert active[0].provider == "Hetzner"


@pytest.mark.asyncio
async def test_unique_by_ip_port(db):
    await upsert_instance(db, _make_instance("1.1.1.1", 18789), SecurityStatus.UNKNOWN, None)
    await upsert_instance(db, _make_instance("1.1.1.1", 8080), SecurityStatus.UNKNOWN, None)
    await upsert_instance(db, _make_instance("2.2.2.2", 18789), SecurityStatus.UNKNOWN, None)

    active = await get_active_instances(db)
    assert len(active) == 3


@pytest.mark.asyncio
async def test_mark_stale(db):
    inst = _make_instance()
    await upsert_instance(db, inst, SecurityStatus.UNKNOWN, None)

    # Manually backdate last_seen
    old_time = (datetime.now(timezone.utc) - timedelta(hours=72)).isoformat()
    await db.execute("UPDATE instances SET last_seen = ?", (old_time,))
    await db.commit()

    stale_count = await mark_stale_instances(db)
    assert stale_count == 1

    active = await get_active_instances(db)
    assert len(active) == 0


@pytest.mark.asyncio
async def test_scan_summary(db):
    await upsert_instance(db, _make_instance("1.1.1.1"), SecurityStatus.UNSECURED, 200)
    await upsert_instance(db, _make_instance("2.2.2.2"), SecurityStatus.SECURED, 401)
    await upsert_instance(db, _make_instance("3.3.3.3"), SecurityStatus.UNKNOWN, None)

    summary = await get_scan_summary(db)
    assert summary["total"] == 3
    assert summary["active"] == 3
    assert summary["unsecured"] == 1
    assert summary["secured"] == 1
    assert summary["unknown"] == 1
