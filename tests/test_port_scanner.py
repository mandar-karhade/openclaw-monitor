"""Tests for the async port scanner."""
from __future__ import annotations

import asyncio

import pytest

from clawmon.scanner.port_scanner import _expand_targets, scan_range


def test_expand_single_ip():
    result = _expand_targets(["10.0.0.1"])
    assert result == ["10.0.0.1"]


def test_expand_cidr_24():
    result = _expand_targets(["192.168.1.0/24"])
    assert len(result) == 254  # .1 through .254 (hosts only)
    assert "192.168.1.1" in result
    assert "192.168.1.254" in result
    assert "192.168.1.0" not in result  # network address excluded


def test_expand_cidr_30():
    result = _expand_targets(["10.0.0.0/30"])
    assert len(result) == 2
    assert "10.0.0.1" in result
    assert "10.0.0.2" in result


def test_expand_range():
    result = _expand_targets(["10.0.0.1-10.0.0.5"])
    assert len(result) == 5
    assert result[0] == "10.0.0.1"
    assert result[-1] == "10.0.0.5"


def test_expand_invalid_ip():
    result = _expand_targets(["not-an-ip"])
    assert result == []


def test_expand_invalid_cidr():
    result = _expand_targets(["999.999.999.999/24"])
    assert result == []


def test_expand_mixed():
    result = _expand_targets([
        "10.0.0.1",
        "192.168.1.0/30",
        "172.16.0.1-172.16.0.3",
    ])
    # 1 + 2 + 3 = 6
    assert len(result) == 6


def test_expand_empty_and_comments():
    result = _expand_targets(["", "  ", "# comment won't parse"])
    # These should fail validation and return empty
    assert result == []


def test_expand_range_too_large():
    result = _expand_targets(["10.0.0.0-10.1.0.0"])
    assert result == []  # > 65536, rejected


@pytest.mark.asyncio
async def test_scan_range_no_targets():
    result = await scan_range([])
    assert result == []


@pytest.mark.asyncio
async def test_scan_range_localhost():
    """Scan localhost - at least verifies the scanner runs without crashing."""
    # This won't find OpenClaw but tests the mechanics
    result = await scan_range(
        ["127.0.0.1"],
        ports=[1],  # Port 1 is almost certainly closed
        concurrency=1,
        timeout=0.5,
    )
    # Port 1 on localhost should be closed
    assert result == []
