"""Tests for the HTTP fingerprinter."""
from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from clawmon.models import SecurityStatus
from clawmon.scanner.fingerprinter import _matches_openclaw, fingerprint_all, fingerprint_host
from clawmon.scanner.port_scanner import OpenPort


def test_matches_openclaw_title():
    assert _matches_openclaw("Clawdbot Control", "", "") is True


def test_matches_openclaw_title_case_insensitive():
    assert _matches_openclaw("CLAWDBOT CONTROL", "", "") is True


def test_matches_openclaw_server_header():
    assert _matches_openclaw(None, "OpenClaw-Gateway/2.1.0", "") is True


def test_matches_openclaw_body():
    assert _matches_openclaw(None, "", '<div class="openclaw-dashboard">') is True


def test_no_match():
    assert _matches_openclaw("Apache Default Page", "nginx/1.18", "<html>hello</html>") is False


@pytest.mark.asyncio
@respx.mock
async def test_fingerprint_host_match():
    host = OpenPort(ip="10.0.0.1", port=18789)
    respx.get("http://10.0.0.1:18789/").mock(
        return_value=httpx.Response(
            200,
            headers={"server": "OpenClaw-Gateway/2.1.0"},
            text="<html><title>Clawdbot Control</title></html>",
        )
    )

    semaphore = asyncio.Semaphore(5)
    async with httpx.AsyncClient() as client:
        result = await fingerprint_host(client, host, semaphore)

    assert result is not None
    assert result.ip == "10.0.0.1"
    assert result.port == 18789
    assert result.version == "2.1.0"
    assert result.title == "Clawdbot Control"
    assert result.secured == SecurityStatus.UNSECURED
    assert result.http_status == 200


@pytest.mark.asyncio
@respx.mock
async def test_fingerprint_host_secured():
    host = OpenPort(ip="10.0.0.2", port=18789)
    respx.get("http://10.0.0.2:18789/").mock(
        return_value=httpx.Response(
            401,
            headers={"server": "OpenClaw-Gateway"},
            text="<html><title>Clawdbot Control - Login</title></html>",
        )
    )

    semaphore = asyncio.Semaphore(5)
    async with httpx.AsyncClient() as client:
        result = await fingerprint_host(client, host, semaphore)

    assert result is not None
    assert result.secured == SecurityStatus.SECURED
    assert result.http_status == 401


@pytest.mark.asyncio
@respx.mock
async def test_fingerprint_host_no_match():
    host = OpenPort(ip="10.0.0.3", port=18789)
    respx.get("http://10.0.0.3:18789/").mock(
        return_value=httpx.Response(
            200,
            headers={"server": "nginx/1.18"},
            text="<html><title>Welcome to nginx</title></html>",
        )
    )

    semaphore = asyncio.Semaphore(5)
    async with httpx.AsyncClient() as client:
        result = await fingerprint_host(client, host, semaphore)

    assert result is None


@pytest.mark.asyncio
@respx.mock
async def test_fingerprint_host_timeout():
    host = OpenPort(ip="10.0.0.4", port=18789)
    respx.get("http://10.0.0.4:18789/").mock(side_effect=httpx.ConnectTimeout("timeout"))

    semaphore = asyncio.Semaphore(5)
    async with httpx.AsyncClient() as client:
        result = await fingerprint_host(client, host, semaphore)

    assert result is None


@pytest.mark.asyncio
@respx.mock
async def test_fingerprint_all_filters():
    hosts = [
        OpenPort(ip="10.0.0.1", port=18789),
        OpenPort(ip="10.0.0.2", port=18789),
        OpenPort(ip="10.0.0.3", port=18789),
    ]
    respx.get("http://10.0.0.1:18789/").mock(
        return_value=httpx.Response(
            200,
            headers={"server": "OpenClaw-Gateway/2.0"},
            text="<title>Clawdbot Control</title>",
        )
    )
    respx.get("http://10.0.0.2:18789/").mock(
        return_value=httpx.Response(200, text="<title>Welcome to nginx</title>")
    )
    respx.get("http://10.0.0.3:18789/").mock(
        return_value=httpx.Response(
            401,
            headers={"server": "OpenClaw-Gateway"},
            text="Unauthorized",
        )
    )

    results = await fingerprint_all(hosts)
    assert len(results) == 2  # Only .1 and .3 match OpenClaw fingerprint
    ips = {r.ip for r in results}
    assert "10.0.0.1" in ips
    assert "10.0.0.3" in ips
