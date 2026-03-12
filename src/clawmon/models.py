from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class SecurityStatus(StrEnum):
    SECURED = "secured"
    UNSECURED = "unsecured"
    UNKNOWN = "unknown"


class InstanceStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"


class DiscoveredInstance(BaseModel):
    """Raw instance discovered by scanner + fingerprinter."""

    ip: str
    port: int
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    provider: str | None = None
    server_header: str | None = None
    title: str | None = None
    version: str | None = None
    # Set by fingerprinter during discovery
    http_status: int | None = None
    secured: SecurityStatus = SecurityStatus.UNKNOWN


class InstanceRecord(BaseModel):
    """Full instance record as stored in DB."""

    id: int | None = None
    ip: str
    port: int
    first_seen: datetime
    last_seen: datetime
    last_checked: datetime
    status: InstanceStatus = InstanceStatus.ACTIVE
    secured: SecurityStatus = SecurityStatus.UNKNOWN
    http_status: int | None = None
    version: str | None = None
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    provider: str | None = None
    server_header: str | None = None
    title: str | None = None
