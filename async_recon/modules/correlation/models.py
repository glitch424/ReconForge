"""Normalized asset model for the correlation layer.

These Pydantic models represent the complete attack surface of a target
after all passive and active recon stages have completed. The correlator
produces an AssetModel; the reporter consumes it. No other component
should bridge the two layers directly.
"""

from datetime import datetime, timezone
from typing import List

from pydantic import BaseModel, Field


class AssetPort(BaseModel):
    """An open port on an asset."""

    port: int
    protocol: str = "tcp"
    service: str = ""


class AssetHttpEndpoint(BaseModel):
    """An HTTP/HTTPS endpoint discovered on an asset."""

    url: str
    port: int
    status_code: int
    title: str = ""
    server: str = ""
    content_type: str = ""
    content_length: int = 0
    redirect_url: str = ""
    tls_issuer: str = ""
    tls_subject: str = ""
    tls_not_after: str = ""
    screenshot_path: str = ""  # Empty string when no screenshot available


class AssetTechnology(BaseModel):
    """A technology fingerprinted on an asset."""

    category: str
    name: str
    version: str = ""
    confidence: int = 100


class AssetDnsRecord(BaseModel):
    """A DNS record for an asset."""

    record_type: str
    value: str


class AssetSubdomain(BaseModel):
    """A fully correlated subdomain with all associated recon data.

    This is the primary unit of the attack surface model. Every field is
    optional so a partially-scanned asset can still be represented.
    """

    subdomain: str
    source: str
    resolved: bool = False
    is_wildcard: bool = False

    dns_records: List[AssetDnsRecord] = Field(default_factory=list)
    ports: List[AssetPort] = Field(default_factory=list)
    http_endpoints: List[AssetHttpEndpoint] = Field(default_factory=list)
    technologies: List[AssetTechnology] = Field(default_factory=list)

    # Derived convenience flags for quick report filtering
    @property
    def is_live(self) -> bool:
        """True if at least one HTTP endpoint returned a response."""
        return any(e.status_code > 0 for e in self.http_endpoints)

    @property
    def has_screenshot(self) -> bool:
        """True if at least one HTTP endpoint has a screenshot."""
        return any(e.screenshot_path for e in self.http_endpoints)


class AssetModel(BaseModel):
    """The complete normalized attack surface for a target.

    Produced by AssetCorrelator and consumed exclusively by ReportExporter.
    Contains no business logic — it is a pure data container.
    """

    target: str
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    subdomains: List[AssetSubdomain] = Field(default_factory=list)

    # Summary statistics derived at correlation time
    total_subdomains: int = 0
    live_subdomains: int = 0
    total_open_ports: int = 0
    total_http_endpoints: int = 0
    unique_technologies: List[str] = Field(default_factory=list)
