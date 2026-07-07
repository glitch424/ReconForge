"""Data models for the async_recon framework.

All persistent data flows through these Pydantic models before reaching
the database layer, ensuring validation and type safety.
"""

from typing import Optional

from pydantic import BaseModel, ConfigDict


class SubdomainRecord(BaseModel):
    """A discovered subdomain and its source plugin."""

    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    target: str
    subdomain: str
    source: str
    resolved: bool = False
    is_wildcard: bool = False


class DNSRecord(BaseModel):
    """A DNS record associated with a subdomain."""

    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    subdomain_id: int
    record_type: str
    value: str


class PortRecord(BaseModel):
    """An open port discovered on a subdomain."""

    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    subdomain_id: int
    port: int
    protocol: str = "tcp"
    service: str = ""


class HttpRecord(BaseModel):
    """HTTP probe result for a subdomain + port combination."""

    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    subdomain_id: int
    port: int
    url: str
    status_code: int
    title: str = ""
    content_length: int = 0
    redirect_url: str = ""
    server: str = ""
    content_type: str = ""
    tls_issuer: str = ""
    tls_subject: str = ""
    tls_not_after: str = ""


class TechRecord(BaseModel):
    """A technology detected on a subdomain."""

    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    subdomain_id: int
    category: str
    name: str
    version: str = ""
    confidence: int = 100


class ScreenshotRecord(BaseModel):
    """Screenshot metadata captured by gowitness for a URL.

    The actual image file is stored on disk; this record persists the
    filesystem path so reports can reference it without re-scanning.
    """

    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    subdomain_id: int
    url: str
    file_path: str  # Absolute or workspace-relative path to PNG
    width: int = 1280
    height: int = 800
