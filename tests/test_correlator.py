"""Tests for the AssetCorrelator."""

from collections.abc import AsyncGenerator

import pytest

from async_recon.database.store import DatabaseStore
from async_recon.modules.correlation.correlator import AssetCorrelator


@pytest.fixture
async def db_store() -> AsyncGenerator[DatabaseStore, None]:
    store = DatabaseStore(":memory:")
    await store.connect()
    await store.init_schema()
    yield store
    await store.disconnect()


@pytest.mark.asyncio
async def test_correlate_empty(db_store: DatabaseStore) -> None:
    """Test correlation with no data."""
    correlator = AssetCorrelator(db_store)
    model = await correlator.correlate("example.com")

    assert model.target == "example.com"
    assert model.total_subdomains == 0
    assert model.live_subdomains == 0
    assert len(model.subdomains) == 0


@pytest.mark.asyncio
async def test_correlate_full_subdomain(db_store: DatabaseStore) -> None:
    """Test correlation joins all data sources for a subdomain."""
    target = "example.com"
    sub = "www.example.com"

    # 1. Add Subdomain
    sub_id = await db_store.add_subdomain(target, sub, "subfinder")

    # 2. Add DNS
    await db_store.add_dns_record(sub_id, "A", "1.2.3.4")

    # 3. Add Ports
    await db_store.add_port(sub_id, 80)
    await db_store.add_port(sub_id, 443)

    # 4. Add HTTP
    url = f"https://{sub}"
    await db_store.add_http_record(sub_id, 443, url, 200, "Test Page", server="nginx")

    # 5. Add Tech
    await db_store.add_tech_record(sub_id, "web-server", "Nginx", "1.21.0")

    # 6. Add Screenshot
    await db_store.add_screenshot(sub_id, url, "/tmp/screenshot.png")

    # Correlate
    correlator = AssetCorrelator(db_store)
    model = await correlator.correlate(target)

    # Verify overall stats
    assert model.target == target
    assert model.total_subdomains == 1
    assert model.live_subdomains == 1
    assert model.total_open_ports == 2
    assert model.total_http_endpoints == 1
    assert model.unique_technologies == ["Nginx"]

    # Verify subdomain details
    asset_sub = model.subdomains[0]
    assert asset_sub.subdomain == sub
    assert asset_sub.is_live is True
    assert asset_sub.has_screenshot is True

    # Verify nested data
    assert len(asset_sub.dns_records) == 1
    assert asset_sub.dns_records[0].value == "1.2.3.4"

    assert len(asset_sub.ports) == 2
    assert {p.port for p in asset_sub.ports} == {80, 443}

    assert len(asset_sub.http_endpoints) == 1
    ep = asset_sub.http_endpoints[0]
    assert ep.url == url
    assert ep.status_code == 200
    assert ep.server == "nginx"
    assert ep.screenshot_path == "/tmp/screenshot.png"

    assert len(asset_sub.technologies) == 1
    tech = asset_sub.technologies[0]
    assert tech.name == "Nginx"
    assert tech.version == "1.21.0"
