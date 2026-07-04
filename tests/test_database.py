"""Tests for the database store.

All tests use an in-memory SQLite database — no files on disk.
"""

from collections.abc import AsyncGenerator

import pytest

from async_recon.database.store import DatabaseStore


@pytest.fixture
async def db_store() -> AsyncGenerator[DatabaseStore, None]:
    store = DatabaseStore(":memory:")
    await store.connect()
    await store.init_schema()
    yield store
    await store.disconnect()


# ------------------------------------------------------------------
# Subdomains
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_subdomain(db_store: DatabaseStore) -> None:
    id1 = await db_store.add_subdomain("example.com", "www.example.com", "test")
    id2 = await db_store.add_subdomain("example.com", "api.example.com", "test")
    assert id1 != id2

    # Test deduplication
    id3 = await db_store.add_subdomain("example.com", "www.example.com", "other")
    assert id1 == id3


@pytest.mark.asyncio
async def test_get_unresolved_subdomains(db_store: DatabaseStore) -> None:
    await db_store.add_subdomain("example.com", "www.example.com", "test")
    unresolved = await db_store.get_unresolved_subdomains()
    assert len(unresolved) == 1
    assert unresolved[0].subdomain == "www.example.com"
    assert not unresolved[0].resolved


@pytest.mark.asyncio
async def test_mark_resolved(db_store: DatabaseStore) -> None:
    sub_id = await db_store.add_subdomain("example.com", "www.example.com", "test")
    await db_store.mark_resolved(sub_id, is_wildcard=True)

    unresolved = await db_store.get_unresolved_subdomains()
    assert len(unresolved) == 0


@pytest.mark.asyncio
async def test_add_dns_record(db_store: DatabaseStore) -> None:
    sub_id = await db_store.add_subdomain("example.com", "www.example.com", "test")
    await db_store.add_dns_record(sub_id, "A", "1.2.3.4")


@pytest.mark.asyncio
async def test_get_all_subdomains(db_store: DatabaseStore) -> None:
    await db_store.add_subdomain("example.com", "www.example.com", "test")
    await db_store.add_subdomain("example.com", "api.example.com", "test")
    await db_store.add_subdomain("other.com", "www.other.com", "test")

    subs = await db_store.get_all_subdomains("example.com")
    assert len(subs) == 2


# ------------------------------------------------------------------
# Ports
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_and_get_ports(db_store: DatabaseStore) -> None:
    sub_id = await db_store.add_subdomain("example.com", "www.example.com", "test")
    await db_store.add_port(sub_id, 80)
    await db_store.add_port(sub_id, 443, protocol="tcp", service="https")

    ports = await db_store.get_ports(sub_id)
    assert len(ports) == 2
    assert {p.port for p in ports} == {80, 443}


@pytest.mark.asyncio
async def test_add_port_deduplication(db_store: DatabaseStore) -> None:
    sub_id = await db_store.add_subdomain("example.com", "www.example.com", "test")
    await db_store.add_port(sub_id, 80)
    await db_store.add_port(sub_id, 80)  # duplicate

    ports = await db_store.get_ports(sub_id)
    assert len(ports) == 1


# ------------------------------------------------------------------
# HTTP Records
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_and_get_http_records(db_store: DatabaseStore) -> None:
    sub_id = await db_store.add_subdomain("example.com", "www.example.com", "test")
    await db_store.add_http_record(
        subdomain_id=sub_id,
        port=443,
        url="https://www.example.com",
        status_code=200,
        title="Example",
        server="nginx",
    )

    records = await db_store.get_http_records(sub_id)
    assert len(records) == 1
    assert records[0].status_code == 200
    assert records[0].title == "Example"
    assert records[0].server == "nginx"


@pytest.mark.asyncio
async def test_http_record_upsert(db_store: DatabaseStore) -> None:
    """Test that INSERT OR REPLACE updates existing records."""
    sub_id = await db_store.add_subdomain("example.com", "www.example.com", "test")
    await db_store.add_http_record(
        subdomain_id=sub_id,
        port=443,
        url="https://www.example.com",
        status_code=200,
    )
    await db_store.add_http_record(
        subdomain_id=sub_id,
        port=443,
        url="https://www.example.com",
        status_code=301,
    )

    records = await db_store.get_http_records(sub_id)
    assert len(records) == 1
    assert records[0].status_code == 301


# ------------------------------------------------------------------
# Technology Records
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_tech_record(db_store: DatabaseStore) -> None:
    sub_id = await db_store.add_subdomain("example.com", "www.example.com", "test")
    await db_store.add_tech_record(sub_id, "web-server", "nginx", version="1.21.0")
    await db_store.add_tech_record(sub_id, "cms", "WordPress")

    # Deduplication
    await db_store.add_tech_record(sub_id, "web-server", "nginx", version="1.21.0")
    # Should still only have 2 records (no way to query tech yet, but insert didn't crash)


# ------------------------------------------------------------------
# Error handling
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_require_conn_raises() -> None:
    store = DatabaseStore(":memory:")
    with pytest.raises(RuntimeError, match="Database not connected"):
        await store.add_subdomain("x", "y", "z")
